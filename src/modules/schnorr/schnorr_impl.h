/***********************************************************************
 * Copyright (c) 2017 Amaury SÉCHET                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef _SECP256K1_SCHNORR_IMPL_H_
#define _SECP256K1_SCHNORR_IMPL_H_

#include <string.h>

#include "schnorr.h"
#include "field.h"
#include "group.h"
#include "ecmult.h"
#include "ecmult_gen.h"

/**
 * Custom Schnorr-based signature scheme. They support multiparty signing and
 * batch validation.
 *
 * Rationale for verifying R's y coordinate:
 * In order to support batch validation, the full R point must be known to
 * verifiers, rather than just its x coordinate. In order to not risk being
 * more strict in batch validation than normal validation, validators must be
 * required to reject signatures with incorrect y coordinate. This is only
 * possible by including a (relatively slow) field inverse, or a field square
 * root. However, batch validation offers potentially much higher benefits
 * than this cost.
 *
 * Rationale for having an implicit y coordinate oddness:
 * If we commit to having the full R point known to verifiers, there are two
 * mechanism. Either include its oddness in the signature, or give it an
 * implicit fixed value. As the R y coordinate can be flipped by a simple
 * negation of the nonce, we choose the latter, as it comes with nearly zero
 * impact on signing or validation performance, and saves a byte in the
 * signature.
 *
 * Signing:
 *   Inputs:
 *     32-byte message m,
 *     32-byte scalar key x (!=0)
 *     public key point P,
 *     32-byte scalar nonce k (!=0)
 *
 *   Compute point R = k * G. Negate nonce and R if R's y coordinate is odd.
 *   Compute scalar e = Hash(r || P || m). Reject nonce if e == 0 or e >= order.
 *   Compute scalar s = k - e * x.
 *   The signature is (r, s).
 *
 * Verification:
 *   Inputs:
 *     32-byte message m,
 *     public key point P,
 *     signature: (32-byte r, scalar s)
 *
 *   Signature is invalid if s >= order or r >= p.
 *   Compute scalar e = Hash(r || P || m). Reject e == 0 or e >= order.
 *   Option 1 (faster for single verification):
 *     Compute point R = e * P + s * G. reject if R is infinity or R.y is odd.
 *     Signature is valid if the serialization of R.x equals r.
 *   Option 2 (allows batch validation):
 *     Decompress x coordinate r into point R, with odd y coordinate.
 *     Reject if R is not on the curve.
 *     Signature is valid if R + e * P + s * G == 0.
 */
static int secp256k1_schnorr_sig_sign(
    const secp256k1_ecmult_gen_context* ctx,
    unsigned char *sig64,
    const secp256k1_scalar *privkey,
    const secp256k1_ge *pubkey,
    const secp256k1_scalar *nonce,
    const unsigned char *msg32
) {
    secp256k1_gej Rj;
    secp256k1_ge Ra;
    secp256k1_scalar e, s, k;

    if (secp256k1_scalar_is_zero(privkey) || secp256k1_scalar_is_zero(nonce)) {
        return 0;
    }
    k = *nonce;

    secp256k1_ecmult_gen(ctx, &Rj, &k);
    secp256k1_ge_set_gej(&Ra, &Rj);
    secp256k1_fe_normalize(&Ra.y);
    if (secp256k1_fe_is_odd(&Ra.y)) {
        /**
         * R's y coordinate is odd, which is not allowed (see rationale above).
         * Force it to be even by negating the nonce. Note that this even works
         * for multiparty signing, as the R point is known to all participants,
         * which can all decide to flip the sign in unison, resulting in the
         * overall R point to be negated too.
         */
        secp256k1_scalar_negate(&k, &k);
    }

    secp256k1_fe_normalize(&Ra.x);
    secp256k1_fe_get_b32(sig64, &Ra.x);
    if (!secp256k1_schnorr_compute_e(&e, sig64, pubkey, msg32)) {
        secp256k1_scalar_clear(&k);
        return 0;
    }

    secp256k1_scalar_mul(&s, &e, privkey);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_add(&s, &s, &k);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_get_b32(sig64 + 32, &s);
    return 1;
}

static int secp256k1_schnorr_sig_verify(
    const secp256k1_ecmult_context* ctx,
    const unsigned char *sig64,
    const secp256k1_ge *pubkey,
    const unsigned char *msg32
) {
    secp256k1_gej Pj, Rj;
    secp256k1_ge Ra;
    secp256k1_fe Rx;
    secp256k1_scalar e, s;
    int overflow;

    if (secp256k1_ge_is_infinity(pubkey)) {
        return 0;
    }

    /* Extract s */
    overflow = 0;
    secp256k1_scalar_set_b32(&s, sig64 + 32, &overflow);
    if (overflow) {
        return 0;
    }

    /* Extract R.x */
    if (!secp256k1_fe_set_b32(&Rx, sig64)) {
        return 0;
    }

    /* Compute e */
    if (!secp256k1_schnorr_compute_e(&e, sig64, pubkey, msg32)) {
        return 0;
    }

    /* Verify the signature */
    secp256k1_gej_set_ge(&Pj, pubkey);
    secp256k1_ecmult(ctx, &Rj, &Pj, &e, &s);
    if (secp256k1_gej_is_infinity(&Rj)) {
        return 0;
    }

    secp256k1_ge_set_gej_var(&Ra, &Rj);
    secp256k1_fe_normalize_var(&Ra.y);
    if (secp256k1_fe_is_odd(&Ra.y)) {
        return 0;
    }

    return secp256k1_fe_equal_var(&Rx, &Ra.x);
}

static int secp256k1_schnorr_compute_e(
    secp256k1_scalar* e,
    const unsigned char *rx,
    const secp256k1_ge *p,
    const unsigned char *msg32
) {
    int overflow = 0;
    secp256k1_sha256_t sha;
    unsigned char buf[32];
    secp256k1_sha256_initialize(&sha);

    /* R.x */
    secp256k1_sha256_write(&sha, rx, 32);

    /* P.x and P.y */
    secp256k1_fe_get_b32(buf, &p->x);
    secp256k1_sha256_write(&sha, buf, 32);
    secp256k1_fe_get_b32(buf, &p->y);
    secp256k1_sha256_write(&sha, buf, 32);

    /* msg */
    secp256k1_sha256_write(&sha, msg32, 32);

    /* compute e */
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(e, buf, &overflow);
    return !overflow & !secp256k1_scalar_is_zero(e);
}

#endif
