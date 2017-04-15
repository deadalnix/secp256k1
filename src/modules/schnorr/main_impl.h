/**********************************************************************
 * Copyright (c) 2017 Amaury SÉCHET                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORR_MAIN
#define SECP256K1_MODULE_SCHNORR_MAIN

#include "include/secp256k1_schnorr.h"
#include "modules/schnorr/schnorr_impl.h"

static const unsigned char secp256k1_schnorr_algo16[17] = "Schnorr+SHA256  ";

int secp256k1_schnorr_sign(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const unsigned char *seckey,
    const secp256k1_pubkey *pubkey,
    secp256k1_nonce_function noncefp,
    const void *noncedata
) {
    secp256k1_scalar sec, non;
    secp256k1_ge p;
    int ret = 0;
    int overflow = 0;
    unsigned char nonce32[32];
    unsigned int count = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(pubkey != NULL);
    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_default;
    }

    secp256k1_pubkey_load(ctx, &p, pubkey);
    secp256k1_scalar_set_b32(&sec, seckey, NULL);
    while (1) {
        ret = noncefp(nonce32, msg32, seckey, secp256k1_schnorr_algo16, (void*)noncedata, count);
        if (!ret) {
            break;
        }
        secp256k1_scalar_set_b32(&non, nonce32, &overflow);
        if (!secp256k1_scalar_is_zero(&non) && !overflow) {
            if (secp256k1_schnorr_sig_sign(&ctx->ecmult_gen_ctx, sig64, &sec, &p, &non, msg32)) {
                break;
            }
        }
        count++;
    }
    if (!ret) {
        memset(sig64, 0, 64);
    }
    memset(nonce32, 0, 32);
    secp256k1_scalar_clear(&non);
    secp256k1_scalar_clear(&sec);
    return ret;
}

int secp256k1_schnorr_verify(const secp256k1_context* ctx, const unsigned char *sig64, const unsigned char *msg32, const secp256k1_pubkey *pubkey) {
    secp256k1_ge q;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pubkey != NULL);

    secp256k1_pubkey_load(ctx, &q, pubkey);
    return secp256k1_schnorr_sig_verify(&ctx->ecmult_ctx, sig64, &q, msg32);
}

#endif
