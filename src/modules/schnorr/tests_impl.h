/**********************************************************************
 * Copyright (c) 2017 Amaury SÉCHET                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORR_TESTS
#define SECP256K1_MODULE_SCHNORR_TESTS

#include "scalar.h"

#include "include/secp256k1_schnorr.h"

void test_schnorr_end_to_end(void) {
    unsigned char privkey[32];
    unsigned char message[32];
    unsigned char schnorr_signature[64];
    secp256k1_pubkey pubkey;

    /* Generate a random key and message. */
    {
        secp256k1_scalar key;
        random_scalar_order_test(&key);
        secp256k1_scalar_get_b32(privkey, &key);
        secp256k1_rand256_test(message);
    }

    /* Construct and verify corresponding public key. */
    CHECK(secp256k1_ec_seckey_verify(ctx, privkey) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, privkey) == 1);

    /* Schnorr sign. */
    CHECK(secp256k1_schnorr_sign(ctx, schnorr_signature, message, privkey, &pubkey, NULL, NULL) == 1);
    CHECK(secp256k1_schnorr_verify(ctx, schnorr_signature, message, &pubkey) == 1);
    /* Destroy signature and verify again. */
    schnorr_signature[secp256k1_rand_bits(6)] += 1 + secp256k1_rand_int(255);
    CHECK(secp256k1_schnorr_verify(ctx, schnorr_signature, message, &pubkey) == 0);
}

void test_schnorr_sign_verify(void) {
    unsigned char msg32[32];
    unsigned char sig64[3][64];
    secp256k1_gej pubkeyj[3];
    secp256k1_ge pubkey[3];
    secp256k1_scalar nonce[3], key[3];
    int i = 0;
    int k;

    secp256k1_rand256_test(msg32);

    for (k = 0; k < 3; k++) {
        random_scalar_order_test(&key[k]);
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pubkeyj[k], &key[k]);
        secp256k1_ge_set_gej_var(&pubkey[k], &pubkeyj[k]);
        secp256k1_fe_normalize(&pubkey[k].x);
        secp256k1_fe_normalize(&pubkey[k].y);

        do {
            random_scalar_order_test(&nonce[k]);
            if (secp256k1_schnorr_sig_sign(&ctx->ecmult_gen_ctx, sig64[k], &key[k], &pubkey[k], &nonce[k], msg32)) {
                break;
            }
        } while(1);

        CHECK(secp256k1_schnorr_sig_verify(&ctx->ecmult_ctx, sig64[k], &pubkey[k], msg32));

        for (i = 0; i < 4; i++) {
            int pos = secp256k1_rand_bits(6);
            int mod = 1 + secp256k1_rand_int(255);
            sig64[k][pos] ^= mod;
            CHECK(secp256k1_schnorr_sig_verify(&ctx->ecmult_ctx, sig64[k], &pubkey[k], msg32) == 0);
            sig64[k][pos] ^= mod;
        }
    }
}

void run_schnorr_compact_test(void) {
    /**
     * This check a signature generated using another
     * implementation in order to ensure compatibility.
     */
    static const unsigned char msg[32] = {0};

    static const unsigned char pkbuf[33] = {
        0x03,
        0xe5, 0x47, 0xc9, 0x69, 0xf5, 0xa5, 0xf4, 0x14,
        0x39, 0x18, 0xae, 0x4a, 0xf7, 0x66, 0xe5, 0x43,
        0x87, 0x37, 0xa3, 0xbd, 0xdd, 0x0e, 0x1e, 0xf3,
        0x5d, 0xae, 0x3a, 0x46, 0x7b, 0x27, 0x6f, 0xd4,
    };

    static const unsigned char sig[64] = {
        0x7b, 0xc9, 0x56, 0xe8, 0xa5, 0xa2, 0x0d, 0x43,
        0xf6, 0x6e, 0x86, 0xa8, 0xbf, 0x3f, 0x7b, 0xca,
        0xbe, 0x3b, 0xee, 0x37, 0x8b, 0xc0, 0xf8, 0x5c,
        0xab, 0xb8, 0xac, 0xc9, 0xc9, 0xaa, 0x73, 0x4d,
        0x51, 0xc4, 0xbc, 0x23, 0x4a, 0x4b, 0x63, 0x3a,
        0x00, 0x27, 0x63, 0xb3, 0x88, 0x0f, 0x91, 0xe2,
        0xda, 0x3d, 0x97, 0x28, 0x2e, 0xd9, 0x7d, 0x96,
        0xb9, 0xef, 0xfb, 0xcd, 0x82, 0x87, 0x3c, 0x6c
    };

    secp256k1_pubkey pubkey;
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pkbuf, 33));
    CHECK(secp256k1_schnorr_verify(ctx, sig, msg, &pubkey));
}

void run_schnorr_tests(void) {
    int i;
    for (i = 0; i < 32*count; i++) {
        test_schnorr_end_to_end();
    }
    for (i = 0; i < 32 * count; i++) {
         test_schnorr_sign_verify();
    }

    run_schnorr_compact_test();
}

#endif
