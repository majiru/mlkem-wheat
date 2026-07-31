/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [FIPS203]
 *   FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/pubs/fips/203/final
 */

/******************************* Key sizes ************************************/

#define MLKEM512_SECRETKEYBYTES 1632
#define MLKEM512_PUBLICKEYBYTES 800
#define MLKEM512_CIPHERTEXTBYTES 768

#define MLKEM768_SECRETKEYBYTES 2400
#define MLKEM768_PUBLICKEYBYTES 1184
#define MLKEM768_CIPHERTEXTBYTES 1088

#define MLKEM1024_SECRETKEYBYTES 3168
#define MLKEM1024_PUBLICKEYBYTES 1568
#define MLKEM1024_CIPHERTEXTBYTES 1568

/* Size of randomness coins in bytes (level-independent) */
#define MLKEM_SYMBYTES 32
#define MLKEM512_SYMBYTES MLKEM_SYMBYTES
#define MLKEM768_SYMBYTES MLKEM_SYMBYTES
#define MLKEM1024_SYMBYTES MLKEM_SYMBYTES
/* Size of shared secret in bytes (level-independent) */
#define MLKEM_BYTES 32
#define MLKEM512_BYTES MLKEM_BYTES
#define MLKEM768_BYTES MLKEM_BYTES
#define MLKEM1024_BYTES MLKEM_BYTES

/****************************** Error codes ***********************************/

/* Generic failure condition */
#define MLK_ERR_FAIL -1
/* An allocation failed. This can only happen if MLK_CONFIG_CUSTOM_ALLOC_FREE
 * is defined and the provided MLK_CUSTOM_ALLOC can fail. */
#define MLK_ERR_OUT_OF_MEMORY -2
/* An rng failure occured. Might be due to insufficient entropy or
 * system misconfiguration. */
#define MLK_ERR_RNG_FAIL -3

int mlkem512_keypair_derand(
    u8int pk[MLKEM512_PUBLICKEYBYTES],
    u8int sk[MLKEM512_SECRETKEYBYTES],
    const u8int coins[2 * MLKEM_SYMBYTES]
);
int mlkem512_keypair(
    u8int pk[MLKEM512_PUBLICKEYBYTES],
    u8int sk[MLKEM512_SECRETKEYBYTES]
);
int mlkem512_enc_derand(
    u8int ct[MLKEM512_CIPHERTEXTBYTES],
    u8int ss[MLKEM_BYTES],
    const u8int pk[MLKEM512_PUBLICKEYBYTES],
    const u8int coins[MLKEM_SYMBYTES]
);
int mlkem512_enc(
    u8int ct[MLKEM512_CIPHERTEXTBYTES],
    u8int ss[MLKEM_BYTES],
    const u8int pk[MLKEM512_PUBLICKEYBYTES]
);
int mlkem512_dec(
    u8int ss[MLKEM_BYTES],
    const u8int ct[MLKEM512_CIPHERTEXTBYTES],
    const u8int sk[MLKEM512_SECRETKEYBYTES]
);
int mlkem512_check_pk(
    const u8int pk[MLKEM512_PUBLICKEYBYTES]
);
int mlkem512_check_sk(
    const u8int sk[MLKEM512_SECRETKEYBYTES]
);
int mlkem768_keypair_derand(
    u8int pk[MLKEM768_PUBLICKEYBYTES],
    u8int sk[MLKEM768_SECRETKEYBYTES],
    const u8int coins[2 * MLKEM_SYMBYTES]
);
int mlkem768_keypair(
    u8int pk[MLKEM768_PUBLICKEYBYTES],
    u8int sk[MLKEM768_SECRETKEYBYTES]
);
int mlkem768_enc_derand(
    u8int ct[MLKEM768_CIPHERTEXTBYTES],
    u8int ss[MLKEM_BYTES],
    const u8int pk[MLKEM768_PUBLICKEYBYTES],
    const u8int coins[MLKEM_SYMBYTES]
);
int mlkem768_enc(
    u8int ct[MLKEM768_CIPHERTEXTBYTES],
    u8int ss[MLKEM_BYTES],
    const u8int pk[MLKEM768_PUBLICKEYBYTES]
);
int mlkem768_dec(
    u8int ss[MLKEM_BYTES],
    const u8int ct[MLKEM768_CIPHERTEXTBYTES],
    const u8int sk[MLKEM768_SECRETKEYBYTES]
);
int mlkem768_check_pk(
    const u8int pk[MLKEM768_PUBLICKEYBYTES]
);
int mlkem768_check_sk(
    const u8int sk[MLKEM768_SECRETKEYBYTES]
);
int mlkem1024_keypair_derand(
    u8int pk[MLKEM1024_PUBLICKEYBYTES],
    u8int sk[MLKEM1024_SECRETKEYBYTES],
    const u8int coins[2 * MLKEM_SYMBYTES]
);
int mlkem1024_keypair(
    u8int pk[MLKEM1024_PUBLICKEYBYTES],
    u8int sk[MLKEM1024_SECRETKEYBYTES]
);
int mlkem1024_enc_derand(
    u8int ct[MLKEM1024_CIPHERTEXTBYTES],
    u8int ss[MLKEM_BYTES],
    const u8int pk[MLKEM1024_PUBLICKEYBYTES],
    const u8int coins[MLKEM_SYMBYTES]
);
int mlkem1024_enc(
    u8int ct[MLKEM1024_CIPHERTEXTBYTES],
    u8int ss[MLKEM_BYTES],
    const u8int pk[MLKEM1024_PUBLICKEYBYTES]
);
int mlkem1024_dec(
    u8int ss[MLKEM_BYTES],
    const u8int ct[MLKEM1024_CIPHERTEXTBYTES],
    const u8int sk[MLKEM1024_SECRETKEYBYTES]
);
int mlkem1024_check_pk(
    const u8int pk[MLKEM1024_PUBLICKEYBYTES]
);
int mlkem1024_check_sk(
    const u8int sk[MLKEM1024_SECRETKEYBYTES]
);
