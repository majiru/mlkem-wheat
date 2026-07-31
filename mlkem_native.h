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

/* Sizes of cryptographic material, as a function of LVL=512,768,1024 */
#define MLKEM_SECRETKEYBYTES_(LVL) MLKEM##LVL##_SECRETKEYBYTES
#define MLKEM_PUBLICKEYBYTES_(LVL) MLKEM##LVL##_PUBLICKEYBYTES
#define MLKEM_CIPHERTEXTBYTES_(LVL) MLKEM##LVL##_CIPHERTEXTBYTES
#define MLKEM_SECRETKEYBYTES(LVL) MLKEM_SECRETKEYBYTES_(LVL)
#define MLKEM_PUBLICKEYBYTES(LVL) MLKEM_PUBLICKEYBYTES_(LVL)
#define MLKEM_CIPHERTEXTBYTES(LVL) MLKEM_CIPHERTEXTBYTES_(LVL)

/****************************** Error codes ***********************************/

/* Generic failure condition */
#define MLK_ERR_FAIL -1
/* An allocation failed. This can only happen if MLK_CONFIG_CUSTOM_ALLOC_FREE
 * is defined and the provided MLK_CUSTOM_ALLOC can fail. */
#define MLK_ERR_OUT_OF_MEMORY -2
/* An rng failure occured. Might be due to insufficient entropy or
 * system misconfiguration. */
#define MLK_ERR_RNG_FAIL -3

/****************************** Function API **********************************/

#define MLK_API_CONCAT_(x, y) x##y
#define MLK_API_CONCAT(x, y) MLK_API_CONCAT_(x, y)
#define MLK_API_CONCAT_UNDERSCORE(x, y) MLK_API_CONCAT(MLK_API_CONCAT(x, _), y)

#include "mlkem_native_config.h"

#define MLK_CONFIG_API_PARAMETER_SET MLK_CONFIG_PARAMETER_SET

#define MLK_CONFIG_API_NAMESPACE_PREFIX \
  MLK_API_CONCAT(MLK_CONFIG_NAMESPACE_PREFIX, MLK_CONFIG_PARAMETER_SET)

#define MLK_API_NAMESPACE(sym) \
  MLK_API_CONCAT_UNDERSCORE(MLK_CONFIG_API_NAMESPACE_PREFIX, sym)


/**
 * Generate a public/private keypair for the ML-KEM key encapsulation mechanism.
 *
 * @spec{Implements @[FIPS203, Algorithm 16, ML-KEM.KeyGen_Internal].}
 *
 * @param[out] pk      Output public key, an array of
 *                     MLKEM{512,768,1024}_PUBLICKEYBYTES bytes.
 * @param[out] sk      Output private key, an array of
 *                     MLKEM{512,768,1024}_SECRETKEYBYTES bytes.
 * @param[in]  coins   Input randomness, an array of 2*MLKEM_SYMBYTES uniformly
 *                     random bytes.
 * @param      context Application context. Only present when
 *                     MLK_CONFIG_CONTEXT_PARAMETER is defined; type set by
 *                     MLK_CONFIG_CONTEXT_PARAMETER_TYPE.
 *
 * @retval 0                     Success.
 * @retval MLK_ERR_FAIL          MLK_CONFIG_KEYGEN_PCT enabled and PCT failed.
 * @retval MLK_ERR_OUT_OF_MEMORY MLK_CONFIG_CUSTOM_ALLOC_FREE was used and
 *                               MLK_CUSTOM_ALLOC returned NULL.
 */
int MLK_API_NAMESPACE(keypair_derand)(
    u8int pk[MLKEM_PUBLICKEYBYTES(MLK_CONFIG_API_PARAMETER_SET)],
    u8int sk[MLKEM_SECRETKEYBYTES(MLK_CONFIG_API_PARAMETER_SET)],
    const u8int coins[2 * MLKEM_SYMBYTES]
);

/**
 * Generate a public/private keypair for the ML-KEM key encapsulation mechanism.
 *
 * @spec{Implements @[FIPS203, Algorithm 19, ML-KEM.KeyGen].}
 *
 * @param[out] pk      Output public key, an array of
 *                     MLKEM{512,768,1024}_PUBLICKEYBYTES bytes.
 * @param[out] sk      Output private key, an array of
 *                     MLKEM{512,768,1024}_SECRETKEYBYTES bytes.
 * @param      context Application context. Only present when
 *                     MLK_CONFIG_CONTEXT_PARAMETER is defined; type set by
 *                     MLK_CONFIG_CONTEXT_PARAMETER_TYPE.
 *
 * @retval 0                     Success.
 * @retval MLK_ERR_FAIL          MLK_CONFIG_KEYGEN_PCT enabled and PCT failed.
 * @retval MLK_ERR_OUT_OF_MEMORY MLK_CONFIG_CUSTOM_ALLOC_FREE was used and
 *                               MLK_CUSTOM_ALLOC returned NULL.
 * @retval MLK_ERR_RNG_FAIL      Random number generation failed.
 */
int MLK_API_NAMESPACE(keypair)(
    u8int pk[MLKEM_PUBLICKEYBYTES(MLK_CONFIG_API_PARAMETER_SET)],
    u8int sk[MLKEM_SECRETKEYBYTES(MLK_CONFIG_API_PARAMETER_SET)]
);

/**
 * Generate ciphertext and shared secret for a given public key.
 *
 * @spec{Implements @[FIPS203, Algorithm 17, ML-KEM.Encaps_Internal].}
 *
 * @param[out] ct      Output ciphertext, an array of
 *                     MLKEM{512,768,1024}_CIPHERTEXTBYTES bytes.
 * @param[out] ss      Output shared secret, an array of MLKEM_BYTES bytes.
 * @param[in]  pk      Input public key, an array of
 *                     MLKEM{512,768,1024}_PUBLICKEYBYTES bytes.
 * @param[in]  coins   Input randomness, an array of MLKEM_SYMBYTES bytes.
 * @param      context Application context. Only present when
 *                     MLK_CONFIG_CONTEXT_PARAMETER is defined; type set by
 *                     MLK_CONFIG_CONTEXT_PARAMETER_TYPE.
 *
 * @retval 0                     Success.
 * @retval MLK_ERR_FAIL          The 'modulus check' @[FIPS203, Section 7.2]
 *                               for the public key failed.
 * @retval MLK_ERR_OUT_OF_MEMORY MLK_CONFIG_CUSTOM_ALLOC_FREE was used and
 *                               MLK_CUSTOM_ALLOC returned NULL.
 */
int MLK_API_NAMESPACE(enc_derand)(
    u8int ct[MLKEM_CIPHERTEXTBYTES(MLK_CONFIG_API_PARAMETER_SET)],
    u8int ss[MLKEM_BYTES],
    const u8int pk[MLKEM_PUBLICKEYBYTES(MLK_CONFIG_API_PARAMETER_SET)],
    const u8int coins[MLKEM_SYMBYTES]
);

/**
 * Generate ciphertext and shared secret for a given public key.
 *
 * @spec{Implements @[FIPS203, Algorithm 20, ML-KEM.Encaps].}
 *
 * @param[out] ct      Output ciphertext, an array of
 *                     MLKEM{512,768,1024}_CIPHERTEXTBYTES bytes.
 * @param[out] ss      Output shared secret, an array of MLKEM_BYTES bytes.
 * @param[in]  pk      Input public key, an array of
 *                     MLKEM{512,768,1024}_PUBLICKEYBYTES bytes.
 * @param      context Application context. Only present when
 *                     MLK_CONFIG_CONTEXT_PARAMETER is defined; type set by
 *                     MLK_CONFIG_CONTEXT_PARAMETER_TYPE.
 *
 * @retval 0                     Success.
 * @retval MLK_ERR_FAIL          The 'modulus check' @[FIPS203, Section 7.2]
 *                               for the public key failed.
 * @retval MLK_ERR_OUT_OF_MEMORY MLK_CONFIG_CUSTOM_ALLOC_FREE was used and
 *                               MLK_CUSTOM_ALLOC returned NULL.
 * @retval MLK_ERR_RNG_FAIL      Random number generation failed.
 */
int MLK_API_NAMESPACE(enc)(
    u8int ct[MLKEM_CIPHERTEXTBYTES(MLK_CONFIG_API_PARAMETER_SET)],
    u8int ss[MLKEM_BYTES],
    const u8int pk[MLKEM_PUBLICKEYBYTES(MLK_CONFIG_API_PARAMETER_SET)]
);

/**
 * Generate shared secret for a given ciphertext and private key.
 *
 * @spec{Implements @[FIPS203, Algorithm 21, ML-KEM.Decaps].}
 *
 * @param[out] ss      Output shared secret, an array of MLKEM_BYTES bytes.
 * @param[in]  ct      Input ciphertext, an array of
 *                     MLKEM{512,768,1024}_CIPHERTEXTBYTES bytes.
 * @param[in]  sk      Input private key, an array of
 *                     MLKEM{512,768,1024}_SECRETKEYBYTES bytes.
 * @param      context Application context. Only present when
 *                     MLK_CONFIG_CONTEXT_PARAMETER is defined; type set by
 *                     MLK_CONFIG_CONTEXT_PARAMETER_TYPE.
 *
 * @retval 0                     Success.
 * @retval MLK_ERR_FAIL          The 'hash check' @[FIPS203, Section 7.3]
 *                               for the secret key failed.
 * @retval MLK_ERR_OUT_OF_MEMORY MLK_CONFIG_CUSTOM_ALLOC_FREE was used and
 *                               MLK_CUSTOM_ALLOC returned NULL.
 */
int MLK_API_NAMESPACE(dec)(
    u8int ss[MLKEM_BYTES],
    const u8int ct[MLKEM_CIPHERTEXTBYTES(MLK_CONFIG_API_PARAMETER_SET)],
    const u8int sk[MLKEM_SECRETKEYBYTES(MLK_CONFIG_API_PARAMETER_SET)]
);


/**
 * Implements modulus check mandated by FIPS 203, i.e., ensures that
 * coefficients are in [0,q-1].
 *
 * @spec{Implements @[FIPS203, Section 7.2, 'modulus check'].}
 *
 * @param[in] pk      Input public key, an array of
 *                    MLKEM{512,768,1024}_PUBLICKEYBYTES bytes.
 * @param     context Application context. Only present when
 *                    MLK_CONFIG_CONTEXT_PARAMETER is defined; type set by
 *                    MLK_CONFIG_CONTEXT_PARAMETER_TYPE.
 *
 * @retval 0                     Success.
 * @retval MLK_ERR_FAIL          Modulus check failed.
 * @retval MLK_ERR_OUT_OF_MEMORY MLK_CONFIG_CUSTOM_ALLOC_FREE was used and
 *                               MLK_CUSTOM_ALLOC returned NULL.
 */
int MLK_API_NAMESPACE(check_pk)(
    const u8int pk[MLKEM_PUBLICKEYBYTES(MLK_CONFIG_API_PARAMETER_SET)]
);

/**
 * Implements public key hash check mandated by FIPS 203, i.e., ensures that
 * sk[768𝑘+32 ∶ 768𝑘+64] = H(pk) = H(sk[384𝑘 : 768𝑘+32]).
 *
 * @spec{Implements @[FIPS203, Section 7.3, 'hash check'].}
 *
 * @param[in] sk      Input private key, an array of
 *                    MLKEM{512,768,1024}_SECRETKEYBYTES bytes.
 * @param     context Application context. Only present when
 *                    MLK_CONFIG_CONTEXT_PARAMETER is defined; type set by
 *                    MLK_CONFIG_CONTEXT_PARAMETER_TYPE.
 *
 * @retval 0                     Success.
 * @retval MLK_ERR_FAIL          Public key hash check failed.
 * @retval MLK_ERR_OUT_OF_MEMORY MLK_CONFIG_CUSTOM_ALLOC_FREE was used and
 *                               MLK_CUSTOM_ALLOC returned NULL.
 */
int MLK_API_NAMESPACE(check_sk)(
    const u8int sk[MLKEM_SECRETKEYBYTES(MLK_CONFIG_API_PARAMETER_SET)]
);

#undef MLK_CONFIG_API_PARAMETER_SET
#undef MLK_CONFIG_API_NAMESPACE_PREFIX
#undef MLK_CONFIG_API_QUALIFIER
#undef MLK_API_CONCAT
#undef MLK_API_CONCAT_
#undef MLK_API_CONCAT_UNDERSCORE
#undef MLK_API_NAMESPACE
