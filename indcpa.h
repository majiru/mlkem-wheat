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

#define mlk_gen_matrix MLK_NAMESPACE_K(gen_matrix)
/**
 * Deterministically generate matrix A (or the transpose of A) from a seed.
 * Entries of the matrix are polynomials that look uniformly random.
 * Performs rejection sampling on the output of an XOF.
 *
 * @spec{Implements @[FIPS203, Algorithm 13 (K-PKE.KeyGen), L3-7] and
 * @[FIPS203, Algorithm 14 (K-PKE.Encrypt), L4-8]. The @p transposed
 * parameter only affects internal presentation.}
 *
 * @param[out] a          Output matrix A.
 * @param[in]  seed       Input seed.
 * @param      transposed Boolean deciding whether A or A^T is generated.
 */
MLK_INTERNAL_API
void mlk_gen_matrix(mlk_polymat *a, const u8int seed[MLKEM_SYMBYTES],
                    int transposed);

#define mlk_indcpa_keypair_derand \
  MLK_NAMESPACE_K(indcpa_keypair_derand) MLK_CONTEXT_PARAMETERS_3
/**
 * Generate public and private key for the CPA-secure public-key encryption
 * scheme underlying ML-KEM.
 *
 * @spec{Implements @[FIPS203, Algorithm 13 (K-PKE.KeyGen)].}
 *
 * @param[out] pk      Output public key
 *                     (length MLKEM_INDCPA_PUBLICKEYBYTES bytes).
 * @param[out] sk      Output private key
 *                     (length MLKEM_INDCPA_SECRETKEYBYTES bytes).
 * @param[in]  coins   Input randomness (length MLKEM_SYMBYTES bytes).
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
MLK_INTERNAL_API
int mlk_indcpa_keypair_derand(u8int pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                              u8int sk[MLKEM_INDCPA_SECRETKEYBYTES],
                              const u8int coins[MLKEM_SYMBYTES],
                              MLK_CONFIG_CONTEXT_PARAMETER_TYPE context);

#define mlk_indcpa_enc MLK_NAMESPACE_K(indcpa_enc) MLK_CONTEXT_PARAMETERS_4
/**
 * Encryption function of the CPA-secure public-key encryption scheme
 * underlying ML-KEM.
 *
 * @spec{Implements @[FIPS203, Algorithm 14 (K-PKE.Encrypt)].}
 *
 * @param[out] c       Output ciphertext (length MLKEM_INDCPA_BYTES bytes).
 * @param[in]  m       Input message (length MLKEM_INDCPA_MSGBYTES bytes).
 * @param[in]  pk      Input public key
 *                     (length MLKEM_INDCPA_PUBLICKEYBYTES bytes).
 * @param[in]  coins   Input random coins used as seed (length MLKEM_SYMBYTES
 *                     bytes) to deterministically generate all randomness.
 * @param      context Application context. Only present when
 *                     MLK_CONFIG_CONTEXT_PARAMETER is defined; type set by
 *                     MLK_CONFIG_CONTEXT_PARAMETER_TYPE.
 *
 * @retval 0                     Success.
 * @retval MLK_ERR_FAIL          Operation failed.
 * @retval MLK_ERR_OUT_OF_MEMORY MLK_CONFIG_CUSTOM_ALLOC_FREE was used and
 *                               MLK_CUSTOM_ALLOC returned NULL.
 */
MLK_INTERNAL_API
int mlk_indcpa_enc(u8int c[MLKEM_INDCPA_BYTES],
                   const u8int m[MLKEM_INDCPA_MSGBYTES],
                   const u8int pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                   const u8int coins[MLKEM_SYMBYTES],
                   MLK_CONFIG_CONTEXT_PARAMETER_TYPE context);

#define mlk_indcpa_dec MLK_NAMESPACE_K(indcpa_dec) MLK_CONTEXT_PARAMETERS_3
/**
 * Decryption function of the CPA-secure public-key encryption scheme
 * underlying ML-KEM.
 *
 * @spec{Implements @[FIPS203, Algorithm 15 (K-PKE.Decrypt)].}
 *
 * @param[out] m       Output decrypted message
 *                     (length MLKEM_INDCPA_MSGBYTES bytes).
 * @param[in]  c       Input ciphertext (length MLKEM_INDCPA_BYTES bytes).
 * @param[in]  sk      Input secret key
 *                     (length MLKEM_INDCPA_SECRETKEYBYTES bytes).
 * @param      context Application context. Only present when
 *                     MLK_CONFIG_CONTEXT_PARAMETER is defined; type set by
 *                     MLK_CONFIG_CONTEXT_PARAMETER_TYPE.
 *
 * @retval 0                     Success.
 * @retval MLK_ERR_FAIL          Operation failed.
 * @retval MLK_ERR_OUT_OF_MEMORY MLK_CONFIG_CUSTOM_ALLOC_FREE was used and
 *                               MLK_CUSTOM_ALLOC returned NULL.
 */
MLK_INTERNAL_API
int mlk_indcpa_dec(u8int m[MLKEM_INDCPA_MSGBYTES],
                   const u8int c[MLKEM_INDCPA_BYTES],
                   const u8int sk[MLKEM_INDCPA_SECRETKEYBYTES],
                   MLK_CONFIG_CONTEXT_PARAMETER_TYPE context);
