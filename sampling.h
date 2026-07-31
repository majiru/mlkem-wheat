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

/**
 * Given an array of uniformly random bytes, compute a polynomial with
 * coefficients distributed according to a centered binomial distribution
 * with parameter eta=2.
 *
 * @spec{Implements @[FIPS203, Algorithm 8, SamplePolyCBD_2].}
 *
 * @param[out] r   Output polynomial.
 * @param[in]  buf Input byte array.
 */
MLK_INTERNAL_API
void mlk_poly_cbd2(mlk_poly *r, const u8int buf[2 * MLKEM_N / 4]);

/**
 * Given an array of uniformly random bytes, compute a polynomial with
 * coefficients distributed according to a centered binomial distribution
 * with parameter eta=3.
 *
 * This function is only needed for ML-KEM-512.
 *
 * @spec{Implements @[FIPS203, Algorithm 8, SamplePolyCBD_3].}
 *
 * @param[out] r   Output polynomial.
 * @param[in]  buf Input byte array.
 */
MLK_INTERNAL_API
void mlk_poly_cbd3(mlk_poly *r, const u8int buf[3 * MLKEM_N / 4]);

/**
 * Generate a polynomial using rejection sampling on (pseudo-)uniformly
 * random bytes sampled from a seed.
 *
 * @spec{Implements @[FIPS203, Algorithm 7, SampleNTT].}
 *
 * @param[out] entry Polynomial to be sampled.
 * @param[in]  seed  Seed buffer of size MLKEM_SYMBYTES + 2.
 */
MLK_INTERNAL_API
void mlk_poly_rej_uniform(mlk_poly *entry, u8int seed[MLKEM_SYMBYTES + 2]);

