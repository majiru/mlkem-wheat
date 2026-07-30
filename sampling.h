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

#ifndef MLK_SAMPLING_H
#define MLK_SAMPLING_H

#include "common.h"
#include "poly.h"

#define mlk_poly_cbd2 MLK_NAMESPACE(poly_cbd2)
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

#if defined(MLK_CONFIG_MULTILEVEL_WITH_SHARED) || MLKEM_ETA1 == 3
#define mlk_poly_cbd3 MLK_NAMESPACE(poly_cbd3)
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
#endif /* MLK_CONFIG_MULTILEVEL_WITH_SHARED || MLKEM_ETA1 == 3 */

#define mlk_poly_rej_uniform MLK_NAMESPACE(poly_rej_uniform)
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

#endif /* !MLK_SAMPLING_H */
