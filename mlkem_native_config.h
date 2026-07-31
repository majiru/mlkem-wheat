/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [FIPS140_3_IG]
 *   Implementation Guidance for FIPS 140-3 and the Cryptographic Module
 *   Validation Program
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-ig-announcements
 *
 * - [FIPS203]
 *   FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/pubs/fips/203/final
 */

/*
 * Test configuration: Multilevel build config
 *
 * This configuration differs from the default mlkem/mlkem_native_config.h in
 * the following places:
 *   - MLK_CONFIG_NO_SUPERCOP
 *   - MLK_CONFIG_MULTILEVEL_BUILD
 *   - MLK_CONFIG_NAMESPACE_PREFIX
 */


#ifndef MLK_CONFIG_H
#define MLK_CONFIG_H

/**
 * The prefix to use to namespace global symbols from mlkem/.
 *
 * In a multi-level build, level-dependent symbols will additionally be
 * prefixed with the parameter set (512/768/1024).
 *
 * This can also be set using CFLAGS.
 */
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem

/**
 * MLK_CONFIG_MULTILEVEL_BUILD
 *
 * Set this if the build is part of a multi-level build supporting multiple
 * parameter sets.
 *
 * If you need only a single parameter set, keep this unset.
 *
 * To build mlkem-native with support for all parameter sets, build it three
 * times -- once per parameter set -- and set the option
 * MLK_CONFIG_MULTILEVEL_WITH_SHARED for exactly one of them, and
 * MLK_CONFIG_MULTILEVEL_NO_SHARED for the others.
 * MLK_CONFIG_MULTILEVEL_BUILD should be set for all of them.
 *
 * See examples/multilevel_build for an example.
 *
 * This can also be set using CFLAGS.
 */
#define MLK_CONFIG_MULTILEVEL_BUILD

/******************************************************************************
 *
 * Build-only configuration options
 *
 * The remaining configurations are build-options only.
 * They do not affect the API described in mlkem_native.h.
 *
 *****************************************************************************/

#ifdef MLK_BUILD_INTERNAL

/**
 * MLK_CONFIG_KEYGEN_PCT
 *
 * Compliance with @[FIPS140_3_IG, p.87] requires a Pairwise Consistency
 * Test (PCT) to be carried out on a freshly generated keypair before it
 * can be exported.
 *
 * Set this option if such a check should be implemented. In this case,
 * crypto_kem_keypair_derand and crypto_kem_keypair will return a non-zero
 * error code if the PCT failed.
 *
 * @note This feature will drastically lower the performance of key
 *       generation.
 */
/* #define MLK_CONFIG_KEYGEN_PCT */

/**
 * MLK_CONFIG_KEYGEN_PCT_BREAKAGE_TEST
 *
 * If this option is set, the user must provide a runtime function
 * `static inline int mlk_break_pct() { ... }` to indicate whether the PCT
 * should be made to fail.
 *
 * This option only has an effect if MLK_CONFIG_KEYGEN_PCT is set.
 */
/* #define MLK_CONFIG_KEYGEN_PCT_BREAKAGE_TEST
   static MLK_INLINE int mlk_break_pct(void)
   {
       ... return 0/1 depending on whether PCT should be broken ...
   }
*/

#endif /* MLK_BUILD_INTERNAL */

#endif /* !MLK_CONFIG_H */
