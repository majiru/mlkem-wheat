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
 *
 * - [REF]
 *   CRYSTALS-Kyber C reference implementation
 *   Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schanck, Schwabe, Seiler, Stehlé
 *   https://github.com/pq-crystals/kyber/tree/main/ref
 */

#include "common.h"
#include "verify.h"
#include "debug.h"
#include "randombytes.h"
#include "fips202.h"
#include "symmetric.h"
#include "poly.h"
#include "compress.h"
#include "ns.h"
#include "params.h"
#include "poly_k.h"
#include "indcpa.h"
#include "kem.h"

/* Parameter set namespacing
 * This is to facilitate building multiple instances
 * of mlkem-native (e.g. with varying security levels)
 * within a single compilation unit. */
#define mlk_check_pct MLK_ADD_PARAM_SET(mlk_check_pct)
/* End of parameter set namespacing */

/* Reference: Not implemented in the reference implementation @[REF]. */
MLK_EXTERNAL_API
int mlk_kem_check_pk(const u8int pk[MLKEM_INDCCA_PUBLICKEYBYTES])
{
  int ret;
  MLK_ALLOC(p, mlk_polyvec, 1);
  MLK_ALLOC(p_reencoded, u8int, MLKEM_POLYVECBYTES);

  if (p == NULL || p_reencoded == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  mlk_polyvec_frombytes(p, pk);
  mlk_polyvec_reduce(p);
  mlk_polyvec_tobytes(p_reencoded, p);

  /* We use a constant-time memcmp here to avoid having to
   * declassify the PK before the PCT has succeeded. */
  ret = mlk_ct_memcmp(pk, p_reencoded, MLKEM_POLYVECBYTES) ? MLK_ERR_FAIL : 0;

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(p_reencoded, u8int, MLKEM_POLYVECBYTES);
  MLK_FREE(p, mlk_polyvec, 1);
  return ret;
}


/* Reference: Not implemented in the reference implementation @[REF]. */
MLK_EXTERNAL_API
int mlk_kem_check_sk(const u8int sk[MLKEM_INDCCA_SECRETKEYBYTES])
{
  int ret;
  MLK_ALLOC(test, u8int, MLKEM_SYMBYTES);

  if (test == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /*
   * The parts of `sk` being hashed and compared here are public, so
   * no public information is leaked through the runtime or the return value
   * of this function.
   */

  mlk_hash_h(test, sk + MLKEM_INDCPA_SECRETKEYBYTES,
             MLKEM_INDCCA_PUBLICKEYBYTES);
  /* This doesn't have to be a constant-time memcmp, but it's the only place
   * in the library where a normal memcmp would be used otherwise, so for sake
   * of minimizing stdlib dependency, we use our constant-time one anyway. */
  ret = mlk_ct_memcmp(sk + MLKEM_INDCCA_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES,
                      test, MLKEM_SYMBYTES)
            ? MLK_ERR_FAIL
            : 0;

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(test, u8int, MLKEM_SYMBYTES);
  return ret;
}

static int mlk_check_pct(u8int const pk[MLKEM_INDCCA_PUBLICKEYBYTES],
                         u8int const sk[MLKEM_INDCCA_SECRETKEYBYTES]);

#if defined(MLK_CONFIG_KEYGEN_PCT)
/* Specification:
 * Partially implements 'Pairwise Consistency Test' @[FIPS140_3_IG, p.87] and
 * @[FIPS203, Section 7.1, Pairwise Consistency]. */

/* Reference: Not implemented in the reference implementation @[REF]. */
static int mlk_check_pct(u8int const pk[MLKEM_INDCCA_PUBLICKEYBYTES],
                         u8int const sk[MLKEM_INDCCA_SECRETKEYBYTES])
{
  int ret = 0;
  MLK_ALLOC(ct, u8int, MLKEM_INDCCA_CIPHERTEXTBYTES);
  MLK_ALLOC(ss_enc, u8int, MLKEM_SSBYTES);
  MLK_ALLOC(ss_dec, u8int, MLKEM_SSBYTES);

  if (ct == NULL || ss_enc == NULL || ss_dec == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  ret = mlk_kem_enc(ct, ss_enc, pk);
  if (ret != 0)
  {
    goto cleanup;
  }

  ret = mlk_kem_dec(ss_dec, ct, sk);
  if (ret != 0)
  {
    goto cleanup;
  }

#if defined(MLK_CONFIG_KEYGEN_PCT_BREAKAGE_TEST)
  /* Deliberately break PCT for testing purposes */
  if (mlk_break_pct())
  {
    ss_enc[0] = ~ss_enc[0];
  }
#endif /* MLK_CONFIG_KEYGEN_PCT_BREAKAGE_TEST */

  ret = mlk_ct_memcmp(ss_enc, ss_dec, MLKEM_SSBYTES);

  if (ret != 0)
  {
    ret = MLK_ERR_FAIL;
  }

cleanup:

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(ss_dec, u8int, MLKEM_SSBYTES);
  MLK_FREE(ss_enc, u8int, MLKEM_SSBYTES);
  MLK_FREE(ct, u8int, MLKEM_INDCCA_CIPHERTEXTBYTES);
  return ret;
}
#else /* MLK_CONFIG_KEYGEN_PCT */
static int mlk_check_pct(u8int const pk[MLKEM_INDCCA_PUBLICKEYBYTES],
                         u8int const sk[MLKEM_INDCCA_SECRETKEYBYTES])
{
  USED(pk);
  USED(sk);
  return 0;
}
#endif /* !MLK_CONFIG_KEYGEN_PCT */

/* Reference: `crypto_kem_keypair_derand()` in the reference implementation
 *            @[REF].
 *            - We optionally include PCT which is not present in
 *              the reference code. */
MLK_EXTERNAL_API
int mlk_kem_keypair_derand(u8int pk[MLKEM_INDCCA_PUBLICKEYBYTES],
                           u8int sk[MLKEM_INDCCA_SECRETKEYBYTES],
                           const u8int coins[2 * MLKEM_SYMBYTES])
{
  int ret;

  ret = mlk_indcpa_keypair_derand(pk, sk, coins);
  if (ret != 0)
  {
    goto cleanup;
  }

  mlk_memcpy(sk + MLKEM_INDCPA_SECRETKEYBYTES, pk, MLKEM_INDCCA_PUBLICKEYBYTES);
  mlk_hash_h(sk + MLKEM_INDCCA_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES, pk,
             MLKEM_INDCCA_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  mlk_memcpy(sk + MLKEM_INDCCA_SECRETKEYBYTES - MLKEM_SYMBYTES,
             coins + MLKEM_SYMBYTES, MLKEM_SYMBYTES);

  /* Pairwise Consistency Test (PCT) @[FIPS140_3_IG, p.87] */
  ret = mlk_check_pct(pk, sk);
  if (ret != 0)
  {
    goto cleanup;
  }

cleanup:
  if (ret != 0)
  {
    mlk_zeroize(pk, MLKEM_INDCCA_PUBLICKEYBYTES);
    mlk_zeroize(sk, MLKEM_INDCCA_SECRETKEYBYTES);
  }

  return ret;
}

MLK_EXTERNAL_API
int mlk_kem_keypair(u8int pk[MLKEM_INDCCA_PUBLICKEYBYTES],
                    u8int sk[MLKEM_INDCCA_SECRETKEYBYTES])
{
  int ret;
  MLK_ALLOC(coins, u8int, 2 * MLKEM_SYMBYTES);

  if (coins == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Acquire necessary randomness, and mark it as secret. */
  if (mlk_randombytes(coins, 2 * MLKEM_SYMBYTES) != 0)
  {
    ret = MLK_ERR_RNG_FAIL;
    goto cleanup;
  }

  ret = mlk_kem_keypair_derand(pk, sk, coins);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(coins, u8int, 2 * MLKEM_SYMBYTES);
  return ret;
}

/* Reference: `crypto_kem_enc_derand()` in the reference implementation @[REF]
 *            - We include public key check
 *            - We include stack buffer zeroization */
MLK_EXTERNAL_API
int mlk_kem_enc_derand(u8int ct[MLKEM_INDCCA_CIPHERTEXTBYTES],
                       u8int ss[MLKEM_SSBYTES],
                       const u8int pk[MLKEM_INDCCA_PUBLICKEYBYTES],
                       const u8int coins[MLKEM_SYMBYTES])
{
  int ret;
  MLK_ALLOC(buf, u8int, 2 * MLKEM_SYMBYTES);
  MLK_ALLOC(kr, u8int, 2 * MLKEM_SYMBYTES);

  if (buf == NULL || kr == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Specification: Implements @[FIPS203, Section 7.2, Modulus check] */
  ret = mlk_kem_check_pk(pk);
  if (ret != 0)
  {
    goto cleanup;
  }

  mlk_memcpy(buf, coins, MLKEM_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  mlk_hash_h(buf + MLKEM_SYMBYTES, pk, MLKEM_INDCCA_PUBLICKEYBYTES);
  mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

  /* coins are in kr+MLKEM_SYMBYTES */
  ret = mlk_indcpa_enc(ct, buf, pk, kr + MLKEM_SYMBYTES);
  if (ret != 0)
  {
    goto cleanup;
  }

  mlk_memcpy(ss, kr, MLKEM_SYMBYTES);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(kr, u8int, 2 * MLKEM_SYMBYTES);
  MLK_FREE(buf, u8int, 2 * MLKEM_SYMBYTES);
  return ret;
}

/* Reference: `crypto_kem_enc()` in the reference implementation @[REF]
 *            - We include stack buffer zeroization */
MLK_EXTERNAL_API
int mlk_kem_enc(u8int ct[MLKEM_INDCCA_CIPHERTEXTBYTES],
                u8int ss[MLKEM_SSBYTES],
                const u8int pk[MLKEM_INDCCA_PUBLICKEYBYTES])
{
  int ret;
  MLK_ALLOC(coins, u8int, MLKEM_SYMBYTES);

  if (coins == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  if (mlk_randombytes(coins, MLKEM_SYMBYTES) != 0)
  {
    ret = MLK_ERR_RNG_FAIL;
    goto cleanup;
  }

  ret = mlk_kem_enc_derand(ct, ss, pk, coins);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(coins, u8int, MLKEM_SYMBYTES);
  return ret;
}

/* Reference: `crypto_kem_dec()` in the reference implementation @[REF]
 *            - We include secret key check
 *            - We include stack buffer zeroization */
MLK_EXTERNAL_API
int mlk_kem_dec(u8int ss[MLKEM_SSBYTES],
                const u8int ct[MLKEM_INDCCA_CIPHERTEXTBYTES],
                const u8int sk[MLKEM_INDCCA_SECRETKEYBYTES])
{
  int ret;
  u8int fail;
  const u8int *pk = sk + MLKEM_INDCPA_SECRETKEYBYTES;
  MLK_ALLOC(buf, u8int, 2 * MLKEM_SYMBYTES);
  MLK_ALLOC(kr, u8int, 2 * MLKEM_SYMBYTES);
  MLK_ALLOC(tmp, u8int, MLKEM_SYMBYTES + MLKEM_INDCCA_CIPHERTEXTBYTES);

  if (buf == NULL || kr == NULL || tmp == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Specification: Implements @[FIPS203, Section 7.3, Hash check] */
  ret = mlk_kem_check_sk(sk);
  if (ret != 0)
  {
    goto cleanup;
  }

  ret = mlk_indcpa_dec(buf, ct, sk);
  if (ret != 0)
  {
    goto cleanup;
  }

  /* Multitarget countermeasure for coins + contributory KEM */
  mlk_memcpy(buf + MLKEM_SYMBYTES,
             sk + MLKEM_INDCCA_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES,
             MLKEM_SYMBYTES);
  mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

  /* Recompute and compare ciphertext */
  /* coins are in kr+MLKEM_SYMBYTES */
  ret = mlk_indcpa_enc(tmp, buf, pk, kr + MLKEM_SYMBYTES);
  if (ret != 0)
  {
    goto cleanup;
  }

  fail = mlk_ct_memcmp(ct, tmp, MLKEM_INDCCA_CIPHERTEXTBYTES);

  /* Compute rejection key */
  mlk_memcpy(tmp, sk + MLKEM_INDCCA_SECRETKEYBYTES - MLKEM_SYMBYTES,
             MLKEM_SYMBYTES);
  mlk_memcpy(tmp + MLKEM_SYMBYTES, ct, MLKEM_INDCCA_CIPHERTEXTBYTES);
  mlk_hash_j(ss, tmp, MLKEM_SYMBYTES + MLKEM_INDCCA_CIPHERTEXTBYTES);

  /* Copy true key to return buffer if fail is 0 */
  mlk_ct_cmov_zero(ss, kr, MLKEM_SYMBYTES, fail);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(tmp, u8int, MLKEM_SYMBYTES + MLKEM_INDCCA_CIPHERTEXTBYTES);
  MLK_FREE(kr, u8int, 2 * MLKEM_SYMBYTES);
  MLK_FREE(buf, u8int, 2 * MLKEM_SYMBYTES);

  return ret;
}

/* To facilitate single-compilation-unit (SCU) builds, undefine all macros.
 * Don't modify by hand -- this is auto-generated by scripts/autogen. */
#undef mlk_check_pct
