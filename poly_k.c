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
 *
 * - [NeonNTT]
 *   Neon NTT: Faster Dilithium, Kyber, and Saber on Cortex-A72 and Apple M1
 *   Becker, Hwang, Kannwischer, Yang, Yang
 *   https://eprint.iacr.org/2021/986
 *
 * - [REF]
 *   CRYSTALS-Kyber C reference implementation
 *   Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schanck, Schwabe, Seiler, Stehlé
 *   https://github.com/pq-crystals/kyber/tree/main/ref
 */

#include "common.h"
#include "debug.h"
#include "verify.h"
#include "fips202.h"
#include "symmetric.h"
#include "poly.h"
#include "sampling.h"
#include "compress.h"
#include "ns.h"
#include "params.h"
#include "poly_k.h"

/* Parameter set namespacing
 * This is to facilitate building multiple instances
 * of mlkem-native (e.g. with varying parameter sets)
 * within a single compilation unit. */
#define mlk_poly_cbd_eta1 MLK_ADD_PARAM_SET(mlk_poly_cbd_eta1)
#define mlk_poly_cbd_eta2 MLK_ADD_PARAM_SET(mlk_poly_cbd_eta2)
#define mlk_polyvec_basemul_acc_montgomery_cached_c \
  MLK_ADD_PARAM_SET(mlk_polyvec_basemul_acc_montgomery_cached_c)
/* End of parameter set namespacing */

/**
 * Compression (du bits) and subsequent serialization of a polynomial.
 *
 * @spec{Implements `ByteEncode_{d_u} (Compress_{d_u} (u))` in @[FIPS203,
 * Algorithm 14 (K-PKE.Encrypt), L22], with level-specific d_u defined in
 * @[FIPS203, Table 2], and given by MLKEM_DU here.}
 *
 * @param[out] r Output byte array (of length MLKEM_POLYCOMPRESSEDBYTES_DU
 *               bytes).
 * @param[in]  a Input polynomial. Coefficients must be unsigned canonical,
 *               i.e. in [0,1,..,MLKEM_Q-1].
 */
void mlk_poly_compress_du(
    u8int r[MLKEM_POLYCOMPRESSEDBYTES_DU], const mlk_poly *a)
{
#if MLKEM_DU == 10
  mlk_poly_compress_d10(r, a);
#elif MLKEM_DU == 11
  mlk_poly_compress_d11(r, a);
#else
#error "Invalid value of MLKEM_DU"
#endif
}

/**
 * De-serialization and subsequent decompression (du bits) of a polynomial;
 * approximate inverse of mlk_poly_compress_du.
 *
 * Upon return, the coefficients of the output polynomial are
 * unsigned-canonical (non-negative and smaller than MLKEM_Q).
 *
 * @spec{Implements `Decompress_{d_u} (ByteDecode_{d_u} (u))` in @[FIPS203,
 * Algorithm 15 (K-PKE.Decrypt), L3], with level-specific d_u defined in
 * @[FIPS203, Table 2], and given by MLKEM_DU here.}
 *
 * @param[out] r Output polynomial.
 * @param[in]  a Input byte array (of length MLKEM_POLYCOMPRESSEDBYTES_DU
 *               bytes).
 */
void mlk_poly_decompress_du(
    mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_DU])
{
#if MLKEM_DU == 10
  mlk_poly_decompress_d10(r, a);
#elif MLKEM_DU == 11
  mlk_poly_decompress_d11(r, a);
#else
#error "Invalid value of MLKEM_DU"
#endif
}

/**
 * Compression (dv bits) and subsequent serialization of a polynomial.
 *
 * @spec{Implements `ByteEncode_{d_v} (Compress_{d_v} (v))` in @[FIPS203,
 * Algorithm 14 (K-PKE.Encrypt), L23], with level-specific d_v defined in
 * @[FIPS203, Table 2], and given by MLKEM_DV here.}
 *
 * @param[out] r Output byte array (of length MLKEM_POLYCOMPRESSEDBYTES_DV
 *               bytes).
 * @param[in]  a Input polynomial. Coefficients must be unsigned canonical,
 *               i.e. in [0,1,..,MLKEM_Q-1].
 */
void mlk_poly_compress_dv(
    u8int r[MLKEM_POLYCOMPRESSEDBYTES_DV], const mlk_poly *a)
{
#if MLKEM_DV == 4
  mlk_poly_compress_d4(r, a);
#elif MLKEM_DV == 5
  mlk_poly_compress_d5(r, a);
#else
#error "Invalid value of MLKEM_DV"
#endif
}

/**
 * De-serialization and subsequent decompression (dv bits) of a polynomial;
 * approximate inverse of mlk_poly_compress_dv.
 *
 * Upon return, the coefficients of the output polynomial are
 * unsigned-canonical (non-negative and smaller than MLKEM_Q).
 *
 * @spec{Implements `Decompress_{d_v} (ByteDecode_{d_v} (v))` in @[FIPS203,
 * Algorithm 15 (K-PKE.Decrypt), L4], with level-specific d_v defined in
 * @[FIPS203, Table 2], and given by MLKEM_DV here.}
 *
 * @param[out] r Output polynomial.
 * @param[in]  a Input byte array (of length MLKEM_POLYCOMPRESSEDBYTES_DV
 *               bytes).
 */
void mlk_poly_decompress_dv(
    mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_DV])
{
#if MLKEM_DV == 4
  mlk_poly_decompress_d4(r, a);
#elif MLKEM_DV == 5
  mlk_poly_decompress_d5(r, a);
#else
#error "Invalid value of MLKEM_DV"
#endif
}


/* Reference: `polyvec_compress()` in the reference implementation @[REF]
 *            - In contrast to the reference implementation, we assume
 *              unsigned canonical coefficients here.
 *              The reference implementation works with coefficients
 *              in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
MLK_INTERNAL_API
void mlk_polyvec_compress_du(u8int r[MLKEM_POLYVECCOMPRESSEDBYTES_DU],
                             const mlk_polyvec *a)
{
  unsigned i;
  mlk_assert_bound_2d(a->vec, MLKEM_K, MLKEM_N, 0, MLKEM_Q);

  for (i = 0; i < MLKEM_K; i++)
  {
    mlk_poly_compress_du(r + i * MLKEM_POLYCOMPRESSEDBYTES_DU, &a->vec[i]);
  }
}

/* Reference: `polyvec_decompress()` in the reference implementation @[REF]. */
MLK_INTERNAL_API
void mlk_polyvec_decompress_du(mlk_polyvec *r,
                               const u8int a[MLKEM_POLYVECCOMPRESSEDBYTES_DU])
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++)
  {
    mlk_poly_decompress_du(&r->vec[i], a + i * MLKEM_POLYCOMPRESSEDBYTES_DU);
  }

  mlk_assert_bound_2d(r->vec, MLKEM_K, MLKEM_N, 0, MLKEM_Q);
}

/* Reference: `polyvec_tobytes()` in the reference implementation @[REF].
 *            - In contrast to the reference implementation, we assume
 *              unsigned canonical coefficients here.
 *              The reference implementation works with coefficients
 *              in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
MLK_INTERNAL_API
void mlk_polyvec_tobytes(u8int r[MLKEM_POLYVECBYTES], const mlk_polyvec *a)
{
  unsigned i;
  mlk_assert_bound_2d(a->vec, MLKEM_K, MLKEM_N, 0, MLKEM_Q);

  for (i = 0; i < MLKEM_K; i++)
  {
    mlk_poly_tobytes(&r[i * MLKEM_POLYBYTES], &a->vec[i]);
  }
}

/* Reference: `polyvec_frombytes()` in the reference implementation @[REF]. */
MLK_INTERNAL_API
void mlk_polyvec_frombytes(mlk_polyvec *r, const u8int a[MLKEM_POLYVECBYTES])
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++)
  {
    mlk_poly_frombytes(&r->vec[i], a + i * MLKEM_POLYBYTES);
  }

  mlk_assert_bound_2d(r->vec, MLKEM_K, MLKEM_N, 0, MLKEM_UINT12_LIMIT);
}

/* Reference: `polyvec_ntt()` in the reference implementation @[REF]. */
MLK_INTERNAL_API
void mlk_polyvec_ntt(mlk_polyvec *r)
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++)
  {
    mlk_poly_ntt(&r->vec[i]);
  }

  mlk_assert_abs_bound_2d(r->vec, MLKEM_K, MLKEM_N, MLK_NTT_BOUND);
}

/* Reference: `polyvec_invntt_tomont()` in the reference implementation @[REF].
 *            - We normalize at the beginning of the inverse NTT,
 *              while the reference implementation normalizes at
 *              the end. This allows us to drop a call to `poly_reduce()`
 *              from the base multiplication. */
MLK_INTERNAL_API
void mlk_polyvec_invntt_tomont(mlk_polyvec *r)
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++)
  {
    mlk_poly_invntt_tomont(&r->vec[i]);
  }

  mlk_assert_abs_bound_2d(r->vec, MLKEM_K, MLKEM_N, MLK_INVNTT_BOUND);
}

/* Reference: `polyvec_basemul_acc_montgomery()` in the
 *            reference implementation @[REF].
 *            - We use a multiplication cache ('mulcache') here
 *              which is not present in the reference implementation @[REF].
 *              This idea originates from @[NeonNTT] and is used
 *              at the C level here.
 *            - We compute the coefficients of the scalar product in 32-bit
 *              coefficients and perform only a single modular reduction
 *              at the end. The reference implementation uses 2 * MLKEM_K
 *              more modular reductions since it reduces after every modular
 *              multiplication. */
MLK_INTERNAL_API void mlk_polyvec_basemul_acc_montgomery_cached(
    mlk_poly *r, const mlk_polyvec *a, const mlk_polyvec *b,
    const mlk_polyvec_mulcache *b_cache)
{
  unsigned i;
  mlk_assert_bound_2d(a->vec, MLKEM_K, MLKEM_N, 0, MLKEM_UINT12_LIMIT);

  for (i = 0; i < MLKEM_N / 2; i++)
  {
    unsigned k;
    s32int t[2] = {0};
    for (k = 0; k < MLKEM_K; k++)
    {
      t[0] += (s32int)a->vec[k].coeffs[2 * i + 1] * b_cache->vec[k].coeffs[i];
      t[0] += (s32int)a->vec[k].coeffs[2 * i] * b->vec[k].coeffs[2 * i];
      t[1] += (s32int)a->vec[k].coeffs[2 * i] * b->vec[k].coeffs[2 * i + 1];
      t[1] += (s32int)a->vec[k].coeffs[2 * i + 1] * b->vec[k].coeffs[2 * i];
    }
    r->coeffs[2 * i + 0] = mlk_montgomery_reduce(t[0]);
    r->coeffs[2 * i + 1] = mlk_montgomery_reduce(t[1]);
  }
}

/* Reference: Does not exist in the reference implementation @[REF].
 *            - The reference implementation does not use a
 *              multiplication cache ('mulcache'). This idea originates
 *              from @[NeonNTT] and is used at the C level here. */
MLK_INTERNAL_API
void mlk_polyvec_mulcache_compute(mlk_polyvec_mulcache *x, const mlk_polyvec *a)
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++)
  {
    mlk_poly_mulcache_compute(&x->vec[i], &a->vec[i]);
  }
}

/* Reference: `polyvec_reduce()` in the reference implementation @[REF].
 *            - We use _unsigned_ canonical outputs, while the reference
 *              implementation uses _signed_ canonical outputs.
 *              Accordingly, we need a conditional addition of MLKEM_Q
 *              here to go from signed to unsigned representatives.
 *              This conditional addition is then dropped from all
 *              polynomial compression functions instead (see `compress.c`). */
MLK_INTERNAL_API
void mlk_polyvec_reduce(mlk_polyvec *r)
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++)
  {
    mlk_poly_reduce(&r->vec[i]);
  }

  mlk_assert_bound_2d(r->vec, MLKEM_K, MLKEM_N, 0, MLKEM_Q);
}

/* Reference: `polyvec_add()` in the reference implementation @[REF].
 *            - We use destructive version (output=first input) to avoid
 *              reasoning about aliasing in the CBMC specification */
MLK_INTERNAL_API
void mlk_polyvec_add(mlk_polyvec *r, const mlk_polyvec *b)
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++)
  {
    mlk_poly_add(&r->vec[i], &b->vec[i]);
  }
}

/* Reference: `polyvec_tomont()` in the reference implementation @[REF]. */
MLK_INTERNAL_API
void mlk_polyvec_tomont(mlk_polyvec *r)
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++)
  {
    mlk_poly_tomont(&r->vec[i]);
  }

  mlk_assert_abs_bound_2d(r->vec, MLKEM_K, MLKEM_N, MLKEM_Q);
}


/**
 * Given an array of uniformly random bytes, compute a polynomial with
 * coefficients distributed according to a centered binomial distribution
 * with parameter MLKEM_ETA1.
 *
 * @spec{Implements @[FIPS203, Algorithm 8, SamplePolyCBD_eta1], where eta1
 * is specified per parameter set in @[FIPS203, Table 2] and represented as
 * MLKEM_ETA1 here.}
 *
 * @reference{`poly_cbd_eta1` in the reference implementation @[REF].}
 *
 * @param[out] r   Output polynomial.
 * @param[in]  buf Input byte array.
 */
static void mlk_poly_cbd_eta1(
    mlk_poly *r, const u8int buf[MLKEM_ETA1 * MLKEM_N / 4])
{
#if MLKEM_ETA1 == 2
  mlk_poly_cbd2(r, buf);
#elif MLKEM_ETA1 == 3
  mlk_poly_cbd3(r, buf);
#else
#error "Invalid value of MLKEM_ETA1"
#endif
}

/* Reference: Does not exist in the reference implementation @[REF].
 *            - This implements a x4-batched version of `poly_getnoise_eta1()`
 *              from the reference implementation, to leverage
 *              batched Keccak-f1600.*/
MLK_INTERNAL_API
void mlk_poly_getnoise_eta1_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                               mlk_poly *r3, const u8int seed[MLKEM_SYMBYTES],
                               u8int nonce0, u8int nonce1, u8int nonce2,
                               u8int nonce3)
{
  u8int buf[4][MLK_ALIGN_UP(MLKEM_ETA1 * MLKEM_N / 4)];
  u8int extkey[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 1)];
  mlk_memcpy(extkey[0], seed, MLKEM_SYMBYTES);
  mlk_memcpy(extkey[1], seed, MLKEM_SYMBYTES);
  mlk_memcpy(extkey[2], seed, MLKEM_SYMBYTES);
  mlk_memcpy(extkey[3], seed, MLKEM_SYMBYTES);
  extkey[0][MLKEM_SYMBYTES] = nonce0;
  extkey[1][MLKEM_SYMBYTES] = nonce1;
  extkey[2][MLKEM_SYMBYTES] = nonce2;
  extkey[3][MLKEM_SYMBYTES] = nonce3;

  mlk_prf_eta1(buf[0], extkey[0]);
  mlk_prf_eta1(buf[1], extkey[1]);
  mlk_prf_eta1(buf[2], extkey[2]);
  if (r3 != nil)
  {
    mlk_prf_eta1(buf[3], extkey[3]);
  }

  mlk_poly_cbd_eta1(r0, buf[0]);
  mlk_poly_cbd_eta1(r1, buf[1]);
  mlk_poly_cbd_eta1(r2, buf[2]);
  if (r3 != nil)
  {
    mlk_poly_cbd_eta1(r3, buf[3]);
    mlk_assert_abs_bound(r3, MLKEM_N, MLKEM_ETA1 + 1);
  }

  mlk_assert_abs_bound(r0, MLKEM_N, MLKEM_ETA1 + 1);
  mlk_assert_abs_bound(r1, MLKEM_N, MLKEM_ETA1 + 1);
  mlk_assert_abs_bound(r2, MLKEM_N, MLKEM_ETA1 + 1);

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(buf, sizeof(buf));
  mlk_zeroize(extkey, sizeof(extkey));
}

#if MLKEM_K == 2 || MLKEM_K == 4
/**
 * Given an array of uniformly random bytes, compute a polynomial with
 * coefficients distributed according to a centered binomial distribution
 * with parameter MLKEM_ETA2.
 *
 * @spec{Implements @[FIPS203, Algorithm 8, SamplePolyCBD_eta2], where eta2
 * is specified per parameter set in @[FIPS203, Table 2] and represented as
 * MLKEM_ETA2 here.}
 *
 * @reference{`poly_cbd_eta2` in the reference implementation @[REF].}
 *
 * @param[out] r   Output polynomial.
 * @param[in]  buf Input byte array.
 */
static void mlk_poly_cbd_eta2(
    mlk_poly *r, const u8int buf[MLKEM_ETA2 * MLKEM_N / 4])
{
#if MLKEM_ETA2 == 2
  mlk_poly_cbd2(r, buf);
#else
#error "Invalid value of MLKEM_ETA2"
#endif
}

/* Reference: `poly_getnoise_eta2()` in the reference implementation @[REF].
 *            - We include buffer zeroization. */
MLK_INTERNAL_API
void mlk_poly_getnoise_eta2(mlk_poly *r, const u8int seed[MLKEM_SYMBYTES],
                            u8int nonce)
{
  u8int buf[MLKEM_ETA2 * MLKEM_N / 4];
  u8int extkey[MLKEM_SYMBYTES + 1];

  mlk_memcpy(extkey, seed, MLKEM_SYMBYTES);
  extkey[MLKEM_SYMBYTES] = nonce;
  mlk_prf_eta2(buf, extkey);

  mlk_poly_cbd_eta2(r, buf);

  mlk_assert_abs_bound(r, MLKEM_N, MLKEM_ETA2 + 1);

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(buf, sizeof(buf));
  mlk_zeroize(extkey, sizeof(extkey));
}
#endif /* MLKEM_K == 2 || MLKEM_K == 4 */

#if MLKEM_K == 2
/* Reference: Does not exist in the reference implementation @[REF].
 *            - This implements a x4-batched version of `poly_getnoise_eta1()`
 *              and `poly_getnoise_eta2()` from the reference implementation,
 *              leveraging batched Keccak-f1600.
 *            - If a x4-batched Keccak-f1600 is available, we squeeze
 *              more random data than needed for the eta2 calls, to be
 *              be able to use a x4-batched Keccak-f1600. */
MLK_INTERNAL_API
void mlk_poly_getnoise_eta1122_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                                  mlk_poly *r3,
                                  const u8int seed[MLKEM_SYMBYTES],
                                  u8int nonce0, u8int nonce1,
                                  u8int nonce2, u8int nonce3)
{
#if MLKEM_ETA2 >= MLKEM_ETA1
#error mlk_poly_getnoise_eta1122_4x assumes MLKEM_ETA1 > MLKEM_ETA2
#endif
  u8int buf[4][MLK_ALIGN_UP(MLKEM_ETA1 * MLKEM_N / 4)];
  u8int extkey[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 1)];

  mlk_memcpy(extkey[0], seed, MLKEM_SYMBYTES);
  mlk_memcpy(extkey[1], seed, MLKEM_SYMBYTES);
  mlk_memcpy(extkey[2], seed, MLKEM_SYMBYTES);
  mlk_memcpy(extkey[3], seed, MLKEM_SYMBYTES);
  extkey[0][MLKEM_SYMBYTES] = nonce0;
  extkey[1][MLKEM_SYMBYTES] = nonce1;
  extkey[2][MLKEM_SYMBYTES] = nonce2;
  extkey[3][MLKEM_SYMBYTES] = nonce3;

  /* On systems with fast batched Keccak, we use 4-fold batched PRF,
   * even though that means generating more random data in buf[2] and buf[3]
   * than necessary. */
  mlk_prf_eta1(buf[0], extkey[0]);
  mlk_prf_eta1(buf[1], extkey[1]);
  mlk_prf_eta2(buf[2], extkey[2]);
  mlk_prf_eta2(buf[3], extkey[3]);

  mlk_poly_cbd_eta1(r0, buf[0]);
  mlk_poly_cbd_eta1(r1, buf[1]);
  mlk_poly_cbd_eta2(r2, buf[2]);
  mlk_poly_cbd_eta2(r3, buf[3]);

  mlk_assert_abs_bound(r0, MLKEM_N, MLKEM_ETA1 + 1);
  mlk_assert_abs_bound(r1, MLKEM_N, MLKEM_ETA1 + 1);
  mlk_assert_abs_bound(r2, MLKEM_N, MLKEM_ETA2 + 1);
  mlk_assert_abs_bound(r3, MLKEM_N, MLKEM_ETA2 + 1);

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(buf, sizeof(buf));
  mlk_zeroize(extkey, sizeof(extkey));
}
#endif /* MLKEM_K == 2 */

/* To facilitate single-compilation-unit (SCU) builds, undefine all macros.
 * Don't modify by hand -- this is auto-generated by scripts/autogen. */
#undef mlk_poly_cbd_eta1
#undef mlk_poly_cbd_eta2
#undef mlk_polyvec_basemul_acc_montgomery_cached_c
