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

#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

#include "a.h"
#include "fips202.h"

#define _MLKEM_POLYVECBYTES(lvl) (lvl * MLKEM_POLYBYTES)

/* Reference: `polyvec_compress()` in the reference implementation @[REF]
 *            - In contrast to the reference implementation, we assume
 *              unsigned canonical coefficients here.
 *              The reference implementation works with coefficients
 *              in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
MLK_INTERNAL_API
void mlk_polyvec_compress_du(int level, u8int *r, const mlk_polyvec *a)
{
  unsigned i;

  for (i = 0; i < level; i++){
    if(level == K1024)
      mlk_poly_compress_d11(r + i * MLKEM_POLYCOMPRESSEDBYTES_D11, &a->vec[i]);
    else
      mlk_poly_compress_d10(r + i * MLKEM_POLYCOMPRESSEDBYTES_D10, &a->vec[i]);
  }
}

/* Reference: `polyvec_decompress()` in the reference implementation @[REF]. */
MLK_INTERNAL_API
void mlk_polyvec_decompress_du(int level, mlk_polyvec *r, const u8int *a)
{
  unsigned i;

  for (i = 0; i < level; i++){
    if(level == K1024)
      mlk_poly_decompress_d11(&r->vec[i], a + i * MLKEM_POLYCOMPRESSEDBYTES_D11);
    else
      mlk_poly_decompress_d10(&r->vec[i], a + i * MLKEM_POLYCOMPRESSEDBYTES_D10);
  }
}

/* Reference: `polyvec_tobytes()` in the reference implementation @[REF].
 *            - In contrast to the reference implementation, we assume
 *              unsigned canonical coefficients here.
 *              The reference implementation works with coefficients
 *              in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
MLK_INTERNAL_API
void mlk_polyvec_tobytes(int level, u8int *r, const mlk_polyvec *a)
{
  unsigned i;

  for (i = 0; i < level; i++)
  {
    mlk_poly_tobytes(&r[i * MLKEM_POLYBYTES], &a->vec[i]);
  }
}

/* Reference: `polyvec_frombytes()` in the reference implementation @[REF]. */
MLK_INTERNAL_API
void mlk_polyvec_frombytes(int level, mlk_polyvec *r, const u8int *a)
{
  unsigned i;
  for (i = 0; i < level; i++)
  {
    mlk_poly_frombytes(&r->vec[i], a + i * MLKEM_POLYBYTES);
  }

}

/* Reference: `polyvec_ntt()` in the reference implementation @[REF]. */
MLK_INTERNAL_API
void mlk_polyvec_ntt(int level, mlk_polyvec *r)
{
  unsigned i;
  for (i = 0; i < level; i++)
  {
    mlk_poly_ntt(&r->vec[i]);
  }

}

/* Reference: `polyvec_invntt_tomont()` in the reference implementation @[REF].
 *            - We normalize at the beginning of the inverse NTT,
 *              while the reference implementation normalizes at
 *              the end. This allows us to drop a call to `poly_reduce()`
 *              from the base multiplication. */
MLK_INTERNAL_API
void mlk_polyvec_invntt_tomont(int level, mlk_polyvec *r)
{
  unsigned i;
  for (i = 0; i < level; i++)
  {
    mlk_poly_invntt_tomont(&r->vec[i]);
  }

}

/* Reference: `polyvec_tomont()` in the reference implementation @[REF]. */
MLK_INTERNAL_API
void mlk_polyvec_tomont(int level, mlk_polyvec *r)
{
  unsigned i;
  for (i = 0; i < level; i++)
  {
    mlk_poly_tomont(&r->vec[i]);
  }

}

/* Reference: Does not exist in the reference implementation @[REF].
 *            - The reference implementation does not use a
 *              multiplication cache ('mulcache'). This idea originates
 *              from @[NeonNTT] and is used at the C level here. */
MLK_INTERNAL_API
void mlk_polyvec_mulcache_compute(int level, mlk_polyvec_mulcache *x, const mlk_polyvec *a)
{
  unsigned i;
  for (i = 0; i < level; i++)
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
void mlk_polyvec_reduce(int level, mlk_polyvec *r)
{
  unsigned i;
  for (i = 0; i < level; i++)
  {
    mlk_poly_reduce(&r->vec[i]);
  }

}

/* Reference: `polyvec_add()` in the reference implementation @[REF].
 *            - We use destructive version (output=first input) to avoid
 *              reasoning about aliasing in the CBMC specification */
MLK_INTERNAL_API
void mlk_polyvec_add(int level, mlk_polyvec *r, const mlk_polyvec *b)
{
  unsigned i;
  for (i = 0; i < level; i++)
  {
    mlk_poly_add(&r->vec[i], &b->vec[i]);
  }
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
MLK_INTERNAL_API void mlk_polyvec_basemul_acc_montgomery_cached(int level,
    mlk_poly *r, const mlk_polyvec *a, const mlk_polyvec *b,
    const mlk_polyvec_mulcache *b_cache)
{
  unsigned i;

  for (i = 0; i < MLKEM_N / 2; i++)
  {
    unsigned k;
    s32int t[2] = {0};
    for (k = 0; k < level; k++)
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
 *            - This implements a x4-batched version of `poly_getnoise_eta1()`
 *              from the reference implementation, to leverage
 *              batched Keccak-f1600.*/
MLK_INTERNAL_API
void mlk_poly_getnoise_eta1_4x(int level, mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                               mlk_poly *r3, const u8int seed[MLKEM_SYMBYTES],
                               u8int nonce0, u8int nonce1, u8int nonce2,
                               u8int nonce3)
{
  u8int buf[4][MLK_ALIGN_UP(3 * MLKEM_N / 4)];
  u8int extkey[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 1)];
  mlk_memcpy(extkey[0], seed, MLKEM_SYMBYTES);
  mlk_memcpy(extkey[1], seed, MLKEM_SYMBYTES);
  mlk_memcpy(extkey[2], seed, MLKEM_SYMBYTES);
  mlk_memcpy(extkey[3], seed, MLKEM_SYMBYTES);
  extkey[0][MLKEM_SYMBYTES] = nonce0;
  extkey[1][MLKEM_SYMBYTES] = nonce1;
  extkey[2][MLKEM_SYMBYTES] = nonce2;
  extkey[3][MLKEM_SYMBYTES] = nonce3;

  if(level == K512){
    mlk_prf_eta(3, buf[0], extkey[0]);
    mlk_prf_eta(3, buf[1], extkey[1]);
    mlk_prf_eta(3, buf[2], extkey[2]);
    if (r3 != nil){
      mlk_prf_eta(3, buf[3], extkey[3]);
    }
    mlk_poly_cbd3(r0, buf[0]);
    mlk_poly_cbd3(r1, buf[1]);
    mlk_poly_cbd3(r2, buf[2]);
    if (r3 != nil){
      mlk_poly_cbd3(r3, buf[3]);
    }
  } else if(level == K768 || level == K1024){
    mlk_prf_eta(2, buf[0], extkey[0]);
    mlk_prf_eta(2, buf[1], extkey[1]);
    mlk_prf_eta(2, buf[2], extkey[2]);
    if (r3 != nil){
      mlk_prf_eta(2, buf[3], extkey[3]);
    }
    mlk_poly_cbd2(r0, buf[0]);
    mlk_poly_cbd2(r1, buf[1]);
    mlk_poly_cbd2(r2, buf[2]);
    if (r3 != nil){
      mlk_poly_cbd2(r3, buf[3]);
    }
  } else
    abort();


  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(buf, sizeof(buf));
  mlk_zeroize(extkey, sizeof(extkey));
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
  mlk_prf_eta(MLKEM_ETA2, buf, extkey);

  mlk_poly_cbd2(r, buf);


  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(buf, sizeof(buf));
  mlk_zeroize(extkey, sizeof(extkey));
}

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
  u8int buf[4][MLK_ALIGN_UP(3 * MLKEM_N / 4)];
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
  mlk_prf_eta(1, buf[0], extkey[0]);
  mlk_prf_eta(1, buf[1], extkey[1]);
  mlk_prf_eta(2, buf[2], extkey[2]);
  mlk_prf_eta(2, buf[3], extkey[3]);

  mlk_poly_cbd3(r0, buf[0]);
  mlk_poly_cbd3(r1, buf[1]);
  mlk_poly_cbd2(r2, buf[2]);
  mlk_poly_cbd2(r3, buf[3]);


  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(buf, sizeof(buf));
  mlk_zeroize(extkey, sizeof(extkey));
}
