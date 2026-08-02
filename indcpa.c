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
#include "params.h"

#define mlk_indcpa_keypair_derand MLK_NAMESPACE_K(indcpa_keypair_derand)
#define mlk_indcpa_enc MLK_NAMESPACE_K(indcpa_enc)
#define mlk_indcpa_dec MLK_NAMESPACE_K(indcpa_dec)

/**
 * Serialize the public key as the concatenation of the serialized vector of
 * polynomials pk and the public seed used to generate the matrix A.
 *
 * @spec{Implements @[FIPS203, Algorithm 13 (K-PKE.KeyGen), L19].}
 *
 * @param[out] r    Output serialized public key.
 * @param[in]  pk   Input public-key polyvec. Must have coefficients within
 *                  [0,..,MLKEM_Q-1].
 * @param[in]  seed Input public seed.
 */
static void mlk_pack_pk(u8int r[MLKEM_INDCPA_PUBLICKEYBYTES],
                        const mlk_polyvec *pk,
                        const u8int seed[MLKEM_SYMBYTES])
{
  mlk_polyvec_tobytes(MLKEM_K, r, pk);
  mlk_memcpy(r + MLKEM_POLYVECBYTES, seed, MLKEM_SYMBYTES);
}

/**
 * De-serialize public key from a byte array; approximate inverse of
 * mlk_pack_pk.
 *
 * @spec{Implements @[FIPS203, Algorithm 14 (K-PKE.Encrypt), L2-3].}
 *
 * @param[out] pk       Output public-key polynomial vector. Coefficients
 *                      will be normalized to [0,1,..,MLKEM_Q-1].
 * @param[out] seed     Output seed to generate matrix A.
 * @param[in]  packedpk Input serialized public key.
 */
static void mlk_unpack_pk(mlk_polyvec *pk, u8int seed[MLKEM_SYMBYTES],
                          const u8int packedpk[MLKEM_INDCPA_PUBLICKEYBYTES])
{
  mlk_polyvec_frombytes(MLKEM_K, pk, packedpk);
  mlk_memcpy(seed, packedpk + MLKEM_POLYVECBYTES, MLKEM_SYMBYTES);

  /* NOTE: If a modulus check was conducted on the PK, we know at this
   * point that the coefficients of `pk` are unsigned canonical. The
   * specifications and proofs, however, do _not_ assume this, and instead
   * work with the easily provable bound by MLKEM_UINT12_LIMIT. */
}

/**
 * Serialize the secret key.
 *
 * @spec{Implements @[FIPS203, Algorithm 13 (K-PKE.KeyGen), L20].}
 *
 * @param[out] r  Output serialized secret key.
 * @param[in]  sk Input vector of polynomials (secret key).
 */
static void mlk_pack_sk(u8int r[MLKEM_INDCPA_SECRETKEYBYTES],
                        const mlk_polyvec *sk)
{
  mlk_polyvec_tobytes(MLKEM_K, r, sk);
}

/**
 * De-serialize the secret key; inverse of mlk_pack_sk.
 *
 * @spec{Implements @[FIPS203, Algorithm 15 (K-PKE.Decrypt), L5].}
 *
 * @param[out] sk       Output vector of polynomials (secret key).
 * @param[in]  packedsk Input serialized secret key.
 */
static void mlk_unpack_sk(mlk_polyvec *sk,
                          const u8int packedsk[MLKEM_INDCPA_SECRETKEYBYTES])
{
  mlk_polyvec_frombytes(MLKEM_K, sk, packedsk);
}

/**
 * Serialize the ciphertext as the concatenation of the compressed and
 * serialized vector of polynomials b and the compressed and serialized
 * polynomial v.
 *
 * @spec{Implements @[FIPS203, Algorithm 14 (K-PKE.Encrypt), L22-23].}
 *
 * @param[out] r Output serialized ciphertext.
 * @param[in]  b Input vector of polynomials b.
 * @param[in]  v Input polynomial v.
 */
static void mlk_pack_ciphertext(u8int r[MLKEM_INDCPA_BYTES],
                                const mlk_polyvec *b, mlk_poly *v)
{
  mlk_polyvec_compress_du(MLKEM_K, r, b);
#if MLKEM_K == 2 || MLKEM_K == 3
  mlk_poly_compress_d4(r + MLKEM_POLYVECCOMPRESSEDBYTES_DU, v);
#else
  mlk_poly_compress_d5(r + MLKEM_POLYVECCOMPRESSEDBYTES_DU, v);
#endif
}

/**
 * De-serialize and decompress ciphertext from a byte array; approximate
 * inverse of mlk_pack_ciphertext.
 *
 * @spec{Implements @[FIPS203, Algorithm 15 (K-PKE.Decrypt), L1-4].}
 *
 * @param[out] b Output vector of polynomials b.
 * @param[out] v Output polynomial v.
 * @param[in]  c Input serialized ciphertext.
 */
static void mlk_unpack_ciphertext(mlk_polyvec *b, mlk_poly *v,
                                  const u8int c[MLKEM_INDCPA_BYTES])
{
  mlk_polyvec_decompress_du(MLKEM_K, b, c);
#if MLKEM_K == 2 || MLKEM_K == 3
  mlk_poly_decompress_d4(v, c + MLKEM_POLYVECCOMPRESSEDBYTES_DU);
#else
  mlk_poly_decompress_d5(v, c + MLKEM_POLYVECCOMPRESSEDBYTES_DU);
#endif
}

/* Helper function to ensure that the polynomial entries in the output
 * of gen_matrix use the standard (bitreversed) ordering of coefficients.
 * No-op unless a native backend with a custom ordering is used.
 *
 * We don't inline this into gen_matrix to avoid having to split the CBMC
 * proof for gen_matrix based on MLK_USE_NATIVE_NTT_CUSTOM_ORDER. */
static void mlk_polyvec_permute_bitrev_to_custom(mlk_polyvec*)
{
}

static void mlk_polymat_permute_bitrev_to_custom(mlk_polymat *a)
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++)
  {
    mlk_polyvec_permute_bitrev_to_custom(&a->vec[i]);
  }
}

/* Reference: `gen_matrix()` in the reference implementation @[REF].
 *            - We use a special subroutine to generate 4 polynomials
 *              at a time, to be able to leverage batched Keccak-f1600
 *              implementations. The reference implementation generates
 *              one matrix entry a time.
 *
 */
static
void mlk_gen_matrix(mlk_polymat *a, const u8int seed[MLKEM_SYMBYTES],
                    int transposed)
{
  unsigned i, j;
  u8int seed_ext[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 2)];

  for (j = 0; j < 4; j++)
  {
    mlk_memcpy(seed_ext[j], seed, MLKEM_SYMBYTES);
  }

  /* When using serial FIPS202, sample all entries individually. */
  i = 0;

  /* For MLKEM_K == 3, sample the last entry individually.
   * When MLK_CONFIG_SERIAL_FIPS202_ONLY is set, sample all entries
   * individually. */
  for (; i < MLKEM_K * MLKEM_K; i++)
  {
    u8int x, y;
    /* MLKEM_K <= 4, so the values fit in u8int. */
    x = (u8int)(i / MLKEM_K);
    y = (u8int)(i % MLKEM_K);

    if (transposed)
    {
      seed_ext[0][MLKEM_SYMBYTES + 0] = x;
      seed_ext[0][MLKEM_SYMBYTES + 1] = y;
    }
    else
    {
      seed_ext[0][MLKEM_SYMBYTES + 0] = y;
      seed_ext[0][MLKEM_SYMBYTES + 1] = x;
    }

    mlk_poly_rej_uniform(&a->vec[i / MLKEM_K].vec[i % MLKEM_K], seed_ext[0]);
  }

  /*
   * The public matrix is generated in NTT domain. If the native backend
   * uses a custom order in NTT domain, permute A accordingly.
   */
  mlk_polymat_permute_bitrev_to_custom(a);

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(seed_ext, sizeof(seed_ext));
}

/**
 * Compute matrix-vector product in NTT domain, via Montgomery multiplication.
 *
 * @spec{Implements @[FIPS203, Section 2.4.7, Eq (2.12), (2.13)].}
 *
 * @param[out] out Output polynomial vector.
 * @param[in]  a   Input matrix. Must be in NTT domain and have coefficients
 *                 of absolute value < 4096.
 * @param[in]  v   Input polynomial vector. Must be in NTT domain.
 * @param[in]  vc  Mulcache for @p v, computed via
 *                 mlk_polyvec_mulcache_compute().
 */
static void mlk_matvec_mul(mlk_polyvec *out, const mlk_polymat *a,
                           const mlk_polyvec *v, const mlk_polyvec_mulcache *vc)
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++)
  {
    mlk_polyvec_basemul_acc_montgomery_cached(MLKEM_K, &out->vec[i], &a->vec[i], v, vc);
  }
}

/**
 * Compute and fill the pv and e polyvec structures needed by
 * mlk_keypair_derand(). Uses x4-batched versions of `poly_getnoise` to
 * leverage batched Keccak-f1600.
 *
 * @spec{Implements @[FIPS203, Algorithm 13 (K-PKE.KeyGen)] steps 8-15.}
 *
 * @param[out] pv   Output polynomial vector.
 * @param[out] e    Output polynomial vector.
 * @param[in]  seed Seed bytes for sampling.
 */
static void mlk_keypair_getnoise_eta1(mlk_polyvec *pv, mlk_polyvec *e,
                                      const u8int seed[MLKEM_SYMBYTES])
{
#if MLKEM_K == 2
  mlk_poly_getnoise_eta1_4x(MLKEM_K, &pv->vec[0], &pv->vec[1], /* Fill elements of pv */
                            &e->vec[0], &e->vec[1], /* and two elements of e */
                            seed, 0, 1, 2, 3);
#elif MLKEM_K == 3
  /*
   * Only the first three output buffers are needed, so we pass nil as
   * the fourth parameter, and 0xFF as its dummy nonce.
   */
  mlk_poly_getnoise_eta1_4x(MLKEM_K, &pv->vec[0], &pv->vec[1], &pv->vec[2], nil, seed,
                            0, 1, 2, 0xFF);
  /* Same here */
  mlk_poly_getnoise_eta1_4x(MLKEM_K, &e->vec[0], &e->vec[1], &e->vec[2], nil, seed, 3,
                            4, 5, 0xFF);
#elif MLKEM_K == 4
  mlk_poly_getnoise_eta1_4x(MLKEM_K, &pv->vec[0], &pv->vec[1], &pv->vec[2], &pv->vec[3],
                            seed, 0, 1, 2, 3);
  mlk_poly_getnoise_eta1_4x(MLKEM_K, &e->vec[0], &e->vec[1], &e->vec[2], &e->vec[3],
                            seed, 4, 5, 6, 7);
#endif /* MLKEM_K == 4 */
}

/**
 * Compute and fill the sp, ep, and epp polynomial structures needed by
 * mlk_indcpa_enc(). Uses x4-batched versions of `poly_getnoise` to leverage
 * batched Keccak-f1600.
 *
 * @spec{Implements @[FIPS203, Algorithm 14 (K-PKE.Encrypt)] steps 9-16.}
 *
 * @param[out] sp    Output polynomial vector.
 * @param[out] ep    Output polynomial vector.
 * @param[out] epp   Output polynomial.
 * @param[in]  coins Seed bytes for sampling.
 */
static void mlk_enc_getnoise_eta1_eta2(mlk_polyvec *sp, mlk_polyvec *ep,
                                       mlk_poly *epp,
                                       const u8int coins[MLKEM_SYMBYTES])
{
#if MLKEM_K == 2
  mlk_poly_getnoise_eta1122_4x(&sp->vec[0], &sp->vec[1], &ep->vec[0],
                               &ep->vec[1], coins, 0, 1, 2, 3);
  mlk_poly_getnoise_eta2(epp, coins, 4);
#elif MLKEM_K == 3
  /*
   * In this call, only the first three output buffers are needed.
   * The last parameter is a dummy that's overwritten later.
   */
  mlk_poly_getnoise_eta1_4x(MLKEM_K, &sp->vec[0], &sp->vec[1], &sp->vec[2], nil, coins,
                            0, 1, 2, 0xFF /* irrelevant */);
  /* The fourth output buffer in this call _is_ used. */
  mlk_poly_getnoise_eta1_4x(MLKEM_K, &ep->vec[0], &ep->vec[1], &ep->vec[2], epp, coins,
                            3, 4, 5, 6);
#elif MLKEM_K == 4
  mlk_poly_getnoise_eta1_4x(MLKEM_K, &sp->vec[0], &sp->vec[1], &sp->vec[2], &sp->vec[3],
                            coins, 0, 1, 2, 3);
  mlk_poly_getnoise_eta1_4x(MLKEM_K, &ep->vec[0], &ep->vec[1], &ep->vec[2], &ep->vec[3],
                            coins, 4, 5, 6, 7);
  mlk_poly_getnoise_eta2(epp, coins, 8);
#endif /* MLKEM_K == 4 */
}


/* Reference: `indcpa_keypair_derand()` in the reference implementation @[REF].
 *            - We use a different implementation of `gen_matrix()` which
 *              uses x4-batched Keccak-f1600 (see `mlk_gen_matrix()` above).
 *            - We use a mulcache to speed up matrix-vector multiplication.
 *            - We include buffer zeroization.
 */
MLK_INTERNAL_API
int mlk_indcpa_keypair_derand(u8int pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                              u8int sk[MLKEM_INDCPA_SECRETKEYBYTES],
                              const u8int coins[MLKEM_SYMBYTES])
{
  int ret = 0;
  const u8int *publicseed;
  const u8int *noiseseed;
  MLK_ALLOC(buf, u8int, 2 * MLKEM_SYMBYTES);
  MLK_ALLOC(coins_with_domain_separator, u8int, MLKEM_SYMBYTES + 1);
  MLK_ALLOC(a, mlk_polymat, 1);
  MLK_ALLOC(e, mlk_polyvec, 1);
  MLK_ALLOC(pkpv, mlk_polyvec, 1);
  MLK_ALLOC(skpv, mlk_polyvec, 1);
  MLK_ALLOC(skpv_cache, mlk_polyvec_mulcache, 1);

  if (buf == nil || coins_with_domain_separator == nil || a == nil ||
      e == nil || pkpv == nil || skpv == nil || skpv_cache == nil)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  publicseed = buf;
  noiseseed = buf + MLKEM_SYMBYTES;

  /* Concatenate coins with MLKEM_K for domain separation of security levels */
  mlk_memcpy(coins_with_domain_separator, coins, MLKEM_SYMBYTES);
  coins_with_domain_separator[MLKEM_SYMBYTES] = MLKEM_K;

  mlk_hash_g(buf, coins_with_domain_separator, MLKEM_SYMBYTES + 1);

  mlk_gen_matrix(a, publicseed, 0 /* no transpose */);

  mlk_keypair_getnoise_eta1(skpv, e, noiseseed);

  mlk_polyvec_ntt(MLKEM_K, skpv);
  mlk_polyvec_ntt(MLKEM_K, e);

  mlk_polyvec_mulcache_compute(MLKEM_K, skpv_cache, skpv);
  mlk_matvec_mul(pkpv, a, skpv, skpv_cache);
  mlk_polyvec_tomont(MLKEM_K, pkpv);

  mlk_polyvec_add(MLKEM_K, pkpv, e);
  mlk_polyvec_reduce(MLKEM_K, pkpv);
  mlk_polyvec_reduce(MLKEM_K, skpv);

  mlk_pack_sk(sk, skpv);
  mlk_pack_pk(pk, pkpv, publicseed);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(skpv_cache, mlk_polyvec_mulcache, 1);
  MLK_FREE(skpv, mlk_polyvec, 1);
  MLK_FREE(pkpv, mlk_polyvec, 1);
  MLK_FREE(e, mlk_polyvec, 1);
  MLK_FREE(a, mlk_polymat, 1);
  MLK_FREE(coins_with_domain_separator, u8int, MLKEM_SYMBYTES + 1);
  MLK_FREE(buf, u8int, 2 * MLKEM_SYMBYTES);
  return ret;
}

/* Reference: `indcpa_enc()` in the reference implementation @[REF].
 *            - We use x4-batched versions of `poly_getnoise` to leverage
 *              batched x4-batched Keccak-f1600.
 *            - We use a different implementation of `gen_matrix()` which
 *              uses x4-batched Keccak-f1600 (see `mlk_gen_matrix()` above).
 *            - We use a mulcache to speed up matrix-vector multiplication.
 *            - We include buffer zeroization.
 */
MLK_INTERNAL_API
int mlk_indcpa_enc(u8int c[MLKEM_INDCPA_BYTES],
                   const u8int m[MLKEM_INDCPA_MSGBYTES],
                   const u8int pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                   const u8int coins[MLKEM_SYMBYTES])
{
  int ret = 0;
  MLK_ALLOC(seed, u8int, MLKEM_SYMBYTES);
  MLK_ALLOC(at, mlk_polymat, 1);
  MLK_ALLOC(sp, mlk_polyvec, 1);
  MLK_ALLOC(pkpv, mlk_polyvec, 1);
  MLK_ALLOC(ep, mlk_polyvec, 1);
  MLK_ALLOC(b, mlk_polyvec, 1);
  MLK_ALLOC(v, mlk_poly, 1);
  MLK_ALLOC(k, mlk_poly, 1);
  MLK_ALLOC(epp, mlk_poly, 1);
  MLK_ALLOC(sp_cache, mlk_polyvec_mulcache, 1);

  if (seed == nil || at == nil || sp == nil || pkpv == nil || ep == nil ||
      b == nil || v == nil || k == nil || epp == nil || sp_cache == nil)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  mlk_unpack_pk(pkpv, seed, pk);
  mlk_poly_frommsg(k, m);

  mlk_gen_matrix(at, seed, 1 /* transpose */);

  mlk_enc_getnoise_eta1_eta2(sp, ep, epp, coins);

  mlk_polyvec_ntt(MLKEM_K, sp);

  mlk_polyvec_mulcache_compute(MLKEM_K, sp_cache, sp);
  mlk_matvec_mul(b, at, sp, sp_cache);
  mlk_polyvec_basemul_acc_montgomery_cached(MLKEM_K, v, pkpv, sp, sp_cache);

  mlk_polyvec_invntt_tomont(MLKEM_K, b);
  mlk_poly_invntt_tomont(v);

  mlk_polyvec_add(MLKEM_K, b, ep);
  mlk_poly_add(v, epp);
  mlk_poly_add(v, k);

  mlk_polyvec_reduce(MLKEM_K, b);
  mlk_poly_reduce(v);

  mlk_pack_ciphertext(c, b, v);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(sp_cache, mlk_polyvec_mulcache, 1);
  MLK_FREE(epp, mlk_poly, 1);
  MLK_FREE(k, mlk_poly, 1);
  MLK_FREE(v, mlk_poly, 1);
  MLK_FREE(b, mlk_polyvec, 1);
  MLK_FREE(ep, mlk_polyvec, 1);
  MLK_FREE(pkpv, mlk_polyvec, 1);
  MLK_FREE(sp, mlk_polyvec, 1);
  MLK_FREE(at, mlk_polymat, 1);
  MLK_FREE(seed, u8int, MLKEM_SYMBYTES);
  return ret;
}

/* Reference: `indcpa_dec()` in the reference implementation @[REF].
 *            - We use a mulcache for the scalar product.
 *            - We include buffer zeroization. */
MLK_INTERNAL_API
int mlk_indcpa_dec(u8int m[MLKEM_INDCPA_MSGBYTES],
                   const u8int c[MLKEM_INDCPA_BYTES],
                   const u8int sk[MLKEM_INDCPA_SECRETKEYBYTES])
{
  int ret = 0;
  MLK_ALLOC(b, mlk_polyvec, 1);
  MLK_ALLOC(skpv, mlk_polyvec, 1);
  MLK_ALLOC(v, mlk_poly, 1);
  MLK_ALLOC(sb, mlk_poly, 1);
  MLK_ALLOC(b_cache, mlk_polyvec_mulcache, 1);

  if (b == nil || skpv == nil || v == nil || sb == nil || b_cache == nil)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  mlk_unpack_ciphertext(b, v, c);
  mlk_unpack_sk(skpv, sk);

  mlk_polyvec_ntt(MLKEM_K, b);
  mlk_polyvec_mulcache_compute(MLKEM_K, b_cache, b);
  mlk_polyvec_basemul_acc_montgomery_cached(MLKEM_K, sb, skpv, b, b_cache);
  mlk_poly_invntt_tomont(sb);

  mlk_poly_sub(v, sb);
  mlk_poly_reduce(v);

  mlk_poly_tomsg(m, v);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(b_cache, mlk_polyvec_mulcache, 1);
  MLK_FREE(sb, mlk_poly, 1);
  MLK_FREE(v, mlk_poly, 1);
  MLK_FREE(skpv, mlk_polyvec, 1);
  MLK_FREE(b, mlk_polyvec, 1);
  return ret;
}

/* To facilitate single-compilation-unit (SCU) builds, undefine all macros.
 * Don't modify by hand -- this is auto-generated by scripts/autogen. */
#undef mlk_pack_pk
#undef mlk_unpack_pk
#undef mlk_pack_sk
#undef mlk_unpack_sk
#undef mlk_pack_ciphertext
#undef mlk_unpack_ciphertext
#undef mlk_matvec_mul
#undef mlk_polyvec_permute_bitrev_to_custom
#undef mlk_polymat_permute_bitrev_to_custom
#undef mlk_keypair_getnoise_eta1
#undef mlk_enc_getnoise_eta1_eta2
