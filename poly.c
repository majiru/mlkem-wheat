/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
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

/**
 * Generic Montgomery reduction; given a 32-bit integer a, computes a 16-bit
 * integer congruent to a * R^-1 mod MLKEM_Q, where R=2^16.
 *
 * @param a Input integer to be reduced, of absolute value smaller or equal
 *          to INT32_MAX - 2^15 * MLKEM_Q.
 *
 * @return Integer congruent to a * R^-1 modulo MLKEM_Q, with absolute value
 *         <= ceil(|a| / 2^16) + (MLKEM_Q + 1)/2.
 */
s16int mlk_montgomery_reduce(s32int a)
{
  /* check-magic: 62209 == unsigned_mod(pow(MLKEM_Q, -1, 2^16), 2^16) */
  const u32int QINV = 62209;

  /* Compute a*q^{-1} mod 2^16 in unsigned representatives. */
  const u16int a_reduced = (u16int)(a & (s32int)0xffff);
  const u16int a_inverted = (a_reduced * QINV) & 0xffff;

  /* Lift to signed canonical representative mod 2^16. */
  const s16int t = (s16int)a_inverted;

  s32int r;

  r = a - ((s32int)t * MLKEM_Q);

  /*
   * PORTABILITY: Right-shift on a signed integer is, strictly-speaking,
   * implementation-defined for negative left argument. Here,
   * we assume it's sign-preserving "arithmetic" shift right. (C99 6.5.7 (5))
   */
  r = r >> 16;
  /* Bounds: |r >> 16| <= ceil(|r| / 2^16)
   *                   <= ceil(|a| / 2^16 + MLKEM_Q / 2)
   *                   <= ceil(|a| / 2^16) + (MLKEM_Q + 1) / 2
   *
   * (Note that |a >> n| = ceil(|a| / 2^16) for negative a)
   */
  return (s16int)r;
}

/**
 * Montgomery multiplication modulo MLKEM_Q.
 *
 * @reference{`fqmul()` in the reference implementation @[REF].}
 *
 * @param a First factor. Can be any s16int.
 * @param b Second factor. Must be signed canonical
 *          (abs value < (MLKEM_Q+1)/2).
 *
 * @return 16-bit integer congruent to a*b*R^{-1} mod MLKEM_Q, and
 *         smaller than MLKEM_Q in absolute value.
 */
static s16int mlk_fqmul(s16int a, s16int b)
{
  s16int res;

  res = mlk_montgomery_reduce((s32int)a * (s32int)b);
  /* Bounds:
   * |res| <= ceil(|a| * |b| / 2^16) + (MLKEM_Q + 1) / 2
   *       <= ceil(2^15 * ((MLKEM_Q - 1)/2) / 2^16) + (MLKEM_Q + 1) / 2
   *       <= ceil((MLKEM_Q - 1) / 4) + (MLKEM_Q + 1) / 2
   *        < MLKEM_Q
   */

  return res;
}

/**
 * Barrett reduction; given a 16-bit integer a, computes the centered
 * representative congruent to a mod MLKEM_Q in [-(MLKEM_Q-1)/2, (MLKEM_Q-1)/2].
 *
 * @reference{`barrett_reduce()` in the reference implementation @[REF].}
 *
 * @param a Input integer to be reduced.
 *
 * @return Integer in [-(MLKEM_Q-1)/2, (MLKEM_Q-1)/2] congruent to @p a modulo
 *         MLKEM_Q.
 */
static s16int mlk_barrett_reduce(s16int a)
{
  /* Barrett reduction approximates
   * ```
   *     round(a/MLKEM_Q)
   *   = round(a*(2^N/MLKEM_Q))/2^N)
   *  ~= round(a*round(2^N/MLKEM_Q)/2^N)
   * ```
   * Here, we pick N=26.
   */
  const s32int magic = 20159; /* check-magic: 20159 == round(2^26 / MLKEM_Q) */

  /*
   * PORTABILITY: Right-shift on a signed integer is
   * implementation-defined for negative left argument.
   * Here, we assume it's sign-preserving "arithmetic" shift right.
   * See (C99 6.5.7 (5))
   */
  const s32int t = (magic * a + ((s32int)1 << 25)) >> 26;

  /*
   * t is in -10 .. +10, so we need 32-bit math to
   * evaluate t * MLKEM_Q and the subsequent subtraction
   */
  s16int res = (s16int)(a - t * MLKEM_Q);

  return res;
}

/* Reference: `poly_tomont()` in the reference implementation @[REF]. */
MLK_INTERNAL_API void mlk_poly_tomont(mlk_poly *r)
{
  unsigned i;
  const s16int f = 1353; /* check-magic: 1353 == signed_mod(2^32, MLKEM_Q) */
  for (i = 0; i < MLKEM_N; i++)
  {
    r->coeffs[i] = mlk_fqmul(r->coeffs[i], f);
  }

}

/**
 * Constant-time conversion of signed representatives modulo MLKEM_Q within
 * range [-(MLKEM_Q-1), MLKEM_Q-1] into unsigned representatives within
 * range [0, MLKEM_Q-1].
 *
 * @reference{Not present in the reference implementation @[REF]. Used here
 * to implement different semantics of `poly_reduce()`; see below. In the
 * reference implementation @[REF] this logic is part of all compression
 * functions (see `compress.c`).}
 *
 * @param c Signed coefficient to be converted.
 *
 * @return Unsigned representative in [0, MLKEM_Q).
 */
static s16int mlk_scalar_signed_to_unsigned_q(s16int c)
{

  /* Add MLKEM_Q if c is negative, but in constant time.
   *
   * Note that c + MLKEM_Q does not overflow in s16int,
   * so the cast to u16int is safe. */
  c = mlk_ct_sel_int16((s16int)(c + MLKEM_Q), c, ((u16int)(((s32int)c)>>16) & (s32int)0xffff));

  return c;
}

/* Reference: `poly_reduce()` in the reference implementation @[REF]
 *            - We use _unsigned_ canonical outputs, while the reference
 *              implementation uses _signed_ canonical outputs.
 *              Accordingly, we need a conditional addition of MLKEM_Q
 *              here to go from signed to unsigned representatives.
 *              This conditional addition is then dropped from all
 *              polynomial compression functions instead (see `compress.c`). */
MLK_INTERNAL_API void mlk_poly_reduce(mlk_poly *r)
{
  unsigned i;

  for (i = 0; i < MLKEM_N; i++)
  {
    /* Barrett reduction, giving signed canonical representative */
    s16int t = mlk_barrett_reduce(r->coeffs[i]);
    /* Conditional addition to get unsigned canonical representative */
    r->coeffs[i] = mlk_scalar_signed_to_unsigned_q(t);
  }

}

/* Reference: `poly_add()` in the reference implementation @[REF].
 *            - We use destructive version (output=first input) to avoid
 *              reasoning about aliasing in the CBMC specification */
MLK_INTERNAL_API
void mlk_poly_add(mlk_poly *r, const mlk_poly *b)
{
  unsigned i;
  for (i = 0; i < MLKEM_N; i++)
  {
    /* The preconditions imply that the addition stays within s16int. */
    r->coeffs[i] = (s16int)(r->coeffs[i] + b->coeffs[i]);
  }
}

/* Reference: `poly_sub()` in the reference implementation @[REF].
 *            - We use destructive version (output=first input) to avoid
 *              reasoning about aliasing in the CBMC specification */
MLK_INTERNAL_API
void mlk_poly_sub(mlk_poly *r, const mlk_poly *b)
{
  unsigned i;
  for (i = 0; i < MLKEM_N; i++)
  {
    /* The preconditions imply that the subtraction stays within s16int. */
    r->coeffs[i] = (s16int)(r->coeffs[i] - b->coeffs[i]);
  }
}

#include "zetas.inc"

/* Reference: Does not exist in the reference implementation @[REF].
 *            - The reference implementation does not use a
 *              multiplication cache ('mulcache'). This idea originates
 *              from @[NeonNTT] and is used at the C level here. */
MLK_INTERNAL_API void mlk_poly_mulcache_compute(mlk_poly_mulcache *x,
                                                     const mlk_poly *a)
{
  unsigned i;
  for (i = 0; i < MLKEM_N / 4; i++)
  {
    x->coeffs[2 * i + 0] = mlk_fqmul(a->coeffs[4 * i + 1], mlk_zetas[64 + i]);
    /* The values in zeta table are <= MLKEM_Q in absolute value,
     * so the negation in s16int is safe. */
    x->coeffs[2 * i + 1] =
        mlk_fqmul(a->coeffs[4 * i + 3], (s16int)(-mlk_zetas[64 + i]));
  }

  /*
   * This bound is true for the C implementation, but not needed
   * in the higher level bounds reasoning. It is thus omitted
   * from the spec to not unnecessarily constrain native
   * implementations, but checked here nonetheless.
   */
}

/*
 * Computes a block CT butterflies with a fixed twiddle factor,
 * using Montgomery multiplication.
 * Parameters:
 * - r: Pointer to base of polynomial (_not_ the base of butterfly block)
 * - root: Twiddle factor to use for the butterfly. This must be in
 *         Montgomery form and signed canonical.
 * - start: Offset to the beginning of the butterfly block
 * - len: Index difference between coefficients subject to a butterfly
 * - bound: Ghost variable describing coefficient bound: Prior to `start`,
 *          coefficients must be bound by `bound + MLKEM_Q`. Post `start`,
 *          they must be bound by `bound`.
 * When this function returns, output coefficients in the index range
 * [start, start+2*len) have bound bumped to `bound + MLKEM_Q`.
 * Example:
 * - start=8, len=4
 *   This would compute the following four butterflies
 *          8     --    12
 *             9    --     13
 *                10   --     14
 *                   11   --     15
 * - start=4, len=2
 *   This would compute the following two butterflies
 *          4 -- 6
 *             5 -- 7
 */

/* Reference: Embedded in `ntt()` in the reference implementation @[REF]. */
static void mlk_ntt_butterfly_block(s16int r[MLKEM_N], s16int zeta,
                                    unsigned start, unsigned len,
                                    unsigned bound)
{
  /* `bound` is a ghost variable only needed in the CBMC specification */
  unsigned j;
  ((void)bound);
  for (j = start; j < start + len; j++)
  {
    s16int t;
    t = mlk_fqmul(r[j + len], zeta);
    /* The precondition implies that the arithmetic does not overflow. */
    r[j + len] = (s16int)(r[j] - t);
    r[j] = (s16int)(r[j] + t);
  }
}

/*
 * Compute one layer of forward NTT
 * Parameters:
 * - r: Pointer to base of polynomial
 * - layer: Variable indicating which layer is being applied.
 */

/* Reference: Embedded in `ntt()` in the reference implementation @[REF]. */
static void mlk_ntt_layer(s16int r[MLKEM_N], unsigned layer)
{
  unsigned start, k, len;
  /* Twiddle factors for layer n are at indices 2^(n-1)..2^n-1. */
  k = 1u << (layer - 1);
  len = (unsigned)MLKEM_N >> layer;
  for (start = 0; start < MLKEM_N; start += 2 * len)
  {
    s16int zeta = mlk_zetas[k++];
    mlk_ntt_butterfly_block(r, zeta, start, len, layer * MLKEM_Q);
  }
}

/*
 * Compute full forward NTT
 * NOTE: This particular implementation satisfies a much tighter
 * bound on the output coefficients (5*q) than the contractual one (8*q),
 * but this is not needed in the calling code. Should we change the
 * base multiplication strategy to require smaller NTT output bounds,
 * the proof may need strengthening.
 */

/* Reference: `ntt()` in the reference implementation @[REF].
 * - Iterate over `layer` instead of `len` in the outer loop
 *   to simplify computation of zeta index. */
MLK_INTERNAL_API void mlk_poly_ntt(mlk_poly *p)
{
  unsigned layer;
  s16int *r;


  r = p->coeffs;

  for (layer = 1; layer <= 7; layer++)
  {
    mlk_ntt_layer(r, layer);
  }

  /* Check the stronger bound */
}


/* Compute one layer of inverse NTT */

/* Reference: Embedded into `invntt()` in the reference implementation @[REF] */
static void mlk_invntt_layer(s16int *r, unsigned layer)
{
  unsigned start, k, len;
  len = (unsigned)MLKEM_N >> layer;
  k = (1u << layer) - 1;
  for (start = 0; start < MLKEM_N; start += 2 * len)
  {
    unsigned j;
    s16int zeta = mlk_zetas[k--];
    for (j = start; j < start + len; j++)
    {
      s16int t = r[j];
      /* The preconditions imply that the arithmetic does not overflow. */
      r[j] = mlk_barrett_reduce((s16int)(t + r[j + len]));
      r[j + len] = (s16int)(r[j + len] - t);
      r[j + len] = mlk_fqmul(r[j + len], zeta);
    }
  }
}

/* Reference: `invntt()` in the reference implementation @[REF]
 *            - We normalize at the beginning of the inverse NTT,
 *              while the reference implementation normalizes at
 *              the end. This allows us to drop a call to `poly_reduce()`
 *              from the base multiplication. */
MLK_INTERNAL_API void mlk_poly_invntt_tomont(mlk_poly *p)
{
  unsigned j, layer;
  const s16int f = 1441; /* check-magic: 1441 == pow(2,32 - 7,MLKEM_Q) */
  s16int *r = p->coeffs;

  /*
   * Scale input polynomial to account for Montgomery factor
   * and NTT twist. This also brings coefficients down to
   * absolute value < MLKEM_Q.
   */
  for (j = 0; j < MLKEM_N; j++)
  {
    r[j] = mlk_fqmul(r[j], f);
  }

  /* Run the invNTT layers */
  for (layer = 7; layer > 0; layer--)
  {
    mlk_invntt_layer(r, layer);
  }

}
