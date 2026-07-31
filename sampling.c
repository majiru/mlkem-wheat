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

/**
 * Run rejection sampling on uniform random bytes to generate uniform random
 * integers mod MLKEM_Q.
 *
 * @reference{`rej_uniform()` in the reference implementation @[REF]. Our
 * signature differs from the reference in that it adds the offset and always
 * expects the base of the target buffer; this avoids shifting the buffer
 * base in the caller, which is tricky to reason about. Has an optional
 * fallback to a native implementation.}
 *
 * @param[out] r      Output buffer.
 * @param      target Requested number of 16-bit integers (uniform mod MLKEM_Q).
 *                    Must be <= 4096.
 * @param      offset Number of 16-bit integers that have already been
 *                    sampled. Must be <= @p target.
 * @param[in]  buf    Input buffer (assumed to be uniform random bytes).
 * @param      buflen Length of input buffer in bytes. Must be <= 4096 and a
 *                    multiple of 3.
 *
 * @note Strictly speaking, only a few values of @p buflen near UINT_MAX need
 *       excluding. The limit of 4096 is somewhat arbitrary but sufficient
 *       for all uses of this function. Similarly, the actual limit for
 *       @p target is UINT_MAX/2.
 *
 * @return New offset of sampled 16-bit integers, at most @p target and at
 *         least the initial @p offset. If the new offset is strictly less
 *         than @p target, the entire input buffer is guaranteed to have been
 *         consumed; otherwise no information is provided on how many bytes
 *         of the input buffer have been consumed.
 */

/* Reference: `rej_uniform()` in the reference implementation @[REF].
 *            - Our signature differs from the reference implementation
 *              in that it adds the offset and always expects the base of the
 *              target buffer. This avoids shifting the buffer base in the
 *              caller, which appears tricky to reason about. */
static unsigned mlk_rej_uniform(s16int *r, unsigned target,
                                               unsigned offset,
                                               const u8int *buf,
                                               unsigned buflen)
{
  unsigned ctr, pos;
  s16int val0, val1;


  ctr = offset;
  pos = 0;
  /* pos + 3 cannot overflow due to the assumption buflen <= 4096 */
  while (ctr < target && pos + 3 <= buflen)
  {
    val0 = ((buf[pos + 0] >> 0) | (buf[pos + 1] << 8)) & 0xFFF;
    val1 = ((buf[pos + 1] >> 4) | (buf[pos + 2] << 4)) & 0xFFF;
    pos += 3;

    if (val0 < MLKEM_Q)
    {
      r[ctr++] = val0;
    }
    if (ctr < target && val1 < MLKEM_Q)
    {
      r[ctr++] = val1;
    }
  }

  return ctr;
}

#define MLKEM_GEN_MATRIX_NBLOCKS                                       \
  ((12 * MLKEM_N / 8 * ((u32int)1 << 12) / MLKEM_Q + MLK_XOF_RATE) / \
   MLK_XOF_RATE)

MLK_INTERNAL_API
void mlk_poly_rej_uniform(mlk_poly *entry, u8int seed[MLKEM_SYMBYTES + 2])
{
  mlk_xof_ctx state;
  u8int buf[MLKEM_GEN_MATRIX_NBLOCKS * MLK_XOF_RATE];
  unsigned ctr, buflen;

  mlk_xof_init(&state);
  mlk_xof_absorb(&state, seed, MLKEM_SYMBYTES + 2);

  /* Initially, squeeze + sample heuristic number of MLKEM_GEN_MATRIX_NBLOCKS.
   */
  /* This should generate the matrix entry with high probability. */
  mlk_xof_squeezeblocks(buf, MLKEM_GEN_MATRIX_NBLOCKS, &state);
  buflen = MLKEM_GEN_MATRIX_NBLOCKS * MLK_XOF_RATE;
  ctr = mlk_rej_uniform(entry->coeffs, MLKEM_N, 0, buf, buflen);

  /* Squeeze + sample one more block a time until we're done */
  buflen = MLK_XOF_RATE;
  while (ctr < MLKEM_N)
  {
    mlk_xof_squeezeblocks(buf, 1, &state);
    ctr = mlk_rej_uniform(entry->coeffs, MLKEM_N, ctr, buf, buflen);
  }

  mlk_xof_release(&state);

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(buf, sizeof(buf));
}

/**
 * Load 4 bytes into a 32-bit integer in little-endian order.
 *
 * @reference{`load32_littleendian()` in the reference implementation @[REF].}
 *
 * @param[in] x Input byte array.
 *
 * @return 32-bit unsigned integer loaded from @p x.
 */
static u32int mlk_load32_littleendian(const u8int x[4])
{
  u32int r;
  r = (u32int)x[0];
  r |= (u32int)x[1] << 8;
  r |= (u32int)x[2] << 16;
  r |= (u32int)x[3] << 24;
  return r;
}

/* Reference: `cbd2()` in the reference implementation @[REF]. */
MLK_INTERNAL_API
void mlk_poly_cbd2(mlk_poly *r, const u8int buf[2 * MLKEM_N / 4])
{
  unsigned i;
  for (i = 0; i < MLKEM_N / 8; i++)
  {
    unsigned j;
    u32int t = mlk_load32_littleendian(buf + 4 * i);
    u32int d = t & 0x55555555;
    d += (t >> 1) & 0x55555555;

    for (j = 0; j < 8; j++)
    {
      const s16int a = (d >> (4 * j + 0)) & 0x3;
      const s16int b = (d >> (4 * j + 2)) & 0x3;
      r->coeffs[8 * i + j] = (s16int)(a - b);
    }
  }
}

/**
 * Load 3 bytes into a 32-bit integer in little-endian order.
 *
 * This function is only needed for ML-KEM-512.
 *
 * @reference{`load24_littleendian()` in the reference implementation @[REF].}
 *
 * @param[in] x Input byte array.
 *
 * @return 32-bit unsigned integer loaded from @p x (most significant byte
 *         is zero).
 */
static u32int mlk_load24_littleendian(const u8int x[3])
{
  u32int r;
  r = (u32int)x[0];
  r |= (u32int)x[1] << 8;
  r |= (u32int)x[2] << 16;
  return r;
}

/* Reference: `cbd3()` in the reference implementation @[REF]. */
MLK_INTERNAL_API
void mlk_poly_cbd3(mlk_poly *r, const u8int buf[3 * MLKEM_N / 4])
{
  unsigned i;
  for (i = 0; i < MLKEM_N / 4; i++)
  {
    unsigned j;
    const u32int t = mlk_load24_littleendian(buf + 3 * i);
    u32int d = t & 0x00249249;
    d += (t >> 1) & 0x00249249;
    d += (t >> 2) & 0x00249249;

    for (j = 0; j < 4; j++)
    {
      const s16int a = (d >> (6 * j + 0)) & 0x7;
      const s16int b = (d >> (6 * j + 3)) & 0x7;
      r->coeffs[4 * i + j] = (s16int)(a - b);
    }
  }
}

/* To facilitate single-compilation-unit (SCU) builds, undefine all macros.
 * Don't modify by hand -- this is auto-generated by scripts/autogen. */
#undef MLKEM_GEN_MATRIX_NBLOCKS
