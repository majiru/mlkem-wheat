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

#include "common.h"
#include "compress.h"
#include "debug.h"
#include "verify.h"

/* Reference: `poly_compress()` in the reference implementation @[REF],
 *            for ML-KEM-{512,768}.
 *            - In contrast to the reference implementation, we assume
 *              unsigned canonical coefficients here.
 *              The reference implementation works with coefficients
 *              in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
MLK_INTERNAL_API
void mlk_poly_compress_d4(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D4], const mlk_poly *a)
{
  unsigned i;
  mlk_assert_bound(a, MLKEM_N, 0, MLKEM_Q);

  for (i = 0; i < MLKEM_N / 8; i++)
  {
    unsigned j;
    u8int t[8] = {0};
    for (j = 0; j < 8; j++)
    {
      t[j] = mlk_scalar_compress_d4(a->coeffs[8 * i + j]);
    }

    /* All t[i] are 4-bit wide, so the truncations don't alter the value. */
    r[i * 4] = (u8int)(t[0] | (t[1] << 4));
    r[i * 4 + 1] = (u8int)(t[2] | (t[3] << 4));
    r[i * 4 + 2] = (u8int)(t[4] | (t[5] << 4));
    r[i * 4 + 3] = (u8int)(t[6] | (t[7] << 4));
  }
}

/* Reference: Embedded into `polyvec_compress()` in the
 *            reference implementation, for ML-KEM-{512,768}.
 *            - In contrast to the reference implementation, we assume
 *              unsigned canonical coefficients here.
 *              The reference implementation works with coefficients
 *              in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
MLK_INTERNAL_API
void mlk_poly_compress_d10(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D10], const mlk_poly *a)
{
  unsigned j;
  mlk_assert_bound(a, MLKEM_N, 0, MLKEM_Q);
  for (j = 0; j < MLKEM_N / 4; j++)
  {
    unsigned k;
    u16int t[4];
    for (k = 0; k < 4; k++)
    {
      t[k] = mlk_scalar_compress_d10(a->coeffs[4 * j + k]);
    }

    /*
     * Make all implicit truncation explicit. No data is being
     * truncated for the LHS's since each t[i] is 10-bit in size.
     */
    r[5 * j + 0] = (u8int)((t[0] >> 0) & 0xFF);
    r[5 * j + 1] = (u8int)((t[0] >> 8) | ((t[1] << 2) & 0xFF));
    r[5 * j + 2] = (u8int)((t[1] >> 6) | ((t[2] << 4) & 0xFF));
    r[5 * j + 3] = (u8int)((t[2] >> 4) | ((t[3] << 6) & 0xFF));
    r[5 * j + 4] = (u8int)(t[3] >> 2);
  }
}

/* Reference: `poly_decompress()` in the reference implementation @[REF],
 *            for ML-KEM-{512,768}. */
MLK_INTERNAL_API
void mlk_poly_decompress_d4(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D4])
{
  unsigned i;
  for (i = 0; i < MLKEM_N / 2; i++)
  {
    r->coeffs[2 * i + 0] = mlk_scalar_decompress_d4((a[i] >> 0) & 0xF);
    r->coeffs[2 * i + 1] = mlk_scalar_decompress_d4((a[i] >> 4) & 0xF);
  }

  mlk_assert_bound(r, MLKEM_N, 0, MLKEM_Q);
}

/* Reference: Embedded into `polyvec_decompress()` in the
 *            reference implementation, for ML-KEM-{512,768}. */
MLK_INTERNAL_API
void mlk_poly_decompress_d10(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D10])
{
  unsigned j;
  for (j = 0; j < MLKEM_N / 4; j++)
  {
    unsigned k;
    u16int t[4];
    u8int const *base = &a[5 * j];

    t[0] = 0x3FF & ((base[0] >> 0) | ((u16int)base[1] << 8));
    t[1] = 0x3FF & ((base[1] >> 2) | ((u16int)base[2] << 6));
    t[2] = 0x3FF & ((base[2] >> 4) | ((u16int)base[3] << 4));
    t[3] = 0x3FF & ((base[3] >> 6) | ((u16int)base[4] << 2));

    for (k = 0; k < 4; k++)
    {
      r->coeffs[4 * j + k] = mlk_scalar_decompress_d10(t[k]);
    }
  }

  mlk_assert_bound(r, MLKEM_N, 0, MLKEM_Q);
}

/* Reference: `poly_compress()` in the reference implementation @[REF],
 *            for ML-KEM-1024.
 *            - In contrast to the reference implementation, we assume
 *              unsigned canonical coefficients here.
 *              The reference implementation works with coefficients
 *              in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
MLK_INTERNAL_API
void mlk_poly_compress_d5(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D5], const mlk_poly *a)
{
  unsigned i;
  mlk_assert_bound(a, MLKEM_N, 0, MLKEM_Q);

  for (i = 0; i < MLKEM_N / 8; i++)
  {
    unsigned j;
    u8int t[8] = {0};
    for (j = 0; j < 8; j++)
    {
      t[j] = mlk_scalar_compress_d5(a->coeffs[8 * i + j]);
    }

    r[i * 5] = (u8int)(0xFF & ((t[0] >> 0) | (t[1] << 5)));
    r[i * 5 + 1] = (u8int)(0xFF & ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7)));
    r[i * 5 + 2] = (u8int)(0xFF & ((t[3] >> 1) | (t[4] << 4)));
    r[i * 5 + 3] = (u8int)(0xFF & ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6)));
    r[i * 5 + 4] = (u8int)(0xFF & ((t[6] >> 2) | (t[7] << 3)));
  }
}

/* Reference: Embedded into `polyvec_compress()` in the
 *            reference implementation, for ML-KEM-1024.
 *            - In contrast to the reference implementation, we assume
 *              unsigned canonical coefficients here.
 *              The reference implementation works with coefficients
 *              in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
MLK_INTERNAL_API
void mlk_poly_compress_d11(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D11], const mlk_poly *a)
{
  unsigned j;
  mlk_assert_bound(a, MLKEM_N, 0, MLKEM_Q);

  for (j = 0; j < MLKEM_N / 8; j++)
  {
    unsigned k;
    u16int t[8];
    for (k = 0; k < 8; k++)
    {
      t[k] = mlk_scalar_compress_d11(a->coeffs[8 * j + k]);
    }

    /*
     * Make all implicit truncation explicit. No data is being
     * truncated for the LHS's since each t[i] is 11-bit in size.
     */
    r[11 * j + 0] = (u8int)((t[0] >> 0) & 0xFF);
    r[11 * j + 1] = (u8int)((t[0] >> 8) | ((t[1] << 3) & 0xFF));
    r[11 * j + 2] = (u8int)((t[1] >> 5) | ((t[2] << 6) & 0xFF));
    r[11 * j + 3] = (u8int)((t[2] >> 2) & 0xFF);
    r[11 * j + 4] = (u8int)((t[2] >> 10) | ((t[3] << 1) & 0xFF));
    r[11 * j + 5] = (u8int)((t[3] >> 7) | ((t[4] << 4) & 0xFF));
    r[11 * j + 6] = (u8int)((t[4] >> 4) | ((t[5] << 7) & 0xFF));
    r[11 * j + 7] = (u8int)((t[5] >> 1) & 0xFF);
    r[11 * j + 8] = (u8int)((t[5] >> 9) | ((t[6] << 2) & 0xFF));
    r[11 * j + 9] = (u8int)((t[6] >> 6) | ((t[7] << 5) & 0xFF));
    r[11 * j + 10] = (u8int)(t[7] >> 3);
  }
}

/* Reference: `poly_decompress()` in the reference implementation @[REF],
 *            for ML-KEM-1024. */
MLK_INTERNAL_API
void mlk_poly_decompress_d5(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D5])
{
  unsigned i;
  for (i = 0; i < MLKEM_N / 8; i++)
  {
    unsigned j;
    u8int t[8];
    const unsigned offset = i * 5;
    /*
     * Explicitly truncate to avoid warning about
     * implicit truncation in CBMC and unwind loop for ease
     * of proof.
     */

    /*
     * Decompress 5 8-bit bytes (so 40 bits) into
     * 8 5-bit values stored in t[]
     */
    t[0] = 0x1F & (a[offset + 0] >> 0);
    t[1] = 0x1F & ((a[offset + 0] >> 5) | (a[offset + 1] << 3));
    t[2] = 0x1F & (a[offset + 1] >> 2);
    t[3] = 0x1F & ((a[offset + 1] >> 7) | (a[offset + 2] << 1));
    t[4] = 0x1F & ((a[offset + 2] >> 4) | (a[offset + 3] << 4));
    t[5] = 0x1F & (a[offset + 3] >> 1);
    t[6] = 0x1F & ((a[offset + 3] >> 6) | (a[offset + 4] << 2));
    t[7] = 0x1F & (a[offset + 4] >> 3);

    /* and copy to the correct slice in r[] */
    for (j = 0; j < 8; j++)
    {
      r->coeffs[8 * i + j] = mlk_scalar_decompress_d5(t[j]);
    }
  }

  mlk_assert_bound(r, MLKEM_N, 0, MLKEM_Q);
}

/* Reference: Embedded into `polyvec_decompress()` in the
 *            reference implementation, for ML-KEM-1024. */
MLK_INTERNAL_API
void mlk_poly_decompress_d11(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D11])
{
  unsigned j;
  for (j = 0; j < MLKEM_N / 8; j++)
  {
    unsigned k;
    u16int t[8];
    u8int const *base = &a[11 * j];
    t[0] = 0x7FF & ((base[0] >> 0) | ((u16int)base[1] << 8));
    t[1] = 0x7FF & ((base[1] >> 3) | ((u16int)base[2] << 5));
    t[2] = 0x7FF & ((base[2] >> 6) | ((u16int)base[3] << 2) |
                    ((u16int)base[4] << 10));
    t[3] = 0x7FF & ((base[4] >> 1) | ((u16int)base[5] << 7));
    t[4] = 0x7FF & ((base[5] >> 4) | ((u16int)base[6] << 4));
    t[5] = 0x7FF & ((base[6] >> 7) | ((u16int)base[7] << 1) |
                    ((u16int)base[8] << 9));
    t[6] = 0x7FF & ((base[8] >> 2) | ((u16int)base[9] << 6));
    t[7] = 0x7FF & ((base[9] >> 5) | ((u16int)base[10] << 3));

    for (k = 0; k < 8; k++)
    {
      r->coeffs[8 * j + k] = mlk_scalar_decompress_d11(t[k]);
    }
  }

  mlk_assert_bound(r, MLKEM_N, 0, MLKEM_Q);
}

/* Reference: `poly_tobytes()` in the reference implementation @[REF].
 *            - In contrast to the reference implementation, we assume
 *              unsigned canonical coefficients here.
 *              The reference implementation works with coefficients
 *              in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
MLK_INTERNAL_API
void mlk_poly_tobytes(u8int r[MLKEM_POLYBYTES], const mlk_poly *a)
{
  unsigned i;
  mlk_assert_bound(a, MLKEM_N, 0, MLKEM_Q);

  for (i = 0; i < MLKEM_N / 2; i++)
  {
    /* The conversion to u16int is safe since we assume that
     * the coefficients of `a` are non-negative. */
    const u16int t0 = (u16int)a->coeffs[2 * i];
    const u16int t1 = (u16int)a->coeffs[2 * i + 1];
    /*
     * t0 and t1 are both < MLKEM_Q, so contain at most 12 bits each of
     * significant data, so these can be packed into 24 bits or exactly
     * 3 bytes, as follows.
     */

    /* Least significant bits 0 - 7 of t0. */
    r[3 * i + 0] = (u8int)(t0 & 0xFF);

    /*
     * Most significant bits 8 - 11 of t0 become the least significant
     * nibble of the second byte. The least significant 4 bits
     * of t1 become the upper nibble of the second byte.
     *
     * The conversion to u8int does not alter the value.
     */
    r[3 * i + 1] = (u8int)((t0 >> 8) | ((t1 << 4) & 0xF0));

    /* Bits 4 - 11 of t1 become the third byte. The conversion to u8int
     * does not alter the value because t1 is 12-bit wide. */
    r[3 * i + 2] = (u8int)(t1 >> 4);
  }
}

/* Reference: `poly_frombytes()` in the reference implementation @[REF]. */
MLK_INTERNAL_API
void mlk_poly_frombytes(mlk_poly *r, const u8int a[MLKEM_POLYBYTES])
{
  unsigned i;
  for (i = 0; i < MLKEM_N / 2; i++)
  {
    const u8int t0 = a[3 * i + 0];
    const u8int t1 = a[3 * i + 1];
    const u8int t2 = a[3 * i + 2];
    r->coeffs[2 * i + 0] = (s16int)(t0 | ((t1 << 8) & 0xFFF));
    r->coeffs[2 * i + 1] = (s16int)((t1 >> 4) | (t2 << 4));
  }

  /* Note that the coefficients are not canonical */
  mlk_assert_bound(r, MLKEM_N, 0, MLKEM_UINT12_LIMIT);
}

/* Reference: `poly_frommsg()` in the reference implementation @[REF].
 *            - We use a value barrier around the bit-selection mask to
 *              reduce the risk of compiler-introduced branches.
 *              The reference implementation contains the expression
 *              `(msg[i] >> j) & 1` which the compiler can reason must
 *              be either 0 or 1. */
MLK_INTERNAL_API
void mlk_poly_frommsg(mlk_poly *r, const u8int msg[MLKEM_INDCPA_MSGBYTES])
{
  unsigned i;
#if (MLKEM_INDCPA_MSGBYTES != MLKEM_N / 8)
#error "MLKEM_INDCPA_MSGBYTES must be equal to MLKEM_N/8 bytes!"
#endif

  for (i = 0; i < MLKEM_N / 8; i++)
  {
    unsigned j;
    for (j = 0; j < 8; j++)
    {
      /* mlk_ct_sel_int16(MLKEM_Q_HALF, 0, b) is `Decompress_1(b != 0)`
       * as per @[FIPS203, Eq (4.8)]. */

      /* Prevent the compiler from recognizing this as a bit selection */
      u8int mask = mlk_value_barrier_u8((u8int)(1u << j));
      r->coeffs[8 * i + j] = mlk_ct_sel_int16(MLKEM_Q_HALF, 0, msg[i] & mask);
    }
  }
  mlk_assert_abs_bound(r, MLKEM_N, MLKEM_Q);
}

/* Reference: `poly_tomsg()` in the reference implementation @[REF].
 *            - In contrast to the reference implementation, we assume
 *              unsigned canonical coefficients here.
 *              The reference implementation works with coefficients
 *              in the range [-(MLKEM_Q-1), MLKEM_Q-1].
 */
MLK_INTERNAL_API
void mlk_poly_tomsg(u8int msg[MLKEM_INDCPA_MSGBYTES], const mlk_poly *a)
{
  unsigned i;
  mlk_assert_bound(a, MLKEM_N, 0, MLKEM_Q);

  for (i = 0; i < MLKEM_N / 8; i++)
  {
    unsigned j;
    msg[i] = 0;
    for (j = 0; j < 8; j++)
    {
      u32int t = mlk_scalar_compress_d1(a->coeffs[8 * i + j]);
      msg[i] |= (u8int)(t << j);
    }
  }
}

