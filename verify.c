/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

/**
 * Return 0 if input is zero, and -1 otherwise.
 *
 * @reference{Embedded in `cmov_int16()` in the reference implementation
 * @[REF]. Uses a value barrier and shift instead of `b = -b` to convert
 * condition into mask.}
 *
 * @param x Value to be converted into a mask.
 *
 * @return Mask value (0 or 0xFFFF).
 */
u16int mlk_ct_cmask_nonzero_u16(u16int x)
{
  s32int tmp = -((s32int)x);
  tmp >>= 16;
  return (u16int)(tmp & (s32int)0xffff);
}

/**
 * Return 0 if input is zero, and -1 otherwise.
 *
 * @reference{Embedded in `verify()` and `cmov()` in the reference
 * implementation @[REF]. We include a value barrier not present in the
 * reference implementation, to prevent the compiler from realizing that
 * this function returns a mask.}
 *
 * @param x Value to be converted into a mask.
 *
 * @return Mask value (0 or 0xFF).
 */
u8int mlk_ct_cmask_nonzero_u8(u8int x)
{
  u16int mask = mlk_ct_cmask_nonzero_u16((u16int)x);
  return (u8int)(mask & 0xFF);
}

/**
 * Functionally equivalent to cond ? a : b, but implemented with guards
 * against compiler-introduced branches.
 *
 * @spec{With `a = MLKEM_Q_HALF` and `b=0`, this essentially implements
 * `Decompress_1` @[FIPS203, Eq (4.8)] in `mlk_poly_frommsg()`. With
 * `a = x + MLKEM_Q`, `b = x`, and `cond` indicating whether `x` is negative,
 * implements signed->unsigned conversion of modular representatives.
 * Questions of representation are not considered in the specification
 * @[FIPS203, Section 2.4.1, "The pseudocode is agnostic regarding how an
 * integer modulo 𝑚 is represented in actual implementations"].}
 *
 * @reference{Embedded in the polynomial compression function in the
 * reference implementation @[REF]. Used as part of signed->unsigned
 * conversion for modular representatives. This happens in `mlk_poly_reduce()`
 * here, and as part of polynomial compression functions in @[REF]. See
 * `mlk_poly_reduce()`. Barrier to reduce the risk of compiler-introduced
 * branches. For `a = MLKEM_Q_HALF` and `b=0`, also embedded in
 * `poly_frommsg()` from the reference implementation, which uses
 * `cmov_int16()` instead.}
 *
 * @param a    First alternative.
 * @param b    Second alternative.
 * @param cond Condition variable.
 *
 * @return @p a if @p cond != 0, else @p b.
 */
s16int mlk_ct_sel_int16(s16int a, s16int b, u16int cond)
{
  u16int au = (u16int)(((s32int)a) & (s32int)0xffff);
  u16int bu = (u16int)(((s32int)b) & (s32int)0xffff);
  u16int res = bu ^ (mlk_ct_cmask_nonzero_u16(cond) & (au ^ bu));
  return (s16int)res;
}

/**
 * Functionally equivalent to cond ? a : b, but implemented with guards
 * against compiler-introduced branches.
 *
 * @reference{Embedded into `cmov()` in the reference implementation @[REF].
 * Uses a value barrier to get mask from condition value.}
 *
 * @return @p a if @p cond != 0, else @p b.
 */
u8int mlk_ct_sel_uint8(u8int a, u8int b, u8int cond)
{
  return b ^ (mlk_ct_cmask_nonzero_u8(cond) & (a ^ b));
}

void mlk_ct_cmov_zero(u8int *r, const u8int *x,
                                        ulong len, u8int b)
{
  ulong i;
  for (i = 0; i < len; i++){
    r[i] = mlk_ct_sel_uint8(r[i], x[i], b);
  }
}
