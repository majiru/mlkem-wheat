/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#include "common.h"
#include "verify.h"
/*
 * Masking value used in constant-time functions from
 * verify.h to block the compiler's range analysis and
 * thereby reduce the risk of compiler-introduced branches.
 */
volatile u64int mlk_ct_opt_blocker_u64 = 0;

/* Helper functions for obtaining global masks of various sizes */

/* This contract is not proved but treated as an axiom.
 *
 * Its validity relies on the assumption that the global opt-blocker
 * constant mlk_ct_opt_blocker_u64 is not modified.
 */
u64int mlk_ct_get_optblocker_u64(void)
{ return mlk_ct_opt_blocker_u64; }

u8int mlk_ct_get_optblocker_u8(void)
{ return (u8int)mlk_ct_get_optblocker_u64(); }

u32int mlk_ct_get_optblocker_u32(void)
{ return (u32int)mlk_ct_get_optblocker_u64(); }

s32int mlk_ct_get_optblocker_i32(void)
{ return (s32int)mlk_ct_get_optblocker_u64(); }

/* Opt-blocker based implementation of value barriers */
u32int mlk_value_barrier_u32(u32int b)
{ return (b ^ mlk_ct_get_optblocker_u32()); }

s32int mlk_value_barrier_i32(s32int b)
{ return (b ^ mlk_ct_get_optblocker_i32()); }

u8int mlk_value_barrier_u8(u8int b)
{ return (b ^ mlk_ct_get_optblocker_u8()); }

/**
 * Cast uint16 value to int16.
 *
 * @param x Input value.
 *
 * @return For u16int x, the unique y in s16int so that x == y mod 2^16.
 *         Concretely:
 *         - x <  32768: returns x
 *         - x >= 32768: returns x - 65536
 */
s16int mlk_cast_u16into_int16(u16int x)
{
  /*
   * PORTABILITY: This relies on u16int -> s16int
   * being implemented as the inverse of s16int -> u16int,
   * which is implementation-defined (C99 6.3.1.3 (3))
   * CBMC (correctly) fails to prove this conversion is OK,
   * so we have to suppress that check here
   */
  return (s16int)x;
}

/**
 * Cast int32 value to uint16 as per C standard.
 *
 * @param x Input value.
 *
 * @return For s32int x, the unique y in u16int so that x == y mod 2^16.
 */
u16int mlk_cast_s32into_uint16(s32int x)
{
  return (u16int)(x & (s32int)UINT16_MAX);
}

/**
 * Cast int16 value to uint16 as per C standard.
 *
 * @param x Input value.
 *
 * @return For s16int x, the unique y in u16int so that x == y mod 2^16.
 */
u16int mlk_cast_s16into_uint16(s32int x)
{
  return mlk_cast_s32into_uint16((s32int)x);
}

/**
 * Return 0 if input is non-negative, and -1 otherwise.
 *
 * @reference{Embedded in the polynomial compression function in the
 * reference implementation @[REF]. Used as part of signed->unsigned
 * conversion for modular representatives to detect whether the input is
 * negative. This happens in `mlk_poly_reduce()` here, and as part of
 * polynomial compression functions in the reference implementation. See
 * `mlk_poly_reduce()`. We use value barriers to reduce the risk of
 * compiler-introduced branches.}
 *
 * @param x Value to be converted into a mask.
 *
 * @return Mask value (0 or 0xFFFF).
 */
u16int mlk_ct_cmask_neg_i16(s16int x)
{
  s32int tmp = mlk_value_barrier_i32((s32int)x);
  tmp >>= 16;
  return mlk_cast_s32into_uint16(tmp);
}

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
  s32int tmp = mlk_value_barrier_i32(-((s32int)x));
  tmp >>= 16;
  return mlk_cast_s32into_uint16(tmp);
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
  u16int au = mlk_cast_s16into_uint16(a);
  u16int bu = mlk_cast_s16into_uint16(b);
  u16int res = bu ^ (mlk_ct_cmask_nonzero_u16(cond) & (au ^ bu));
  return mlk_cast_u16into_int16(res);
}

/**
 * Functionally equivalent to cond ? a : b, but implemented with guards
 * against compiler-introduced branches.
 *
 * @reference{Embedded into `cmov()` in the reference implementation @[REF].
 * Uses a value barrier to get mask from condition value.}
 *
 * @param a    First alternative.
 * @param b    Second alternative.
 * @param cond Condition variable.
 *
 * @return @p a if @p cond != 0, else @p b.
 */
u8int mlk_ct_sel_uint8(u8int a, u8int b, u8int cond)
{
  return b ^ (mlk_ct_cmask_nonzero_u8(cond) & (a ^ b));
}

/**
 * Compare two arrays for equality in constant time.
 *
 * @spec{Used to securely compute conditional move in @[FIPS203, Algorithm
 * 18 (ML-KEM.Decaps_Internal, L9-11].}
 *
 * @reference{`cmov()` in the reference implementation @[REF]. We return
 * `u8int`, not `int`. We use an additional XOR-accumulator in the
 * comparison loop which prevents early abort if the OR-accumulator is 0xFF.
 * We use a value barrier to convert the OR-accumulator into a mask; the
 * reference implementation uses a shift which the compiler can argue to
 * result in either 0 or 0xFF..FF.}
 *
 * @param[in] a   First byte array.
 * @param[in] b   Second byte array.
 * @param     len Length of the byte arrays, upper-bounded to UINT16_MAX to
 *                control proof complexity only.
 *
 * @retval 0    The byte arrays are equal.
 * @retval 0xFF The byte arrays are not equal.
 */
u8int mlk_ct_memcmp(const u8int *a, const u8int *b,
                                        const ulong len)
{
  u8int r = 0, s = 0;
  unsigned i;

  for (i = 0; i < len; i++)
  {
    r |= a[i] ^ b[i];
    /* s is useless, but prevents the loop from being aborted once r=0xff. */
    s ^= a[i] ^ b[i];
  }

  /*
   * - Convert r into a mask; this may not be necessary, but is an additional
   *   safeguard
   *   towards leaking information about a and b.
   * - XOR twice with s, separated by a value barrier, to prevent the compile
   *   from dropping the s computation in the loop.
   */
  return (mlk_value_barrier_u8(mlk_ct_cmask_nonzero_u8(r) ^ s) ^ s);
}

/**
 * Copy len bytes from x to r if b is zero; don't modify x if b is non-zero.
 * Assumes two's complement representation of negative integers. Runs in
 * constant time.
 *
 * @spec{Used to securely compute conditional move in @[FIPS203, Algorithm
 * 18 (ML-KEM.Decaps_Internal, L9-11].}
 *
 * @reference{`cmov()` in the reference implementation @[REF]. We move if
 * condition value is `0`, not `1`. We use `mlk_ct_sel_uint8` for
 * constant-time selection.}
 *
 * @param[out] r   Output byte array.
 * @param[in]  x   Input byte array.
 * @param      len Number of bytes to be copied.
 * @param      b   Condition value.
 */
void mlk_ct_cmov_zero(u8int *r, const u8int *x,
                                        ulong len, u8int b)
{
  ulong i;
  for (i = 0; i < len; i++)
  {
    r[i] = mlk_ct_sel_uint8(r[i], x[i], b);
  }
}

/**
 * Force-zeroize a buffer.
 *
 * @spec{Used to implement @[FIPS203, Section 3.3, Destruction of
 * intermediate values].}
 *
 * @reference{Not present in the reference implementation @[REF].}
 *
 * @param[out] ptr Buffer to be zeroed.
 * @param      len Number of bytes to be zeroed.
 */
void mlk_zeroize(void *ptr, ulong len)
{
  memset(ptr, 0, len);
}
