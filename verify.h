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
 *
 * - [libmceliece]
 *   libmceliece implementation of Classic McEliece
 *   Bernstein, Chou
 *   https://lib.mceliece.org/
 *
 * - [optblocker]
 *   PQC forum post on opt-blockers using volatile globals
 *   Daniel J. Bernstein
 *   https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/hqbtIGFKIpU/m/H14H0wOlBgAJ
 */

/* Constant-time comparisons and conditional operations

   We reduce the risk for compilation into variable-time code
   through the use of 'value barriers'.

   Functionally, a value barrier is a no-op. To the compiler, however,
   it constitutes an arbitrary modification of its input, and therefore
   harden's value propagation and range analysis.

   We consider two approaches to implement a value barrier:
   - An empty inline asm block which marks the target value as clobbered.
   - XOR'ing with the value of a volatile global that's set to 0;
     see @[optblocker] for a discussion of this idea, and
     @[libmceliece, inttypes/crypto_intN.h] for an implementation.

   The first approach is cheap because it only prevents the compiler
   from reasoning about the value of the variable past the barrier,
   but does not directly generate additional instructions.

   The second approach generates redundant loads and XOR operations
   and therefore comes at a higher runtime cost. However, it appears
   more robust towards optimization, as compilers should never drop
   a volatile load.

   We use the empty-ASM value barrier for GCC and clang, and fall
   back to the global volatile barrier otherwise.

   The global value barrier can be forced by setting
   MLK_CONFIG_NO_ASM_VALUE_BARRIER.

*/

u64int mlk_ct_get_optblocker_u64(void);
u8int mlk_ct_get_optblocker_u8(void);
u32int mlk_ct_get_optblocker_u32(void);
s32int mlk_ct_get_optblocker_i32(void);
u32int mlk_value_barrier_u32(u32int b);
s32int mlk_value_barrier_i32(s32int b);
u8int mlk_value_barrier_u8(u8int b);
s16int mlk_cast_u16into_int16(u16int x);
u16int mlk_cast_s32into_uint16(s32int x);
u16int mlk_cast_s16into_uint16(s32int x);
u16int mlk_ct_cmask_neg_i16(s16int x);
u16int mlk_ct_cmask_nonzero_u16(u16int x);
u8int mlk_ct_cmask_nonzero_u8(u8int x);
s16int mlk_ct_sel_int16(s16int a, s16int b, u16int cond);
u8int mlk_ct_sel_uint8(u8int a, u8int b, u8int cond);
u8int mlk_ct_memcmp(const u8int *a, const u8int *b, const ulong len);
void mlk_ct_cmov_zero(u8int *r, const u8int *x, ulong len, u8int b);
void mlk_zeroize(void *ptr, ulong len);
