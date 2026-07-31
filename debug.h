/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLK_DEBUG_H
#define MLK_DEBUG_H

#ifdef MLKEM_DEBUG

/**
 * Check debug assertion.
 *
 * Prints an error message to stderr and calls exit(1) on failure.
 *
 * @param[in] file Filename.
 * @param     line Line number.
 * @param     val  Value asserted to be non-zero.
 */
void mlk_debug_check_assert(const char *file, int line, const int val);

/**
 * Check whether values in an array of s16int are within specified bounds.
 *
 * Prints an error message to stderr and calls exit(1) on failure.
 *
 * @param[in] file                  Filename.
 * @param     line                  Line number.
 * @param[in] ptr                   Base of array to be checked.
 * @param     len                   Number of s16int in @p ptr.
 * @param     lower_bound_exclusive Exclusive lower bound.
 * @param     upper_bound_exclusive Exclusive upper bound.
 */
void mlk_debug_check_bounds(const char *file, int line, const s16int *ptr,
                            unsigned len, int lower_bound_exclusive,
                            int upper_bound_exclusive);

/* Check assertion, calling exit() upon failure
 *
 * val: Value that's asserted to be non-zero
 */
#define mlk_assert(val) mlk_debug_check_assert(__FILE__, __LINE__, (val))

/* Check bounds in array of s16int's
 * ptr: Base of s16int array; will be explicitly cast to s16int*,
 *      so you may pass a byte-compatible type such as mlk_poly or mlk_polyvec.
 * len: Number of s16int in array
 * value_lb: Inclusive lower value bound
 * value_ub: Exclusive upper value bound */
#define mlk_assert_bound(ptr, len, value_lb, value_ub)                      \
  mlk_debug_check_bounds(__FILE__, __LINE__, (const s16int *)(ptr), (len), \
                         (value_lb) - 1, (value_ub))

/* Check absolute bounds in array of s16int's
 * ptr: Base of array, expression of type s16int*
 * len: Number of s16int in array
 * value_abs_bd: Exclusive absolute upper bound */
#define mlk_assert_abs_bound(ptr, len, value_abs_bd) \
  mlk_assert_bound((ptr), (len), (-(value_abs_bd) + 1), (value_abs_bd))

/* Version of bounds assertions for 2-dimensional arrays */
#define mlk_assert_bound_2d(ptr, len0, len1, value_lb, value_ub) \
  mlk_assert_bound((ptr), ((len0) * (len1)), (value_lb), (value_ub))

#define mlk_assert_abs_bound_2d(ptr, len0, len1, value_abs_bd) \
  mlk_assert_abs_bound((ptr), ((len0) * (len1)), (value_abs_bd))

#else

#define mlk_assert(val) \
  do                    \
  {                     \
  } while (0)
#define mlk_assert_bound(ptr, len, value_lb, value_ub) \
  do                                                   \
  {                                                    \
  } while (0)
#define mlk_assert_abs_bound(ptr, len, value_abs_bd) \
  do                                                 \
  {                                                  \
  } while (0)

#define mlk_assert_bound_2d(ptr, len0, len1, value_lb, value_ub) \
  do                                                             \
  {                                                              \
  } while (0)

#define mlk_assert_abs_bound_2d(ptr, len0, len1, value_abs_bd) \
  do                                                           \
  {                                                            \
  } while (0)


#endif /* !MLKEM_DEBUG */
#endif /* !MLK_DEBUG_H */
