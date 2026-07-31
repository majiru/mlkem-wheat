/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLK_COMMON_H
#define MLK_COMMON_H

#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>
#include "limits.h"

#define NULL 0

#define MLK_BUILD_INTERNAL

#include "mlkem_native_config.h"

#include "params.h"
#include "sys.h"

#define MLK_INTERNAL_API
#define MLK_INTERNAL_DATA_DECLARATION extern
#define MLK_INTERNAL_DATA_DEFINITION
#define MLK_EXTERNAL_API

#define MLK_CONCAT_(x1, x2) x1##x2
#define MLK_CONCAT(x1, x2) MLK_CONCAT_(x1, x2)

#define MLK_ADD_PARAM_SET(s) MLK_CONCAT(s, MLK_CONFIG_PARAMETER_SET)

#define MLK_NAMESPACE_PREFIX MLK_CONCAT(MLK_CONFIG_NAMESPACE_PREFIX, _)
#define MLK_NAMESPACE_PREFIX_K \
  MLK_CONCAT(MLK_ADD_PARAM_SET(MLK_CONFIG_NAMESPACE_PREFIX), _)

/* Functions are prefixed by MLK_CONFIG_NAMESPACE_PREFIX.
 *
 * If multiple parameter sets are used, functions depending on the parameter
 * set are additionally prefixed with 512/768/1024. See mlkem_native_config.h.
 *
 * Example: If MLK_CONFIG_NAMESPACE_PREFIX is mlkem, then
 * MLK_NAMESPACE_K(enc) becomes mlkem512_enc/mlkem768_enc/mlkem1024_enc.
 */
#define MLK_NAMESPACE(s) MLK_CONCAT(MLK_NAMESPACE_PREFIX, s)
#define MLK_NAMESPACE_K(s) MLK_CONCAT(MLK_NAMESPACE_PREFIX_K, s)

#define MLK_FIPS202_HEADER_FILE "fips202.h"

/* Standard library function replacements */
#define mlk_memcpy memcpy
#define mlk_memset memset


/* Allocation macros for large local structures
 *
 * MLK_ALLOC(v, T, N) declares T *v and attempts to point it to an T[N]
 * MLK_FREE(v, T, N) zeroizes and frees the allocation
 *
 * Default implementation uses stack allocation.
 * Can be overridden by setting the config option MLK_CONFIG_CUSTOM_ALLOC_FREE
 * and defining MLK_CUSTOM_ALLOC and MLK_CUSTOM_FREE.
 */

#define MLK_CONTEXT_PARAMETERS_0(context) ()
#define MLK_CONTEXT_PARAMETERS_1(arg0, context) (arg0)
#define MLK_CONTEXT_PARAMETERS_2(arg0, arg1, context) (arg0, arg1)
#define MLK_CONTEXT_PARAMETERS_3(arg0, arg1, arg2, context) (arg0, arg1, arg2)
#define MLK_CONTEXT_PARAMETERS_4(arg0, arg1, arg2, arg3, context) \
  (arg0, arg1, arg2, arg3)

/* Default: stack allocation */

#define MLK_ALLOC(v, T, N, context) \
  MLK_ALIGN T mlk_alloc_##v[N];     \
  T *v = mlk_alloc_##v

/* TODO: This leads to a circular dependency between common and verify.h
 * It just works out before we're at the end of the file, but it's still
 * prone to issues in the future. */
#include "verify.h"
#define MLK_FREE(v, T, N, context)                     \
  do                                                   \
  {                                                    \
    mlk_zeroize(mlk_alloc_##v, sizeof(mlk_alloc_##v)); \
    (v) = NULL;                                        \
    USED((v));                                         \
  } while (0)

/****************************** Error codes ***********************************/

/* Generic failure condition */
#define MLK_ERR_FAIL -1
/* An allocation failed. This can only happen if MLK_CONFIG_CUSTOM_ALLOC_FREE
 * is defined and the provided MLK_CUSTOM_ALLOC can fail. */
#define MLK_ERR_OUT_OF_MEMORY -2
/* An rng failure occured. Might be due to insufficient entropy or
 * system misconfiguration. */
#define MLK_ERR_RNG_FAIL -3

#endif /* !MLK_COMMON_H */
