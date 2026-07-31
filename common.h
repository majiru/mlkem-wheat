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
#include "sys.h"

#define MLKEM_N 256
#define MLKEM_Q 3329
#define MLKEM_Q_HALF ((MLKEM_Q + 1) / 2) /* 1665 */
#define MLKEM_UINT12_LIMIT 4096

#define MLKEM_SYMBYTES 32 /* size in bytes of hashes, and seeds */
#define MLKEM_SSBYTES 32  /* size in bytes of shared key */

#define MLKEM_POLYBYTES 384
#define MLKEM_POLYVECBYTES (MLKEM_K * MLKEM_POLYBYTES)

#define MLKEM_POLYCOMPRESSEDBYTES_D4 128
#define MLKEM_POLYCOMPRESSEDBYTES_D5 160
#define MLKEM_POLYCOMPRESSEDBYTES_D10 320
#define MLKEM_POLYCOMPRESSEDBYTES_D11 352

#define MLKEM_ETA2 2

#define MLKEM_INDCPA_MSGBYTES (MLKEM_SYMBYTES)
#define MLKEM_INDCPA_PUBLICKEYBYTES (MLKEM_POLYVECBYTES + MLKEM_SYMBYTES)
#define MLKEM_INDCPA_SECRETKEYBYTES (MLKEM_POLYVECBYTES)

#define MLKEM_INDCCA_PUBLICKEYBYTES (MLKEM_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define MLKEM_INDCCA_SECRETKEYBYTES                            \
  (MLKEM_INDCPA_SECRETKEYBYTES + MLKEM_INDCPA_PUBLICKEYBYTES + \
   2 * MLKEM_SYMBYTES)

#define MLK_INTERNAL_API
#define MLK_INTERNAL_DATA_DECLARATION extern
#define MLK_INTERNAL_DATA_DEFINITION
#define MLK_EXTERNAL_API

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
