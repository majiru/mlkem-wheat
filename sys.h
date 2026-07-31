/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLK_STATIC_TESTABLE
#define MLK_STATIC_TESTABLE static
#endif

#define MLK_RESTRICT restrict

#define MLK_DEFAULT_ALIGN 32
#define MLK_ALIGN_UP(N) \
  ((((N) + (MLK_DEFAULT_ALIGN - 1)) / MLK_DEFAULT_ALIGN) * MLK_DEFAULT_ALIGN)
#define MLK_ALIGN /* No known support for alignment constraints */


/* New X86_64 CPUs support Conflow-flow protection using the CET instructions.
 * When enabled (through -fcf-protection=), all compilation units (including
 * empty ones) need to support CET for this to work.
 * For assembly, this means that source files need to signal support for
 * CET by setting the appropriate note.gnu.property section.
 * This can be achieved by including the <cet.h> header in all assembly file.
 * This file also provides the _CET_ENDBR macro which needs to be placed at
 * every potential target of an indirect branch.
 * If CET is enabled _CET_ENDBR maps to the endbr64 instruction, otherwise
 * it is empty.
 * In case the compiler does not support CET (e.g., <gcc8, <clang11),
 * the __CET__ macro is not set and we default to nothing.
 * Note that we only issue _CET_ENDBR instructions through the MLK_ASM_FN_SYMBOL
 * macro as the global symbols are the only possible targets of indirect
 * branches in our code.
 */

#define MLK_CT_TESTING_SECRET(ptr, len) \
  do                                    \
  {                                     \
  } while (0)
#define MLK_CT_TESTING_DECLASSIFY(ptr, len) \
  do                                        \
  {                                         \
  } while (0)

#define MLK_MUST_CHECK_RETURN_VALUE

