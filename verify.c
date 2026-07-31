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
