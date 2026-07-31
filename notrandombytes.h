/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MI
 */

/* References
 * ==========
 *
 * - [surf]
 *   SURF: Simple Unpredictable Random Function
 *   Daniel J. Bernstein
 *   https://cr.yp.to/papers.html#surf
 */

/* Based on @[surf]. */

/**
 * WARNING
 *
 * The randombytes() implementation in this file is for TESTING ONLY.
 * You MUST NOT use this implementation outside of testing.
 *
 */

void randombytes_reset(void);
int mlk_randombytes(u8int *buf, ulong n);
