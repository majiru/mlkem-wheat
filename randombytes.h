/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
/**
 * Fill a buffer with cryptographically secure random bytes.
 *
 * mlkem-native does not provide an implementation of this function.
 * It must be provided by the consumer.
 *
 * To use a custom random byte source with a different name or signature,
 * set MLK_CONFIG_CUSTOM_RANDOMBYTES and define mlk_randombytes directly.
 *
 * @param[out] out    Output buffer.
 * @param      outlen Number of random bytes to write.
 *
 * @retval 0     Success.
 * @retval other Failure; top-level APIs propagate this as MLK_ERR_RNG_FAIL.
 */
int mlk_randombytes(u8int *out, ulong outlen);
