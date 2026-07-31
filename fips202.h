/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_384_RATE 104
#define SHA3_512_RATE 72

/** Context for the non-incremental SHAKE128 API. */
typedef struct
{
  DigestState d;
  XOFState x;
} MLK_ALIGN mlk_shake128ctx;

/**
 * One-shot absorb step of the SHAKE128 XOF.
 *
 * For call-sites (in mlkem-native):
 * - This function MUST ONLY be called straight after mlk_shake128_init().
 * - This function MUST ONLY be called once.
 *
 * Consequently, for providers of custom FIPS202 code to be used with
 * mlkem-native:
 * - You may assume that the input context is freshly initialized via
 *   mlk_shake128_init().
 * - You may assume that this function is called exactly once.
 *
 * @param[in,out] state SHAKE128 context.
 * @param[in]     input Input to be absorbed into the state.
 * @param         inlen Length of input in bytes.
 */
void mlk_shake128_absorb_once(mlk_shake128ctx *state, const u8int *input,
                              ulong inlen);

/**
 * Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHAKE128_RATE bytes
 * each. Modifies the state. Can be called multiple times to keep squeezing,
 * i.e., is incremental.
 *
 * @param[out]    output  Output blocks.
 * @param         nblocks Number of blocks to be squeezed (written to output).
 * @param[in,out] state   Keccak state.
 */
void mlk_shake128_squeezeblocks(u8int *output, ulong nblocks,
                                mlk_shake128ctx *state);

void mlk_shake128_init(mlk_shake128ctx *state);

void mlk_shake128_release(mlk_shake128ctx *state);

/* One-stop SHAKE256 call. Aliasing between input and
 * output is not permitted */
/**
 * SHAKE256 XOF with non-incremental API.
 *
 * @param[out] output Output buffer.
 * @param      outlen Requested output length in bytes.
 * @param[in]  input  Input buffer.
 * @param      inlen  Length of input in bytes.
 */
void mlk_shake256(u8int *output, ulong outlen, const u8int *input,
                  ulong inlen);

/* One-stop SHA3_256 call. Aliasing between input and
 * output is not permitted */
#define SHA3_256_HASHBYTES 32
/**
 * SHA3-256 with non-incremental API.
 *
 * @param[out] output Output buffer.
 * @param[in]  input  Input buffer.
 * @param      inlen  Length of input in bytes.
 */
void mlk_sha3_256(u8int *output, const u8int *input, ulong inlen);

/* One-stop SHA3_512 call. Aliasing between input and
 * output is not permitted */
#define SHA3_512_HASHBYTES 64
/**
 * SHA3-512 with non-incremental API.
 *
 * @param[out] output Output buffer.
 * @param[in]  input  Input buffer.
 * @param      inlen  Length of input in bytes.
 */
void mlk_sha3_512(u8int *output, const u8int *input, ulong inlen);
