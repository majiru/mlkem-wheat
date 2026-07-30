#include "fips202.h"
#if !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)

void
mlk_shake128_init(mlk_shake128ctx *state)
{
	memset(state, 0, sizeof *state);
}

void
mlk_shake128_release(mlk_shake128ctx *state)
{
	memset(state, 0, sizeof *state);
}

void
mlk_shake128_absorb_once(mlk_shake128ctx *state, const u8int *input, ulong inlen)
{
	shake_128_in(input, inlen, &state->d);
	shake_128_convert(&state->x, &state->d);
}

void
mlk_shake128_squeezeblocks(u8int *output, ulong nblocks, mlk_shake128ctx *state)
{
	shake_128_out(output, nblocks * SHAKE128_RATE, &state->x);
}

void
mlk_shake256(u8int *output, ulong outlen, const u8int *input, ulong inlen)
{
	shake_256(input, inlen, output, outlen);
}

void
mlk_sha3_256(u8int *output, const u8int *input, ulong inlen)
{
	sha3_256(input, inlen, output, nil);
}

void
mlk_sha3_512(u8int *output, const u8int *input, ulong inlen)
{
	sha3_512(input, inlen, output, nil);
}

#endif
