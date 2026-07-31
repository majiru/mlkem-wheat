#include "common.h"
#include "randombytes.h"

int
randombytes(uchar *buf, ulong n)
{
	genrandom(buf, n);
	return 0;
}

void
randombytes_reset(void)
{
}
