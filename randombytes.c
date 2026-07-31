#include "common.h"
#include "randombytes.h"

int
mlk_randombytes(uchar *buf, ulong n)
{
	genrandom(buf, n);
	return 0;
}
