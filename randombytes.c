#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>
#include "a.h"

int
mlk_randombytes(uchar *buf, ulong n)
{
	genrandom(buf, n);
	return 0;
}
