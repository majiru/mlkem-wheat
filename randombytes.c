#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

int
mlk_randombytes(uchar *buf, ulong n)
{
	genrandom(buf, n);
	return 0;
}
