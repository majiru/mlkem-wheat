#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

/*
 * Both of these functions use the same general method for doing constant time selection.
 * The first is a (x | -x) >> 31 clamps the input to either 0 or 1.
 * This trick is stolen from "Hacker's Delight" by Henry S. Warren Jr.
 * The next line x = -x then does a sign extension to get a mask.
 */

int
ctsell(ulong a, ulong b, ulong cond)
{
	cond = (cond | -cond) >> 31;
	cond = -cond;
	return b ^ (cond & (a ^ b));
}

void
ctmemsel(uchar *dst, uchar *src, ulong len, ulong b)
{
	b = (b | -b) >> 31;
	b = -b;
	for(; len != 0; dst++, src++, len--)
		*dst = *src ^ (b & (*dst ^ *src));
}
