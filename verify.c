#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

int
mlk_ct_sel_int(int a, int b, uint cond)
{
  uint au, bu;

  au = a, bu = b;
  cond = -cond >> 16;
  return bu ^ (cond & (au ^ bu));
}

void
mlk_ct_cmov_zero(uchar *dst, uchar *src, ulong len, ulong b)
{
  b = -b >> 24;
  for(; len != 0; dst++, src++, len--)
	*dst = *src ^ (b & (*dst ^ *src));
}
