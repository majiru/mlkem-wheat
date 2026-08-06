#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

enum{
	K512 = 2,
	K768,
	K1024,
};

#define MLK_DEFAULT_ALIGN 32
#define MLK_ALIGN_UP(N) \
  ((((N) + (MLK_DEFAULT_ALIGN - 1)) / MLK_DEFAULT_ALIGN) * MLK_DEFAULT_ALIGN)

#define MLKEM_N 256
#define MLKEM_Q 3329
#define MLKEM_Q_HALF ((MLKEM_Q + 1) / 2) /* 1665 */

#define MLKEM_SYMBYTES 32 /* size in bytes of hashes, and seeds */

#define MLKEM_POLYBYTES 384

#define MLKEM_POLYCOMPRESSEDBYTES_D4 128
#define MLKEM_POLYCOMPRESSEDBYTES_D5 160
#define MLKEM_POLYCOMPRESSEDBYTES_D10 320
#define MLKEM_POLYCOMPRESSEDBYTES_D11 352

#define MLKEM_ETA2 2

#define MLKEM_INDCPA_MSGBYTES (MLKEM_SYMBYTES)

#define MLK_ALLOC(v, T, N) \
  T *v = malloc(N * sizeof(T));

#define MLK_FREE(v, T, N)			\
  do						\
  {						\
    memset(v, 0, N * sizeof(T));		\
    free(v);					\
    (v) = nil;					\
    USED((v));					\
  } while(0)

s16int mlk_ct_sel_int16(s16int a, s16int b, u16int cond);
void mlk_ct_cmov_zero(u8int *r, const u8int *x, ulong len, u8int b);

/* Macros denoting FIPS 203 specific Hash functions */

/* Hash function H, @[FIPS203, Section 4.1, Eq (4.4)] */
#define mlk_hash_h(OUT, IN, INBYTES) sha3_256(IN, INBYTES, OUT, nil)

/* Hash function G, @[FIPS203, Section 4.1, Eq (4.5)] */
#define mlk_hash_g(OUT, IN, INBYTES) sha3_512(IN, INBYTES, OUT, nil)

/* Hash function J, @[FIPS203, Section 4.1, Eq (4.4)] */
#define mlk_hash_j(OUT, IN, INBYTES) \
  shake_256(IN, INBYTES, OUT, MLKEM_SYMBYTES)

/* PRF function, @[FIPS203, Section 4.1, Eq (4.3)]
 * Referring to (eq 4.3), `OUT` is assumed to contain `s || b`. */
#define mlk_prf_eta(ETA, OUT, IN) \
  shake_256(IN, MLKEM_SYMBYTES + 1, OUT, (ETA) * MLKEM_N / 4)

#define SHAKE128_RATE 168
#define MLK_XOF_RATE SHAKE128_RATE

/**
 * Element of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1].
 */
typedef struct {
	s16int coeffs[MLKEM_N]; /**< Polynomial coefficients. */
} mlk_poly;

/**
 * INTERNAL representation of precomputed data speeding up
 * the base multiplication of two polynomials in NTT domain.
 */
typedef struct {
	s16int coeffs[MLKEM_N >> 1]; /**< Cached coefficients. */
} mlk_poly_mulcache;

/* Sized up to the max it can be for 1024 FIXME(?) */
typedef struct {
	mlk_poly vec[K1024];
} mlk_polyvec;

typedef struct {
	mlk_polyvec vec[K1024];
} mlk_polymat;

typedef struct {
	mlk_poly_mulcache vec[K1024];
} mlk_polyvec_mulcache;

#define _MLKEM_POLYVECBYTES(lvl) (lvl * MLKEM_POLYBYTES)
#define _MLKEM_INDCPA_PUBLICKEYBYTES(lvl) (_MLKEM_POLYVECBYTES(lvl) + MLKEM_SYMBYTES)
#define _MLKEM_INDCPA_SECRETKEYBYTES(lvl) (_MLKEM_POLYVECBYTES(lvl))

#define _MLKEM_INDCCA_PUBLICKEYBYTES(lvl) (_MLKEM_INDCPA_PUBLICKEYBYTES(lvl))
/* 32 bytes of additional space to save H(pk) */
#define _MLKEM_INDCCA_SECRETKEYBYTES(lvl) (_MLKEM_INDCPA_SECRETKEYBYTES(lvl) + _MLKEM_INDCPA_PUBLICKEYBYTES(lvl) + 2 * MLKEM_SYMBYTES)

#define _MLKEM512_INDCPA_BYTES (MLKEM_POLYCOMPRESSEDBYTES_D4 + MLKEM_POLYCOMPRESSEDBYTES_D10 * K512)
#define _MLKEM768_INDCPA_BYTES (MLKEM_POLYCOMPRESSEDBYTES_D4 + MLKEM_POLYCOMPRESSEDBYTES_D10 * K768)
#define _MLKEM1024_INDCPA_BYTES (MLKEM_POLYCOMPRESSEDBYTES_D5 + MLKEM_POLYCOMPRESSEDBYTES_D11 * K1024)
#define _MLKEM512_INDCCA_CIPHERTEXTBYTES (_MLKEM512_INDCPA_BYTES)
#define _MLKEM768_INDCCA_CIPHERTEXTBYTES (_MLKEM768_INDCPA_BYTES)
#define _MLKEM1024_INDCCA_CIPHERTEXTBYTES (_MLKEM1024_INDCPA_BYTES)

/**
 * Generic Montgomery reduction; given a 32-bit integer a, computes a 16-bit
 * integer congruent to a * R^-1 mod MLKEM_Q, where R=2^16.
 */
static s16int
mlk_montgomery_reduce(s32int a)
{
	/* check-magic: 62209 == unsigned_mod(pow(MLKEM_Q, -1, 2^16), 2^16) */
	const u32int QINV = 62209;

	/* Compute a*q^{-1} mod 2^16 in unsigned representatives. */
	const u16int a_reduced = (u16int)(a & (s32int)0xffff);
	const u16int a_inverted = (a_reduced * QINV) & 0xffff;

	/* Lift to signed canonical representative mod 2^16. */
	const s16int t = (s16int)a_inverted;

	s32int r;

	r = a - ((s32int)t * MLKEM_Q);

	/*
	 * PORTABILITY: Right-shift on a signed integer is, strictly-speaking,
	 * implementation-defined for negative left argument. Here,
	 * we assume it's sign-preserving "arithmetic" shift right. (C99 6.5.7 (5))
	 */
	r = r >> 16;

	/* Bounds: |r >> 16| <= ceil(|r| / 2^16)
	 *	<= ceil(|a| / 2^16 + MLKEM_Q / 2)
	 *	<= ceil(|a| / 2^16) + (MLKEM_Q + 1) / 2
	 * (Note that |a >> n| = ceil(|a| / 2^16) for negative a)
	 */
	return (s16int)r;
}

/**
 * Barrett reduction; given a 16-bit integer a, computes the centered
 * representative congruent to a mod MLKEM_Q in [-(MLKEM_Q-1)/2, (MLKEM_Q-1)/2].
 *
 */
static s16int
mlk_barrett_reduce(s16int a)
{
	/* Barrett reduction approximates
	 * ```
	 *		 round(a/MLKEM_Q)
	 *	 = round(a*(2^N/MLKEM_Q))/2^N)
	 *	~= round(a*round(2^N/MLKEM_Q)/2^N)
	 * ```
	 * Here, we pick N=26.
	 * PORTABILITY: Right-shift on a signed integer is
	 * implementation-defined for negative left argument.
	 * Here, we assume it's sign-preserving "arithmetic" shift right.
	 * See (C99 6.5.7 (5))
	 */
	const s32int t = (20159 * a + ((s32int)1 << 25)) >> 26;

	/*
	 * t is in -10 .. +10, so we need 32-bit math to
	 * evaluate t * MLKEM_Q and the subsequent subtraction
	 */
	s16int res = (s16int)(a - t * MLKEM_Q);

	return res;
}

/* Reference: `poly_tomont()` in the reference implementation @[REF]. */
static void
mlk_poly_tomont(mlk_poly *r)
{
	unsigned i;
	for(i = 0; i < MLKEM_N; i++)
		r->coeffs[i] = mlk_montgomery_reduce((s32int)r->coeffs[i] * 1353);
}

/**
 * Constant-time conversion of signed representatives modulo MLKEM_Q within
 * range [-(MLKEM_Q-1), MLKEM_Q-1] into unsigned representatives within
 * range [0, MLKEM_Q-1].
 */
static s16int
mlk_scalar_signed_to_unsigned_q(s16int c)
{

	/* Add MLKEM_Q if c is negative, but in constant time.
	 *
	 * Note that c + MLKEM_Q does not overflow in s16int,
	 * so the cast to u16int is safe. */
	c = mlk_ct_sel_int16((s16int)(c + MLKEM_Q), c, ((u16int)(((s32int)c)>>16) & (s32int)0xffff));

	return c;
}

/* Reference: `poly_reduce()` in the reference implementation @[REF]
 * - We use _unsigned_ canonical outputs, while the reference
 *	implementation uses _signed_ canonical outputs.
 *	Accordingly, we need a conditional addition of MLKEM_Q
 *	here to go from signed to unsigned representatives.
 *	This conditional addition is then dropped from all
 *	polynomial compression functions instead (see `compress.c`). */
static void
mlk_poly_reduce(mlk_poly *r)
{
	unsigned i;

	for(i = 0; i < MLKEM_N; i++){
		/* Barrett reduction, giving signed canonical representative */
		s16int t = mlk_barrett_reduce(r->coeffs[i]);
		/* Conditional addition to get unsigned canonical representative */
		r->coeffs[i] = mlk_scalar_signed_to_unsigned_q(t);
	}

}

/* Reference: `poly_add()` in the reference implementation @[REF].
 * - We use destructive version (output=first input) to avoid
 *	reasoning about aliasing in the CBMC specification */
static void
mlk_poly_add(mlk_poly *r, const mlk_poly *b)
{
	unsigned i;
	for(i = 0; i < MLKEM_N; i++){
		/* The preconditions imply that the addition stays within s16int. */
		r->coeffs[i] = (s16int)(r->coeffs[i] + b->coeffs[i]);
	}
}

/* Reference: `poly_sub()` in the reference implementation @[REF].
 * - We use destructive version (output=first input) to avoid
 *	reasoning about aliasing in the CBMC specification */
static void
mlk_poly_sub(mlk_poly *r, const mlk_poly *b)
{
	unsigned i;
	for(i = 0; i < MLKEM_N; i++){
		/* The preconditions imply that the subtraction stays within s16int. */
		r->coeffs[i] = (s16int)(r->coeffs[i] - b->coeffs[i]);
	}
}

static const s16int mlk_zetas[128] = {
	 -1044, -758, -359, -1517, 1493, 1422, 287,  202, -171, 622,  1577,
	 182,  962,  -1202, -1474, 1468, 573,  -1325, 264, 383,  -829, 1458,
	 -1602, -130, -681, 1017, 732,  608,  -1542, 411, -205, -1571, 1223,
	 652,  -552, 1015, -1293, 1491, -282, -1544, 516, -8,  -320, -666,
	 -1618, -1162, 126,  1469, -853, -90,  -271, 830, 107,  -1421, -247,
	 -951, -398, 961,  -1508, -725, 448,  -1065, 677, -1275, -1103, 430,
	 555,  843,  -1251, 871,  1550, 105,  422,  587, 177,  -235, -291,
	 -460, 1574, 1653, -246, 778,  1159, -147, -777, 1483, -602, 1119,
	 -1590, 644,  -872, 349,  418,  329,  -156, -75, 817,  1097, 603,
	 610,  1322, -1285, -1465, 384,  -1215, -136, 1218, -1335, -874, 220,
	 -1187, -1659, -1185, -1530, -1278, 794,  -1510, -854, -870, 478,  -108,
	 -308, 996,  991,  958,  -1460, 1522, 1628,
};

/* Reference: Does not exist in the reference implementation @[REF].
 * - The reference implementation does not use a
 *	multiplication cache ('mulcache'). This idea originates
 *	from @[NeonNTT] and is used at the C level here. */
static void
mlk_poly_mulcache_compute(mlk_poly_mulcache *x, const mlk_poly *a)
{
	unsigned i;
	for(i = 0; i < MLKEM_N / 4; i++){
		x->coeffs[2 * i + 0] = mlk_montgomery_reduce((s32int)a->coeffs[4 * i + 1] * (s32int)mlk_zetas[64 + i]);
		/* The values in zeta table are <= MLKEM_Q in absolute value,
		 * so the negation in s16int is safe. */
		x->coeffs[2 * i + 1] = mlk_montgomery_reduce((s32int)a->coeffs[4 * i + 3] * (s32int)(-mlk_zetas[64 + i]));
	}
}

/* manually inlined compared to upstream mlk_poly_ntt */
static void
mlk_poly_ntt(mlk_poly *p)
{
	unsigned layer;
	s16int *r;
	unsigned start, k, len;
	unsigned j;

	r = p->coeffs;

	for(layer = 1; layer <= 7; layer++){
		/* Twiddle factors for layer n are at indices 2^(n-1)..2^n-1. */
		k = 1u << (layer - 1);
		len = (unsigned)MLKEM_N >> layer;
		for(start = 0; start < MLKEM_N; start += 2 * len){
			s16int zeta = mlk_zetas[k++];
			for(j = start; j < start + len; j++){
				s16int t;
				t = mlk_montgomery_reduce((s32int)r[j + len] * (s32int)zeta);
				/* The precondition implies that the arithmetic does not overflow. */
				r[j + len] = (s16int)(r[j] - t);
				r[j] = (s16int)(r[j] + t);
			}
		}
	}
}

/* Reference: `invntt()` in the reference implementation @[REF]
 * - We normalize at the beginning of the inverse NTT,
 *	while the reference implementation normalizes at
 *	the end. This allows us to drop a call to `poly_reduce()`
 *	from the base multiplication. */
static void
mlk_poly_invntt_tomont(mlk_poly *p)
{
	unsigned j, layer;
	unsigned start, k, len;
	s16int zeta;
	s16int *r = p->coeffs;

	/*
	 * Scale input polynomial to account for Montgomery factor
	 * and NTT twist. This also brings coefficients down to
	 * absolute value < MLKEM_Q.
	 */
	for(j = 0; j < MLKEM_N; j++)
		r[j] = mlk_montgomery_reduce((s32int)r[j] * 1441);

	/* Run the invNTT layers */
	for(layer = 7; layer > 0; layer--){
		len = (unsigned)MLKEM_N >> layer;
		k = (1u << layer) - 1;

		for(start = 0; start < MLKEM_N; start += 2 * len){
			zeta = mlk_zetas[k--];

			for(j = start; j < start + len; j++){
				s16int t = r[j];
				/* The preconditions imply that the arithmetic does not overflow. */
				r[j] = mlk_barrett_reduce((s16int)(t + r[j + len]));
				r[j + len] = (s16int)(r[j + len] - t);
				r[j + len] = mlk_montgomery_reduce((s32int)r[j + len] * (s32int)zeta);
			}
		}
	}
}

/**
 * Run rejection sampling on uniform random bytes to generate uniform random
 * integers mod MLKEM_Q.
 *
 * @reference{`rej_uniform()` in the reference implementation @[REF]. Our
 * signature differs from the reference in that it adds the offset and always
 * expects the base of the target buffer; this avoids shifting the buffer
 * base in the caller, which is tricky to reason about. Has an optional
 * fallback to a native implementation.}
 *
 * @note Strictly speaking, only a few values of @p buflen near UINT_MAX need
 *	excluding. The limit of 4096 is somewhat arbitrary but sufficient
 *	for all uses of this function. Similarly, the actual limit for
 *	@p target is UINT_MAX/2.
 *
 * @return New offset of sampled 16-bit integers, at most @p target and at
 *	least the initial @p offset. If the new offset is strictly less
 *	han @p target, the entire input buffer is guaranteed to have been
 *	consumed; otherwise no information is provided on how many bytes
 *	of the input buffer have been consumed.
 */

/* Reference: `rej_uniform()` in the reference implementation @[REF].
 * - Our signature differs from the reference implementation
 *	in that it adds the offset and always expects the base of the
 *	target buffer. This avoids shifting the buffer base in the
 *	caller, which appears tricky to reason about. */
static unsigned
mlk_rej_uniform(s16int *r, unsigned target, unsigned offset, const u8int *buf, unsigned buflen)
{
	unsigned ctr, pos;
	s16int val0, val1;


	ctr = offset;
	pos = 0;
	/* pos + 3 cannot overflow due to the assumption buflen <= 4096 */
	while(ctr < target && pos + 3 <= buflen){
		val0 = ((buf[pos + 0] >> 0) | (buf[pos + 1] << 8)) & 0xFFF;
		val1 = ((buf[pos + 1] >> 4) | (buf[pos + 2] << 4)) & 0xFFF;
		pos += 3;

		if(val0 < MLKEM_Q)
			r[ctr++] = val0;
		if(ctr < target && val1 < MLKEM_Q)
			r[ctr++] = val1;
	}

	return ctr;
}

#define MLKEM_GEN_MATRIX_NBLOCKS																			 \
	((12 * MLKEM_N / 8 * ((u32int)1 << 12) / MLKEM_Q + MLK_XOF_RATE) / \
	 MLK_XOF_RATE)

static void
mlk_poly_rej_uniform(mlk_poly *entry, u8int seed[MLKEM_SYMBYTES + 2])
{
	struct {
		DigestState d;
		XOFState x;
	} state;
	u8int buf[MLKEM_GEN_MATRIX_NBLOCKS * MLK_XOF_RATE];
	unsigned ctr, buflen;

	memset(&state, 0, sizeof state);
	shake_128_in(seed, MLKEM_SYMBYTES + 2, &state.d);
	shake_128_conv(&state.x, &state.d);

	/* Initially, squeeze + sample heuristic number of MLKEM_GEN_MATRIX_NBLOCKS. */
	/* This should generate the matrix entry with high probability. */
	shake_128_out(buf, MLKEM_GEN_MATRIX_NBLOCKS * SHAKE128_RATE, &state.x);
	buflen = MLKEM_GEN_MATRIX_NBLOCKS * MLK_XOF_RATE;
	ctr = mlk_rej_uniform(entry->coeffs, MLKEM_N, 0, buf, buflen);

	/* Squeeze + sample one more block a time until we're done */
	buflen = MLK_XOF_RATE;
	while(ctr < MLKEM_N){
		shake_128_out(buf, SHAKE128_RATE, &state.x);
		ctr = mlk_rej_uniform(entry->coeffs, MLKEM_N, ctr, buf, buflen);
	}

	memset(&state, 0, sizeof state);

	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	memset(buf, 0, sizeof(buf));
}

/**
 * Load 4 bytes into a 32-bit integer in little-endian order.
 *
 * @reference{`load32_littleendian()` in the reference implementation @[REF].}
 *
 * @param[in] x Input byte array.
 *
 * @return 32-bit unsigned integer loaded from @p x.
 */
static u32int
mlk_load32_littleendian(const u8int x[4])
{
	u32int r;
	r = (u32int)x[0];
	r |= (u32int)x[1] << 8;
	r |= (u32int)x[2] << 16;
	r |= (u32int)x[3] << 24;
	return r;
}

/* Reference: `cbd2()` in the reference implementation @[REF]. */
static void
mlk_poly_cbd2(mlk_poly *r, const u8int buf[2 * MLKEM_N / 4])
{
	unsigned i;
	for(i = 0; i < MLKEM_N / 8; i++){
		unsigned j;
		u32int t = mlk_load32_littleendian(buf + 4 * i);
		u32int d = t & 0x55555555;
		d += (t >> 1) & 0x55555555;

		for(j = 0; j < 8; j++){
			const s16int a = (d >> (4 * j + 0)) & 0x3;
			const s16int b = (d >> (4 * j + 2)) & 0x3;
			r->coeffs[8 * i + j] = (s16int)(a - b);
		}
	}
}

/**
 * Load 3 bytes into a 32-bit integer in little-endian order.
 *
 * This function is only needed for ML-KEM-512.
 *
 * @reference{`load24_littleendian()` in the reference implementation @[REF].}
 *
 * @param[in] x Input byte array.
 *
 * @return 32-bit unsigned integer loaded from @p x (most significant byte is zero).
 */
static u32int
mlk_load24_littleendian(const u8int x[3])
{
	u32int r;
	r = (u32int)x[0];
	r |= (u32int)x[1] << 8;
	r |= (u32int)x[2] << 16;
	return r;
}

/* Reference: `cbd3()` in the reference implementation @[REF]. */
static void
mlk_poly_cbd3(mlk_poly *r, const u8int buf[3 * MLKEM_N / 4])
{
	unsigned i;
	for(i = 0; i < MLKEM_N / 4; i++){
		unsigned j;
		const u32int t = mlk_load24_littleendian(buf + 3 * i);
		u32int d = t & 0x00249249;
		d += (t >> 1) & 0x00249249;
		d += (t >> 2) & 0x00249249;

		for(j = 0; j < 4; j++){
			const s16int a = (d >> (6 * j + 0)) & 0x7;
			const s16int b = (d >> (6 * j + 3)) & 0x7;
			r->coeffs[4 * i + j] = (s16int)(a - b);
		}
	}
}
/**
 * Compute round(u * 2 / MLKEM_Q).
 */
static u8int
mlk_scalar_compress_d1(s16int u)
{
	/* Compute as follows:
	 * ```
	 * round(u * 2 / MLKEM_Q)
	 *	 = round(u * 2 * (2^31 / MLKEM_Q) / 2^31)
	 *	~= round(u * 2 * round(2^31 / MLKEM_Q) / 2^31)
	 * ```
	 */
	/* check-magic: 1290168 == 2*round(2^31 / MLKEM_Q) */
	u32int d0 = (u32int)u * 1290168;
	/* Unsigned shifting by 31 positions leaves only the top bit. */
	return (u8int)((d0 + ((u32int)1u << 30)) >> 31);
}

/*
 * The multiplication in this routine will exceed UINT32_MAX
 * and wrap around for large values of u. This is expected and required.
 *
 * Compute round(u * 16 / MLKEM_Q) % 16.
 */
static u8int
mlk_scalar_compress_d4(s16int u)
{
	/* Compute as follows:
	 * ```
	 * round(u * 16 / MLKEM_Q)
	 *	 = round(u * 16 * (2^28 / MLKEM_Q) / 2^28)
	 *	~= round(u * 16 * round(2^28 / MLKEM_Q) / 2^28)
	 * ```
	 */
	/* check-magic: 1290160 == 16 * round(2^28 / MLKEM_Q) */
	u32int d0 = (u32int)u * 1290160;
	/* The return value is < 16, so not altered by the conversion to u8int. */
	return (u8int)((d0 + ((u32int)1u << 27)) >> 28); /* round(d0/2^28) */
}

/**
 * Compute round(u * MLKEM_Q / 16).
 *
 */
static s16int
mlk_scalar_decompress_d4(u8int u)
{
	/* The return value is in 0..MLKEM_Q-1, hence not altered by the
	 * conversion to s16int. */
	return (s16int)((((u32int)u * MLKEM_Q) + 8) >> 4);
}

/*
 * The multiplication in this routine will exceed UINT32_MAX
 * and wrap around for large values of u. This is expected and required.
 */

/**
 * Compute round(u * 32 / MLKEM_Q) % 32.
 *
 */
static u8int
mlk_scalar_compress_d5(s16int u)
{
	/* Compute as follows:
	 * ```
	 * round(u * 32 / MLKEM_Q)
	 *	 = round(u * 32 * (2^27 / MLKEM_Q) / 2^27)
	 *	~= round(u * 32 * round(2^27 / MLKEM_Q) / 2^27)
	 * ```
	 */
	/* check-magic: 1290176 == 2^5 * round(2^27 / MLKEM_Q) */
	u32int d0 = (u32int)u * 1290176;
	/* The return value is < 32, so not altered by the conversion to u8int. */
	return (u8int)((d0 + ((u32int)1u << 26)) >> 27); /* round(d0/2^27) */
}

/**
 * Compute round(u * MLKEM_Q / 32).
 */
static s16int
mlk_scalar_decompress_d5(u8int u)
{
	/* The return value is in 0..MLKEM_Q-1, hence not altered by the
	 * conversion to s16int. */
	return (s16int)((((u32int)u * MLKEM_Q) + 16) >> 5);
}

/*
 * The multiplication in this routine will exceed UINT32_MAX
 * and wrap around for large values of u. This is expected and required.
 */

/**
 * Compute round(u * 2**10 / MLKEM_Q) % 2**10.
 *
 */
static u16int
mlk_scalar_compress_d10(s16int u)
{
	/* Compute as follows:
	 * ```
	 * round(u * 1024 / MLKEM_Q)
	 *	 = round(u * 1024 * (2^33 / MLKEM_Q) / 2^33)
	 *	~= round(u * 1024 * round(2^33 / MLKEM_Q) / 2^33)
	 * ```
	 */
	/* check-magic: 2642263040 == 2^10 * round(2^33 / MLKEM_Q) */
	u64int d0 = (u64int)u * 2642263040ULL;
	d0 = (d0 + ((u64int)1u << 32)) >> 33; /* round(d0/2^33) */
	return (d0 & 0x3FF);
}

/**
 * Compute round(u * MLKEM_Q / 1024).
 */
static s16int
mlk_scalar_decompress_d10(u16int u)
{
	/* The return value is in 0..MLKEM_Q-1, hence not altered by the
	 * conversion to s16int. */
	return (s16int)((((u32int)u * MLKEM_Q) + 512) >> 10);
}

/*
 * The multiplication in this routine will exceed UINT32_MAX
 * and wrap around for large values of u. This is expected and required.
 */

/**
 * Compute round(u * 2**11 / MLKEM_Q) % 2**11.
 *
 */
static u16int
mlk_scalar_compress_d11(s16int u)
{
	/* Compute as follows:
	 * ```
	 * round(u * 2048 / MLKEM_Q)
	 *	 = round(u * 2048 * (2^33 / MLKEM_Q) / 2^33)
	 *	~= round(u * 2048 * round(2^33 / MLKEM_Q) / 2^33)
	 * ```
	 */
	/* check-magic: 5284526080 == 2^11 * round(2^33 / MLKEM_Q) */
	u64int d0 = (u64int)u * 5284526080;
	d0 = (d0 + ((u64int)1u << 32)) >> 33; /* round(d0/2^33) */
	return (d0 & 0x7FF);
}

/**
 * Compute round(u * MLKEM_Q / 2048).
 */
static s16int
mlk_scalar_decompress_d11(u16int u)
{
	/* The return value is in 0..MLKEM_Q-1, hence not altered by the
	 * conversion to s16int. */
	return (s16int)((((u32int)u * MLKEM_Q) + 1024) >> 11);
}

/* Reference: `poly_compress()` in the reference implementation @[REF], for ML-KEM-{512,768}.
 * - In contrast to the reference implementation, we assume
 *	unsigned canonical coefficients here.
 *	The reference implementation works with coefficients
 *	in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
static void
mlk_poly_compress_d4(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D4], const mlk_poly *a)
{
	unsigned i;

	for(i = 0; i < MLKEM_N / 8; i++){
		unsigned j;
		u8int t[8] = {0};
		for(j = 0; j < 8; j++)
			t[j] = mlk_scalar_compress_d4(a->coeffs[8 * i + j]);

		/* All t[i] are 4-bit wide, so the truncations don't alter the value. */
		r[i * 4] = (u8int)(t[0] | (t[1] << 4));
		r[i * 4 + 1] = (u8int)(t[2] | (t[3] << 4));
		r[i * 4 + 2] = (u8int)(t[4] | (t[5] << 4));
		r[i * 4 + 3] = (u8int)(t[6] | (t[7] << 4));
	}
}

/* Reference: Embedded into `polyvec_compress()` in the reference implementation, for ML-KEM-{512,768}.
 * - In contrast to the reference implementation, we assume
 * 	unsigned canonical coefficients here.
 *	The reference implementation works with coefficients
 *	in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
static void
mlk_poly_compress_d10(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D10], const mlk_poly *a)
{
	unsigned j;
	for(j = 0; j < MLKEM_N / 4; j++){
		unsigned k;
		u16int t[4];
		for(k = 0; k < 4; k++)
			t[k] = mlk_scalar_compress_d10(a->coeffs[4 * j + k]);

		/*
		 * Make all implicit truncation explicit. No data is being
		 * truncated for the LHS's since each t[i] is 10-bit in size.
		 */
		r[5 * j + 0] = (u8int)((t[0] >> 0) & 0xFF);
		r[5 * j + 1] = (u8int)((t[0] >> 8) | ((t[1] << 2) & 0xFF));
		r[5 * j + 2] = (u8int)((t[1] >> 6) | ((t[2] << 4) & 0xFF));
		r[5 * j + 3] = (u8int)((t[2] >> 4) | ((t[3] << 6) & 0xFF));
		r[5 * j + 4] = (u8int)(t[3] >> 2);
	}
}

/* Reference: `poly_decompress()` in the reference implementation @[REF], for ML-KEM-{512,768}. */
static void
mlk_poly_decompress_d4(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D4])
{
	unsigned i;
	for(i = 0; i < MLKEM_N / 2; i++){
		r->coeffs[2 * i + 0] = mlk_scalar_decompress_d4((a[i] >> 0) & 0xF);
		r->coeffs[2 * i + 1] = mlk_scalar_decompress_d4((a[i] >> 4) & 0xF);
	}

}

/* Reference: Embedded into `polyvec_decompress()` in the reference implementation, for ML-KEM-{512,768}. */
static void
mlk_poly_decompress_d10(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D10])
{
	unsigned j;
	for(j = 0; j < MLKEM_N / 4; j++){
		unsigned k;
		u16int t[4];
		u8int const *base = &a[5 * j];

		t[0] = 0x3FF & ((base[0] >> 0) | ((u16int)base[1] << 8));
		t[1] = 0x3FF & ((base[1] >> 2) | ((u16int)base[2] << 6));
		t[2] = 0x3FF & ((base[2] >> 4) | ((u16int)base[3] << 4));
		t[3] = 0x3FF & ((base[3] >> 6) | ((u16int)base[4] << 2));

		for(k = 0; k < 4; k++)
			r->coeffs[4 * j + k] = mlk_scalar_decompress_d10(t[k]);
	}

}

/* Reference: `poly_compress()` in the reference implementation @[REF], for ML-KEM-1024.
 * - In contrast to the reference implementation, we assume
 *	unsigned canonical coefficients here.
 *	The reference implementation works with coefficients
 *	in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
static void
mlk_poly_compress_d5(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D5], const mlk_poly *a)
{
	unsigned i;

	for(i = 0; i < MLKEM_N / 8; i++){
		unsigned j;
		u8int t[8] = {0};
		for(j = 0; j < 8; j++)
			t[j] = mlk_scalar_compress_d5(a->coeffs[8 * i + j]);

		r[i * 5] = (u8int)(0xFF & ((t[0] >> 0) | (t[1] << 5)));
		r[i * 5 + 1] = (u8int)(0xFF & ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7)));
		r[i * 5 + 2] = (u8int)(0xFF & ((t[3] >> 1) | (t[4] << 4)));
		r[i * 5 + 3] = (u8int)(0xFF & ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6)));
		r[i * 5 + 4] = (u8int)(0xFF & ((t[6] >> 2) | (t[7] << 3)));
	}
}

/* Reference: Embedded into `polyvec_compress()` in the reference implementation, for ML-KEM-1024.
 * - In contrast to the reference implementation, we assume
 *	unsigned canonical coefficients here.
 *	The reference implementation works with coefficients
 *	in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
static void
mlk_poly_compress_d11(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D11], const mlk_poly *a)
{
	unsigned j;

	for(j = 0; j < MLKEM_N / 8; j++){
		unsigned k;
		u16int t[8];
		for(k = 0; k < 8; k++)
			t[k] = mlk_scalar_compress_d11(a->coeffs[8 * j + k]);

		/*
		 * Make all implicit truncation explicit. No data is being
		 * truncated for the LHS's since each t[i] is 11-bit in size.
		 */
		r[11 * j + 0] = (u8int)((t[0] >> 0) & 0xFF);
		r[11 * j + 1] = (u8int)((t[0] >> 8) | ((t[1] << 3) & 0xFF));
		r[11 * j + 2] = (u8int)((t[1] >> 5) | ((t[2] << 6) & 0xFF));
		r[11 * j + 3] = (u8int)((t[2] >> 2) & 0xFF);
		r[11 * j + 4] = (u8int)((t[2] >> 10) | ((t[3] << 1) & 0xFF));
		r[11 * j + 5] = (u8int)((t[3] >> 7) | ((t[4] << 4) & 0xFF));
		r[11 * j + 6] = (u8int)((t[4] >> 4) | ((t[5] << 7) & 0xFF));
		r[11 * j + 7] = (u8int)((t[5] >> 1) & 0xFF);
		r[11 * j + 8] = (u8int)((t[5] >> 9) | ((t[6] << 2) & 0xFF));
		r[11 * j + 9] = (u8int)((t[6] >> 6) | ((t[7] << 5) & 0xFF));
		r[11 * j + 10] = (u8int)(t[7] >> 3);
	}
}

/* Reference: `poly_decompress()` in the reference implementation @[REF], for ML-KEM-1024. */
static void
mlk_poly_decompress_d5(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D5])
{
	unsigned i;
	for(i = 0; i < MLKEM_N / 8; i++){
		unsigned j;
		u8int t[8];
		const unsigned offset = i * 5;
		/*
		 * Explicitly truncate to avoid warning about
		 * implicit truncation in CBMC and unwind loop for ease
		 * of proof.
		 */

		/*
		 * Decompress 5 8-bit bytes (so 40 bits) into
		 * 8 5-bit values stored in t[]
		 */
		t[0] = 0x1F & (a[offset + 0] >> 0);
		t[1] = 0x1F & ((a[offset + 0] >> 5) | (a[offset + 1] << 3));
		t[2] = 0x1F & (a[offset + 1] >> 2);
		t[3] = 0x1F & ((a[offset + 1] >> 7) | (a[offset + 2] << 1));
		t[4] = 0x1F & ((a[offset + 2] >> 4) | (a[offset + 3] << 4));
		t[5] = 0x1F & (a[offset + 3] >> 1);
		t[6] = 0x1F & ((a[offset + 3] >> 6) | (a[offset + 4] << 2));
		t[7] = 0x1F & (a[offset + 4] >> 3);

		/* and copy to the correct slice in r[] */
		for(j = 0; j < 8; j++)
			r->coeffs[8 * i + j] = mlk_scalar_decompress_d5(t[j]);
	}

}

/* Reference: Embedded into `polyvec_decompress()` in the reference implementation, for ML-KEM-1024. */
static void
mlk_poly_decompress_d11(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D11])
{
	unsigned j;
	for(j = 0; j < MLKEM_N / 8; j++){
		unsigned k;
		u16int t[8];
		u8int const *base = &a[11 * j];
		t[0] = 0x7FF & ((base[0] >> 0) | ((u16int)base[1] << 8));
		t[1] = 0x7FF & ((base[1] >> 3) | ((u16int)base[2] << 5));
		t[2] = 0x7FF & ((base[2] >> 6) | ((u16int)base[3] << 2) |
										((u16int)base[4] << 10));
		t[3] = 0x7FF & ((base[4] >> 1) | ((u16int)base[5] << 7));
		t[4] = 0x7FF & ((base[5] >> 4) | ((u16int)base[6] << 4));
		t[5] = 0x7FF & ((base[6] >> 7) | ((u16int)base[7] << 1) |
										((u16int)base[8] << 9));
		t[6] = 0x7FF & ((base[8] >> 2) | ((u16int)base[9] << 6));
		t[7] = 0x7FF & ((base[9] >> 5) | ((u16int)base[10] << 3));

		for(k = 0; k < 8; k++)
			r->coeffs[8 * j + k] = mlk_scalar_decompress_d11(t[k]);
	}

}

/* Reference: `poly_tobytes()` in the reference implementation @[REF].
 * - In contrast to the reference implementation, we assume
 *	unsigned canonical coefficients here.
 *	The reference implementation works with coefficients
 *	in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
static void
mlk_poly_tobytes(u8int r[MLKEM_POLYBYTES], const mlk_poly *a)
{
	unsigned i;

	for(i = 0; i < MLKEM_N / 2; i++){
		/* The conversion to u16int is safe since we assume that
		 * the coefficients of `a` are non-negative. */
		const u16int t0 = (u16int)a->coeffs[2 * i];
		const u16int t1 = (u16int)a->coeffs[2 * i + 1];
		/*
		 * t0 and t1 are both < MLKEM_Q, so contain at most 12 bits each of
		 * significant data, so these can be packed into 24 bits or exactly
		 * 3 bytes, as follows.
		 */

		/* Least significant bits 0 - 7 of t0. */
		r[3 * i + 0] = (u8int)(t0 & 0xFF);

		/*
		 * Most significant bits 8 - 11 of t0 become the least significant
		 * nibble of the second byte. The least significant 4 bits
		 * of t1 become the upper nibble of the second byte.
		 *
		 * The conversion to u8int does not alter the value.
		 */
		r[3 * i + 1] = (u8int)((t0 >> 8) | ((t1 << 4) & 0xF0));

		/* Bits 4 - 11 of t1 become the third byte. The conversion to u8int
		 * does not alter the value because t1 is 12-bit wide. */
		r[3 * i + 2] = (u8int)(t1 >> 4);
	}
}

/* Reference: `poly_frombytes()` in the reference implementation @[REF]. */
static void
mlk_poly_frombytes(mlk_poly *r, const u8int a[MLKEM_POLYBYTES])
{
	unsigned i;
	for(i = 0; i < MLKEM_N / 2; i++){
		const u8int t0 = a[3 * i + 0];
		const u8int t1 = a[3 * i + 1];
		const u8int t2 = a[3 * i + 2];
		r->coeffs[2 * i + 0] = (s16int)(t0 | ((t1 << 8) & 0xFFF));
		r->coeffs[2 * i + 1] = (s16int)((t1 >> 4) | (t2 << 4));
	}

	/* Note that the coefficients are not canonical */
}

/* Reference: `poly_frommsg()` in the reference implementation @[REF].
 * - We use a value barrier around the bit-selection mask to
 *	reduce the risk of compiler-introduced branches.
 *	The reference implementation contains the expression
 *	`(msg[i] >> j) & 1` which the compiler can reason must
 *	be either 0 or 1. */
static void
mlk_poly_frommsg(mlk_poly *r, const u8int msg[MLKEM_INDCPA_MSGBYTES])
{
	unsigned i;

	for(i = 0; i < MLKEM_N / 8; i++){
		unsigned j;
		for(j = 0; j < 8; j++){
			/* mlk_ct_sel_int16(MLKEM_Q_HALF, 0, b) is `Decompress_1(b != 0)`
			 * as per @[FIPS203, Eq (4.8)]. */

			/* Assumes the compiler does not change this to a bit selection */
			u8int mask = 1u << j;
			r->coeffs[8 * i + j] = mlk_ct_sel_int16(MLKEM_Q_HALF, 0, msg[i] & mask);
		}
	}
}

/* Reference: `poly_tomsg()` in the reference implementation @[REF].
 * - In contrast to the reference implementation, we assume
 *	unsigned canonical coefficients here.
 *	The reference implementation works with coefficients
 *	in the range [-(MLKEM_Q-1), MLKEM_Q-1].
 */
static void
mlk_poly_tomsg(u8int msg[MLKEM_INDCPA_MSGBYTES], const mlk_poly *a)
{
	unsigned i;

	for(i = 0; i < MLKEM_N / 8; i++){
		unsigned j;
		msg[i] = 0;
		for(j = 0; j < 8; j++){
			u32int t = mlk_scalar_compress_d1(a->coeffs[8 * i + j]);
			msg[i] |= (u8int)(t << j);
		}
	}
}

/* Reference: `polyvec_compress()` in the reference implementation @[REF]
 * - In contrast to the reference implementation, we assume
 *	unsigned canonical coefficients here.
 *	The reference implementation works with coefficients
 *	in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
static void
mlk_polyvec_compress_du(int level, u8int *r, const mlk_polyvec *a)
{
	unsigned i;

	for(i = 0; i < level; i++){
		if(level == K1024)
			mlk_poly_compress_d11(r + i * MLKEM_POLYCOMPRESSEDBYTES_D11, &a->vec[i]);
		else
			mlk_poly_compress_d10(r + i * MLKEM_POLYCOMPRESSEDBYTES_D10, &a->vec[i]);
	}
}

/* Reference: `polyvec_decompress()` in the reference implementation @[REF]. */
static void
mlk_polyvec_decompress_du(int level, mlk_polyvec *r, const u8int *a)
{
	unsigned i;

	for(i = 0; i < level; i++){
		if(level == K1024)
			mlk_poly_decompress_d11(&r->vec[i], a + i * MLKEM_POLYCOMPRESSEDBYTES_D11);
		else
			mlk_poly_decompress_d10(&r->vec[i], a + i * MLKEM_POLYCOMPRESSEDBYTES_D10);
	}
}

/* Reference: `polyvec_tobytes()` in the reference implementation @[REF].
 * - In contrast to the reference implementation, we assume
 *	unsigned canonical coefficients here.
 *	The reference implementation works with coefficients
 *	in the range [-(MLKEM_Q-1), MLKEM_Q-1]. */
static void
mlk_polyvec_tobytes(int level, u8int *r, const mlk_polyvec *a)
{
	unsigned i;

	for(i = 0; i < level; i++)
		mlk_poly_tobytes(&r[i * MLKEM_POLYBYTES], &a->vec[i]);
}

/* Reference: `polyvec_frombytes()` in the reference implementation @[REF]. */
static void
mlk_polyvec_frombytes(int level, mlk_polyvec *r, const u8int *a)
{
	unsigned i;
	for(i = 0; i < level; i++)
		mlk_poly_frombytes(&r->vec[i], a + i * MLKEM_POLYBYTES);

}

/* Reference: `polyvec_ntt()` in the reference implementation @[REF]. */
static void
mlk_polyvec_ntt(int level, mlk_polyvec *r)
{
	unsigned i;
	for(i = 0; i < level; i++)
		mlk_poly_ntt(&r->vec[i]);

}

/* Reference: `polyvec_invntt_tomont()` in the reference implementation @[REF].
 * - We normalize at the beginning of the inverse NTT,
 *	while the reference implementation normalizes at
 *	the end. This allows us to drop a call to `poly_reduce()`
 *	from the base multiplication. */
static void
mlk_polyvec_invntt_tomont(int level, mlk_polyvec *r)
{
	unsigned i;
	for(i = 0; i < level; i++)
		mlk_poly_invntt_tomont(&r->vec[i]);

}

/* Reference: `polyvec_tomont()` in the reference implementation @[REF]. */
static void
mlk_polyvec_tomont(int level, mlk_polyvec *r)
{
	unsigned i;
	for(i = 0; i < level; i++)
		mlk_poly_tomont(&r->vec[i]);

}

/* Reference: Does not exist in the reference implementation @[REF].
 * - The reference implementation does not use a
 *	multiplication cache ('mulcache'). This idea originates
 *	from @[NeonNTT] and is used at the C level here. */
static void
mlk_polyvec_mulcache_compute(int level, mlk_polyvec_mulcache *x, const mlk_polyvec *a)
{
	unsigned i;
	for(i = 0; i < level; i++)
		mlk_poly_mulcache_compute(&x->vec[i], &a->vec[i]);
}

/* Reference: `polyvec_reduce()` in the reference implementation @[REF].
 * - We use _unsigned_ canonical outputs, while the reference
 *	implementation uses _signed_ canonical outputs.
 *	Accordingly, we need a conditional addition of MLKEM_Q
 *	here to go from signed to unsigned representatives.
 *	This conditional addition is then dropped from all
 *	polynomial compression functions instead (see `compress.c`). */
static void
mlk_polyvec_reduce(int level, mlk_polyvec *r)
{
	unsigned i;
	for(i = 0; i < level; i++)
		mlk_poly_reduce(&r->vec[i]);

}

/* Reference: `polyvec_add()` in the reference implementation @[REF].
 * - We use destructive version (output=first input) to avoid
 *	reasoning about aliasing in the CBMC specification */
static void
mlk_polyvec_add(int level, mlk_polyvec *r, const mlk_polyvec *b)
{
	unsigned i;
	for(i = 0; i < level; i++)
		mlk_poly_add(&r->vec[i], &b->vec[i]);
}

/* Reference: `polyvec_basemul_acc_montgomery()` in the reference implementation @[REF].
 * - We use a multiplication cache ('mulcache') here
 *	which is not present in the reference implementation @[REF].
 *	This idea originates from @[NeonNTT] and is used
 *	at the C level here.
 * - We compute the coefficients of the scalar product in 32-bit
 *	coefficients and perform only a single modular reduction
 *	at the end. The reference implementation uses 2 * MLKEM_K
 *	more modular reductions since it reduces after every modular
 *	multiplication. */
static void
mlk_polyvec_basemul_acc_montgomery_cached(int level, mlk_poly *r, const mlk_polyvec *a, const mlk_polyvec *b, const mlk_polyvec_mulcache *b_cache)
{
	unsigned i;

	for(i = 0; i < MLKEM_N / 2; i++){
		unsigned k;
		s32int t[2] = {0};
		for(k = 0; k < level; k++){
			t[0] += (s32int)a->vec[k].coeffs[2 * i + 1] * b_cache->vec[k].coeffs[i];
			t[0] += (s32int)a->vec[k].coeffs[2 * i] * b->vec[k].coeffs[2 * i];
			t[1] += (s32int)a->vec[k].coeffs[2 * i] * b->vec[k].coeffs[2 * i + 1];
			t[1] += (s32int)a->vec[k].coeffs[2 * i + 1] * b->vec[k].coeffs[2 * i];
		}
		r->coeffs[2 * i + 0] = mlk_montgomery_reduce(t[0]);
		r->coeffs[2 * i + 1] = mlk_montgomery_reduce(t[1]);
	}
}

/* Reference: Does not exist in the reference implementation @[REF].
 * - This implements a x4-batched version of `poly_getnoise_eta1()`
 *	from the reference implementation, to leverage
 *	batched Keccak-f1600.*/
static void
mlk_poly_getnoise_eta1_4x(int level, mlk_poly *r0, mlk_poly *r1, mlk_poly *r2, mlk_poly *r3, const u8int seed[MLKEM_SYMBYTES], u8int nonce0, u8int nonce1, u8int nonce2, u8int nonce3)
{
	u8int buf[4][MLK_ALIGN_UP(3 * MLKEM_N / 4)];
	u8int extkey[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 1)];
	memcpy(extkey[0], seed, MLKEM_SYMBYTES);
	memcpy(extkey[1], seed, MLKEM_SYMBYTES);
	memcpy(extkey[2], seed, MLKEM_SYMBYTES);
	memcpy(extkey[3], seed, MLKEM_SYMBYTES);
	extkey[0][MLKEM_SYMBYTES] = nonce0;
	extkey[1][MLKEM_SYMBYTES] = nonce1;
	extkey[2][MLKEM_SYMBYTES] = nonce2;
	extkey[3][MLKEM_SYMBYTES] = nonce3;

	if(level == K512){
		mlk_prf_eta(3, buf[0], extkey[0]);
		mlk_prf_eta(3, buf[1], extkey[1]);
		mlk_prf_eta(3, buf[2], extkey[2]);
		if(r3 != nil){
			mlk_prf_eta(3, buf[3], extkey[3]);
		}
		mlk_poly_cbd3(r0, buf[0]);
		mlk_poly_cbd3(r1, buf[1]);
		mlk_poly_cbd3(r2, buf[2]);
		if(r3 != nil){
			mlk_poly_cbd3(r3, buf[3]);
		}
	} else if(level == K768 || level == K1024){
		mlk_prf_eta(2, buf[0], extkey[0]);
		mlk_prf_eta(2, buf[1], extkey[1]);
		mlk_prf_eta(2, buf[2], extkey[2]);
		if(r3 != nil){
			mlk_prf_eta(2, buf[3], extkey[3]);
		}
		mlk_poly_cbd2(r0, buf[0]);
		mlk_poly_cbd2(r1, buf[1]);
		mlk_poly_cbd2(r2, buf[2]);
		if(r3 != nil){
			mlk_poly_cbd2(r3, buf[3]);
		}
	} else
		abort();


	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	memset(buf, 0, sizeof(buf));
	memset(extkey, 0, sizeof(extkey));
}

/* Reference: `poly_getnoise_eta2()` in the reference implementation @[REF].
 * - We include buffer zeroization. */
static void
mlk_poly_getnoise_eta2(mlk_poly *r, const u8int seed[MLKEM_SYMBYTES], u8int nonce)
{
	u8int buf[MLKEM_ETA2 * MLKEM_N / 4];
	u8int extkey[MLKEM_SYMBYTES + 1];

	memcpy(extkey, seed, MLKEM_SYMBYTES);
	extkey[MLKEM_SYMBYTES] = nonce;
	mlk_prf_eta(MLKEM_ETA2, buf, extkey);

	mlk_poly_cbd2(r, buf);


	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	memset(buf, 0, sizeof(buf));
	memset(extkey, 0, sizeof(extkey));
}

/* Reference: Does not exist in the reference implementation @[REF].
 * - This implements a x4-batched version of `poly_getnoise_eta1()`
 *	and `poly_getnoise_eta2()` from the reference implementation,
 *	leveraging batched Keccak-f1600.
 * - If a x4-batched Keccak-f1600 is available, we squeeze
 *	more random data than needed for the eta2 calls, to be
 *	be able to use a x4-batched Keccak-f1600. */
static void
mlk_poly_getnoise_eta1122_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2, mlk_poly *r3, const u8int seed[MLKEM_SYMBYTES], u8int nonce0, u8int nonce1, u8int nonce2, u8int nonce3)
{
	u8int buf[4][MLK_ALIGN_UP(3 * MLKEM_N / 4)];
	u8int extkey[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 1)];

	memcpy(extkey[0], seed, MLKEM_SYMBYTES);
	memcpy(extkey[1], seed, MLKEM_SYMBYTES);
	memcpy(extkey[2], seed, MLKEM_SYMBYTES);
	memcpy(extkey[3], seed, MLKEM_SYMBYTES);
	extkey[0][MLKEM_SYMBYTES] = nonce0;
	extkey[1][MLKEM_SYMBYTES] = nonce1;
	extkey[2][MLKEM_SYMBYTES] = nonce2;
	extkey[3][MLKEM_SYMBYTES] = nonce3;

	/* On systems with fast batched Keccak, we use 4-fold batched PRF,
	 * even though that means generating more random data in buf[2] and buf[3]
	 * than necessary. */
	mlk_prf_eta(1, buf[0], extkey[0]);
	mlk_prf_eta(1, buf[1], extkey[1]);
	mlk_prf_eta(2, buf[2], extkey[2]);
	mlk_prf_eta(2, buf[3], extkey[3]);

	mlk_poly_cbd3(r0, buf[0]);
	mlk_poly_cbd3(r1, buf[1]);
	mlk_poly_cbd2(r2, buf[2]);
	mlk_poly_cbd2(r3, buf[3]);


	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	memset(buf, 0, sizeof(buf));
	memset(extkey, 0, sizeof(extkey));
}

/**
 * Serialize the public key as the concatenation of the serialized vector of
 * polynomials pk and the public seed used to generate the matrix A.
 *
 */
static void
mlk_pack_pk(int level, u8int *r, const mlk_polyvec *pk, const u8int seed[MLKEM_SYMBYTES])
{
	mlk_polyvec_tobytes(level, r, pk);
	memcpy(r + _MLKEM_POLYVECBYTES(level), seed, MLKEM_SYMBYTES);
}

/**
 * De-serialize public key from a byte array; approximate inverse of
 * mlk_pack_pk.
 *
 */
static void
mlk_unpack_pk(int level, mlk_polyvec *pk, u8int seed[MLKEM_SYMBYTES], const u8int *packedpk)
{
	mlk_polyvec_frombytes(level, pk, packedpk);
	memcpy(seed, packedpk + _MLKEM_POLYVECBYTES(level), MLKEM_SYMBYTES);
}

/**
 * Serialize the secret key.
 */
static void
mlk_pack_sk(int level, u8int *r, const mlk_polyvec *sk)
{
	mlk_polyvec_tobytes(level, r, sk);
}

/**
 * De-serialize the secret key; inverse of mlk_pack_sk.
 */
static void
mlk_unpack_sk(int level, mlk_polyvec *sk, const u8int *packedsk)
{
	mlk_polyvec_frombytes(level, sk, packedsk);
}

/**
 * Serialize the ciphertext as the concatenation of the compressed and
 * serialized vector of polynomials b and the compressed and serialized
 * polynomial v.
 */
static void
mlk_pack_ciphertext(int level, u8int *r, const mlk_polyvec *b, mlk_poly *v)
{
	mlk_polyvec_compress_du(level, r, b);
	if(level == K512 || level == K768)
		mlk_poly_compress_d4(r + level*MLKEM_POLYCOMPRESSEDBYTES_D10, v);
	else
		mlk_poly_compress_d5(r + level*MLKEM_POLYCOMPRESSEDBYTES_D11, v);
}

/**
 * De-serialize and decompress ciphertext from a byte array; approximate
 * inverse of mlk_pack_ciphertext.
 *
 */
static void
mlk_unpack_ciphertext(int level, mlk_polyvec *b, mlk_poly *v, const u8int *c)
{
	mlk_polyvec_decompress_du(level, b, c);
	if(level == K512 || level == K768)
		mlk_poly_decompress_d4(v, c + level*MLKEM_POLYCOMPRESSEDBYTES_D10);
	else
		mlk_poly_decompress_d5(v, c + level*MLKEM_POLYCOMPRESSEDBYTES_D11);
}

/* Reference: `gen_matrix()` in the reference implementation @[REF].
 * - We use a special subroutine to generate 4 polynomials
 *	at a time, to be able to leverage batched Keccak-f1600
 *	implementations. The reference implementation generates
 *	one matrix entry a time.
 */
static void
mlk_gen_matrix(int level, mlk_polymat *a, const u8int seed[MLKEM_SYMBYTES], int transposed)
{
	unsigned i, j;
	u8int seed_ext[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 2)];

	for(j = 0; j < 4; j++)
		memcpy(seed_ext[j], seed, MLKEM_SYMBYTES);

	/* When using serial FIPS202, sample all entries individually. */
	i = 0;

	/* For MLKEM_K == 3, sample the last entry individually.
	 * When MLK_CONFIG_SERIAL_FIPS202_ONLY is set, sample all entries
	 * individually. */
	for(; i < level * level; i++){
		u8int x, y;
		/* MLKEM_K <= 4, so the values fit in u8int. */
		x = (u8int)(i / level);
		y = (u8int)(i % level);

		if(transposed){
			seed_ext[0][MLKEM_SYMBYTES + 0] = x;
			seed_ext[0][MLKEM_SYMBYTES + 1] = y;
		} else {
			seed_ext[0][MLKEM_SYMBYTES + 0] = y;
			seed_ext[0][MLKEM_SYMBYTES + 1] = x;
		}

		mlk_poly_rej_uniform(&a->vec[i / level].vec[i % level], seed_ext[0]);
	}

	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	memset(seed_ext, 0, sizeof(seed_ext));
}

/**
 * Compute matrix-vector product in NTT domain, via Montgomery multiplication.
 */
static void
mlk_matvec_mul(int level, mlk_polyvec *out, const mlk_polymat *a, const mlk_polyvec *v, const mlk_polyvec_mulcache *vc)
{
	unsigned i;
	for(i = 0; i < level; i++)
		mlk_polyvec_basemul_acc_montgomery_cached(level, &out->vec[i], &a->vec[i], v, vc);
}

/**
 * Compute and fill the pv and e polyvec structures needed by
 * mlk_keypair_derand(). Uses x4-batched versions of `poly_getnoise` to
 * leverage batched Keccak-f1600.
 */
static void
mlk_keypair_getnoise_eta1(int level, mlk_polyvec *pv, mlk_polyvec *e, const u8int seed[MLKEM_SYMBYTES])
{
	switch(level){
	case K512:
		mlk_poly_getnoise_eta1_4x(level, &pv->vec[0], &pv->vec[1], &e->vec[0], &e->vec[1], seed, 0, 1, 2, 3);
		break;
	case K768:
		/*
		 * Only the first three output buffers are needed, so we pass nil as
		 * the fourth parameter, and 0xFF as its dummy nonce.
		 */
		mlk_poly_getnoise_eta1_4x(level, &pv->vec[0], &pv->vec[1], &pv->vec[2], nil, seed, 0, 1, 2, 0xFF);
		/* Same here */
		mlk_poly_getnoise_eta1_4x(level, &e->vec[0], &e->vec[1], &e->vec[2], nil, seed, 3, 4, 5, 0xFF);
		break;
	case K1024:
		mlk_poly_getnoise_eta1_4x(level, &pv->vec[0], &pv->vec[1], &pv->vec[2], &pv->vec[3], seed, 0, 1, 2, 3);
		mlk_poly_getnoise_eta1_4x(level, &e->vec[0], &e->vec[1], &e->vec[2], &e->vec[3], seed, 4, 5, 6, 7);
		break;
	default:
		abort();
	}
}

/**
 * Compute and fill the sp, ep, and epp polynomial structures needed by
 * mlk_indcpa_enc(). Uses x4-batched versions of `poly_getnoise` to leverage
 * batched Keccak-f1600.
 */
static void
mlk_enc_getnoise_eta1_eta2(int level, mlk_polyvec *sp, mlk_polyvec *ep, mlk_poly *epp, const u8int coins[MLKEM_SYMBYTES])
{
	switch(level){
	case K512:
		mlk_poly_getnoise_eta1122_4x(&sp->vec[0], &sp->vec[1], &ep->vec[0], &ep->vec[1], coins, 0, 1, 2, 3);
		mlk_poly_getnoise_eta2(epp, coins, 4);
		break;
	case K768:
		/*
		 * In this call, only the first three output buffers are needed.
		 * The last parameter is a dummy that's overwritten later.
		 */
		mlk_poly_getnoise_eta1_4x(level, &sp->vec[0], &sp->vec[1], &sp->vec[2], nil, coins, 0, 1, 2, 0xFF /* irrelevant */);
		/* The fourth output buffer in this call _is_ used. */
		mlk_poly_getnoise_eta1_4x(level, &ep->vec[0], &ep->vec[1], &ep->vec[2], epp, coins, 3, 4, 5, 6);
		break;
	case K1024:
		mlk_poly_getnoise_eta1_4x(level, &sp->vec[0], &sp->vec[1], &sp->vec[2], &sp->vec[3], coins, 0, 1, 2, 3);
		mlk_poly_getnoise_eta1_4x(level, &ep->vec[0], &ep->vec[1], &ep->vec[2], &ep->vec[3], coins, 4, 5, 6, 7);
		mlk_poly_getnoise_eta2(epp, coins, 8);
		break;
	default:
		abort();
	}
}


/* Reference: `indcpa_keypair_derand()` in the reference implementation @[REF].
 * - We use a different implementation of `gen_matrix()` which
 *	uses x4-batched Keccak-f1600 (see `mlk_gen_matrix()` above).
 * - We use a mulcache to speed up matrix-vector multiplication.
 * - We include buffer zeroization.
 */
static int
mlk_indcpa_keypair_derand(int level, u8int *pk, u8int *sk, const u8int coins[MLKEM_SYMBYTES])
{
	int ret = 0;
	const u8int *publicseed;
	const u8int *noiseseed;
	MLK_ALLOC(buf, u8int, 2 * MLKEM_SYMBYTES);
	MLK_ALLOC(coins_with_domain_separator, u8int, MLKEM_SYMBYTES + 1);
	MLK_ALLOC(a, mlk_polymat, 1);
	MLK_ALLOC(e, mlk_polyvec, 1);
	MLK_ALLOC(pkpv, mlk_polyvec, 1);
	MLK_ALLOC(skpv, mlk_polyvec, 1);
	MLK_ALLOC(skpv_cache, mlk_polyvec_mulcache, 1);

	if(buf == nil || coins_with_domain_separator == nil || a == nil || e == nil || pkpv == nil || skpv == nil || skpv_cache == nil){
		ret = -1;
		goto cleanup;
	}

	publicseed = buf;
	noiseseed = buf + MLKEM_SYMBYTES;

	/* Concatenate coins with MLKEM_K for domain separation of security levels */
	memcpy(coins_with_domain_separator, coins, MLKEM_SYMBYTES);
	coins_with_domain_separator[MLKEM_SYMBYTES] = level;

	mlk_hash_g(buf, coins_with_domain_separator, MLKEM_SYMBYTES + 1);

	mlk_gen_matrix(level, a, publicseed, 0 /* no transpose */);

	mlk_keypair_getnoise_eta1(level, skpv, e, noiseseed);

	mlk_polyvec_ntt(level, skpv);
	mlk_polyvec_ntt(level, e);

	mlk_polyvec_mulcache_compute(level, skpv_cache, skpv);
	mlk_matvec_mul(level, pkpv, a, skpv, skpv_cache);
	mlk_polyvec_tomont(level, pkpv);

	mlk_polyvec_add(level, pkpv, e);
	mlk_polyvec_reduce(level, pkpv);
	mlk_polyvec_reduce(level, skpv);

	mlk_pack_sk(level, sk, skpv);
	mlk_pack_pk(level, pk, pkpv, publicseed);

cleanup:
	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	MLK_FREE(skpv_cache, mlk_polyvec_mulcache, 1);
	MLK_FREE(skpv, mlk_polyvec, 1);
	MLK_FREE(pkpv, mlk_polyvec, 1);
	MLK_FREE(e, mlk_polyvec, 1);
	MLK_FREE(a, mlk_polymat, 1);
	MLK_FREE(coins_with_domain_separator, u8int, MLKEM_SYMBYTES + 1);
	MLK_FREE(buf, u8int, 2 * MLKEM_SYMBYTES);
	return ret;
}

/* Reference: `indcpa_enc()` in the reference implementation @[REF].
 *	- We use x4-batched versions of `poly_getnoise` to leverage
 * 		batched x4-batched Keccak-f1600.
 *	- We use a different implementation of `gen_matrix()` which
 *		uses x4-batched Keccak-f1600 (see `mlk_gen_matrix()` above).
 *	- We use a mulcache to speed up matrix-vector multiplication.
 *	- We include buffer zeroization.
 */
static int
mlk_indcpa_enc(int level, u8int *c, const u8int *m, const u8int *pk, const u8int coins[MLKEM_SYMBYTES])
{
	int ret = 0;
	MLK_ALLOC(seed, u8int, MLKEM_SYMBYTES);
	MLK_ALLOC(at, mlk_polymat, 1);
	MLK_ALLOC(sp, mlk_polyvec, 1);
	MLK_ALLOC(pkpv, mlk_polyvec, 1);
	MLK_ALLOC(ep, mlk_polyvec, 1);
	MLK_ALLOC(b, mlk_polyvec, 1);
	MLK_ALLOC(v, mlk_poly, 1);
	MLK_ALLOC(k, mlk_poly, 1);
	MLK_ALLOC(epp, mlk_poly, 1);
	MLK_ALLOC(sp_cache, mlk_polyvec_mulcache, 1);

	if(seed == nil || at == nil || sp == nil || pkpv == nil || ep == nil || b == nil || v == nil || k == nil || epp == nil || sp_cache == nil){
		ret = -1;
		goto cleanup;
	}

	mlk_unpack_pk(level, pkpv, seed, pk);
	mlk_poly_frommsg(k, m);

	mlk_gen_matrix(level, at, seed, 1 /* transpose */);

	mlk_enc_getnoise_eta1_eta2(level, sp, ep, epp, coins);

	mlk_polyvec_ntt(level, sp);

	mlk_polyvec_mulcache_compute(level, sp_cache, sp);
	mlk_matvec_mul(level, b, at, sp, sp_cache);
	mlk_polyvec_basemul_acc_montgomery_cached(level, v, pkpv, sp, sp_cache);

	mlk_polyvec_invntt_tomont(level, b);
	mlk_poly_invntt_tomont(v);

	mlk_polyvec_add(level, b, ep);
	mlk_poly_add(v, epp);
	mlk_poly_add(v, k);

	mlk_polyvec_reduce(level, b);
	mlk_poly_reduce(v);

	mlk_pack_ciphertext(level, c, b, v);

cleanup:
	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	MLK_FREE(sp_cache, mlk_polyvec_mulcache, 1);
	MLK_FREE(epp, mlk_poly, 1);
	MLK_FREE(k, mlk_poly, 1);
	MLK_FREE(v, mlk_poly, 1);
	MLK_FREE(b, mlk_polyvec, 1);
	MLK_FREE(ep, mlk_polyvec, 1);
	MLK_FREE(pkpv, mlk_polyvec, 1);
	MLK_FREE(sp, mlk_polyvec, 1);
	MLK_FREE(at, mlk_polymat, 1);
	MLK_FREE(seed, u8int, MLKEM_SYMBYTES);
	return ret;
}

/* Reference: `indcpa_dec()` in the reference implementation @[REF].
 *	- We use a mulcache for the scalar product.
 *	- We include buffer zeroization. */
static int
mlk_indcpa_dec(int level, u8int *m, const u8int *c, const u8int *sk)
{
	int ret = 0;
	MLK_ALLOC(b, mlk_polyvec, 1);
	MLK_ALLOC(skpv, mlk_polyvec, 1);
	MLK_ALLOC(v, mlk_poly, 1);
	MLK_ALLOC(sb, mlk_poly, 1);
	MLK_ALLOC(b_cache, mlk_polyvec_mulcache, 1);

	if(b == nil || skpv == nil || v == nil || sb == nil || b_cache == nil){
		ret = -1;
		goto cleanup;
	}

	mlk_unpack_ciphertext(level, b, v, c);
	mlk_unpack_sk(level, skpv, sk);

	mlk_polyvec_ntt(level, b);
	mlk_polyvec_mulcache_compute(level, b_cache, b);
	mlk_polyvec_basemul_acc_montgomery_cached(level, sb, skpv, b, b_cache);
	mlk_poly_invntt_tomont(sb);

	mlk_poly_sub(v, sb);
	mlk_poly_reduce(v);

	mlk_poly_tomsg(m, v);

cleanup:
	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	MLK_FREE(b_cache, mlk_polyvec_mulcache, 1);
	MLK_FREE(sb, mlk_poly, 1);
	MLK_FREE(v, mlk_poly, 1);
	MLK_FREE(skpv, mlk_polyvec, 1);
	MLK_FREE(b, mlk_polyvec, 1);
	return ret;
}

static int
mlk_kem_check_pk(int level, const u8int *pk)
{
	mlk_polyvec p;
	u8int p_reencoded[_MLKEM_POLYVECBYTES(K1024)];

	mlk_polyvec_frombytes(level, &p, pk);
	mlk_polyvec_reduce(level, &p);
	mlk_polyvec_tobytes(level, p_reencoded, &p);
	return tsmemcmp(pk, p_reencoded, _MLKEM_POLYVECBYTES(level)) ? -1 : 0;
}

static
int mlk_kem_check_sk(const u8int *sk, int sn, int pn)
{
	u8int test[MLKEM_SYMBYTES];

	/*
	 * The parts of `sk` being hashed and compared here are public, so
	 * no private information is leaked through the runtime or the return value
	 * of this function.
	 */

	mlk_hash_h(test, sk + sn, pn);
	return memcmp(sk + sn - 2 * MLKEM_SYMBYTES, test, MLKEM_SYMBYTES) ? -1 : 0;
}

/* keypair_x and enc_x are public for testing only */
int
mlk_kem_keypair_x(int level, u8int *pk, u8int *sk, u8int *coins)
{
	int ret;

	ret = mlk_indcpa_keypair_derand(level, pk, sk, coins);
	if(ret != 0)
		goto cleanup;

	memcpy(sk + _MLKEM_INDCPA_SECRETKEYBYTES(level), pk, _MLKEM_INDCCA_PUBLICKEYBYTES(level));
	mlk_hash_h(sk + _MLKEM_INDCCA_SECRETKEYBYTES(level) - 2 * MLKEM_SYMBYTES, pk, _MLKEM_INDCCA_PUBLICKEYBYTES(level));
	/* Value z for pseudo-random output on reject */
	memcpy(sk + _MLKEM_INDCCA_SECRETKEYBYTES(level) - MLKEM_SYMBYTES, coins + MLKEM_SYMBYTES, MLKEM_SYMBYTES);

cleanup:
	memset(coins, 0, sizeof coins);
	if(ret != 0){
		memset(pk, 0, _MLKEM_INDCCA_PUBLICKEYBYTES(level));
		memset(sk, 0, _MLKEM_INDCCA_SECRETKEYBYTES(level));
	}

	return ret;
}

int
mlk_kem_enc_x(int level, u8int *ct, u8int *ss, const u8int *pk, u8int *coins)
{
	int ret;
	u8int buf[2 * MLKEM_SYMBYTES];
	u8int kr[2 * MLKEM_SYMBYTES];

	/* Specification: Implements @[FIPS203, Section 7.2, Modulus check] */
	ret = mlk_kem_check_pk(level, pk);
	if(ret != 0)
		goto cleanup;

	memcpy(buf, coins, MLKEM_SYMBYTES);

	/* Multitarget countermeasure for coins + contributory KEM */
	mlk_hash_h(buf + MLKEM_SYMBYTES, pk, _MLKEM_INDCCA_PUBLICKEYBYTES(level));
	mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

	/* coins are in kr+MLKEM_SYMBYTES */
	ret = mlk_indcpa_enc(level, ct, buf, pk, kr + MLKEM_SYMBYTES);
	if(ret != 0)
		goto cleanup;

	memcpy(ss, kr, MLKEM_SYMBYTES);

cleanup:
	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	memset(coins, 0, sizeof coins);
	memset(kr, 0, sizeof buf);
	memset(buf, 0, sizeof buf);
	return ret;
}

static int
mlk_kem_dec_x(int level, u8int *ss, const u8int *ct, const u8int *sk)
{
	int ret;
	u8int fail;
	const u8int *pk = sk + _MLKEM_INDCPA_SECRETKEYBYTES(level);
	u8int buf[2 * MLKEM_SYMBYTES];
	u8int kr[2 * MLKEM_SYMBYTES];
	u8int tmp[MLKEM_SYMBYTES + _MLKEM1024_INDCCA_CIPHERTEXTBYTES];

	/* Specification: Implements @[FIPS203, Section 7.3, Hash check] */
	ret = mlk_kem_check_sk(sk, _MLKEM_INDCCA_SECRETKEYBYTES(level), _MLKEM_INDCCA_PUBLICKEYBYTES(level));
	if(ret != 0)
		goto cleanup;

	ret = mlk_indcpa_dec(level, buf, ct, sk);
	if(ret != 0)
		goto cleanup;

	/* Multitarget countermeasure for coins + contributory KEM */
	memcpy(buf + MLKEM_SYMBYTES, sk + _MLKEM_INDCCA_SECRETKEYBYTES(level) - 2 * MLKEM_SYMBYTES, MLKEM_SYMBYTES);
	mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

	/* Recompute and compare ciphertext */
	/* coins are in kr+MLKEM_SYMBYTES */
	ret = mlk_indcpa_enc(level, tmp, buf, pk, kr + MLKEM_SYMBYTES);
	if(ret != 0)
		goto cleanup;

	switch(level){
	case K512:
		fail = tsmemcmp(ct, tmp, _MLKEM512_INDCCA_CIPHERTEXTBYTES);
		/* Compute rejection key */
		memcpy(tmp, sk + _MLKEM_INDCCA_SECRETKEYBYTES(K512) - MLKEM_SYMBYTES, MLKEM_SYMBYTES);
		memcpy(tmp + MLKEM_SYMBYTES, ct, _MLKEM512_INDCCA_CIPHERTEXTBYTES);
		mlk_hash_j(ss, tmp, MLKEM_SYMBYTES + _MLKEM512_INDCCA_CIPHERTEXTBYTES);
		break;
	case K768:
		fail = tsmemcmp(ct, tmp, _MLKEM768_INDCCA_CIPHERTEXTBYTES);
		/* Compute rejection key */
		memcpy(tmp, sk + _MLKEM_INDCCA_SECRETKEYBYTES(K768) - MLKEM_SYMBYTES, MLKEM_SYMBYTES);
		memcpy(tmp + MLKEM_SYMBYTES, ct, _MLKEM768_INDCCA_CIPHERTEXTBYTES);
		mlk_hash_j(ss, tmp, MLKEM_SYMBYTES + _MLKEM768_INDCCA_CIPHERTEXTBYTES);
		break;
	case K1024:
		fail = tsmemcmp(ct, tmp, _MLKEM1024_INDCCA_CIPHERTEXTBYTES);
		/* Compute rejection key */
		memcpy(tmp, sk + _MLKEM_INDCCA_SECRETKEYBYTES(K1024) - MLKEM_SYMBYTES, MLKEM_SYMBYTES);
		memcpy(tmp + MLKEM_SYMBYTES, ct, _MLKEM1024_INDCCA_CIPHERTEXTBYTES);
		mlk_hash_j(ss, tmp, MLKEM_SYMBYTES + _MLKEM1024_INDCCA_CIPHERTEXTBYTES);
		break;
	default:
		abort();
	}

	/* constant time memcpy using fail as the conditional */
	mlk_ct_cmov_zero(ss, kr, MLKEM_SYMBYTES, fail);

cleanup:
	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	memset(tmp, 0, sizeof tmp);
	memset(kr, 0, sizeof kr);
	memset(buf, 0, sizeof buf);

	return ret;
}

int
mlkem512_keypair(u8int *pk, u8int *sk)
{
	u8int coins[2 * MLKEM_SYMBYTES];

	genrandom(coins, sizeof coins);
	return mlk_kem_keypair_x(K512, pk, sk, coins);
}

int
mlkem768_keypair(u8int *pk, u8int *sk)
{
	u8int coins[2 * MLKEM_SYMBYTES];

	genrandom(coins, sizeof coins);
	return mlk_kem_keypair_x(K768, pk, sk, coins);
}

int
mlkem1024_keypair(u8int *pk, u8int *sk)
{
	u8int coins[2 * MLKEM_SYMBYTES];

	genrandom(coins, sizeof coins);
	return mlk_kem_keypair_x(K1024, pk, sk, coins);
}

int
mlkem512_enc(u8int *ct, u8int *ss, const u8int *pk)
{
	u8int coins[MLKEM_SYMBYTES];

	genrandom(coins, MLKEM_SYMBYTES);
	return mlk_kem_enc_x(K512, ct, ss, pk, coins);
}

int
mlkem768_enc(u8int *ct, u8int *ss, const u8int *pk)
{
	u8int coins[MLKEM_SYMBYTES];

	genrandom(coins, MLKEM_SYMBYTES);
	return mlk_kem_enc_x(K768, ct, ss, pk, coins);
}

int
mlkem1024_enc(u8int *ct, u8int *ss, const u8int *pk)
{
	u8int coins[MLKEM_SYMBYTES];

	genrandom(coins, MLKEM_SYMBYTES);
	return mlk_kem_enc_x(K1024, ct, ss, pk, coins);
}

int
mlkem512_dec(u8int *ss, const u8int *ct, const u8int *sk)
{
	return mlk_kem_dec_x(K512, ss, ct, sk);
}

int
mlkem768_dec(u8int *ss, const u8int *ct, const u8int *sk)
{
	return mlk_kem_dec_x(K768, ss, ct, sk);
}

int
mlkem1024_dec(u8int *ss, const u8int *ct, const u8int *sk)
{
	return mlk_kem_dec_x(K1024, ss, ct, sk);
}
