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
#define MLKEM_UINT12_LIMIT 4096

#define MLKEM_SYMBYTES 32 /* size in bytes of hashes, and seeds */
#define MLKEM_SSBYTES 32  /* size in bytes of shared key */

#define MLKEM_POLYBYTES 384

#define MLKEM_POLYCOMPRESSEDBYTES_D4 128
#define MLKEM_POLYCOMPRESSEDBYTES_D5 160
#define MLKEM_POLYCOMPRESSEDBYTES_D10 320
#define MLKEM_POLYCOMPRESSEDBYTES_D11 352

#define MLKEM_ETA2 2

#define MLKEM_INDCPA_MSGBYTES (MLKEM_SYMBYTES)

#define MLK_INTERNAL_API
#define MLK_INTERNAL_DATA_DECLARATION extern
#define MLK_INTERNAL_DATA_DEFINITION
#define MLK_EXTERNAL_API

/* Standard library function replacements */
#define mlk_memcpy memcpy
#define mlk_memset memset

/* Default: stack allocation */

#define MLK_ALLOC(v, T, N) \
  T *v = malloc(N * sizeof(T));

#define MLK_FREE(v, T, N)			\
  do						\
  {						\
    memset(v, 0, N * sizeof(T));		\
    free(v);					\
    (v) = nil;					\
    USED((v));					\
  } while (0)

/* Generic failure condition */
#define MLK_ERR_FAIL -1
/* An allocation failed. This can only happen if MLK_CONFIG_CUSTOM_ALLOC_FREE
 * is defined and the provided MLK_CUSTOM_ALLOC can fail. */
#define MLK_ERR_OUT_OF_MEMORY -2
/* An rng failure occured. Might be due to insufficient entropy or
 * system misconfiguration. */
#define MLK_ERR_RNG_FAIL -3

/***** verify.c  *****/

#define mlk_ct_memcmp tsmemcmp
#define mlk_zeroize(ptr, len) memset(ptr, 0, len)

u64int mlk_ct_get_optblocker_u64(void);
u8int mlk_ct_get_optblocker_u8(void);
u32int mlk_ct_get_optblocker_u32(void);
s32int mlk_ct_get_optblocker_i32(void);
u32int mlk_value_barrier_u32(u32int b);
s32int mlk_value_barrier_i32(s32int b);
u8int mlk_value_barrier_u8(u8int b);
s16int mlk_cast_u16into_int16(u16int x);
u16int mlk_cast_s32into_uint16(s32int x);
u16int mlk_cast_s16into_uint16(s32int x);
u16int mlk_ct_cmask_neg_i16(s16int x);
u16int mlk_ct_cmask_nonzero_u16(u16int x);
u8int mlk_ct_cmask_nonzero_u8(u8int x);
s16int mlk_ct_sel_int16(s16int a, s16int b, u16int cond);
u8int mlk_ct_sel_uint8(u8int a, u8int b, u8int cond);

/***** randombytes.c  *****/

int mlk_randombytes(u8int *out, ulong outlen);

/***** symmetric.h  *****/

/* Macros denoting FIPS 203 specific Hash functions */

/* Hash function H, @[FIPS203, Section 4.1, Eq (4.4)] */
#define mlk_hash_h(OUT, IN, INBYTES) mlk_sha3_256(OUT, IN, INBYTES)

/* Hash function G, @[FIPS203, Section 4.1, Eq (4.5)] */
#define mlk_hash_g(OUT, IN, INBYTES) mlk_sha3_512(OUT, IN, INBYTES)

/* Hash function J, @[FIPS203, Section 4.1, Eq (4.4)] */
#define mlk_hash_j(OUT, IN, INBYTES) \
  mlk_shake256(OUT, MLKEM_SYMBYTES, IN, INBYTES)

/* PRF function, @[FIPS203, Section 4.1, Eq (4.3)]
 * Referring to (eq 4.3), `OUT` is assumed to contain `s || b`. */
#define mlk_prf_eta(ETA, OUT, IN) \
  mlk_shake256(OUT, (ETA) * MLKEM_N / 4, IN, MLKEM_SYMBYTES + 1)
#define mlk_prf_eta1(OUT, IN) mlk_prf_eta(MLKEM_ETA1, OUT, IN)
#define mlk_prf_eta2(OUT, IN) mlk_prf_eta(MLKEM_ETA2, OUT, IN)

/* XOF function, FIPS 203 4.1 */
#define mlk_xof_ctx mlk_shake128ctx
#define mlk_xof_init(CTX) mlk_shake128_init((CTX))
#define mlk_xof_absorb(CTX, IN, INBYTES) \
  mlk_shake128_absorb_once((CTX), (IN), (INBYTES))
#define mlk_xof_squeezeblocks(BUF, NBLOCKS, CTX) \
  mlk_shake128_squeezeblocks((BUF), (NBLOCKS), (CTX))
#define mlk_xof_release(CTX) mlk_shake128_release((CTX))

#define MLK_XOF_RATE SHAKE128_RATE

/***** poly.c  *****/

/* Absolute exclusive upper bound for the output of the inverse NTT */
#define MLK_INVNTT_BOUND (8 * MLKEM_Q)

/* Absolute exclusive upper bound for the output of the forward NTT */
#define MLK_NTT_BOUND (8 * MLKEM_Q)

/**
 * Element of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1].
 */
typedef struct
{
  s16int coeffs[MLKEM_N]; /**< Polynomial coefficients. */
} mlk_poly;

/**
 * INTERNAL representation of precomputed data speeding up
 * the base multiplication of two polynomials in NTT domain.
 */
typedef struct
{
  s16int coeffs[MLKEM_N >> 1]; /**< Cached coefficients. */
} mlk_poly_mulcache;

s16int mlk_montgomery_reduce(s32int a);
void mlk_poly_tomont(mlk_poly *r);
void mlk_poly_mulcache_compute(mlk_poly_mulcache *x, const mlk_poly *a);
void mlk_poly_reduce(mlk_poly *r);
void mlk_poly_add(mlk_poly *r, const mlk_poly *b);
void mlk_poly_sub(mlk_poly *r, const mlk_poly *b);
void mlk_poly_ntt(mlk_poly *r);
void mlk_poly_invntt_tomont(mlk_poly *r);

/***** sampling.c *****/

void mlk_poly_cbd2(mlk_poly *r, const u8int buf[2 * MLKEM_N / 4]);
void mlk_poly_cbd3(mlk_poly *r, const u8int buf[3 * MLKEM_N / 4]);
void mlk_poly_rej_uniform(mlk_poly *entry, u8int seed[MLKEM_SYMBYTES + 2]);

/***** compress.c  *****/

u8int mlk_scalar_compress_d1(s16int u);
u8int mlk_scalar_compress_d4(s16int u);
s16int mlk_scalar_decompress_d4(u8int u);
u8int mlk_scalar_compress_d5(s16int u);
s16int mlk_scalar_decompress_d5(u8int u);
u16int mlk_scalar_compress_d10(s16int u);
s16int mlk_scalar_decompress_d10(u16int u);
u16int mlk_scalar_compress_d11(s16int u);
s16int mlk_scalar_decompress_d11(u16int u);

void mlk_poly_compress_d4(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D4], const mlk_poly *a);
void mlk_poly_compress_d10(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D10], const mlk_poly *a);
void mlk_poly_decompress_d4(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D4]);
void mlk_poly_decompress_d10(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D10]);
void mlk_poly_compress_d5(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D5], const mlk_poly *a);
void mlk_poly_compress_d11(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D11], const mlk_poly *a);
void mlk_poly_decompress_d5(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D5]);
void mlk_poly_decompress_d11(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D11]);
void mlk_poly_tobytes(u8int r[MLKEM_POLYBYTES], const mlk_poly *a);
void mlk_poly_frombytes(mlk_poly *r, const u8int a[MLKEM_POLYBYTES]);
void mlk_poly_frommsg(mlk_poly *r, const u8int msg[MLKEM_INDCPA_MSGBYTES]);
void mlk_poly_tomsg(u8int msg[MLKEM_INDCPA_MSGBYTES], const mlk_poly *r);

/***** poly_k.c  *****/

/* Sized up to the max it can be for 1024 FIXME(?) */
typedef struct
{
  mlk_poly vec[K1024];
} mlk_polyvec;

typedef struct
{
 mlk_polyvec vec[K1024];
} mlk_polymat;

typedef struct
{
  mlk_poly_mulcache vec[K1024];
} mlk_polyvec_mulcache;

void mlk_polyvec_compress_du(int level, u8int r[(2 * MLKEM_POLYCOMPRESSEDBYTES_D10)],
                             const mlk_polyvec *a);
void mlk_polyvec_decompress_du(int level, mlk_polyvec *r,
                               const u8int a[(2 * MLKEM_POLYCOMPRESSEDBYTES_D10)]);
void mlk_polyvec_tobytes(int level, u8int r[(3 * MLKEM_POLYBYTES)], const mlk_polyvec *a);
void mlk_polyvec_frombytes(int level, mlk_polyvec *r, const u8int a[(3 * MLKEM_POLYBYTES)]);
void mlk_polyvec_ntt(int level, mlk_polyvec *r);
void mlk_polyvec_invntt_tomont(int level, mlk_polyvec *r);
void mlk_polyvec_tomont(int level, mlk_polyvec *r);
void mlk_polyvec_mulcache_compute(int level, mlk_polyvec_mulcache *x, const mlk_polyvec *a);
void mlk_polyvec_reduce(int level, mlk_polyvec *r);
void mlk_polyvec_add(int level, mlk_polyvec *r, const mlk_polyvec *b);
void mlk_polyvec_basemul_acc_montgomery_cached(int level,
    mlk_poly *r, const mlk_polyvec *a, const mlk_polyvec *b,
    const mlk_polyvec_mulcache *b_cache);


void mlkem512_poly_getnoise_eta1_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                               mlk_poly *r3, const u8int seed[MLKEM_SYMBYTES],
                               u8int nonce0, u8int nonce1, u8int nonce2,
                               u8int nonce3);
void mlkem512_poly_getnoise_eta2(mlk_poly *r, const u8int seed[MLKEM_SYMBYTES],
                            u8int nonce);
void mlkem512_poly_getnoise_eta1122_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                                  mlk_poly *r3,
                                  const u8int seed[MLKEM_SYMBYTES],
                                  u8int nonce0, u8int nonce1,
                                  u8int nonce2, u8int nonce3);

void mlkem768_poly_getnoise_eta1_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                               mlk_poly *r3, const u8int seed[MLKEM_SYMBYTES],
                               u8int nonce0, u8int nonce1, u8int nonce2,
                               u8int nonce3);

void mlkem1024_poly_getnoise_eta1_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                               mlk_poly *r3, const u8int seed[MLKEM_SYMBYTES],
                               u8int nonce0, u8int nonce1, u8int nonce2,
                               u8int nonce3);
void mlkem1024_poly_getnoise_eta2(mlk_poly *r, const u8int seed[MLKEM_SYMBYTES],
                            u8int nonce);

/***** indcpa.c  *****/

int mlkem512_indcpa_keypair_derand(u8int pk[((2 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES)],
                              u8int sk[((2 * MLKEM_POLYBYTES))],
                              const u8int coins[MLKEM_SYMBYTES]);
int mlkem512_indcpa_enc(u8int c[((2 * MLKEM_POLYCOMPRESSEDBYTES_D10) + MLKEM_POLYCOMPRESSEDBYTES_D4)],
                   const u8int m[MLKEM_INDCPA_MSGBYTES],
                   const u8int pk[((2 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES)],
                   const u8int coins[MLKEM_SYMBYTES]);
int mlkem512_indcpa_dec(u8int m[MLKEM_INDCPA_MSGBYTES],
                   const u8int c[((2 * MLKEM_POLYCOMPRESSEDBYTES_D10) + MLKEM_POLYCOMPRESSEDBYTES_D4)],
                   const u8int sk[((2 * MLKEM_POLYBYTES))]);
int mlkem768_indcpa_keypair_derand(u8int pk[((3 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES)],
                              u8int sk[((3 * MLKEM_POLYBYTES))],
                              const u8int coins[MLKEM_SYMBYTES]);
int mlkem768_indcpa_enc(u8int c[((3 * MLKEM_POLYCOMPRESSEDBYTES_D10) + MLKEM_POLYCOMPRESSEDBYTES_D4)],
                   const u8int m[MLKEM_INDCPA_MSGBYTES],
                   const u8int pk[((3 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES)],
                   const u8int coins[MLKEM_SYMBYTES]);
int mlkem768_indcpa_dec(u8int m[MLKEM_INDCPA_MSGBYTES],
                   const u8int c[((3 * MLKEM_POLYCOMPRESSEDBYTES_D10) + MLKEM_POLYCOMPRESSEDBYTES_D4)],
                   const u8int sk[((3 * MLKEM_POLYBYTES))]);
int mlkem1024_indcpa_keypair_derand(u8int pk[((4 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES)],
                              u8int sk[((4 * MLKEM_POLYBYTES))],
                              const u8int coins[MLKEM_SYMBYTES]);
int mlkem1024_indcpa_enc(u8int c[((4 * MLKEM_POLYCOMPRESSEDBYTES_D11) + MLKEM_POLYCOMPRESSEDBYTES_D5)],
                   const u8int m[MLKEM_INDCPA_MSGBYTES],
                   const u8int pk[((4 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES)],
                   const u8int coins[MLKEM_SYMBYTES]);
int mlkem1024_indcpa_dec(u8int m[MLKEM_INDCPA_MSGBYTES],
                   const u8int c[((4 * MLKEM_POLYCOMPRESSEDBYTES_D11) + MLKEM_POLYCOMPRESSEDBYTES_D5)],
                   const u8int sk[((4 * MLKEM_POLYBYTES))]);
