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
