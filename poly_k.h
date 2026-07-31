/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [FIPS203]
 *   FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/pubs/fips/203/final
 */

/* Sized up to the max it can be for 1024 FIXME(?) */
typedef struct
{
  mlk_poly vec[4];
} mlk_polyvec;

typedef struct
{
 mlk_polyvec vec[4];
} mlk_polymat;

typedef struct
{
  mlk_poly_mulcache vec[4];
} mlk_polyvec_mulcache;

void mlkem512_poly_compress_du(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D10], const mlk_poly *a);
void mlkem512_poly_decompress_du(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D10]);
void mlkem512_poly_compress_dv(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D4], const mlk_poly *a);
void mlkem512_poly_decompress_dv(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D4]);
void mlkem512_polyvec_compress_du(u8int r[(2 * MLKEM_POLYCOMPRESSEDBYTES_D10)],
                             const mlk_polyvec *a);
void mlkem512_polyvec_decompress_du(mlk_polyvec *r,
                               const u8int a[(2 * MLKEM_POLYCOMPRESSEDBYTES_D10)]);
void mlkem512_polyvec_tobytes(u8int r[(2 * MLKEM_POLYBYTES)], const mlk_polyvec *a);
void mlkem512_polyvec_frombytes(mlk_polyvec *r, const u8int a[(2 * MLKEM_POLYBYTES)]);
void mlkem512_polyvec_ntt(mlk_polyvec *r);
void mlkem512_polyvec_invntt_tomont(mlk_polyvec *r);
void mlkem512_polyvec_basemul_acc_montgomery_cached(
    mlk_poly *r, const mlk_polyvec *a, const mlk_polyvec *b,
    const mlk_polyvec_mulcache *b_cache);
void mlkem512_polyvec_mulcache_compute(mlk_polyvec_mulcache *x, const mlk_polyvec *a);
void mlkem512_polyvec_reduce(mlk_polyvec *r);
void mlkem512_polyvec_add(mlk_polyvec *r, const mlk_polyvec *b);
void mlkem512_polyvec_tomont(mlk_polyvec *r);
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

void mlkem768_poly_compress_du(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D10], const mlk_poly *a);
void mlkem768_poly_decompress_du(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D10]);
void mlkem768_poly_compress_dv(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D4], const mlk_poly *a);
void mlkem768_poly_decompress_dv(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D4]);
void mlkem768_polyvec_compress_du(u8int r[(3 * MLKEM_POLYCOMPRESSEDBYTES_D10)],
                             const mlk_polyvec *a);
void mlkem768_polyvec_decompress_du(mlk_polyvec *r,
                               const u8int a[(3 * MLKEM_POLYCOMPRESSEDBYTES_D10)]);
void mlkem768_polyvec_tobytes(u8int r[(3 * MLKEM_POLYBYTES)], const mlk_polyvec *a);
void mlkem768_polyvec_frombytes(mlk_polyvec *r, const u8int a[(3 * MLKEM_POLYBYTES)]);
void mlkem768_polyvec_ntt(mlk_polyvec *r);
void mlkem768_polyvec_invntt_tomont(mlk_polyvec *r);
void mlkem768_polyvec_basemul_acc_montgomery_cached(
    mlk_poly *r, const mlk_polyvec *a, const mlk_polyvec *b,
    const mlk_polyvec_mulcache *b_cache);
void mlkem768_polyvec_mulcache_compute(mlk_polyvec_mulcache *x, const mlk_polyvec *a);
void mlkem768_polyvec_reduce(mlk_polyvec *r);
void mlkem768_polyvec_add(mlk_polyvec *r, const mlk_polyvec *b);
void mlkem768_polyvec_tomont(mlk_polyvec *r);
void mlkem768_poly_getnoise_eta1_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                               mlk_poly *r3, const u8int seed[MLKEM_SYMBYTES],
                               u8int nonce0, u8int nonce1, u8int nonce2,
                               u8int nonce3);

void mlkem1024_poly_compress_du(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D11], const mlk_poly *a);
void mlkem1024_poly_decompress_du(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D11]);
void mlkem1024_poly_compress_dv(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D5], const mlk_poly *a);
void mlkem1024_poly_decompress_dv(mlk_poly *r, const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D5]);
void mlkem1024_polyvec_compress_du(u8int r[(4 * MLKEM_POLYCOMPRESSEDBYTES_D11)],
                             const mlk_polyvec *a);
void mlkem1024_polyvec_decompress_du(mlk_polyvec *r,
                               const u8int a[(4 * MLKEM_POLYCOMPRESSEDBYTES_D11)]);
void mlkem1024_polyvec_tobytes(u8int r[(4 * MLKEM_POLYBYTES)], const mlk_polyvec *a);
void mlkem1024_polyvec_frombytes(mlk_polyvec *r, const u8int a[(4 * MLKEM_POLYBYTES)]);
void mlkem1024_polyvec_ntt(mlk_polyvec *r);
void mlkem1024_polyvec_invntt_tomont(mlk_polyvec *r);
void mlkem1024_polyvec_basemul_acc_montgomery_cached(
    mlk_poly *r, const mlk_polyvec *a, const mlk_polyvec *b,
    const mlk_polyvec_mulcache *b_cache);
void mlkem1024_polyvec_mulcache_compute(mlk_polyvec_mulcache *x, const mlk_polyvec *a);
void mlkem1024_polyvec_reduce(mlk_polyvec *r);
void mlkem1024_polyvec_add(mlk_polyvec *r, const mlk_polyvec *b);
void mlkem1024_polyvec_tomont(mlk_polyvec *r);
void mlkem1024_poly_getnoise_eta1_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                               mlk_poly *r3, const u8int seed[MLKEM_SYMBYTES],
                               u8int nonce0, u8int nonce1, u8int nonce2,
                               u8int nonce3);
void mlkem1024_poly_getnoise_eta2(mlk_poly *r, const u8int seed[MLKEM_SYMBYTES],
                            u8int nonce);
