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
 *
 * - [REF]
 *   CRYSTALS-Kyber C reference implementation
 *   Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schanck, Schwabe, Seiler, Stehlé
 *   https://github.com/pq-crystals/kyber/tree/main/ref
 */

/*
 * The multiplication in this routine will exceed UINT32_MAX
 * and wrap around for large values of u. This is expected and required.
 */

u8int mlk_scalar_compress_d1(s16int u);
u8int mlk_scalar_compress_d4(s16int u);
s16int mlk_scalar_decompress_d4(u8int u);
u8int mlk_scalar_compress_d5(s16int u);
s16int mlk_scalar_decompress_d5(u8int u);
u16int mlk_scalar_compress_d10(s16int u);
s16int mlk_scalar_decompress_d10(u16int u);
u16int mlk_scalar_compress_d11(s16int u);
s16int mlk_scalar_decompress_d11(u16int u);

/**
 * Compression (4 bits) and subsequent serialization of a polynomial.
 *
 * @spec{Implements `ByteEncode_4 (Compress_4 (a))`: ByteEncode_d
 * @[FIPS203, Algorithm 5], Compress_d @[FIPS203, Eq (4.7)], extended to
 * vectors as per @[FIPS203, 2.4.8 Applying Algorithms to Arrays].
 * `ByteEncode_{d_v} (Compress_{d_v} (v))` appears in @[FIPS203, Algorithm
 * 14 (K-PKE.Encrypt), L23], where `d_v=4` for ML-KEM-{512,768} @[FIPS203,
 * Table 2].}
 *
 * @param[out] r Output byte array (of length MLKEM_POLYCOMPRESSEDBYTES_D4
 *               bytes).
 * @param[in]  a Input polynomial. Coefficients must be unsigned canonical,
 *               i.e. in [0,1,..,MLKEM_Q-1].
 */
MLK_INTERNAL_API
void mlk_poly_compress_d4(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D4],
                          const mlk_poly *a);

/**
 * Compression (10 bits) and subsequent serialization of a polynomial.
 *
 * @spec{Implements `ByteEncode_10 (Compress_10 (a))`: ByteEncode_d
 * @[FIPS203, Algorithm 5], Compress_d @[FIPS203, Eq (4.7)], extended to
 * vectors as per @[FIPS203, 2.4.8 Applying Algorithms to Arrays].
 * `ByteEncode_{d_u} (Compress_{d_u} (u))` appears in @[FIPS203, Algorithm
 * 14 (K-PKE.Encrypt), L22], where `d_u=10` for ML-KEM-{512,768} @[FIPS203,
 * Table 2].}
 *
 * @param[out] r Output byte array (of length MLKEM_POLYCOMPRESSEDBYTES_D10
 *               bytes).
 * @param[in]  a Input polynomial. Coefficients must be unsigned canonical,
 *               i.e. in [0,1,..,MLKEM_Q-1].
 */
MLK_INTERNAL_API
void mlk_poly_compress_d10(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D10],
                           const mlk_poly *a);

/**
 * De-serialization and subsequent decompression (4 bits) of a polynomial;
 * approximate inverse of mlk_poly_compress_d4.
 *
 * Upon return, the coefficients of the output polynomial are
 * unsigned-canonical (non-negative and smaller than MLKEM_Q).
 *
 * @spec{Implements `Decompress_4 (ByteDecode_4 (a))`: ByteDecode_d
 * @[FIPS203, Algorithm 6], Decompress_d @[FIPS203, Eq (4.8)], extended to
 * vectors as per @[FIPS203, 2.4.8 Applying Algorithms to Arrays].
 * `Decompress_{d_v} (ByteDecode_{d_v} (v))` appears in @[FIPS203, Algorithm
 * 15 (K-PKE.Decrypt), L4], where `d_v=4` for ML-KEM-{512,768} @[FIPS203,
 * Table 2].}
 *
 * @param[out] r Output polynomial.
 * @param[in]  a Input byte array (of length MLKEM_POLYCOMPRESSEDBYTES_D4
 *               bytes).
 */
MLK_INTERNAL_API
void mlk_poly_decompress_d4(mlk_poly *r,
                            const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D4]);

/**
 * De-serialization and subsequent decompression (10 bits) of a polynomial;
 * approximate inverse of mlk_poly_compress_d10.
 *
 * Upon return, the coefficients of the output polynomial are
 * unsigned-canonical (non-negative and smaller than MLKEM_Q).
 *
 * @spec{Implements `Decompress_10 (ByteDecode_10 (a))`: ByteDecode_d
 * @[FIPS203, Algorithm 6], Decompress_d @[FIPS203, Eq (4.8)], extended to
 * vectors as per @[FIPS203, 2.4.8 Applying Algorithms to Arrays].
 * `Decompress_{d_u} (ByteDecode_{d_u} (u))` appears in @[FIPS203, Algorithm
 * 15 (K-PKE.Decrypt), L3], where `d_u=10` for ML-KEM-{512,768} @[FIPS203,
 * Table 2].}
 *
 * @param[out] r Output polynomial.
 * @param[in]  a Input byte array (of length MLKEM_POLYCOMPRESSEDBYTES_D10
 *               bytes).
 */
MLK_INTERNAL_API
void mlk_poly_decompress_d10(mlk_poly *r,
                             const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D10]);

/**
 * Compression (5 bits) and subsequent serialization of a polynomial.
 *
 * @spec{Implements `ByteEncode_5 (Compress_5 (a))`: ByteEncode_d
 * @[FIPS203, Algorithm 5], Compress_d @[FIPS203, Eq (4.7)], extended to
 * vectors as per @[FIPS203, 2.4.8 Applying Algorithms to Arrays].
 * `ByteEncode_{d_v} (Compress_{d_v} (v))` appears in @[FIPS203, Algorithm
 * 14 (K-PKE.Encrypt), L23], where `d_v=5` for ML-KEM-1024 @[FIPS203,
 * Table 2].}
 *
 * @param[out] r Output byte array (of length MLKEM_POLYCOMPRESSEDBYTES_D5
 *               bytes).
 * @param[in]  a Input polynomial. Coefficients must be unsigned canonical,
 *               i.e. in [0,1,..,MLKEM_Q-1].
 */
MLK_INTERNAL_API
void mlk_poly_compress_d5(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D5],
                          const mlk_poly *a);

/**
 * Compression (11 bits) and subsequent serialization of a polynomial.
 *
 * @spec{`ByteEncode_11 (Compress_11 (a))`: ByteEncode_d @[FIPS203,
 * Algorithm 5], Compress_d @[FIPS203, Eq (4.7)], extended to vectors as
 * per @[FIPS203, 2.4.8 Applying Algorithms to Arrays].
 * `ByteEncode_{d_u} (Compress_{d_u} (u))` appears in @[FIPS203, Algorithm
 * 14 (K-PKE.Encrypt), L22], where `d_u=11` for ML-KEM-1024 @[FIPS203,
 * Table 2].}
 *
 * @param[out] r Output byte array (of length MLKEM_POLYCOMPRESSEDBYTES_D11
 *               bytes).
 * @param[in]  a Input polynomial. Coefficients must be unsigned canonical,
 *               i.e. in [0,1,..,MLKEM_Q-1].
 */
MLK_INTERNAL_API
void mlk_poly_compress_d11(u8int r[MLKEM_POLYCOMPRESSEDBYTES_D11],
                           const mlk_poly *a);

/**
 * De-serialization and subsequent decompression (5 bits) of a polynomial;
 * approximate inverse of mlk_poly_compress_d5.
 *
 * Upon return, the coefficients of the output polynomial are
 * unsigned-canonical (non-negative and smaller than MLKEM_Q).
 *
 * @spec{Implements `Decompress_5 (ByteDecode_5 (a))`: ByteDecode_d
 * @[FIPS203, Algorithm 6], Decompress_d @[FIPS203, Eq (4.8)], extended to
 * vectors as per @[FIPS203, 2.4.8 Applying Algorithms to Arrays].
 * `Decompress_{d_v} (ByteDecode_{d_v} (v))` appears in @[FIPS203, Algorithm
 * 15 (K-PKE.Decrypt), L4], where `d_v=5` for ML-KEM-1024 @[FIPS203,
 * Table 2].}
 *
 * @param[out] r Output polynomial.
 * @param[in]  a Input byte array (of length MLKEM_POLYCOMPRESSEDBYTES_D5
 *               bytes).
 */
MLK_INTERNAL_API
void mlk_poly_decompress_d5(mlk_poly *r,
                            const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D5]);

/**
 * De-serialization and subsequent decompression (11 bits) of a polynomial;
 * approximate inverse of mlk_poly_compress_d11.
 *
 * Upon return, the coefficients of the output polynomial are
 * unsigned-canonical (non-negative and smaller than MLKEM_Q).
 *
 * @spec{Implements `Decompress_11 (ByteDecode_11 (a))`: ByteDecode_d
 * @[FIPS203, Algorithm 6], Decompress_d @[FIPS203, Eq (4.8)], extended to
 * vectors as per @[FIPS203, 2.4.8 Applying Algorithms to Arrays].
 * `Decompress_{d_u} (ByteDecode_{d_u} (u))` appears in @[FIPS203, Algorithm
 * 15 (K-PKE.Decrypt), L3], where `d_u=11` for ML-KEM-1024 @[FIPS203,
 * Table 2].}
 *
 * @param[out] r Output polynomial.
 * @param[in]  a Input byte array (of length MLKEM_POLYCOMPRESSEDBYTES_D11
 *               bytes).
 */
MLK_INTERNAL_API
void mlk_poly_decompress_d11(mlk_poly *r,
                             const u8int a[MLKEM_POLYCOMPRESSEDBYTES_D11]);

/**
 * Serialization of a polynomial. Signed coefficients are converted to
 * unsigned form before serialization.
 *
 * @spec{Implements ByteEncode_12 @[FIPS203, Algorithm 5]. Extended to
 * vectors as per @[FIPS203, 2.4.8 Applying Algorithms to Arrays].}
 *
 * @param[out] r Output byte array (of MLKEM_POLYBYTES bytes).
 * @param[in]  a Input polynomial, with each coefficient in the range
 *               [0,1,..,MLKEM_Q-1].
 */
MLK_INTERNAL_API
void mlk_poly_tobytes(u8int r[MLKEM_POLYBYTES], const mlk_poly *a);


/**
 * De-serialization of a polynomial.
 *
 * @spec{Implements ByteDecode_12 @[FIPS203, Algorithm 6]. Extended to
 * vectors as per @[FIPS203, 2.4.8 Applying Algorithms to Arrays].}
 *
 * @param[out] r Output polynomial, with each coefficient unsigned and in
 *               the range 0..4095.
 * @param[in]  a Input byte array (of MLKEM_POLYBYTES bytes).
 */
MLK_INTERNAL_API
void mlk_poly_frombytes(mlk_poly *r, const u8int a[MLKEM_POLYBYTES]);


/**
 * Convert a 32-byte message to a polynomial.
 *
 * @spec{Implements `Decompress_1 (ByteDecode_1 (a))`: ByteDecode_d
 * @[FIPS203, Algorithm 6], Decompress_d @[FIPS203, Eq (4.8)], extended to
 * vectors as per @[FIPS203, 2.4.8 Applying Algorithms to Arrays].
 * `Decompress_1 (ByteDecode_1 (w))` appears in @[FIPS203, Algorithm 15
 * (K-PKE.Encrypt), L20].}
 *
 * @param[out] r   Output polynomial.
 * @param[in]  msg Input message.
 */
MLK_INTERNAL_API
void mlk_poly_frommsg(mlk_poly *r, const u8int msg[MLKEM_INDCPA_MSGBYTES]);

/**
 * Convert a polynomial to a 32-byte message.
 *
 * @spec{Implements `ByteEncode_1 (Compress_1 (a))`: ByteEncode_d
 * @[FIPS203, Algorithm 5], Compress_d @[FIPS203, Eq (4.7)], extended to
 * vectors as per @[FIPS203, 2.4.8 Applying Algorithms to Arrays].
 * `ByteEncode_1 (Compress_1 (w))` appears in @[FIPS203, Algorithm 14
 * (K-PKE.Decrypt), L7].}
 *
 * @param[out] msg Output message.
 * @param[in]  r   Input polynomial. Coefficients must be unsigned canonical.
 */
MLK_INTERNAL_API
void mlk_poly_tomsg(u8int msg[MLKEM_INDCPA_MSGBYTES], const mlk_poly *r);

