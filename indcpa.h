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

void mlkem512_gen_matrix(mlk_polymat *a, const u8int seed[MLKEM_SYMBYTES],
                    int transposed);
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
void mlkem768_gen_matrix(mlk_polymat *a, const u8int seed[MLKEM_SYMBYTES],
                    int transposed);
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
void mlkem1024_gen_matrix(mlk_polymat *a, const u8int seed[MLKEM_SYMBYTES],
                    int transposed);
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
