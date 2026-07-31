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

int mlkem512_check_pk(const u8int pk[(((2 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))]);
int mlkem512_check_sk(const u8int sk[(((2 * MLKEM_POLYBYTES)) +((2 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES) + 2 * MLKEM_SYMBYTES)]);
int mlkem512_keypair_derand(u8int pk[(((2 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))],
                           u8int sk[(((2 * MLKEM_POLYBYTES)) +((2 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES) + 2 * MLKEM_SYMBYTES)],
                           const u8int coins[2 * MLKEM_SYMBYTES]);
int mlkem512_keypair(u8int pk[(((2 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))],
                    u8int sk[(((2 * MLKEM_POLYBYTES)) +((2 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES) + 2 * MLKEM_SYMBYTES)]);
int mlkem512_enc_derand(u8int ct[(((2 * MLKEM_POLYCOMPRESSEDBYTES_D10) + MLKEM_POLYCOMPRESSEDBYTES_D4))],
                       u8int ss[MLKEM_SSBYTES],
                       const u8int pk[(((2 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))],
                       const u8int coins[MLKEM_SYMBYTES]);
int mlkem512_enc(u8int ct[(((2 * MLKEM_POLYCOMPRESSEDBYTES_D10) + MLKEM_POLYCOMPRESSEDBYTES_D4))],
                u8int ss[MLKEM_SSBYTES],
                const u8int pk[(((2 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))]);
int mlkem512_dec(u8int ss[MLKEM_SSBYTES],
                const u8int ct[(((2 * MLKEM_POLYCOMPRESSEDBYTES_D10) + MLKEM_POLYCOMPRESSEDBYTES_D4))],
                const u8int sk[(((2 * MLKEM_POLYBYTES)) +((2 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES) + 2 * MLKEM_SYMBYTES)]);
int mlkem768_check_pk(const u8int pk[(((3 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))]);
int mlkem768_check_sk(const u8int sk[(((3 * MLKEM_POLYBYTES)) +((3 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES) + 2 * MLKEM_SYMBYTES)]);
int mlkem768_keypair_derand(u8int pk[(((3 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))],
                           u8int sk[(((3 * MLKEM_POLYBYTES)) +((3 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES) + 2 * MLKEM_SYMBYTES)],
                           const u8int coins[2 * MLKEM_SYMBYTES]);
int mlkem768_keypair(u8int pk[(((3 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))],
                    u8int sk[(((3 * MLKEM_POLYBYTES)) +((3 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES) + 2 * MLKEM_SYMBYTES)]);
int mlkem768_enc_derand(u8int ct[(((3 * MLKEM_POLYCOMPRESSEDBYTES_D10) + MLKEM_POLYCOMPRESSEDBYTES_D4))],
                       u8int ss[MLKEM_SSBYTES],
                       const u8int pk[(((3 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))],
                       const u8int coins[MLKEM_SYMBYTES]);
int mlkem768_enc(u8int ct[(((3 * MLKEM_POLYCOMPRESSEDBYTES_D10) + MLKEM_POLYCOMPRESSEDBYTES_D4))],
                u8int ss[MLKEM_SSBYTES],
                const u8int pk[(((3 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))]);
int mlkem768_dec(u8int ss[MLKEM_SSBYTES],
                const u8int ct[(((3 * MLKEM_POLYCOMPRESSEDBYTES_D10) + MLKEM_POLYCOMPRESSEDBYTES_D4))],
                const u8int sk[(((3 * MLKEM_POLYBYTES)) +((3 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES) + 2 * MLKEM_SYMBYTES)]);
int mlkem1024_check_pk(const u8int pk[(((4 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))]);
int mlkem1024_check_sk(const u8int sk[(((4 * MLKEM_POLYBYTES)) +((4 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES) + 2 * MLKEM_SYMBYTES)]);
int mlkem1024_keypair_derand(u8int pk[(((4 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))],
                           u8int sk[(((4 * MLKEM_POLYBYTES)) +((4 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES) + 2 * MLKEM_SYMBYTES)],
                           const u8int coins[2 * MLKEM_SYMBYTES]);
int mlkem1024_keypair(u8int pk[(((4 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))],
                    u8int sk[(((4 * MLKEM_POLYBYTES)) +((4 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES) + 2 * MLKEM_SYMBYTES)]);
int mlkem1024_enc_derand(u8int ct[(((4 * MLKEM_POLYCOMPRESSEDBYTES_D11) + MLKEM_POLYCOMPRESSEDBYTES_D5))],
                       u8int ss[MLKEM_SSBYTES],
                       const u8int pk[(((4 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))],
                       const u8int coins[MLKEM_SYMBYTES]);
int mlkem1024_enc(u8int ct[(((4 * MLKEM_POLYCOMPRESSEDBYTES_D11) + MLKEM_POLYCOMPRESSEDBYTES_D5))],
                u8int ss[MLKEM_SSBYTES],
                const u8int pk[(((4 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES))]);
int mlkem1024_dec(u8int ss[MLKEM_SSBYTES],
                const u8int ct[(((4 * MLKEM_POLYCOMPRESSEDBYTES_D11) + MLKEM_POLYCOMPRESSEDBYTES_D5))],
                const u8int sk[(((4 * MLKEM_POLYBYTES)) +((4 * MLKEM_POLYBYTES) + MLKEM_SYMBYTES) + 2 * MLKEM_SYMBYTES)]);
