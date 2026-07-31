/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#include <u.h>
#include <libc.h>
#include <stdio.h>

#include "mlkem_native.h"
#include "notrandombytes.h"

#define CHECK(x) assert(x)

static int test_keys_mlkem512(void)
{
  /* The PCT modifies the PRNG state, so the KAT tests don't work.
   * We run KAT tests only for disabled PCT. */
#ifndef MLK_CONFIG_KEYGEN_PCT
  const u8int expected_key[] = {
      0x77, 0x6c, 0x74, 0xdf, 0x30, 0x1f, 0x8d, 0x82, 0x52, 0x5e, 0x8e,
      0xbb, 0xb4, 0x00, 0x95, 0xcd, 0x2e, 0x92, 0xdf, 0x6d, 0xc9, 0x33,
      0xe7, 0x86, 0x62, 0x59, 0xf5, 0x31, 0xc7, 0x35, 0x0a, 0xd5};
#endif /* !MLK_CONFIG_KEYGEN_PCT */

  u8int pk[MLKEM512_PUBLICKEYBYTES];
  u8int sk[MLKEM512_SECRETKEYBYTES];
  u8int ct[MLKEM512_CIPHERTEXTBYTES];
  u8int key_a[MLKEM512_BYTES];
  u8int key_b[MLKEM512_BYTES];

  /* WARNING: Test-only
   * Normally, you would want to seed a PRNG with trustworthy entropy here. */
  randombytes_reset();

  /* Alice generates a public key */
  CHECK(mlkem512_keypair(pk, sk) == 0);

  /* Bob derives a secret key and creates a response */
  CHECK(mlkem512_enc(ct, key_b, pk) == 0);

  /* Alice uses Bobs response to get her shared key */
  CHECK(mlkem512_dec(key_a, ct, sk) == 0);

  CHECK(memcmp(key_a, key_b, MLKEM512_BYTES) == 0);

  printf("Shared secret: ");
  {
    ulong i;
    for (i = 0; i < sizeof(key_a); i++)
    {
      printf("%02x", key_a[i]);
    }
  }
  printf("\n");

#ifndef MLK_CONFIG_KEYGEN_PCT
  /* Check against hardcoded result to make sure that
   * we integrated custom FIPS202 correctly */
  CHECK(memcmp(key_a, expected_key, sizeof(key_a)) == 0);
#else
  printf(
      "[WARNING] Skipping KAT test since PCT is enabled and modifies PRNG\n");
#endif

  printf("[MLKEM-512] OK\n");
  return 0;
}

static int test_keys_mlkem768(void)
{
  /* The PCT modifies the PRNG state, so the KAT tests don't work.
   * We run KAT tests only for disabled PCT. */
#ifndef MLK_CONFIG_KEYGEN_PCT
  const u8int expected_key[] = {
      0xe9, 0x13, 0x77, 0x84, 0x0e, 0x6b, 0x66, 0x94, 0xea, 0xa9, 0xf0,
      0x1c, 0x97, 0xff, 0x68, 0x87, 0x4e, 0x8b, 0x0c, 0x52, 0x0b, 0x00,
      0xc2, 0xcd, 0xe3, 0x7c, 0x4f, 0xc2, 0x39, 0x62, 0x6e, 0x70};
#endif /* !MLK_CONFIG_KEYGEN_PCT */

  u8int pk[MLKEM768_PUBLICKEYBYTES];
  u8int sk[MLKEM768_SECRETKEYBYTES];
  u8int ct[MLKEM768_CIPHERTEXTBYTES];
  u8int key_a[MLKEM768_BYTES];
  u8int key_b[MLKEM768_BYTES];

  /* WARNING: Test-only
   * Normally, you would want to seed a PRNG with trustworthy entropy here. */
  randombytes_reset();

  /* Alice generates a public key */
  CHECK(mlkem768_keypair(pk, sk) == 0);

  /* Bob derives a secret key and creates a response */
  CHECK(mlkem768_enc(ct, key_b, pk) == 0);

  /* Alice uses Bobs response to get her shared key */
  CHECK(mlkem768_dec(key_a, ct, sk) == 0);

  CHECK(memcmp(key_a, key_b, MLKEM768_BYTES) == 0);

  printf("Shared secret: ");
  {
    ulong i;
    for (i = 0; i < sizeof(key_a); i++)
    {
      printf("%02x", key_a[i]);
    }
  }
  printf("\n");

#ifndef MLK_CONFIG_KEYGEN_PCT
  /* Check against hardcoded result to make sure that
   * we integrated custom FIPS202 correctly */
  CHECK(memcmp(key_a, expected_key, sizeof(key_a)) == 0);
#else
  printf(
      "[WARNING] Skipping KAT test since PCT is enabled and modifies PRNG\n");
#endif

  printf("[MLKEM-768] OK\n");
  return 0;
}


static int test_keys_mlkem1024(void)
{
  /* The PCT modifies the PRNG state, so the KAT tests don't work.
   * We run KAT tests only for disabled PCT. */
#ifndef MLK_CONFIG_KEYGEN_PCT
  const u8int expected_key[] = {
      0x5d, 0x9e, 0x23, 0x5f, 0xcc, 0xb2, 0xb3, 0x49, 0x9a, 0x5f, 0x49,
      0x0a, 0x56, 0xe3, 0xf0, 0xd3, 0xfd, 0x9b, 0x58, 0xbd, 0xa2, 0x8b,
      0x69, 0x0f, 0x91, 0xb5, 0x7b, 0x88, 0xa5, 0xa8, 0x0b, 0x90};
#endif /* !MLK_CONFIG_KEYGEN_PCT */
  u8int pk[MLKEM1024_PUBLICKEYBYTES];
  u8int sk[MLKEM1024_SECRETKEYBYTES];
  u8int ct[MLKEM1024_CIPHERTEXTBYTES];
  u8int key_a[MLKEM1024_BYTES];
  u8int key_b[MLKEM1024_BYTES];

  /* WARNING: Test-only
   * Normally, you would want to seed a PRNG with trustworthy entropy here. */
  randombytes_reset();

  /* Alice generates a public key */
  CHECK(mlkem1024_keypair(pk, sk) == 0);

  /* Bob derives a secret key and creates a response */
  CHECK(mlkem1024_enc(ct, key_b, pk) == 0);

  /* Alice uses Bobs response to get her shared key */
  CHECK(mlkem1024_dec(key_a, ct, sk) == 0);

  CHECK(memcmp(key_a, key_b, MLKEM1024_BYTES) == 0);

  printf("Shared secret: ");
  {
    ulong i;
    for (i = 0; i < sizeof(key_a); i++)
    {
      printf("%02x", key_a[i]);
    }
  }
  printf("\n");

#ifndef MLK_CONFIG_KEYGEN_PCT
  /* Check against hardcoded result to make sure that
   * we integrated custom FIPS202 correctly */
  CHECK(memcmp(key_a, expected_key, sizeof(key_a)) == 0);
#else
  printf(
      "[WARNING] Skipping KAT test since PCT is enabled and modifies PRNG\n");
#endif

  printf("[MLKEM-1024] OK\n");
  return 0;
}

int main(void)
{
  if (test_keys_mlkem512() != 0)
  {
    return 1;
  }

  if (test_keys_mlkem768() != 0)
  {
    return 1;
  }

  if (test_keys_mlkem1024() != 0)
  {
    return 1;
  }

  exits(0);
}
