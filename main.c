#include <u.h>
#include <libc.h>
#include <stdio.h>

/* expose some internals for testing */
enum{
	K512 = 2,
	K768,
	K1024,
};

#define MLKEM_SYMBYTES 32 /* size in bytes of hashes, and seeds */

int mlk_kem_keypair_x(int level, u8int *pk, u8int *sk, u8int *coins);
int mlk_kem_enc_x(int level, u8int *ct, u8int *ss, const u8int *pk, u8int *coins);

#include "expected_test_vectors_multilevel.h"
#include "mlkem_native.h"

static u32int seed[32] = {3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3,
                            2, 3, 8, 4, 6, 2, 6, 4, 3, 3, 8, 3, 2, 7, 9, 5};
static u32int in[12];
static u32int out[8];
static s32int outleft = 0;

void randombytes_reset(void)
{
  memset(in, 0, sizeof(in));
  memset(out, 0, sizeof(out));
  outleft = 0;
}

#define ROTATE(x, b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i, b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x, b));

static void surf(void)
{
  u32int t[12];
  u32int x;
  u32int sum = 0;
  s32int r;
  s32int i;
  s32int loop;

  for (i = 0; i < 12; ++i)
  {
    t[i] = in[i] ^ seed[12 + i];
  }
  for (i = 0; i < 8; ++i)
  {
    out[i] = seed[24 + i];
  }
  x = t[11];
  for (loop = 0; loop < 2; ++loop)
  {
    for (r = 0; r < 16; ++r)
    {
      sum += 0x9e3779b9;
      MUSH(0, 5)
      MUSH(1, 7)
      MUSH(2, 9)
      MUSH(3, 13)
      MUSH(4, 5)
      MUSH(5, 7)
      MUSH(6, 9)
      MUSH(7, 13)
      MUSH(8, 5)
      MUSH(9, 7)
      MUSH(10, 9)
      MUSH(11, 13)
    }
    for (i = 0; i < 8; ++i)
    {
      out[i] ^= t[i + 4];
    }
  }
}

void genrandom(u8int *buf, int n)
{
  while (n > 0)
  {
    if (!outleft)
    {
      if (!++in[0])
      {
        if (!++in[1])
        {
          if (!++in[2])
          {
            ++in[3];
          }
        }
      }
      surf();
      outleft = 8;
    }
    *buf = (u8int)out[--outleft];
    ++buf;
    --n;
  }
}

#define CHECK assert

static int example_mlkem512_keygen(void)
{
  uchar pk[MLKEM512_PUBLICKEYBYTES];
  uchar sk[MLKEM512_SECRETKEYBYTES];
  uchar coins[2 * MLKEM_SYMBYTES];

  printf("  Generating keypair (randomized)... ");
  CHECK(mlkem512_keypair(pk, sk) == 0);
  CHECK(memcmp(pk, test_vector_pk_512, MLKEM512_PUBLICKEYBYTES) == 0);
  CHECK(memcmp(sk, test_vector_sk_512, MLKEM512_SECRETKEYBYTES) == 0);
  printf("DONE\n");

  printf("  Generating keypair (deterministic)... ");
  memcpy(coins, test_vector_d, MLKEM_SYMBYTES);
  memcpy(coins + MLKEM_SYMBYTES, test_vector_z, MLKEM_SYMBYTES);
  CHECK(mlk_kem_keypair_x(K512, pk, sk, coins) == 0);
  CHECK(memcmp(pk, test_vector_pk_512, MLKEM512_PUBLICKEYBYTES) == 0);
  CHECK(memcmp(sk, test_vector_sk_512, MLKEM512_SECRETKEYBYTES) == 0);
  printf("DONE\n");
  return 0;
}

static int example_mlkem768_keygen(void)
{
  uchar pk[MLKEM768_PUBLICKEYBYTES];
  uchar sk[MLKEM768_SECRETKEYBYTES];
  uchar coins[2 * MLKEM_SYMBYTES];

  printf("  Generating keypair (randomized)... ");
  CHECK(mlkem768_keypair(pk, sk) == 0);
  CHECK(memcmp(pk, test_vector_pk_768, MLKEM768_PUBLICKEYBYTES) == 0);
  CHECK(memcmp(sk, test_vector_sk_768, MLKEM768_SECRETKEYBYTES) == 0);
  printf("DONE\n");

  printf("  Generating keypair (deterministic)... ");
  memcpy(coins, test_vector_d, MLKEM_SYMBYTES);
  memcpy(coins + MLKEM_SYMBYTES, test_vector_z, MLKEM_SYMBYTES);
  CHECK(mlk_kem_keypair_x(K768, pk, sk, coins) == 0);
  CHECK(memcmp(pk, test_vector_pk_768, MLKEM768_PUBLICKEYBYTES) == 0);
  CHECK(memcmp(sk, test_vector_sk_768, MLKEM768_SECRETKEYBYTES) == 0);
  printf("DONE\n");
  return 0;
}

static int example_mlkem1024_keygen(void)
{
  uchar pk[MLKEM1024_PUBLICKEYBYTES];
  uchar sk[MLKEM1024_SECRETKEYBYTES];
  uchar coins[2 * MLKEM_SYMBYTES];

  printf("  Generating keypair (randomized)... ");
  CHECK(mlkem1024_keypair(pk, sk) == 0);
  CHECK(memcmp(pk, test_vector_pk_1024, MLKEM1024_PUBLICKEYBYTES) == 0);
  CHECK(memcmp(sk, test_vector_sk_1024, MLKEM1024_SECRETKEYBYTES) == 0);
  printf("DONE\n");

  printf("  Generating keypair (deterministic)... ");
  memcpy(coins, test_vector_d, MLKEM_SYMBYTES);
  memcpy(coins + MLKEM_SYMBYTES, test_vector_z, MLKEM_SYMBYTES);
  CHECK(mlk_kem_keypair_x(K1024, pk, sk, coins) == 0);
  CHECK(memcmp(pk, test_vector_pk_1024, MLKEM1024_PUBLICKEYBYTES) == 0);
  CHECK(memcmp(sk, test_vector_sk_1024, MLKEM1024_SECRETKEYBYTES) == 0);
  printf("DONE\n");
  return 0;
}

/* Encaps examples */

static int example_mlkem512_encaps(void)
{
  uchar ct[MLKEM512_CIPHERTEXTBYTES];
  uchar ss[MLKEM512_BYTES];

  printf("  Encaps (randomized)... ");
  CHECK(mlkem512_enc(ct, ss, test_vector_pk_512) == 0);
  CHECK(memcmp(ct, test_vector_ct_512, MLKEM512_CIPHERTEXTBYTES) == 0);
  CHECK(memcmp(ss, test_vector_ss_512, MLKEM512_BYTES) == 0);
  printf("DONE\n");

  printf("  Encaps (deterministic)... ");
  CHECK(mlk_kem_enc_x(K512, ct, ss, test_vector_pk_512, test_vector_m) == 0);
  CHECK(memcmp(ct, test_vector_ct_512, MLKEM512_CIPHERTEXTBYTES) == 0);
  CHECK(memcmp(ss, test_vector_ss_512, MLKEM512_BYTES) == 0);
  printf("DONE\n");
  return 0;
}

static int example_mlkem768_encaps(void)
{
  uchar ct[MLKEM768_CIPHERTEXTBYTES];
  uchar ss[MLKEM768_BYTES];

  printf("  Encaps (randomized)... ");
  CHECK(mlkem768_enc(ct, ss, test_vector_pk_768) == 0);
  CHECK(memcmp(ct, test_vector_ct_768, MLKEM768_CIPHERTEXTBYTES) == 0);
  CHECK(memcmp(ss, test_vector_ss_768, MLKEM768_BYTES) == 0);
  printf("DONE\n");

  printf("  Encaps (deterministic)... ");
  CHECK(mlk_kem_enc_x(K768, ct, ss, test_vector_pk_768, test_vector_m) == 0);
  CHECK(memcmp(ct, test_vector_ct_768, MLKEM768_CIPHERTEXTBYTES) == 0);
  CHECK(memcmp(ss, test_vector_ss_768, MLKEM768_BYTES) == 0);
  printf("DONE\n");
  return 0;
}

static int example_mlkem1024_encaps(void)
{
  uchar ct[MLKEM1024_CIPHERTEXTBYTES];
  uchar ss[MLKEM1024_BYTES];

  printf("  Encaps (randomized)... ");
  CHECK(mlkem1024_enc(ct, ss, test_vector_pk_1024) == 0);
  CHECK(memcmp(ct, test_vector_ct_1024, MLKEM1024_CIPHERTEXTBYTES) == 0);
  CHECK(memcmp(ss, test_vector_ss_1024, MLKEM1024_BYTES) == 0);
  printf("DONE\n");

  printf("  Encaps (deterministic)... ");
  CHECK(mlk_kem_enc_x(K1024, ct, ss, test_vector_pk_1024, test_vector_m) == 0);
  CHECK(memcmp(ct, test_vector_ct_1024, MLKEM1024_CIPHERTEXTBYTES) == 0);
  CHECK(memcmp(ss, test_vector_ss_1024, MLKEM1024_BYTES) == 0);
  printf("DONE\n");
  return 0;
}

/* Decaps examples */

static int example_mlkem512_decaps(void)
{
  uchar ss[MLKEM512_BYTES];

  printf("  Decaps... ");
  CHECK(mlkem512_dec(ss, test_vector_ct_512, test_vector_sk_512) == 0);
  CHECK(memcmp(ss, test_vector_ss_512, MLKEM512_BYTES) == 0);
  printf("DONE\n");
  return 0;
}

static int example_mlkem768_decaps(void)
{
  uchar ss[MLKEM768_BYTES];

  printf("  Decaps... ");
  CHECK(mlkem768_dec(ss, test_vector_ct_768, test_vector_sk_768) == 0);
  CHECK(memcmp(ss, test_vector_ss_768, MLKEM768_BYTES) == 0);
  printf("DONE\n");
  return 0;
}

static int example_mlkem1024_decaps(void)
{
  uchar ss[MLKEM1024_BYTES];

  printf("  Decaps... ");
  CHECK(mlkem1024_dec(ss, test_vector_ct_1024, test_vector_sk_1024) == 0);
  CHECK(memcmp(ss, test_vector_ss_1024, MLKEM1024_BYTES) == 0);
  printf("DONE\n");
  return 0;
}

int main(void)
{
  int r = 0;

  printf("ML-KEM multilevel_build Example\n");
  printf("======================\n\n");

  printf("ML-KEM-512\n");
  /* WARNING: Test-only
   * Normally, you would want to seed a PRNG with trustworthy entropy here. */
  randombytes_reset();
  r |= example_mlkem512_keygen();
  /* WARNING: Test-only
   * Normally, you would seed a PRNG _once_ with trustworthy entropy
   * and not reseed it afterwards. Here, we reseed to make tests
   * independent and reproducible. */
  randombytes_reset();
  r |= example_mlkem512_encaps();
  r |= example_mlkem512_decaps();

  printf("\nML-KEM-768\n");
  randombytes_reset();
  r |= example_mlkem768_keygen();
  randombytes_reset();
  r |= example_mlkem768_encaps();
  r |= example_mlkem768_decaps();

  printf("\nML-KEM-1024\n");
  randombytes_reset();
  r |= example_mlkem1024_keygen();
  randombytes_reset();
  r |= example_mlkem1024_encaps();
  r |= example_mlkem1024_decaps();

  if (r)
  {
    return 1;
  }

  printf("\nAll tests passed!\n");
  return 0;
}
