#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

#include "a.h"
#include "fips202.h"

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

static int
mlk_kem_check_pk(int level, const u8int *pk)
{
	mlk_polyvec p;
	u8int p_reencoded[_MLKEM_POLYVECBYTES(K1024)];

	mlk_polyvec_frombytes(level, &p, pk);
	mlk_polyvec_reduce(level, &p);
	mlk_polyvec_tobytes(level, p_reencoded, &p);
	return tsmemcmp(pk, p_reencoded, _MLKEM_POLYVECBYTES(level)) ? MLK_ERR_FAIL : 0;
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
	return memcmp(sk + sn - 2 * MLKEM_SYMBYTES, test, MLKEM_SYMBYTES) ? MLK_ERR_FAIL : 0;
}

static int
mlk_kem_keypair_x(int level, u8int *pk, u8int *sk)
{
	int ret;
	u8int coins[2 * MLKEM_SYMBYTES];

	if(mlk_randombytes(coins, sizeof coins) != 0){
		ret = MLK_ERR_RNG_FAIL;
		goto cleanup;
	}

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

static int
mlk_kem_enc_x(int level, u8int *ct, u8int *ss, const u8int *pk)
{
	int ret;
	u8int coins[MLKEM_SYMBYTES];
	u8int buf[2 * MLKEM_SYMBYTES];
	u8int kr[2 * MLKEM_SYMBYTES];

	if(mlk_randombytes(coins, MLKEM_SYMBYTES) != 0){
		ret = MLK_ERR_RNG_FAIL;
		goto cleanup;
	}

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

	switch(level){
	case K512:
		ret = mlk_indcpa_dec(level, buf, ct, sk);
		if(ret != 0)
			goto cleanup;

		/* Multitarget countermeasure for coins + contributory KEM */
		memcpy(buf + MLKEM_SYMBYTES, sk + _MLKEM_INDCCA_SECRETKEYBYTES(K512) - 2 * MLKEM_SYMBYTES, MLKEM_SYMBYTES);
		mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

		/* Recompute and compare ciphertext */
		/* coins are in kr+MLKEM_SYMBYTES */
		ret = mlk_indcpa_enc(level, tmp, buf, pk, kr + MLKEM_SYMBYTES);
		if(ret != 0)
			goto cleanup;
		fail = mlk_ct_memcmp(ct, tmp, _MLKEM512_INDCCA_CIPHERTEXTBYTES);
		/* Compute rejection key */
		memcpy(tmp, sk + _MLKEM_INDCCA_SECRETKEYBYTES(K512) - MLKEM_SYMBYTES, MLKEM_SYMBYTES);
		memcpy(tmp + MLKEM_SYMBYTES, ct, _MLKEM512_INDCCA_CIPHERTEXTBYTES);
		mlk_hash_j(ss, tmp, MLKEM_SYMBYTES + _MLKEM512_INDCCA_CIPHERTEXTBYTES);
		break;
	case K768:
		ret = mlk_indcpa_dec(level, buf, ct, sk);
		if(ret != 0)
			goto cleanup;

		/* Multitarget countermeasure for coins + contributory KEM */
		memcpy(buf + MLKEM_SYMBYTES, sk + _MLKEM_INDCCA_SECRETKEYBYTES(K768) - 2 * MLKEM_SYMBYTES, MLKEM_SYMBYTES);
		mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

		/* Recompute and compare ciphertext */
		/* coins are in kr+MLKEM_SYMBYTES */
		ret = mlk_indcpa_enc(level, tmp, buf, pk, kr + MLKEM_SYMBYTES);
		if(ret != 0)
			goto cleanup;
		fail = mlk_ct_memcmp(ct, tmp, _MLKEM768_INDCCA_CIPHERTEXTBYTES);
		/* Compute rejection key */
		memcpy(tmp, sk + _MLKEM_INDCCA_SECRETKEYBYTES(K768) - MLKEM_SYMBYTES, MLKEM_SYMBYTES);
		memcpy(tmp + MLKEM_SYMBYTES, ct, _MLKEM768_INDCCA_CIPHERTEXTBYTES);
		mlk_hash_j(ss, tmp, MLKEM_SYMBYTES + _MLKEM768_INDCCA_CIPHERTEXTBYTES);
		break;
	case K1024:
		ret = mlk_indcpa_dec(level, buf, ct, sk);
		if(ret != 0)
			goto cleanup;

		/* Multitarget countermeasure for coins + contributory KEM */
		memcpy(buf + MLKEM_SYMBYTES, sk + _MLKEM_INDCCA_SECRETKEYBYTES(K1024) - 2 * MLKEM_SYMBYTES, MLKEM_SYMBYTES);
		mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

		/* Recompute and compare ciphertext */
		/* coins are in kr+MLKEM_SYMBYTES */
		ret = mlk_indcpa_enc(level, tmp, buf, pk, kr + MLKEM_SYMBYTES);
		if(ret != 0)
			goto cleanup;
		fail = mlk_ct_memcmp(ct, tmp, _MLKEM1024_INDCCA_CIPHERTEXTBYTES);
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
	return mlk_kem_keypair_x(K512, pk, sk);
}

int
mlkem768_keypair(u8int *pk, u8int *sk)
{
	return mlk_kem_keypair_x(K768, pk, sk);
}

int
mlkem1024_keypair(u8int *pk, u8int *sk)
{
	return mlk_kem_keypair_x(K1024, pk, sk);
}

int
mlkem512_enc(u8int *ct, u8int *ss, const u8int *pk)
{
	return mlk_kem_enc_x(K512, ct, ss, pk);
}

int
mlkem768_enc(u8int *ct, u8int *ss, const u8int *pk)
{
	return mlk_kem_enc_x(K768, ct, ss, pk);
}

int
mlkem1024_enc(u8int *ct, u8int *ss, const u8int *pk)
{
	return mlk_kem_enc_x(K1024, ct, ss, pk);
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
