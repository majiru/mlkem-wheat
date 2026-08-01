#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

#include "a.h"
#include "fips202.h"
#include "params.h"

static int
mlk_kem_check_pk(const u8int *pk, int n)
{
	mlk_polyvec p;
	u8int p_reencoded[K1024 * MLKEM_POLYBYTES];

	switch(n){
	case K512 * MLKEM_POLYBYTES:
		mlkem512_polyvec_frombytes(&p, pk);
		mlkem512_polyvec_reduce(&p);
		mlkem512_polyvec_tobytes(p_reencoded, &p);
		break;
	case K768 * MLKEM_POLYBYTES:
		mlkem768_polyvec_frombytes(&p, pk);
		mlkem768_polyvec_reduce(&p);
		mlkem768_polyvec_tobytes(p_reencoded, &p);
		break;
	case K1024 * MLKEM_POLYBYTES:
		mlkem1024_polyvec_frombytes(&p, pk);
		mlkem1024_polyvec_reduce(&p);
		mlkem1024_polyvec_tobytes(p_reencoded, &p);
		break;
	default:
		abort();
	}
	return mlk_ct_memcmp(pk, p_reencoded, n) ? MLK_ERR_FAIL : 0;
}

static
int mlk_kem_check_sk(const u8int sk[MLKEM_INDCCA_SECRETKEYBYTES])
{
	int ret;
	MLK_ALLOC(test, u8int, MLKEM_SYMBYTES);

	if(test == nil){
		ret = MLK_ERR_OUT_OF_MEMORY;
		goto cleanup;
	}

	/*
	 * The parts of `sk` being hashed and compared here are public, so
	 * no public information is leaked through the runtime or the return value
	 * of this function.
	 */

	mlk_hash_h(test, sk + MLKEM_INDCPA_SECRETKEYBYTES, MLKEM_INDCCA_PUBLICKEYBYTES);
	/* This doesn't have to be a constant-time memcmp, but it's the only place
	 * in the library where a normal memcmp would be used otherwise, so for sake
	 * of minimizing stdlib dependency, we use our constant-time one anyway. */
	ret = mlk_ct_memcmp(sk + MLKEM_INDCCA_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES, test, MLKEM_SYMBYTES) ? MLK_ERR_FAIL : 0;

cleanup:
	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	MLK_FREE(test, u8int, MLKEM_SYMBYTES);
	return ret;
}

#if defined(MLK_CONFIG_KEYGEN_PCT)
/* Specification:
 * Partially implements 'Pairwise Consistency Test' @[FIPS140_3_IG, p.87] and
 * @[FIPS203, Section 7.1, Pairwise Consistency]. */

/* Reference: Not implemented in the reference implementation @[REF]. */
static int mlk_check_pct(u8int const pk[MLKEM_INDCCA_PUBLICKEYBYTES], u8int const sk[MLKEM_INDCCA_SECRETKEYBYTES])
{
	int ret = 0;
	MLK_ALLOC(ct, u8int, MLKEM_INDCCA_CIPHERTEXTBYTES);
	MLK_ALLOC(ss_enc, u8int, MLKEM_SSBYTES);
	MLK_ALLOC(ss_dec, u8int, MLKEM_SSBYTES);

	if (ct == nil || ss_enc == nil || ss_dec == nil)
	{
		ret = MLK_ERR_OUT_OF_MEMORY;
		goto cleanup;
	}

	ret = mlk_kem_enc(ct, ss_enc, pk);
	if (ret != 0)
		goto cleanup;

	ret = mlk_kem_dec(ss_dec, ct, sk);
	if (ret != 0)
		goto cleanup;

#if defined(MLK_CONFIG_KEYGEN_PCT_BREAKAGE_TEST)
	/* Deliberately break PCT for testing purposes */
	if (mlk_break_pct())
	{
		ss_enc[0] = ~ss_enc[0];
	}
#endif /* MLK_CONFIG_KEYGEN_PCT_BREAKAGE_TEST */

	ret = mlk_ct_memcmp(ss_enc, ss_dec, MLKEM_SSBYTES);

	if (ret != 0)
		ret = MLK_ERR_FAIL;

cleanup:

	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	MLK_FREE(ss_dec, u8int, MLKEM_SSBYTES);
	MLK_FREE(ss_enc, u8int, MLKEM_SSBYTES);
	MLK_FREE(ct, u8int, MLKEM_INDCCA_CIPHERTEXTBYTES);
	return ret;
}
#else /* MLK_CONFIG_KEYGEN_PCT */
static int mlk_check_pct(u8int const pk[MLKEM_INDCCA_PUBLICKEYBYTES], u8int const sk[MLKEM_INDCCA_SECRETKEYBYTES])
{
	USED(pk);
	USED(sk);
	return 0;
}
#endif /* !MLK_CONFIG_KEYGEN_PCT */

static int
mlk_kem_keypair_x(int level, u8int pk[MLKEM_INDCCA_PUBLICKEYBYTES], u8int sk[MLKEM_INDCCA_SECRETKEYBYTES])
{
	int ret;
	MLK_ALLOC(coins, u8int, 2 * MLKEM_SYMBYTES);

	if(coins == nil){
		ret = MLK_ERR_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* Acquire necessary randomness, and mark it as secret. */
	if(mlk_randombytes(coins, 2 * MLKEM_SYMBYTES) != 0){
		ret = MLK_ERR_RNG_FAIL;
		goto cleanup;
	}

	switch(level){
	case 512:
		ret = mlkem512_indcpa_keypair_derand(pk, sk, coins);
		break;
	case 768:
		ret = mlkem768_indcpa_keypair_derand(pk, sk, coins);
		break;
	case 1024:
		ret = mlkem1024_indcpa_keypair_derand(pk, sk, coins);
		break;
	default:
		abort();
	}
	if(ret != 0)
		goto cleanup;

	mlk_memcpy(sk + MLKEM_INDCPA_SECRETKEYBYTES, pk, MLKEM_INDCCA_PUBLICKEYBYTES);
	mlk_hash_h(sk + MLKEM_INDCCA_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES, pk, MLKEM_INDCCA_PUBLICKEYBYTES);
	/* Value z for pseudo-random output on reject */
	mlk_memcpy(sk + MLKEM_INDCCA_SECRETKEYBYTES - MLKEM_SYMBYTES, coins + MLKEM_SYMBYTES, MLKEM_SYMBYTES);

	/* Pairwise Consistency Test (PCT) @[FIPS140_3_IG, p.87] */
	ret = mlk_check_pct(pk, sk);
	if(ret != 0)
		goto cleanup;

cleanup:
	MLK_FREE(coins, u8int, 2 * MLKEM_SYMBYTES);
	if(ret != 0){
		mlk_zeroize(pk, MLKEM_INDCCA_PUBLICKEYBYTES);
		mlk_zeroize(sk, MLKEM_INDCCA_SECRETKEYBYTES);
	}

	return ret;
}

static int
mlk_kem_enc_x(int level, u8int ct[MLKEM_INDCCA_CIPHERTEXTBYTES], u8int ss[MLKEM_SSBYTES], const u8int pk[MLKEM_INDCCA_PUBLICKEYBYTES])
{
	int ret;
	MLK_ALLOC(coins, u8int, MLKEM_SYMBYTES);
	MLK_ALLOC(buf, u8int, 2 * MLKEM_SYMBYTES);
	MLK_ALLOC(kr, u8int, 2 * MLKEM_SYMBYTES);

	if(coins == nil){
		ret = MLK_ERR_OUT_OF_MEMORY;
		goto cleanup;
	}

	if(mlk_randombytes(coins, MLKEM_SYMBYTES) != 0){
		ret = MLK_ERR_RNG_FAIL;
		goto cleanup;
	}

	if(buf == nil || kr == nil){
		ret = MLK_ERR_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* Specification: Implements @[FIPS203, Section 7.2, Modulus check] */
	ret = mlk_kem_check_pk(pk, MLKEM_POLYVECBYTES);
	if(ret != 0)
		goto cleanup;

	mlk_memcpy(buf, coins, MLKEM_SYMBYTES);

	/* Multitarget countermeasure for coins + contributory KEM */
	mlk_hash_h(buf + MLKEM_SYMBYTES, pk, MLKEM_INDCCA_PUBLICKEYBYTES);
	mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

	/* coins are in kr+MLKEM_SYMBYTES */
	switch(level){
	case 512:
		ret = mlkem512_indcpa_enc(ct, buf, pk, kr + MLKEM_SYMBYTES);
		break;
	case 768:
		ret = mlkem768_indcpa_enc(ct, buf, pk, kr + MLKEM_SYMBYTES);
		break;
	case 1024:
		ret = mlkem1024_indcpa_enc(ct, buf, pk, kr + MLKEM_SYMBYTES);
		break;
	default:
		abort();
	}
	if(ret != 0)
		goto cleanup;

	mlk_memcpy(ss, kr, MLKEM_SYMBYTES);

cleanup:
	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	MLK_FREE(coins, u8int, MLKEM_SYMBYTES);
	MLK_FREE(kr, u8int, 2 * MLKEM_SYMBYTES);
	MLK_FREE(buf, u8int, 2 * MLKEM_SYMBYTES);
	return ret;
}

static int
mlk_kem_dec_x(int level, u8int ss[MLKEM_SSBYTES], const u8int ct[MLKEM_INDCCA_CIPHERTEXTBYTES], const u8int sk[MLKEM_INDCCA_SECRETKEYBYTES])
{
	int ret;
	u8int fail;
	const u8int *pk = sk + MLKEM_INDCPA_SECRETKEYBYTES;
	MLK_ALLOC(buf, u8int, 2 * MLKEM_SYMBYTES);
	MLK_ALLOC(kr, u8int, 2 * MLKEM_SYMBYTES);
	MLK_ALLOC(tmp, u8int, MLKEM_SYMBYTES + MLKEM_INDCCA_CIPHERTEXTBYTES);

	if(buf == nil || kr == nil || tmp == nil){
		ret = MLK_ERR_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* Specification: Implements @[FIPS203, Section 7.3, Hash check] */
	ret = mlk_kem_check_sk(sk);
	if(ret != 0)
		goto cleanup;

	switch(level){
	case 512:
		ret = mlkem512_indcpa_dec(buf, ct, sk);
		if(ret != 0)
			goto cleanup;

		/* Multitarget countermeasure for coins + contributory KEM */
		mlk_memcpy(buf + MLKEM_SYMBYTES, sk + MLKEM_INDCCA_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES, MLKEM_SYMBYTES);
		mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

		/* Recompute and compare ciphertext */
		/* coins are in kr+MLKEM_SYMBYTES */
		ret = mlkem512_indcpa_enc(tmp, buf, pk, kr + MLKEM_SYMBYTES);
		if(ret != 0)
			goto cleanup;
		break;
	case 768:
		ret = mlkem768_indcpa_dec(buf, ct, sk);
		if(ret != 0)
			goto cleanup;

		/* Multitarget countermeasure for coins + contributory KEM */
		mlk_memcpy(buf + MLKEM_SYMBYTES, sk + MLKEM_INDCCA_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES, MLKEM_SYMBYTES);
		mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

		/* Recompute and compare ciphertext */
		/* coins are in kr+MLKEM_SYMBYTES */
		ret = mlkem768_indcpa_enc(tmp, buf, pk, kr + MLKEM_SYMBYTES);
		if(ret != 0)
			goto cleanup;
		break;
	case 1024:
		ret = mlkem1024_indcpa_dec(buf, ct, sk);
		if(ret != 0)
			goto cleanup;

		/* Multitarget countermeasure for coins + contributory KEM */
		mlk_memcpy(buf + MLKEM_SYMBYTES, sk + MLKEM_INDCCA_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES, MLKEM_SYMBYTES);
		mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

		/* Recompute and compare ciphertext */
		/* coins are in kr+MLKEM_SYMBYTES */
		ret = mlkem1024_indcpa_enc(tmp, buf, pk, kr + MLKEM_SYMBYTES);
		if(ret != 0)
			goto cleanup;
		break;
	default:
		abort();
	}

	fail = mlk_ct_memcmp(ct, tmp, MLKEM_INDCCA_CIPHERTEXTBYTES);

	/* Compute rejection key */
	mlk_memcpy(tmp, sk + MLKEM_INDCCA_SECRETKEYBYTES - MLKEM_SYMBYTES, MLKEM_SYMBYTES);
	mlk_memcpy(tmp + MLKEM_SYMBYTES, ct, MLKEM_INDCCA_CIPHERTEXTBYTES);
	mlk_hash_j(ss, tmp, MLKEM_SYMBYTES + MLKEM_INDCCA_CIPHERTEXTBYTES);

	/* Copy true key to return buffer if fail is 0 */
	mlk_ct_cmov_zero(ss, kr, MLKEM_SYMBYTES, fail);

cleanup:
	/* Specification: Partially implements
	 * @[FIPS203, Section 3.3, Destruction of intermediate values] */
	MLK_FREE(tmp, u8int, MLKEM_SYMBYTES + MLKEM_INDCCA_CIPHERTEXTBYTES);
	MLK_FREE(kr, u8int, 2 * MLKEM_SYMBYTES);
	MLK_FREE(buf, u8int, 2 * MLKEM_SYMBYTES);

	return ret;
}

#define mlk_kem_keypair MLK_NAMESPACE_K(keypair)
#define mlk_kem_enc MLK_NAMESPACE_K(enc)
#define mlk_kem_dec MLK_NAMESPACE_K(dec)

int
mlk_kem_keypair(u8int pk[MLKEM_INDCCA_PUBLICKEYBYTES], u8int sk[MLKEM_INDCCA_SECRETKEYBYTES])
{
	return mlk_kem_keypair_x(MLK_CONFIG_PARAMETER_SET, pk, sk);
}

int
mlk_kem_enc(u8int ct[MLKEM_INDCCA_CIPHERTEXTBYTES], u8int ss[MLKEM_SSBYTES], const u8int pk[MLKEM_INDCCA_PUBLICKEYBYTES])
{
	return mlk_kem_enc_x(MLK_CONFIG_PARAMETER_SET, ct, ss, pk);
}

int
mlk_kem_dec(u8int ss[MLKEM_SSBYTES], const u8int ct[MLKEM_INDCCA_CIPHERTEXTBYTES], const u8int sk[MLKEM_INDCCA_SECRETKEYBYTES])
{
	return mlk_kem_dec_x(MLK_CONFIG_PARAMETER_SET, ss, ct, sk);
}
