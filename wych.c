#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>
#include <json.h>

/* expose some internals for testing */
enum{
	K512 = 2,
	K768,
	K1024,
};

#define MLKEM_SYMBYTES 32 /* size in bytes of hashes, and seeds */

int mlk_kem_keypair_x(int level, u8int *pk, u8int *sk, u8int *coins);
int mlk_kem_enc_x(int level, u8int *ct, u8int *ss, const u8int *pk, u8int *coins);
int mlk_kem_dec_x(int level, u8int *ss, const u8int *ct, const u8int *sk);

#include "mlkem_native.h"

char*
slurp(char *file)
{
	char *p;
	int n, r, sz;
	int fd;

	n = 0;
	sz = 8192;
	fd = open(file, OREAD);
	if(fd < 0)
		sysfatal("slurp: %r");
	if((p = malloc(sz+1)) == nil)
		abort();
	for(;;){
		if(n == sz){
			sz *= 2;
			if((p = realloc(p, sz+1)) == nil)
				abort();
		}
		r = read(fd, p+n, sz-n);
		if(r < 0)
			sysfatal("slurp: %r");
		if(r == 0)
			break;
		n += r;
	}
	p[n] = 0;
	return p;
}

static char *tab[] = {
	[K512] "512",
	[K768] "768",
	[K1024] "1024",
};

static void
keygen(int lvl, int pksz, int sksz)
{
	char *data;
	JSON *top, *p;
	JSONEl *e, *t;

	uchar seed[2 * MLKEM_SYMBYTES];
	uchar ek[MLKEM1024_PUBLICKEYBYTES], ekout[MLKEM1024_PUBLICKEYBYTES];
	uchar dk[MLKEM1024_SECRETKEYBYTES], dkout[MLKEM1024_SECRETKEYBYTES];

	data = slurp(smprint("data/mlkem_%s_keygen_seed_test.json", tab[lvl]));
	top = jsonparse(data);
	if(top == nil)
		sysfatal("jsonparse: %r");
	p = jsonbyname(top, "testGroups");
	if(p == nil)
		sysfatal("no testGroups");
	for(t = p->first; t; t = t->next){
		p = jsonbyname(t->val, "tests");
		if(p == nil)
			sysfatal("no tests");
		for(e = p->first; e; e = e->next){
			p = jsonbyname(e->val, "seed");
			assert(dec16(seed, sizeof seed, p->s, strlen(p->s)) == sizeof seed);
			p = jsonbyname(e->val, "ek");
			dec16(ek, sizeof ek, p->s, strlen(p->s));
			p = jsonbyname(e->val, "dk");
			dec16(dk, sizeof dk, p->s, strlen(p->s));
			assert(mlk_kem_keypair_x(lvl, ekout, dkout, seed) == 0);
			if(memcmp(ekout, ek, pksz) != 0)
				sysfatal("ek fail");
			if(memcmp(dkout, dk, sksz) != 0)
				sysfatal("dk fail");
		}
	}
}

static void
assertinvalid(JSON *p)
{
	p = jsonbyname(p, "result");
	assert(p != nil);
	if(strcmp(p->s, "invalid") != 0)
		sysfatal("skipping non invalid test");
}

static void
enc(int lvl, int pksz, int ctsz)
{
	char *data;
	JSON *top, *p;
	JSONEl *e, *t;

	uchar ek[MLKEM1024_PUBLICKEYBYTES + 512];
	uchar m[MLKEM_SYMBYTES];
	uchar ct[MLKEM1024_CIPHERTEXTBYTES], ctout[MLKEM1024_CIPHERTEXTBYTES];
	uchar ss[MLKEM_BYTES], ssout[MLKEM_BYTES];

	data = slurp(smprint("data/mlkem_%s_encaps_test.json", tab[lvl]));
	top = jsonparse(data);
	if(top == nil)
		sysfatal("jsonparse: %r");
	p = jsonbyname(top, "testGroups");
	if(p == nil)
		sysfatal("no testGroups");

	for(t = p->first; t; t = t->next){
		p = jsonbyname(t->val, "tests");
		if(p == nil)
			sysfatal("no tests");
		for(e = p->first; e; e = e->next){
			p = jsonbyname(e->val, "m");
			assert(dec16(m, sizeof m, p->s, strlen(p->s)) == sizeof m);
			p = jsonbyname(e->val, "ek");
			if(dec16(ek, sizeof ek, p->s, strlen(p->s)) != pksz){
				assertinvalid(e->val);
				continue;
			}
			p = jsonbyname(e->val, "c");
			dec16(ct, sizeof ct, p->s, strlen(p->s));
			p = jsonbyname(e->val, "K");
			dec16(ss, sizeof ss, p->s, strlen(p->s));
			p = jsonbyname(e->val, "result");
			if(strcmp(p->s, "invalid") == 0)
				assert(mlk_kem_enc_x(lvl, ctout, ssout, ek, m) != 0);
			else if(strcmp(p->s, "valid") == 0) {
				assert(mlk_kem_enc_x(lvl, ctout, ssout, ek, m) == 0);
				if(memcmp(ctout, ct, ctsz) != 0)
					sysfatal("enc ct fail");
				if(memcmp(ssout, ss, sizeof ss) != 0)
					sysfatal("ss fail");
			} else
				sysfatal("unknown result: %s", p->s);
		}
	}
}

static void
dec(int lvl, int sksz, int ctsz)
{
	char *data;
	JSON *top, *p;
	JSONEl *e, *t;

	uchar dk[MLKEM1024_SECRETKEYBYTES + 512];
	uchar c[MLKEM1024_CIPHERTEXTBYTES + 512];
	uchar ss[MLKEM_BYTES], ssout[MLKEM_BYTES];


	data = slurp(smprint("data/mlkem_%s_semi_expanded_decaps_test.json", tab[lvl]));
	top = jsonparse(data);
	if(top == nil)
		sysfatal("jsonparse: %r");
	p = jsonbyname(top, "testGroups");
	if(p == nil)
		sysfatal("no testGroups");

	for(t = p->first; t; t = t->next){
		p = jsonbyname(t->val, "tests");
		if(p == nil)
			sysfatal("no tests");
		for(e = p->first; e; e = e->next){
			p = jsonbyname(e->val, "c");
			if(dec16(c, sizeof c, p->s, strlen(p->s)) != ctsz){
				assertinvalid(e->val);
				continue;
			}
			p = jsonbyname(e->val, "dk");
			if(dec16(dk, sizeof dk, p->s, strlen(p->s)) != sksz){
				assertinvalid(e->val);
				continue;
			}
			p = jsonbyname(e->val, "result");
			if(strcmp(p->s, "invalid") == 0){
				assert(mlk_kem_dec_x(lvl, ssout, c, dk) != 0);
			} else if(strcmp(p->s, "valid") == 0) {
				p = jsonbyname(e->val, "K");
				dec16(ss, sizeof ss, p->s, strlen(p->s));
				assert(mlk_kem_dec_x(lvl, ssout, c, dk) == 0);
				if(memcmp(ssout, ss, sizeof ss) != 0)
					sysfatal("ss fail");
			} else
				sysfatal("unknown result: %s", p->s);
		}
	}
}

static void
test(int lvl, int pksz, int ctsz)
{
	char *data;
	JSON *top, *p;
	JSONEl *e, *t;

	uchar seed[2 * MLKEM_SYMBYTES + 128];
	uchar ek[MLKEM1024_PUBLICKEYBYTES], ekout[MLKEM1024_PUBLICKEYBYTES];
	uchar dk[MLKEM1024_SECRETKEYBYTES];
	uchar ct[MLKEM1024_CIPHERTEXTBYTES + 512];
	uchar ss[MLKEM_BYTES], ssout[MLKEM_BYTES];

	data = slurp(smprint("data/mlkem_%s_test.json", tab[lvl]));
	top = jsonparse(data);
	if(top == nil)
		sysfatal("jsonparse: %r");
	p = jsonbyname(top, "testGroups");
	if(p == nil)
		sysfatal("no testGroups");

	for(t = p->first; t; t = t->next){
		p = jsonbyname(t->val, "tests");
		if(p == nil)
			sysfatal("no tests");
		for(e = p->first; e; e = e->next){
			p = jsonbyname(e->val, "seed");
			assert(p != nil);
			if(dec16(seed, sizeof seed, p->s, strlen(p->s)) != 2 * MLKEM_SYMBYTES){
				assertinvalid(e->val);
				continue;
			}
			p = jsonbyname(e->val, "ek");
			if(dec16(ek, sizeof ek, p->s, strlen(p->s)) != pksz){
				assertinvalid(e->val);
				continue;
			}
			assert(mlk_kem_keypair_x(lvl, ekout, dk, seed) == 0);
			if(memcmp(ek, ekout, pksz) != 0)
				sysfatal("ek mistmatch");

			p = jsonbyname(e->val, "c");
			if(dec16(ct, sizeof ct, p->s, strlen(p->s)) != ctsz){
				assertinvalid(e->val);
				continue;
			}
			p = jsonbyname(e->val, "K");
			dec16(ss, sizeof ss, p->s, strlen(p->s));
			p = jsonbyname(e->val, "result");
			if(strcmp(p->s, "invalid") == 0){
				assert(mlk_kem_dec_x(lvl, ssout, ct, dk) != 0);
			} else if(strcmp(p->s, "valid") == 0) {
				p = jsonbyname(e->val, "K");
				dec16(ss, sizeof ss, p->s, strlen(p->s));
				assert(mlk_kem_dec_x(lvl, ssout, ct, dk) == 0);
				if(memcmp(ssout, ss, sizeof ss) != 0)
					sysfatal("ss fail");
			} else
				sysfatal("unknown result: %s", p->s);
		}
	}
}

void
main(int,char**)
{
	JSONfmtinstall();
	fmtinstall('H', encodefmt);
	keygen(K512, MLKEM512_PUBLICKEYBYTES, MLKEM512_SECRETKEYBYTES);
	keygen(K768, MLKEM768_PUBLICKEYBYTES, MLKEM768_SECRETKEYBYTES);
	keygen(K1024, MLKEM1024_PUBLICKEYBYTES, MLKEM1024_SECRETKEYBYTES);
	enc(K512, MLKEM512_PUBLICKEYBYTES, MLKEM512_CIPHERTEXTBYTES);
	enc(K768, MLKEM768_PUBLICKEYBYTES, MLKEM768_CIPHERTEXTBYTES);
	enc(K1024, MLKEM1024_PUBLICKEYBYTES, MLKEM1024_CIPHERTEXTBYTES);
	dec(K512, MLKEM512_SECRETKEYBYTES, MLKEM512_CIPHERTEXTBYTES);
	dec(K768, MLKEM768_SECRETKEYBYTES, MLKEM768_CIPHERTEXTBYTES);
	dec(K1024, MLKEM1024_SECRETKEYBYTES, MLKEM1024_CIPHERTEXTBYTES);
	test(K512, MLKEM512_PUBLICKEYBYTES, MLKEM512_CIPHERTEXTBYTES);
	test(K768, MLKEM768_PUBLICKEYBYTES, MLKEM768_CIPHERTEXTBYTES);
	test(K1024, MLKEM1024_PUBLICKEYBYTES, MLKEM1024_CIPHERTEXTBYTES);
	exits(nil);
}
