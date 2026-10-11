/* Equivalence tests for the batched paths used by dpdk_forward:
 *
 *   - ab_derive_aes128_keys_and_L_x4/_x8 against the per-packet reference
 *     CBCMAC(master, input) -> ExpandKey128 -> L = AES_K(0), using the
 *     assembly routines (independent of the batched key schedule).
 *   - pmac1_aes128_with_L_x4/_x8 against single pmac1_aes128_with_L calls,
 *     with independent keys and mixed lengths in every batch.
 *   - pmac1_aes128_with_L against the sequential reference pmac1_aes128_seq
 *     for every length 0..2100.
 *
 * The GF doubling itself is covered independently by pmac1_kat (vectors
 * from OpenSSL + a Python reference). Run by `make test`. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../aesni.h"
#include "../pmac1.h"

static uint64_t rng = 0x9E3779B97F4A7C15ull;

static uint64_t
xr(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return rng;
}

static void
fill(unsigned char *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		p[i] = (unsigned char)xr();
}

static int fails;

static void
fail(const char *what, int iter, int lane, size_t len)
{
	if (fails < 10)
		printf("FAIL  %s iter=%d lane=%d len=%zu\n", what, iter, lane, len);
	fails++;
}

static void
test_derive(int n, int iters)
{
	unsigned char key[16];
	static unsigned char master[8][176] __attribute__((aligned(16)));

	for (int iter = 0; iter < iters; iter++) {
		const void *mrks[8];
		unsigned char in[8][16] __attribute__((aligned(16)));
		unsigned char out[8][176], L[8][16];
		unsigned char *outs[8];
		for (int k = 0; k < n; k++) {
			if (iter % 64 == 0) {
				fill(key, 16);
				ExpandKey128(key, master[k]);
			}
			mrks[k] = master[k];
			fill(in[k], 16);
			outs[k] = out[k];
		}
		if (n == 8)
			ab_derive_aes128_keys_and_L_x8(mrks, in, outs, L);
		else
			ab_derive_aes128_keys_and_L_x4(mrks, in, outs, L);
		for (int k = 0; k < n; k++) {
			unsigned char dk[16], rk[176] __attribute__((aligned(16)));
			unsigned char zero[16] = { 0 }, refL[16];
			CBCMAC(master[k], 1, in[k], dk);
			ExpandKey128(dk, rk);
			CBCMAC(rk, 1, zero, refL);
			if (memcmp(rk, out[k], 176) || memcmp(refL, L[k], 16))
				fail(n == 8 ? "derive x8" : "derive x4", iter, k, 16);
		}
	}
}

static void
test_pmac_batch(int n, int iters)
{
	static unsigned char msg[8][2200];
	static unsigned char rk[8][176] __attribute__((aligned(16)));
	static unsigned char L[8][16];
	unsigned char key[16], zero[16] = { 0 };

	for (int iter = 0; iter < iters; iter++) {
		const void *rks[8];
		const unsigned char *msgs[8];
		size_t lens[8];
		unsigned char tags[8][16], t1[16];
		size_t uniform = xr() % 300;
		for (int k = 0; k < n; k++) {
			if (iter % 32 == 0) {
				fill(key, 16);
				ExpandKey128(key, rk[k]);
				CBCMAC(rk[k], 1, zero, L[k]);
			}
			/* Uniform small batches (the validator's common case), small
			 * mixed lengths, and anything up to 2100 B. */
			switch (iter % 3) {
			case 0: lens[k] = uniform; break;
			case 1: lens[k] = 64 + xr() % 200; break;
			default: lens[k] = xr() % 2101; break;
			}
			fill(msg[k], lens[k]);
			rks[k] = rk[k];
			msgs[k] = msg[k];
		}
		if (n == 8)
			pmac1_aes128_with_L_x8(rks, (const unsigned char (*)[16])L, msgs, lens, tags);
		else
			pmac1_aes128_with_L_x4(rks, (const unsigned char (*)[16])L, msgs, lens, tags);
		for (int k = 0; k < n; k++) {
			pmac1_aes128_with_L(rk[k], L[k], msg[k], lens[k], t1);
			if (memcmp(t1, tags[k], 16))
				fail(n == 8 ? "pmac x8" : "pmac x4", iter, k, lens[k]);
		}
	}
}

static void
test_pmac_single(void)
{
	static unsigned char msg[2200];
	unsigned char key[16], rk[176] __attribute__((aligned(16)));
	unsigned char zero[16] = { 0 }, L[16];

	for (int kk = 0; kk < 16; kk++) {
		fill(key, 16);
		ExpandKey128(key, rk);
		CBCMAC(rk, 1, zero, L);
		for (size_t len = 0; len <= 2100; len++) {
			unsigned char ref[16], got[16];
			fill(msg, len);
			pmac1_aes128_seq(rk, msg, len, ref);
			pmac1_aes128_with_L(rk, L, msg, len, got);
			if (memcmp(ref, got, 16))
				fail("pmac single vs seq", kk, 0, len);
		}
	}
}

int
main(void)
{
	test_derive(4, 20000);
	test_derive(8, 20000);
	test_pmac_batch(4, 30000);
	test_pmac_batch(8, 30000);
	test_pmac_single();
	printf("%s  batched derive/PMAC equivalence (%d mismatches)\n",
	       fails ? "FAIL" : "PASS", fails);
	return fails != 0;
}
