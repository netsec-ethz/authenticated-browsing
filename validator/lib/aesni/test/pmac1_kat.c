/* Known-answer tests for PMAC1, derived independently:
 *  - AES primitive: openssl's libcrypto AES-128 (separate codebase from
 *    this project's AES-NI asm).
 *  - PMAC1 algorithm: a textbook Python reference (test/pmac1_ref.py) that
 *    implements GF(2^128) doublings + offset Gray-code chain in pure
 *    Python, using openssl for AES.
 *  - Test vectors: the PMAC-AES-128 KATs provided by Black/Rogaway/Krovetz
 *
 * If our AES-NI / SSE implementation agrees with these tags across single-
 * block, partial, multi-block-bulk, and the actual benchmark sizes, then
 * the byte/bit conventions, doubling, halving, and offset recurrence are
 * all correct. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../aesni.h"
#include "../pmac1.h"

static void *
xmalloc_aligned(size_t a, size_t n)
{
	void *p = NULL;
	if (posix_memalign(&p, a, n) != 0) {
		fprintf(stderr, "alloc fail\n");
		exit(1);
	}
	return p;
}

static int
hex_eq(const unsigned char *a, const char *hex)
{
	for (int i = 0; i < 16; i++) {
		unsigned int x;
		if (sscanf(hex + 2 * i, "%2x", &x) != 1) return 0;
		if (a[i] != (unsigned char)x) return 0;
	}
	return 1;
}

static void
print_hex(const unsigned char *a)
{
	for (int i = 0; i < 16; i++) printf("%02x", a[i]);
}

static int g_failures;

static void
check(const char *label, const unsigned char *got, const char *expected)
{
	if (hex_eq(got, expected)) {
		printf("PASS  %-30s  ", label);
		print_hex(got);
		printf("\n");
	} else {
		printf("FAIL  %-30s\n", label);
		printf("        got:      ");
		print_hex(got);
		printf("\n        expected: %s\n", expected);
		g_failures++;
	}
}

int
main(void)
{
	unsigned char zero_key[16] = { 0 };
	unsigned char *rk = xmalloc_aligned(16, 11 * 16);
	memset(rk, 0, 11 * 16);
	ExpandKey128(zero_key, rk);

	pmac1_ctx *ctx = xmalloc_aligned(16, sizeof(pmac1_ctx));
	pmac1_keysetup(rk, ctx);

	/* Author-provided test vectors (Black/Rogaway/Krovetz, PMAC-AES-128).
	 * These are the canonical reference KATs. */
	unsigned char author_key[16];
	for (int i = 0; i < 16; i++) author_key[i] = (unsigned char)i;
	unsigned char *author_rk = xmalloc_aligned(16, 11 * 16);
	memset(author_rk, 0, 11 * 16);
	ExpandKey128(author_key, author_rk);
	pmac1_ctx *author_ctx = xmalloc_aligned(16, sizeof(pmac1_ctx));
	pmac1_keysetup(author_rk, author_ctx);

	unsigned char tag[16];

	/* PMAC-AES-128 author vectors (key = 00..0f). */
	{
		pmac1_aes128(author_rk, NULL, 0, tag);
		check("[author] empty (0B)", tag,
				"4399572cd6ea5341b8d35876a7098af7");

		unsigned char m3[3] = { 0x00, 0x01, 0x02 };
		pmac1_aes128(author_rk, m3, sizeof(m3), tag);
		check("[author] 3B", tag,
				"256ba5193c1b991b4df0c51f388a9e27");

		unsigned char m16[16];
		for (int i = 0; i < 16; i++) m16[i] = (unsigned char)i;
		pmac1_aes128(author_rk, m16, sizeof(m16), tag);
		check("[author] 16B", tag,
				"ebbd822fa458daf6dfdad7c27da76338");

		unsigned char m20[20];
		for (int i = 0; i < 20; i++) m20[i] = (unsigned char)i;
		pmac1_aes128(author_rk, m20, sizeof(m20), tag);
		check("[author] 20B", tag,
				"0412ca150bbf79058d8c75a58c993f55");

		unsigned char m32[32];
		for (int i = 0; i < 32; i++) m32[i] = (unsigned char)i;
		pmac1_aes128(author_rk, m32, sizeof(m32), tag);
		check("[author] 32B", tag,
				"e97ac04e9e5e3399ce5355cd7407bc75");

		unsigned char m34[34];
		for (int i = 0; i < 34; i++) m34[i] = (unsigned char)i;
		pmac1_aes128(author_rk, m34, sizeof(m34), tag);
		check("[author] 34B", tag,
				"5cba7d5eb24f7c86ccc54604e53d5512");

		unsigned char *m1000 = xmalloc_aligned(16, 1000);
		memset(m1000, 0, 1000);
		pmac1_aes128(author_rk, m1000, 1000, tag);
		check("[author] 1000B zeros", tag,
				"c2c9fa1d9985f6f0d2aff915a0e8d910");
		pmac1_aes128_ctx(author_ctx, m1000, 1000, tag);
		check("[author] 1000B zeros (ctx)", tag,
				"c2c9fa1d9985f6f0d2aff915a0e8d910");
		free(m1000);
	}

	/* Test 1: 1 full block, M = 0xff..ff. Derived from openssl + hand-
	 * computed L_inv; equals AES_0(M XOR L_inv). */
	{
		unsigned char M[16];
		memset(M, 0xff, 16);
		pmac1_aes128(rk, M, sizeof(M), tag);
		check("1-block full M=ff..ff", tag,
				"b2395edb4d4df5519fc3e1b0f4bf2571");
		pmac1_aes128_ctx(ctx, M, sizeof(M), tag);
		check("1-block full (ctx)", tag,
				"b2395edb4d4df5519fc3e1b0f4bf2571");
	}

	/* Test 2: 2 full blocks of zero. Σ = AES_0(L); T = AES_0(Σ XOR L_inv). */
	{
		unsigned char M[32] = { 0 };
		pmac1_aes128(rk, M, sizeof(M), tag);
		check("2-block full M=0..0", tag,
				"178f2974ba5fa21f3dc598bec10207e4");
	}

	/* Test 3: 5-byte partial "Hello". Σ=0; T = AES_0(pad("Hello")). */
	{
		const unsigned char M[] = { 'H', 'e', 'l', 'l', 'o' };
		pmac1_aes128(rk, M, sizeof(M), tag);
		check("5-byte partial \"Hello\"", tag,
				"a30bc83db8a2816e77e6bda00ffa36e6");
	}

	/* Tests 4–7: derived via the Python reference impl (openssl AES +
	 * textbook GF math). M[i] = i & 0xff for byte-counter patterns. */
	{
		unsigned char M[5 * 16];
		for (size_t i = 0; i < sizeof(M); i++) M[i] = (unsigned char)i;
		pmac1_aes128(rk, M, sizeof(M), tag);
		check("5-block (80B) i&0xff", tag,
				"1fe845b2a8edca65c3c571cb6fe9af00");
	}
	{
		unsigned char M[16 * 16];
		for (size_t i = 0; i < sizeof(M); i++) M[i] = (unsigned char)i;
		pmac1_aes128(rk, M, sizeof(M), tag);
		check("16-block (256B) i&0xff", tag,
				"70592bf8461525a6b0ec7f89adceab14");
		pmac1_aes128_ctx(ctx, M, sizeof(M), tag);
		check("16-block (256B) i&0xff ctx", tag,
				"70592bf8461525a6b0ec7f89adceab14");
		/* Drop-in: legacy PMAC(rk, numblk, plain, mac) signature must
		 * produce the same tag for full-block input. */
		PMAC(rk, 16, M, tag);
		check("16-block via legacy PMAC sig", tag,
				"70592bf8461525a6b0ec7f89adceab14");
	}
	{
		unsigned char M[17];
		for (size_t i = 0; i < sizeof(M); i++) M[i] = (unsigned char)i;
		pmac1_aes128(rk, M, sizeof(M), tag);
		check("17-byte (1full+partial)", tag,
				"621572c7043582162150abf28dfe539f");
	}
	{
		unsigned char M[1500];
		for (size_t i = 0; i < sizeof(M); i++) M[i] = (unsigned char)((i * 31) & 0xff);
		pmac1_aes128(rk, M, sizeof(M), tag);
		check("1500B benchmark pattern", tag,
				"942cc98c6fff8ffb89a354351baddc18");
		pmac1_aes128_ctx(ctx, M, sizeof(M), tag);
		check("1500B benchmark pattern ctx", tag,
				"942cc98c6fff8ffb89a354351baddc18");
	}

	free(author_ctx);
	free(author_rk);
	free(ctx);
	free(rk);
	return g_failures ? 1 : 0;
}
