/* PMAC1 (Rogaway) under AES-128, using AES-NI intrinsics.
 *
 * Two paths:
 *   - pmac1_aes128 / pmac1_aes128_seq: one-shot API; recomputes L, L_inv,
 *     and the L-doubling table every call.
 *   - pmac1_keysetup / pmac1_aes128_ctx: precomputed-context API; expensive
 *     bits run once per key, not per message.
 *
 * SIMD is restricted to SSE/SSSE3/SSE4.1 + AES-NI. No AVX/AVX2/VAES. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>
#include <tmmintrin.h>
#include <smmintrin.h>

#include "pmac1.h"

#define PMAC1_ATTR __attribute__((target("aes,ssse3,sse4.1")))

PMAC1_ATTR static inline __m128i
bswap128(__m128i v)
{
	const __m128i mask = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
			4, 3, 2, 1, 0);
	return _mm_shuffle_epi8(v, mask);
}

PMAC1_ATTR static inline __m128i
double_block(__m128i v)
{
	__m128i x = bswap128(v);
	__m128i hi = _mm_srli_epi64(x, 63);
	__m128i shifted = _mm_slli_epi64(x, 1);
	__m128i carry = _mm_slli_si128(hi, 8);
	shifted = _mm_or_si128(shifted, carry);
	int64_t msb = _mm_extract_epi64(hi, 1);
	if (msb) {
		const __m128i poly = _mm_setr_epi8(
				0x87, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
		shifted = _mm_xor_si128(shifted, poly);
	}
	return bswap128(shifted);
}

PMAC1_ATTR static inline __m128i
half_block(__m128i v)
{
	__m128i x = bswap128(v);
	int lsb = _mm_extract_epi8(x, 0) & 1;
	__m128i lo = _mm_slli_epi64(x, 63);
	__m128i shifted = _mm_srli_epi64(x, 1);
	__m128i borrow = _mm_srli_si128(lo, 8);
	shifted = _mm_or_si128(shifted, borrow);
	if (lsb) {
		const __m128i fix = _mm_setr_epi8(0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, (char)0x80);
		shifted = _mm_xor_si128(shifted, fix);
	}
	return bswap128(shifted);
}

PMAC1_ATTR static inline __m128i
aes128_encrypt(const __m128i *rk, __m128i x)
{
	x = _mm_xor_si128(x, rk[0]);
	x = _mm_aesenc_si128(x, rk[1]);
	x = _mm_aesenc_si128(x, rk[2]);
	x = _mm_aesenc_si128(x, rk[3]);
	x = _mm_aesenc_si128(x, rk[4]);
	x = _mm_aesenc_si128(x, rk[5]);
	x = _mm_aesenc_si128(x, rk[6]);
	x = _mm_aesenc_si128(x, rk[7]);
	x = _mm_aesenc_si128(x, rk[8]);
	x = _mm_aesenc_si128(x, rk[9]);
	return _mm_aesenclast_si128(x, rk[10]);
}

static inline void
segment(size_t msg_bytes, size_t *m_full_out, size_t *m_out, int *last_full_out)
{
	size_t m_full = msg_bytes / 16;
	int last_full = (msg_bytes > 0) && (msg_bytes % 16 == 0);
	size_t m;
	if (msg_bytes == 0) m = 1;
	else if (last_full) m = m_full;
	else m = m_full + 1;
	*m_full_out = m_full;
	*m_out = m;
	*last_full_out = last_full;
}

PMAC1_ATTR void
pmac1_keysetup(const void *roundkey, pmac1_ctx *ctx)
{
	const __m128i *rk_in = (const __m128i *)roundkey;
	__m128i rk[11];
	for (int i = 0; i < 11; i++) {
		rk[i] = _mm_loadu_si128(&rk_in[i]);
		_mm_store_si128((__m128i *)(ctx->rk + i * 16), rk[i]);
	}
	__m128i L = aes128_encrypt(rk, _mm_setzero_si128());
	__m128i Linv = half_block(L);
	_mm_store_si128((__m128i *)ctx->L, L);
	_mm_store_si128((__m128i *)ctx->L_inv, Linv);
	__m128i Lj = L;
	_mm_store_si128((__m128i *)(ctx->Ltab + 0 * 16), Lj);
	for (int j = 1; j < 24; j++) {
		Lj = double_block(Lj);
		_mm_store_si128((__m128i *)(ctx->Ltab + j * 16), Lj);
	}
}

PMAC1_ATTR void
pmac1_aes128_seq(const void *roundkey, const unsigned char *msg,
		size_t msg_bytes, unsigned char tag[16])
{
	const __m128i *rk = (const __m128i *)roundkey;
	__m128i L = aes128_encrypt(rk, _mm_setzero_si128());
	__m128i L_inv = half_block(L);

	size_t m_full, m;
	int last_full;
	segment(msg_bytes, &m_full, &m, &last_full);

	__m128i Sum = _mm_setzero_si128();
	__m128i Delta = _mm_setzero_si128();

	for (size_t i = 1; i + 1 <= m; i++) {
		int j = __builtin_ctzll((unsigned long long)i);
		__m128i Lj = L;
		for (int k = 0; k < j; k++) Lj = double_block(Lj);
		Delta = _mm_xor_si128(Delta, Lj);
		__m128i Mi = _mm_loadu_si128(
				(const __m128i *)(msg + (i - 1) * 16));
		__m128i x = _mm_xor_si128(Mi, Delta);
		Sum = _mm_xor_si128(Sum, aes128_encrypt(rk, x));
	}

	__m128i final_in;
	if (last_full) {
		__m128i Mm = _mm_loadu_si128(
				(const __m128i *)(msg + (m - 1) * 16));
		final_in = _mm_xor_si128(_mm_xor_si128(Sum, Mm), L_inv);
	} else {
		unsigned char buf[16] = { 0 };
		size_t off = m_full * 16;
		size_t rem = msg_bytes - off;
		if (rem) memcpy(buf, msg + off, rem);
		buf[rem] = 0x80;
		__m128i Mm = _mm_loadu_si128((const __m128i *)buf);
		final_in = _mm_xor_si128(Sum, Mm);
	}
	_mm_storeu_si128((__m128i *)tag, aes128_encrypt(rk, final_in));
}

/* Core implementation, parameterized over precomputed inputs. The compiler
 * inlines this into both the one-shot and ctx wrappers. */
PMAC1_ATTR static inline void
pmac1_core(const __m128i *rk, __m128i Linv, const __m128i *Ltab, int ltab_max,
		const unsigned char *msg, size_t msg_bytes, unsigned char tag[16])
{
	size_t m_full, m;
	int last_full;
	segment(msg_bytes, &m_full, &m, &last_full);

	__m128i Sum = _mm_setzero_si128();
	__m128i Delta = _mm_setzero_si128();

	/* Number of auxiliary blocks (i = 1..m-1). */
	size_t naux = (m == 0) ? 0 : m - 1;

	/* Bulk loop: 4 auxiliary blocks per iteration. */
	size_t i = 1;
	while (i + 3 <= naux) {
		int j0 = __builtin_ctzll((unsigned long long)(i + 0));
		int j1 = __builtin_ctzll((unsigned long long)(i + 1));
		int j2 = __builtin_ctzll((unsigned long long)(i + 2));
		int j3 = __builtin_ctzll((unsigned long long)(i + 3));
		(void)ltab_max;

		__m128i d0 = _mm_xor_si128(Delta, Ltab[j0]);
		__m128i d1 = _mm_xor_si128(d0, Ltab[j1]);
		__m128i d2 = _mm_xor_si128(d1, Ltab[j2]);
		__m128i d3 = _mm_xor_si128(d2, Ltab[j3]);
		Delta = d3;

		const unsigned char *p = msg + (i - 1) * 16;
		__m128i m0 = _mm_loadu_si128((const __m128i *)(p + 0));
		__m128i m1 = _mm_loadu_si128((const __m128i *)(p + 16));
		__m128i m2 = _mm_loadu_si128((const __m128i *)(p + 32));
		__m128i m3 = _mm_loadu_si128((const __m128i *)(p + 48));

		__m128i x0 = _mm_xor_si128(_mm_xor_si128(m0, d0), rk[0]);
		__m128i x1 = _mm_xor_si128(_mm_xor_si128(m1, d1), rk[0]);
		__m128i x2 = _mm_xor_si128(_mm_xor_si128(m2, d2), rk[0]);
		__m128i x3 = _mm_xor_si128(_mm_xor_si128(m3, d3), rk[0]);

#define R(rn)                                          \
	x0 = _mm_aesenc_si128(x0, rk[rn]);                \
	x1 = _mm_aesenc_si128(x1, rk[rn]);                \
	x2 = _mm_aesenc_si128(x2, rk[rn]);                \
	x3 = _mm_aesenc_si128(x3, rk[rn])
		R(1); R(2); R(3); R(4); R(5); R(6); R(7); R(8); R(9);
#undef R
		x0 = _mm_aesenclast_si128(x0, rk[10]);
		x1 = _mm_aesenclast_si128(x1, rk[10]);
		x2 = _mm_aesenclast_si128(x2, rk[10]);
		x3 = _mm_aesenclast_si128(x3, rk[10]);

		Sum = _mm_xor_si128(Sum,
				_mm_xor_si128(_mm_xor_si128(x0, x1), _mm_xor_si128(x2, x3)));
		i += 4;
	}

	/* Trailing auxiliary blocks: 0..3. Issue exactly that many aesenc
	 * chains so we don't waste throughput on dummy lanes. */
	size_t left = (naux >= i) ? (naux - i + 1) : 0;
#define LOAD_TRAIL(k)                                                          \
	int j##k = __builtin_ctzll((unsigned long long)(i + (k)));                \
	Delta = _mm_xor_si128(Delta, Ltab[j##k]);                                 \
	__m128i d##k = Delta;                                                     \
	__m128i mi##k = _mm_loadu_si128(                                          \
			(const __m128i *)(msg + (i + (k) - 1) * 16));                     \
	__m128i x##k = _mm_xor_si128(_mm_xor_si128(mi##k, d##k), rk[0])
	if (left == 1) {
		LOAD_TRAIL(0);
		x0 = _mm_aesenc_si128(x0, rk[1]);
		x0 = _mm_aesenc_si128(x0, rk[2]);
		x0 = _mm_aesenc_si128(x0, rk[3]);
		x0 = _mm_aesenc_si128(x0, rk[4]);
		x0 = _mm_aesenc_si128(x0, rk[5]);
		x0 = _mm_aesenc_si128(x0, rk[6]);
		x0 = _mm_aesenc_si128(x0, rk[7]);
		x0 = _mm_aesenc_si128(x0, rk[8]);
		x0 = _mm_aesenc_si128(x0, rk[9]);
		x0 = _mm_aesenclast_si128(x0, rk[10]);
		Sum = _mm_xor_si128(Sum, x0);
	} else if (left == 2) {
		LOAD_TRAIL(0);
		LOAD_TRAIL(1);
#define R2(rn)                                                                 \
	x0 = _mm_aesenc_si128(x0, rk[rn]);                                        \
	x1 = _mm_aesenc_si128(x1, rk[rn])
		R2(1); R2(2); R2(3); R2(4); R2(5); R2(6); R2(7); R2(8); R2(9);
#undef R2
		x0 = _mm_aesenclast_si128(x0, rk[10]);
		x1 = _mm_aesenclast_si128(x1, rk[10]);
		Sum = _mm_xor_si128(Sum, _mm_xor_si128(x0, x1));
	} else if (left == 3) {
		LOAD_TRAIL(0);
		LOAD_TRAIL(1);
		LOAD_TRAIL(2);
#define R3(rn)                                                                 \
	x0 = _mm_aesenc_si128(x0, rk[rn]);                                        \
	x1 = _mm_aesenc_si128(x1, rk[rn]);                                        \
	x2 = _mm_aesenc_si128(x2, rk[rn])
		R3(1); R3(2); R3(3); R3(4); R3(5); R3(6); R3(7); R3(8); R3(9);
#undef R3
		x0 = _mm_aesenclast_si128(x0, rk[10]);
		x1 = _mm_aesenclast_si128(x1, rk[10]);
		x2 = _mm_aesenclast_si128(x2, rk[10]);
		Sum = _mm_xor_si128(Sum,
				_mm_xor_si128(_mm_xor_si128(x0, x1), x2));
	}
#undef LOAD_TRAIL

	/* Final block. */
	__m128i final_in;
	if (last_full) {
		__m128i Mm = _mm_loadu_si128(
				(const __m128i *)(msg + (m - 1) * 16));
		final_in = _mm_xor_si128(_mm_xor_si128(Sum, Mm), Linv);
	} else {
		unsigned char buf[16] = { 0 };
		size_t off = m_full * 16;
		size_t rem = msg_bytes - off;
		if (rem) memcpy(buf, msg + off, rem);
		buf[rem] = 0x80;
		__m128i Mm = _mm_loadu_si128((const __m128i *)buf);
		final_in = _mm_xor_si128(Sum, Mm);
	}
	_mm_storeu_si128((__m128i *)tag, aes128_encrypt(rk, final_in));
}

PMAC1_ATTR void
pmac1_aes128_ctx(const pmac1_ctx *ctx, const unsigned char *msg,
		size_t msg_bytes, unsigned char tag[16])
{
	const __m128i *rk = (const __m128i *)ctx->rk;
	__m128i Linv = _mm_load_si128((const __m128i *)ctx->L_inv);
	const __m128i *Ltab = (const __m128i *)ctx->Ltab;
	pmac1_core(rk, Linv, Ltab, 23, msg, msg_bytes, tag);
}

/* Drop-in replacement for the legacy asm PMAC symbol. Same signature; calls
 * the real PMAC1 internally. Per-call cost includes deriving L, L_inv, and
 * the doubling table; protocols that mac many messages under one key should
 * migrate to pmac1_keysetup + pmac1_aes128_ctx instead. */
PMAC1_ATTR void
PMAC(const void *roundkey, int numblk, unsigned char *plain,
		unsigned char *mac)
{
	size_t bytes = (numblk > 0) ? (size_t)numblk * 16 : 0;
	pmac1_aes128(roundkey, plain, bytes, mac);
}

PMAC1_ATTR void
pmac1_aes128(const void *roundkey, const unsigned char *msg, size_t msg_bytes,
		unsigned char tag[16])
{
	const __m128i *rk = (const __m128i *)roundkey;
	__m128i L = aes128_encrypt(rk, _mm_setzero_si128());
	__m128i Linv = half_block(L);
	__m128i Ltab[24];
	Ltab[0] = L;
	/* Only precompute as many doublings as the message will actually use:
	 * max ntz over 1..m-1 is at most floor(log2(m-1)). */
	size_t blocks_for_aux;
	if (msg_bytes == 0) blocks_for_aux = 0;
	else if (msg_bytes % 16 == 0) blocks_for_aux = msg_bytes / 16 - 1;
	else blocks_for_aux = msg_bytes / 16;
	int needed = 0;
	while (((size_t)1 << needed) <= blocks_for_aux) needed++;
	if (needed > 23) needed = 23;
	for (int j = 1; j <= needed; j++) Ltab[j] = double_block(Ltab[j - 1]);
	pmac1_core(rk, Linv, Ltab, needed, msg, msg_bytes, tag);
}
