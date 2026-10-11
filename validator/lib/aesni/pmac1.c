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

/* GF(2^128) doubling (L * x) and halving (L * x^{-1}), branchless. The
 * conditional reduction depends on a bit of L, a uniformly random AES output,
 * so a branch would mispredict about half the time (~2 mispredicts per
 * packet in the validator's per-packet table setup). The bit is instead
 * broadcast into a mask (sign of the top dword for doubling, bit 0 for
 * halving) and ANDed into the reduction constant. */
PMAC1_ATTR static inline __m128i
double_block(__m128i v)
{
	const __m128i poly = _mm_setr_epi32(0x87, 0, 0, 0);
	__m128i x = bswap128(v);
	__m128i carry = _mm_slli_si128(_mm_srli_epi64(x, 63), 8);
	__m128i shifted = _mm_or_si128(_mm_slli_epi64(x, 1), carry);
	__m128i msb = _mm_shuffle_epi32(_mm_srai_epi32(x, 31), 0xFF);
	return bswap128(_mm_xor_si128(shifted, _mm_and_si128(poly, msb)));
}

PMAC1_ATTR static inline __m128i
half_block(__m128i v)
{
	const __m128i fix = _mm_setr_epi8(0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, (char)0x80);
	__m128i x = bswap128(v);
	__m128i borrow = _mm_srli_si128(_mm_slli_epi64(x, 63), 8);
	__m128i shifted = _mm_or_si128(_mm_srli_epi64(x, 1), borrow);
	__m128i lsb = _mm_shuffle_epi32(
			_mm_srai_epi32(_mm_slli_epi32(x, 31), 31), 0x00);
	return bswap128(_mm_xor_si128(shifted, _mm_and_si128(fix, lsb)));
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

/* Same shape as aes128_encrypt, but expects the caller to have already
 * XORed rk[0] into x. Used for the final-encrypt entry where rk[0] has
 * been folded into the pre-staged final input so the post-bulk critical
 * path is one XOR (Sum ⊕ final_pre) instead of three. */
PMAC1_ATTR static inline __m128i
aes128_encrypt_pre_whitened(const __m128i *rk, __m128i x)
{
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
	(void)ltab_max;
	size_t m_full, m;
	int last_full;
	segment(msg_bytes, &m_full, &m, &last_full);

	/* Fold rk[0] into the running Δ. The per-block prologue then becomes
	 * x = M ⊕ Δ' (one XOR) instead of x = M ⊕ Δ ⊕ rk[0] (two serial
	 * XORs). The fold is preserved across all bulk/trail iterations
	 * because Δ_{i+1} = Δ_i ⊕ Ltab[ntz(i+1)] commutes with the rk[0]
	 * XOR. Δ doesn't feed the final block, so the fold is local to the
	 * aux loop. */
	__m128i rk0 = rk[0];
	__m128i Sum = _mm_setzero_si128();
	__m128i Delta = rk0;

	/* Number of auxiliary blocks (i = 1..m-1). */
	size_t naux = (m == 0) ? 0 : m - 1;

	/* Pre-stage the final-block input: precompute M_m ⊕ L_inv ⊕ rk[0]
	 * (full last) or M_m_padded ⊕ rk[0] (partial last) eagerly, hoisting
	 * the Mm load and these XORs above the bulk loop so the post-bulk
	 * critical path is a single Sum ⊕ final_pre, then aesenc rounds 1..10
	 * via aes128_encrypt_pre_whitened. Saves ~2 cycles on tag entry. */
	__m128i final_pre;
	if (last_full) {
		__m128i Mm = _mm_loadu_si128(
				(const __m128i *)(msg + (m - 1) * 16));
		final_pre = _mm_xor_si128(_mm_xor_si128(Mm, Linv), rk0);
	} else {
		unsigned char buf[16] = { 0 };
		size_t off = m_full * 16;
		size_t rem = msg_bytes - off;
		if (rem) memcpy(buf, msg + off, rem);
		buf[rem] = 0x80;
		__m128i Mm = _mm_loadu_si128((const __m128i *)buf);
		final_pre = _mm_xor_si128(Mm, rk0);
	}

	size_t i = 1;

	/* Bulk loop: 8 auxiliary blocks per iteration. AES-NI on Broadwell has
	 * latency 7 / throughput 1, so 7 dependent chains saturate the AES port.
	 * 8-way uses 16 xmm regs (8 states + the running Delta + a scratch) and
	 * runs the AES port at near 100% utilisation; the previous 4-way only
	 * hit ~57%. We fall through to a 4-way pass and then the 1-3 trail. */
	while (i + 7 <= naux) {
		int j0 = __builtin_ctzll((unsigned long long)(i + 0));
		int j1 = __builtin_ctzll((unsigned long long)(i + 1));
		int j2 = __builtin_ctzll((unsigned long long)(i + 2));
		int j3 = __builtin_ctzll((unsigned long long)(i + 3));
		int j4 = __builtin_ctzll((unsigned long long)(i + 4));
		int j5 = __builtin_ctzll((unsigned long long)(i + 5));
		int j6 = __builtin_ctzll((unsigned long long)(i + 6));
		int j7 = __builtin_ctzll((unsigned long long)(i + 7));

		__m128i d0 = _mm_xor_si128(Delta, Ltab[j0]);
		__m128i d1 = _mm_xor_si128(d0, Ltab[j1]);
		__m128i d2 = _mm_xor_si128(d1, Ltab[j2]);
		__m128i d3 = _mm_xor_si128(d2, Ltab[j3]);
		__m128i d4 = _mm_xor_si128(d3, Ltab[j4]);
		__m128i d5 = _mm_xor_si128(d4, Ltab[j5]);
		__m128i d6 = _mm_xor_si128(d5, Ltab[j6]);
		__m128i d7 = _mm_xor_si128(d6, Ltab[j7]);
		Delta = d7;

		const unsigned char *p = msg + (i - 1) * 16;
		__m128i m0 = _mm_loadu_si128((const __m128i *)(p +   0));
		__m128i m1 = _mm_loadu_si128((const __m128i *)(p +  16));
		__m128i m2 = _mm_loadu_si128((const __m128i *)(p +  32));
		__m128i m3 = _mm_loadu_si128((const __m128i *)(p +  48));
		__m128i m4 = _mm_loadu_si128((const __m128i *)(p +  64));
		__m128i m5 = _mm_loadu_si128((const __m128i *)(p +  80));
		__m128i m6 = _mm_loadu_si128((const __m128i *)(p +  96));
		__m128i m7 = _mm_loadu_si128((const __m128i *)(p + 112));

		/* d_k already has rk[0] folded in via Δ', so prologue is one XOR. */
		__m128i x0 = _mm_xor_si128(m0, d0);
		__m128i x1 = _mm_xor_si128(m1, d1);
		__m128i x2 = _mm_xor_si128(m2, d2);
		__m128i x3 = _mm_xor_si128(m3, d3);
		__m128i x4 = _mm_xor_si128(m4, d4);
		__m128i x5 = _mm_xor_si128(m5, d5);
		__m128i x6 = _mm_xor_si128(m6, d6);
		__m128i x7 = _mm_xor_si128(m7, d7);

#define R8(rn)                                          \
		x0 = _mm_aesenc_si128(x0, rk[rn]);              \
		x1 = _mm_aesenc_si128(x1, rk[rn]);              \
		x2 = _mm_aesenc_si128(x2, rk[rn]);              \
		x3 = _mm_aesenc_si128(x3, rk[rn]);              \
		x4 = _mm_aesenc_si128(x4, rk[rn]);              \
		x5 = _mm_aesenc_si128(x5, rk[rn]);              \
		x6 = _mm_aesenc_si128(x6, rk[rn]);              \
		x7 = _mm_aesenc_si128(x7, rk[rn])
		R8(1); R8(2); R8(3); R8(4); R8(5); R8(6); R8(7); R8(8); R8(9);
#undef R8
		x0 = _mm_aesenclast_si128(x0, rk[10]);
		x1 = _mm_aesenclast_si128(x1, rk[10]);
		x2 = _mm_aesenclast_si128(x2, rk[10]);
		x3 = _mm_aesenclast_si128(x3, rk[10]);
		x4 = _mm_aesenclast_si128(x4, rk[10]);
		x5 = _mm_aesenclast_si128(x5, rk[10]);
		x6 = _mm_aesenclast_si128(x6, rk[10]);
		x7 = _mm_aesenclast_si128(x7, rk[10]);

		__m128i s01 = _mm_xor_si128(x0, x1);
		__m128i s23 = _mm_xor_si128(x2, x3);
		__m128i s45 = _mm_xor_si128(x4, x5);
		__m128i s67 = _mm_xor_si128(x6, x7);
		Sum = _mm_xor_si128(Sum,
				_mm_xor_si128(_mm_xor_si128(s01, s23),
				              _mm_xor_si128(s45, s67)));
		i += 8;
	}

	/* 4-way pass for naux % 8 in [4..7]. */
	while (i + 3 <= naux) {
		int j0 = __builtin_ctzll((unsigned long long)(i + 0));
		int j1 = __builtin_ctzll((unsigned long long)(i + 1));
		int j2 = __builtin_ctzll((unsigned long long)(i + 2));
		int j3 = __builtin_ctzll((unsigned long long)(i + 3));

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

		__m128i x0 = _mm_xor_si128(m0, d0);
		__m128i x1 = _mm_xor_si128(m1, d1);
		__m128i x2 = _mm_xor_si128(m2, d2);
		__m128i x3 = _mm_xor_si128(m3, d3);

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
	__m128i x##k = _mm_xor_si128(mi##k, d##k)
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

	/* Final block: final_pre = (M_m ⊕ L_inv ⊕ rk[0]) or (M_m_padded ⊕
	 * rk[0]) was hoisted above the bulk loop. The post-bulk critical path
	 * is one XOR, then aesenc rounds 1..10. */
	__m128i final_in = _mm_xor_si128(Sum, final_pre);
	_mm_storeu_si128((__m128i *)tag,
			aes128_encrypt_pre_whitened(rk, final_in));
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

/* AES-128 key-schedule round, replicated 4-way. The serial form is:
 *     a = aeskeygenassist(k, rcon)
 *     k = k XOR (k << 32)
 *     k = k XOR (k << 32)
 *     k = k XOR (k << 32)
 *     k = k XOR shuffle32(a, 0xff)   // broadcast high lane (RotSub(W3)^Rcon)
 * Doing four keys' rounds back-to-back lets the AES unit pipeline four
 * aeskeygenassists (each ~7c latency, 1c throughput) instead of stalling. */
#define AB_KS_TRANSFORM(kv) do {                              \
	__m128i _t = _mm_slli_si128((kv), 4);                     \
	(kv) = _mm_xor_si128((kv), _t);                           \
	_t = _mm_slli_si128((kv), 4);                             \
	(kv) = _mm_xor_si128((kv), _t);                           \
	_t = _mm_slli_si128((kv), 4);                             \
	(kv) = _mm_xor_si128((kv), _t);                           \
} while (0)

#define AB_KS_ROUND(rcon, r) do {                                              \
	__m128i a0 = _mm_aeskeygenassist_si128(k0, (rcon));                        \
	__m128i a1 = _mm_aeskeygenassist_si128(k1, (rcon));                        \
	__m128i a2 = _mm_aeskeygenassist_si128(k2, (rcon));                        \
	__m128i a3 = _mm_aeskeygenassist_si128(k3, (rcon));                        \
	AB_KS_TRANSFORM(k0);                                                       \
	AB_KS_TRANSFORM(k1);                                                       \
	AB_KS_TRANSFORM(k2);                                                       \
	AB_KS_TRANSFORM(k3);                                                       \
	k0 = _mm_xor_si128(k0, _mm_shuffle_epi32(a0, 0xff));                       \
	k1 = _mm_xor_si128(k1, _mm_shuffle_epi32(a1, 0xff));                       \
	k2 = _mm_xor_si128(k2, _mm_shuffle_epi32(a2, 0xff));                       \
	k3 = _mm_xor_si128(k3, _mm_shuffle_epi32(a3, 0xff));                       \
	_mm_storeu_si128((__m128i *)(out_rks[0] + ((r) + 1) * 16), k0);            \
	_mm_storeu_si128((__m128i *)(out_rks[1] + ((r) + 1) * 16), k1);            \
	_mm_storeu_si128((__m128i *)(out_rks[2] + ((r) + 1) * 16), k2);            \
	_mm_storeu_si128((__m128i *)(out_rks[3] + ((r) + 1) * 16), k3);            \
} while (0)

PMAC1_ATTR void
ab_derive_aes128_keys_x4(const void *const master_rks[4],
		const unsigned char inputs[4][16],
		unsigned char *const out_rks[4])
{
	const __m128i *rk0 = (const __m128i *)master_rks[0];
	const __m128i *rk1 = (const __m128i *)master_rks[1];
	const __m128i *rk2 = (const __m128i *)master_rks[2];
	const __m128i *rk3 = (const __m128i *)master_rks[3];

	__m128i x0 = _mm_loadu_si128((const __m128i *)inputs[0]);
	__m128i x1 = _mm_loadu_si128((const __m128i *)inputs[1]);
	__m128i x2 = _mm_loadu_si128((const __m128i *)inputs[2]);
	__m128i x3 = _mm_loadu_si128((const __m128i *)inputs[3]);
	x0 = _mm_xor_si128(x0, _mm_loadu_si128(&rk0[0]));
	x1 = _mm_xor_si128(x1, _mm_loadu_si128(&rk1[0]));
	x2 = _mm_xor_si128(x2, _mm_loadu_si128(&rk2[0]));
	x3 = _mm_xor_si128(x3, _mm_loadu_si128(&rk3[0]));
#define AB_DERIVE_ENC(r)                                                       \
	x0 = _mm_aesenc_si128(x0, _mm_loadu_si128(&rk0[r]));                       \
	x1 = _mm_aesenc_si128(x1, _mm_loadu_si128(&rk1[r]));                       \
	x2 = _mm_aesenc_si128(x2, _mm_loadu_si128(&rk2[r]));                       \
	x3 = _mm_aesenc_si128(x3, _mm_loadu_si128(&rk3[r]))
	AB_DERIVE_ENC(1); AB_DERIVE_ENC(2); AB_DERIVE_ENC(3);
	AB_DERIVE_ENC(4); AB_DERIVE_ENC(5); AB_DERIVE_ENC(6);
	AB_DERIVE_ENC(7); AB_DERIVE_ENC(8); AB_DERIVE_ENC(9);
#undef AB_DERIVE_ENC
	x0 = _mm_aesenclast_si128(x0, _mm_loadu_si128(&rk0[10]));
	x1 = _mm_aesenclast_si128(x1, _mm_loadu_si128(&rk1[10]));
	x2 = _mm_aesenclast_si128(x2, _mm_loadu_si128(&rk2[10]));
	x3 = _mm_aesenclast_si128(x3, _mm_loadu_si128(&rk3[10]));

	__m128i k0 = x0, k1 = x1, k2 = x2, k3 = x3;
	_mm_storeu_si128((__m128i *)(out_rks[0]), k0);
	_mm_storeu_si128((__m128i *)(out_rks[1]), k1);
	_mm_storeu_si128((__m128i *)(out_rks[2]), k2);
	_mm_storeu_si128((__m128i *)(out_rks[3]), k3);

	AB_KS_ROUND(0x01, 0);
	AB_KS_ROUND(0x02, 1);
	AB_KS_ROUND(0x04, 2);
	AB_KS_ROUND(0x08, 3);
	AB_KS_ROUND(0x10, 4);
	AB_KS_ROUND(0x20, 5);
	AB_KS_ROUND(0x40, 6);
	AB_KS_ROUND(0x80, 7);
	AB_KS_ROUND(0x1b, 8);
	AB_KS_ROUND(0x36, 9);
}

/* Key derivation for n packets (4 or 8) in lockstep: derived key =
 * AES_master(input), expanded to 11 round keys, plus L = AES_K(0) for PMAC.
 *
 * The key schedule does not use AESKEYGENASSIST, which is slow on
 * Broadwell/Skylake-SP (2 uops, poor throughput). Each step needs
 * SubWord(RotWord(w3)) ^ rcon in every word; pshufb broadcasts RotWord(w3)
 * into all four columns, so ShiftRows inside AESENCLAST is a no-op and
 * AESENCLAST(t, rcon) yields exactly that in one AES uop. The L chain runs
 * one round behind the schedule, so it needs no second pass over the keys.
 * Lanes are independent chains: 4 lanes cover most of the AES latency,
 * 8 cover it fully. */
PMAC1_ATTR static inline __attribute__((always_inline)) void
derive_keys_and_L_lanes(const int n, const void *const *master_rks,
		const unsigned char (*inputs)[16],
		unsigned char *const *out_rks, unsigned char (*out_L)[16])
{
	static const int rcons[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
			0x80, 0x1b, 0x36 };
	const __m128i rot = _mm_set1_epi32(0x0c0f0e0d);
	const __m128i *m[8];
	__m128i *o[8];
	__m128i k[8], l[8];

	for (int j = 0; j < n; j++) {
		m[j] = (const __m128i *)master_rks[j];
		o[j] = (__m128i *)out_rks[j];
		k[j] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)inputs[j]),
				_mm_loadu_si128(&m[j][0]));
	}
	for (int r = 1; r < 10; r++)
		for (int j = 0; j < n; j++)
			k[j] = _mm_aesenc_si128(k[j], _mm_loadu_si128(&m[j][r]));
	for (int j = 0; j < n; j++) {
		k[j] = _mm_aesenclast_si128(k[j], _mm_loadu_si128(&m[j][10]));
		_mm_storeu_si128(&o[j][0], k[j]);
		l[j] = k[j];  /* L chain: AES_K(0) starts as 0 ^ rk[0] */
	}
	for (int r = 0; r < 10; r++) {
		const __m128i rc = _mm_set1_epi32(rcons[r]);
		for (int j = 0; j < n; j++) {
			__m128i a = _mm_aesenclast_si128(_mm_shuffle_epi8(k[j], rot), rc);
			/* k ^= (k << 32) ^ (k << 64) ^ (k << 96) ^ a */
			__m128i t = _mm_slli_si128(k[j], 4);
			k[j] = _mm_xor_si128(k[j], t);
			t = _mm_slli_si128(k[j], 4);
			k[j] = _mm_xor_si128(k[j], t);
			t = _mm_slli_si128(k[j], 4);
			k[j] = _mm_xor_si128(k[j], t);
			k[j] = _mm_xor_si128(k[j], a);
			_mm_storeu_si128(&o[j][r + 1], k[j]);
			l[j] = (r < 9) ? _mm_aesenc_si128(l[j], k[j])
			               : _mm_aesenclast_si128(l[j], k[j]);
		}
	}
	for (int j = 0; j < n; j++)
		_mm_storeu_si128((__m128i *)out_L[j], l[j]);
}

PMAC1_ATTR void
ab_derive_aes128_keys_and_L_x4(const void *const master_rks[4],
		const unsigned char inputs[4][16],
		unsigned char *const out_rks[4],
		unsigned char out_L[4][16])
{
	derive_keys_and_L_lanes(4, master_rks, inputs, out_rks, out_L);
}

PMAC1_ATTR void
ab_derive_aes128_keys_and_L_x8(const void *const master_rks[8],
		const unsigned char inputs[8][16],
		unsigned char *const out_rks[8],
		unsigned char out_L[8][16])
{
	derive_keys_and_L_lanes(8, master_rks, inputs, out_rks, out_L);
}

PMAC1_ATTR void
pmac1_aes128_with_L(const void *roundkey, const unsigned char L[16],
		const unsigned char *msg, size_t msg_bytes, unsigned char tag[16])
{
	const __m128i *rk = (const __m128i *)roundkey;
	__m128i Lv = _mm_loadu_si128((const __m128i *)L);
	__m128i Linv = half_block(Lv);
	__m128i Ltab[24];
	Ltab[0] = Lv;
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

PMAC1_ATTR static inline __attribute__((always_inline)) void
pmac1_with_L_lanes(const int n, const void *const *rks,
		const unsigned char (*L)[16],
		const unsigned char *const *msgs, const size_t *lens,
		unsigned char (*tags)[16])
{
	static const unsigned char zero_block[16] __attribute__((aligned(16)));
	const __m128i *rk[8];
	size_t naux[8];
	size_t max_naux = 0;
	__m128i final_pre[8], Delta[8], Sum[8];
	__m128i Ltab[8][24];

	for (int k = 0; k < n; k++) {
		rk[k] = (const __m128i *)rks[k];
		size_t m_full, m;
		int last_full;
		segment(lens[k], &m_full, &m, &last_full);
		naux[k] = m - 1;
		if (naux[k] > max_naux)
			max_naux = naux[k];
		Ltab[k][0] = _mm_loadu_si128((const __m128i *)L[k]);
		__m128i rk0 = _mm_loadu_si128(&rk[k][0]);
		if (last_full) {
			__m128i Mm = _mm_loadu_si128(
					(const __m128i *)(msgs[k] + (m - 1) * 16));
			final_pre[k] = _mm_xor_si128(
					_mm_xor_si128(Mm, half_block(Ltab[k][0])), rk0);
		} else {
			unsigned char buf[16] = { 0 };
			size_t off = m_full * 16;
			size_t rem = lens[k] - off;
			if (rem) memcpy(buf, msgs[k] + off, rem);
			buf[rem] = 0x80;
			final_pre[k] = _mm_xor_si128(
					_mm_loadu_si128((const __m128i *)buf), rk0);
		}
		/* rk[0] folded into Delta, as in pmac1_core. */
		Delta[k] = rk0;
		Sum[k] = _mm_setzero_si128();
	}

	int needed = 0;
	while (((size_t)1 << needed) <= max_naux) needed++;
	if (needed > 23) needed = 23;
	for (int j = 1; j <= needed; j++)
		for (int k = 0; k < n; k++)
			Ltab[k][j] = double_block(Ltab[k][j - 1]);

	for (size_t i = 1; i <= max_naux; i++) {
		int j = __builtin_ctzll((unsigned long long)i);
		__m128i x[8], live[8];
		for (int k = 0; k < n; k++) {
			int on = i <= naux[k];
			const unsigned char *p = on ? msgs[k] + (i - 1) * 16 : zero_block;
			live[k] = _mm_set1_epi32(on ? -1 : 0);
			Delta[k] = _mm_xor_si128(Delta[k], Ltab[k][j]);
			x[k] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)p), Delta[k]);
		}
		for (int r = 1; r < 10; r++)
			for (int k = 0; k < n; k++)
				x[k] = _mm_aesenc_si128(x[k], _mm_loadu_si128(&rk[k][r]));
		for (int k = 0; k < n; k++) {
			x[k] = _mm_aesenclast_si128(x[k], _mm_loadu_si128(&rk[k][10]));
			Sum[k] = _mm_xor_si128(Sum[k], _mm_and_si128(x[k], live[k]));
		}
	}

	__m128i t[8];
	for (int k = 0; k < n; k++)
		t[k] = _mm_xor_si128(Sum[k], final_pre[k]);
	for (int r = 1; r < 10; r++)
		for (int k = 0; k < n; k++)
			t[k] = _mm_aesenc_si128(t[k], _mm_loadu_si128(&rk[k][r]));
	for (int k = 0; k < n; k++)
		_mm_storeu_si128((__m128i *)tags[k],
				_mm_aesenclast_si128(t[k], _mm_loadu_si128(&rk[k][10])));
}

/* PMAC1 for four packets in lockstep (dpdk_forward stage 5). At small sizes a single packet's PMAC is a short dependent
 * chain (doubling table -> a few blocks -> 10-round final encrypt) that
 * leaves the AES unit mostly idle: an 86 B packet is ~80 AES ops but took
 * ~420 cycles. Here every step works on one block of each packet, so the
 * packets' chains are in flight together, and the doubling tables and final
 * encrypts are interleaved the same way. Lengths may differ: a packet that
 * has run out of auxiliary blocks gets a zero block whose output is masked
 * out of its Sum, so no lane reads past its end. Same result as separate
 * pmac1_aes128_with_L calls. */
PMAC1_ATTR void
pmac1_aes128_with_L_x4(const void *const rks[4],
		const unsigned char L[4][16],
		const unsigned char *const msgs[4], const size_t lens[4],
		unsigned char tags[4][16])
{
	pmac1_with_L_lanes(4, rks, L, msgs, lens, tags);
}

/* Eight packets in lockstep: with ~7 cycles of AES latency (Broadwell),
 * eight independent chains keep the AES unit busier than four. */
PMAC1_ATTR void
pmac1_aes128_with_L_x8(const void *const rks[8],
		const unsigned char L[8][16],
		const unsigned char *const msgs[8], const size_t lens[8],
		unsigned char tags[8][16])
{
	pmac1_with_L_lanes(8, rks, L, msgs, lens, tags);
}

/* Split-finalize compute path. Runs the same bulk/trail pipeline as
 * pmac1_core but stops before the final encrypt, exporting Sum and
 * final_pre. The implementation duplicates pmac1_core's loop bodies —
 * sharing via inline-everything would force the compiler to spill xmm
 * regs to memory anyway. Keeping the duplication local and clearly
 * marked beats fighting the optimiser. */
PMAC1_ATTR void
pmac1_aes128_compute_sum_with_L(const void *roundkey, const unsigned char L[16],
		const unsigned char *msg, size_t msg_bytes,
		unsigned char sum_out[16], unsigned char final_pre_out[16])
{
	const __m128i *rk = (const __m128i *)roundkey;
	__m128i Lv = _mm_loadu_si128((const __m128i *)L);
	__m128i Linv = half_block(Lv);
	__m128i Ltab[24];
	Ltab[0] = Lv;
	size_t blocks_for_aux;
	if (msg_bytes == 0) blocks_for_aux = 0;
	else if (msg_bytes % 16 == 0) blocks_for_aux = msg_bytes / 16 - 1;
	else blocks_for_aux = msg_bytes / 16;
	int needed = 0;
	while (((size_t)1 << needed) <= blocks_for_aux) needed++;
	if (needed > 23) needed = 23;
	for (int j = 1; j <= needed; j++) Ltab[j] = double_block(Ltab[j - 1]);

	size_t m_full, m;
	int last_full;
	segment(msg_bytes, &m_full, &m, &last_full);

	__m128i rk0 = rk[0];
	__m128i Sum = _mm_setzero_si128();
	__m128i Delta = rk0;

	size_t naux = (m == 0) ? 0 : m - 1;

	__m128i final_pre;
	if (last_full) {
		__m128i Mm = _mm_loadu_si128(
				(const __m128i *)(msg + (m - 1) * 16));
		final_pre = _mm_xor_si128(_mm_xor_si128(Mm, Linv), rk0);
	} else {
		unsigned char buf[16] = { 0 };
		size_t off = m_full * 16;
		size_t rem = msg_bytes - off;
		if (rem) memcpy(buf, msg + off, rem);
		buf[rem] = 0x80;
		__m128i Mm = _mm_loadu_si128((const __m128i *)buf);
		final_pre = _mm_xor_si128(Mm, rk0);
	}

	size_t i = 1;

	/* Bulk loop: 8-way, identical to pmac1_core. */
	while (i + 7 <= naux) {
		int j0 = __builtin_ctzll((unsigned long long)(i + 0));
		int j1 = __builtin_ctzll((unsigned long long)(i + 1));
		int j2 = __builtin_ctzll((unsigned long long)(i + 2));
		int j3 = __builtin_ctzll((unsigned long long)(i + 3));
		int j4 = __builtin_ctzll((unsigned long long)(i + 4));
		int j5 = __builtin_ctzll((unsigned long long)(i + 5));
		int j6 = __builtin_ctzll((unsigned long long)(i + 6));
		int j7 = __builtin_ctzll((unsigned long long)(i + 7));
		__m128i d0 = _mm_xor_si128(Delta, Ltab[j0]);
		__m128i d1 = _mm_xor_si128(d0, Ltab[j1]);
		__m128i d2 = _mm_xor_si128(d1, Ltab[j2]);
		__m128i d3 = _mm_xor_si128(d2, Ltab[j3]);
		__m128i d4 = _mm_xor_si128(d3, Ltab[j4]);
		__m128i d5 = _mm_xor_si128(d4, Ltab[j5]);
		__m128i d6 = _mm_xor_si128(d5, Ltab[j6]);
		__m128i d7 = _mm_xor_si128(d6, Ltab[j7]);
		Delta = d7;
		const unsigned char *p = msg + (i - 1) * 16;
		__m128i x0 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(p +   0)), d0);
		__m128i x1 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(p +  16)), d1);
		__m128i x2 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(p +  32)), d2);
		__m128i x3 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(p +  48)), d3);
		__m128i x4 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(p +  64)), d4);
		__m128i x5 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(p +  80)), d5);
		__m128i x6 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(p +  96)), d6);
		__m128i x7 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(p + 112)), d7);
#define R8(rn)                                          \
		x0 = _mm_aesenc_si128(x0, rk[rn]);              \
		x1 = _mm_aesenc_si128(x1, rk[rn]);              \
		x2 = _mm_aesenc_si128(x2, rk[rn]);              \
		x3 = _mm_aesenc_si128(x3, rk[rn]);              \
		x4 = _mm_aesenc_si128(x4, rk[rn]);              \
		x5 = _mm_aesenc_si128(x5, rk[rn]);              \
		x6 = _mm_aesenc_si128(x6, rk[rn]);              \
		x7 = _mm_aesenc_si128(x7, rk[rn])
		R8(1); R8(2); R8(3); R8(4); R8(5); R8(6); R8(7); R8(8); R8(9);
#undef R8
		x0 = _mm_aesenclast_si128(x0, rk[10]);
		x1 = _mm_aesenclast_si128(x1, rk[10]);
		x2 = _mm_aesenclast_si128(x2, rk[10]);
		x3 = _mm_aesenclast_si128(x3, rk[10]);
		x4 = _mm_aesenclast_si128(x4, rk[10]);
		x5 = _mm_aesenclast_si128(x5, rk[10]);
		x6 = _mm_aesenclast_si128(x6, rk[10]);
		x7 = _mm_aesenclast_si128(x7, rk[10]);
		Sum = _mm_xor_si128(Sum,
				_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(x0, x1),
				                            _mm_xor_si128(x2, x3)),
				              _mm_xor_si128(_mm_xor_si128(x4, x5),
				                            _mm_xor_si128(x6, x7))));
		i += 8;
	}
	while (i + 3 <= naux) {
		int j0 = __builtin_ctzll((unsigned long long)(i + 0));
		int j1 = __builtin_ctzll((unsigned long long)(i + 1));
		int j2 = __builtin_ctzll((unsigned long long)(i + 2));
		int j3 = __builtin_ctzll((unsigned long long)(i + 3));
		__m128i d0 = _mm_xor_si128(Delta, Ltab[j0]);
		__m128i d1 = _mm_xor_si128(d0, Ltab[j1]);
		__m128i d2 = _mm_xor_si128(d1, Ltab[j2]);
		__m128i d3 = _mm_xor_si128(d2, Ltab[j3]);
		Delta = d3;
		const unsigned char *p = msg + (i - 1) * 16;
		__m128i x0 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(p +  0)), d0);
		__m128i x1 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(p + 16)), d1);
		__m128i x2 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(p + 32)), d2);
		__m128i x3 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(p + 48)), d3);
#define R(rn)                                          \
		x0 = _mm_aesenc_si128(x0, rk[rn]);              \
		x1 = _mm_aesenc_si128(x1, rk[rn]);              \
		x2 = _mm_aesenc_si128(x2, rk[rn]);              \
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
	size_t left = (naux >= i) ? (naux - i + 1) : 0;
	if (left == 1) {
		int j0_ = __builtin_ctzll((unsigned long long)(i + 0));
		Delta = _mm_xor_si128(Delta, Ltab[j0_]);
		__m128i mi0 = _mm_loadu_si128(
				(const __m128i *)(msg + (i - 1) * 16));
		__m128i x0 = _mm_xor_si128(mi0, Delta);
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
		int j0_ = __builtin_ctzll((unsigned long long)(i + 0));
		Delta = _mm_xor_si128(Delta, Ltab[j0_]);
		__m128i d0 = Delta;
		__m128i mi0 = _mm_loadu_si128((const __m128i *)(msg + (i - 1) * 16));
		__m128i x0 = _mm_xor_si128(mi0, d0);
		int j1_ = __builtin_ctzll((unsigned long long)(i + 1));
		Delta = _mm_xor_si128(Delta, Ltab[j1_]);
		__m128i d1 = Delta;
		__m128i mi1 = _mm_loadu_si128((const __m128i *)(msg + i * 16));
		__m128i x1 = _mm_xor_si128(mi1, d1);
#define R2(rn)                                                                 \
	x0 = _mm_aesenc_si128(x0, rk[rn]);                                        \
	x1 = _mm_aesenc_si128(x1, rk[rn])
		R2(1); R2(2); R2(3); R2(4); R2(5); R2(6); R2(7); R2(8); R2(9);
#undef R2
		x0 = _mm_aesenclast_si128(x0, rk[10]);
		x1 = _mm_aesenclast_si128(x1, rk[10]);
		Sum = _mm_xor_si128(Sum, _mm_xor_si128(x0, x1));
	} else if (left == 3) {
		int j0_ = __builtin_ctzll((unsigned long long)(i + 0));
		Delta = _mm_xor_si128(Delta, Ltab[j0_]);
		__m128i d0 = Delta;
		__m128i mi0 = _mm_loadu_si128((const __m128i *)(msg + (i - 1) * 16));
		__m128i x0 = _mm_xor_si128(mi0, d0);
		int j1_ = __builtin_ctzll((unsigned long long)(i + 1));
		Delta = _mm_xor_si128(Delta, Ltab[j1_]);
		__m128i d1 = Delta;
		__m128i mi1 = _mm_loadu_si128((const __m128i *)(msg + i * 16));
		__m128i x1 = _mm_xor_si128(mi1, d1);
		int j2_ = __builtin_ctzll((unsigned long long)(i + 2));
		Delta = _mm_xor_si128(Delta, Ltab[j2_]);
		__m128i d2 = Delta;
		__m128i mi2 = _mm_loadu_si128((const __m128i *)(msg + (i + 1) * 16));
		__m128i x2 = _mm_xor_si128(mi2, d2);
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

	_mm_storeu_si128((__m128i *)sum_out, Sum);
	_mm_storeu_si128((__m128i *)final_pre_out, final_pre);
}

PMAC1_ATTR void
pmac1_finalize_tag_one(const void *roundkey,
		const unsigned char sum[16],
		const unsigned char final_pre[16],
		unsigned char tag[16])
{
	const __m128i *rk = (const __m128i *)roundkey;
	__m128i x = _mm_xor_si128(_mm_loadu_si128((const __m128i *)sum),
			_mm_loadu_si128((const __m128i *)final_pre));
	/* final_pre has rk[0] folded in already, so skip the round-0 XOR. */
	_mm_storeu_si128((__m128i *)tag, aes128_encrypt_pre_whitened(rk, x));
}

/* 8-way batched final encrypt: 88 AES instructions issued across 8
 * independent chains, ~95 cycles wall-clock total on Broadwell port 5
 * (~12c/pkt vs 77c sequential). final_pre[i] already has rk[i][0]
 * folded in, so we go straight from XOR to aesenc rounds 1..10. */
PMAC1_ATTR void
pmac1_finalize_tags_x8(const void *const rks[8],
		const unsigned char sums[8][16],
		const unsigned char final_pres[8][16],
		unsigned char tags[8][16])
{
	const __m128i *rk0p = (const __m128i *)rks[0];
	const __m128i *rk1p = (const __m128i *)rks[1];
	const __m128i *rk2p = (const __m128i *)rks[2];
	const __m128i *rk3p = (const __m128i *)rks[3];
	const __m128i *rk4p = (const __m128i *)rks[4];
	const __m128i *rk5p = (const __m128i *)rks[5];
	const __m128i *rk6p = (const __m128i *)rks[6];
	const __m128i *rk7p = (const __m128i *)rks[7];

	__m128i x0 = _mm_xor_si128(
			_mm_loadu_si128((const __m128i *)sums[0]),
			_mm_loadu_si128((const __m128i *)final_pres[0]));
	__m128i x1 = _mm_xor_si128(
			_mm_loadu_si128((const __m128i *)sums[1]),
			_mm_loadu_si128((const __m128i *)final_pres[1]));
	__m128i x2 = _mm_xor_si128(
			_mm_loadu_si128((const __m128i *)sums[2]),
			_mm_loadu_si128((const __m128i *)final_pres[2]));
	__m128i x3 = _mm_xor_si128(
			_mm_loadu_si128((const __m128i *)sums[3]),
			_mm_loadu_si128((const __m128i *)final_pres[3]));
	__m128i x4 = _mm_xor_si128(
			_mm_loadu_si128((const __m128i *)sums[4]),
			_mm_loadu_si128((const __m128i *)final_pres[4]));
	__m128i x5 = _mm_xor_si128(
			_mm_loadu_si128((const __m128i *)sums[5]),
			_mm_loadu_si128((const __m128i *)final_pres[5]));
	__m128i x6 = _mm_xor_si128(
			_mm_loadu_si128((const __m128i *)sums[6]),
			_mm_loadu_si128((const __m128i *)final_pres[6]));
	__m128i x7 = _mm_xor_si128(
			_mm_loadu_si128((const __m128i *)sums[7]),
			_mm_loadu_si128((const __m128i *)final_pres[7]));

#define R8F(rn)                                                                \
	x0 = _mm_aesenc_si128(x0, _mm_loadu_si128(&rk0p[rn]));                     \
	x1 = _mm_aesenc_si128(x1, _mm_loadu_si128(&rk1p[rn]));                     \
	x2 = _mm_aesenc_si128(x2, _mm_loadu_si128(&rk2p[rn]));                     \
	x3 = _mm_aesenc_si128(x3, _mm_loadu_si128(&rk3p[rn]));                     \
	x4 = _mm_aesenc_si128(x4, _mm_loadu_si128(&rk4p[rn]));                     \
	x5 = _mm_aesenc_si128(x5, _mm_loadu_si128(&rk5p[rn]));                     \
	x6 = _mm_aesenc_si128(x6, _mm_loadu_si128(&rk6p[rn]));                     \
	x7 = _mm_aesenc_si128(x7, _mm_loadu_si128(&rk7p[rn]))
	R8F(1); R8F(2); R8F(3); R8F(4); R8F(5); R8F(6); R8F(7); R8F(8); R8F(9);
#undef R8F
	x0 = _mm_aesenclast_si128(x0, _mm_loadu_si128(&rk0p[10]));
	x1 = _mm_aesenclast_si128(x1, _mm_loadu_si128(&rk1p[10]));
	x2 = _mm_aesenclast_si128(x2, _mm_loadu_si128(&rk2p[10]));
	x3 = _mm_aesenclast_si128(x3, _mm_loadu_si128(&rk3p[10]));
	x4 = _mm_aesenclast_si128(x4, _mm_loadu_si128(&rk4p[10]));
	x5 = _mm_aesenclast_si128(x5, _mm_loadu_si128(&rk5p[10]));
	x6 = _mm_aesenclast_si128(x6, _mm_loadu_si128(&rk6p[10]));
	x7 = _mm_aesenclast_si128(x7, _mm_loadu_si128(&rk7p[10]));

	_mm_storeu_si128((__m128i *)tags[0], x0);
	_mm_storeu_si128((__m128i *)tags[1], x1);
	_mm_storeu_si128((__m128i *)tags[2], x2);
	_mm_storeu_si128((__m128i *)tags[3], x3);
	_mm_storeu_si128((__m128i *)tags[4], x4);
	_mm_storeu_si128((__m128i *)tags[5], x5);
	_mm_storeu_si128((__m128i *)tags[6], x6);
	_mm_storeu_si128((__m128i *)tags[7], x7);
}

#undef AB_KS_ROUND
#undef AB_KS_TRANSFORM
