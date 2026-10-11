#ifndef PMAC1_H
#define PMAC1_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PMAC1 (Rogaway, "A Block-Cipher Mode of Operation for Parallelizable
 * Message Authentication", EUROCRYPT 2002) under AES-128.
 *
 * roundkey: 11*16 = 176 byte AES-128 round-key schedule produced by
 *           ExpandKey128. Note this is one block more than aesni.h's
 *           comment claims; AES-128 has 11 round keys, not 10.
 *
 * Two API tiers:
 *
 *   pmac1_aes128(rk, msg, msg_bytes, tag)
 *     One-shot: derives L, L_inv, and the doubling table internally on
 *     every call. Convenient but costs ~80-100 cycles of avoidable per-call
 *     setup work.
 *
 *   pmac1_keysetup(rk, ctx); pmac1_aes128_ctx(ctx, msg, msg_bytes, tag)
 *     Precompute everything once per key, then amortize over many tags.
 *     This is the form a production protocol should use.
 *
 *   pmac1_aes128_seq is a 1-block-at-a-time reference used by tests. */

#include <stdint.h>

/* Precomputed PMAC1 context. Allocate with 16-byte alignment. */
typedef struct pmac1_ctx {
	/* Round keys, copied so per-call code reads from one struct. */
	uint8_t rk[11 * 16] __attribute__((aligned(16)));
	uint8_t L[16] __attribute__((aligned(16)));     /* E_K(0)                */
	uint8_t L_inv[16] __attribute__((aligned(16))); /* L * x^{-1}            */
	/* L_j = L * 2^j for j = 0..23. The j we need at block i is ntz(i), and
	 * max ntz over 1..m-1 is at most floor(log2(m-1)). 24 entries cover
	 * messages up to 2^24 ≈ 16 M blocks (256 MB). */
	uint8_t Ltab[24 * 16] __attribute__((aligned(16)));
} pmac1_ctx;

void pmac1_keysetup(const void *roundkey, pmac1_ctx *ctx);
void pmac1_aes128_ctx(const pmac1_ctx *ctx, const unsigned char *msg,
		size_t msg_bytes, unsigned char tag[16]);

void pmac1_aes128(const void *roundkey, const unsigned char *msg,
		size_t msg_bytes, unsigned char tag[16]);
void pmac1_aes128_seq(const void *roundkey, const unsigned char *msg,
		size_t msg_bytes, unsigned char tag[16]);

/* 4-way batched AB key derivation: encrypt inputs[i] (single block) under
 * master_rks[i] to produce a derived AES-128 key, then expand it into
 * out_rks[i] (176 bytes of round keys). One call does what four
 * `CBCMAC(rk, 1, in, dk); ExpandKey128(dk, out)` pairs do, but interleaves
 * the AES-NI ops across the four lanes so they pipeline through the AES
 * unit instead of serialising. Used by the validator hot path. */
void
ab_derive_aes128_keys_x4(const void *const master_rks[4],
		const unsigned char inputs[4][16],
		unsigned char *const out_rks[4]);

/* Same as above, but additionally computes L[i] = AES(out_rks[i], 0) for
 * each packet, which the caller passes to pmac1_aes128_with_L so it skips
 * the 11-round serial L derivation. The key schedule here uses pshufb +
 * AESENCLAST instead of AESKEYGENASSIST (much cheaper on Broadwell and
 * Skylake-SP) and runs the L chain alongside it; same results as
 * CBCMAC + ExpandKey128 + AES_K(0). The _x8 form does eight packets, which
 * covers more of the AES latency. */
void
ab_derive_aes128_keys_and_L_x4(const void *const master_rks[4],
		const unsigned char inputs[4][16],
		unsigned char *const out_rks[4],
		unsigned char out_L[4][16]);
void
ab_derive_aes128_keys_and_L_x8(const void *const master_rks[8],
		const unsigned char inputs[8][16],
		unsigned char *const out_rks[8],
		unsigned char out_L[8][16]);

/* PMAC1 with a precomputed L. The caller supplies L = AES_K(0); the
 * function still computes L_inv and the L-doublings table internally
 * (cheap relative to L itself). Use with ab_derive_aes128_keys_and_L_x4. */
void
pmac1_aes128_with_L(const void *roundkey, const unsigned char L[16],
		const unsigned char *msg, size_t msg_bytes,
		unsigned char tag[16]);

/* PMAC1 for four or eight packets in lockstep, each with its own key, L and
 * length; same tags as separate pmac1_aes128_with_L calls. A single small
 * packet's PMAC is a short dependent chain that leaves the AES unit mostly
 * idle; interleaving packets overlaps their chains. Lanes that run out of
 * blocks are masked, so lengths may differ and no lane reads past its
 * message. For large packets the single-packet path is faster (it
 * interleaves 8 blocks of one packet). */
void
pmac1_aes128_with_L_x4(const void *const rks[4],
		const unsigned char L[4][16],
		const unsigned char *const msgs[4], const size_t lens[4],
		unsigned char tags[4][16]);
void
pmac1_aes128_with_L_x8(const void *const rks[8],
		const unsigned char L[8][16],
		const unsigned char *const msgs[8], const size_t lens[8],
		unsigned char tags[8][16]);

/* Split-finalize variants for inter-packet pipelining.
 *
 * Per packet, the post-bulk critical path is `final_in = Sum ⊕ final_pre`
 * then 11 dependent AES rounds — that's 77c of latency that uses only
 * one chain on Broadwell's port 5. Doing eight packets' final encrypts
 * in lockstep saturates the AES port (88 ops in ~95c, so ~12c/pkt
 * instead of 77c).
 *
 * pmac1_aes128_compute_sum_with_L runs the bulk + trail blocks but
 * stops before the final encrypt, exporting Sum and final_pre. Caller
 * gathers eight packets' (rk, Sum, final_pre) and calls
 * pmac1_finalize_tags_x8 to produce eight tags in parallel. For burst
 * sizes that are not multiples of eight, the trailing 1..7 packets use
 * the per-packet finalize fallback. */
void
pmac1_aes128_compute_sum_with_L(const void *roundkey, const unsigned char L[16],
		const unsigned char *msg, size_t msg_bytes,
		unsigned char sum_out[16], unsigned char final_pre_out[16]);

void
pmac1_finalize_tags_x8(const void *const rks[8],
		const unsigned char sums[8][16],
		const unsigned char final_pres[8][16],
		unsigned char tags[8][16]);

void
pmac1_finalize_tag_one(const void *roundkey,
		const unsigned char sum[16],
		const unsigned char final_pre[16],
		unsigned char tag[16]);

#ifdef __cplusplus
}
#endif

#endif
