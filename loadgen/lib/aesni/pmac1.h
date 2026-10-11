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

#ifdef __cplusplus
}
#endif

#endif
