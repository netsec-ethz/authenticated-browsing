#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

#include <aesni/aesni.h>
#include <aesni/pmac1.h>

#define IPV6_NEXT_HEADER_DEST_OPTS 60
#define IPV6_NEXT_HEADER_UDP       17
#define IPV6_NEXT_HEADER_TCP        6
#define EXT_HDR_SIZE 24
#define EXT_OPT_TYPE 0x1E
#define EXT_OPT_LEN 20
#define EXT_HDR_EXT_LEN 2
#define EXT_NEXT_HDR_OFFSET 0
#define EXT_HDR_EXT_LEN_OFFSET 1
#define EXT_OPT_TYPE_OFFSET 2
#define EXT_OPT_LEN_OFFSET 3
#define EXT_IDPID_OFFSET 4
#define EXT_TIMEOUT_OFFSET 5
#define EXT_ERUID_OFFSET 7
#define EXT_PAD_OFFSET 14
#define EXT_MAC_OFFSET 16
#define EXT_MAC_SIZE 8

#define ETH_HDR_SIZE 14
#define IPV6_HDR_SIZE 40
#define UDP_HDR_SIZE 8
#define HEADERS_TO_UDP_PAYLOAD (ETH_HDR_SIZE + IPV6_HDR_SIZE + EXT_HDR_SIZE + UDP_HDR_SIZE)

#define AES_ROUNDKEY_SIZE (11 * 16)
#define PMAC_SCRATCH_SIZE 2048

/* Packet class tags (also written to identifier byte 0 for the receiver). */
#define AB_CLASS_LEGIT     1
#define AB_CLASS_NO_HEADER 2
#define AB_CLASS_MALFORMED 3
#define AB_CLASS_FORGED    4
#define AB_CLASS_REPLAY    5

/* Malformed sub-kinds (also written to identifier byte 1). */
#define AB_MAL_OPT_TYPE    0
#define AB_MAL_OPT_LEN     1
#define AB_MAL_TRUNCATED   2
#define AB_MAL_HDR_LEN     3
#define AB_MAL_MAC_GARBAGE 4
#define AB_MAL_RANDOM      5

struct ab_mac_ctx {
    uint8_t master_key[16];
    uint8_t master_roundkey[AES_ROUNDKEY_SIZE];
    uint8_t *pmac_scratch;
    uint64_t rng_state;
};

#define MAX_THREADS 128
struct ab_mac_ctx* contexts[MAX_THREADS];

static inline uint64_t
xorshift64(uint64_t *s)
{
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x ? x : 0x9E3779B97F4A7C15ULL;
    return *s;
}

/* Compute PMAC1 over `msg` of `msg_len` bytes, with the IPv6 mutable-field
 * mask applied (top nibble of byte 0 kept, bytes 1..3 and 7 zeroed). The
 * validator applies the same mask before verifying. The packet itself is
 * not modified — we mask in place and restore the saved bytes after.
 */
static inline int
pmac_compute(const uint8_t roundkey[AES_ROUNDKEY_SIZE],
             uint8_t *msg, size_t msg_len, uint8_t out[16])
{
    if (msg_len < 8)
        return -1;
    uint8_t b0 = msg[0], b1 = msg[1], b2 = msg[2], b3 = msg[3], b7 = msg[7];
    msg[0] = (uint8_t)(b0 & 0xF0);
    msg[1] = 0;
    msg[2] = 0;
    msg[3] = 0;
    msg[7] = 0;
    pmac1_aes128(roundkey, msg, msg_len, out);
    msg[0] = b0;
    msg[1] = b1;
    msg[2] = b2;
    msg[3] = b3;
    msg[7] = b7;
    return 0;
}

/* Write a valid PMAC tag into ext[EXT_MAC_OFFSET..+8]. */
static inline void
compute_and_write_mac(struct ab_mac_ctx *ctx,
                      const struct rte_ipv6_hdr *ip6,
                      uint16_t ipv6_plen,
                      uint8_t *ext)
{
    uint8_t der_input[16] = {0};
    memcpy(der_input, ext + EXT_ERUID_OFFSET, 7);
    memcpy(der_input + 7, ext + EXT_TIMEOUT_OFFSET, 2);
    der_input[9] = 0x80;

    uint8_t derived_key[16];
    CBCMAC(ctx->master_roundkey, 1, der_input, derived_key);

    uint8_t roundkey2[AES_ROUNDKEY_SIZE] __attribute__((aligned(16)));
    ExpandKey128(derived_key, roundkey2);

    memset(ext + EXT_MAC_OFFSET, 0, EXT_MAC_SIZE);
    uint8_t mac_out[16];
    uint32_t ipv6_total_len = (uint32_t)ipv6_plen + IPV6_HDR_SIZE;
    if (pmac_compute(roundkey2, (uint8_t *)ip6, ipv6_total_len, mac_out) != 0)
        return;
    memcpy(ext + EXT_MAC_OFFSET, mac_out, EXT_MAC_SIZE);
}

/* pack identifier: byte 0 = class, byte 1 = sub_kind, bytes 2..7 = seq.
 * Written as a little-endian uint64 so byte 0 lands first in memory. */
static inline uint64_t
pack_ident(uint8_t class_tag, uint8_t sub_kind, uint64_t seq)
{
    return ((uint64_t)class_tag)
         | ((uint64_t)sub_kind << 8)
         | ((seq & 0x0000FFFFFFFFFFFFULL) << 16);
}

void
ab_init_mac_ctx(int index, const uint8_t key[16])
{
    contexts[index] = rte_malloc(NULL, sizeof(struct ab_mac_ctx), 64);
    memcpy(contexts[index]->master_key, key, 16);
    ExpandKey128(contexts[index]->master_key, contexts[index]->master_roundkey);
    contexts[index]->pmac_scratch = NULL;  /* unused with in-place PMAC1 */
    /* Seed the RNG with a per-thread value so threads draw independent streams. */
    contexts[index]->rng_state = 0xA5A5A5A5DEADBEEFULL ^ ((uint64_t)(index + 1) * 0x9E3779B97F4A7C15ULL);
}

/* Backward-compatible entry point (pre-mix callers). */
void
ab_generate_mac_ipv6_ext(int index, struct rte_mbuf *m, uint16_t payload_len, uint8_t hdr_len)
{
    (void)hdr_len;
    struct ab_mac_ctx *ctx = contexts[index];
    uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(pkt + ETH_HDR_SIZE);
    uint8_t *ext = (uint8_t *)ip6 + IPV6_HDR_SIZE;
    compute_and_write_mac(ctx, ip6, payload_len, ext);
}

/* Build a mixed-traffic packet in place.
 *
 * The mbuf enters with the full legit template laid out
 * (eth + ip6 + ext + udp + payload), and pkt_len/data_len set by Lua.
 * ipv6_plen is the IPv6 payload length in the incoming buffer
 * (ext + udp + payload), i.e. pkt_len - ETH_HDR_SIZE - IPV6_HDR_SIZE.
 *
 * For AB_CLASS_NO_HEADER and AB_CLASS_MALFORMED/AB_MAL_TRUNCATED the mbuf
 * is shrunk (by 24 B and 10 B respectively); callers should not rely on
 * pkt_len being unchanged for those cases.
 */
void
ab_build_packet(int index,
                struct rte_mbuf *m,
                uint16_t ipv6_plen,
                uint8_t class_tag,
                uint8_t sub_kind,
                uint8_t idpid,
                uint16_t timeout,
                const uint8_t *eruid,
                uint64_t seq)
{
    struct ab_mac_ctx *ctx = contexts[index];
    uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(pkt + ETH_HDR_SIZE);
    uint8_t *ext = (uint8_t *)ip6 + IPV6_HDR_SIZE;
    uint8_t *udp_hdr = ext + EXT_HDR_SIZE;
    uint8_t *udp_payload = udp_hdr + UDP_HDR_SIZE;

    switch (class_tag) {
    case AB_CLASS_LEGIT:
    case AB_CLASS_REPLAY: {
        /* Populate ext header derivation inputs + ident, then sign. */
        ext[EXT_NEXT_HDR_OFFSET]   = IPV6_NEXT_HEADER_UDP;
        ext[EXT_HDR_EXT_LEN_OFFSET] = EXT_HDR_EXT_LEN;
        ext[EXT_OPT_TYPE_OFFSET]   = EXT_OPT_TYPE;
        ext[EXT_OPT_LEN_OFFSET]    = EXT_OPT_LEN;
        ext[EXT_IDPID_OFFSET]      = idpid;
        ext[EXT_TIMEOUT_OFFSET]    = (uint8_t)(timeout >> 8);
        ext[EXT_TIMEOUT_OFFSET+1]  = (uint8_t)(timeout & 0xff);
        memcpy(ext + EXT_ERUID_OFFSET, eruid, 7);
        ext[EXT_PAD_OFFSET]     = 0;
        ext[EXT_PAD_OFFSET + 1] = 0;

        uint64_t ident = pack_ident(class_tag, 0, seq);
        memcpy(udp_payload, &ident, 8);

        compute_and_write_mac(ctx, ip6, ipv6_plen, ext);
        break;
    }

    case AB_CLASS_FORGED: {
        /* Well-formed shape, random 8-byte tag, no PMAC. */
        ext[EXT_NEXT_HDR_OFFSET]   = IPV6_NEXT_HEADER_UDP;
        ext[EXT_HDR_EXT_LEN_OFFSET] = EXT_HDR_EXT_LEN;
        ext[EXT_OPT_TYPE_OFFSET]   = EXT_OPT_TYPE;
        ext[EXT_OPT_LEN_OFFSET]    = EXT_OPT_LEN;
        ext[EXT_IDPID_OFFSET]      = idpid;
        ext[EXT_TIMEOUT_OFFSET]    = (uint8_t)(timeout >> 8);
        ext[EXT_TIMEOUT_OFFSET+1]  = (uint8_t)(timeout & 0xff);
        memcpy(ext + EXT_ERUID_OFFSET, eruid, 7);
        ext[EXT_PAD_OFFSET]     = 0;
        ext[EXT_PAD_OFFSET + 1] = 0;

        uint64_t ident = pack_ident(class_tag, 0, seq);
        memcpy(udp_payload, &ident, 8);

        uint64_t r = xorshift64(&ctx->rng_state);
        memcpy(ext + EXT_MAC_OFFSET, &r, 8);
        break;
    }

    case AB_CLASS_NO_HEADER: {
        /* Shift udp+payload up 24 B and trim the mbuf to match so the
         * packet has consistent lengths at every layer.
         */
        size_t move_len = (size_t)ipv6_plen - EXT_HDR_SIZE; /* udp + data */
        memmove(ext, ext + EXT_HDR_SIZE, move_len);

        ip6->proto = IPV6_NEXT_HEADER_UDP;
        uint16_t new_ipv6_plen = ipv6_plen - EXT_HDR_SIZE;
        ip6->payload_len = rte_cpu_to_be_16(new_ipv6_plen);

        /* UDP length = udp_hdr + udp_payload = new IPv6 payload. */
        uint16_t udp_len_be = rte_cpu_to_be_16(new_ipv6_plen);
        memcpy(ext + 4, &udp_len_be, 2);
        ext[6] = 0;
        ext[7] = 0;

        /* Drop the 24 stale ext-header bytes off the tail. */
        m->pkt_len  -= EXT_HDR_SIZE;
        m->data_len -= EXT_HDR_SIZE;

        /* identifier at start of (new) UDP payload */
        uint64_t ident = pack_ident(class_tag, 0, seq);
        memcpy(ext + UDP_HDR_SIZE, &ident, 8);
        break;
    }

    case AB_CLASS_MALFORMED: {
        /* Start with a legit-shaped ext header, then corrupt. */
        ext[EXT_NEXT_HDR_OFFSET]   = IPV6_NEXT_HEADER_UDP;
        ext[EXT_HDR_EXT_LEN_OFFSET] = EXT_HDR_EXT_LEN;
        ext[EXT_OPT_TYPE_OFFSET]   = EXT_OPT_TYPE;
        ext[EXT_OPT_LEN_OFFSET]    = EXT_OPT_LEN;
        ext[EXT_IDPID_OFFSET]      = idpid;
        ext[EXT_TIMEOUT_OFFSET]    = (uint8_t)(timeout >> 8);
        ext[EXT_TIMEOUT_OFFSET+1]  = (uint8_t)(timeout & 0xff);
        memcpy(ext + EXT_ERUID_OFFSET, eruid, 7);
        ext[EXT_PAD_OFFSET]     = 0;
        ext[EXT_PAD_OFFSET + 1] = 0;

        /* Identifier goes in first (validator may or may not cover it,
         * but the receiver reads it from UDP payload either way). */
        uint64_t ident = pack_ident(class_tag, sub_kind, seq);
        memcpy(udp_payload, &ident, 8);

        switch (sub_kind) {
        case AB_MAL_OPT_TYPE: {
            /* Wrong option type; validator drops at header parse.
             * Garbage tag so we never accidentally emit a verifiable MAC. */
            ext[EXT_OPT_TYPE_OFFSET] = 0x42;
            uint64_t g = xorshift64(&ctx->rng_state);
            memcpy(ext + EXT_MAC_OFFSET, &g, 8);
            break;
        }

        case AB_MAL_OPT_LEN: {
            ext[EXT_OPT_LEN_OFFSET] = 10;
            uint64_t g = xorshift64(&ctx->rng_state);
            memcpy(ext + EXT_MAC_OFFSET, &g, 8);
            break;
        }

        case AB_MAL_TRUNCATED: {
            /* Shrink the mbuf tail while leaving ip6->payload_len
             * unchanged. The validator sees a packet shorter than
             * its own IPv6 payload_len claims and should drop.
             * The identifier at the start of UDP payload stays
             * readable because we only trim the trailing bytes.
             * We bail out of trimming if the payload is already so
             * small that trimming would eat the identifier. */
            uint16_t shrink = 10;
            uint16_t udp_payload_len = ipv6_plen - EXT_HDR_SIZE - UDP_HDR_SIZE;
            if (udp_payload_len > (uint16_t)(8 + shrink)) {
                m->pkt_len  -= shrink;
                m->data_len -= shrink;
            }
            uint64_t g = xorshift64(&ctx->rng_state);
            memcpy(ext + EXT_MAC_OFFSET, &g, 8);
            break;
        }

        case AB_MAL_HDR_LEN: {
            /* Claim 48-byte ext hdr while we only have 24. */
            ext[EXT_HDR_EXT_LEN_OFFSET] = 5;
            uint64_t g = xorshift64(&ctx->rng_state);
            memcpy(ext + EXT_MAC_OFFSET, &g, 8);
            break;
        }

        case AB_MAL_MAC_GARBAGE: {
            /* Valid shape, 8-byte tag is garbage. Distinct from FORGED
             * only in labelling — lets the receiver bucket separately. */
            uint64_t r = xorshift64(&ctx->rng_state);
            memcpy(ext + EXT_MAC_OFFSET, &r, 8);
            break;
        }

        case AB_MAL_RANDOM:
        default: {
            /* Fill entire ext hdr (past next_hdr) with random bytes. */
            uint64_t r0 = xorshift64(&ctx->rng_state);
            uint64_t r1 = xorshift64(&ctx->rng_state);
            uint64_t r2 = xorshift64(&ctx->rng_state);
            /* keep next_hdr = UDP so the packet advances to ext parse. */
            memcpy(ext + 1, (uint8_t *)&r0 + 0, 7);
            memcpy(ext + 8, &r1, 8);
            memcpy(ext + 16, &r2, 8);
            break;
        }
        }
        break;
    }

    default:
        /* Unknown class — fall through to a legit packet to fail safe. */
        compute_and_write_mac(ctx, ip6, ipv6_plen, ext);
        break;
    }
}

/* Wrap an incoming IPv6 TCP packet with the AB destination-options extension
 * header and sign it. The mbuf enters as
 *   eth | ip6(proto=TCP, plen=N) | tcp+data(N)
 * and leaves as
 *   eth | ip6(proto=DEST_OPTS, plen=N+24) | ext(24) | tcp+data(N)
 *
 * Returns 0 on success, -1 if the packet is not IPv6 TCP or the mbuf cannot
 * be grown (caller should forward the mbuf unchanged in that case).
 *
 * The IPv6 TCP pseudo-header uses only the upper-layer (TCP) length, not the
 * ext-header length, so the TCP checksum stays valid after insertion (RFC
 * 8200 §8.1). We intentionally do not recompute it. */
int
ab_wrap_packet(int index,
               struct rte_mbuf *m,
               uint8_t idpid,
               uint16_t timeout,
               const uint8_t *eruid)
{
    if (rte_pktmbuf_pkt_len(m) < ETH_HDR_SIZE + IPV6_HDR_SIZE)
        return -1;

    uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt;
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
        return -1;

    struct rte_ipv6_hdr *ip6_in = (struct rte_ipv6_hdr *)(pkt + ETH_HDR_SIZE);
    uint8_t orig_nh = ip6_in->proto;
    /* Only wrap TCP for the wrk2↔nginx path. Other L4s (ICMPv6 for NDP,
     * UDP, already-wrapped dest-opts) pass through untouched; the caller
     * still forwards them. */
    if (orig_nh != IPV6_NEXT_HEADER_TCP)
        return -1;

    /* Make room for the 24-byte ext header by prepending headroom, then
     * shift eth+ip6 left so they sit adjacent to the (empty) ext slot. */
    uint8_t *new_head = (uint8_t *)rte_pktmbuf_prepend(m, EXT_HDR_SIZE);
    if (new_head == NULL)
        return -1;
    memmove(new_head, new_head + EXT_HDR_SIZE, ETH_HDR_SIZE + IPV6_HDR_SIZE);

    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(new_head + ETH_HDR_SIZE);
    uint8_t *ext = (uint8_t *)ip6 + IPV6_HDR_SIZE;

    ext[EXT_NEXT_HDR_OFFSET]     = orig_nh;
    ext[EXT_HDR_EXT_LEN_OFFSET]  = EXT_HDR_EXT_LEN;
    ext[EXT_OPT_TYPE_OFFSET]     = EXT_OPT_TYPE;
    ext[EXT_OPT_LEN_OFFSET]      = EXT_OPT_LEN;
    ext[EXT_IDPID_OFFSET]        = idpid;
    ext[EXT_TIMEOUT_OFFSET]      = (uint8_t)(timeout >> 8);
    ext[EXT_TIMEOUT_OFFSET + 1]  = (uint8_t)(timeout & 0xff);
    memcpy(ext + EXT_ERUID_OFFSET, eruid, 7);
    ext[EXT_PAD_OFFSET]     = 0;
    ext[EXT_PAD_OFFSET + 1] = 0;

    uint16_t new_plen = (uint16_t)(rte_be_to_cpu_16(ip6->payload_len) + EXT_HDR_SIZE);
    ip6->payload_len = rte_cpu_to_be_16(new_plen);
    ip6->proto = IPV6_NEXT_HEADER_DEST_OPTS;

    compute_and_write_mac(contexts[index], ip6, new_plen, ext);
    return 0;
}

/* Per-thread generator state for ab_build_burst. */
#define AB_ALIAS_MAX 4096
struct ab_gen_state {
    uint8_t class_tbl[AB_ALIAS_MAX];
    uint8_t sub_tbl[AB_ALIAS_MAX];
    uint32_t alias_mask;
    uint32_t alias_idx;
    uint64_t seq[6];          /* per class tag (1..5) */
    uint32_t flow_counter;
    uint32_t flow_limit;
    uint16_t src_base;
    uint8_t thread_idx;
};
static struct ab_gen_state *gen_states[MAX_THREADS];

/* Install the shuffled (class, sub_kind) slot table and flow parameters for
 * generator thread `index`. alias_size must be a power of two. */
void
ab_gen_init(int index, const uint8_t *class_tbl, const uint8_t *sub_tbl,
            uint32_t alias_size, uint16_t src_base, uint32_t flow_limit)
{
    struct ab_gen_state *g = rte_zmalloc(NULL, sizeof(*g), 64);
    if (alias_size > AB_ALIAS_MAX)
        alias_size = AB_ALIAS_MAX;
    memcpy(g->class_tbl, class_tbl, alias_size);
    memcpy(g->sub_tbl, sub_tbl, alias_size);
    g->alias_mask = alias_size - 1;
    g->flow_limit = flow_limit ? flow_limit : 1;
    g->src_base = src_base;
    g->thread_idx = (uint8_t)index;
    gen_states[index] = g;
}

/* eruid = "dead" || (thread_idx + 1) || low 4 bytes of seq (little endian).
 * The prefix and nonzero thread byte keep the ID away from degenerate
 * all-zero patterns; the sequence bytes rotate the derived key every packet
 * so the validator's per-packet key derivation is exercised. 4 bytes of seq
 * (not 2) keep the MAC input from cycling within the dedup retention window:
 * with 2 bytes, legit packets genuinely repeated after ~400 K packets per
 * thread and showed up as duplicates. */
static inline void
fill_eruid(uint8_t eruid[7], uint8_t thread_idx, uint64_t seq)
{
    eruid[0] = 0xde;
    eruid[1] = 0xad;
    eruid[2] = (uint8_t)(thread_idx + 1);
    eruid[3] = (uint8_t)(seq);
    eruid[4] = (uint8_t)(seq >> 8);
    eruid[5] = (uint8_t)(seq >> 16);
    eruid[6] = (uint8_t)(seq >> 24);
}

/* Build a whole burst of mixed-class packets: per packet, rotate the UDP
 * source port over the thread's flows, take the next (class, sub_kind) slot
 * from the shuffled alias table, pick sequence number, eruid and timeout for
 * that class, then fill the packet with ab_build_packet. This runs in C, one
 * call per burst, because branching on the class per packet in Lua made the
 * offered rate depend on the traffic mix (see abgen.lua gen()).
 *
 * All classes carry the template's idpid, so attack packets fail the
 * intended check (ext header parse or MAC) rather than an idpid pre-filter. */
void
ab_build_burst(int index, struct rte_mbuf **bufs, uint32_t n)
{
    struct ab_gen_state *g = gen_states[index];
    const uint8_t idpid = 0x11;   /* matches the pcap template */
    uint8_t eruid[7];

    for (uint32_t i = 0; i < n; i++) {
        struct rte_mbuf *m = bufs[i];
        uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);
        uint8_t *udp_src = pkt + ETH_HDR_SIZE + IPV6_HDR_SIZE + EXT_HDR_SIZE;

        uint16_t src = rte_cpu_to_be_16((uint16_t)(g->src_base + g->flow_counter));
        memcpy(udp_src, &src, 2);
        g->flow_counter = (g->flow_counter + 1 >= g->flow_limit) ? 0 : g->flow_counter + 1;

        uint8_t cls = g->class_tbl[g->alias_idx];
        uint8_t sub = g->sub_tbl[g->alias_idx];
        g->alias_idx = (g->alias_idx + 1) & g->alias_mask;

        uint64_t seq;
        uint16_t timeout;
        switch (cls) {
        case AB_CLASS_LEGIT:
            seq = g->seq[AB_CLASS_LEGIT]++;
            fill_eruid(eruid, g->thread_idx, seq);
            /* Slow-rotating timeout, always in [1, 65535]. */
            timeout = (uint16_t)(1 + (seq / 256) % 65535);
            break;
        case AB_CLASS_NO_HEADER:
            seq = g->seq[AB_CLASS_NO_HEADER]++;
            memset(eruid, 0, sizeof(eruid));
            timeout = 0;
            break;
        case AB_CLASS_MALFORMED:
            seq = g->seq[AB_CLASS_MALFORMED]++;
            fill_eruid(eruid, g->thread_idx, seq);
            timeout = 1;
            break;
        case AB_CLASS_FORGED:
            seq = g->seq[AB_CLASS_FORGED]++;
            fill_eruid(eruid, g->thread_idx, seq);
            timeout = 1;
            break;
        case AB_CLASS_REPLAY: {
            /* Every replay packet is bit-identical: canonical seq, eruid,
             * timeout and source port, independent of the thread. */
            static const uint8_t replay_eruid[7] = { 0xde, 0xad, 0x01, 0, 0, 0, 0x01 };
            seq = 0;
            memcpy(eruid, replay_eruid, sizeof(eruid));
            timeout = 1;
            src = rte_cpu_to_be_16(g->src_base);
            memcpy(udp_src, &src, 2);
            break;
        }
        default:
            /* Unreachable; fall back to legit parameters. */
            seq = g->seq[AB_CLASS_LEGIT]++;
            fill_eruid(eruid, g->thread_idx, seq);
            timeout = 1;
            break;
        }

        ab_build_packet(index, m, (uint16_t)(m->pkt_len - ETH_HDR_SIZE - IPV6_HDR_SIZE),
                        cls, sub, idpid, timeout, eruid, seq);
    }
}
