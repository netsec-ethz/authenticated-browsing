#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>   /* getentropy() for the dedup index key */

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#ifdef AB_PER_CLASS_STATS
#include <rte_telemetry.h>
#endif

#include <aesni.h>
#include <pmac1.h>

/* 4096 RX descriptors was ~1% slower (DDIO). The larger TX ring absorbs
 * short NIC TX stalls. */
#define RX_RING_SIZE 2048
#define TX_RING_SIZE 4096
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 64

#define IPV6_NEXT_HEADER_DEST_OPTS 60
#define IPV6_NEXT_HEADER_UDP 17
#define EXT_HDR_SIZE 24
#define EXT_OPT_TYPE 0x1E
#define EXT_OPT_LEN 20
#define EXT_IDPID_OFFSET 4
#define EXT_TIMEOUT_OFFSET 5
#define EXT_ERUID_OFFSET 7
#define EXT_PAD_OFFSET 14
#define EXT_MAC_OFFSET 16
#define EXT_MAC_SIZE 8

#define ETH_HDR_SIZE 14
#define IPV6_HDR_SIZE 40
#define UDP_HDR_SIZE 8

#define AES_ROUNDKEY_SIZE (11 * 16)

/* Per-class counters (make PER_CLASS_STATS=1). The loadgen writes the class
 * into UDP payload byte 0, see loadgen/abgen.c. */
#ifdef AB_PER_CLASS_STATS
#define AB_CLASS_MAX      6
#define AB_CLASS_UNKNOWN  0
#define AB_CLASS_LEGIT    1
#define AB_CLASS_NO_HDR   2
#define AB_CLASS_MALFORM  3
#define AB_CLASS_FORGED   4
#define AB_CLASS_REPLAY   5
static const char *const ab_class_names[AB_CLASS_MAX] = {
    "unknown", "legit", "no_header", "malformed", "forged", "replay",
};
#endif

static volatile bool force_quit = false;
/* STRIP_ONLY: skip PMAC and dedup, only strip the ext header. */
static bool g_strip_only = false;
/* RAW_FORWARD: bridge ports do a plain L2 forward. Baseline for RAW_FWD=1 on the loadgen. */
static bool g_raw_forward = false;

struct worker_stats {
    uint64_t rx_pkts;
    uint64_t tx_pkts;
    uint64_t reject_pkts;   /* validator-side drops: parse/lookup/dedup/PMAC */
    uint64_t tx_full_pkts;  /* tx_burst returned < submitted (queue full) */
#ifdef AB_PER_CLASS_STATS
    uint64_t rx_by_class[AB_CLASS_MAX];
    uint64_t tx_by_class[AB_CLASS_MAX];
#endif
} __rte_cache_aligned;
/* Cumulative; the reporter diffs against g_stats_prev for per-second rates. */
static struct worker_stats g_stats[RTE_MAX_LCORE] __rte_cache_aligned;
static struct worker_stats g_stats_prev[RTE_MAX_LCORE] __rte_cache_aligned;
/* Port of each worker, so the reporter can show per-port RSS imbalance. */
static uint16_t g_worker_port[RTE_MAX_LCORE];
static uint16_t g_nb_workers;

#ifdef AB_PER_CLASS_STATS
/* Class tag is the first UDP payload byte, with or without the ext header.
 * Expects a linear mbuf. */
static inline uint8_t
ab_extract_class(const uint8_t *pkt, uint32_t pkt_len, uint8_t ip6_proto)
{
    uint32_t off;
    if (ip6_proto == IPV6_NEXT_HEADER_DEST_OPTS)
        off = ETH_HDR_SIZE + IPV6_HDR_SIZE + EXT_HDR_SIZE + UDP_HDR_SIZE;
    else if (ip6_proto == IPV6_NEXT_HEADER_UDP)
        off = ETH_HDR_SIZE + IPV6_HDR_SIZE + UDP_HDR_SIZE;
    else
        return AB_CLASS_UNKNOWN;
    if (pkt_len <= off)
        return AB_CLASS_UNKNOWN;
    uint8_t tag = pkt[off];
    return tag < AB_CLASS_MAX ? tag : AB_CLASS_UNKNOWN;
}

/* /ab/stats: per-class rx/tx totals summed over workers. */
static int
ab_telemetry_stats(const char *cmd __rte_unused,
                   const char *params __rte_unused,
                   struct rte_tel_data *d)
{
    uint64_t rx[AB_CLASS_MAX] = {0};
    uint64_t tx[AB_CLASS_MAX] = {0};
    uint64_t rx_total = 0, tx_total = 0;
    for (uint16_t i = 0; i < RTE_MAX_LCORE; i++) {
        rx_total += g_stats[i].rx_pkts;
        tx_total += g_stats[i].tx_pkts;
        for (uint32_t c = 0; c < AB_CLASS_MAX; c++) {
            rx[c] += g_stats[i].rx_by_class[c];
            tx[c] += g_stats[i].tx_by_class[c];
        }
    }
    rte_tel_data_start_dict(d);
    rte_tel_data_add_dict_uint(d, "rx_total", rx_total);
    rte_tel_data_add_dict_uint(d, "tx_total", tx_total);
    for (uint32_t c = 0; c < AB_CLASS_MAX; c++) {
        char key[64];
        snprintf(key, sizeof(key), "%s_rx", ab_class_names[c]);
        rte_tel_data_add_dict_uint(d, key, rx[c]);
        snprintf(key, sizeof(key), "%s_tx", ab_class_names[c]);
        rte_tel_data_add_dict_uint(d, key, tx[c]);
    }
    return 0;
}
#endif
struct key_entry {
    uint8_t addr[16];
    uint8_t key[16];
    uint8_t roundkey[AES_ROUNDKEY_SIZE];
    uint64_t dedup_mul;   /* secret, odd: per-destination dedup index key */
    bool used;
};

#define KEY_TABLE_SIZE 512
static struct key_entry g_key_table[KEY_TABLE_SIZE];
static uint8_t g_default_roundkey[AES_ROUNDKEY_SIZE];
static bool g_has_default_key = false;

/* Per-socket copies of the key tables, so workers on socket 1 don't read
 * keys across QPI. Read-only after startup. */
static struct key_entry *g_key_table_numa[RTE_MAX_NUMA_NODES];
static uint8_t *g_default_roundkey_numa[RTE_MAX_NUMA_NODES];

/* Per-worker cache of derived round keys, indexed by the derivation input
 * (ERUID || timeout || pad). Packets from one source share it, which saves
 * the CBCMAC + key expansion. */
#define DK_CACHE_SHIFT 6
#define DK_CACHE_SIZE (1u << DK_CACHE_SHIFT)
#define DK_CACHE_MASK (DK_CACHE_SIZE - 1)

struct dk_cache_entry {
    uint8_t der_input[16];
    const uint8_t *master_rk;
    uint8_t roundkey[AES_ROUNDKEY_SIZE] __attribute__((aligned(16)));
    bool valid;
} __rte_cache_aligned;

struct dk_cache {
    struct dk_cache_entry entries[DK_CACHE_SIZE];
} __rte_cache_aligned;

static inline uint32_t
dk_cache_hash(const uint8_t der_input[16])
{
    uint32_t v;
    memcpy(&v, der_input, 4);
    v ^= (uint32_t)der_input[4] << 8;
    v ^= (uint32_t)der_input[7] << 16;
    v *= 2654435761u; /* Knuth multiplicative hash */
    return (v >> (32 - DK_CACHE_SHIFT)) & DK_CACHE_MASK;
}

/*
 * Per-worker replay table: 4-way set-associative on the 8-byte MAC tag,
 * round-robin eviction, one cache line per set. Per-worker is fine because
 * RSS sends a replayed packet to the same queue as the original.
 * 2^18 sets x 4 ways = 1M tags, 16 MB per worker.
 */
#define DEDUP_SET_BITS 18u
#define DEDUP_NUM_SETS (1u << DEDUP_SET_BITS)
#define DEDUP_SET_MASK (DEDUP_NUM_SETS - 1u)
#define DEDUP_WAYS 4u

/* The dedup set index is keyed by a secret, odd multiplier (Dietzfelbinger
 * multiply-shift). The 8-byte MAC tag is public (it rides on the wire), so
 * indexing by raw tag bits lets an attacker bucket replay packets into the
 * same set off-line and cycle 5+ of them past the 4-way round-robin eviction.
 * Mixing with a secret multiplier makes the set assignment unpredictable: the
 * tag distribution is independent of the multiplier and the appliance gives the
 * sender no accept/reject feedback, so an off-line attacker gains zero
 * information about which tags collide.
 *
 * The multiplier is PER DESTINATION (stored in key_entry.dedup_mul, seeded at
 * insert): otherwise an attacker who controls one destination could run a
 * dedup oracle against their own host, recover the single secret, and then
 * off-line-bucket every other host. Per-destination keys contain that to the
 * compromised host. This global is only the fallback for default-key traffic
 * (which already shares one key, hence one trust domain). MUST stay secret and
 * independent of the PMAC key. */
static uint64_t g_default_dedup_mul;

struct dedup_set {
    uint64_t tags[DEDUP_WAYS];   /* 0 = empty */
    uint32_t next_way;
    uint32_t pad[7];             /* one cache line */
} __rte_cache_aligned;

struct dedup_table {
    struct dedup_set sets[DEDUP_NUM_SETS];
};

/* Top DEDUP_SET_BITS of tag * mul. */
static inline uint32_t __attribute__((always_inline))
dedup_set_index(uint64_t tag, uint64_t mul)
{
    return (uint32_t)((tag * mul) >> (64 - DEDUP_SET_BITS));
}

/* 1 if the tag was seen before. Does not insert. */
static inline int __attribute__((always_inline))
dedup_check(struct dedup_table *t, const uint8_t mac[8], uint64_t mul)
{
    uint64_t tag;
    memcpy(&tag, mac, 8);

    uint32_t idx = dedup_set_index(tag, mul);
    struct dedup_set *set = &t->sets[idx];

    if (__builtin_expect(set->tags[0] == tag, 0)) return 1;
    if (__builtin_expect(set->tags[1] == tag, 0)) return 1;
    if (__builtin_expect(set->tags[2] == tag, 0)) return 1;
    if (__builtin_expect(set->tags[3] == tag, 0)) return 1;
    return 0;
}

/* Only call after the MAC verified. */
static inline void __attribute__((always_inline))
dedup_insert(struct dedup_table *t, const uint8_t mac[8], uint64_t mul)
{
    uint64_t tag;
    memcpy(&tag, mac, 8);

    uint32_t idx = dedup_set_index(tag, mul);
    struct dedup_set *set = &t->sets[idx];

    set->tags[set->next_way & 3u] = tag;
    set->next_way++;
}

struct worker_burst_data {
    int results[BURST_SIZE];
    const uint8_t *master_roundkeys[BURST_SIZE];
    uint64_t dedup_mul[BURST_SIZE];   /* per-destination dedup index key */
    uint8_t *mac_fields[BURST_SIZE];
    uint8_t mac_expected[BURST_SIZE][EXT_MAC_SIZE];
    uint8_t mac_out[BURST_SIZE][16];
    uint16_t ipv6_total_len[BURST_SIZE];
    uint8_t *ip6_ptrs[BURST_SIZE];
    uint8_t roundkeys2[BURST_SIZE][AES_ROUNDKEY_SIZE] __attribute__((aligned(16)));
    uint8_t pmac_L[BURST_SIZE][16] __attribute__((aligned(16)));
#ifdef AB_PER_CLASS_STATS
    uint8_t class_tag[BURST_SIZE];
#endif
} __rte_cache_aligned;

enum worker_mode {
    MODE_BOUNCE = 0,        /* validate, send back out the same port */
    MODE_VALIDATE_STRIP,    /* -b ingress side: validate, strip ext header, send to peer */
    MODE_BRIDGE_ONLY,       /* -b egress side: plain L2 forward to peer (server replies) */
};

struct worker_ctx {
    uint16_t port_id;
    uint16_t queue_id;
    uint16_t egress_port_id;
    enum worker_mode mode;
    struct rte_ether_addr dst_mac;
    struct rte_ether_addr src_mac;
    uint16_t worker_idx;
    /* Socket-local key tables, never NULL. */
    const struct key_entry *key_table;
    const uint8_t *default_roundkey;
    struct worker_burst_data *burst;
    struct dedup_table *dedup;
    /* Coalesces several RX bursts into one TX burst: fewer descriptor
     * write-backs over PCIe. */
    struct rte_eth_dev_tx_buffer *tx_buffer;
} __rte_cache_aligned;

/* From -b: peer port (-1 if unpaired), and whether this side validates. */
static int16_t g_port_peer[RTE_MAX_ETHPORTS];
static int8_t  g_port_validate[RTE_MAX_ETHPORTS];

static void __rte_unused
dump_hex(const char *label, const uint8_t *buf, size_t len)
{
    fprintf(stderr, "%s (%zu): ", label, len);
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, "%02x", buf[i]);
    fprintf(stderr, "\n");
}

/* Key table hash: CRC32C over the IPv6 address. */
#include <nmmintrin.h>
static inline uint32_t
addr_hash16(const uint8_t *data)
{
    uint64_t a, b;
    memcpy(&a, data, 8);
    memcpy(&b, data + 8, 8);
    uint64_t h = _mm_crc32_u64(0, a);
    return (uint32_t)_mm_crc32_u64(h, b);
}

/* Falls back to the default key (or NULL if there is none). */
static inline const uint8_t *
lookup_roundkey_for_dst(const uint8_t dst_addr[16],
                        const struct key_entry *table,
                        const uint8_t *default_rk,
                        uint64_t *dedup_mul_out)
{
    uint32_t mask = KEY_TABLE_SIZE - 1;
    uint32_t h = addr_hash16(dst_addr);
    for (uint32_t i = 0; i < KEY_TABLE_SIZE; i++) {
        uint32_t idx = (h + i) & mask;
        if (!table[idx].used)
            break;
        if (memcmp(table[idx].addr, dst_addr, 16) == 0) {
            *dedup_mul_out = table[idx].dedup_mul;
            return table[idx].roundkey;
        }
    }
    *dedup_mul_out = g_default_dedup_mul;
    return g_has_default_key ? default_rk : NULL;
}

static int
hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len < out_len * 2)
        return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte = 0;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1)
            return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

static int
insert_key_entry(const uint8_t addr[16], const uint8_t key[16])
{
    uint32_t mask = KEY_TABLE_SIZE - 1;
    uint32_t h = addr_hash16(addr);
    for (uint32_t i = 0; i < KEY_TABLE_SIZE; i++) {
        uint32_t idx = (h + i) & mask;
        if (!g_key_table[idx].used) {
            memcpy(g_key_table[idx].addr, addr, 16);
            memcpy(g_key_table[idx].key, key, 16);
            ExpandKey128(key, g_key_table[idx].roundkey);
            /* Per-destination secret dedup index key, from the OS CSPRNG.
             * Independent of the PMAC key and odd for the multiply-shift. */
            if (getentropy(&g_key_table[idx].dedup_mul,
                           sizeof(g_key_table[idx].dedup_mul)) != 0)
                return -1;
            g_key_table[idx].dedup_mul |= 1ull;
            g_key_table[idx].used = true;
            return 0;
        }
    }
    return -1;
}

static int
load_keys_from_json(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return -1;
    }
    char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    const char *p = buf;
    while ((p = strchr(p, '"')) != NULL) {
        const char *k_start = p + 1;
        const char *k_end = strchr(k_start, '"');
        if (!k_end)
            break;
        size_t k_len = (size_t)(k_end - k_start);
        char key_name[128];
        if (k_len >= sizeof(key_name)) {
            p = k_end + 1;
            continue;
        }
        memcpy(key_name, k_start, k_len);
        key_name[k_len] = '\0';
        p = k_end + 1;

        const char *colon = strchr(p, ':');
        if (!colon)
            break;
        const char *v_start = strchr(colon, '"');
        if (!v_start)
            break;
        v_start++;
        const char *v_end = strchr(v_start, '"');
        if (!v_end)
            break;
        size_t v_len = (size_t)(v_end - v_start);
        char val[128];
        if (v_len >= sizeof(val)) {
            p = v_end + 1;
            continue;
        }
        memcpy(val, v_start, v_len);
        val[v_len] = '\0';
        p = v_end + 1;

        uint8_t key_bytes[16];
        if (hex_to_bytes(val, key_bytes, 16) != 0)
            continue;

        if (strcmp(key_name, "default") == 0) {
            ExpandKey128(key_bytes, g_default_roundkey);
            g_has_default_key = true;
            continue;
        }

        uint8_t addr[16];
        if (inet_pton(AF_INET6, key_name, addr) == 1) {
            (void)insert_key_entry(addr, key_bytes);
        }
    }

    return g_has_default_key ? 0 : -1;
}

/* PMAC1 over the IPv6 header + payload, in place. The mutable IPv6 fields
 * (traffic class, flow label, hop limit) are zeroed for the MAC and restored
 * afterwards, as on the sender. L = AES_K(0) comes from stage 3.
 * The caller zeroes the MAC field. */
static inline int __attribute__((always_inline))
pmac_compute_with_L(const uint8_t roundkey[AES_ROUNDKEY_SIZE],
                    const uint8_t L[16],
                    uint8_t *msg, size_t msg_len, uint8_t out[16])
{
    if (__builtin_expect(msg_len < 8, 0))
        return -1;
    uint8_t b0 = msg[0], b1 = msg[1], b2 = msg[2], b3 = msg[3], b7 = msg[7];
    msg[0] = (uint8_t)(b0 & 0xF0);
    msg[1] = 0;
    msg[2] = 0;
    msg[3] = 0;
    msg[7] = 0;
    pmac1_aes128_with_L(roundkey, L, msg, msg_len, out);
    msg[0] = b0;
    msg[1] = b1;
    msg[2] = b2;
    msg[3] = b3;
    msg[7] = b7;
    return 0;
}


static void
handle_signal(int sig)
{
    if (sig == SIGINT || sig == SIGTERM)
        force_quit = true;
}

static int
read_mac_from_file(const char *path, struct rte_ether_addr *out)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '\n' || *p == '#')
            continue;

        if (strncmp(p, "mac=", 4) == 0)
            p += 4;

        char *end = p;
        while (*end && *end != '\n' && *end != '\r')
            end++;
        *end = '\0';

        if (rte_ether_unformat_addr(p, out) == 0) {
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    fprintf(stderr, "No valid MAC found in %s\n", path);
    return -1;
}


static inline int __attribute__((always_inline))
mac_equal8(const uint8_t *a, const uint8_t *b)
{
    /* one 64-bit compare, so no early exit per byte */
    uint64_t av, bv;
    memcpy(&av, a, 8);
    memcpy(&bv, b, 8);
    return av == bv;
}

enum mac_check_result {
    MAC_CHECK_OK = 1,
    MAC_CHECK_INVALID = 0,
    MAC_CHECK_BATCHED_OK = 2   /* stage 5 only: verified by the batched path */
};

static void
program_rss_reta(uint16_t port, uint16_t nb_queues)
{
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port, &dev_info);
    if (dev_info.reta_size == 0)
        return;

    /* RETA entries come in groups of 64; max defined by DPDK is 512 */
    uint16_t nb_groups = dev_info.reta_size / RTE_ETH_RETA_GROUP_SIZE;
    struct rte_eth_rss_reta_entry64 reta[RTE_ETH_RSS_RETA_SIZE_512 / RTE_ETH_RETA_GROUP_SIZE];
    memset(reta, 0, sizeof(reta));
    for (uint16_t g = 0; g < nb_groups; g++) {
        reta[g].mask = UINT64_MAX;
        for (uint16_t e = 0; e < RTE_ETH_RETA_GROUP_SIZE; e++)
            reta[g].reta[e] = (uint16_t)((g * RTE_ETH_RETA_GROUP_SIZE + e) % nb_queues);
    }
    if (rte_eth_dev_rss_reta_update(port, reta, dev_info.reta_size) != 0) {
        fprintf(stderr, "[warn] port %u: RETA update failed\n", port);
        return;
    }
    fprintf(stderr, "[dbg] port %u: RETA programmed (%u entries, %u queues)\n",
            port, dev_info.reta_size, nb_queues);

    /* read back, some NICs ignore the update silently */
    struct rte_eth_rss_reta_entry64 rb[RTE_ETH_RSS_RETA_SIZE_512 / RTE_ETH_RETA_GROUP_SIZE];
    memset(rb, 0, sizeof(rb));
    for (uint16_t g = 0; g < nb_groups; g++)
        rb[g].mask = UINT64_MAX;
    if (rte_eth_dev_rss_reta_query(port, rb, dev_info.reta_size) != 0) {
        fprintf(stderr, "[warn] port %u: RETA readback failed\n", port);
        return;
    }
    uint16_t queue_hits[RTE_MAX_QUEUES_PER_PORT] = {0};
    bool mismatch = false;
    for (uint16_t g = 0; g < nb_groups; g++) {
        for (uint16_t e = 0; e < RTE_ETH_RETA_GROUP_SIZE; e++) {
            uint16_t idx = (uint16_t)(g * RTE_ETH_RETA_GROUP_SIZE + e);
            uint16_t expected = (uint16_t)(idx % nb_queues);
            uint16_t actual = rb[g].reta[e];
            if (actual != expected) mismatch = true;
            if (actual < nb_queues) queue_hits[actual]++;
        }
    }
    fprintf(stderr, "[dbg] port %u: RETA readback queue distribution%s:",
            port, mismatch ? " (MISMATCH!)" : "");
    for (uint16_t q = 0; q < nb_queues; q++)
        fprintf(stderr, " q%u=%u", q, queue_hits[q]);
    fprintf(stderr, "\n");
}

/* Same RSS key on every port; firmware defaults differ between cards. */
static const uint8_t RSS_KEY[52] = {
    0x44, 0x39, 0x79, 0x6b, 0xb5, 0x4c, 0x50, 0x23,
    0xb6, 0x75, 0xea, 0x5b, 0x12, 0x4f, 0x9f, 0x30,
    0xb8, 0xa2, 0xc0, 0x3d, 0xdf, 0xdc, 0x4d, 0x02,
    0xa0, 0x8c, 0x9b, 0x33, 0x4a, 0xf6, 0x4a, 0x4c,
    0x05, 0xc6, 0xfa, 0x34, 0x39, 0x58, 0xd8, 0x55,
    0x7d, 0x99, 0x58, 0x3a, 0xe1, 0x38, 0xc9, 0x2e,
    0x81, 0x15, 0x03, 0x66,
};

static int
port_init(uint16_t port, struct rte_mempool *mbuf_pool,
          uint16_t rx_rings, uint16_t tx_rings, uint64_t rss_hf,
          uint64_t rx_offloads, uint64_t tx_offloads)
{
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf;
    struct rte_eth_dev_info di;
    rte_eth_dev_info_get(port, &di);
    uint8_t key_len = di.hash_key_size ? di.hash_key_size : (uint8_t)sizeof(RSS_KEY);
    if (key_len > sizeof(RSS_KEY)) key_len = (uint8_t)sizeof(RSS_KEY);
    port_conf.rx_adv_conf.rss_conf.rss_key = (uint8_t *)(uintptr_t)RSS_KEY;
    port_conf.rx_adv_conf.rss_conf.rss_key_len = key_len;
    port_conf.rxmode.offloads = rx_offloads;
    port_conf.txmode.offloads = tx_offloads;

    int retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval < 0)
        return retval;

    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                                        rte_eth_dev_socket_id(port),
                                        NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    for (uint16_t q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                                        rte_eth_dev_socket_id(port),
                                        NULL);
        if (retval < 0)
            return retval;
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    rte_eth_promiscuous_enable(port);
    return 0;
}

static inline void __attribute__((always_inline))
prefetch_mbuf(struct rte_mbuf *m)
{
    /* First 256 bytes: headers for stages 1-4, start of the body for the
     * PMAC. The HW prefetcher handles the rest of larger packets. */
    char *p = rte_pktmbuf_mtod(m, char *);
    rte_prefetch0(p);
    rte_prefetch0(p + 64);
    rte_prefetch0(p + 128);
    rte_prefetch0(p + 192);
}

/* Prints per-second stats from the main lcore. Not needed for forwarding. */
static int
reporter_loop(void *arg __attribute__((unused)))
{
    uint64_t last_tsc = rte_rdtsc();
    const uint64_t hz = rte_get_timer_hz();
    const uint64_t stat_interval = hz; /* 1 second */
    while (__builtin_expect(!force_quit, 1)) {
        uint64_t now = rte_rdtsc();
        if (now - last_tsc < stat_interval) {
            rte_pause();
            continue;
        }
        last_tsc = now;

        uint64_t worker_rx = 0, worker_tx = 0;
        uint64_t worker_reject = 0, worker_tx_full = 0;
        uint64_t per_port_min[RTE_MAX_ETHPORTS];
        uint64_t per_port_max[RTE_MAX_ETHPORTS] = {0};
        uint64_t per_port_sum[RTE_MAX_ETHPORTS] = {0};
        uint16_t per_port_n[RTE_MAX_ETHPORTS] = {0};
        for (int p = 0; p < RTE_MAX_ETHPORTS; p++)
            per_port_min[p] = UINT64_MAX;
        for (uint16_t i = 0; i < g_nb_workers && i < RTE_MAX_LCORE; i++) {
            struct worker_stats cur = g_stats[i];
            uint64_t drx = cur.rx_pkts - g_stats_prev[i].rx_pkts;
            uint64_t dtx = cur.tx_pkts - g_stats_prev[i].tx_pkts;
            worker_rx += drx;
            worker_tx += dtx;
            worker_reject += cur.reject_pkts - g_stats_prev[i].reject_pkts;
            worker_tx_full += cur.tx_full_pkts - g_stats_prev[i].tx_full_pkts;
            g_stats_prev[i] = cur;
            uint16_t pid = g_worker_port[i];
            if (pid < RTE_MAX_ETHPORTS) {
                per_port_sum[pid] += drx;
                per_port_n[pid]++;
                if (drx < per_port_min[pid]) per_port_min[pid] = drx;
                if (drx > per_port_max[pid]) per_port_max[pid] = drx;
            }
        }

        char buf[1024];
        int off = 0;
        off += snprintf(buf + off, sizeof(buf) - off,
                "[stats] worker_rx=%" PRIu64 " worker_tx=%" PRIu64
                " reject=%" PRIu64 " tx_full=%" PRIu64
                " (delta, 1s)\n",
                worker_rx, worker_tx, worker_reject, worker_tx_full);
        uint16_t pid;
        RTE_ETH_FOREACH_DEV(pid) {
            struct rte_eth_stats es;
            if (rte_eth_stats_get(pid, &es) != 0)
                continue;
            uint64_t avg = per_port_n[pid]
                    ? per_port_sum[pid] / per_port_n[pid] : 0;
            uint64_t mn = (per_port_min[pid] == UINT64_MAX)
                    ? 0 : per_port_min[pid];
            off += snprintf(buf + off, sizeof(buf) - off,
                    "[stats] port=%u ipkts=%" PRIu64 " opkts=%" PRIu64
                    " imissed=%" PRIu64 " ierr=%" PRIu64
                    " oerr=%" PRIu64 " rx_nombuf=%" PRIu64
                    " worker_rx[min=%" PRIu64 " avg=%" PRIu64
                    " max=%" PRIu64 " n=%u]\n",
                    pid, es.ipackets, es.opackets, es.imissed,
                    es.ierrors, es.oerrors, es.rx_nombuf,
                    mn, avg, per_port_max[pid], per_port_n[pid]);
            if (off >= (int)sizeof(buf) - 384) break;
        }
        fputs(buf, stdout);
        fflush(stdout);
    }
    return 0;
}

/* Stage 3 inputs for packets [i0, i0 + n): master key and ERUID || timeout
 * || 0x80. Already-invalid packets get the default key and a zero input so
 * the batch never touches a bad pointer; their output is ignored. */
static inline __attribute__((always_inline)) void
derive_lanes_fill(const struct worker_ctx *ctx, struct worker_burst_data *bd,
                  uint16_t i0, int n, const void **mrks,
                  unsigned char (*inputs)[16], unsigned char **outs)
{
    for (int k = 0; k < n; k++) {
        int valid = (bd->results[i0 + k] == MAC_CHECK_OK);
        mrks[k] = valid ? bd->master_roundkeys[i0 + k]
                        : (const void *)ctx->default_roundkey;
        memset(inputs[k], 0, 16);
        if (valid) {
            uint8_t *ext = bd->ip6_ptrs[i0 + k] + sizeof(struct rte_ipv6_hdr);
            memcpy(inputs[k], ext + EXT_ERUID_OFFSET, 7);
            memcpy(inputs[k] + 7, ext + EXT_TIMEOUT_OFFSET, 2);
            inputs[k][9] = 0x80;
        }
        outs[k] = bd->roundkeys2[i0 + k];
    }
}

/* Stage 5, 4 or 8 packets per PMAC call. Same masking as pmac_compute_with_L. */
static inline __attribute__((always_inline)) void
verify_pmac_batch(struct worker_burst_data *bd, const uint16_t *idx, const int n)
{
    const void *rks[8];
    const unsigned char *msgs[8];
    size_t lens[8];
    uint8_t saved[8][5];
    unsigned char tags[8][16];
    unsigned char Ls[8][16];
    for (int k = 0; k < n; k++) {
        uint16_t i = idx[k];
        uint8_t *msg = bd->ip6_ptrs[i];
        memset(bd->mac_fields[i], 0, EXT_MAC_SIZE);
        saved[k][0] = msg[0]; saved[k][1] = msg[1];
        saved[k][2] = msg[2]; saved[k][3] = msg[3];
        saved[k][4] = msg[7];
        msg[0] = (uint8_t)(msg[0] & 0xF0);
        msg[1] = 0; msg[2] = 0; msg[3] = 0; msg[7] = 0;
        rks[k] = bd->roundkeys2[i];
        msgs[k] = msg;
        lens[k] = bd->ipv6_total_len[i];
        memcpy(Ls[k], bd->pmac_L[i], 16);
    }
    if (n == 8)
        pmac1_aes128_with_L_x8(rks, (const unsigned char (*)[16])Ls, msgs, lens, tags);
    else
        pmac1_aes128_with_L_x4(rks, (const unsigned char (*)[16])Ls, msgs, lens, tags);
    for (int k = 0; k < n; k++) {
        uint16_t i = idx[k];
        uint8_t *msg = bd->ip6_ptrs[i];
        msg[0] = saved[k][0]; msg[1] = saved[k][1];
        msg[2] = saved[k][2]; msg[3] = saved[k][3];
        msg[7] = saved[k][4];
        memcpy(bd->mac_fields[i], bd->mac_expected[i], EXT_MAC_SIZE);
        bd->results[i] = mac_equal8(tags[k], bd->mac_expected[i])
            ? MAC_CHECK_BATCHED_OK : MAC_CHECK_INVALID;
    }
}

/* Larger packets are faster on the single-packet path (8 blocks interleaved). */
#define AB_BATCH_PMAC_MAX_LEN 256

static int
worker_main(void *arg)
{
    struct worker_ctx *ctx = (struct worker_ctx *)arg;
    struct worker_burst_data *bd = ctx->burst;
    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_mbuf *tx_bufs[BURST_SIZE];
    uint64_t local_rx = 0, local_tx = 0;
    uint64_t local_reject = 0;   /* tx_full_pkts is counted by the tx_buffer callback */
#ifdef AB_PER_CLASS_STATS
    uint64_t local_rx_class[AB_CLASS_MAX] = {0};
    uint64_t local_tx_class[AB_CLASS_MAX] = {0};
#endif
    while (__builtin_expect(!force_quit, 1)) {
        uint16_t nb_tx_pkts = 0;
        const uint16_t nb_rx = rte_eth_rx_burst(ctx->port_id, ctx->queue_id, bufs, BURST_SIZE);
        if (__builtin_expect(nb_rx == 0, 1)) {
            /* idle: flush the TX buffer so low-rate traffic isn't held back */
            uint16_t flushed_idle = rte_eth_tx_buffer_flush(
                    ctx->egress_port_id, ctx->queue_id, ctx->tx_buffer);
            local_tx += flushed_idle;
            continue;
        }

        for (uint16_t i = 0; i < RTE_MIN(nb_rx, (uint16_t)4); i++)
            prefetch_mbuf(bufs[i]);

        /* Return path. Keep the server's eth header: mac.conf holds the
         * forward-direction dst MAC. */
        if (__builtin_expect(ctx->mode == MODE_BRIDGE_ONLY, 0)) {
            for (uint16_t i = 0; i < nb_rx; i++)
                tx_bufs[nb_tx_pkts++] = bufs[i];
            goto tx_out;
        }

        /* Stage 1: parse and check the headers. */
        for (uint16_t i = 0; i < nb_rx; i++) {
            if (i + 4 < nb_rx)
                prefetch_mbuf(bufs[i + 4]);

            bd->results[i] = MAC_CHECK_INVALID;
#ifdef AB_PER_CLASS_STATS
            bd->class_tag[i] = AB_CLASS_UNKNOWN;
#endif
            struct rte_mbuf *m = bufs[i];
            uint32_t pkt_len = rte_pktmbuf_pkt_len(m);
            if (__builtin_expect(pkt_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr), 0))
                continue;
            if (__builtin_expect(m->nb_segs > 1, 0)) {
                if (rte_pktmbuf_linearize(m) != 0)
                    continue;
            }
            uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);
            struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt;
            if (__builtin_expect(eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6), 0))
                continue;
            struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(pkt + sizeof(struct rte_ether_hdr));
#ifdef AB_PER_CLASS_STATS
            /* before the ext header check, so no_header packets count too */
            bd->class_tag[i] = ab_extract_class(pkt, pkt_len, ip6->proto);
#endif
            if (__builtin_expect(ip6->proto != IPV6_NEXT_HEADER_DEST_OPTS, 0))
                continue;
            uint16_t payload_len = rte_be_to_cpu_16(ip6->payload_len);
            uint32_t ip_len = (uint32_t)payload_len + sizeof(struct rte_ipv6_hdr);
            if (__builtin_expect(pkt_len < sizeof(struct rte_ether_hdr) + ip_len, 0))
                continue;
            uint8_t *ext = (uint8_t *)ip6 + sizeof(struct rte_ipv6_hdr);
            uint32_t ext_len = (uint32_t)(ext[1] + 1) * 8;
            if (__builtin_expect(ext_len < EXT_HDR_SIZE || payload_len < ext_len, 0))
                continue;
            if (__builtin_expect(ext[2] != EXT_OPT_TYPE || ext[3] != EXT_OPT_LEN, 0))
                continue;

            bd->ip6_ptrs[i] = (uint8_t *)ip6;
            bd->ipv6_total_len[i] = (uint16_t)ip_len;
            bd->mac_fields[i] = ext + EXT_MAC_OFFSET;
            memcpy(bd->mac_expected[i], bd->mac_fields[i], EXT_MAC_SIZE);
            bd->results[i] = MAC_CHECK_OK;
        }

        /* Stages 2-6: crypto checks, skipped with STRIP_ONLY. */
        if (!g_strip_only) {
            /* Stage 2: key lookup. */
            for (uint16_t i = 0; i < nb_rx; i++) {
                if (bd->results[i] != MAC_CHECK_OK)
                    continue;
                struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)bd->ip6_ptrs[i];
                bd->master_roundkeys[i] = lookup_roundkey_for_dst(
                        ip6->dst_addr, ctx->key_table, ctx->default_roundkey,
                        &bd->dedup_mul[i]);
                if (__builtin_expect(!bd->master_roundkeys[i], 0)) {
                    bd->results[i] = MAC_CHECK_INVALID;
                    continue;
                }
                /* The dedup set almost always misses L2; prefetching it here
                 * hides the miss behind stage 3. */
                {
                    uint64_t pf_tag;
                    memcpy(&pf_tag, bd->mac_expected[i], 8);
                    rte_prefetch0(&ctx->dedup->sets[
                            dedup_set_index(pf_tag, bd->dedup_mul[i])]);
                }
            }

            /* Stage 3: derive the per-packet key and L = AES_K(0), 8 or 4
             * packets interleaved per call, the last 1-3 one by one. */
            uint16_t i_d = 0;
            while (i_d + 8 <= nb_rx) {
                const void *mrks[8];
                unsigned char inputs[8][16] __attribute__((aligned(16)));
                unsigned char *outs[8];
                derive_lanes_fill(ctx, bd, i_d, 8, mrks, inputs, outs);
                ab_derive_aes128_keys_and_L_x8(mrks, inputs, outs,
                        (unsigned char (*)[16])&bd->pmac_L[i_d]);
                i_d += 8;
            }
            while (i_d + 4 <= nb_rx) {
                const void *mrks[4];
                unsigned char inputs[4][16] __attribute__((aligned(16)));
                unsigned char *outs[4];
                derive_lanes_fill(ctx, bd, i_d, 4, mrks, inputs, outs);
                ab_derive_aes128_keys_and_L_x4(mrks, inputs, outs,
                        (unsigned char (*)[16])&bd->pmac_L[i_d]);
                i_d += 4;
            }
            for (; i_d < nb_rx; i_d++) {
                if (bd->results[i_d] != MAC_CHECK_OK)
                    continue;
                uint8_t *ext = bd->ip6_ptrs[i_d] + sizeof(struct rte_ipv6_hdr);
                uint8_t der_input[16] __attribute__((aligned(16))) = {0};
                memcpy(der_input, ext + EXT_ERUID_OFFSET, 7);
                memcpy(der_input + 7, ext + EXT_TIMEOUT_OFFSET, 2);
                der_input[9] = 0x80;
                uint8_t derived_key[16];
                CBCMAC(bd->master_roundkeys[i_d], 1, der_input, derived_key);
                ExpandKey128(derived_key, bd->roundkeys2[i_d]);
                uint8_t zero[16] = {0};   /* L = AES_K(0) */
                CBCMAC(bd->roundkeys2[i_d], 1, zero, bd->pmac_L[i_d]);
            }

            /* Stage 4: drop known replays before paying for the PMAC. */
            for (uint16_t i = 0; i < nb_rx; i++) {
                if (bd->results[i] != MAC_CHECK_OK)
                    continue;
                if (__builtin_expect(
                        dedup_check(ctx->dedup, bd->mac_expected[i],
                                    bd->dedup_mul[i]), 0)) {
                    bd->results[i] = MAC_CHECK_INVALID;
                }
            }

            /* Stage 5: PMAC. Small packets are batched 8/4 at a time since a
             * single short PMAC leaves the AES unit idle; the rest go one by one. */
            {
                uint16_t ok_idx[BURST_SIZE];
                uint16_t n_ok = 0;
                for (uint16_t i = 0; i < nb_rx; i++)
                    if (bd->results[i] == MAC_CHECK_OK &&
                        bd->ipv6_total_len[i] >= 8 &&
                        bd->ipv6_total_len[i] <= AB_BATCH_PMAC_MAX_LEN)
                        ok_idx[n_ok++] = i;
                uint16_t q = 0;
                for (; q + 8 <= n_ok; q += 8)
                    verify_pmac_batch(bd, &ok_idx[q], 8);
                for (; q + 4 <= n_ok; q += 4)
                    verify_pmac_batch(bd, &ok_idx[q], 4);
            }
            for (uint16_t i = 0; i < nb_rx; i++) {
                if (bd->results[i] != MAC_CHECK_OK) {
                    if (bd->results[i] == MAC_CHECK_BATCHED_OK)
                        bd->results[i] = MAC_CHECK_OK;
                    continue;
                }
                memset(bd->mac_fields[i], 0, EXT_MAC_SIZE);
                if (__builtin_expect(
                    pmac_compute_with_L(bd->roundkeys2[i], bd->pmac_L[i],
                                bd->ip6_ptrs[i], bd->ipv6_total_len[i],
                                bd->mac_out[i]) != 0, 0)) {
                    bd->results[i] = MAC_CHECK_INVALID;
                    continue;
                }
                memcpy(bd->mac_fields[i], bd->mac_expected[i], EXT_MAC_SIZE);
                if (!mac_equal8(bd->mac_out[i], bd->mac_expected[i]))
                    bd->results[i] = MAC_CHECK_INVALID;
            }

            /* Stage 6: remember the tags of valid packets. */
            for (uint16_t i = 0; i < nb_rx; i++) {
                if (bd->results[i] != MAC_CHECK_OK)
                    continue;
                dedup_insert(ctx->dedup, bd->mac_expected[i], bd->dedup_mul[i]);
            }
        }

        /* Stage 7: strip (bridge mode), rewrite MACs, queue for TX. */
        for (uint16_t i = 0; i < nb_rx; i++) {
#ifdef AB_PER_CLASS_STATS
            local_rx_class[bd->class_tag[i]]++;
#endif
            if (__builtin_expect(bd->results[i] != MAC_CHECK_OK, 0)) {
                rte_pktmbuf_free(bufs[i]);
                continue;
            }
            if (ctx->mode == MODE_VALIDATE_STRIP) {
                /* remove the 24-byte ext header */
                struct rte_ipv6_hdr *ip6 =
                    (struct rte_ipv6_hdr *)bd->ip6_ptrs[i];
                uint8_t *ext = (uint8_t *)ip6 + sizeof(struct rte_ipv6_hdr);
                uint8_t orig_nh = ext[0];
                uint16_t payload_len = rte_be_to_cpu_16(ip6->payload_len);
                uint16_t after_ext = (uint16_t)(payload_len - EXT_HDR_SIZE);
                memmove(ext, ext + EXT_HDR_SIZE, after_ext);
                if (__builtin_expect(rte_pktmbuf_trim(bufs[i], EXT_HDR_SIZE) != 0, 0)) {
                    rte_pktmbuf_free(bufs[i]);
                    continue;
                }
                ip6->proto = orig_nh;
                ip6->payload_len = rte_cpu_to_be_16(after_ext);
            }
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
            rte_ether_addr_copy(&ctx->dst_mac, &eth->dst_addr);
            rte_ether_addr_copy(&ctx->src_mac, &eth->src_addr);
#ifdef AB_PER_CLASS_STATS
            local_tx_class[bd->class_tag[i]]++;
#endif
            tx_bufs[nb_tx_pkts++] = bufs[i];
        }

tx_out:
        /* Sends once the buffer is full; returns how many went out. */
        uint16_t flushed_total = 0;
        for (uint16_t i = 0; i < nb_tx_pkts; i++) {
            flushed_total += rte_eth_tx_buffer(
                    ctx->egress_port_id, ctx->queue_id, ctx->tx_buffer, tx_bufs[i]);
        }

        local_reject += (uint64_t)(nb_rx - nb_tx_pkts);
        local_rx += nb_rx;
        local_tx += flushed_total;

        /* batch updates to the shared counters */
        if (__builtin_expect(local_rx >= 1024, 0)) {
            g_stats[ctx->worker_idx].rx_pkts += local_rx;
            g_stats[ctx->worker_idx].tx_pkts += local_tx;
            g_stats[ctx->worker_idx].reject_pkts += local_reject;
            local_rx = 0;
            local_tx = 0;
            local_reject = 0;
#ifdef AB_PER_CLASS_STATS
            for (uint32_t c = 0; c < AB_CLASS_MAX; c++) {
                g_stats[ctx->worker_idx].rx_by_class[c] += local_rx_class[c];
                g_stats[ctx->worker_idx].tx_by_class[c] += local_tx_class[c];
                local_rx_class[c] = 0;
                local_tx_class[c] = 0;
            }
#endif
        }
    }

    uint16_t final_flushed = rte_eth_tx_buffer_flush(
            ctx->egress_port_id, ctx->queue_id, ctx->tx_buffer);
    local_tx += final_flushed;

    g_stats[ctx->worker_idx].rx_pkts += local_rx;
    g_stats[ctx->worker_idx].tx_pkts += local_tx;
    g_stats[ctx->worker_idx].reject_pkts += local_reject;
#ifdef AB_PER_CLASS_STATS
    for (uint32_t c = 0; c < AB_CLASS_MAX; c++) {
        g_stats[ctx->worker_idx].rx_by_class[c] += local_rx_class[c];
        g_stats[ctx->worker_idx].tx_by_class[c] += local_tx_class[c];
    }
#endif

    return 0;
}

int
main(int argc, char *argv[])
{
    const char *config_path = "config/mac.conf";
    const char *key_path = "config/keys.json";
    g_strip_only = getenv("STRIP_ONLY") != NULL;
    if (g_strip_only)
        fprintf(stderr, "[info] STRIP_ONLY=1: bridge ports skip PMAC validation\n");
    g_raw_forward = getenv("RAW_FORWARD") != NULL;
    if (g_raw_forward)
        fprintf(stderr, "[info] RAW_FORWARD=1: bridge ports do plain L2 forward (no validation, no strip)\n");
    uint16_t worker_lcores[RTE_MAX_LCORE];
    uint16_t nb_workers = 0;

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    /* Seed the default-key dedup index multiplier (per-destination ones live
     * in each key_entry, seeded at insert) from the OS CSPRNG, before any
     * worker runs. Force it odd so the multiply-shift bijects on the high
     * bits. Keep it secret and never log it. */
    if (getentropy(&g_default_dedup_mul, sizeof(g_default_dedup_mul)) != 0) {
        rte_exit(EXIT_FAILURE, "getentropy failed for dedup index key\n");
    }
    g_default_dedup_mul |= 1ull;

#ifdef AB_PER_CLASS_STATS
    rte_telemetry_register_cmd("/ab/stats", ab_telemetry_stats,
        "Cumulative per-class rx/tx totals (legit/no_header/malformed/forged/replay/unknown)");
#endif

    argc -= ret;
    argv += ret;

    /* default: every port bounces */
    for (int i = 0; i < RTE_MAX_ETHPORTS; i++) {
        g_port_peer[i] = -1;
        g_port_validate[i] = 1;
    }

    optind = 1;
    int opt;
    while ((opt = getopt(argc, argv, "c:i:o:k:b:")) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
            break;
        case 'k':
            key_path = optarg;
            break;
        case 'b': {
            /* -b IN=OUT: validate+strip IN -> OUT, plain forward OUT -> IN.
             * Can be given more than once. */
            char *eq = strchr(optarg, '=');
            if (!eq) {
                fprintf(stderr, "bad -b argument %s: expected INGRESS=EGRESS\n", optarg);
                return 1;
            }
            int in_port = atoi(optarg);
            int eg_port = atoi(eq + 1);
            if (in_port < 0 || in_port >= RTE_MAX_ETHPORTS ||
                eg_port < 0 || eg_port >= RTE_MAX_ETHPORTS ||
                in_port == eg_port) {
                fprintf(stderr, "bad -b port pair %d=%d\n", in_port, eg_port);
                return 1;
            }
            g_port_peer[in_port] = (int16_t)eg_port;
            g_port_peer[eg_port] = (int16_t)in_port;
            g_port_validate[in_port] = 1;
            g_port_validate[eg_port] = 0;
            break;
        }
        default:
            fprintf(stderr, "Usage: %s [-c config] [-k keys] [-b INGRESS=EGRESS]\n", argv[0]);
            return 1;
        }
    }

    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        rte_exit(EXIT_FAILURE, "No available DPDK ports\n");
    }

    fprintf(stderr, "[dbg] reading dst mac from %s\n", config_path);
    struct rte_ether_addr dst_mac;
    if (read_mac_from_file(config_path, &dst_mac) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to read MAC from config\n");
    }

    fprintf(stderr, "[dbg] loading keys from %s\n", key_path);
    if (load_keys_from_json(key_path) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to load keys from %s\n", key_path);
    }

    uint16_t lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        worker_lcores[nb_workers++] = lcore_id;
    }
    if (nb_workers == 0) {
        worker_lcores[nb_workers++] = rte_lcore_id();
    }

    uint16_t port_ids[RTE_MAX_ETHPORTS];
    uint16_t nb_ports_valid = 0;
    struct rte_ether_addr src_macs[RTE_MAX_ETHPORTS];
    struct rte_eth_dev_info dev_info;

    for (uint16_t port_id = 0; port_id < nb_ports; port_id++) {
        if (!rte_eth_dev_is_valid_port(port_id))
            continue;
        port_ids[nb_ports_valid++] = port_id;
    }

    if (nb_workers < nb_ports_valid) {
        rte_exit(EXIT_FAILURE, "Need >= %u workers for %u ports\n",
                 nb_ports_valid, nb_ports_valid);
    }

    uint16_t workers_per_port[RTE_MAX_ETHPORTS] = {0};
    const char *wpp_list_env = getenv("WORKERS_PER_PORT_LIST");
    const char *workers_per_port_env = getenv("WORKERS_PER_PORT");
    if (wpp_list_env && wpp_list_env[0] != '\0') {
        /* per-port worker counts in port order, e.g. "1,8,8,8,7" */
        const char *p = wpp_list_env;
        uint32_t total = 0;
        for (uint16_t i = 0; i < nb_ports_valid; i++) {
            char *endp = NULL;
            long v = strtol(p, &endp, 10);
            if (endp == p || v <= 0 || v > UINT16_MAX) {
                rte_exit(EXIT_FAILURE,
                    "Invalid WORKERS_PER_PORT_LIST=%s (need %u positive ints comma-separated)\n",
                    wpp_list_env, nb_ports_valid);
            }
            workers_per_port[i] = (uint16_t)v;
            total += (uint32_t)v;
            p = endp;
            if (i + 1 < nb_ports_valid) {
                if (*p != ',') {
                    rte_exit(EXIT_FAILURE,
                        "WORKERS_PER_PORT_LIST=%s: expected %u entries, got %u\n",
                        wpp_list_env, nb_ports_valid, i + 1);
                }
                p++;
            }
        }
        if (total > nb_workers) {
            rte_exit(EXIT_FAILURE,
                "WORKERS_PER_PORT_LIST sum=%u exceeds available workers %u\n",
                total, nb_workers);
        }
    } else if (workers_per_port_env && workers_per_port_env[0] != '\0') {
        uint16_t wpp = (uint16_t)atoi(workers_per_port_env);
        if (wpp == 0 || (uint32_t)wpp * nb_ports_valid > nb_workers) {
            rte_exit(EXIT_FAILURE, "Invalid WORKERS_PER_PORT=%s for %u workers and %u ports\n",
                     workers_per_port_env, nb_workers, nb_ports_valid);
        }
        for (uint16_t i = 0; i < nb_ports_valid; i++)
            workers_per_port[i] = wpp;
    } else {
        /* Return-path ports only carry server replies and get one worker;
         * the rest are spread round-robin over the validating ports. */
        uint16_t nb_bridge_only = 0;
        for (uint16_t i = 0; i < nb_ports_valid; i++) {
            uint16_t pid = port_ids[i];
            if (g_port_peer[pid] >= 0 && !g_port_validate[pid])
                nb_bridge_only++;
        }
        const uint16_t bridge_only_workers = 1;
        uint16_t reserved = nb_bridge_only * bridge_only_workers;
        if (reserved >= nb_workers) {
            rte_exit(EXIT_FAILURE, "not enough workers (%u) to seed %u bridge-only ports\n",
                     nb_workers, nb_bridge_only);
        }
        uint16_t remaining = (uint16_t)(nb_workers - reserved);
        uint16_t nb_other = (uint16_t)(nb_ports_valid - nb_bridge_only);
        for (uint16_t i = 0; i < nb_ports_valid; i++) {
            uint16_t pid = port_ids[i];
            if (g_port_peer[pid] >= 0 && !g_port_validate[pid])
                workers_per_port[i] = bridge_only_workers;
        }
        if (nb_other > 0) {
            for (uint16_t k = 0; k < remaining; k++) {
                uint16_t hit = 0;
                for (uint16_t i = 0; i < nb_ports_valid; i++) {
                    uint16_t pid = port_ids[i];
                    if (g_port_peer[pid] >= 0 && !g_port_validate[pid])
                        continue;
                    if (hit == k % nb_other) {
                        workers_per_port[i]++;
                        break;
                    }
                    hit++;
                }
            }
        }
    }

    /* Workers TX on the peer port using their own queue id, so each port
     * needs max(own, peer) TX queues. */
    uint16_t tx_queues_per_port[RTE_MAX_ETHPORTS];
    for (uint16_t i = 0; i < nb_ports_valid; i++) {
        uint16_t pid = port_ids[i];
        tx_queues_per_port[i] = workers_per_port[i];
        if (g_port_peer[pid] < 0) continue;
        uint16_t peer = (uint16_t)g_port_peer[pid];
        uint16_t j;
        for (j = 0; j < nb_ports_valid; j++)
            if (port_ids[j] == peer) break;
        if (j == nb_ports_valid) {
            rte_exit(EXIT_FAILURE, "bridge peer port %u not available\n", peer);
        }
        if (workers_per_port[j] > tx_queues_per_port[i])
            tx_queues_per_port[i] = workers_per_port[j];
    }

    {
        fprintf(stderr, "[info] worker layout:");
        for (uint16_t i = 0; i < nb_ports_valid; i++)
            fprintf(stderr, " p%u=%u(tx=%u)", port_ids[i],
                    workers_per_port[i], tx_queues_per_port[i]);
        fprintf(stderr, "\n");
    }

    uint32_t total_rx_queues = 0;
    for (uint16_t i = 0; i < nb_ports_valid; i++)
        total_rx_queues += workers_per_port[i];

    /* Too small a pool shows up as rx_nombuf drops at line rate. */
    uint32_t per_queue_budget = RX_RING_SIZE        /* RX descriptors */
                              + TX_RING_SIZE        /* TX descriptors  */
                              + MBUF_CACHE_SIZE * 2 /* lcore + per-port cache */
                              + BURST_SIZE * 4;     /* in-flight slack */
    uint32_t pool_mbufs = total_rx_queues * per_queue_budget;
    if (pool_mbufs < (NUM_MBUFS * nb_ports_valid))
        pool_mbufs = NUM_MBUFS * nb_ports_valid;

    /* One mbuf pool per socket so DMA stays NUMA-local. */
    struct rte_mempool *mbuf_pools[RTE_MAX_NUMA_NODES] = {NULL};
    uint32_t ports_per_socket[RTE_MAX_NUMA_NODES] = {0};
    for (uint16_t i = 0; i < nb_ports_valid; i++)
        ports_per_socket[rte_eth_dev_socket_id(port_ids[i])]++;
    for (int s = 0; s < RTE_MAX_NUMA_NODES; s++) {
        if (ports_per_socket[s] == 0) continue;
        char pname[32];
        snprintf(pname, sizeof(pname), "MBUF_POOL_%d", s);
        uint32_t n = (pool_mbufs / nb_ports_valid) * ports_per_socket[s];
        if (n < NUM_MBUFS) n = NUM_MBUFS;
        mbuf_pools[s] = rte_pktmbuf_pool_create(pname, n, MBUF_CACHE_SIZE, 0,
            RTE_MBUF_DEFAULT_BUF_SIZE, s);
        if (mbuf_pools[s] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot create mbuf pool for socket %d\n", s);
        fprintf(stderr, "[info] mbuf pool socket %d: %u mbufs\n", s, n);

        g_key_table_numa[s] = rte_zmalloc_socket("key_table_numa",
                sizeof(g_key_table), RTE_CACHE_LINE_SIZE, s);
        g_default_roundkey_numa[s] = rte_zmalloc_socket("default_rk_numa",
                AES_ROUNDKEY_SIZE, RTE_CACHE_LINE_SIZE, s);
        if (!g_key_table_numa[s] || !g_default_roundkey_numa[s])
            rte_exit(EXIT_FAILURE,
                    "Cannot alloc per-NUMA key tables for socket %d\n", s);
        memcpy(g_key_table_numa[s], g_key_table, sizeof(g_key_table));
        memcpy(g_default_roundkey_numa[s], g_default_roundkey,
                AES_ROUNDKEY_SIZE);
        fprintf(stderr, "[info] key tables replicated to socket %d\n", s);
    }

    for (uint16_t i = 0; i < nb_ports_valid; i++) {
        uint16_t port_id = port_ids[i];
        rte_eth_dev_info_get(port_id, &dev_info);
        uint64_t rss_hf = dev_info.flow_type_rss_offloads & RTE_ETH_RSS_NONFRAG_IPV6_UDP;
        if (rss_hf == 0) {
            fprintf(stderr, "[warn] port %u does not support IPv6 UDP RSS; falling back to device defaults\n", port_id);
            rss_hf = dev_info.flow_type_rss_offloads;
        }
        uint16_t rx_queues = workers_per_port[i];
        uint16_t tx_queues = tx_queues_per_port[i];
        uint64_t rx_offloads = dev_info.rx_offload_capa &
            (RTE_ETH_RX_OFFLOAD_CHECKSUM |
             RTE_ETH_RX_OFFLOAD_IPV4_CKSUM |
             RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
             RTE_ETH_RX_OFFLOAD_UDP_CKSUM
             );
        /* Any other TX offload makes i40e use its scalar TX path. */
        uint64_t tx_offloads = dev_info.tx_offload_capa &
            RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
        if (port_init(port_id, mbuf_pools[rte_eth_dev_socket_id(port_id)], rx_queues, tx_queues, rss_hf, rx_offloads, tx_offloads) != 0) {
            rte_exit(EXIT_FAILURE, "Cannot init port %u\n", port_id);
        }
        program_rss_reta(port_id, rx_queues);
        rte_eth_macaddr_get(port_id, &src_macs[port_id]);
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("Forwarding on %u ports to same ingress port, dst %02X:%02X:%02X:%02X:%02X:%02X (workers=%u)\n",
           nb_ports_valid,
           dst_mac.addr_bytes[0], dst_mac.addr_bytes[1], dst_mac.addr_bytes[2],
           dst_mac.addr_bytes[3], dst_mac.addr_bytes[4], dst_mac.addr_bytes[5],
           nb_workers);

    struct worker_ctx worker_ctxs[RTE_MAX_LCORE];
    uint16_t worker_idx = 0;
    for (uint16_t i = 0; i < nb_ports_valid; i++) {
        uint16_t port_id = port_ids[i];
        uint16_t queues = workers_per_port[i];
        for (uint16_t q = 0; q < queues; q++) {
            struct worker_ctx *ctx = &worker_ctxs[worker_idx];
            ctx->port_id = port_id;
            ctx->queue_id = q;
            if (g_port_peer[port_id] >= 0) {
                ctx->egress_port_id = (uint16_t)g_port_peer[port_id];
                ctx->mode = (g_port_validate[port_id] && !g_raw_forward)
                    ? MODE_VALIDATE_STRIP : MODE_BRIDGE_ONLY;
            } else {
                ctx->egress_port_id = port_id;
                ctx->mode = MODE_BOUNCE;
            }
            ctx->dst_mac = dst_mac;
            ctx->src_mac = src_macs[port_id];
            unsigned int actual_lcore = worker_lcores[worker_idx];
            unsigned int wsock = rte_lcore_to_socket_id(actual_lcore);
            unsigned int psock = (unsigned int)rte_eth_dev_socket_id(port_id);
            if (wsock != psock)
                fprintf(stderr, "[warn] w%u: lcore %u (socket %u) is cross-NUMA for port %u "
                        "(socket %u), use socket-%u lcores for this port\n",
                        worker_idx, actual_lcore, wsock, port_id, psock, psock);
            ctx->worker_idx = worker_idx;
            ctx->key_table = (wsock < RTE_MAX_NUMA_NODES && g_key_table_numa[wsock])
                    ? g_key_table_numa[wsock] : g_key_table;
            ctx->default_roundkey =
                    (wsock < RTE_MAX_NUMA_NODES && g_default_roundkey_numa[wsock])
                    ? g_default_roundkey_numa[wsock] : g_default_roundkey;
            g_worker_port[worker_idx] = port_id;
            ctx->burst = rte_zmalloc_socket("burst_data",
                sizeof(struct worker_burst_data), RTE_CACHE_LINE_SIZE,
                wsock);
            if (!ctx->burst) {
                rte_exit(EXIT_FAILURE, "Cannot alloc burst data for worker %u\n", worker_idx);
            }
            ctx->dedup = rte_zmalloc_socket("dedup_table",
                sizeof(struct dedup_table), RTE_CACHE_LINE_SIZE,
                wsock);
            if (!ctx->dedup) {
                rte_exit(EXIT_FAILURE, "Cannot alloc dedup table for worker %u\n", worker_idx);
            }
            /* flushes every ~4 RX bursts; unsent mbufs are freed and counted as tx_full */
            const uint16_t txbuf_n = (uint16_t)(BURST_SIZE * 4);
            ctx->tx_buffer = rte_zmalloc_socket("tx_buffer",
                RTE_ETH_TX_BUFFER_SIZE(txbuf_n),
                RTE_CACHE_LINE_SIZE, wsock);
            if (!ctx->tx_buffer)
                rte_exit(EXIT_FAILURE,
                        "Cannot alloc tx_buffer for worker %u\n", worker_idx);
            rte_eth_tx_buffer_init(ctx->tx_buffer, txbuf_n);
            rte_eth_tx_buffer_set_err_callback(ctx->tx_buffer,
                    rte_eth_tx_buffer_count_callback,
                    &g_stats[worker_idx].tx_full_pkts);
            fprintf(stderr, "[dbg] w%u: lcore %u socket %u port %u queue %u\n",
                    worker_idx, actual_lcore, wsock, port_id, q);
            worker_idx++;
        }
    }

    g_nb_workers = nb_workers;
    /* Workers on the worker lcores, reporter on main. With a single lcore
     * (the tests use -l 0) the worker runs on main and there is no reporter. */
    unsigned int main_lcore = rte_lcore_id();
    int main_is_worker = -1;
    for (uint16_t i = 0; i < nb_workers; i++) {
        if (worker_lcores[i] == main_lcore) {
            main_is_worker = (int)i;
            break;
        }
    }
    if (main_is_worker >= 0) {
        fprintf(stderr,
                "[info] single-lcore mode: worker %d on main, no reporter\n",
                main_is_worker);
        for (uint16_t i = 0; i < nb_workers; i++) {
            if ((int)i == main_is_worker) continue;
            rte_eal_remote_launch(worker_main, &worker_ctxs[i],
                    worker_lcores[i]);
        }
        worker_main(&worker_ctxs[main_is_worker]);
    } else {
        for (uint16_t i = 0; i < nb_workers; i++) {
            rte_eal_remote_launch(worker_main, &worker_ctxs[i],
                    worker_lcores[i]);
        }
        reporter_loop(NULL);
    }

    rte_eal_mp_wait_lcore();

    for (uint16_t i = 0; i < nb_ports_valid; i++) {
        uint16_t port_id = port_ids[i];
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }

    printf("Exiting\n");
    return 0;
}
