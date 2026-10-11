#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/params.h>

#include <aesni.h>
#include <pmac1.h>

#define IPV6_NEXT_HEADER_DEST_OPTS 60
#define EXT_HDR_SIZE 24
#define EXT_OPT_TYPE 0x1E
#define EXT_OPT_LEN 20
#define EXT_IDPID_OFFSET 4
#define EXT_TIMEOUT_OFFSET 5
#define EXT_ERUID_OFFSET 7
#define EXT_PAD_OFFSET 14
#define EXT_MAC_OFFSET 16
#define EXT_MAC_SIZE 8

#define FRAME_SIZE 2048
#define RECV_TIMEOUT_MS 500

struct ipv6hdr {
    uint32_t vtc_flow;
    uint16_t payload_len;
    uint8_t nexthdr;
    uint8_t hop_limit;
    uint8_t saddr[16];
    uint8_t daddr[16];
} __attribute__((packed));

static uint8_t master_roundkey[176] __attribute__((aligned(16)));

static int g_send_sock = -1;
static int g_recv_sock = -1;
static int g_ifindex = 0;
static uint8_t g_src_mac[6];
static uint8_t g_fwd_dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
static int g_pass = 0;
static int g_fail = 0;
static int g_debug = 0;

static void
print_hex(const char *label, const uint8_t *buf, size_t len)
{
    fprintf(stderr, "  %s", label);
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, "%02x", buf[i]);
    fprintf(stderr, "\n");
}

static int
hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    if (strlen(hex) < out_len * 2)
        return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte = 0;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1)
            return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

/* PMAC1 with IPv6 mutable-field masking, in place on the caller's buffer.
 * Mirrors validator/loadgen pmac_compute exactly so test traffic matches
 * what the validator computes. */
static int
pmac_compute(const uint8_t roundkey[176],
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
    msg[0] = b0; msg[1] = b1; msg[2] = b2; msg[3] = b3;
    msg[7] = b7;
    return 0;
}

static int
openssl_cmac(const uint8_t key[16], const uint8_t *msg, size_t msg_len, uint8_t out[16])
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac)
        return -1;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        return -1;
    }
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("cipher", "AES-128-CBC", 0);
    params[1] = OSSL_PARAM_construct_end();
    int ok = (EVP_MAC_init(ctx, key, 16, params) == 1 &&
              EVP_MAC_update(ctx, msg, msg_len) == 1);
    size_t out_len = 0;
    if (ok)
        ok = (EVP_MAC_final(ctx, out, &out_len, 16) == 1);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok ? 0 : -1;
}

static uint16_t
ipv6_l4_checksum(struct ipv6hdr *ip6, uint8_t proto, void *l4, uint16_t l4_len)
{
    uint32_t sum = 0;
    uint16_t *p = (uint16_t *)&ip6->saddr;
    for (int i = 0; i < 8; i++) sum += ntohs(p[i]);
    p = (uint16_t *)&ip6->daddr;
    for (int i = 0; i < 8; i++) sum += ntohs(p[i]);
    sum += l4_len;
    sum += proto;
    p = (uint16_t *)l4;
    for (int i = 0; i < l4_len / 2; i++) sum += ntohs(p[i]);
    if (l4_len & 1) sum += (uint16_t)((uint8_t *)l4)[l4_len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return htons((uint16_t)~sum);
}

struct pkt_params {
    const char *src_ip;
    const char *dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t eruid[7];
    uint16_t timeout;
    const uint8_t *payload;
    size_t payload_len;
    const uint8_t *key;
    bool corrupt_mac;
    bool use_openssl_cmac;
    bool skip_mac;
};

static size_t
build_packet(uint8_t *frame, size_t frame_cap, const struct pkt_params *p)
{
    memset(frame, 0, frame_cap);
    size_t offset = 0;

    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_source, g_src_mac, 6);
    memset(eth->h_dest, 0xff, 6);
    eth->h_proto = htons(ETH_P_IPV6);
    offset += sizeof(*eth);

    struct ipv6hdr *ip6 = (struct ipv6hdr *)(frame + offset);
    ip6->vtc_flow = htonl(6u << 28);
    ip6->hop_limit = 64;
    inet_pton(AF_INET6, p->src_ip, ip6->saddr);
    inet_pton(AF_INET6, p->dst_ip, ip6->daddr);
    offset += sizeof(*ip6);

    uint8_t *ext = frame + offset;
    ext[0] = IPPROTO_UDP;
    ext[1] = 2;
    ext[2] = EXT_OPT_TYPE;
    ext[3] = EXT_OPT_LEN;
    ext[EXT_IDPID_OFFSET] = 0x11;
    uint16_t timeout_n = htons(p->timeout);
    memcpy(ext + EXT_TIMEOUT_OFFSET, &timeout_n, 2);
    memcpy(ext + EXT_ERUID_OFFSET, p->eruid, 7);
    ext[EXT_PAD_OFFSET] = 0x00;
    ext[EXT_PAD_OFFSET + 1] = 0x00;
    memset(ext + EXT_MAC_OFFSET, 0, EXT_MAC_SIZE);
    offset += EXT_HDR_SIZE;

    struct udphdr *udp = (struct udphdr *)(frame + offset);
    udp->source = htons(p->src_port);
    udp->dest = htons(p->dst_port);
    uint16_t udp_len = (uint16_t)(sizeof(*udp) + p->payload_len);
    udp->len = htons(udp_len);
    udp->check = 0;
    offset += sizeof(*udp);

    memcpy(frame + offset, p->payload, p->payload_len);
    offset += p->payload_len;

    /* Compute UDP checksum BEFORE MAC (matching send_pkt/process_packet flow).
     * The verifier sees the packet with a real UDP csum, so the MAC must be
     * computed over the packet bytes including that checksum. */
    {
        struct ipv6hdr tmp_ip6 = *ip6;
        tmp_ip6.payload_len = htons(udp_len);
        udp->check = 0;
        udp->check = ipv6_l4_checksum(&tmp_ip6, IPPROTO_UDP, udp, udp_len);
        if (udp->check == 0) udp->check = 0xFFFF;
    }

    ip6->nexthdr = IPV6_NEXT_HEADER_DEST_OPTS;
    ip6->payload_len = htons((uint16_t)(EXT_HDR_SIZE + udp_len));

    if (!p->skip_mac) {
        uint8_t rk[176] __attribute__((aligned(16)));
        uint8_t der_input[16] = {0};
        memcpy(der_input, p->eruid, 7);
        memcpy(der_input + 7, &timeout_n, 2);
        der_input[9] = 0x80;

        uint8_t tmp_master_rk[176] __attribute__((aligned(16)));
        ExpandKey128(p->key, tmp_master_rk);

        uint8_t derived_key[16];
        CBCMAC(tmp_master_rk, 1, der_input, derived_key);
        ExpandKey128(derived_key, rk);

        uint16_t ipv6_total = ntohs(ip6->payload_len) + (uint16_t)sizeof(*ip6);

        if (p->use_openssl_cmac) {
            uint8_t mac_msg[2048];
            memcpy(mac_msg, (uint8_t *)ip6, ipv6_total);
            uint8_t *mac_ext = mac_msg + sizeof(*ip6);
            memset(mac_ext + EXT_MAC_OFFSET, 0, EXT_MAC_SIZE);
            mac_msg[0] &= 0xF0;
            mac_msg[1] = 0;
            mac_msg[2] = 0;
            mac_msg[3] = 0;
            mac_msg[7] = 0;
            uint8_t mac_out[16];
            openssl_cmac(derived_key, mac_msg, ipv6_total, mac_out);
            memcpy(ext + EXT_MAC_OFFSET, mac_out, EXT_MAC_SIZE);
        } else {
            uint8_t mac_out[16];
            pmac_compute(rk, (uint8_t *)ip6, ipv6_total, mac_out);
            memcpy(ext + EXT_MAC_OFFSET, mac_out, EXT_MAC_SIZE);
        }

        if (p->corrupt_mac) {
            ext[EXT_MAC_OFFSET] ^= 0xff;
        }
    }

    return offset;
}

static int
send_frame(const uint8_t *frame, size_t len)
{
    if (g_debug) {
        fprintf(stderr, "    [dbg] TX %zu bytes: ", len);
        for (size_t i = 0; i < len && i < 100; i++) {
            fprintf(stderr, "%02x", frame[i]);
            if ((i+1) % 16 == 0) fprintf(stderr, " ");
        }
        fprintf(stderr, "\n");
    }
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = g_ifindex;
    addr.sll_protocol = htons(ETH_P_IPV6);
    ssize_t sent = sendto(g_send_sock, frame, len, 0,
                          (struct sockaddr *)&addr, sizeof(addr));
    return (sent == (ssize_t)len) ? 0 : -1;
}

static int
recv_forwarded(int timeout_ms)
{
    struct pollfd pfd = { .fd = g_recv_sock, .events = POLLIN };
    uint8_t buf[FRAME_SIZE];
    int64_t deadline_ms = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    deadline_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + timeout_ms;
    int pkts_seen = 0;

    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        int64_t now_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        int remaining = (int)(deadline_ms - now_ms);
        if (remaining <= 0) {
            if (g_debug)
                fprintf(stderr, "    [dbg] recv timeout after %d pkts\n", pkts_seen);
            return 0;
        }

        int ret = poll(&pfd, 1, remaining);
        if (ret <= 0)
            return 0;

        struct sockaddr_ll from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(g_recv_sock, buf, sizeof(buf), MSG_DONTWAIT,
                             (struct sockaddr *)&from, &fromlen);
        if (n < (ssize_t)sizeof(struct ethhdr))
            continue;

        pkts_seen++;
        struct ethhdr *eth = (struct ethhdr *)buf;

        if (g_debug && pkts_seen <= 10) {
            fprintf(stderr, "    [dbg] pkt %d: len=%zd type=%d proto=0x%04x dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
                    pkts_seen, n, from.sll_pkttype, ntohs(eth->h_proto),
                    eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                    eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        }

        if (ntohs(eth->h_proto) != ETH_P_IPV6)
            continue;

        if (memcmp(eth->h_dest, g_fwd_dst_mac, 6) == 0)
            return 1;
    }
}

static void
drain_socket(void)
{
    uint8_t buf[FRAME_SIZE];
    while (recv(g_recv_sock, buf, sizeof(buf), MSG_DONTWAIT) > 0)
        ;
}

static void
check(const char *name, bool expected_forward, const uint8_t *frame, size_t len)
{
    drain_socket();
    if (send_frame(frame, len) != 0) {
        fprintf(stderr, "  [ERROR] %s: send failed\n", name);
        g_fail++;
        return;
    }
    int got = recv_forwarded(RECV_TIMEOUT_MS);
    if (got == expected_forward) {
        fprintf(stderr, "  [PASS] %s\n", name);
        g_pass++;
    } else {
        fprintf(stderr, "  [FAIL] %s: expected %s, got %s\n", name,
                expected_forward ? "forwarded" : "dropped",
                got ? "forwarded" : "dropped");
        g_fail++;
    }
}

static const uint8_t DEFAULT_KEY[16] = {0};
static const uint8_t ALT_KEY[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};
static const uint8_t DEFAULT_ERUID[7] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x01};
static const uint8_t DEFAULT_PAYLOAD[] = {'A', 'U', 'T', 'H', 0x01, 'T'};

/* ---------- Test 1: Invalid MAC ---------- */
static void
test_invalid_mac(void)
{
    fprintf(stderr, "\n--- Test 1: Invalid MAC ---\n");
    uint8_t frame[FRAME_SIZE];
    struct pkt_params p = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
        .src_port = 10001, .dst_port = 10002,
        .timeout = 0x5678, .key = DEFAULT_KEY,
        .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
        .corrupt_mac = true,
    };
    memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
    size_t len = build_packet(frame, sizeof(frame), &p);
    print_hex("mac (corrupted): ", frame + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + EXT_MAC_OFFSET, 8);
    check("invalid MAC", false, frame, len);
}

/* ---------- Test 2: Valid MAC ---------- */
static void
test_valid_mac(void)
{
    fprintf(stderr, "\n--- Test 2: Valid MAC ---\n");
    uint8_t frame[FRAME_SIZE];
    struct pkt_params p = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
        .src_port = 10003, .dst_port = 10004,
        .timeout = 0x5678, .key = DEFAULT_KEY,
        .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
    };
    memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
    size_t len = build_packet(frame, sizeof(frame), &p);
    print_hex("mac: ", frame + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + EXT_MAC_OFFSET, 8);
    check("valid MAC", true, frame, len);
}

/* ---------- Test 3: Expired timeout ---------- */
static void
test_expired_timeout(void)
{
    fprintf(stderr, "\n--- Test 3: Expired timeout ---\n");
    fprintf(stderr, "  (note: dpdk_forward does not check timeout expiry;\n");
    fprintf(stderr, "   timeout only affects key derivation. A correctly\n");
    fprintf(stderr, "   MAC'd packet with any timeout value should pass.)\n");
    uint8_t frame[FRAME_SIZE];
    struct pkt_params p = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
        .src_port = 10005, .dst_port = 10006,
        .timeout = 0x0001,
        .key = DEFAULT_KEY,
        .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
    };
    memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
    size_t len = build_packet(frame, sizeof(frame), &p);
    check("expired timeout (MAC valid for this timeout)", true, frame, len);
}

/* ---------- Test 4: Future timeout ---------- */
static void
test_future_timeout(void)
{
    fprintf(stderr, "\n--- Test 4: Future timeout ---\n");
    uint8_t frame[FRAME_SIZE];
    struct pkt_params p = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
        .src_port = 10007, .dst_port = 10008,
        .timeout = 0xFFFF,
        .key = DEFAULT_KEY,
        .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
    };
    memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
    size_t len = build_packet(frame, sizeof(frame), &p);
    check("future timeout (MAC valid for this timeout)", true, frame, len);
}

/* ---------- Test 5: Default key ---------- */
static void
test_default_key(void)
{
    fprintf(stderr, "\n--- Test 5: Default key ---\n");
    uint8_t frame[FRAME_SIZE];
    struct pkt_params p = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
        .src_port = 10009, .dst_port = 10010,
        .timeout = 0x5678, .key = DEFAULT_KEY,
        .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
    };
    memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
    size_t len = build_packet(frame, sizeof(frame), &p);
    check("default key", true, frame, len);
}

/* ---------- Test 6: Different key (alt dest addr) ---------- */
static void
test_different_key(void)
{
    fprintf(stderr, "\n--- Test 6: Different key (alt destination) ---\n");

    uint8_t frame[FRAME_SIZE];
    struct pkt_params p = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::ff",
        .src_port = 10011, .dst_port = 10012,
        .timeout = 0x5678, .key = ALT_KEY,
        .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
    };
    memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
    size_t len = build_packet(frame, sizeof(frame), &p);
    check("alt key for alt dest", true, frame, len);
}

/* ---------- Test 7: Duplicate packets ---------- */
static void
test_duplicate_packets(void)
{
    fprintf(stderr, "\n--- Test 7: Duplicate packets ---\n");
    uint8_t frame[FRAME_SIZE];
    struct pkt_params p = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
        .src_port = 10013, .dst_port = 10014,
        .timeout = 0x5678, .key = DEFAULT_KEY,
        .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
    };
    memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
    size_t len = build_packet(frame, sizeof(frame), &p);

    drain_socket();
    send_frame(frame, len);
    int first = recv_forwarded(RECV_TIMEOUT_MS);

    drain_socket();
    send_frame(frame, len);
    int second = recv_forwarded(RECV_TIMEOUT_MS);

    if (first && !second) {
        fprintf(stderr, "  [PASS] duplicate detection: first forwarded, second dropped\n");
        g_pass++;
    } else {
        fprintf(stderr, "  [FAIL] duplicate detection: first=%s second=%s\n",
                first ? "fwd" : "drop", second ? "fwd" : "drop");
        g_fail++;
    }
}

/* ---------- Test 8: Duplicate MACs, different IPs ---------- */
static void
test_duplicate_mac_different_ips(void)
{
    fprintf(stderr, "\n--- Test 8: Duplicate MAC tags with different src/dst IPs ---\n");
    fprintf(stderr, "  (Packets share the same MAC tag bytes but have different IPs.\n");
    fprintf(stderr, "   PMAC verification should fail because the MAC covers the IPs.)\n");

    uint8_t frame1[FRAME_SIZE];
    struct pkt_params p1 = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
        .src_port = 10015, .dst_port = 10016,
        .timeout = 0x5678, .key = DEFAULT_KEY,
        .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
    };
    memcpy((void *)p1.eruid, DEFAULT_ERUID, 7);
    build_packet(frame1, sizeof(frame1), &p1);

    uint8_t saved_mac[EXT_MAC_SIZE];
    size_t mac_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + EXT_MAC_OFFSET;
    memcpy(saved_mac, frame1 + mac_off, EXT_MAC_SIZE);

    int total_dropped = 0;
    const char *alt_srcs[] = {"2001:db8::10", "2001:db8::11", "2001:db8::12",
                              "2001:db8::13", "2001:db8::14"};
    for (int i = 0; i < 5; i++) {
        uint8_t frame2[FRAME_SIZE];
        struct pkt_params p2 = {
            .src_ip = alt_srcs[i], .dst_ip = "2001:db8::2",
            .src_port = (uint16_t)(10020 + i), .dst_port = 10016,
            .timeout = 0x5678, .key = DEFAULT_KEY,
            .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
            .skip_mac = true,
        };
        memcpy((void *)p2.eruid, DEFAULT_ERUID, 7);
        size_t len2 = build_packet(frame2, sizeof(frame2), &p2);
        memcpy(frame2 + mac_off, saved_mac, EXT_MAC_SIZE);

        drain_socket();
        send_frame(frame2, len2);
        if (!recv_forwarded(RECV_TIMEOUT_MS))
            total_dropped++;
    }

    if (total_dropped == 5) {
        fprintf(stderr, "  [PASS] all 5 spoofed-MAC packets dropped\n");
        g_pass++;
    } else {
        fprintf(stderr, "  [FAIL] %d/5 spoofed-MAC packets dropped (expected 5)\n", total_dropped);
        g_fail++;
    }
}

/* ---------- Test 9: Increasing lengths + OpenSSL CMAC ---------- */
static void
test_increasing_lengths(void)
{
    fprintf(stderr, "\n--- Test 9: Increasing packet lengths + OpenSSL CMAC ---\n");

    size_t sizes[] = {1, 7, 8, 15, 16, 17, 31, 32, 33, 48, 64, 100, 128, 255, 256, 500, 1000};
    size_t nsizes = sizeof(sizes) / sizeof(sizes[0]);
    int sub_pass = 0, sub_fail = 0;

    for (size_t s = 0; s < nsizes; s++) {
        uint8_t payload[1024];
        for (size_t i = 0; i < sizes[s]; i++)
            payload[i] = (uint8_t)(i & 0xff);

        uint8_t frame[FRAME_SIZE];
        struct pkt_params p = {
            .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
            .src_port = (uint16_t)(20000 + s), .dst_port = 20001,
            .timeout = (uint16_t)(0x1000 + s),
            .key = DEFAULT_KEY,
            .payload = payload, .payload_len = sizes[s],
        };
        memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
        p.eruid[6] = (uint8_t)(0x80 + s);
        size_t len = build_packet(frame, sizeof(frame), &p);

        drain_socket();
        send_frame(frame, len);
        int got = recv_forwarded(RECV_TIMEOUT_MS);
        if (got) {
            sub_pass++;
        } else {
            fprintf(stderr, "  [FAIL] PMAC payload_len=%zu: dropped\n", sizes[s]);
            sub_fail++;
        }
    }
    fprintf(stderr, "  PMAC lengths: %d/%zu passed\n", sub_pass, nsizes);
    if (sub_fail == 0) g_pass++; else g_fail++;

    fprintf(stderr, "  --- OpenSSL CMAC (should be REJECTED by PMAC verifier) ---\n");
    uint8_t ossl_payload[64];
    for (size_t i = 0; i < sizeof(ossl_payload); i++)
        ossl_payload[i] = (uint8_t)(i & 0xff);

    uint8_t frame[FRAME_SIZE];
    struct pkt_params p = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
        .src_port = 30000, .dst_port = 30001,
        .timeout = 0xAAAA,
        .key = DEFAULT_KEY,
        .payload = ossl_payload, .payload_len = sizeof(ossl_payload),
        .use_openssl_cmac = true,
    };
    uint8_t ossl_eruid[7] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01};
    memcpy((void *)p.eruid, ossl_eruid, 7);
    size_t len = build_packet(frame, sizeof(frame), &p);
    check("OpenSSL CMAC tag (wrong algorithm)", false, frame, len);
}

/* ---------- Test 10: IPv6 mutable-field masking ---------- */
static void
test_mutable_field_masking(void)
{
    fprintf(stderr, "\n--- Test 10: IPv6 mutable-field masking (hop_limit, tc/flow) ---\n");
    uint8_t frame[FRAME_SIZE];
    struct pkt_params p = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
        .src_port = 11001, .dst_port = 11002,
        .timeout = 0x5678, .key = DEFAULT_KEY,
        .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
    };
    memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
    size_t len = build_packet(frame, sizeof(frame), &p);
    /* After MAC compute, mutate bytes that the mask zeroes: tc/flow and hop_limit */
    struct ipv6hdr *ip6 = (struct ipv6hdr *)(frame + sizeof(struct ethhdr));
    ip6->vtc_flow = htonl((6u << 28) | 0x0AABCDEF);
    ip6->hop_limit = 7;
    check("mutated hop_limit + tc/flow still verifies", true, frame, len);
}

/* ---------- Test 11: Wrong key for alt-dest ---------- */
static void
test_wrong_key_alt_dest(void)
{
    fprintf(stderr, "\n--- Test 11: Default key used for alt-dest (wrong key) ---\n");
    uint8_t frame[FRAME_SIZE];
    struct pkt_params p = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::ff",
        .src_port = 11003, .dst_port = 11004,
        .timeout = 0x5678, .key = DEFAULT_KEY,
        .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
    };
    memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
    size_t len = build_packet(frame, sizeof(frame), &p);
    check("default-key MAC for alt-dest rejected", false, frame, len);
}

/* ---------- Test 12: Plain IPv6 UDP (no DestOpts) ---------- */
static void
test_no_destopts(void)
{
    fprintf(stderr, "\n--- Test 12: IPv6 UDP without DestOpts ext header ---\n");
    uint8_t frame[FRAME_SIZE];
    memset(frame, 0, sizeof(frame));
    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_source, g_src_mac, 6);
    memset(eth->h_dest, 0xff, 6);
    eth->h_proto = htons(ETH_P_IPV6);

    struct ipv6hdr *ip6 = (struct ipv6hdr *)(frame + sizeof(*eth));
    ip6->vtc_flow = htonl(6u << 28);
    ip6->hop_limit = 64;
    ip6->nexthdr = IPPROTO_UDP;
    inet_pton(AF_INET6, "2001:db8::1", ip6->saddr);
    inet_pton(AF_INET6, "2001:db8::2", ip6->daddr);

    struct udphdr *udp = (struct udphdr *)(frame + sizeof(*eth) + sizeof(*ip6));
    udp->source = htons(11005);
    udp->dest = htons(11006);
    uint16_t udp_len = sizeof(*udp) + sizeof(DEFAULT_PAYLOAD);
    udp->len = htons(udp_len);
    memcpy((uint8_t *)udp + sizeof(*udp), DEFAULT_PAYLOAD, sizeof(DEFAULT_PAYLOAD));
    ip6->payload_len = htons(udp_len);
    udp->check = 0;
    udp->check = ipv6_l4_checksum(ip6, IPPROTO_UDP, udp, udp_len);
    if (udp->check == 0) udp->check = 0xFFFF;

    size_t len = sizeof(*eth) + sizeof(*ip6) + udp_len;
    check("plain IPv6 UDP (no ext header) dropped", false, frame, len);
}

/* ---------- Test 13: Non-IPv6 frame (IPv4) ---------- */
static void
test_non_ipv6(void)
{
    fprintf(stderr, "\n--- Test 13: IPv4 frame ---\n");
    uint8_t frame[64];
    memset(frame, 0, sizeof(frame));
    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_source, g_src_mac, 6);
    memset(eth->h_dest, 0xff, 6);
    eth->h_proto = htons(ETH_P_IP);
    /* Minimal IPv4 header (version 4, IHL 5, proto 17 UDP, random payload) */
    uint8_t *ip4 = frame + sizeof(*eth);
    ip4[0] = 0x45;
    ip4[9] = 17;
    /* Not a parseable packet -- just needs to be non-IPv6 */
    check("IPv4 frame dropped", false, frame, sizeof(*eth) + 20 + 8);
}

/* ---------- Test 14: Malformed ext header (wrong option type) ---------- */
static void
test_malformed_ext(void)
{
    fprintf(stderr, "\n--- Test 14: Malformed ext header ---\n");
    uint8_t frame[FRAME_SIZE];
    struct pkt_params p = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
        .src_port = 11007, .dst_port = 11008,
        .timeout = 0x5678, .key = DEFAULT_KEY,
        .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
    };
    memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
    size_t len = build_packet(frame, sizeof(frame), &p);
    /* Corrupt option type (expected 0x1E) */
    uint8_t *ext = frame + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    ext[2] = 0x00;
    check("malformed ext option type dropped", false, frame, len);
}

/* ---------- Test 15: Payload bit-flip after MAC ---------- */
static void
test_payload_bitflip(void)
{
    fprintf(stderr, "\n--- Test 15: Payload bit-flip after MAC ---\n");
    uint8_t frame[FRAME_SIZE];
    struct pkt_params p = {
        .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
        .src_port = 11009, .dst_port = 11010,
        .timeout = 0x5678, .key = DEFAULT_KEY,
        .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
    };
    memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
    size_t len = build_packet(frame, sizeof(frame), &p);
    /* Flip last payload byte */
    frame[len - 1] ^= 0x01;
    check("payload bit-flip dropped", false, frame, len);
}

/* ---------- Test 16: Dedup 4-way set-associative capacity ---------- */
static void
test_dedup_capacity(void)
{
    fprintf(stderr, "\n--- Test 16: Dedup retains first entry after N distinct ---\n");
    uint8_t first_frame[FRAME_SIZE];
    size_t first_len = 0;
    const int N = 16;

    for (int i = 0; i < N; i++) {
        uint8_t frame[FRAME_SIZE];
        struct pkt_params p = {
            .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
            .src_port = (uint16_t)(12000 + i), .dst_port = 12500,
            .timeout = (uint16_t)(0x6000 + i),
            .key = DEFAULT_KEY,
            .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
        };
        memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
        p.eruid[6] = (uint8_t)(0xC0 + i);
        size_t len = build_packet(frame, sizeof(frame), &p);
        if (i == 0) {
            memcpy(first_frame, frame, len);
            first_len = len;
        }
        drain_socket();
        send_frame(frame, len);
        recv_forwarded(RECV_TIMEOUT_MS);
    }
    /* Re-send the first packet; it must still be detected as a duplicate */
    drain_socket();
    send_frame(first_frame, first_len);
    int got = recv_forwarded(RECV_TIMEOUT_MS);
    if (!got) {
        fprintf(stderr, "  [PASS] first packet still marked duplicate after %d others\n", N);
        g_pass++;
    } else {
        fprintf(stderr, "  [FAIL] first packet was re-forwarded (evicted from dedup)\n");
        g_fail++;
    }
}

/* ---------- Test 17: Burst ---------- */
static void
test_burst(void)
{
    fprintf(stderr, "\n--- Test 17: Burst of distinct valid packets ---\n");
    const int N = 64;
    /* Send all first, then count. Socket buffer must hold N * ~100 bytes. */
    drain_socket();
    for (int i = 0; i < N; i++) {
        uint8_t frame[FRAME_SIZE];
        struct pkt_params p = {
            .src_ip = "2001:db8::1", .dst_ip = "2001:db8::2",
            .src_port = (uint16_t)(13000 + i), .dst_port = 13500,
            .timeout = (uint16_t)(0x7000 + i),
            .key = DEFAULT_KEY,
            .payload = DEFAULT_PAYLOAD, .payload_len = sizeof(DEFAULT_PAYLOAD),
        };
        memcpy((void *)p.eruid, DEFAULT_ERUID, 7);
        p.eruid[6] = (uint8_t)(0xE0 + (i & 0x1F));
        p.eruid[5] = (uint8_t)(i >> 5);
        size_t len = build_packet(frame, sizeof(frame), &p);
        send_frame(frame, len);
    }
    /* Count forwarded frames within total deadline */
    int fwd = 0;
    int deadline = 1500;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t end_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + deadline;
    uint8_t buf[FRAME_SIZE];
    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        int64_t now_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        int remaining = (int)(end_ms - now_ms);
        if (remaining <= 0) break;
        struct pollfd pfd = { .fd = g_recv_sock, .events = POLLIN };
        if (poll(&pfd, 1, remaining) <= 0) break;
        ssize_t n = recv(g_recv_sock, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < (ssize_t)sizeof(struct ethhdr)) continue;
        struct ethhdr *eth = (struct ethhdr *)buf;
        if (ntohs(eth->h_proto) != ETH_P_IPV6) continue;
        if (memcmp(eth->h_dest, g_fwd_dst_mac, 6) == 0) {
            fwd++;
            if (fwd >= N) break;
        }
    }
    if (fwd == N) {
        fprintf(stderr, "  [PASS] burst: %d/%d forwarded\n", fwd, N);
        g_pass++;
    } else {
        fprintf(stderr, "  [FAIL] burst: %d/%d forwarded\n", fwd, N);
        g_fail++;
    }
}

static int
get_iface_info(const char *iface, uint8_t mac[6], int *ifindex)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { close(fd); return -1; }
    *ifindex = ifr.ifr_ifindex;
    close(fd);
    return 0;
}

int
main(int argc, char **argv)
{
    const char *iface = "dpdk_test0";
    const char *key_hex = NULL;
    const char *alt_key_hex = NULL;
    const char *alt_dest = NULL;
    const char *dst_mac_str = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc)
            iface = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            key_hex = argv[++i];
        else if (strcmp(argv[i], "--alt-key") == 0 && i + 1 < argc)
            alt_key_hex = argv[++i];
        else if (strcmp(argv[i], "--alt-dest") == 0 && i + 1 < argc)
            alt_dest = argv[++i];
        else if (strcmp(argv[i], "--dst-mac") == 0 && i + 1 < argc)
            dst_mac_str = argv[++i];
    }

    if (dst_mac_str) {
        unsigned int m[6];
        if (sscanf(dst_mac_str, "%x:%x:%x:%x:%x:%x",
                   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
            for (int i = 0; i < 6; i++)
                g_fwd_dst_mac[i] = (uint8_t)m[i];
        }
    }

    uint8_t key[16] = {0};
    if (key_hex) {
        if (hex_to_bytes(key_hex, key, 16) != 0) {
            fprintf(stderr, "Invalid --key hex\n");
            return 1;
        }
    }
    ExpandKey128(key, master_roundkey);

    if (get_iface_info(iface, g_src_mac, &g_ifindex) != 0) {
        fprintf(stderr, "Cannot get interface info for %s\n", iface);
        return 1;
    }

    /* Separate send socket (like send_pkt uses) */
    g_send_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
    if (g_send_sock < 0) {
        perror("send socket");
        return 1;
    }

    /* Separate recv socket with promiscuous mode */
    g_recv_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_recv_sock < 0) {
        perror("recv socket");
        return 1;
    }
    struct sockaddr_ll bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_ifindex = g_ifindex;
    bind_addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(g_recv_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind recv");
        close(g_recv_sock);
        return 1;
    }
    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = g_ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(g_recv_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0)
        perror("setsockopt PACKET_MR_PROMISC");

    g_debug = (getenv("TEST_DEBUG") != NULL);
    fprintf(stderr, "=== dpdk_forward test harness ===\n");
    fprintf(stderr, "interface: %s  ifindex: %d\n", iface, g_ifindex);
    print_hex("src_mac: ", g_src_mac, 6);
    print_hex("key: ", key, 16);

    (void)alt_key_hex;
    (void)alt_dest;

    test_invalid_mac();
    test_valid_mac();
    test_expired_timeout();
    test_future_timeout();
    test_default_key();
    test_different_key();
    test_duplicate_packets();
    test_duplicate_mac_different_ips();
    test_increasing_lengths();
    test_mutable_field_masking();
    test_wrong_key_alt_dest();
    test_no_destopts();
    test_non_ipv6();
    test_malformed_ext();
    test_payload_bitflip();
    test_dedup_capacity();
    test_burst();

    fprintf(stderr, "\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);

    close(g_send_sock);
    close(g_recv_sock);
    return g_fail > 0 ? 1 : 0;
}
