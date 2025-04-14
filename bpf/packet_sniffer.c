/*
    -------------------------------------------------------------------------------
                            Simplified packet flow diagram

                       │                                 ▲
                       │                                 │
                       │                                 │
                       │                                 │
                       │                                 │
                       │                                 │
                       │                                 │
                       │                                 │
                       │                                 │
                       │                                 │
cgroup_skb/ingress hook│                                 │cgroup_skb/egress hook
                       │                                 │
                       │                                 │
                       │                                 │
                       ▼                                 │

                                k8s applications

    --------------------------------------------------------------------------------

    cgroup_skb/ to hook on each targeted cgroup
    socket cookies mechanism to track packets

    Each hook type attached into ingress and egrees parts.

    Since preemption was introduced into eBPF starting from kernel 5.11, all functions should be thread-safe

    References:
    https://docs.cilium.io/en/stable/bpf/#bpf-guide

*/

#include "include/headers.h"
#include "include/util.h"
#include "include/maps.h"
#include "include/log.h"
#include "include/logger_messages.h"
#include "include/common.h"
#include "include/cgroups.h"
#include "include/stats.h"

#include "packet_sniffer_v1.c"

struct pkt
{
    __u64 timestamp;
    __u64 cgroup_id;
    __u64 id;
    __u32 len;
    __u32 tot_len;
    __u32 counter;
    __u16 num;
    __u16 last;
    __u16 ip_hdr_type;
    __u8 direction;
    unsigned char buf[PKT_PART_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct pkt);
} pkt_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct flow_t);
} heap_flow SEC(".maps");

struct pkt_id_t
{
    __u64 id;
    struct bpf_spin_lock lock;
};
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct pkt_id_t);
} pkt_id SEC(".maps");

BPF_PERF_OUTPUT_LARGE(pkts_buffer);

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64); // sock id
    __type(value, __u64); // cgroup id
} socket_cgroups SEC(".maps");

#define NSEC_PER_SEC 1000000000

/*
    defining ENABLE_TRACE_PACKETS enables tracing into kernel cyclic buffer
    which can be fetched on a host system with `cat /sys/kernel/debug/tracing/trace_pipe`
*/

// #define ENABLE_TRACE_PACKETS

#ifdef ENABLE_TRACE_PACKETS
#define TRACE_PACKET_IPV4(NAME, IS_CGROUP, LOCAL_IP, REMOTE_IP, LOCAL_PORT,    \
                          REMOTE_PORT, CGROUP_ID)                              \
  bpf_printk("PKT " NAME " skb: %p len: %d ret: %d", skb,                      \
             (IS_CGROUP ? (skb->len + 14) : skb->len), ret);                   \
  bpf_printk("PKT " NAME " cgroup: %d cookie:0x%x", CGROUP_ID,                 \
             bpf_get_socket_cookie(skb));                                      \
  bpf_printk("PKT " NAME " ip_local: %pi4 ip_remote: %pi4", &(LOCAL_IP),       \
             &(REMOTE_IP));                                                    \
  {                                                                            \
    __u32 __port_local = bpf_ntohl(LOCAL_PORT);                                \
    __u32 __port_remote = bpf_ntohl(REMOTE_PORT);                              \
    bpf_printk("PKT " NAME " port_local: 0x%x port_remote: 0x%x",              \
               __port_local, __port_remote);                                   \
  }                                                                            \
  bpf_printk("PKT " NAME " ip_src: %pi4 ip_dst:%pi4", &(src_ip), &(dst_ip));   \
  {                                                                            \
    __u32 __src_port = bpf_ntohl(src_port);                                    \
    __u32 __dst_port = bpf_ntohl(dst_port);                                    \
    bpf_printk("PKT " NAME " port_src: 0x%x port_dst: 0x%x", __src_port,       \
               __dst_port);                                                    \
  }

#define PRINT_IPV6_ADDR(NAME, ADDR)                                           \
  bpf_printk(NAME ": %x:%x:%x:%x",                                           \
             bpf_ntohl(ADDR[0]), bpf_ntohl(ADDR[1]),                          \
             bpf_ntohl(ADDR[2]), bpf_ntohl(ADDR[3]));
#define PRINT_IPV6_ADDR_STRUCT(NAME, ADDR)                                      \
   __u16 addr_parts[8];                                                        \
    __builtin_memcpy(addr_parts, &ADDR, sizeof(addr_parts));                    \
    bpf_printk(NAME ": %x:%x:%x:%x",                                           \
               bpf_ntohs(addr_parts[0]),                                        \
               bpf_ntohs(addr_parts[1]),                                        \
               bpf_ntohs(addr_parts[2]),                                        \
               bpf_ntohs(addr_parts[3]));                                       \
    bpf_printk(NAME ": %x:%x:%x:%x",                                           \
               bpf_ntohs(addr_parts[4]),                                        \
               bpf_ntohs(addr_parts[5]),                                        \
               bpf_ntohs(addr_parts[6]),                                        \
               bpf_ntohs(addr_parts[7]));                                       
#define TRACE_PACKET_IPV6(NAME, IS_CGROUP, LOCAL_IP6, REMOTE_IP6, LOCAL_PORT,    \
                          REMOTE_PORT, CGROUP_ID)                              \
  bpf_printk("PKT " NAME " [IPv6] skb: %p len: %d", skb,                       \
             (IS_CGROUP ? (skb->len + 14) : skb->len));                        \
  bpf_printk("PKT " NAME " [IPv6] cgroup: %d cookie:0x%x", CGROUP_ID,          \
             bpf_get_socket_cookie(skb));                                      \
  PRINT_IPV6_ADDR("ip_local", LOCAL_IP6);                                      \
  PRINT_IPV6_ADDR("ip_remote", REMOTE_IP6);                                    \
  {                                                                            \
    __u32 __port_local = bpf_ntohl(LOCAL_PORT);                                \
    __u32 __port_remote = bpf_ntohl(REMOTE_PORT);                              \
    bpf_printk("PKT " NAME " port_local: 0x%x port_remote: 0x%x",              \
               __port_local, __port_remote);                                   \
  }                                                                            \
  PRINT_IPV6_ADDR_STRUCT("ip_src", src_ip6);                                          \
  PRINT_IPV6_ADDR_STRUCT("ip_dst", dst_ip6);                                          \
  {                                                                            \
    __u32 __src_port = bpf_ntohl(src_port);                                    \
    __u32 __dst_port = bpf_ntohl(dst_port);                                    \
    bpf_printk("PKT " NAME " port_src: 0x%x port_dst: 0x%x", __src_port,       \
               __dst_port);                                                    \
  }
#define TRACE_PACKET_SENT(NAME) bpf_printk("PKT " NAME " sent");
#else
#define TRACE_PACKET_IPV4(NAME, IS_CGROUP, LOCAL_IP, REMOTE_IP, LOCAL_PORT,    \
                          REMOTE_PORT, CGROUP_ID)
#define TRACE_PACKET_IPV6(NAME, IS_CGROUP, LOCAL_IP6, REMOTE_IP6, LOCAL_PORT,  \
                          REMOTE_PORT, CGROUP_ID)
#define TRACE_PACKET_SENT(NAME)
#endif

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPV6_EXT_MAX_CHAIN 4
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS   0
#endif

#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING   43
#endif

#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT  44
#endif

#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS   60
#endif

#ifndef IPPROTO_MH
#define IPPROTO_MH        135
#endif

struct pkt_sniffer_ctx {
    struct __sk_buff* skb;

    union {
        struct {
            __u32 src;    // IPv4 source
            __u32 dst;    // IPv4 destination
        } v4;
        struct {
            struct in6_addr src; // IPv6 source
            struct in6_addr dst; // IPv6 destination
        } v6;
    } ip;

    __u16 rewrite_port_src;
    __u16 rewrite_port_dst;

    __u64 cgroup_id;
    __u8 direction;
    __u8 transportHdrType;
    __u32 transportOffset;
    bool is_ipv6;
};


static __always_inline void update_flow_stats(struct __sk_buff* skb, struct flow_t* key_flow, __u8 side);
static __always_inline int save_packet(struct pkt_sniffer_ctx* args);
static __always_inline int parse_packet(struct __sk_buff* skb,
    __u32* src_ip4, __u16* src_port,
    __u32* dst_ip4, __u16* dst_port,
    __u8* ipp, struct in6_addr* src_ip6,
    struct in6_addr* dst_ip6,
    __u32* transportOffset);

static __always_inline int filter_packets(struct __sk_buff* skb,
    void* cgrpctxmap, struct packet_sniffer_stats* stats, __u8 side) {
    ++stats->packets_total;

    struct bpf_sock* sk = skb->sk;
    if (!sk) {
        return 1;
    }
    __u64 sknum = (__u64)(void*)sk;

    int zero = 0;
    struct flow_t* key_flow = bpf_map_lookup_elem(&heap_flow, &zero);
    if (key_flow == NULL)
    {
        return 1;
    }

    __u64 cgroup_id = 0;
    if (CGROUP_V1 || PREFER_CGROUP_V1_EBPF_CAPTURE) {
        cgroup_id = get_packet_cgroup(skb, cgrpctxmap);

        // cgroup can not always be defined by context map
        // save socket to the dedicated map
        if (cgroup_id) {
            bpf_map_update_elem(&socket_cgroups, &sknum, &cgroup_id, BPF_ANY);
        } else {
            __u64* c = bpf_map_lookup_elem(&socket_cgroups, &sknum);
            if (c && *c) {
                cgroup_id = *c;
            }
        }

    } else {
        cgroup_id = bpf_skb_cgroup_id(skb);
    }

    __u32 src_ip = 0;
    __u16 src_port = 0;
    __u32 dst_ip = 0;
    __u16 dst_port = 0;
    struct in6_addr src_ip6 = { 0 };
    struct in6_addr dst_ip6 = { 0 };
    __u8 transportHdr = 0;
    __u32 transportOffset = 0;
    int ret = -1;

    __u8 ip_version = 0;

    if (bpf_skb_load_bytes(skb, 0, &ip_version, 1) < 0) {
        return 1;
    }

    ip_version = (ip_version >> 4) & 0xF;

    if (ip_version == 6) {
        ++stats->packets_ipv6;
        ret = parse_packet(skb, &src_ip, &src_port, &dst_ip, &dst_port,
            &transportHdr, &src_ip6, &dst_ip6, &transportOffset);
    } else {
        ++stats->packets_ipv4;
        ret = parse_packet(skb, &src_ip, &src_port, &dst_ip, &dst_port, &transportHdr,
            &src_ip6, &dst_ip6, NULL);
    }
    if (ret) {
        ++stats->packets_parse_failed;
        return 1;
    }
    ++stats->packets_parse_passed;

    struct pkt_sniffer_ctx ctx = {
        .skb = skb,
        .cgroup_id = cgroup_id,
        .direction = side,
        .transportHdrType = transportHdr,
        .transportOffset = transportOffset,
        .rewrite_port_src =
            (side == PACKET_DIRECTION_RECEIVED ? skb->remote_port >> 16
                                               : bpf_htons(skb->local_port)),
        .rewrite_port_dst =
            (side == PACKET_DIRECTION_RECEIVED ? bpf_htons(skb->local_port)
                                               : skb->remote_port >> 16),
    };

    __builtin_memset(key_flow, 0, sizeof(struct flow_t));
    if (side == PACKET_DIRECTION_RECEIVED) {
        key_flow->port_remote = src_port;
        key_flow->port_local = bpf_ntohs(dst_port);
    } else {
        key_flow->port_local = bpf_ntohs(src_port);
        key_flow->port_remote = dst_port;
    }
    key_flow->protocol = transportHdr;
    key_flow->ip_version = ip_version;

    const char* flow_label =
        (side == PACKET_DIRECTION_RECEIVED) ? "cg/in" : "cg/out";
    if (ip_version == 4) {
        ctx.ip.v4.src = src_ip;
        ctx.ip.v4.dst = dst_ip;
        TRACE_PACKET_IPV4(flow_label, true, skb->local_ip4, skb->remote_ip4,
            skb->local_port & 0xffff, skb->remote_port & 0xffff,
            cgroup_id);
        if (side == PACKET_DIRECTION_RECEIVED) {
            key_flow->ip_local.addr_v4.s_addr = dst_ip;
            key_flow->ip_remote.addr_v4.s_addr = src_ip;
        } else {
            key_flow->ip_local.addr_v4.s_addr = src_ip;
            key_flow->ip_remote.addr_v4.s_addr = dst_ip;
        }
    } else {
        __builtin_memcpy(&ctx.ip.v6.src, &src_ip6, sizeof(struct in6_addr));
        __builtin_memcpy(&ctx.ip.v6.dst, &dst_ip6, sizeof(struct in6_addr));
        TRACE_PACKET_IPV6(flow_label, true, skb->local_ip6, skb->remote_ip6,
            skb->local_port & 0xffff, skb->remote_port & 0xffff,
            cgroup_id);

        if (side == PACKET_DIRECTION_RECEIVED) {
            __builtin_memcpy(&key_flow->ip_local.addr_v6, &dst_ip6, sizeof(struct in6_addr));
            __builtin_memcpy(&key_flow->ip_remote.addr_v6, &src_ip6, sizeof(struct in6_addr));
        } else {
            __builtin_memcpy(&key_flow->ip_local.addr_v6, &src_ip6, sizeof(struct in6_addr));
            __builtin_memcpy(&key_flow->ip_remote.addr_v6, &dst_ip6, sizeof(struct in6_addr));
        }
    }
    update_flow_stats(skb, key_flow, side);

    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_PLAIN)) {
        return 1;
    }
    ++stats->packets_program_enabled;

    if (cgroup_id == 0 || !should_target_cgroup(cgroup_id)) {
        return 1;
    }
    ++stats->packets_matched_cgroup;

    ret = save_packet(&ctx);

    if (likely(ret == 0)) {
        ++stats->save_stats.save_packets;
    } else if (ret > 0) {
        ++stats->save_stats.save_failed_logic;
    } else if (ret == -EINVAL) {
        ++stats->save_stats.save_failed_not_opened;
    } else if (ret == -EAGAIN) {
        ++stats->save_stats.save_failed_full;
    } else {
        ++stats->save_stats.save_failed_other;
    }

    return 1;
}

static __always_inline void send_flow_stats(struct __sk_buff* skb, struct flow_stats_t* val_flow, __u8 side, __u8 is_client) {
    if (!val_flow) {
        return;
    }
    if (side == PACKET_DIRECTION_RECEIVED) {
        if (is_client) {
            val_flow->event.packets_recv++;
            val_flow->event.bytes_recv += skb->len;
        } else {
            val_flow->event.packets_sent++;
            val_flow->event.bytes_sent += skb->len;
        }
    } else {
        if (is_client) {
            val_flow->event.packets_sent++;
            val_flow->event.bytes_sent += skb->len;
        } else {
            val_flow->event.packets_recv++;
            val_flow->event.bytes_recv += skb->len;
        }
    }

    __u64 now = bpf_ktime_get_ns();
    if (now - val_flow->last_update_time > 10lu * NSEC_PER_SEC) {
        val_flow->last_update_time = now;
        bpf_perf_event_output(skb, &syscall_events, BPF_F_CURRENT_CPU, &val_flow->event, sizeof(struct syscall_event));
    }
}

static __always_inline void update_flow_stats(struct __sk_buff* skb, struct flow_t* key_flow, __u8 side) {
    send_flow_stats(skb, bpf_map_lookup_elem(&tcp_connect_flow_context, key_flow), side, 1);
    send_flow_stats(skb, bpf_map_lookup_elem(&tcp_accept_flow_context, key_flow), side, 0);

    SWAP_FLOW(key_flow);

    send_flow_stats(skb, bpf_map_lookup_elem(&tcp_connect_flow_context, key_flow), side, 1);
    send_flow_stats(skb, bpf_map_lookup_elem(&tcp_accept_flow_context, key_flow), side, 0);
}

SEC("cgroup_skb/ingress")
int filter_ingress_packets(struct __sk_buff* skb)
{
    struct packet_sniffer_stats* stats = stats_packet_sniffer();
    if (stats == NULL) {
        return 1;
    }

    return filter_packets(skb, &cgrpctxmap_in, stats, PACKET_DIRECTION_RECEIVED);
}

SEC("cgroup_skb/egress")
int filter_egress_packets(struct __sk_buff* skb)
{
    struct packet_sniffer_stats* stats = stats_packet_sniffer();
    if (stats == NULL) {
        return 1;
    }
    return filter_packets(skb, &cgrpctxmap_eg, stats, PACKET_DIRECTION_SENT);
}

static __noinline int save_packet(struct pkt_sniffer_ctx* ctx)
{
    int ret = 0;
    struct __sk_buff* skb = ctx->skb;

    __u8 ip_version = 0;

    if (bpf_skb_load_bytes(skb, 0, &ip_version, 1) < 0) {
        return 1;
    }

    ip_version = (ip_version >> 4) & 0xF;

    __u32 rewrite_ip_src = 0;
    __u32 rewrite_ip_dst = 0;
    struct in6_addr* rewrite_ip6_src = 0;
    struct in6_addr* rewrite_ip6_dst = 0;

    if (ip_version == 4) {
        rewrite_ip_src = ctx->ip.v4.src;
        rewrite_ip_dst = ctx->ip.v4.dst;
    } else {
        rewrite_ip6_src = &ctx->ip.v6.src;
        rewrite_ip6_dst = &ctx->ip.v6.dst;
    }
    __u16 rewrite_port_src = ctx->rewrite_port_src;
    __u16 rewrite_port_dst = ctx->rewrite_port_dst;
    __u64 cgroup_id = ctx->cgroup_id;
    __u8 direction = ctx->direction;
    int zero = 0;

    struct pkt* p = bpf_map_lookup_elem(&pkt_heap, &zero);
    if (p == NULL)
    {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 3, 0l, 0l);
        return 2;
    }

    p->tot_len = skb->len;
    p->counter = skb->len;

    if (p->counter == 0)
    {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 1, 0l, 0l);
        return 3;
    }

    if (p->counter > PKT_MAX_LEN)
    {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 2, 0l, 0l);
        return 4;
    }

    struct pkt_id_t* pkt_id_ptr = bpf_map_lookup_elem(&pkt_id, &zero);
    if (pkt_id_ptr == NULL)
    {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 4, 0l, 0l);
        return 5;
    }
    __u64 packet_id = 0;
    bpf_spin_lock(&pkt_id_ptr->lock);
    packet_id = pkt_id_ptr->id++;
    bpf_spin_unlock(&pkt_id_ptr->lock);

    // send initial chunk before the first packet
    if (unlikely(packet_id == 0)) {
        if (bpf_perf_event_output(skb, &pkts_buffer, BPF_F_CURRENT_CPU, p, 0))
        {
            log_error(skb, LOG_ERROR_PKT_SNIFFER, 11, 0l, 0l);
        }
    }

    p->timestamp = compat_get_uprobe_timestamp();
    p->cgroup_id = cgroup_id;
    p->direction = direction;
    p->id = packet_id;
    p->num = 0;
    p->len = 0;
    p->last = 0;
    p->ip_hdr_type = bpf_ntohs(ctx->skb->protocol);

#pragma unroll
    for (__u32 i = 0; (i < PKT_MAX_LEN / PKT_PART_LEN) && p->counter; i++)
    {
        p->len = (p->counter <= PKT_PART_LEN) ? p->counter : PKT_PART_LEN;
        p->num = i;
        p->counter -= p->len;
        p->last = (p->counter == 0) ? 1 : 0;

        if (p->len == PKT_PART_LEN)
        {
            if (bpf_skb_load_bytes(skb, i * PKT_PART_LEN, &p->buf[0], PKT_PART_LEN) != 0)
            {
                log_error(skb, LOG_ERROR_PKT_SNIFFER, 6, 0l, 0l);
                return 6;
            }
        } else
        {
            uint16_t p_len = p->len;
            if (p_len < 1 || p_len > 4095)
            {
                // This is assertion if branch - should never happens according above logic
                log_error(skb, LOG_ERROR_PKT_SNIFFER, 7, 0l, 0l);
                return 7;
            }
            p_len -= 1; // to satisfy verifier in below bpf_skb_load_bytes
            if (p_len + 1 < sizeof(p->buf))
            {
                if (bpf_skb_load_bytes(skb, i * PKT_PART_LEN, &p->buf[0], p_len + 1) != 0)
                {
                    log_error(skb, LOG_ERROR_PKT_SNIFFER, 8, 0l, 0l);
                    return 8;
                }
            } else
            {
                // This is assertion if branch - should never happens according above logic
                log_error(skb, LOG_ERROR_PKT_SNIFFER, 9, 0l, 0l);
                return 9;
            }
        }
        if (ip_version == 6) {
            struct ipv6hdr* ip6 = (struct ipv6hdr*)p->buf;
            if (rewrite_ip6_src)
                __builtin_memcpy(&ip6->saddr, rewrite_ip6_src, sizeof(struct in6_addr));
            if (rewrite_ip6_dst)
                __builtin_memcpy(&ip6->daddr, rewrite_ip6_dst, sizeof(struct in6_addr));

            if (ctx->transportHdrType == IPPROTO_TCP || ctx->transportHdrType == IPPROTO_UDP) {
                if (ctx->transportOffset >= PKT_PART_LEN) {
                    log_error(skb, LOG_ERROR_PKT_SNIFFER, 12, ctx->transportOffset, 0l);
                    return 10;
                }

                void* transport_hdr = (void*)(&p->buf[ctx->transportOffset]);

                if ((void*)transport_hdr + sizeof(struct tcphdr) > (void*)&p->buf[PKT_PART_LEN]) {
                    log_error(skb, LOG_ERROR_PKT_SNIFFER, 13, ctx->transportOffset, 0l);
                    return 11;
                }

                __u16* src_dst = (__u16*)transport_hdr;
                if (rewrite_port_src)
                    *src_dst = rewrite_port_src;
                if (rewrite_port_dst)
                    *(src_dst + 1) = rewrite_port_dst;
            }
        } else {
            struct iphdr* ip = (struct iphdr*)p->buf;
            if (rewrite_ip_src)
                ip->saddr = rewrite_ip_src;
            if (rewrite_ip_dst)
                ip->daddr = rewrite_ip_dst;
            if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP)
            {
                int hdrsize = ip->ihl * 4;
                __u16* src_dst = (__u16*)(&p->buf[0] + hdrsize);
                if (rewrite_port_src)
                    *src_dst = rewrite_port_src;
                if (rewrite_port_dst)
                    *(src_dst + 1) = rewrite_port_dst;
            }
        }

        long err_perf = bpf_perf_event_output(skb, &pkts_buffer, BPF_F_CURRENT_CPU, p, sizeof(struct pkt));
        if (err_perf)
        {
            if (!ret) {
                ret = err_perf;
            }
            log_error(skb, LOG_ERROR_PKT_SNIFFER, 10, 0l, 0l);
        }
    }
    return ret;
}

/* parse_packet to find out IP addresses and ports information
   @skb: pointer to the packet
   @src_ip4: pointer to the source IPv4 address
   @src_port: pointer to the source port
   @dst_ip4: pointer to the destination IPv4 address
   @dst_port: pointer to the destination port
   @ipp: pointer to the IP protocol number
   @src_ip6: pointer to the source IPv6 address
   @dst_ip6: pointer to the destination IPv6 address
   @transportOffset: pointer to the transport layer offset
returns 0 on success, -1 on error
*/
static __always_inline int parse_packet(struct __sk_buff* skb,
    __u32* src_ip4, __u16* src_port,
    __u32* dst_ip4, __u16* dst_port,
    __u8* ipp, struct in6_addr* src_ip6,
    struct in6_addr* dst_ip6,
    __u32* transportOffset) {
    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    void* cursor = data;

    __u8 ip_proto = 0;
    if (skb->protocol == bpf_htons(ETH_P_IP)) {

        struct iphdr* ip = (struct iphdr*)cursor;
        if (ip + 1 > (struct iphdr*)data_end)
            return -1;

        if (src_ip4) {
            *src_ip4 = ip->saddr;
        }
        if (dst_ip4) {
            *dst_ip4 = ip->daddr;
        }

        int hdrsize = ip->ihl * 4;
        if (hdrsize < sizeof(struct iphdr))
            return -1;

        if ((void*)ip + hdrsize > data_end)
            return -1;

        cursor += hdrsize;
        ip_proto = ip->protocol;
        if (ipp) {
            *ipp = ip_proto;
        }
    } else {
        struct ipv6hdr* ip6 = (struct ipv6hdr*)cursor;
        if ((ip6 + 1 > (struct ipv6hdr*)data_end)) {
            return -1;
        }

        if (src_ip6) {
            __builtin_memcpy(src_ip6, &ip6->saddr, sizeof(struct in6_addr));
        }

        if (dst_ip6) {
            __builtin_memcpy(dst_ip6, &ip6->daddr, sizeof(struct in6_addr));
        }

        ip_proto = ip6->nexthdr;
        cursor += sizeof(struct ipv6hdr);

#pragma unroll
        for (int i = 0; i < IPV6_EXT_MAX_CHAIN; i++) {
            struct ipv6_opt_hdr* hdr = (struct ipv6_opt_hdr*)cursor;

            if (hdr + 1 > (struct ipv6_opt_hdr*)data_end)
                return -1;

            if (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP ||
                ip_proto == IPPROTO_ICMPV6) {
                break; // Reached the transport layer
            }

            switch (ip_proto) {
            case IPPROTO_HOPOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_DSTOPTS:
            case IPPROTO_MH:
                cursor += (hdr->hdrlen + 1) * 8;
                break;
            case IPPROTO_AH:
                cursor += hdr->hdrlen * 4;
                break;
            case IPPROTO_FRAGMENT:
                cursor += 8;
                break;
            default:
                return -1;
            }

            if (cursor > data_end)
                return -1;

            ip_proto = hdr->nexthdr;
        }

        if (transportOffset) {
            *transportOffset = cursor - data;
        }

        if (ipp) {
            *ipp = ip_proto;
        }
    }

    if (ip_proto == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)cursor;
        if (tcp + 1 > (struct tcphdr*)data_end)
            return -1;
        if (src_port) {
            *src_port = tcp->source;
        }
        if (dst_port) {
            *dst_port = tcp->dest;
        }

        cursor += tcp->doff * 4;
    }

    if (ip_proto == IPPROTO_UDP) {
        struct udphdr* udp = (struct udphdr*)cursor;
        if (udp + 1 > (struct udphdr*)data_end)
            return -1;
        if (src_port) {
            *src_port = udp->source;
        }
        if (dst_port) {
            *dst_port = udp->dest;
        }
    }

    return 0;
}