#ifndef NO_PACKET_SNIFFER

/*
    -------------------------------------------------------------------------------
                            Simplified packet flow diagram

           eth0 ingress│                                 ▲ eth0 egress
                       │                                 │
                       │                                 │
                       │                                 │
                       │                                 │
        tc/ingress hook│                                 │tc/egress hook
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

    Two types of hooks are in use:
    1. tc/ to hook on each kubernetes network interface
    2. cgroup_skb/ to hook on each targeted cgroup

    Each hook type attached into ingress and egrees parts.

    cgroup_skb programs :
    - cgroup_skb/ingress program exports incoming packet with 'received' flag onto perf buffer
    - cgroup_skb/egress program saves ip/port information into the map, the packet expected to be exported into perf buffer once it get into tc/egress

    tc programs :
    - use bpf_skb_pull_data bpf helper to load whole payload into sk_buf. Without that call kernel loads only first 1500 bytes
    - export packets with overrided (from cgroup_skb/) ports into perf buffers

    References:
    https://docs.cilium.io/en/stable/bpf/#bpf-guide

*/

#include "include/headers.h"
#include "include/util.h"
#include "include/maps.h"
#include "include/log.h"
#include "include/logger_messages.h"
#include "include/common.h"

/*
    defining ENABLE_TRACE_PACKETS enables tracing into kernel cyclic buffer
    which can be fetched on a host system with `cat /sys/kernel/debug/tracing/trace_pipe`
*/

// #define ENABLE_TRACE_PACKETS

#ifdef ENABLE_TRACE_PACKETS
#define TRACE_PACKET(NAME, IS_CGROUP, LOCAL_IP, REMOTE_IP, LOCAL_PORT, REMOTE_PORT, CGROUP_ID) \
    bpf_printk("PKT "NAME" len: %d ret: %d, cgroup: %d cookie:0x%x", (IS_CGROUP?(skb->len+14):skb->len), ret, CGROUP_ID, bpf_get_socket_cookie(skb)); \
    bpf_printk("PKT "NAME" ip_local: %pi4 ip_remote: %pi4", &(LOCAL_IP), &(REMOTE_IP)); \
    {__u32 __port_local = bpf_ntohl(LOCAL_PORT); __u32 __port_remote= bpf_ntohl(REMOTE_PORT);bpf_printk("PKT "NAME" port_local: 0x%x port_remote: 0x%x", __port_local, __port_remote);} \
    bpf_printk("PKT "NAME" ip_src: %pi4 ip_dst:%pi4", &(src_ip), &(dst_ip)); \
    {__u32 __src_port = bpf_ntohl(src_port); __u32 __dst_port= bpf_ntohl(dst_port);bpf_printk("PKT "NAME" port_src: 0x%x port_dst: 0x%x", __src_port, __dst_port); }
#define TRACE_PACKET_SENT(NAME) \
        bpf_printk("PKT "NAME" sent");
#else
#define TRACE_PACKET(NAME, IS_CGROUP, LOCAL_IP, REMOTE_IP, LOCAL_PORT, REMOTE_PORT, CGROUP_ID) \
    src_ip; dst_ip; src_port; dst_port;
#define TRACE_PACKET_SENT(NAME)
#endif

#define ETH_P_IP	0x0800

static __always_inline void save_packet(struct __sk_buff* skb, __u32 offset, __u32 rewrite_ip_src, __u16 rewrite_port_src, __u32 rewrite_ip_dst, __u16 rewrite_port_dst, __u64 cgroup_id, __u8 direction);
static __always_inline int parse_packet(struct __sk_buff* skb, int is_tc, __u32* src_ip4, __u16* src_port, __u32* dst_ip4, __u16* dst_port, __u8* ipp);

SEC("cgroup_skb/ingress")
int filter_ingress_packets(struct __sk_buff* skb) {

    __u32 src_ip = 0;
    __u16 src_port = 0;
    __u32 dst_ip = 0;
    __u16 dst_port = 0;
    int ret = parse_packet(skb, 0, &src_ip, &src_port, &dst_ip, &dst_port, NULL);
    if (ret) {
        TRACE_PACKET("cg/in", true, skb->local_ip4, skb->remote_ip4, skb->local_port & 0xffff, skb->remote_port & 0xffff, bpf_skb_cgroup_id(skb));
        save_packet(skb, 0, 0, 0, 0, 0, bpf_skb_cgroup_id(skb), PACKET_DIRECTION_RECEIVED);
        TRACE_PACKET_SENT("cg/in");
    }
    return 1;
}

SEC("cgroup_skb/egress")
int filter_egress_packets(struct __sk_buff* skb) {

    __u32 src_ip = 0;
    __u16 src_port = 0;
    __u8 ip_proto = 0;
    __u32 dst_ip = 0;
    __u16 dst_port = 0;
    int ret = parse_packet(skb, 0, &src_ip, &src_port, &dst_ip, &dst_port, &ip_proto);
    if (ret) {
        TRACE_PACKET("cg/eg", true, skb->local_ip4, skb->remote_ip4, bpf_htons(skb->local_port & 0xffff), skb->remote_port & 0xffff, bpf_skb_cgroup_id(skb));
        struct pkt_flow egress = {
            .src_ip = src_ip,
            .src_port = src_port,
            .size = skb->len + sizeof(struct ethhdr),
            .proto = ip_proto,
            .pad = 0,
        };
        struct pkt_data data = {
            .cgroup_id = bpf_skb_cgroup_id(skb),
            .rewrite_src_port = bpf_htons(skb->local_port & 0xffff),
        };
        bpf_map_update_elem(&pkt_context, &egress, &data, BPF_ANY);
    }
    return 1;
}

SEC("tc/ingress")
int packet_pull_ingress(struct __sk_buff* skb)
{
    bpf_skb_pull_data(skb, skb->len);

    __u32 src_ip = 0;
    __u16 src_port = 0;
    __u32 dst_ip = 0;
    __u16 dst_port = 0;
    __u8 ip_proto = 0;
    int ret = parse_packet(skb, 1, &src_ip, &src_port, &dst_ip, &dst_port, &ip_proto);
    if (ret) {
        TRACE_PACKET("tc/in", false, dst_ip, src_ip, dst_port, src_port, 0);
        struct pkt_flow egress = { };
        egress.size = skb->len;
        egress.src_ip = src_ip;
        egress.src_port = src_port;
        egress.proto = ip_proto;

        // in some cases packet after "cgroup_skb/egress" misses "tc/egress" part and get passed here to "tc/ingress"
        struct pkt_data* data = bpf_map_lookup_elem(&pkt_context, &egress);
        if (data) {
            save_packet(skb, sizeof(struct ethhdr), 0, data->rewrite_src_port, 0, 0, data->cgroup_id, PACKET_DIRECTION_RECEIVED);
            bpf_map_delete_elem(&pkt_context, &egress);
            TRACE_PACKET_SENT("tc/in");
        }
    }
    return 0; //TC_ACT_OK
}

SEC("tc/egress")
int packet_pull_egress(struct __sk_buff* skb)
{
    bpf_skb_pull_data(skb, skb->len);
    __u32 src_ip = 0;
    __u16 src_port = 0;
    __u32 dst_ip = 0;
    __u16 dst_port = 0;
    __u8 ip_proto = 0;
    int ret = parse_packet(skb, 1, &src_ip, &src_port, &dst_ip, &dst_port, &ip_proto);
    if (ret) {
        TRACE_PACKET("tc/eg", false, src_ip, dst_ip, src_port, dst_port, bpf_skb_cgroup_id(skb));
        struct pkt_flow egress = { };
        egress.size = skb->len;
        egress.src_ip = src_ip;
        egress.src_port = src_port;
        egress.proto = ip_proto;

        struct pkt_data* data = bpf_map_lookup_elem(&pkt_context, &egress);
        if (data) {
            save_packet(skb, sizeof(struct ethhdr), 0, data->rewrite_src_port, 0, 0, data->cgroup_id, PACKET_DIRECTION_SENT);
            bpf_map_delete_elem(&pkt_context, &egress);
            TRACE_PACKET_SENT("tc/eg");
        }
    }
    return 0; // TC_ACT_OK
}

struct pkt_sniffer_ctx {
    struct __sk_buff* skb;
    __u32 offset;
    __u32 rewrite_ip_src;
    __u16 rewrite_port_src;
    __u32 rewrite_ip_dst;
    __u16 rewrite_port_dst;
    __u64 cgroup_id;
    __u8 direction;
};

static __noinline void _save_packet(struct pkt_sniffer_ctx* ctx);
static __always_inline void save_packet(struct __sk_buff* skb, __u32 offset, __u32 rewrite_ip_src, __u16 rewrite_port_src, __u32 rewrite_ip_dst, __u16 rewrite_port_dst, __u64 cgroup_id, __u8 direction) {
    struct pkt_sniffer_ctx ctx = {
        .skb = skb,
        .offset = offset,
        .rewrite_ip_src = rewrite_ip_src,
        .rewrite_port_src = rewrite_port_src,
        .rewrite_ip_dst = rewrite_ip_dst,
        .rewrite_port_dst = rewrite_port_dst,
        .cgroup_id = cgroup_id,
        .direction = direction,
    };
    return _save_packet(&ctx);
}

// mark _save_packet as _noinline to make BPF-to-BPF call
static __noinline void _save_packet(struct pkt_sniffer_ctx* ctx) {
    struct __sk_buff* skb = ctx->skb;
    __u32 offset = ctx->offset;
    __u32 rewrite_ip_src = ctx->rewrite_ip_src;
    __u16 rewrite_port_src = ctx->rewrite_port_src;
    __u32 rewrite_ip_dst = ctx->rewrite_ip_dst;
    __u16 rewrite_port_dst = ctx->rewrite_port_dst;
    __u64 cgroup_id = ctx->cgroup_id;
    __u8 direction = ctx->direction;

    void* data = (void*)(long)skb->data;
    __u32 pkt_len = skb->len;

    if (pkt_len < offset) {
        return;
    }
    data += offset;
    pkt_len -= offset;

    if (pkt_len == 0) {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 1, 0l, 0l);
        return;
    }

    if (pkt_len > PKT_MAX_LEN) {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 2, 0l, 0l);
        return;
    }

    int zero = 0;
    struct pkt* p = bpf_map_lookup_elem(&pkt_heap, &zero);
    if (p == NULL) {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 3, 0l, 0l);
        return;
    }

    __u64* pkt_id_ptr = bpf_map_lookup_elem(&pkt_id, &zero);
    if (pkt_id_ptr == NULL) {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 4, 0l, 0l);
        return;
    }
    p->timestamp = bpf_ktime_get_tai_ns();
    p->cgroup_id = cgroup_id;
    p->direction = direction;
    p->id = *pkt_id_ptr;
    (*pkt_id_ptr)++;

    __u32 read_len = 0;

    for (__u32 i = 0; (i < PKT_MAX_LEN / PKT_PART_LEN) && pkt_len; i++) {
        read_len = (pkt_len < PKT_PART_LEN) ? pkt_len : PKT_PART_LEN;
        if (read_len < 0) {
            log_error(skb, LOG_ERROR_PKT_SNIFFER, 5, 0l, 0l);
            return;
        }
        long err = 0;
        p->num = i;
        p->len = read_len;


        if (p->len == sizeof(p->buf)) {
            err = bpf_probe_read_kernel(p->buf, sizeof(p->buf), data + i * PKT_PART_LEN);
        } else {
            read_len &= (sizeof(p->buf) - 1); // Buffer must be N^2
            err = bpf_probe_read_kernel(p->buf, read_len, data + i * PKT_PART_LEN);
        }

        if (err != 0) {
            log_error(skb, LOG_ERROR_PKT_SNIFFER, 6, 0l, 0l);
            return;
        }
        pkt_len -= read_len;
        p->last = (pkt_len == 0) ? 1 : 0;

        struct iphdr* ip = (struct iphdr*)p->buf;
        if (rewrite_ip_src)
            ip->saddr = rewrite_ip_src;
        if (rewrite_ip_dst)
            ip->daddr = rewrite_ip_dst;
        if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
            int hdrsize = ip->ihl * 4;
            __u16* src_dst = (__u16*)(&p->buf[0] + hdrsize);
            if (rewrite_port_src)
                *src_dst = rewrite_port_src;
            if (rewrite_port_dst)
                *(src_dst + 1) = rewrite_port_dst;
        }

        bpf_perf_event_output(skb, &pkts_buffer, BPF_F_CURRENT_CPU, p, sizeof(struct pkt));
    }
}

/* parse_packet identifies TLS packet
  retuns:
  0 in case packet has TCP source or destination port equal to 443 - in this case packet is treated as TLS and not going to be processed
  not 0 in other cases
*/
static __always_inline int parse_packet(struct __sk_buff* skb, int is_tc, __u32* src_ip4, __u16* src_port, __u32* dst_ip4, __u16* dst_port, __u8* ipp) {
    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    void* cursor = data;

    if (is_tc) {
        struct ethhdr* eth = (struct ethhdr*)cursor;
        if (eth + 1 > (struct ethhdr*)data_end)
            return 1;

        cursor += sizeof(struct ethhdr);
    }

    __u8 ip_proto = 0;
    if (skb->protocol == bpf_htons(ETH_P_IP)) {

        struct iphdr* ip = (struct iphdr*)cursor;
        if (ip + 1 > (struct iphdr*)data_end)
            return 2;

        if (src_ip4) {
            *src_ip4 = ip->saddr;
        }
        if (dst_ip4) {
            *dst_ip4 = ip->daddr;
        }

        int hdrsize = ip->ihl * 4;
        if (hdrsize < sizeof(struct iphdr))
            return 3;

        if ((void*)ip + hdrsize > data_end)
            return 4;

        cursor += hdrsize;
        ip_proto = ip->protocol;
        if (ipp) {
            *ipp = ip_proto;
        }

        if (ip_proto == IPPROTO_TCP)
        {
            struct tcphdr* tcp = (struct tcphdr*)cursor;
            if (tcp + 1 > (struct tcphdr*)data_end)
                return 5;
            if (src_port) {
                *src_port = tcp->source;
            }
            if (dst_port) {
                *dst_port = tcp->dest;
            }

            cursor += tcp->doff * 4;
            if (tcp->dest == bpf_htons(443) || tcp->source == bpf_htons(443)) {
                // skip only packets with tcp port 443 to support previous bpf filter
                return 0;
            }
        }

        if (ip_proto == IPPROTO_UDP)
        {
            struct udphdr* udp = (struct udphdr*)cursor;
            if (udp + 1 > (struct udphdr*)data_end)
                return 5;
            if (src_port) {
                *src_port = udp->source;
            }
            if (dst_port) {
                *dst_port = udp->dest;
            }
        }

    }

    return 6;
}

#endif // NO_PACKET_SNIFFER