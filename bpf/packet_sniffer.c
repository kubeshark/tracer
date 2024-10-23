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

    References:
    https://docs.cilium.io/en/stable/bpf/#bpf-guide

*/

#include "include/headers.h"
#include "include/util.h"
#include "include/maps.h"
#include "include/log.h"
#include "include/logger_messages.h"
#include "include/common.h"

const volatile __u64 DISABLE_EBPF_CAPTURE = 0;

/*
    defining ENABLE_TRACE_PACKETS enables tracing into kernel cyclic buffer
    which can be fetched on a host system with `cat /sys/kernel/debug/tracing/trace_pipe`
*/

// #define ENABLE_TRACE_PACKETS

#ifdef ENABLE_TRACE_PACKETS
#define TRACE_PACKET(NAME, IS_CGROUP, LOCAL_IP, REMOTE_IP, LOCAL_PORT, REMOTE_PORT, CGROUP_ID)                                                                             \
    bpf_printk("PKT " NAME " skb: %p len: %d ret: %d, cgroup: %d cookie:0x%x", skb, (IS_CGROUP ? (skb->len + 14) : skb->len), ret, CGROUP_ID, bpf_get_socket_cookie(skb)); \
    bpf_printk("PKT " NAME " ip_local: %pi4 ip_remote: %pi4", &(LOCAL_IP), &(REMOTE_IP));                                                                                  \
    {                                                                                                                                                                      \
        __u32 __port_local = bpf_ntohl(LOCAL_PORT);                                                                                                                        \
        __u32 __port_remote = bpf_ntohl(REMOTE_PORT);                                                                                                                      \
        bpf_printk("PKT " NAME " port_local: 0x%x port_remote: 0x%x", __port_local, __port_remote);                                                                        \
    }                                                                                                                                                                      \
    bpf_printk("PKT " NAME " ip_src: %pi4 ip_dst:%pi4", &(src_ip), &(dst_ip));                                                                                             \
    {                                                                                                                                                                      \
        __u32 __src_port = bpf_ntohl(src_port);                                                                                                                            \
        __u32 __dst_port = bpf_ntohl(dst_port);                                                                                                                            \
        bpf_printk("PKT " NAME " port_src: 0x%x port_dst: 0x%x", __src_port, __dst_port);                                                                                  \
    }
#define TRACE_PACKET_SENT(NAME) \
    bpf_printk("PKT " NAME " sent");
#else
#define TRACE_PACKET(NAME, IS_CGROUP, LOCAL_IP, REMOTE_IP, LOCAL_PORT, REMOTE_PORT, CGROUP_ID) \
    src_ip;                                                                                    \
    dst_ip;                                                                                    \
    src_port;                                                                                  \
    dst_port;
#define TRACE_PACKET_SENT(NAME)
#endif

#define ETH_P_IP 0x0800

static __always_inline void save_packet(struct __sk_buff *skb, __u32 offset, __u32 rewrite_ip_src, __u16 rewrite_port_src, __u32 rewrite_ip_dst, __u16 rewrite_port_dst, __u64 cgroup_id, __u8 direction);
static __always_inline int parse_packet(struct __sk_buff *skb, int is_tc, __u32 *src_ip4, __u16 *src_port, __u32 *dst_ip4, __u16 *dst_port, __u8 *ipp);

// TODO: remove cookies from the socket_cookies map on socket close,
// untill this LRU performs cleaning

int reported_cookie_error = 0;
static __always_inline __u64 get_socket_cookie(struct __sk_buff *skb)
{
    __u64 cookie = bpf_get_socket_cookie(skb);
    if (!cookie && !reported_cookie_error)
    {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 100, 0l, 0l);
        reported_cookie_error = 1;
    }

    return cookie;
}

static __always_inline int filter_packets(struct __sk_buff *skb, __u8 side)
{
    if (DISABLE_EBPF_CAPTURE)
        return 1;
    if (capture_disabled())
        return 1;

    __u64 cookie = get_socket_cookie(skb);
    if (!cookie)
        return 1;

    __u32 src_ip = 0;
    __u16 src_port = 0;
    __u32 dst_ip = 0;
    __u16 dst_port = 0;
    int ret = parse_packet(skb, 0, &src_ip, &src_port, &dst_ip, &dst_port, NULL);
    TRACE_PACKET("cg/in", true, skb->local_ip4, skb->remote_ip4, skb->local_port & 0xffff, skb->remote_port & 0xffff, bpf_skb_cgroup_id(skb));
    if (!ret)
    {
        return 1;
    }

    struct socket_cookie_data init_data = {
        .cgroup_id = bpf_skb_cgroup_id(skb),
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .side = side,
    };
    bpf_map_update_elem(&socket_cookies, &cookie, &init_data, BPF_NOEXIST);
    struct socket_cookie_data *data = bpf_map_lookup_elem(&socket_cookies, &cookie);
    if (!data)
    {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 101, 0l, 0l);
        return 1;
    }

    if (data->side == side)
    {
        src_ip = data->src_ip;
        src_port = data->src_port;
        dst_ip = data->dst_ip;
        dst_port = data->dst_port;
    }
    else
    {
        src_ip = data->dst_ip;
        src_port = data->dst_port;
        dst_ip = data->src_ip;
        dst_port = data->src_port;
    }

    save_packet(skb, 0, src_ip, src_port, dst_ip, dst_port, bpf_skb_cgroup_id(skb), side);

    return 1;
}

SEC("cgroup_skb/ingress")
int filter_ingress_packets(struct __sk_buff *skb)
{
    return filter_packets(skb, PACKET_DIRECTION_RECEIVED);
}

SEC("cgroup_skb/egress")
int filter_egress_packets(struct __sk_buff *skb)
{
    return filter_packets(skb, PACKET_DIRECTION_SENT);
}

struct pkt_sniffer_ctx
{
    struct __sk_buff *skb;
    __u32 offset;
    __u32 rewrite_ip_src;
    __u16 rewrite_port_src;
    __u32 rewrite_ip_dst;
    __u16 rewrite_port_dst;
    __u64 cgroup_id;
    __u8 direction;
};

static __noinline void _save_packet(struct pkt_sniffer_ctx *ctx);
static __always_inline void save_packet(struct __sk_buff *skb, __u32 offset, __u32 rewrite_ip_src, __u16 rewrite_port_src, __u32 rewrite_ip_dst, __u16 rewrite_port_dst, __u64 cgroup_id, __u8 direction)
{
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

// TODO: remove offset:
//  mark _save_packet as _noinline to make BPF-to-BPF call
static __noinline void _save_packet(struct pkt_sniffer_ctx *ctx)
{
    struct __sk_buff *skb = ctx->skb;
    __u32 offset = ctx->offset;
    __u32 rewrite_ip_src = ctx->rewrite_ip_src;
    __u16 rewrite_port_src = ctx->rewrite_port_src;
    __u32 rewrite_ip_dst = ctx->rewrite_ip_dst;
    __u16 rewrite_port_dst = ctx->rewrite_port_dst;
    __u64 cgroup_id = ctx->cgroup_id;
    __u8 direction = ctx->direction;
    int zero = 0;

    struct pkt *p = bpf_map_lookup_elem(&pkt_heap, &zero);
    if (p == NULL)
    {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 3, 0l, 0l);
        return;
    }

    // void *data = (void *)(long)skb->data;
    p->tot_len = skb->len;
    p->counter = skb->len;

    if (p->counter < offset)
    {
        return;
    }
    // data += offset;
    // pkt_len -= offset;

    if (p->counter == 0)
    {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 1, 0l, 0l);
        return;
    }

    if (p->counter > PKT_MAX_LEN)
    {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 2, 0l, 0l);
        return;
    }


    __u64 *pkt_id_ptr = bpf_map_lookup_elem(&pkt_id, &zero);
    if (pkt_id_ptr == NULL)
    {
        log_error(skb, LOG_ERROR_PKT_SNIFFER, 4, 0l, 0l);
        return;
    }
    p->timestamp = compat_get_uprobe_timestamp();
    //p->timestamp = 0;
    p->cgroup_id = cgroup_id;
    p->direction = direction;
    p->id = *pkt_id_ptr;
    p->num = 0;
    p->len = 0;
    p->last = 0;
    (*pkt_id_ptr)++;

    for (__u32 i = 0; (i < PKT_MAX_LEN / PKT_PART_LEN) && p->counter; i++)
    {
        p->len = (p->counter < PKT_PART_LEN) ? p->counter : PKT_PART_LEN;
        if (p->len < 0)
        {
            log_error(skb, LOG_ERROR_PKT_SNIFFER, 5, 0l, 0l);
            bpf_printk("!!! TAIL NOT SENT0: %d", p->len);
            return;
        }
        long err = 0;
        p->num = i;
        p->counter -= p->len;
        p->last = (p->counter == 0) ? 1 : 0;

        if (p->len == PKT_PART_LEN)
        {
            err = bpf_skb_load_bytes(skb, i * PKT_PART_LEN, &p->buf[0], PKT_PART_LEN);
        }
        else
        {
            __s32 p_len = p->len;
            for (int j = 0; j < 4096; j++) {
                if(bpf_skb_load_bytes(skb, i * PKT_PART_LEN+j, &p->buf[j], 1)) break;
                p_len--;
            }
            if (p_len != 0) {
                err = -1;
            }
        }

        if (err != 0)
        {
            log_error(skb, LOG_ERROR_PKT_SNIFFER, 6, 0l, 0l);
            bpf_printk("ERROR 2");
            return;
        }

        struct iphdr *ip = (struct iphdr *)p->buf;
        if (rewrite_ip_src)
            ip->saddr = rewrite_ip_src;
        if (rewrite_ip_dst)
            ip->daddr = rewrite_ip_dst;
        if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP)
        {
            int hdrsize = ip->ihl * 4;
            __u16 *src_dst = (__u16 *)(&p->buf[0] + hdrsize);
            if (rewrite_port_src)
                *src_dst = rewrite_port_src;
            if (rewrite_port_dst)
                *(src_dst + 1) = rewrite_port_dst;
        }

        if (bpf_perf_event_output(skb, &pkts_buffer, BPF_F_CURRENT_CPU, p, sizeof(struct pkt)))
        {
            log_error(skb, LOG_ERROR_PKT_SNIFFER, 7, 0l, 0l);
            bpf_printk("ERROR 3");
        }
    }
}

/* parse_packet identifies TLS packet
  retuns:
  0 in case packet has TCP source or destination port equal to 443 - in this case packet is treated as TLS and not going to be processed
  not 0 in other cases
*/
static __always_inline int parse_packet(struct __sk_buff *skb, int is_tc, __u32 *src_ip4, __u16 *src_port, __u32 *dst_ip4, __u16 *dst_port, __u8 *ipp)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    void *cursor = data;

    if (is_tc)
    {
        struct ethhdr *eth = (struct ethhdr *)cursor;
        if (eth + 1 > (struct ethhdr *)data_end)
            return 1;

        cursor += sizeof(struct ethhdr);
    }

    __u8 ip_proto = 0;
    if (skb->protocol == bpf_htons(ETH_P_IP))
    {

        struct iphdr *ip = (struct iphdr *)cursor;
        if (ip + 1 > (struct iphdr *)data_end)
            return 2;

        if (src_ip4)
        {
            *src_ip4 = ip->saddr;
        }
        if (dst_ip4)
        {
            *dst_ip4 = ip->daddr;
        }

        int hdrsize = ip->ihl * 4;
        if (hdrsize < sizeof(struct iphdr))
            return 3;

        if ((void *)ip + hdrsize > data_end)
            return 4;

        cursor += hdrsize;
        ip_proto = ip->protocol;
        if (ipp)
        {
            *ipp = ip_proto;
        }

        if (ip_proto == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *)cursor;
            if (tcp + 1 > (struct tcphdr *)data_end)
                return 5;
            if (src_port)
            {
                *src_port = tcp->source;
            }
            if (dst_port)
            {
                *dst_port = tcp->dest;
            }

            cursor += tcp->doff * 4;
            if (tcp->dest == bpf_htons(443) || tcp->source == bpf_htons(443))
            {
                // skip only packets with tcp port 443 to support previous bpf filter
                return 0;
            }
        }

        if (ip_proto == IPPROTO_UDP)
        {
            struct udphdr *udp = (struct udphdr *)cursor;
            if (udp + 1 > (struct udphdr *)data_end)
                return 5;
            if (src_port)
            {
                *src_port = udp->source;
            }
            if (dst_port)
            {
                *dst_port = udp->dest;
            }
        }
    }

    return 6;
}