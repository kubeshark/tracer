#include "include/headers.h"
#include "include/util.h"
#include "include/maps.h"
#include "include/log.h"
#include "include/logger_messages.h"
#include "include/common.h"

#define ETH_P_IP	0x0800

static __always_inline void send_packet(struct __sk_buff* skb, __u32 offset, __u32 rewrite_ip_src, __u16 rewrite_port_src, __u32 rewrite_ip_dst, __u16 rewrite_port_dst, __u64 cgroup_id);
static __always_inline int parse_packet(struct __sk_buff* skb, int is_tc, __u32* src_ip4, __u16* src_port, __u32* dst_ip4, __u16* dst_port, __u8* ipp);

SEC("cgroup_skb/ingress")
int filter_ingress_packets(struct __sk_buff* skb) {

    int ret = parse_packet(skb, 0, NULL, NULL, NULL, NULL, NULL);
    if (ret) {
        send_packet(skb, 0, 0, 0, 0, 0, bpf_skb_cgroup_id(skb));
    }
    return 1;
}

SEC("cgroup_skb/egress")
int filter_egress_packets(struct __sk_buff* skb) {

    __u32 src_ip = 0;
    __u16 src_port = 0;
    __u8 ip_proto = 0;
    int ret = parse_packet(skb, 0, &src_ip, &src_port, NULL, NULL, &ip_proto);
    if (ret) {
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
    __u8 ip_proto = 0;
    int ret = parse_packet(skb, 1, &src_ip, &src_port, NULL, NULL, &ip_proto);
    if (ret) {
        struct pkt_flow egress = { };
        egress.size = skb->len;
        egress.src_ip = src_ip;
        egress.src_port = src_port;
        egress.proto = ip_proto;

        struct pkt_data* data = bpf_map_lookup_elem(&pkt_context, &egress);
        if (data) {
            send_packet(skb, sizeof(struct ethhdr), 0, data->rewrite_src_port, 0, 0, data->cgroup_id);
            bpf_map_delete_elem(&pkt_context, &egress);
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
    __u8 ip_proto = 0;
    int ret = parse_packet(skb, 1, &src_ip, &src_port, NULL, NULL, &ip_proto);
    if (ret) {
        struct pkt_flow egress = { };
        egress.size = skb->len;
        egress.src_ip = src_ip;
        egress.src_port = src_port;
        egress.proto = ip_proto;

        struct pkt_data* data = bpf_map_lookup_elem(&pkt_context, &egress);
        if (data) {
            send_packet(skb, sizeof(struct ethhdr), 0, data->rewrite_src_port, 0, 0, data->cgroup_id);
            bpf_map_delete_elem(&pkt_context, &egress);
        }
    }
    return 0; // TC_ACT_OK
}

static __always_inline void send_packet(struct __sk_buff* skb, __u32 offset, __u32 rewrite_ip_src, __u16 rewrite_port_src, __u32 rewrite_ip_dst, __u16 rewrite_port_dst, __u64 cgroup_id) {
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
    p->cgroup_id = cgroup_id;
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

static __always_inline int parse_packet(struct __sk_buff* skb, int is_tc, __u32* src_ip4, __u16* src_port, __u32* dst_ip4, __u16* dst_port, __u8* ipp) {
    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    void* cursor = data;

    if (is_tc) {
        struct ethhdr* eth = (struct ethhdr*)cursor;
        if (eth + 1 > data_end)
            return 1;

        cursor += sizeof(struct ethhdr);
    }

    __u8 ip_proto = 0;
    if (skb->protocol == bpf_htons(ETH_P_IP)) {

        struct iphdr* ip = (struct iphdr*)cursor;
        if (ip + 1 > data_end)
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
            if (tcp + 1 > data_end)
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
            if (udp + 1 > data_end)
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

