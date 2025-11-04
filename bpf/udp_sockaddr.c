/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

/*
 * UDP dynamic context via cgroup sock_addr hooks.
 * Portable (x86_64/arm64), avoids LSM.
 * This does NOT touch packet counters; packet_sniffer already accounts UDP/TCP.
 * We only enrich resolver context similarly to tcp_* probes.
 */

#include "include/common.h"
#include "include/log.h"
#include "include/maps.h"
#include "include/pids.h"

static __always_inline int udp_sockaddr_handle(struct bpf_sock_addr *ctx, bool is_send) {
    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_SYSTEM))
        return 1;

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (!is_task_from_netns(task))
        return 1;

    if (ctx->protocol != IPPROTO_UDP)
        return 1;

    struct bpf_sock* sk = ctx->sk;
    if (sk == NULL) return 1;

    __u16 family = BPF_CORE_READ(sk, family);

    struct flow_t key_flow = {};
    key_flow.protocol = IPPROTO_UDP;

    if (family == AF_INET) {
        key_flow.ip_version = 4;

        __u32 src_ip4 = BPF_CORE_READ(sk, src_ip4);
        __u32 src_port = BPF_CORE_READ(sk, src_port);  
        key_flow.ip_local.addr_v4.s_addr = src_ip4;
        key_flow.port_local = bpf_ntohs((__be16)src_port); 

        if (ctx->user_ip4) {
            key_flow.ip_remote.addr_v4.s_addr = ctx->user_ip4;
            key_flow.port_remote = ctx->user_port;     
        } else {
            // Connected UDP: ctx->user_* may be zero. We leave remote zero here.
            // (Packet sniffer still has full 5-tuple for /flows)
        }
    }
    else if (family == AF_INET6) {
        key_flow.ip_version = 6;

        struct in6_addr src6 = {};
        bpf_core_read(&src6, sizeof(src6), &sk->src_ip6);
        __u32 src_port = BPF_CORE_READ(sk, src_port);  
        key_flow.ip_local.addr_v6 = src6;
        key_flow.port_local = bpf_ntohs((__be16)src_port);

        bool has_user6 = false;
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            if (ctx->user_ip6[i]) { has_user6 = true; break; }
        }
        if (has_user6) {
            __builtin_memcpy(&key_flow.ip_remote.addr_v6, ctx->user_ip6, 16);
            key_flow.port_remote = ctx->user_port;    
        }
    }
    else {
        return 1;
    }

    __u64 sk_key = (__u64)sk;
    if (is_send) {
        bpf_map_update_elem(&udp_send_context, &sk_key, &key_flow, BPF_ANY);
    } else {
        bpf_map_update_elem(&udp_recv_context, &sk_key, &key_flow, BPF_ANY);
    }
    return 1;
}

SEC("cgroup/sendmsg4")
int udp_sendmsg4(struct bpf_sock_addr *ctx) { return udp_sockaddr_handle(ctx, true); }

SEC("cgroup/recvmsg4")
int udp_recvmsg4(struct bpf_sock_addr *ctx) { return udp_sockaddr_handle(ctx, false); }

SEC("cgroup/sendmsg6")
int udp_sendmsg6(struct bpf_sock_addr *ctx) { return udp_sockaddr_handle(ctx, true); }

SEC("cgroup/recvmsg6")
int udp_recvmsg6(struct bpf_sock_addr *ctx) { return udp_sockaddr_handle(ctx, false); }
