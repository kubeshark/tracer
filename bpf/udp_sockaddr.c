/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
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

    __u16 family = ctx->family;

    /* Build a minimal flow_t carrying proto/ip_version and the *peer* (remote) */
    struct flow_t key_flow = {};
    key_flow.protocol = IPPROTO_UDP;

    if (family == AF_INET) {
        key_flow.ip_version = 4;

        /* Remote peer from ctx (already network order). Local stays zero here. */
        if (ctx->user_ip4) {
            key_flow.ip_remote.addr_v4.s_addr = ctx->user_ip4;
            key_flow.port_remote              = ctx->user_port; /* network order */
        }
    }
    else if (family == AF_INET6) {
        key_flow.ip_version = 6;

        bool has_user6 = false;
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            if (ctx->user_ip6[i]) { has_user6 = true; break; }
        }
        if (has_user6) {
            __builtin_memcpy(&key_flow.ip_remote.addr_v6, ctx->user_ip6, 16);
            key_flow.port_remote = ctx->user_port; /* network order */
        }
    }
    else {
        return 1;
    }

    __u64 key = bpf_get_socket_cookie(ctx);
    if (!key) {
        key = (__u64)ctx; /* fallback: unique per call instance */
    }

    if (is_send) {
        bpf_map_update_elem(&udp_send_context, &key, &key_flow, BPF_ANY);
    } else {
        bpf_map_update_elem(&udp_recv_context, &key, &key_flow, BPF_ANY);
    }

    return 1; /* allow the send/recv */
}

SEC("cgroup/sendmsg4")
int udp_sendmsg4(struct bpf_sock_addr *ctx) { return udp_sockaddr_handle(ctx, true); }

SEC("cgroup/recvmsg4")
int udp_recvmsg4(struct bpf_sock_addr *ctx) { return udp_sockaddr_handle(ctx, false); }

SEC("cgroup/sendmsg6")
int udp_sendmsg6(struct bpf_sock_addr *ctx) { return udp_sockaddr_handle(ctx, true); }

SEC("cgroup/recvmsg6")
int udp_recvmsg6(struct bpf_sock_addr *ctx) { return udp_sockaddr_handle(ctx, false); }