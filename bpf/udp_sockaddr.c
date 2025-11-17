/*
SPDX-License-Identifier: GPL-3.0
*/
#include "include/common.h"
#include "include/log.h"
#include "include/maps.h"
#include "include/pids.h"

static __always_inline int udp_sockaddr_store_ctx_v4(struct bpf_sock_addr *ctx, bool is_send) {
    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_SYSTEM)) return 1;
    if (ctx->protocol != IPPROTO_UDP) return 1;

    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (!cookie) cookie = (__u64)ctx->sk;

    __u64 skptr = (__u64)ctx->sk; 
    bpf_map_update_elem(&udp_sk_cookie, &skptr, &cookie, BPF_ANY);

    struct flow_t ft = {};
    ft.protocol   = IPPROTO_UDP;
    ft.ip_version = 4;

    if (is_send && ctx->msg_src_ip4 && ctx->msg_src_ip4 != 0) {
        ft.ip_local.addr_v4.s_addr = ctx->msg_src_ip4;
    }

    if (ctx->user_ip4) {
        ft.ip_remote.addr_v4.s_addr = ctx->user_ip4;
        ft.port_remote = (__be16)(ctx->user_port & 0xffff); 
    }

    if (is_send) {
        bpf_map_update_elem(&udp_send_context, &cookie, &ft, BPF_ANY);
    } else {
        bpf_map_update_elem(&udp_recv_context, &cookie, &ft, BPF_ANY);
    }
    return 1;
}

static __always_inline int udp_sockaddr_store_ctx_v6(struct bpf_sock_addr *ctx, bool is_send) {
    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_SYSTEM)) return 1;
    if (ctx->protocol != IPPROTO_UDP) return 1;

    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (!cookie) cookie = (__u64)ctx->sk;

    __u64 skptr = (__u64)ctx->sk; 
    bpf_map_update_elem(&udp_sk_cookie, &skptr, &cookie, BPF_ANY);

    struct flow_t ft = {};
    ft.protocol   = IPPROTO_UDP;
    ft.ip_version = 6;

    if (is_send) {
        __u32 r0 = ctx->msg_src_ip6[0], r1 = ctx->msg_src_ip6[1], r2 = ctx->msg_src_ip6[2], r3 = ctx->msg_src_ip6[3];
        if ((r0|r1|r2|r3) != 0) {
            ft.ip_local.addr_v6.in6_u.u6_addr32[0] = r0;
            ft.ip_local.addr_v6.in6_u.u6_addr32[1] = r1;
            ft.ip_local.addr_v6.in6_u.u6_addr32[2] = r2;
            ft.ip_local.addr_v6.in6_u.u6_addr32[3] = r3;
        }
    }

    __u32 r0 = ctx->user_ip6[0], r1 = ctx->user_ip6[1], r2 = ctx->user_ip6[2], r3 = ctx->user_ip6[3];
    if ((r0|r1|r2|r3) != 0) {
        ft.ip_remote.addr_v6.in6_u.u6_addr32[0] = r0;
        ft.ip_remote.addr_v6.in6_u.u6_addr32[1] = r1;
        ft.ip_remote.addr_v6.in6_u.u6_addr32[2] = r2;
        ft.ip_remote.addr_v6.in6_u.u6_addr32[3] = r3;
        ft.port_remote = (__be16)(ctx->user_port & 0xffff); 
    }

    if (is_send) {
        bpf_map_update_elem(&udp_send_context, &cookie, &ft, BPF_ANY);
    } else {
        bpf_map_update_elem(&udp_recv_context, &cookie, &ft, BPF_ANY);
    }
    return 1;
}

SEC("cgroup/sendmsg4")
int udp_sendmsg4(struct bpf_sock_addr *ctx) { return udp_sockaddr_store_ctx_v4(ctx, true); }

SEC("cgroup/recvmsg4")
int udp_recvmsg4(struct bpf_sock_addr *ctx) { return udp_sockaddr_store_ctx_v4(ctx, false); }

SEC("cgroup/sendmsg6")
int udp_sendmsg6(struct bpf_sock_addr *ctx) { return udp_sockaddr_store_ctx_v6(ctx, true); }

SEC("cgroup/recvmsg6")
int udp_recvmsg6(struct bpf_sock_addr *ctx) { return udp_sockaddr_store_ctx_v6(ctx, false); }
