/*
SPDX-License-Identifier: GPL-3.0
*/

#include "include/common.h"
#include "include/log.h"
#include "include/maps.h"
#include "include/pids.h"

struct udp_ctx_t {
    __u64 cookie;
    __u64 ts_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u8  is_send;     
    __u8  ip_version; 
    __u8  _pad[2];
    union {
        __be32 v4;
        struct in6_addr v6;  
    } peer_ip;
    __be16 peer_port;        
    __u8   _pad2[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);            
    __type(value, struct udp_ctx_t);
    __uint(max_entries, 32768);
} udp_context_by_cookie SEC(".maps");

static __always_inline int udp_sockaddr_store_ctx_v4(struct bpf_sock_addr *ctx, bool is_send) {
    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_SYSTEM))
        return 1;
    if (ctx->protocol != IPPROTO_UDP)
        return 1;

    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (!cookie) cookie = (__u64)ctx;

    struct udp_ctx_t v = {
        .cookie     = cookie,
        .ts_ns      = bpf_ktime_get_ns(),
        .cgroup_id  = compat_get_current_cgroup_id(NULL),
        .pid        = tracer_get_current_pid_tgid() >> 32,
        .is_send    = is_send ? 1 : 0,
        .ip_version = 4,
        .peer_port  = 0,
    };

    if (ctx->user_ip4) {              
        v.peer_ip.v4 = ctx->user_ip4;
        v.peer_port  = ctx->user_port; 
    }

    bpf_map_update_elem(&udp_context_by_cookie, &cookie, &v, BPF_ANY);
    return 1;
}

static __always_inline int udp_sockaddr_store_ctx_v6(struct bpf_sock_addr *ctx, bool is_send) {
    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_SYSTEM))
        return 1;
    if (ctx->protocol != IPPROTO_UDP)
        return 1;

    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (!cookie) cookie = (__u64)ctx;

    struct udp_ctx_t v = {
        .cookie     = cookie,
        .ts_ns      = bpf_ktime_get_ns(),
        .cgroup_id  = compat_get_current_cgroup_id(NULL),
        .pid        = tracer_get_current_pid_tgid() >> 32,
        .is_send    = is_send ? 1 : 0,
        .ip_version = 6,
        .peer_port  = 0,
    };

    __u8 b0  = ctx->user_ip6[0];  __u8 b1  = ctx->user_ip6[1];
    __u8 b2  = ctx->user_ip6[2];  __u8 b3  = ctx->user_ip6[3];
    __u8 b4  = ctx->user_ip6[4];  __u8 b5  = ctx->user_ip6[5];
    __u8 b6  = ctx->user_ip6[6];  __u8 b7  = ctx->user_ip6[7];
    __u8 b8  = ctx->user_ip6[8];  __u8 b9  = ctx->user_ip6[9];
    __u8 b10 = ctx->user_ip6[10]; __u8 b11 = ctx->user_ip6[11];
    __u8 b12 = ctx->user_ip6[12]; __u8 b13 = ctx->user_ip6[13];
    __u8 b14 = ctx->user_ip6[14]; __u8 b15 = ctx->user_ip6[15];

    bool has6 = (b0|b1|b2|b3|b4|b5|b6|b7|b8|b9|b10|b11|b12|b13|b14|b15) != 0;

    if (has6) {
        v.peer_ip.v6.in6_u.u6_addr8[0]  = b0;
        v.peer_ip.v6.in6_u.u6_addr8[1]  = b1;
        v.peer_ip.v6.in6_u.u6_addr8[2]  = b2;
        v.peer_ip.v6.in6_u.u6_addr8[3]  = b3;
        v.peer_ip.v6.in6_u.u6_addr8[4]  = b4;
        v.peer_ip.v6.in6_u.u6_addr8[5]  = b5;
        v.peer_ip.v6.in6_u.u6_addr8[6]  = b6;
        v.peer_ip.v6.in6_u.u6_addr8[7]  = b7;
        v.peer_ip.v6.in6_u.u6_addr8[8]  = b8;
        v.peer_ip.v6.in6_u.u6_addr8[9]  = b9;
        v.peer_ip.v6.in6_u.u6_addr8[10] = b10;
        v.peer_ip.v6.in6_u.u6_addr8[11] = b11;
        v.peer_ip.v6.in6_u.u6_addr8[12] = b12;
        v.peer_ip.v6.in6_u.u6_addr8[13] = b13;
        v.peer_ip.v6.in6_u.u6_addr8[14] = b14;
        v.peer_ip.v6.in6_u.u6_addr8[15] = b15;

        v.peer_port = ctx->user_port; 
    }

    bpf_map_update_elem(&udp_context_by_cookie, &cookie, &v, BPF_ANY);
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
