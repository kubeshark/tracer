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

static __always_inline int udp_sockaddr_store_ctx(struct bpf_sock_addr *ctx, bool is_send) {
    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_SYSTEM))
        return 1;

    if (ctx->protocol != IPPROTO_UDP)
        return 1;

    __u16 family = ctx->family;

    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (!cookie) cookie = (__u64)ctx;  

    struct udp_ctx_t v = {
        .cookie    = cookie,
        .ts_ns     = bpf_ktime_get_ns(),
        .cgroup_id = compat_get_current_cgroup_id(NULL),
        .pid       = tracer_get_current_pid_tgid() >> 32,
        .is_send   = is_send ? 1 : 0,
        .ip_version= (family == AF_INET) ? 4 : 6,
        .peer_port = 0,
    };

    if (family == AF_INET) {
        if (ctx->user_ip4) {
            v.peer_ip.v4 = ctx->user_ip4;      
            v.peer_port  = ctx->user_port;     
        }
    }
    else if (family == AF_INET6) {
        __u8 tmp6[16];
        #pragma clang loop unroll(full)
        for (int i = 0; i < 16; i++) { tmp6[i] = ctx->user_ip6[i]; }

        bool has6 = false;
        #pragma clang loop unroll(full)
        for (int i = 0; i < 16; i++) { if (tmp6[i]) { has6 = true; break; } }

        if (has6) {
            #pragma clang loop unroll(full)
            for (int i = 0; i < 16; i++) {
                v.peer_ip.v6.in6_u.u6_addr8[i] = tmp6[i];
            }
            v.peer_port = ctx->user_port;      
        }
    }

    bpf_map_update_elem(&udp_context_by_cookie, &cookie, &v, BPF_ANY);
    return 1; 
}

SEC("cgroup/sendmsg4")
int udp_sendmsg4(struct bpf_sock_addr *ctx) { return udp_sockaddr_store_ctx(ctx, true); }

SEC("cgroup/recvmsg4")
int udp_recvmsg4(struct bpf_sock_addr *ctx) { return udp_sockaddr_store_ctx(ctx, false); }

SEC("cgroup/sendmsg6")
int udp_sendmsg6(struct bpf_sock_addr *ctx) { return udp_sockaddr_store_ctx(ctx, true); }

SEC("cgroup/recvmsg6")
int udp_recvmsg6(struct bpf_sock_addr *ctx) { return udp_sockaddr_store_ctx(ctx, false); }
