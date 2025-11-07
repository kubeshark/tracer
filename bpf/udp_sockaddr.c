// bpf/udp_sockaddr_min.c
#include "include/common.h"
#include "include/maps.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);  
    __type(key, __u32);
    __type(value, __u64);
} udp_sockaddr_hits SEC(".maps");

static __always_inline void bump(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&udp_sockaddr_hits, &idx);
    if (v) { (*v)++; }
}

static __always_inline int udp_sa_noop(struct bpf_sock_addr *ctx, __u32 idx) {
    bump(idx);
    return 1;  
}

SEC("cgroup/sendmsg4") int udp_sendmsg4(struct bpf_sock_addr *ctx){ return udp_sa_noop(ctx, 0); }
SEC("cgroup/recvmsg4") int udp_recvmsg4(struct bpf_sock_addr *ctx){ return udp_sa_noop(ctx, 1); }
SEC("cgroup/sendmsg6") int udp_sendmsg6(struct bpf_sock_addr *ctx){ return udp_sa_noop(ctx, 2); }
SEC("cgroup/recvmsg6") int udp_recvmsg6(struct bpf_sock_addr *ctx){ return udp_sa_noop(ctx, 3); }
