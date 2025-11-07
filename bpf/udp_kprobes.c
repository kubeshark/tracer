/*
SPDX-License-Identifier: GPL-3.0
*/

#include "include/common.h"
#include "include/log.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} udp_kprobe_hits SEC(".maps");

static __always_inline void bump(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&udp_kprobe_hits, &idx);
    if (v) {
        (*v)++; 
    }
}

SEC("kprobe/udp_sendmsg")
int udp_sendmsg_kp(struct pt_regs *ctx)
{
    bump(0);
    return 0;
}

SEC("kprobe/udpv6_sendmsg")
int udpv6_sendmsg_kp(struct pt_regs *ctx)
{
    bump(1);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int udp_recvmsg_kp(struct pt_regs *ctx)
{
    bump(2);
    return 0;
}

SEC("kprobe/udpv6_recvmsg")
int udpv6_recvmsg_kp(struct pt_regs *ctx)
{
    bump(3);
    return 0;
}
