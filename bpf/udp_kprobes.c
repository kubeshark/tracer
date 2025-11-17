/*
SPDX-License-Identifier: GPL-3.0
*/

#include "include/common.h"
#include "include/log.h"
#include "include/maps.h"
#include "include/events.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} udp_kprobe_hits SEC(".maps");

static __always_inline void bumpk(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&udp_kprobe_hits, &idx);
    if (v) {
        (*v)++; 
    }
}

SEC("kprobe/udp_sendmsg")
int udp_sendmsg_kp(struct pt_regs *ctx)
{
    bumpk(0);
    return 0;
}

SEC("kprobe/udpv6_sendmsg")
int udpv6_sendmsg_kp(struct pt_regs *ctx)
{
    bumpk(1);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int udp_recvmsg_kp(struct pt_regs *ctx)
{
    bumpk(2);
    return 0;
}

SEC("kprobe/udpv6_recvmsg")
int udpv6_recvmsg_kp(struct pt_regs *ctx)
{
    bumpk(3);
    return 0;
}

SEC("kprobe/udp_destroy_sock")
int BPF_KPROBE(udp_destroy_sock, struct sock *sk)
{
    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_SYSTEM))
        return 0;

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (!is_task_from_netns(task))
        return 0;

    __u64 skptr = (__u64)sk;

    __u64 *pcookie = bpf_map_lookup_elem(&udp_sk_cookie, &skptr);
    if (!pcookie)
        goto cleanup_only_sk;
    __u64 cookie = *pcookie;

    struct flow_t *pft = bpf_map_lookup_elem(&cookie_to_flow, &cookie);
    if (!pft)
        goto cleanup_cookie_and_sk;

    struct flow_t ft = {};
    __builtin_memcpy(&ft, pft, sizeof(ft));

    __u64 sent_pkts=0, sent_bytes=0, recv_pkts=0, recv_bytes=0;

    struct flow_stats_t *s = bpf_map_lookup_elem(&udp_send_flow_context, &ft);
    if (s) { sent_pkts = s->event.packets_sent; sent_bytes = s->event.bytes_sent; }

    struct flow_stats_t *r = bpf_map_lookup_elem(&udp_recv_flow_context, &ft);
    if (r) { recv_pkts = r->event.packets_recv; recv_bytes = r->event.bytes_recv; }

    if (ft.ip_version == 4) {
        struct syscall_event ev = {};
        ev.event_id   = SYSCALL_EVENT_ID_UDP_SUMMARY; 
        ev.cgroup_id  = compat_get_current_cgroup_id(NULL);
        ev.pid        = get_task_pid(task);
        ev.parent_pid = get_task_pid(get_parent_task(task));
        ev.host_pid   = tracer_get_current_pid_tgid() >> 32;
        ev.host_parent_pid = tracer_get_task_pid_tgid(0, get_parent_task(task)) >> 32;

        ev.ip_src   = ft.ip_local.addr_v4.s_addr;
        ev.port_src = ft.port_local;                   
        ev.ip_dst   = ft.ip_remote.addr_v4.s_addr;
        ev.port_dst = bpf_ntohs(ft.port_remote);       

        ev.packets_sent = sent_pkts;
        ev.bytes_sent   = sent_bytes;
        ev.packets_recv = recv_pkts;
        ev.bytes_recv   = recv_bytes;

        bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    }

    bpf_map_delete_elem(&udp_send_flow_context, &ft);
    bpf_map_delete_elem(&udp_recv_flow_context, &ft);
    bpf_map_delete_elem(&cookie_to_flow, &cookie);
    bpf_map_delete_elem(&udp_send_context, &cookie);
    bpf_map_delete_elem(&udp_recv_context, &cookie);

cleanup_cookie_and_sk:
    bpf_map_delete_elem(&udp_sk_cookie, &skptr);
    return 0;

cleanup_only_sk:
    bpf_map_delete_elem(&udp_sk_cookie, &skptr);
    return 0;
}