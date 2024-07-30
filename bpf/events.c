/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#include "include/headers.h"
#include "include/util.h"
#include "include/maps.h"
#include "include/log.h"
#include "include/logger_messages.h"
#include "include/pids.h"
#include "include/common.h"

struct accept_data {
    unsigned long sock;
};

BPF_LRU_HASH(accept_context, __u64, struct accept_data);

#define SYSCALL_EVENT_ID_CONNECT 0
#define SYSCALL_EVENT_ID_ACCEPT 1

struct syscall_event {
    char comm[16];

    __u64 cgroup_id;

    __be32 ip_src;
    __be32 ip_dst;
    __be32 pid;
    __be32 parentPid;
    __be32 hostPid;
    __be32 hostParentPid;

    __u16 event_id;
    __be16 port_src;
    __be16 port_dst;
};

BPF_PERF_OUTPUT(syscall_events);

static __always_inline int read_addrs_ports(struct pt_regs* ctx, struct sock* sk, __be32* saddr, __be16* sport, __be32* daddr, __be16* dport);

SEC("kprobe/tcp_connect")
void BPF_KPROBE(tcp_connect) {
    long err;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&cgroup_ids, &cgroup_id)) {
        return;
    }
    __u64 id = tracer_get_current_pid_tgid();

    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);

    short unsigned int family;
    err = bpf_probe_read(&family, sizeof(family), (void*)&sk->__sk_common.skc_family);
    if (err != 0) {
        log_error(ctx, LOG_ERROR_READING_SOCKET_FAMILY, id, err, 0l);
        return;
    }

    if (family != AF_INET) {
        return;
    }

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    struct syscall_event ev = {
        .event_id = SYSCALL_EVENT_ID_CONNECT,
        .hostPid = BPF_CORE_READ(task, pid),
        .cgroup_id = cgroup_id,
        // TODO:
        //pid;
        //parentPid;
        //hostParentPid;
    };


    if (read_addrs_ports(ctx, (struct sock*)PT_REGS_PARM1(ctx), &ev.ip_src, &ev.port_src, &ev.ip_dst, &ev.port_dst)) {
        return;
    }

    bpf_probe_read_kernel_str(&ev.comm, 16, task->comm);

    ev.port_dst = bpf_ntohs(ev.port_dst);
    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &ev, sizeof(struct syscall_event));
}


SEC("kretprobe/accept4")
void BPF_KRETPROBE(syscall__accept4) {
    long err;
    __u64 id = tracer_get_current_pid_tgid();
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct accept_data* data = bpf_map_lookup_elem(&accept_context, &id);
    if (!data) {
        return;
    }
    bpf_map_delete_elem(&accept_context, &id);
    struct socket* sock = (struct socket*)data->sock;
    if (!sock) {
        return;
    }
    struct sock* sk = BPF_CORE_READ(sock, sk);
    short unsigned int family;

    err = bpf_probe_read(&family, sizeof(family), (void*)&sk->__sk_common.skc_family);
    if (err != 0) {
        log_error(ctx, LOG_ERROR_READING_SOCKET_FAMILY, id, err, 0l);
        return;
    }

    if (family != AF_INET) {
        return;
    }

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();

    struct syscall_event ev = {
        .event_id = SYSCALL_EVENT_ID_ACCEPT,
        .hostPid = BPF_CORE_READ(task, pid),
        .cgroup_id = cgroup_id,
        // TODO:
        //pid;
        //parentPid;
        //hostParentPid;
    };

    if (read_addrs_ports(ctx, sk, &ev.ip_dst, &ev.port_dst, &ev.ip_src, &ev.port_src)) {
        return;
    }

    bpf_probe_read_kernel_str(&ev.comm, 16, task->comm);

    ev.port_src = bpf_ntohs(ev.port_src);
    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &ev, sizeof(struct syscall_event));

    return;
}

SEC("kprobe/security_socket_accept")
int BPF_KPROBE(security_socket_accept) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&cgroup_ids, &cgroup_id)) {
        return 0;
    }
    struct socket* sock = (struct socket*)PT_REGS_PARM1(ctx);
    struct socket* newsock = (struct socket*)PT_REGS_PARM2(ctx);
    long err;
    __u64 id = tracer_get_current_pid_tgid();
    struct accept_data data = {
        .sock = (unsigned long)newsock,
    };
    bpf_map_update_elem(&accept_context, &id, &data, BPF_ANY);
    return 0;
}

SEC("cgroup/connect4")
int trace_cgroup_connect4(struct bpf_sock_addr* ctx) {
    return 1;
}

static __always_inline int read_addrs_ports(struct pt_regs* ctx, struct sock* sk, __be32* saddr, __be16* sport, __be32* daddr, __be16* dport) {
    long err;
    __u64 id = tracer_get_current_pid_tgid();

    err = bpf_probe_read(saddr, sizeof(*saddr), (void*)&sk->__sk_common.skc_rcv_saddr);
    if (err != 0) {
        log_error(ctx, LOG_ERROR_READING_SOCKET_SADDR, id, err, 0l);
        return -1;
    }
    err = bpf_probe_read(daddr, sizeof(*daddr), (void*)&sk->__sk_common.skc_daddr);
    if (err != 0) {
        log_error(ctx, LOG_ERROR_READING_SOCKET_DADDR, id, err, 0l);
        return -1;
    }
    err = bpf_probe_read(dport, sizeof(*dport), (void*)&sk->__sk_common.skc_dport);
    if (err != 0) {
        log_error(ctx, LOG_ERROR_READING_SOCKET_DPORT, id, err, 0l);
        return -1;
    }
    err = bpf_probe_read(sport, sizeof(*sport), (void*)&sk->__sk_common.skc_num);
    if (err != 0) {
        log_error(ctx, LOG_ERROR_READING_SOCKET_SPORT, id, err, 0l);
        return -1;
    }

    return 0;
}