/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

/*

"kprobe/security_*" tracepoints are not used here as soon as they can not be implemented in some platforms (for example arm64 M1)
*/

#include "include/events.h"

SEC("kprobe/tcp_connect")
void BPF_KPROBE(tcp_connect) {
    if (capture_disabled())
        return;

    long err;
    __u64 cgroup_id = compat_get_current_cgroup_id(NULL);
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
        .cgroup_id = cgroup_id,
        .pid = get_task_pid(task),
        .parent_pid = get_task_pid(get_parent_task(task)),
        .host_pid = BPF_CORE_READ(task, tgid),
        .host_parent_pid = get_parent_task_pid(task),
    };

    if (read_addrs_ports(ctx, (struct sock*)PT_REGS_PARM1(ctx), &ev.ip_src, &ev.port_src, &ev.ip_dst, &ev.port_dst)) {
        return;
    }

    __u64 key = (__u64)sk;
    bpf_map_update_elem(&tcp_connect_context, &key, &ev.pid, BPF_ANY);

    bpf_probe_read_kernel_str(&ev.comm, 16, task->comm);

    ev.port_dst = bpf_ntohs(ev.port_dst);
    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &ev, sizeof(struct syscall_event));
}


SEC("kretprobe/accept4")
void BPF_KRETPROBE(syscall__accept4_ret) {
    if (capture_disabled())
        return;

    long err;
    __u64 id = tracer_get_current_pid_tgid();
    __u64 cgroup_id = compat_get_current_cgroup_id(NULL);
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

    struct sock_common* common = (void*)sk;
    family = BPF_CORE_READ(common, skc_family);

    if (family != AF_INET && family != AF_INET6) {
        return;
    }

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();

    struct syscall_event ev = {
        .event_id = SYSCALL_EVENT_ID_ACCEPT,
        .cgroup_id = cgroup_id,
        .pid = get_task_pid(task),
        .parent_pid = get_task_pid(get_parent_task(task)),
        .host_pid = BPF_CORE_READ(task, tgid),
        .host_parent_pid = get_parent_task_pid(task),
    };

    if (read_addrs_ports(ctx, sk, &ev.ip_dst, &ev.port_dst, &ev.ip_src, &ev.port_src)) {
        return;
    }

    __u64 key = (__u64)sk;
    bpf_map_update_elem(&tcp_accept_context, &key, &ev.pid, BPF_ANY);

    bpf_probe_read_kernel_str(&ev.comm, 16, task->comm);

    ev.port_src = bpf_ntohs(ev.port_src);
    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &ev, sizeof(struct syscall_event));

    return;
}

SEC("kretprobe/do_accept")
void BPF_KRETPROBE(do_accept) {
    if (capture_disabled())
        return;

    __u64 cgroup_id = compat_get_current_cgroup_id(NULL);
    struct file* f = (struct file*)PT_REGS_RC(ctx);
    if (!f)
        return;

    void *sock = BPF_CORE_READ(f, private_data);
    if (!sock) {
        return;
    }

    __u64 id = tracer_get_current_pid_tgid();
    struct accept_data data = {
        .sock = (unsigned long)sock,
    };
    bpf_map_update_elem(&accept_context, &id, &data, BPF_ANY);
    return;
}

SEC("cgroup/connect4")
int trace_cgroup_connect4(struct bpf_sock_addr* ctx) {
    if (capture_disabled())
        return 1;

    return 1;
}

SEC("kprobe/tcp_close")
void BPF_KPROBE(tcp_close) {
    if (capture_disabled())
        return;

    long err;
    __u64 cgroup_id = compat_get_current_cgroup_id(NULL);
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

    __u16 event = 0;

    __u64 key = (__u64)sk;
    if (bpf_map_lookup_elem(&tcp_accept_context, &key)) {
        event = SYSCALL_EVENT_ID_CLOSE_ACCEPT;
        bpf_map_delete_elem(&tcp_accept_context, &key);
    } else if (bpf_map_lookup_elem(&tcp_connect_context, &key)) {
        event = SYSCALL_EVENT_ID_CLOSE_CONNECT;
        bpf_map_delete_elem(&tcp_connect_context, &key);
    } else {
        return;
    }

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    struct syscall_event ev = {
        .event_id = event,
        .cgroup_id = cgroup_id,
        .pid = get_task_pid(task),
        .parent_pid = get_task_pid(get_parent_task(task)),
        .host_pid = BPF_CORE_READ(task, tgid),
        .host_parent_pid = get_parent_task_pid(task),
    };

    if (read_addrs_ports(ctx, (struct sock*)PT_REGS_PARM1(ctx), &ev.ip_src, &ev.port_src, &ev.ip_dst, &ev.port_dst)) {
        return;
    }

    bpf_probe_read_kernel_str(&ev.comm, 16, task->comm);

    ev.port_dst = bpf_ntohs(ev.port_dst);
    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &ev, sizeof(struct syscall_event));
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