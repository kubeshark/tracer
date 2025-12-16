/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

/*

"kprobe/security_*" tracepoints are not used here as soon as they can not be implemented in some platforms (for example arm64 M1)
*/

#include "include/events.h"
#include "include/probes.h"

SEC("kprobe/tcp_connect")
void BPF_KPROBE(tcp_connect)
{
    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_SYSTEM))
        return;

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (!is_task_from_netns(task)) {
        return;
    }

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

    u64 inode = 0;
    struct socket* s = BPF_CORE_READ(sk, sk_socket);
    if (s) {
        struct file* sock_file = BPF_CORE_READ(s, file);
        if (sock_file) {
            inode = BPF_CORE_READ(sock_file, f_inode, i_ino);
        }
    }

    struct syscall_event ev = {
        .timestamp = compat_get_uprobe_timestamp(),
        .event_id = SYSCALL_EVENT_ID_CONNECT,
        .cgroup_id = cgroup_id,
        .pid = get_task_pid(task),
        .parent_pid = get_task_pid(get_parent_task(task)),
        .host_pid = tracer_get_current_pid_tgid() >> 32,
        .host_parent_pid = tracer_get_task_pid_tgid(0, get_parent_task(task)) >> 32,
        .inode_id = inode,
    };

    struct flow_t key_flow;
    __builtin_memset(&key_flow, 0, sizeof(key_flow));
    key_flow.protocol = IPPROTO_TCP;
    key_flow.ip_version = 4;

    if (read_addrs_ports(ctx, sk, &key_flow.ip_local.addr_v4.s_addr, &key_flow.port_local,
                         &key_flow.ip_remote.addr_v4.s_addr, &key_flow.port_remote)) {
        return;
    }

    // open connect has local port in host order and remote port in network order
    ev.ip_src = key_flow.ip_local.addr_v4.s_addr;
    ev.port_src = key_flow.port_local;
    ev.ip_dst = key_flow.ip_remote.addr_v4.s_addr;
    ev.port_dst = bpf_ntohs(key_flow.port_remote);

    __u64 key = (__u64)sk;
    if (bpf_map_update_elem(&tcp_connect_context, &key, &key_flow, BPF_ANY)) {
        log_error(ctx, LOG_ERROR_EVENT, EVENT_ERROR_CODE_UPDATE_TCP_CONNECT, 0l, 0l);
        return;
    }

    struct task_struct* group_leader = BPF_CORE_READ(task, group_leader);
    bpf_probe_read_kernel_str(&ev.comm, 16, group_leader->comm);

    if (bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &ev, sizeof(struct syscall_event))) {
        log_error(ctx, LOG_ERROR_EVENT, EVENT_ERROR_CODE_PERF_SYSCALL, 0l, 0l);
        return;
    }

    struct flow_stats_t val_stats = {
        .last_update_time = bpf_ktime_get_ns(),
        .event = ev,
    };
    if (bpf_map_update_elem(&tcp_connect_flow_context, &key_flow, &val_stats, BPF_ANY)) {
        log_error(ctx, LOG_ERROR_EVENT, EVENT_ERROR_CODE_UPDATE_FLOW, 0l, 0l);
        return;
    }
}

SEC("kretprobe/accept4")
void BPF_KRETPROBE(syscall__accept4_ret)
{
    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_SYSTEM))
        return;

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (!is_task_from_netns(task)) {
        return;
    }

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

    u64 inode = 0;
    struct file* sock_file = BPF_CORE_READ(sock, file);
    if (sock_file) {
        inode = BPF_CORE_READ(sock_file, f_inode, i_ino);
    }

    struct syscall_event ev = {
        .timestamp = compat_get_uprobe_timestamp(),
        .event_id = SYSCALL_EVENT_ID_ACCEPT,
        .cgroup_id = cgroup_id,
        .pid = get_task_pid(task),
        .parent_pid = get_task_pid(get_parent_task(task)),
        .host_pid = tracer_get_current_pid_tgid() >> 32,
        .host_parent_pid = tracer_get_task_pid_tgid(0, get_parent_task(task)) >> 32,
        .inode_id = inode,
    };
    struct flow_t key_flow;
    __builtin_memset(&key_flow, 0, sizeof(key_flow));
    key_flow.protocol = IPPROTO_TCP;
    key_flow.ip_version = 4;

    if (read_addrs_ports(ctx, sk, &key_flow.ip_local.addr_v4.s_addr, &key_flow.port_local,
                         &key_flow.ip_remote.addr_v4.s_addr, &key_flow.port_remote)) {
        return;
    }

    // open accept has local port in host order and remote port in network order
    ev.ip_src = key_flow.ip_remote.addr_v4.s_addr;
    ev.port_src = bpf_ntohs(key_flow.port_remote);
    ev.ip_dst = key_flow.ip_local.addr_v4.s_addr;
    ev.port_dst = key_flow.port_local;

    __u64 key = (__u64)sk;
    if (bpf_map_update_elem(&tcp_accept_context, &key, &key_flow, BPF_ANY)) {
        log_error(ctx, LOG_ERROR_EVENT, EVENT_ERROR_CODE_UPDATE_TCP_ACCEPT, 0l, 0l);
        return;
    }

    struct task_struct* group_leader = BPF_CORE_READ(task, group_leader);
    bpf_probe_read_kernel_str(&ev.comm, 16, group_leader->comm);

    if (bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &ev, sizeof(struct syscall_event))) {
        log_error(ctx, LOG_ERROR_EVENT, EVENT_ERROR_CODE_PERF_SYSCALL, 0l, 0l);
        return;
    }

    struct flow_stats_t val_stats = {
        .last_update_time = bpf_ktime_get_ns(),
        .event = ev,
    };
    if (bpf_map_update_elem(&tcp_accept_flow_context, &key_flow, &val_stats, BPF_ANY)) {
        log_error(ctx, LOG_ERROR_EVENT, EVENT_ERROR_CODE_UPDATE_FLOW, 0l, 0l);
        return;
    }

    return;
}

SEC("kretprobe/do_accept")
void BPF_KRETPROBE(do_accept)
{
    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_SYSTEM))
        return;

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (!is_task_from_netns(task)) {
        return;
    }

    __u64 cgroup_id = compat_get_current_cgroup_id(NULL);
    struct file* f = (struct file*)PT_REGS_RC(ctx);
    if (!f)
        return;

    void* sock = BPF_CORE_READ(f, private_data);
    if (!sock) {
        return;
    }

    __u64 id = tracer_get_current_pid_tgid();
    struct accept_data data = {
        .sock = (unsigned long)sock,
    };
    if (bpf_map_update_elem(&accept_context, &id, &data, BPF_ANY)) {
        log_error(ctx, LOG_ERROR_EVENT, EVENT_ERROR_CODE_UPDATE_ACCEPT_CONTEXT, 0l, 0l);
        return;
    }
    return;
}

SEC("cgroup/connect4")
int trace_cgroup_connect4(struct bpf_sock_addr* ctx)
{
    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_SYSTEM))
        return 1;

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (!is_task_from_netns(task)) {
        return 1;
    }

    return 1;
}

SEC("kprobe/tcp_close")
void BPF_KPROBE(tcp_close)
{
    if (program_disabled(PROGRAM_DOMAIN_CAPTURE_SYSTEM))
        return;

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (!is_task_from_netns(task)) {
        return;
    }

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

    u64 inode = 0;
    struct socket* s = BPF_CORE_READ(sk, sk_socket);
    if (s) {
        struct file* sock_file = BPF_CORE_READ(s, file);
        if (sock_file) {
            inode = BPF_CORE_READ(sock_file, f_inode, i_ino);
        }
    }

    __u16 event = 0;
    struct flow_t* key_flow = NULL;
    __u64 key = (__u64)sk;
    key_flow = bpf_map_lookup_elem(&tcp_accept_context, &key);
    event = SYSCALL_EVENT_ID_ACCEPT_CLOSE;
    if (!key_flow) {
        key_flow = bpf_map_lookup_elem(&tcp_connect_context, &key);
        event = SYSCALL_EVENT_ID_CONNECT_CLOSE;
    }
    if (!key_flow) {
        return;
    }

    struct syscall_event ev = {
        .timestamp = compat_get_uprobe_timestamp(),
        .event_id = event,
        .cgroup_id = cgroup_id,
        .pid = get_task_pid(task),
        .parent_pid = get_task_pid(get_parent_task(task)),
        .host_pid = tracer_get_current_pid_tgid() >> 32,
        .host_parent_pid = tracer_get_task_pid_tgid(0, get_parent_task(task)) >> 32,
        .inode_id = inode,
    };

    struct flow_stats_t* val_flow = NULL;
    if (event == SYSCALL_EVENT_ID_ACCEPT_CLOSE) {
        // close accept has local port in host order and remote port in network order
        ev.ip_src = key_flow->ip_remote.addr_v4.s_addr;
        ev.port_src = bpf_ntohs(key_flow->port_remote);
        ev.ip_dst = key_flow->ip_local.addr_v4.s_addr;
        ev.port_dst = key_flow->port_local;

        val_flow = bpf_map_lookup_elem(&tcp_accept_flow_context, key_flow);
    } else if (event == SYSCALL_EVENT_ID_CONNECT_CLOSE) {
        // close connect has local port in host order and remote port in network order
        ev.ip_src = key_flow->ip_local.addr_v4.s_addr;
        ev.port_src = key_flow->port_local;
        ev.ip_dst = key_flow->ip_remote.addr_v4.s_addr;
        ev.port_dst = bpf_ntohs(key_flow->port_remote);

        val_flow = bpf_map_lookup_elem(&tcp_connect_flow_context, key_flow);
    } else {
        log_error(ctx, LOG_ERROR_EVENT, EVENT_ERROR_CODE_UNKOWN_EVENT, 0l, 0l);
        goto cleanup;
    }

    if (val_flow) {
        ev.packets_sent = val_flow->event.packets_sent;
        ev.bytes_sent = val_flow->event.bytes_sent;
        ev.packets_recv = val_flow->event.packets_recv;
        ev.bytes_recv = val_flow->event.bytes_recv;
        if (event == SYSCALL_EVENT_ID_ACCEPT_CLOSE) {
            bpf_map_delete_elem(&tcp_accept_flow_context, key_flow);
        } else {
            bpf_map_delete_elem(&tcp_connect_flow_context, key_flow);
        }
    }

    struct task_struct* group_leader = BPF_CORE_READ(task, group_leader);
    bpf_probe_read_kernel_str(&ev.comm, 16, group_leader->comm);

    if (bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &ev, sizeof(struct syscall_event))) {
        log_error(ctx, LOG_ERROR_EVENT, EVENT_ERROR_CODE_PERF_SYSCALL, 0l, 0l);
        goto cleanup;
    }

cleanup:
    if (event == SYSCALL_EVENT_ID_ACCEPT_CLOSE) {
        bpf_map_delete_elem(&tcp_accept_context, &key);
    } else if (event == SYSCALL_EVENT_ID_CONNECT_CLOSE) {
        bpf_map_delete_elem(&tcp_connect_context, &key);
    }
}

static __always_inline int read_addrs_ports(struct pt_regs* ctx, struct sock* sk, __be32* saddr, __be16* sport, __be32* daddr, __be16* dport)
{
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
