/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#include "include/probes.h"

struct found_pid {
    __u64 cgroup;
    __u32 pid;
    __u32 __pad1;
};

BPF_PERF_OUTPUT(perf_found_pid);

BPF_LRU_HASH(fork_info, __u32, struct found_pid);

SEC("raw_tracepoint/sched_process_fork")
int sched_process_fork(struct bpf_raw_tracepoint_args* ctx) {
    struct task_struct* parent = (struct task_struct*)ctx->args[0];
    struct task_struct* child = (struct task_struct*)ctx->args[1];

    __u64 cgroup_id = compat_get_current_cgroup_id(child);

    __u32 child_pid = BPF_CORE_READ(child, pid);
    __u32 child_tid = BPF_CORE_READ(child, tgid);

    __u64 base_pid_tgid = child_pid;
    base_pid_tgid = (base_pid_tgid << 32) | child_pid;

    __u64 pid_tgid = tracer_get_task_pid_tgid(base_pid_tgid, child);

    child_pid = pid_tgid >> 32;
    child_tid = pid_tgid & 0xffffffff;

    struct found_pid p = {
        .cgroup = cgroup_id,
        .pid = child_tid,
        .__pad1 = 0,
    };

    bpf_map_update_elem(&fork_info, &child_tid, &p, BPF_ANY);

    return 0;
}

SEC("kretprobe/sys_execve")
int BPF_KRETPROBE(sys_execve_exit) {
    __u64 pid_tgid = tracer_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = pid_tgid & 0xffffffff;

    struct found_pid* p = bpf_map_lookup_elem(&fork_info, &tgid);
    if (p) {
        bpf_perf_event_output(ctx, &perf_found_pid, BPF_F_CURRENT_CPU, p, sizeof(struct found_pid));
        bpf_map_delete_elem(&fork_info, &tgid);
    }

    return 0;
}