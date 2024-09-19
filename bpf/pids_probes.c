/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#include "probes.h"

struct found_pid {
    __u64 cgroup;
    __u32 pid;
};

BPF_PERF_OUTPUT(perf_found_pid);

SEC("raw_tracepoint/sched_process_fork")
int sched_process_fork(struct bpf_raw_tracepoint_args* ctx) {
    struct task_struct* parent = (struct task_struct*)ctx->args[0];
    struct task_struct* child = (struct task_struct*)ctx->args[1];

    __u64 cgroup_id = compat_get_current_cgroup_id(child);

    int child_pid = get_task_ns_tgid(child);
    int child_tid = get_task_ns_pid(child);

    struct found_pid p = {
        .cgroup = cgroup_id,
        .pid = child_tid,
    };

    bpf_perf_event_output(ctx, &perf_found_pid, BPF_F_CURRENT_CPU, &p, sizeof(struct found_pid));

    return 0;
}