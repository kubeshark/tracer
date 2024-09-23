/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#include "headers.h"
#include "util.h"
#include "maps.h"
#include "log.h"
#include "logger_messages.h"
#include "pids.h"
#include "cgroups.h"
#include "common.h"

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
    __be32 parent_pid;
    __be32 host_pid;
    __be32 host_parent_pid;

    __u16 event_id;
    __be16 port_src;
    __be16 port_dst;

    char __pad[10]; //padding
};

BPF_PERF_OUTPUT(syscall_events);

static __always_inline int read_addrs_ports(struct pt_regs* ctx, struct sock* sk, __be32* saddr, __be16* sport, __be32* daddr, __be16* dport);


struct task_struct *get_parent_task(struct task_struct *task) {
    struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
    struct task_struct *real_parent =  BPF_CORE_READ(group_leader, real_parent);
    return  BPF_CORE_READ(real_parent, group_leader);
}

static __always_inline __u32 get_parent_task_pid(struct task_struct *task) {
    return BPF_CORE_READ(get_parent_task(task), pid);
}

static __always_inline __u32 get_task_pid(struct task_struct *task)
{
    //TODO: check exists for all kernels:
    struct pid *pid = BPF_CORE_READ(task, thread_pid);

    unsigned int level = BPF_CORE_READ(pid, level);
    return BPF_CORE_READ(pid, numbers[level].nr);
}