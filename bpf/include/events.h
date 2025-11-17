/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#pragma once

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
#define SYSCALL_EVENT_ID_CONNECT_CLOSE 2
#define SYSCALL_EVENT_ID_ACCEPT_CLOSE 3
#define SYSCALL_EVENT_ID_CONNECT_UPDATE 4
#define SYSCALL_EVENT_ID_ACCEPT_UPDATE 5
#define SYSCALL_EVENT_ID_UDP_SUMMARY 6


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