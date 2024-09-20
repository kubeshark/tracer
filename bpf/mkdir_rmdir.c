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

#define MAX_PATH_LEN 4096

// Structure to hold the path
struct event {
    char path[MAX_PATH_LEN];
};

// Map to hold events
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Helper to get the process's filename
static __always_inline int get_filename(struct pt_regs *ctx, const char __user *filename)
{
    struct event ev = {};
    bpf_probe_read_user_str(&ev.path, sizeof(ev.path), filename);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

// Tracepoint for mkdir syscall
SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_mkdir(struct pt_regs *ctx)
{
    const char __user *filename = (const char __user *)PT_REGS_PARM1(ctx);
    return get_filename(ctx, filename);
}

// Tracepoint for mkdirat syscall
SEC("tracepoint/syscalls/sys_enter_mkdirat")
int trace_mkdirat(struct pt_regs *ctx)
{
    const char __user *filename = (const char __user *)PT_REGS_PARM2(ctx);
    return get_filename(ctx, filename);
}

// Tracepoint for rmdir syscall
SEC("tracepoint/syscalls/sys_enter_rmdir")
int trace_rmdir(struct pt_regs *ctx)
{
    const char __user *filename = (const char __user *)PT_REGS_PARM1(ctx);
    return get_filename(ctx, filename);
}

