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
#include "common.h"

#define statfunc static __always_inline

#define MAX_PERCPU_BUFSIZE (1 << 15)  // set by the kernel as an upper bound
#define MAX_PATH_COMPONENTS   20
#define MAX_STRING_SIZE    4096       // same as PATH_MAX

const volatile __u64 KERNEL_VERSION = 0;
const volatile __u64 CGROUP_V1 = 0;
const volatile __u64 HELPER_EXISTS_UPROBE_bpf_ktime_get_tai_ns = 0;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

enum buf_idx_e
{
    STRING_BUF_IDX,
    FILE_BUF_IDX,
    MAX_BUFFERS
};

// percpu global buffer variables
struct bufs {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BUFFERS);
    __type(key, u32);
    __type(value, buf_t);
} bufs SEC(".maps");


statfunc __u64 make_kernel_version(__u64 kernel, __u64 major, __u64 minor) {
    return 1000 * 1000 * kernel + 1000 * major + minor;
}

statfunc buf_t* get_buf(int idx)
{
    return (buf_t*)bpf_map_lookup_elem(&bufs, &idx);
}

statfunc struct mount* real_mount(struct vfsmount* mnt)
{
    return container_of(mnt, struct mount, mnt);
}

statfunc struct dentry* get_mnt_root_ptr_from_vfsmnt(struct vfsmount* vfsmnt)
{
    return BPF_CORE_READ(vfsmnt, mnt_root);
}

statfunc struct dentry* get_d_parent_ptr_from_dentry(struct dentry* dentry)
{
    return BPF_CORE_READ(dentry, d_parent);
}

statfunc u32 get_task_pid_vnr(struct task_struct* task)
{
    unsigned int level = 0;
    struct pid* pid = NULL;

    pid = BPF_CORE_READ(task, thread_pid);

    level = BPF_CORE_READ(pid, level);

    return BPF_CORE_READ(pid, numbers[level].nr);
}

statfunc struct qstr get_d_name_from_dentry(struct dentry* dentry)
{
    return BPF_CORE_READ(dentry, d_name);
}

statfunc u32 get_task_ns_tgid(struct task_struct* task)
{
    struct task_struct* group_leader = BPF_CORE_READ(task, group_leader);
    return get_task_pid_vnr(group_leader);
}

statfunc u32 get_task_ns_pid(struct task_struct* task)
{
    return get_task_pid_vnr(task);
}

// Read the file path to the given buffer, returning the start offset of the path.
statfunc size_t get_path_str_buf(struct path* path, buf_t* out_buf)
{
    if (path == NULL || out_buf == NULL) {
        return 0;
    }

    char slash = '/';
    int zero = 0;
    struct dentry* dentry = BPF_CORE_READ(path, dentry);
    struct vfsmount* vfsmnt = BPF_CORE_READ(path, mnt);
    struct mount* mnt_parent_p;
    struct mount* mnt_p = real_mount(vfsmnt);
    bpf_core_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);
    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);
    struct dentry* mnt_root;
    struct dentry* d_parent;
    struct qstr d_name;
    unsigned int len;
    unsigned int off;
    int sz;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
        d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                break;
            }
            if (mnt_p != mnt_parent_p) {
                // We reached root, but not global root - continue with mount point path
                bpf_core_read(&dentry, sizeof(struct dentry*), &mnt_p->mnt_mountpoint);
                bpf_core_read(&mnt_p, sizeof(struct mount*), &mnt_p->mnt_parent);
                bpf_core_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        d_name = get_d_name_from_dentry(dentry);
        len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        off = buf_off - len;
        // Is string buffer big enough for dentry name?
        sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
            sz = bpf_probe_read_kernel_str(
                &(out_buf->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]), len, (void*)d_name.name);
        } else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read_kernel(&(out_buf->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }
    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_kernel_str(&(out_buf->buf[0]), MAX_STRING_SIZE, (void*)d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read_kernel(&(out_buf->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read_kernel(&(out_buf->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1, &zero);
    }
    return buf_off;
}

static __always_inline void* get_path_str(struct path* path)
{
    // Get per-cpu string buffer
    buf_t* string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;

    size_t buf_off = get_path_str_buf(path, string_p);
    return &string_p->buf[buf_off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)];
}

statfunc void* get_dentry_path_str(struct dentry* dentry)
{
    char slash = '/';
    int zero = 0;

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);

    // Get per-cpu string buffer
    buf_t* string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        struct dentry* d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == d_parent) {
            break;
        }
        // Add this dentry name to path
        struct qstr d_name = get_d_name_from_dentry(dentry);
        unsigned int len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        unsigned int off = buf_off - len;
        // Is string buffer big enough for dentry name?
        int sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
            sz = bpf_probe_read_kernel_str(
                &(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]), len, (void*)d_name.name);
        } else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read_kernel(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        struct qstr d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_kernel_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void*)d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read_kernel(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read_kernel(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1, &zero);
    }

    return &string_p->buf[buf_off];
}

statfunc const u64 get_cgroup_id(struct cgroup* cgrp)
{
    struct kernfs_node* kn = BPF_CORE_READ(cgrp, kn);

    if (kn == NULL)
        return 0;

    u64 id;

    bpf_core_read(&id, sizeof(u64), &kn->id);

    return id;
}

statfunc const u64 get_cgroup_v1_subsys0_id(struct task_struct* task)
{
    struct cgroup* cgroup = BPF_CORE_READ(task, cgroups, subsys[0], cgroup);
    return get_cgroup_id(cgroup);
}


statfunc __u64 compat_get_uprobe_timestamp() {
    return HELPER_EXISTS_UPROBE_bpf_ktime_get_tai_ns ? bpf_ktime_get_tai_ns() : 0;
}

statfunc __u64 compat_get_skb_cgroup_id(struct __sk_buff* skb) {
    return CGROUP_V1 ? bpf_get_cgroup_classid(skb) : bpf_skb_cgroup_id(skb);
}


statfunc __u64 compat_get_current_cgroup_id(struct task_struct* t) {
    if (CGROUP_V1) {
        if (t == NULL) {
            t = (struct task_struct*)bpf_get_current_task();
        }
        return get_cgroup_v1_subsys0_id(t);
    }

    return bpf_get_current_cgroup_id();
}


#undef statfunc