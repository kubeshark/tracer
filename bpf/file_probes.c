/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#include "include/probes.h"

#define S_IFMT 0170000
#define S_IFDIR 0040000

#define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)

//#define DEBUG_FILE_PROBE(x...) bpf_printk(x)
#define DEBUG_FILE_PROBE(x...)

#if defined(bpf_target_x86)
struct renamedata {
    struct mnt_idmap* old_mnt_idmap;
    struct inode* old_dir;
    struct dentry* old_dentry;
    struct mnt_idmap* new_mnt_idmap;
    struct inode* new_dir;
    struct dentry* new_dentry;
    struct inode** delegated_inode;
    unsigned int flags;
};
#endif

typedef struct {
    __u64 __unused_syscall_header;
    __u32 __unused_syscall_nr;

    const char* filename;
    __u64 flags;
    int mode;
} enter_sys_open_ctx;

typedef struct {
    __u64 __unused_syscall_header;
    __u32 __unused_syscall_nr;

    __u64 ret;
} exit_sys_ctx;

typedef struct {
    __u64 __unused_syscall_header;
    __u32 __unused_syscall_nr;

    __u64 dfd;
    const char* filename;
    __u64 flags;
    int mode;
} enter_sys_openat_ctx;

typedef struct {
    __u64 __unused_syscall_header;
    __u32 __unused_syscall_nr;

    __u64 dfd;
    const char* filename;
    void* how;
    size_t usize;
} enter_sys_openat2_ctx;

#define O_CREAT 0100

#define CGROUPV1_FS_PATH "/sys/fs/cgroup/cpuset"
#define CGROUPV1_FS_PATH_LEN __builtin_strlen(CGROUPV1_FS_PATH)

#define CGROUPV2_FS_PATH "/sys/fs/cgroup"
#define CGROUPV2_FS_PATH_LEN __builtin_strlen(CGROUPV2_FS_PATH)

#define PATTERN_LIBSSL "libssl.so"
#define PATTERN_LIBSSL_LEN __builtin_strlen(PATTERN_LIBSSL)

// PATH_MAX is 4096 in Linux kernel
#define MAX_FILEPATH (4096)

static long str_match_begin(const char* s1, __u32 sz1, const char* s2, __u32 sz2) {
    if (sz1 < sz2)
        return 0;

    for (int i = 0; i < sz2; i++) {
        if (s1[i] != s2[i]) return 0;
    }

    return 1;
}

struct file_path {
    char path[MAX_FILEPATH];
    __u64 cgroup_id;
    __u64 inode;
    __u32 device_id;
    __u16 size;
    __u8 remove;
};

BPF_PERF_OUTPUT(perf_found_openssl);
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_path);
} file_probe_heap SEC(".maps");

BPF_PERF_OUTPUT(perf_found_cgroup);

BPF_LRU_HASH(do_mkdir_context, __u64, struct file_path);

struct cgroup_signal {
    unsigned char path[MAX_FILEPATH];
    __u64 cgroup_id;
    __u32 hierarchy_id;
    __u16 size;
    __u8 remove;
};
BPF_PERF_OUTPUT(perf_cgroup_signal);

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cgroup_signal);
} cgroup_signal_heap SEC(".maps");

static __always_inline void find_openssl(void* ctx, __u32 device_id, void* name, uint64_t cgroup_id, uint64_t inode, uint8_t remove) {
    __u32 zero = 0;
    struct file_path* p = bpf_map_lookup_elem(&file_probe_heap, &zero);
    if (p == NULL) {
        log_error(ctx, LOG_ERROR_FILE_PROBES_MAP_ERROR, 3, 0l, 0l);
        return;
    }
    long sz = bpf_probe_read_str(p->path, MAX_FILEPATH, name);
    int ln = PATTERN_LIBSSL_LEN;
    if (sz < PATTERN_LIBSSL_LEN) {
        DEBUG_FILE_PROBE("find_openssl: not found");
        return;
    }
    for (int i = 0; i < 32; i++)
    {
        int offset = sz - 1 - PATTERN_LIBSSL_LEN - i;
        if (offset >= 0 && offset < MAX_FILEPATH)
        {
            if (str_match_begin(&p->path[offset], PATTERN_LIBSSL_LEN, PATTERN_LIBSSL, PATTERN_LIBSSL_LEN))
            {
                p->inode = inode;
                p->cgroup_id = cgroup_id;
                p->device_id = device_id;
                p->remove = remove;
                p->size = sz;
                bpf_perf_event_output(ctx, &perf_found_openssl, BPF_F_CURRENT_CPU, p, sizeof(struct file_path));
            }
        }
    }
}

static __always_inline void find_cgroup_fs(void *ctx, const char *name) {

    char buf[CGROUPV1_FS_PATH_LEN + 1]; // CGROUPV1_FS_PATH_LEN > CGROUPV2_FS_PATH_LEN
    int sz = 0;

    if (CGROUP_V1) {
        sz = bpf_probe_read_str(buf, CGROUPV1_FS_PATH_LEN + 1, name);
        if (sz < CGROUPV1_FS_PATH_LEN + 1) {
            return;
        }
    } else {
        sz = bpf_probe_read_str(buf, CGROUPV2_FS_PATH_LEN + 1, name);
        if (sz < CGROUPV2_FS_PATH_LEN + 1) {
            return;
        }
    }

    DEBUG_FILE_PROBE("FIND_CGROUP_FS BUF: %s", buf);

    long matched = 0;
    if (CGROUP_V1) {
        matched = str_match_begin(buf, sz, CGROUPV1_FS_PATH, CGROUPV1_FS_PATH_LEN);
    } else {
        matched = str_match_begin(buf, sz, CGROUPV2_FS_PATH, CGROUPV2_FS_PATH_LEN);
    }

    if (matched) {
        __u32 zero = 0;
        struct file_path* p = bpf_map_lookup_elem(&file_probe_heap, &zero);
        if (p == NULL) {
            log_error(ctx, LOG_ERROR_FILE_PROBES_MAP_ERROR, 3, 0l, 0l);
            return;
        }
        p->device_id = 0;
        p->size = bpf_probe_read_str(p->path, MAX_FILEPATH, name);

        __u64 pid = tracer_get_current_pid_tgid();
        bpf_map_update_elem(&do_mkdir_context, &pid, p, BPF_ANY);

        DEBUG_FILE_PROBE("FIND_CGROUP_FS UPDATE: PID: %lu SIZE: %u", pid, p->size);
    }
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(security_file_open)
{
    struct file* file = (struct file*)PT_REGS_PARM1(ctx);

    __u32 dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    __u64 inode = BPF_CORE_READ(file, f_inode, i_ino);
    void* file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));
    __u64 flags = BPF_CORE_READ(file, f_flags);
    __u64 cgroup_id = compat_get_current_cgroup_id(NULL);

    unsigned int mode = BPF_CORE_READ(file, f_path.dentry, d_inode, i_mode);
    if (flags & O_CREAT) {
        DEBUG_FILE_PROBE("SECURITY_FILE_OPEN: CREATE: %s, CGROUP: %lu", file_path, cgroup_id);
        if (S_ISDIR(mode)) {
            DEBUG_FILE_PROBE("SECURITY_FILE_OPEN: CREATE FILE IS DIRECTORY");
        }
    }

    __u64 id = tracer_get_current_pid_tgid();
    __u32 pid = id >> 32;
    DEBUG_FILE_PROBE("SECURITY_FILE_OPEN: PID: %d CGROUP: %lu", pid, cgroup_id);
    DEBUG_FILE_PROBE("SECURITY_FILE_OPEN: flags: %x dev: 0x%x", flags, dev);
    DEBUG_FILE_PROBE("SECURITY_FILE_OPEN: inode: %lu filename: %s", inode, file_path);
    find_openssl(ctx, dev, file_path, cgroup_id, inode, 0);

    return 0;
}

SEC("kprobe/security_inode_rename")
int BPF_KPROBE(security_inode_rename)
{
    struct dentry* old_dentry = (struct dentry*)PT_REGS_PARM2(ctx);
    struct dentry* new_dentry = (struct dentry*)PT_REGS_PARM4(ctx);
    __u64 cgroup_id = compat_get_current_cgroup_id(NULL);

    __u64 old_ino = BPF_CORE_READ(old_dentry, d_inode, i_ino);
    __u32 old_dev = BPF_CORE_READ(old_dentry, d_inode, i_sb, s_dev);
    void* old_path = get_dentry_path_str(old_dentry);

    __u64 new_ino = BPF_CORE_READ(new_dentry, d_inode, i_ino);
    __u32 new_dev = BPF_CORE_READ(new_dentry, d_inode, i_sb, s_dev);
    void* new_path = get_dentry_path_str(new_dentry);

    const unsigned char* filename = BPF_CORE_READ(new_dentry, d_name.name);

    __u64 id = tracer_get_current_pid_tgid();
    __u32 pid = id >> 32;

    DEBUG_FILE_PROBE("RENAME OLD: dev: 0x%x inode: %lu filename: %s", old_dev, old_ino, old_path);
    DEBUG_FILE_PROBE("RENAME NEW: dev: ox%x inode: %lu filename: %s", new_dev, new_ino, new_path);
    DEBUG_FILE_PROBE("RENAME NEW: filename: %s pid: %d", filename, pid);
    find_openssl(ctx, new_dev, new_path, cgroup_id, new_ino, 0);

    return 0;
}

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(security_inode_unlink)
{
    struct inode* inode = (struct inode*)PT_REGS_PARM1(ctx);
    struct dentry* dentry = (struct dentry*)PT_REGS_PARM2(ctx);
    __u64 cgroup_id = compat_get_current_cgroup_id(NULL);
    __u64 ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    __u64 ino2 = BPF_CORE_READ(inode, i_ino);
    __u64 dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
    __u64 dev2 = BPF_CORE_READ(inode, i_sb, s_dev);

    void* dentry_path = get_dentry_path_str(dentry);
    DEBUG_FILE_PROBE("SECURITY_FILE_UNLINK: dev: %d inode: %lu filename: %s", dev, ino, dentry_path);
    DEBUG_FILE_PROBE("SECURITY_FILE_UNLINK2: dev: %d inode: %lu", dev2, ino2);
    find_openssl(ctx, dev, dentry_path, cgroup_id, ino, 1);

    return 0;
}

SEC("kprobe/vfs_create")
int BPF_KPROBE(vfs_create)
{
    struct dentry* dentry = (struct dentry*)PT_REGS_PARM3(ctx);
    __u64 ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    __u64 dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
    void* dentry_path = get_dentry_path_str(dentry);
    DEBUG_FILE_PROBE("VFS_CREATE: dev: %d inode: %lu filename: %s", dev, ino, dentry_path);

    return 0;
}

SEC("kprobe/do_mkdirat")
int BPF_KPROBE(do_mkdirat)
{
    const char* fn = NULL;
    if (KERNEL_VERSION < make_kernel_version(5, 15, 0)) {
        fn = (const char*)PT_REGS_PARM2(ctx);
    } else {
        struct filename* fname = (struct filename*)PT_REGS_PARM2(ctx);
        fn = BPF_CORE_READ(fname, name);
    }

    DEBUG_FILE_PROBE("DO_MKDIRAT: filename: %s", fn);
    find_cgroup_fs(ctx, fn);
    return 0;
}

SEC("kretprobe/do_mkdirat")
int BPF_KPROBE(do_mkdirat_ret)
{
    __u64 pid = tracer_get_current_pid_tgid();

    struct file_path* p = bpf_map_lookup_elem(&do_mkdir_context, &pid);
    if (!p) {
        DEBUG_FILE_PROBE("DO_MKDIRAT_RET: NOT_FOUND");
        return 0;
    }

    int ret = (int)PT_REGS_RC(ctx);
    DEBUG_FILE_PROBE("DO_MKDIRAT_RET: FOUND, ret: %d", ret);
    if (ret == 0)
    {
        bpf_perf_event_output(ctx, &perf_found_cgroup, BPF_F_CURRENT_CPU, p, sizeof(struct file_path));
        DEBUG_FILE_PROBE("DO_MKDIRAT_RET: SENT");
    }
    bpf_map_delete_elem(&do_mkdir_context, &pid);

    return 0;
}

SEC("kprobe/security_path_mkdir")
int BPF_KPROBE(security_path_mkdir)
{
    struct path* path = (struct path*)PT_REGS_PARM1(ctx);
    struct dentry* dentry = (struct dentry*)PT_REGS_PARM2(ctx);
    __u64 ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    __u64 dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);

    void* dentry_path = get_dentry_path_str(dentry);
    void* path_str = get_path_str(path);
    __u64 cgroup_id = compat_get_current_cgroup_id(NULL);
    DEBUG_FILE_PROBE("SECURITY_PATH_MKDIR: dev: %d inode: %lu cgroup_id: %lu path: %s filename: %s", dev, ino, cgroup_id, path_str, dentry_path);

    return 0;
}

SEC("kprobe/vfs_rmdir")
int BPF_KPROBE(vfs_rmdir)
{
    struct dentry* dentry = (struct dentry*)PT_REGS_PARM3(ctx);
    void* dentry_path = get_dentry_path_str(dentry);
    DEBUG_FILE_PROBE("VFS_RMDIR: filename: %s", dentry_path);
    return 0;
}

SEC("raw_tracepoint/cgroup_mkdir_signal")
int cgroup_mkdir_signal(struct bpf_raw_tracepoint_args *ctx)
{
    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = BPF_CORE_READ(dst_cgrp, root, hierarchy_id);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    DEBUG_FILE_PROBE("cgroup_mkdir: h: %lu id: %llu path: %s", hierarchy_id, cgroup_id, path);

    __u32 zero = 0;
    struct cgroup_signal* c = bpf_map_lookup_elem(&cgroup_signal_heap, &zero);
    if (c == NULL) {
        log_error(ctx, LOG_ERROR_FILE_PROBES_MAP_ERROR, 3, 0l, 0l);
        return 0;
    }
    long sz = bpf_probe_read_str(c->path, MAX_FILEPATH, path);
    if (sz <= 0) {
        DEBUG_FILE_PROBE("cgroup_mkdir_signal: wrong path");
        return 0;
    }

    c->size = sz;
    c->cgroup_id = cgroup_id;
    c->hierarchy_id = hierarchy_id;
    c->remove = 0;
    bpf_perf_event_output(ctx, &perf_cgroup_signal, BPF_F_CURRENT_CPU, c, sizeof(struct cgroup_signal));

    return 0;
}

SEC("raw_tracepoint/cgroup_rmdir_signal")
int cgroup_rmdir_signal(struct bpf_raw_tracepoint_args *ctx)
{
    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = BPF_CORE_READ(dst_cgrp, root, hierarchy_id);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    DEBUG_FILE_PROBE("cgroup_rmdir: h: %lu id: %llu path: %s", hierarchy_id, cgroup_id, path);

    __u32 zero = 0;
    struct cgroup_signal* c = bpf_map_lookup_elem(&cgroup_signal_heap, &zero);
    if (c == NULL) {
        log_error(ctx, LOG_ERROR_FILE_PROBES_MAP_ERROR, 3, 0l, 0l);
        return 0;
    }
    long sz = bpf_probe_read_str(c->path, MAX_FILEPATH, path);
    if (sz <= 0) {
        DEBUG_FILE_PROBE("cgroup_rmdir_signal: wrong path");
        return 0;
    }

    c->size = sz;
    c->cgroup_id = cgroup_id;
    c->hierarchy_id = hierarchy_id;
    c->remove = 1;
    bpf_perf_event_output(ctx, &perf_cgroup_signal, BPF_F_CURRENT_CPU, c, sizeof(struct cgroup_signal));

    return 0;
}
