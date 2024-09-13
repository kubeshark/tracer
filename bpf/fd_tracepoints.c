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

struct sys_enter_read_write_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;

	__u64 fd;
	__u64* buf;
	__u64 count;
};

struct sys_exit_read_write_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;

	__u64 ret;
};

struct sys_enter_recvfrom_sendto_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;

    __u64 fd;                              // at offset 16, size 4 (signed)
    void *buf;                           // at offset 24, size 8 (unsigned)
    __u64 count;                        // at offset 32, size 8 (unsigned)
    __u32 flags;                           // at offset 40, size 4 (signed)
    void *addr;                      // at offset 48, size 8 (unsigned)
    void *addrlen;                       // at offset 56, size 8 (unsigned)
};

static __always_inline void fd_tracepoints_handle_openssl(void* ctx, __u32 fd, __u64 id, struct ssl_info* infoPtr, void* map_fd, __u64 origin_code) {
	struct ssl_info info;
	long err = bpf_probe_read(&info, sizeof(struct ssl_info), infoPtr);

	if (err != 0) {
		log_error(ctx, LOG_ERROR_READING_SSL_CONTEXT, id, err, origin_code);
		return;
	}

	info.fd = fd;

	err = bpf_map_update_elem(map_fd, &id, &info, BPF_ANY);
	bpf_printk("updated map_fd: %p %u", map_fd, info.fd);//XXX
	//bpf_printk("updated map_fd2: %u %u %u %u", (unsigned)PT_REGS_PARM1_SYSCALL(ctx), (unsigned)PT_REGS_PARM2_SYSCALL(ctx), (unsigned)PT_REGS_PARM3_SYSCALL(ctx), (unsigned)PT_REGS_PARM4_SYSCALL(ctx));//XXX

	if (err != 0) {
		log_error(ctx, LOG_ERROR_PUTTING_FILE_DESCRIPTOR, id, err, origin_code);
		return;
	}
}

static __always_inline void fd_tracepoints_handle_go(void* ctx, __u32 fd, __u64 id, void* map_fd, __u64 origin_code) {
	long err = bpf_map_update_elem(map_fd, &id, &fd, BPF_ANY);

	if (err != 0) {
		log_error(ctx, LOG_ERROR_PUTTING_FILE_DESCRIPTOR, id, err, origin_code);
		return;
	}
}

static __always_inline void handle_read(void* ctx, __u64 fd) {
	__u64 id = tracer_get_current_pid_tgid();

	struct ssl_info* infoPtr = bpf_map_lookup_elem(&openssl_read_context, &id);

	if (infoPtr != NULL) {
		bpf_printk("sys_enter_read: %d", id>>32);//XXX
		fd_tracepoints_handle_openssl(ctx, fd, id, infoPtr, &openssl_read_context, ORIGIN_SYS_ENTER_READ_CODE);
	}

	fd_tracepoints_handle_go(ctx, fd, id, &go_kernel_read_context, ORIGIN_SYS_ENTER_READ_CODE);

}

static __always_inline void handle_write(void* ctx, __u64 fd) {
	__u64 id = tracer_get_current_pid_tgid();

	struct ssl_info* infoPtr = bpf_map_lookup_elem(&openssl_write_context, &id);

	if (infoPtr != NULL) {
		fd_tracepoints_handle_openssl(ctx, fd, id, infoPtr, &openssl_write_context, ORIGIN_SYS_ENTER_WRITE_CODE);
	}

	fd_tracepoints_handle_go(ctx, fd, id, &go_kernel_write_context, ORIGIN_SYS_ENTER_WRITE_CODE);

}

SEC("tracepoint/syscalls/sys_enter_read")
void sys_enter_read(struct sys_enter_read_write_ctx* ctx) {
	handle_read(ctx, ctx->fd);
}

SEC("tracepoint/syscalls/sys_enter_write")
void sys_enter_write(struct sys_enter_read_write_ctx* ctx) {
	handle_write(ctx, ctx->fd);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
void sys_enter_recvfrom(struct sys_enter_recvfrom_sendto_ctx* ctx) {
	handle_read(ctx, ctx->fd);
}


SEC("tracepoint/syscalls/sys_enter_sendto")
void sys_enter_sendto(struct sys_enter_recvfrom_sendto_ctx* ctx) {
	handle_write(ctx, ctx->fd);
}
//TODO: sys_exit_recvfrom and sys_exit_sendto


SEC("tracepoint/syscalls/sys_exit_read")
void sys_exit_read(struct sys_exit_read_write_ctx* ctx) {
	__u64 id = tracer_get_current_pid_tgid();
	// Delete from go map. The value is not used after exiting this syscall.
	// Keep value in openssl map.
	bpf_map_delete_elem(&go_kernel_read_context, &id);
}

SEC("tracepoint/syscalls/sys_exit_write")
void sys_exit_write(struct sys_exit_read_write_ctx* ctx) {
	__u64 id = tracer_get_current_pid_tgid();
	// Delete from go map. The value is not used after exiting this syscall.
	// Keep value in openssl map.
	bpf_map_delete_elem(&go_kernel_write_context, &id);
}
