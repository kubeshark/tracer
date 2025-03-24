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

struct accept_info {
	uintptr_t addrlen;
};

BPF_HASH(accept_syscall_context, __u64, struct accept_info);

struct sys_enter_accept4_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;

	__u64 fd;
	__u64* sockaddr;
	uintptr_t addrlen;
};

SEC("tracepoint/syscalls/sys_enter_accept4")
void sys_enter_accept4(struct sys_enter_accept4_ctx* ctx) {
	__u64 id = tracer_get_current_pid_tgid();

	struct accept_info info = {};

	info.addrlen = ctx->addrlen;

	long err = bpf_map_update_elem(&accept_syscall_context, &id, &info, BPF_ANY);

	if (err != 0) {
		log_error(ctx, LOG_ERROR_PUTTING_ACCEPT_INFO, id, err, 0l);
	}
}

struct sys_exit_accept4_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;

	__u64 ret;
};

SEC("tracepoint/syscalls/sys_exit_accept4")
void sys_exit_accept4(struct sys_exit_accept4_ctx* ctx) {
	__u64 id = tracer_get_current_pid_tgid();

	if (ctx->ret < 0) {
		bpf_map_delete_elem(&accept_syscall_context, &id);
		return;
	}

	struct accept_info* infoPtr = bpf_map_lookup_elem(&accept_syscall_context, &id);

	if (infoPtr == NULL) {
		log_error(ctx, LOG_ERROR_GETTING_ACCEPT_INFO, id, 0l, 0l);
		return;
	}

	struct accept_info info;
	long err = bpf_probe_read(&info, sizeof(struct accept_info), infoPtr);

	bpf_map_delete_elem(&accept_syscall_context, &id);

	if (err != 0) {
		log_error(ctx, LOG_ERROR_READING_ACCEPT_INFO, id, err, 0l);
		return;
	}

	__u32 addrlen;
	bpf_probe_read(&addrlen, sizeof(__u32), (void*)info.addrlen);

	conn_flags flags = 0;

	__u32 pid = id >> 32;
	__u32 fd = (__u32)ctx->ret;

	__u64 key = (__u64)pid << 32 | fd;
	err = bpf_map_update_elem(&connection_context, &key, &flags, BPF_ANY);

	if (err != 0) {
		log_error(ctx, LOG_ERROR_PUTTING_CONNECTION_CONTEXT, id, err, ORIGIN_SYS_EXIT_ACCEPT4_CODE);
	}
}

struct connect_info {
	__u64 fd;
	__u32 addrlen;
};

BPF_HASH(connect_syscall_info, __u64, struct connect_info);

struct sys_enter_connect_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;

	__u64 fd;
	__u64* sockaddr;
	__u32 addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
void sys_enter_connect(struct sys_enter_connect_ctx* ctx) {
	__u64 id = tracer_get_current_pid_tgid();

	struct connect_info info = {};

	info.addrlen = ctx->addrlen;
	info.fd = ctx->fd;

	long err = bpf_map_update_elem(&connect_syscall_info, &id, &info, BPF_ANY);

	if (err != 0) {
		log_error(ctx, LOG_ERROR_PUTTING_CONNECT_INFO, id, err, 0l);
	}
}

struct sys_exit_connect_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;

	__u64 ret;
};

SEC("tracepoint/syscalls/sys_exit_connect")
void sys_exit_connect(struct sys_exit_connect_ctx* ctx) {
	__u64 id = tracer_get_current_pid_tgid();

	// Commented because of async connect which set errno to EINPROGRESS
	//
	// if (ctx->ret != 0) {
	// 	bpf_map_delete_elem(&accept_syscall_context, &id);
	// 	return;
	// }

	struct connect_info* infoPtr = bpf_map_lookup_elem(&connect_syscall_info, &id);

	if (infoPtr == NULL) {
		log_error(ctx, LOG_ERROR_GETTING_CONNECT_INFO, id, 0l, 0l);
		return;
	}

	struct connect_info info;
	long err = bpf_probe_read(&info, sizeof(struct connect_info), infoPtr);

	bpf_map_delete_elem(&connect_syscall_info, &id);

	if (err != 0) {
		log_error(ctx, LOG_ERROR_READING_CONNECT_INFO, id, err, 0l);
		return;
	}

	conn_flags flags = FLAGS_IS_CLIENT_BIT;

	__u32 pid = id >> 32;
	__u32 fd = (__u32)info.fd;

	__u64 key = (__u64)pid << 32 | fd;
	err = bpf_map_update_elem(&connection_context, &key, &flags, BPF_ANY);

	if (err != 0) {
		log_error(ctx, LOG_ERROR_PUTTING_CONNECTION_CONTEXT, id, err, ORIGIN_SYS_EXIT_CONNECT_CODE);
	}
}
