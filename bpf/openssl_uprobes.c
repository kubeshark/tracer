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
#include "include/cgroups.h"
#include "include/common.h"
#include "include/probes.h"
#include "include/stats.h"

static __always_inline int get_count_bytes(struct pt_regs* ctx, struct ssl_info* info, __u64 id) {
	int returnValue = PT_REGS_RC(ctx);

	if (info->count_ptr == 0) {
		// ssl_read and ssl_write return the number of bytes written/read
		//
		return returnValue;
	}

	// ssl_read_ex and ssl_write_ex return 1 for success
	//
	if (returnValue != 1) {
		return 0;
	}

	// ssl_read_ex and ssl_write_ex write the number of bytes to an arg named *count
	//
	size_t countBytes;
	long err = bpf_probe_read_user(&countBytes, sizeof(size_t), (void*)info->count_ptr);

	if (err != 0) {
		log_error(ctx, LOG_ERROR_READING_BYTES_COUNT, id, err, 0l);
		return 0;
	}

	return countBytes;
}

static __always_inline void ssl_uprobe(struct pt_regs* ctx, void* ssl, uintptr_t buffer, int num, void* map_fd, uintptr_t count_ptr) {
	struct openssl_stats* stats = stats_openssl();
	if (stats == NULL) {
		return;
	}
	++stats->uprobes_total;
	long err;

	if (program_disabled(PROGRAM_DOMAIN_CAPTURE_TLS))
		return;
	++stats->uprobes_enabled;

	__u64 cgroup_id = compat_get_current_cgroup_id(NULL);
	if (!should_target_cgroup(cgroup_id)) {
		return;
	}
	++stats->uprobes_matched;

	__u64 id = tracer_get_current_pid_tgid();
	struct ssl_info info = lookup_ssl_info(ctx, map_fd, id);

	info.count_ptr = count_ptr;
	info.buffer = buffer;

	err = bpf_map_update_elem(map_fd, &id, &info, BPF_ANY);

	if (err != 0) {
	    ++stats->uprobes_err_update;
		log_error(ctx, LOG_ERROR_PUTTING_SSL_CONTEXT, id, err, 0l);
	}
}

static __always_inline void ssl_uretprobe(struct pt_regs* ctx, void* map_fd, __u32 flags) {
	struct openssl_stats* stats = stats_openssl();
	if (stats == NULL) {
		return;
	}
	++stats->uretprobes_total;

	if (program_disabled(PROGRAM_DOMAIN_CAPTURE_TLS))
		return;
	++stats->uretprobes_enabled;

	__u64 cgroup_id = compat_get_current_cgroup_id(NULL);
	if (!should_target_cgroup(cgroup_id)) {
		return;
	}
	++stats->uretprobes_matched;

	__u64 id = tracer_get_current_pid_tgid();
	struct ssl_info* infoPtr = bpf_map_lookup_elem(map_fd, &id);

	if (infoPtr == NULL) {
	    ++stats->uretprobes_err_context;
		log_error(ctx, LOG_ERROR_GETTING_SSL_CONTEXT, id, 0l, 0l);
		return;
	}

	struct ssl_info info;
	long err = bpf_probe_read(&info, sizeof(struct ssl_info), infoPtr);

	// Do not clean map on purpose, sometimes there are two calls to ssl_read in a raw
	//	while the first call actually goes to read from socket, and we get the chance
	//	to find the fd. The other call already have all the information and we don't
	//	have the chance to get the fd.
	//
	// There are two risks keeping the map items
	//	1. It gets full - we solve it by using BPF_MAP_TYPE_LRU_HASH with hard limit
	//	2. We get wrong info of an old call - we solve it by comparing the timestamp
	//		info before using it
	//
	// bpf_map_delete_elem(map_fd, &id);

	if (err != 0) {
		log_error(ctx, LOG_ERROR_READING_SSL_CONTEXT, id, err, ORIGIN_SSL_URETPROBE_CODE);
		return;
	}

	if (info.fd == invalid_fd) {
		log_error(ctx, LOG_ERROR_MISSING_FILE_DESCRIPTOR, id, 0l, 0l);
		return;
	}

	int count_bytes = get_count_bytes(ctx, &info, id);
	if (count_bytes <= 0) {
		return;
	}

	output_ssl_chunk(ctx, &info, count_bytes, id, flags, cgroup_id, &stats->save_stats);
}

SEC("uprobe/ssl_write")
void BPF_KPROBE(ssl_write, void* ssl, uintptr_t buffer, int num) {
	ssl_uprobe(ctx, ssl, buffer, num, &openssl_write_context, 0);
}

SEC("uretprobe/ssl_write")
void BPF_KPROBE(ssl_ret_write) {
	ssl_uretprobe(ctx, &openssl_write_context, 0);
}

SEC("uprobe/ssl_read")
void BPF_KPROBE(ssl_read, void* ssl, uintptr_t buffer, int num) {
	ssl_uprobe(ctx, ssl, buffer, num, &openssl_read_context, 0);
}

SEC("uretprobe/ssl_read")
void BPF_KPROBE(ssl_ret_read) {
	ssl_uretprobe(ctx, &openssl_read_context, FLAGS_IS_READ_BIT);
}

SEC("uprobe/ssl_write_ex")
void BPF_KPROBE(ssl_write_ex, void* ssl, uintptr_t buffer, size_t num, uintptr_t written) {
	ssl_uprobe(ctx, ssl, buffer, num, &openssl_write_context, written);
}

SEC("uretprobe/ssl_write_ex")
void BPF_KPROBE(ssl_ret_write_ex) {
	ssl_uretprobe(ctx, &openssl_write_context, 0);
}

SEC("uprobe/ssl_read_ex")
void BPF_KPROBE(ssl_read_ex, void* ssl, uintptr_t buffer, size_t num, uintptr_t readbytes) {
	ssl_uprobe(ctx, ssl, buffer, num, &openssl_read_context, readbytes);
}

SEC("uretprobe/ssl_read_ex")
void BPF_KPROBE(ssl_ret_read_ex) {
	ssl_uretprobe(ctx, &openssl_read_context, FLAGS_IS_READ_BIT);
}

SEC("uprobe/ssl_pending")
void BPF_KPROBE(ssl_pending, void* ssl) {
	ssl_uprobe(ctx, ssl, 0, 0, &openssl_read_context, 0);
}

