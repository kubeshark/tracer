/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#include "stats.h"

#ifndef __COMMON__
#define __COMMON__

#define AF_UNSPEC 0	/* Unspecified */
#define AF_INET	2	/* IPv4 Protocol */
#define AF_INET6 10	/* IPv6 Protocol */

#ifndef EINVAL
#define	EINVAL		22	/* Invalid argument */
#endif

#ifndef EAGAIN
#define	EAGAIN		11	/* Try again */
#endif

#define PROGRAM_DOMAIN_CAPTURE_SYSTEM (0)
#define PROGRAM_DOMAIN_CAPTURE_TLS (1 << 0)
#define PROGRAM_DOMAIN_CAPTURE_PLAIN (1 << 1)

const __s32 invalid_fd = -1;

const volatile __u64 TRACER_NS_INO = 0;
const volatile __u64 KERNEL_VERSION = 0;
const volatile __u64 CGROUP_V1 = 0;
const volatile __u64 HELPER_EXISTS_UPROBE_bpf_ktime_get_tai_ns = 0;
const volatile __u64 PREFER_CGROUP_V1_EBPF_CAPTURE = 0;

static int add_address_to_chunk(struct pt_regs* ctx, struct tls_chunk* chunk, __u64 id, __u32 fd, struct ssl_info* info);
static int send_chunk_part(struct pt_regs* ctx, uintptr_t buffer, __u64 id, struct tls_chunk* chunk, int start, int end);
static int send_chunk(struct pt_regs* ctx, uintptr_t buffer, __u64 id, struct tls_chunk* chunk);
static void output_ssl_chunk(struct pt_regs* ctx, struct ssl_info* info, int count_bytes, __u64 id, __u32 flags, __u64 cgroup_id, struct save_stats* stats);
static struct ssl_info new_ssl_info();
static struct ssl_info lookup_ssl_info(struct pt_regs* ctx, void* map_fd, __u64 pid_tgid);

#endif /* __COMMON__ */
