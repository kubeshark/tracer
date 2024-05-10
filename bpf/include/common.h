/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#ifndef __COMMON__
#define __COMMON__

#define AF_INET	2	/* Internet IP Protocol */

const __s32 invalid_fd = -1;

static int add_address_to_chunk(struct pt_regs* ctx, struct tls_chunk* chunk, __u64 id, __u32 fd, struct ssl_info* info);
static void send_chunk_part(struct pt_regs* ctx, uintptr_t buffer, __u64 id, struct tls_chunk* chunk, int start, int end);
static void send_chunk(struct pt_regs* ctx, uintptr_t buffer, __u64 id, struct tls_chunk* chunk);
static void output_ssl_chunk(struct pt_regs* ctx, struct ssl_info* info, int count_bytes, __u64 id, __u32 flags, __u64 cgroup_id);
static struct ssl_info new_ssl_info();
static struct ssl_info lookup_ssl_info(struct pt_regs* ctx, void* map_fd, __u64 pid_tgid);

#endif /* __COMMON__ */
