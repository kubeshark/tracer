/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#include "include/headers.h"
#include "include/util.h"
#include "include/maps.h"
#include "include/log.h"
#include "include/logger_messages.h"
#include "include/common.h"
#include "include/probes.h"
#include "include/stats.h"

static __always_inline int add_address_to_chunk(struct pt_regs* ctx, struct tls_chunk* chunk, __u64 id, __u32 fd, struct ssl_info* info) {
    __u32 pid = id >> 32;
    __u64 key = (__u64)pid << 32 | fd;

    conn_flags* flags = bpf_map_lookup_elem(&connection_context, &key);

    // Happens when we don't catch the connect / accept (if the connection is created before targeting is started)
    if (flags == NULL) {
        return 0;
    }

    chunk->flags |= (*flags & FLAGS_IS_CLIENT_BIT);

    if (info->address_info.family == AF_INET) {
        chunk->address_info.family = AF_INET;
        bpf_probe_read(&chunk->address_info.saddr4, sizeof(__be32), &info->address_info.saddr4);
        bpf_probe_read(&chunk->address_info.daddr4, sizeof(__be32), &info->address_info.daddr4);
    } else if (info->address_info.family == AF_INET6) {
        chunk->address_info.family = AF_INET6;
        bpf_probe_read(chunk->address_info.saddr6, sizeof(chunk->address_info.saddr6), info->address_info.saddr6);
        bpf_probe_read(chunk->address_info.daddr6, sizeof(chunk->address_info.daddr6), info->address_info.daddr6);
    } else {
        log_error(ctx, LOG_ERROR_UNKNOWN_FAMILY, id, info->address_info.family, 0l);
        return 0;
    }

    chunk->address_info.sport = info->address_info.sport;
    chunk->address_info.dport = info->address_info.dport;

    return 1;
}

static __always_inline int send_chunk_part(struct pt_regs* ctx, uintptr_t buffer, __u64 id,
    struct tls_chunk* chunk, int start, int end) {
    size_t recorded = MIN(end - start, sizeof(chunk->data));

    if (recorded <= 0) {
        return 1;
    }

    chunk->recorded = recorded;
    chunk->start = start;

    // This ugly trick is for the ebpf verifier happiness
    //
    long err = 0;
    if (chunk->recorded == sizeof(chunk->data)) {
        err = bpf_probe_read(chunk->data, sizeof(chunk->data), (void*)(buffer + start));
    } else {
        recorded &= (sizeof(chunk->data) - 1); // Buffer must be N^2
        err = bpf_probe_read(chunk->data, recorded, (void*)(buffer + start));
    }

    if (err != 0) {
        log_error(ctx, LOG_ERROR_READING_FROM_SSL_BUFFER, id, err, 0l);
        return 2;
    }

    return bpf_perf_event_output(ctx, &chunks_buffer, BPF_F_CURRENT_CPU, chunk, sizeof(struct tls_chunk));
}

static __always_inline int send_chunk(struct pt_regs* ctx, uintptr_t buffer, __u64 id, struct tls_chunk* chunk) {
    // ebpf loops must be bounded at compile time, we can't use (i < chunk->len / CHUNK_SIZE)
    //
    // 	https://lwn.net/Articles/794934/
    //
    // However we want to run in kernel older than 5.3, hence we use "#pragma unroll" anyway
    //
    int ret = 0;
#pragma unroll
    for (int i = 0; i < MAX_CHUNKS_PER_OPERATION; i++) {
        if (chunk->len <= (CHUNK_SIZE * i)) {
            break;
        }

        int err = send_chunk_part(ctx, buffer, id, chunk, CHUNK_SIZE * i, chunk->len);
        if (err && ret == 0) {
            ret = err;
        }
    }
    return ret;
}

static __always_inline void output_ssl_chunk(struct pt_regs* ctx, struct ssl_info* info, int count_bytes, __u64 id, __u32 flags, __u64 cgroup_id, struct save_stats* stats) {
    if (count_bytes > (CHUNK_SIZE * MAX_CHUNKS_PER_OPERATION)) {
        log_error(ctx, LOG_ERROR_BUFFER_TOO_BIG, id, count_bytes, 0l);
        return;
    }

    struct tls_chunk* chunk;
    int zero = 0;

    // If other thread, running on the same CPU get to this point at the same time like us (context switch)
    //	the data will be corrupted - protection may be added in the future
    //
    chunk = bpf_map_lookup_elem(&heap, &zero);

    if (!chunk) {
        log_error(ctx, LOG_ERROR_ALLOCATING_CHUNK, id, 0l, 0l);
        return;
    }

    chunk->flags = flags;
    chunk->timestamp = compat_get_uprobe_timestamp();
    chunk->cgroup_id = cgroup_id;
    chunk->pid = id >> 32;
    chunk->tgid = id;
    chunk->len = count_bytes;
    chunk->fd = info->fd;

    if (!add_address_to_chunk(ctx, chunk, id, chunk->fd, info)) {
        // Without an address, we drop the chunk because there is not much to do with it in Go
        //
        return;
    }

    int ret = send_chunk(ctx, info->buffer, id, chunk);
    if (likely(ret == 0)) {
        ++stats->save_packets;
    } else if (ret > 0) {
        ++stats->save_failed_logic;
    } else if (ret == -EINVAL) {
        ++stats->save_failed_not_opened;
    } else if (ret == -EAGAIN) {
        ++stats->save_failed_full;
    } else {
        ++stats->save_failed_other;
    }
}

static __always_inline struct ssl_info new_ssl_info() {
    struct ssl_info info = { .fd = invalid_fd, .created_at_nano = bpf_ktime_get_ns() };
    return info;
}

static __always_inline struct ssl_info lookup_ssl_info(struct pt_regs* ctx, void* map_fd, __u64 pid_tgid) {
    struct ssl_info* infoPtr = bpf_map_lookup_elem(map_fd, &pid_tgid);
    struct ssl_info info = new_ssl_info();

    if (infoPtr != NULL) {
        long err = bpf_probe_read(&info, sizeof(struct ssl_info), infoPtr);

        if (err != 0) {
            log_error(ctx, LOG_ERROR_READING_SSL_CONTEXT, pid_tgid, err, ORIGIN_SSL_UPROBE_CODE);
        }

        if ((bpf_ktime_get_ns() - info.created_at_nano) > SSL_INFO_MAX_TTL_NANO) {
            // If the ssl info is too old, we don't want to use its info because it may be incorrect.
            //
            info.fd = invalid_fd;
            info.created_at_nano = bpf_ktime_get_ns();
        }
    }

    return info;
}

static __always_inline int program_disabled(int program_domain) {
    __u32 zero = 0;
    struct configuration* s = bpf_map_lookup_elem(&settings, &zero);
    if (s && (s->flags & CONFIGURATION_FLAG_CAPTURE_STOPPED)) {
        return 1;
    }

    if (program_domain == PROGRAM_DOMAIN_CAPTURE_SYSTEM)
        return 0; // system always enabled

    __u32* p = bpf_map_lookup_elem(&programs_configuration, &zero);
    if (!p) {
        return 1;
    }

    if (*p & program_domain) {
        return 0;
    }

    return 1;
}
