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


static __always_inline int add_address_to_chunk(struct pt_regs* ctx, struct tls_chunk* chunk, __u64 id, __u32 fd, struct ssl_info* info) {
    __u32 pid = id >> 32;
    __u64 key = (__u64)pid << 32 | fd;

    conn_flags* flags = bpf_map_lookup_elem(&connection_context, &key);

    // Happens when we don't catch the connect / accept (if the connection is created before targeting is started)
    if (flags == NULL) {
        bpf_printk("flags is NULL");
        return 0;
    }

    chunk->flags |= (*flags & FLAGS_IS_CLIENT_BIT);

    bpf_probe_read(&chunk->address_info, sizeof(chunk->address_info), &info->address_info);

    return 1;
}

static int print_tls_chunk(struct tls_chunk *chunk) {
    // Print chunk details
    bpf_printk("Timestamp: %llu", chunk->timestamp);
    bpf_printk("CGroup ID: %u", chunk->cgroup_id);
    bpf_printk("PID: %u", chunk->pid);
    bpf_printk("TGID: %u", chunk->tgid);
    bpf_printk("Length: %u", chunk->len);
    bpf_printk("Start: %u", chunk->start);
    bpf_printk("Recorded: %u", chunk->recorded);
    bpf_printk("FD: %u", chunk->fd);
    bpf_printk("Flags: %u", chunk->flags);
    bpf_printk("Direction: %u", chunk->direction);

    bpf_printk("Family: %u", chunk->address_info.family);
    bpf_printk("Source Address (saddr): %u", chunk->address_info.saddr);
    bpf_printk("Destination Address (daddr): %u", chunk->address_info.daddr);
    bpf_printk("Source Port (sport): %u", chunk->address_info.sport);
    bpf_printk("Destination Port (dport): %u", chunk->address_info.dport);

    // Start printing data in hex on a single line
    bpf_printk("Data (hex): ");
    for (int i = 0; i < 10; i++) {
        bpf_printk("%02x", chunk->data[i]);
    }

    return 0;
}

static __always_inline void send_chunk_part(struct pt_regs* ctx, uintptr_t buffer, __u64 id,
    struct tls_chunk* chunk, int start, int end) {
    size_t recorded = MIN(end - start, sizeof(chunk->data));

    if (recorded <= 0) {
        bpf_printk("recorded less than 0 size of chunk %d start %d end %d", sizeof(chunk->data), start, end);
        return;
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
        return;
    }

    print_tls_chunk(chunk);

    bpf_perf_event_output(ctx, &chunks_buffer, BPF_F_CURRENT_CPU, chunk, sizeof(struct tls_chunk));
}

static __always_inline void send_chunk(struct pt_regs* ctx, uintptr_t buffer, __u64 id, struct tls_chunk* chunk) {
    // ebpf loops must be bounded at compile time, we can't use (i < chunk->len / CHUNK_SIZE)
    //
    // 	https://lwn.net/Articles/794934/
    //
    // However we want to run in kernel older than 5.3, hence we use "#pragma unroll" anyway
    //
#pragma unroll
    for (int i = 0; i < MAX_CHUNKS_PER_OPERATION; i++) {
        if (chunk->len <= (CHUNK_SIZE * i)) {
            break;
        }
        bpf_printk("calling send_chunk_part");
        send_chunk_part(ctx, buffer, id, chunk, CHUNK_SIZE * i, chunk->len);
    }
}

static __always_inline void output_ssl_chunk(struct pt_regs* ctx, struct ssl_info* info, int count_bytes, __u64 id, __u32 flags, __u64 cgroup_id) {
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

    bpf_printk("calling add_address_to_chunk");
    if (!add_address_to_chunk(ctx, chunk, id, chunk->fd, info)) {
        // Without an address, we drop the chunk because there is not much to do with it in Go
        //
        return;
    }

    bpf_printk("calling send_chunk");
    send_chunk(ctx, info->buffer, id, chunk);
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

static __always_inline int capture_disabled() {
    __u32 zero = 0;
    struct configuration* s = bpf_map_lookup_elem(&settings, &zero);
    return s && (s->flags & CONFIGURATION_FLAG_CAPTURE_STOPPED);
}
