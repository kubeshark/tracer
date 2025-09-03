/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#pragma once

#include "headers.h"

struct save_stats {
  __u64 save_packets;
  __u64 save_failed_logic;
  __u64 save_failed_not_opened;
  __u64 save_failed_full;
  __u64 save_failed_other;
};

struct packet_sniffer_stats {
  __u64 packets_total;
  __u64 packets_program_enabled;
  __u64 packets_matched_cgroup;
  __u64 packets_ipv4;
  __u64 packets_ipv6;
  __u64 packets_parse_passed;
  __u64 packets_parse_failed;

  struct save_stats save_stats;
};

struct openssl_stats {
  __u64 uprobes_total;
  __u64 uprobes_enabled;
  __u64 uprobes_matched;
  __u64 uprobes_err_update;

  __u64 uretprobes_total;
  __u64 uretprobes_enabled;
  __u64 uretprobes_matched;
  __u64 uretprobes_err_context;

  struct save_stats save_stats;
};

struct gotls_stats {
  __u64 uprobes_total;
  __u64 uprobes_enabled;
  __u64 uprobes_matched;

  __u64 uretprobes_total;
  __u64 uretprobes_enabled;
  __u64 uretprobes_matched;

  struct save_stats save_stats;
};

struct all_stats {
  struct packet_sniffer_stats pkt_sniffer_stats;
  struct openssl_stats openssl_stats;
  struct gotls_stats gotls_stats;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct all_stats);
} all_stats_map SEC(".maps");

static __always_inline struct packet_sniffer_stats *stats_packet_sniffer() {
  int key = 0;
  struct all_stats *stats = bpf_map_lookup_elem(&all_stats_map, &key);
  if (stats == NULL) {
    return NULL;
  }
  return &stats->pkt_sniffer_stats;
}

static __always_inline struct openssl_stats *stats_openssl() {
  int key = 0;
  struct all_stats *stats = bpf_map_lookup_elem(&all_stats_map, &key);
  if (stats == NULL) {
    return NULL;
  }
  return &stats->openssl_stats;
}

static __always_inline struct gotls_stats *stats_gotls() {
  int key = 0;
  struct all_stats *stats = bpf_map_lookup_elem(&all_stats_map, &key);
  if (stats == NULL) {
    return NULL;
  }
  return &stats->gotls_stats;
}