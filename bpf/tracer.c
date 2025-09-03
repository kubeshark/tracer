/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#include "include/headers.h"
#include "include/log.h"
#include "include/logger_messages.h"
#include "include/maps.h"
#include "include/pids.h"
#include "include/util.h"

// To avoid multiple .o files
//
#include "common.c"
#include "fd_to_address_tracepoints.c"
#include "fd_tracepoints.c"
#include "go_uprobes.c"
#include "openssl_uprobes.c"
#include "tcp_kprobes.c"

#ifndef DISABLE_EBPF_CAPTURE_BACKEND
#include "packet_sniffer.c"
#endif

#include "events.c"
#include "file_probes.c"
#include "pids_probes.c"

char _license[] SEC("license") = "GPL";
