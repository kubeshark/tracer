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

struct mysqlCmdStruct {
  char *command;
  int length;
};

SEC("uprobe/server_command_probe")
void BPF_KPROBE(server_command_probe, void* buffer, int num) {
	__u64 id = bpf_get_current_pid_tgid();

  if(ctx->dx==3) {
    // COM_QUERY
    struct mysqlCmdStruct cmd;
    bpf_probe_read(&cmd,sizeof(cmd),(void *)ctx->si);
    char queryFmt[]="query %s\n";
    bpf_trace_printk(queryFmt,sizeof(queryFmt),(char *)cmd.command);
  }
  
  char msg[]="mysql probe %x\n";
  bpf_perf_event_output(ctx, &mysql_queries, BPF_F_CURRENT_CPU, msg,sizeof(msg));
	
	if (!should_target(id >> 32)) {
		return;
	}
}

