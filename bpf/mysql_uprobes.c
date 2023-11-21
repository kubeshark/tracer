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

// mysql uprobe goes to:
//
// dispatch_command in https://github.com/mysql/mysql-server/blob/trunk/sql/sql_parse.cc
//
//  bool dispatch_command(THD *thd, const COM_DATA *com_data,
//                        enum enum_server_command command)
//
// To attach the uprobe, you have to find the mangled name for
// dispatch_command, and then attach.
//
// In this version of mysql, the *com_data comes in si register, and
// command comes in dx. dx==3 means COM_QUERY, so we read the
// mysql_command structure from si
//
// TODO: Presumable this might be different for different versions of
// mysql, and we need to come up with a way to identify where the
// COM_QUERY_DATA is

SEC("uprobe/server_command_probe")
void BPF_KPROBE(server_command_probe, void* buffer, int num) {
	__u64 id = bpf_get_current_pid_tgid();

  if(ctx->dx==3) {
    // COM_QUERY
    struct mysql_command cmd;
    char (*command)[1024];
    int z = 0;
    command=bpf_map_lookup_elem(&mysql_command_heap,&z);
    if (!command) {
      return;
    }
    // Read the query and length from si
    bpf_probe_read(&cmd,sizeof(cmd),(void *)ctx->si);
    int len=sizeof(*command)-1;
    if (cmd.length<len) {
      len=cmd.length;
    }
    bpf_probe_read(command,len,cmd.command);
    bpf_perf_event_output(ctx, &mysql_queries, BPF_F_CURRENT_CPU, command,len);
  }	
}

