/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#ifndef __PIDS__
#define __PIDS__

#include "common.h"

int _pid_in_map(void* pmap, __u32 pid) {
	__u32* shouldTarget = bpf_map_lookup_elem(pmap, &pid);

	if (shouldTarget != NULL && *shouldTarget == 1) {
		return 1;
	}

	__u32 globalPid = 0;
	__u32* shouldTargetGlobally = bpf_map_lookup_elem(pmap, &globalPid);

	return shouldTargetGlobally != NULL && *shouldTargetGlobally == 1;
}

#define TRACER_NAMESPACES_MAX 4

static __always_inline int is_task_from_netns(struct task_struct* task) {
	unsigned int inum;
	if (TRACER_NS_INO == 0) {
		return 1;
	}

	int level = BPF_CORE_READ(task, group_leader, nsproxy, pid_ns_for_children, level);

	for (int i = 0; i < TRACER_NAMESPACES_MAX; i++) {
		if ((level - i) < 0) {
			break;
		}
		inum = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level - i].ns, ns.inum);
		if (inum == TRACER_NS_INO) {
			return 1;
		}
	}
	return 0;
}

static __always_inline __u64 tracer_get_task_pid_tgid(__u64 base_pid_tgid, struct task_struct* task) {
	unsigned int inum;

	int level = BPF_CORE_READ(task, group_leader, nsproxy, pid_ns_for_children, level);

	for (int i = 0; i < TRACER_NAMESPACES_MAX; i++) {
		if ((level - i) < 0) {
			break;
		}
		inum = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level - i].ns, ns.inum);
		if (inum == TRACER_NS_INO) {
			__u64 ret = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level - i].nr);
			ret = (ret << 32) | (base_pid_tgid & 0xFFFFFFFF);
			return ret;
		}
	}
	return base_pid_tgid;
}

static __always_inline __u64 tracer_get_current_pid_tgid() {
	unsigned int inum;

	__u64 base_pid_tgid = bpf_get_current_pid_tgid();

	if (TRACER_NS_INO == 0) {
		return base_pid_tgid;
	}

	struct task_struct* task = (struct task_struct*)bpf_get_current_task();
	return tracer_get_task_pid_tgid(base_pid_tgid, task);
}

#endif /* __PIDS__ */
