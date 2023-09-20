/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#ifndef __PIDS__
#define __PIDS__

int should_target(__u32 pid) {
	__u32* shouldTarget = bpf_map_lookup_elem(&pids_map, &pid);
	
	if (shouldTarget != NULL && *shouldTarget == 1) {
		return 1;
	}
	
	__u32 globalPid = 0;
	__u32* shouldTargetGlobally = bpf_map_lookup_elem(&pids_map, &globalPid);
	
	return shouldTargetGlobally != NULL && *shouldTargetGlobally == 1;
}

#endif /* __PIDS__ */
