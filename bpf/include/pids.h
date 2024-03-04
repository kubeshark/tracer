/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#ifndef __PIDS__
#define __PIDS__

int _pid_in_map(struct bpf_map_def* pmap, __u32 pid) {
	__u32* shouldTarget = bpf_map_lookup_elem(pmap, &pid);

	if (shouldTarget != NULL && *shouldTarget == 1) {
		return 1;
	}

	__u32 globalPid = 0;
	__u32* shouldTargetGlobally = bpf_map_lookup_elem(pmap, &globalPid);

	return shouldTargetGlobally != NULL && *shouldTargetGlobally == 1;
}


int should_target(__u32 pid) {
	return _pid_in_map(&target_pids_map, pid);
}

int should_watch(__u32 pid) {
	return _pid_in_map(&watch_pids_map, pid);
}

#endif /* __PIDS__ */
