/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#ifndef __PIDS__
#define __PIDS__

int should_target(__u32 pid, struct pid_info** p_info) {
	struct pid_info* p = bpf_map_lookup_elem(&pids_map, &pid);

	if (p != NULL) {
		if (p_info)
			*p_info = p;
		return 1;
	}

	__u32 globalPid = 0;
	p = bpf_map_lookup_elem(&pids_map, &globalPid);

	if (p && p_info)
		*p_info = p;

	return p != NULL;
}

#endif /* __PIDS__ */
