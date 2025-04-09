/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#pragma once

#include "maps.h"

int should_target_cgroup(__u64 cgroup_id) {
    __u32 zero = 0;
    struct configuration* s = bpf_map_lookup_elem(&settings, &zero);
    if (s && (s->flags & CONFIGURATION_PASS_ALL_CGROUPS)) {
        return 1;
    }

    return bpf_map_lookup_elem(&cgroup_ids, &cgroup_id) ? 1 : 0;
}