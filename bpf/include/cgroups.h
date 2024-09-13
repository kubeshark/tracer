/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#pragma once

#include "maps.h"

int should_target_cgroup(__u64 cgroup_id) {
    return bpf_map_lookup_elem(&cgroup_ids, &cgroup_id) ? 1 : 0;
}