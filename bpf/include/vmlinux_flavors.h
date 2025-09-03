#pragma once

union kernfs_node_id {
  struct {
    u32 ino;
    u32 generation;
  };
  u64 id;
};

struct kernfs_node___older_v55 {
  const char *name;
  union kernfs_node_id id;
};

struct kernfs_node___rh8 {
  const char *name;
  union {
    u64 id;
    struct {
      union kernfs_node_id id;
    } rh_kabi_hidden_172;
    union {};
  };
};