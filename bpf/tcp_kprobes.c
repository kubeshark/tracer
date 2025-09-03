#include "include/common.h"
#include "include/headers.h"
#include "include/log.h"
#include "include/logger_messages.h"
#include "include/maps.h"
#include "include/pids.h"

static __always_inline int
tcp_kprobes_get_address_pair_from_ctx(struct pt_regs *ctx, __u64 id,
                                      struct address_info *address_info_ptr) {
  long err;
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  __u16 family_short;

  err = bpf_probe_read_kernel(&family_short, sizeof(family_short),
                              (void *)&sk->__sk_common.skc_family);
  if (err != 0) {
    log_error(ctx, LOG_ERROR_READING_SOCKET_FAMILY, id, err, 0l);
    return -1;
  }

  address_info_ptr->family = (__be32)family_short;

  if (address_info_ptr->family == AF_INET) {
    // Extract IPv4 addresses
    err = bpf_probe_read_kernel(&address_info_ptr->saddr4,
                                sizeof(address_info_ptr->saddr4),
                                (void *)&sk->__sk_common.skc_rcv_saddr);
    if (err != 0) {
      log_error(ctx, LOG_ERROR_READING_SOCKET_SADDR, id, err, 0l);
      return -1;
    }
    err = bpf_probe_read_kernel(&address_info_ptr->daddr4,
                                sizeof(address_info_ptr->daddr4),
                                (void *)&sk->__sk_common.skc_daddr);
    if (err != 0) {
      log_error(ctx, LOG_ERROR_READING_SOCKET_DADDR, id, err, 0l);
      return -1;
    }
  } else if (address_info_ptr->family == AF_INET6) {
    // Extract IPv6 addresses
    err = bpf_probe_read_kernel(address_info_ptr->saddr6,
                                sizeof(address_info_ptr->saddr6),
                                (void *)&sk->__sk_common.skc_v6_rcv_saddr);
    if (err != 0) {
      log_error(ctx, LOG_ERROR_READING_SOCKET_SADDR, id, err, 0l);
      return -1;
    }
    err = bpf_probe_read_kernel(address_info_ptr->daddr6,
                                sizeof(address_info_ptr->daddr6),
                                (void *)&sk->__sk_common.skc_v6_daddr);
    if (err != 0) {
      log_error(ctx, LOG_ERROR_READING_SOCKET_DADDR, id, err, 0l);
      return -1;
    }
  } else {
    log_error(ctx, LOG_ERROR_UNKNOWN_FAMILY, id, address_info_ptr->family, 0l);
    return -1;
  }

  err = bpf_probe_read_kernel(&address_info_ptr->dport,
                              sizeof(address_info_ptr->dport),
                              (void *)&sk->__sk_common.skc_dport);
  if (err != 0) {
    log_error(ctx, LOG_ERROR_READING_SOCKET_DPORT, id, err, 0l);
    return -1;
  }
  err = bpf_probe_read_kernel(&address_info_ptr->sport,
                              sizeof(address_info_ptr->sport),
                              (void *)&sk->__sk_common.skc_num);
  if (err != 0) {
    log_error(ctx, LOG_ERROR_READING_SOCKET_SPORT, id, err, 0l);
    return -1;
  }
  address_info_ptr->sport = bpf_htons(address_info_ptr->sport);

  return 0;
}

static __always_inline void
tcp_kprobes_forward_go(struct pt_regs *ctx, __u64 id, __u32 fd,
                       struct address_info address_info,
                       void *map_fd_go_user_kernel) {
  __u32 pid = id >> 32;
  __u64 key = (__u64)pid << 32 | fd;

  long err =
      bpf_map_update_elem(map_fd_go_user_kernel, &key, &address_info, BPF_ANY);
  if (err != 0) {
    log_error(ctx, LOG_ERROR_PUTTING_GO_USER_KERNEL_CONTEXT, id, fd, err);
    return;
  }
}

static void __always_inline tcp_kprobes_forward_openssl(
    struct pt_regs *ctx, __u64 id, struct ssl_info *info_ptr,
    struct address_info address_info) {
  info_ptr->address_info.family = address_info.family;

  if (address_info.family == AF_INET) {
    info_ptr->address_info.saddr4 = address_info.saddr4;
    info_ptr->address_info.daddr4 = address_info.daddr4;
  } else if (address_info.family == AF_INET6) {
    __builtin_memcpy(info_ptr->address_info.saddr6, address_info.saddr6,
                     sizeof(address_info.saddr6));
    __builtin_memcpy(info_ptr->address_info.daddr6, address_info.daddr6,
                     sizeof(address_info.daddr6));
  } else {
    log_error(ctx, LOG_ERROR_UNKNOWN_FAMILY, id, address_info.family, 0l);
    return;
  }

  info_ptr->address_info.dport = address_info.dport;
  info_ptr->address_info.sport = address_info.sport;
}

static __always_inline void tcp_kprobe(struct pt_regs *ctx,
                                       void *map_fd_openssl,
                                       void *map_fd_go_kernel,
                                       void *map_fd_go_user_kernel) {
  long err;

  __u64 id = tracer_get_current_pid_tgid();

  struct address_info address_info = {};
  if (0 != tcp_kprobes_get_address_pair_from_ctx(ctx, id, &address_info)) {
    return;
  }

  struct ssl_info *info_ptr = bpf_map_lookup_elem(map_fd_openssl, &id);
  __u32 *fd_ptr;
  if (info_ptr == NULL) {
    fd_ptr = bpf_map_lookup_elem(map_fd_go_kernel, &id);
    // Connection is used by a Go program
    if (fd_ptr == NULL) {
      // Connection was not created by a Go program or by openssl lib
      return;
    }
    tcp_kprobes_forward_go(ctx, id, *fd_ptr, address_info,
                           map_fd_go_user_kernel);
  } else {
    // Connection is used by openssl lib
    tcp_kprobes_forward_openssl(ctx, id, info_ptr, address_info);
  }
}

SEC("kprobe/tcp_sendmsg")
void BPF_KPROBE(tcp_sendmsg) {
  __u64 id = tracer_get_current_pid_tgid();
  tcp_kprobe(ctx, &openssl_write_context, &go_kernel_write_context,
             &go_user_kernel_write_context);
}

SEC("kprobe/tcp_recvmsg")
void BPF_KPROBE(tcp_recvmsg) {
  __u64 id = tracer_get_current_pid_tgid();
  tcp_kprobe(ctx, &openssl_read_context, &go_kernel_read_context,
             &go_user_kernel_read_context);
}
