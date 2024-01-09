#include "include/headers.h"
#include "include/maps.h"
#include "include/log.h"
#include "include/logger_messages.h"
#include "include/pids.h"
#include "include/common.h"


// The ctx contains a struct sock * parameter in PT_REGS_PARM1. Use
// that to capture address info
static __always_inline int tcp_kprobes_get_address_pair_from_ctx(struct pt_regs *ctx, __u64 id, struct address_info *address_info_ptr) {
	long err;
	struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
  struct sock_common scommon;
  err=bpf_probe_read(&scommon,sizeof(scommon),&sk->__sk_common);
  if (err!=0) {
    log_error(ctx, LOG_ERROR_READING_SOCKET_INFO, id, err, 0l);
    return -1;
  }
  // Do not capture anything but inet and inet6. Inet4 traffic can
  // also appear as inet6 here.
  if(scommon.skc_family!=AF_INET && scommon.skc_family!=AF_INET6) {
    return -1;
  }
  // ipv4 addresses are populated even if skc_family=AF_INET6
  //
	// daddr, saddr and dport are in network byte order (big endian)
	// sport is in host byte order
  address_info_ptr->daddr = scommon.skc_daddr;
	address_info_ptr->saddr = scommon.skc_rcv_saddr;
	address_info_ptr->dport = scommon.skc_dport;
	address_info_ptr->sport = bpf_htons(scommon.skc_num);

	return 0;
}

static __always_inline void tcp_kprobes_forward_go(struct pt_regs *ctx, __u64 id, __u32 fd, struct address_info address_info, struct bpf_map_def *map_fd_go_user_kernel) {
		__u32 pid = id >> 32;
		__u64 key = (__u64) pid << 32 | fd;

		long err = bpf_map_update_elem(map_fd_go_user_kernel, &key, &address_info, BPF_ANY);
    if (err != 0) {
        log_error(ctx, LOG_ERROR_PUTTING_GO_USER_KERNEL_CONTEXT, id, fd, err);
				return;
    }
}

static void __always_inline tcp_kprobes_forward_openssl(struct ssl_info *info_ptr, struct address_info address_info) {
		info_ptr->address_info.daddr = address_info.daddr;
		info_ptr->address_info.saddr = address_info.saddr;
		info_ptr->address_info.dport = address_info.dport;
		info_ptr->address_info.sport = address_info.sport;
}

// This is called for both tcp sendmsg and receivemsg.
static __always_inline void tcp_kprobe(struct pt_regs *ctx, struct bpf_map_def *map_fd_openssl, struct bpf_map_def *map_fd_go_kernel, struct bpf_map_def *map_fd_go_user_kernel) {
	long err;

	__u64 id = bpf_get_current_pid_tgid();

	if (!should_target(id >> 32)) {
		return;
	}

  // Get the address info from socket
	struct address_info address_info;
	if (0 != tcp_kprobes_get_address_pair_from_ctx(ctx, id, &address_info)) {
		return;
	}

  // Try to access openssl info from the map.
	struct ssl_info *info_ptr = bpf_map_lookup_elem(map_fd_openssl, &id);
	__u32 *fd_ptr;
	if (info_ptr == NULL) {
		fd_ptr = bpf_map_lookup_elem(map_fd_go_kernel, &id);
		// Connection is used by a Go program
		if (fd_ptr == NULL) {
			// Connection was not created by a Go program or by openssl lib
			return;
		}
		tcp_kprobes_forward_go(ctx, id, *fd_ptr, address_info, map_fd_go_user_kernel);
	} else {
		// Connection is used by openssl lib
		tcp_kprobes_forward_openssl(info_ptr, address_info);
	}

}

SEC("kprobe/tcp_sendmsg")
void BPF_KPROBE(tcp_sendmsg) {
	__u64 id = bpf_get_current_pid_tgid();
	tcp_kprobe(ctx, &openssl_write_context, &go_kernel_write_context, &go_user_kernel_write_context);
}

SEC("kprobe/tcp_sendmsg_locked")
void BPF_KPROBE(tcp_sendmsg_locked) {
	__u64 id = bpf_get_current_pid_tgid();
	tcp_kprobe(ctx, &openssl_write_context, &go_kernel_write_context, &go_user_kernel_write_context);
}

SEC("kprobe/tcp_sendmsg_fastopen")
void BPF_KPROBE(tcp_sendmsg_fastopen) {
	__u64 id = bpf_get_current_pid_tgid();
	tcp_kprobe(ctx, &openssl_write_context, &go_kernel_write_context, &go_user_kernel_write_context);
}

SEC("kprobe/tcp_recvmsg")
void BPF_KPROBE(tcp_recvmsg) {
	__u64 id = bpf_get_current_pid_tgid();
	tcp_kprobe(ctx, &openssl_read_context, &go_kernel_read_context, &go_user_kernel_read_context);
}
