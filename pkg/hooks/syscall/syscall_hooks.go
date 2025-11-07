package syscall

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-errors/errors"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/rs/zerolog/log"
)

type syscallHooks struct {
	links      []link.Link
	cgroupPath string
}

func newSyscallHooks(cgroupPath string) *syscallHooks {
	return &syscallHooks{cgroupPath: cgroupPath}
}

func (s *syscallHooks) addTracepoint(group, name string, program *ebpf.Program) error {
	if program == nil {
		return nil
	}
	l, err := link.Tracepoint(group, name, program, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.links = append(s.links, l)
	return nil
}

func (s *syscallHooks) addRawTracepoint(name string, program *ebpf.Program) error {
	if program == nil {
		return nil
	}
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    name,
		Program: program,
	})
	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.links = append(s.links, l)
	return nil
}

func (s *syscallHooks) addKprobe(name string, program *ebpf.Program) error {
	if program == nil {
		return nil
	}
	l, err := link.Kprobe(name, program, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.links = append(s.links, l)
	return nil
}

func (s *syscallHooks) addKretprobe(name string, program *ebpf.Program) error {
	if program == nil {
		return nil
	}
	l, err := link.Kretprobe(name, program, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.links = append(s.links, l)
	return nil
}

func (s *syscallHooks) addCgroupSockAddr(attach ebpf.AttachType, program *ebpf.Program) error {
	if program == nil || s.cgroupPath == "" {
		return nil
	}
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    s.cgroupPath,
		Attach:  attach,
		Program: program,
	})
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, l)
	return nil
}

func (s *syscallHooks) attachSockAddr(objs *bpf.TracerObjects) error {
	if err := s.addCgroupSockAddr(ebpf.AttachCGroupUDP4Sendmsg, objs.UdpSendmsg4); err != nil {
		return err
	}
	if err := s.addCgroupSockAddr(ebpf.AttachCGroupUDP4Recvmsg, objs.UdpRecvmsg4); err != nil {
		return err
	}
	// IPv6 best-effort (don’t fail whole install if missing)
	if err := s.addCgroupSockAddr(ebpf.AttachCGroupUDP6Sendmsg, objs.UdpSendmsg6); err != nil {
		log.Warn().Err(err).Msg("udp sendmsg6 attach failed")
	}
	if err := s.addCgroupSockAddr(ebpf.AttachCGroupUDP6Recvmsg, objs.UdpRecvmsg6); err != nil {
		log.Warn().Err(err).Msg("udp recvmsg6 attach failed")
	}
	return nil
}

func (s *syscallHooks) attachUDPKprobes(objs *bpf.TracerObjects) error {
	if err := s.addKprobe("udp_sendmsg", objs.UdpSendmsgKp); err != nil {
		return err
	}
	if err := s.addKprobe("udpv6_sendmsg", objs.Udpv6SendmsgKp); err != nil {
		return err
	}
	_ = s.addKprobe("udp_recvmsg", objs.UdpRecvmsgKp)
	_ = s.addKprobe("udpv6_recvmsg", objs.Udpv6RecvmsgKp)
	return nil
}

func (s *syscallHooks) installSyscallHooks(bpfObjects *bpf.TracerObjects) error {
	var err error

	if err = s.addTracepoint("syscalls", "sys_enter_read", bpfObjects.SysEnterRead); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_enter_write", bpfObjects.SysEnterWrite); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_enter_recvfrom", bpfObjects.SysEnterRecvfrom); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_enter_sendto", bpfObjects.SysEnterSendto); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_exit_read", bpfObjects.SysExitRead); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_exit_write", bpfObjects.SysExitWrite); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_enter_accept4", bpfObjects.SysEnterAccept4); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_enter_accept", bpfObjects.SysEnterAccept4); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_exit_accept4", bpfObjects.SysExitAccept4); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_exit_accept", bpfObjects.SysExitAccept4); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_enter_connect", bpfObjects.SysEnterConnect); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_exit_connect", bpfObjects.SysExitConnect); err != nil {
		return err
	}

	if err = s.addKprobe("security_file_open", bpfObjects.SecurityFileOpen); err != nil {
		return err
	}

	if err = s.addKprobe("security_inode_unlink", bpfObjects.SecurityInodeUnlink); err != nil {
		return err
	}

	if err = s.addKprobe("security_inode_rename", bpfObjects.SecurityInodeRename); err != nil {
		return err
	}

	if err = s.addKprobe("vfs_create", bpfObjects.VfsCreate); err != nil {
		return err
	}

	if err = s.addKprobe("do_mkdirat", bpfObjects.DoMkdirat); err != nil {
		return err
	}

	if err = s.addKretprobe("do_mkdirat", bpfObjects.DoMkdiratRet); err != nil {
		return err
	}

	if err = s.addKprobe("vfs_rmdir", bpfObjects.VfsRmdir); err != nil {
		return err
	}

	if err = s.addKprobe("security_socket_recvmsg", bpfObjects.SecuritySocketRecvmsg); err != nil {
		return err
	}

	if err = s.addKprobe("security_socket_sendmsg", bpfObjects.SecuritySocketSendmsg); err != nil {
		return err
	}
	if err = s.addKprobe("__cgroup_bpf_run_filter_skb", bpfObjects.CgroupBpfRunFilterSkb); err != nil {
		return err
	}

	if err = s.addKprobe("sock_alloc_file", bpfObjects.SockAllocFile); err != nil {
		return err
	}
	if err = s.addKretprobe("sock_alloc_file", bpfObjects.SockAllocFileRet); err != nil {
		return err
	}

	if err = s.addKprobe("security_path_mkdir", bpfObjects.SecurityPathMkdir); err != nil {
		log.Warn().Err(err).Msg("security_path_mkdir can not be attached. Probably system is running on incomatible kernel")
	}

	if err = s.addRawTracepoint("sched_process_fork", bpfObjects.SchedProcessFork); err != nil {
		return err
	}

	if err = s.addKretprobe("sys_execve", bpfObjects.SysExecveExit); err != nil {
		return err
	}

	if err = s.addKprobe("security_sk_clone", bpfObjects.SecuritySkClone); err != nil {
		return err
	}

	if err = s.addRawTracepoint("cgroup_mkdir", bpfObjects.CgroupMkdirSignal); err != nil {
		return err
	}

	if err = s.addRawTracepoint("cgroup_rmdir", bpfObjects.CgroupRmdirSignal); err != nil {
		return err
	}

	return nil
}

func (s *syscallHooks) close() []error {
	returnValue := make([]error, 0)

	for _, l := range s.links {
		if err := l.Close(); err != nil {
			returnValue = append(returnValue, err)
		}
	}

	return returnValue
}
