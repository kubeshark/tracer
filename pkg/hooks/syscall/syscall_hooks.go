package syscall

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-errors/errors"
	"github.com/kubeshark/tracer/pkg/bpf"
)

type syscallHooks struct {
	links []link.Link

	/*
		sysEnterRead     link.Link
		sysEnterWrite    link.Link
		sysEnterRecvfrom link.Link
		sysEnterSendto   link.Link
		sysExitRead      link.Link
		sysExitWrite     link.Link
		sysEnterAccept4  link.Link
		sysExitAccept4   link.Link
		sysEnterAccept   link.Link
		sysExitAccept    link.Link
		sysEnterConnect  link.Link
		sysExitConnect   link.Link
		sysEnterOpen     link.Link
		sysExitOpen      link.Link
		sysEnterOpenAt   link.Link
		sysExitOpenAt    link.Link
		sysEnterOpenAt2  link.Link
		sysExitOpenAt2   link.Link

		sysSecurityFileOpen    link.Link
		sysSecurityInodeUnlink link.Link
		sysSecurityInodeRename link.Link

		sysVfsCreate         link.Link
		sysVfsRename         link.Link
		sysDoMkdirAt         link.Link
		sysDoMkdirAtRet      link.Link
		sysVfsRmDir          link.Link
		sysSecurityPathMkdir link.Link
	*/
}

func (s *syscallHooks) addTracepoint(group, name string, program *ebpf.Program) error {
	l, err := link.Tracepoint(group, name, program, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.links = append(s.links, l)
	return nil
}

func (s *syscallHooks) addRawTracepoint(name string, program *ebpf.Program) error {
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
	l, err := link.Kprobe(name, program, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.links = append(s.links, l)
	return nil
}

func (s *syscallHooks) addKretprobe(name string, program *ebpf.Program) error {
	l, err := link.Kretprobe(name, program, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.links = append(s.links, l)
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

	if err = s.addTracepoint("syscalls", "sys_enter_open", bpfObjects.SysEnterOpen); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_exit_open", bpfObjects.SysExitOpen); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_enter_openat", bpfObjects.SysEnterOpenat); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_exit_openat", bpfObjects.SysExitOpenat); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_enter_openat2", bpfObjects.SysEnterOpenat2); err != nil {
		return err
	}

	if err = s.addTracepoint("syscalls", "sys_exit_openat2", bpfObjects.SysExitOpenat2); err != nil {
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

	if err = s.addKprobe("vfs_rename", bpfObjects.VfsRename); err != nil {
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

	if err = s.addKprobe("security_path_mkdir", bpfObjects.SecurityPathMkdir); err != nil {
		return err
	}

	if err = s.addRawTracepoint("sched_process_fork", bpfObjects.SchedProcessFork); err != nil {
		return err
	}

	if err = s.addKretprobe("kernel_clone", bpfObjects.KernelClone); err != nil {
		return err
	}

	if err = s.addKretprobe("sys_execve", bpfObjects.SysExecveExit); err != nil {
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
