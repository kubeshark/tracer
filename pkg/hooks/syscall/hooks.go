package syscall

import (
	"fmt"

	"github.com/kubeshark/tracer/pkg/bpf"
)

type Options struct {
	CgroupRoot       string
	UseSockAddr      bool
	EnableUDPKprobes bool
}

type SyscalHooks interface {
	Install() error
	Uninstall() error
}

type SyscalHooksImpl struct {
	bpfObjects     *bpf.BpfObjects
	opts           Options
	syscallHooks   syscallHooks
	tcpKprobeHooks tcpKprobeHooks
}

func NewSyscallHooks(bpfObjects *bpf.BpfObjects, opts Options) SyscalHooks {
	return &SyscalHooksImpl{
		bpfObjects:   bpfObjects,
		opts:         opts,
		syscallHooks: syscallHooks{cgroupPath: opts.CgroupRoot},
	}
}

func (h *SyscalHooksImpl) Install() error {
	if err := h.syscallHooks.installSyscallHooks(&h.bpfObjects.BpfObjs); err != nil {
		return fmt.Errorf("install syscall hooks failed: %v", err)
	}

	if err := h.tcpKprobeHooks.installTcpKprobeHooks(&h.bpfObjects.BpfObjs); err != nil {
		return fmt.Errorf("install tcp kprobe hooks failed: %v", err)
	}

	if h.opts.UseSockAddr && h.opts.CgroupRoot != "" {
		if err := h.syscallHooks.attachSockAddr(&h.bpfObjects.BpfObjs); err != nil {
			return fmt.Errorf("attach UDP sock_addr failed: %w", err)
		}
	} else if h.opts.EnableUDPKprobes {
		return nil
	}

	return nil
}

func (h *SyscalHooksImpl) Uninstall() error {
	if err := h.syscallHooks.close(); err != nil {
		return fmt.Errorf("close syscall hooks failed: %v", err)
	}

	if err := h.tcpKprobeHooks.close(); err != nil {
		return fmt.Errorf("close tcp kprobe hooks failed: %v", err)
	}

	return nil
}
