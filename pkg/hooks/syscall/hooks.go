package syscall

import (
	"fmt"

	"github.com/kubeshark/tracer/pkg/bpf"
)

type SyscalHooks interface {
	Install() error
	Uninstall() error
}

type SyscalHooksImpl struct {
	bpfObjects     *bpf.BpfObjects
	syscallHooks   syscallHooks
	tcpKprobeHooks tcpKprobeHooks
}

func NewSyscallHooks(bpfObjects *bpf.BpfObjects) SyscalHooks {
	return &SyscalHooksImpl{
		bpfObjects: bpfObjects,
	}
}

func (h *SyscalHooksImpl) Install() error {
	if err := h.syscallHooks.installSyscallHooks(&h.bpfObjects.BpfObjs); err != nil {
		return fmt.Errorf("install syscall hooks failed: %v", err)
	}

	if err := h.tcpKprobeHooks.installTcpKprobeHooks(&h.bpfObjects.BpfObjs); err != nil {
		return fmt.Errorf("install tcp kprobe hooks failed: %v", err)
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
