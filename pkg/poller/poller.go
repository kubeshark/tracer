package poller

import (
	"fmt"

	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/cgroup"
	logPoller "github.com/kubeshark/tracer/pkg/poller/log"
	packetsPoller "github.com/kubeshark/tracer/pkg/poller/packets"
	syscallPoller "github.com/kubeshark/tracer/pkg/poller/syscall"
)

type BpfPoller interface {
	Start()
	Stop() error
}

type BpfPollerImpl struct {
	tlsPoller     *bpf.TlsPoller
	syscallPoller *syscallPoller.SyscallEventsTracer
	packetsPoller *packetsPoller.PacketsPoller
	logPoller     *logPoller.BpfLogger
}

func NewBpfPoller(bpfObjs *bpf.BpfObjects, sorter *bpf.PacketSorter, cgroupsController cgroup.CgroupsController, tlsLogDisabled bool) (BpfPoller, error) {
	var err error
	p := BpfPollerImpl{}

	if p.tlsPoller, err = bpf.NewTlsPoller(bpfObjs, sorter); err != nil {
		return nil, fmt.Errorf("create tls poller failed: %v", err)
	}

	if p.syscallPoller, err = syscallPoller.NewSyscallEventsTracer(bpfObjs, cgroupsController); err != nil {
		return nil, fmt.Errorf("create syscall poller failed: %v", err)
	}

	if p.packetsPoller, err = packetsPoller.NewPacketsPoller(bpfObjs, sorter); err != nil {
		return nil, fmt.Errorf("create packets poller failed: %v", err)
	}

	if p.logPoller, err = logPoller.NewBpfLogger(&bpfObjs.BpfObjs, tlsLogDisabled); err != nil {
		return nil, fmt.Errorf("create log poller failed: %v", err)
	}

	return &p, nil
}

func (p *BpfPollerImpl) Start() {
	p.tlsPoller.Start()
	p.syscallPoller.Start()
	p.packetsPoller.Start()
	p.logPoller.Start()
}

func (p *BpfPollerImpl) Stop() error {
	var err error

	if err = p.tlsPoller.Stop(); err != nil {
		return fmt.Errorf("stop tls poller failed: %v", err)
	}

	if err = p.syscallPoller.Stop(); err != nil {
		return fmt.Errorf("stop syscall poller failed: %v", err)
	}

	if err = p.packetsPoller.Stop(); err != nil {
		return fmt.Errorf("stop packets poller failed: %v", err)
	}

	if err = p.logPoller.Stop(); err != nil {
		return fmt.Errorf("stop log poller failed: %v", err)
	}

	return nil
}
