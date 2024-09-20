package poller

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/discoverer"
	logPoller "github.com/kubeshark/tracer/pkg/poller/log"
	packetsPoller "github.com/kubeshark/tracer/pkg/poller/packets"
	syscallPoller "github.com/kubeshark/tracer/pkg/poller/syscall"
	"github.com/rs/zerolog/log"
)

type BpfPoller interface {
	Start() error
	Stop() error
}

type BpfPollerImpl struct {
	tlsPoller     *bpf.TlsPoller
	syscallPoller *syscallPoller.SyscallEventsTracer
	packetsPoller *packetsPoller.PacketsPoller
	logPoller     *logPoller.BpfLogger
}

func NewBpfPoller(bpfObjs *bpf.BpfObjects, sorter *bpf.PacketSorter, cgroupsInfo *lru.Cache[discoverer.CgroupID, discoverer.ContainerID], tlsLogDisabled bool) (BpfPoller, error) {
	log.Info().Msg("NewBpfPoller") //XXX
	var err error
	p := BpfPollerImpl{}

	if p.tlsPoller, err = bpf.NewTlsPoller(bpfObjs, sorter); err != nil {
		return nil, fmt.Errorf("create tls poller failed: %v", err)
	}

	if p.syscallPoller, err = syscallPoller.NewSyscallEventsTracer(bpfObjs, cgroupsInfo); err != nil {
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

func (p *BpfPollerImpl) Start() error {
	log.Info().Msg("BpfPoller Start") //XXX
	p.tlsPoller.Start()
	p.syscallPoller.Start()
	p.packetsPoller.Start()
	p.logPoller.Start()

	return nil
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
