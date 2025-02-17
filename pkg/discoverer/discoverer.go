package discoverer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/go-errors/errors"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/cgroup"
	"github.com/kubeshark/tracer/pkg/utils"

	"github.com/rs/zerolog/log"
)

type InternalEventsDiscoverer interface {
	Start() error
	TargetCgroup(cgroupId uint64)
	UntargetCgroup(cgroupId uint64)
}

type InternalEventsDiscovererImpl struct {
	bpfObjects         *bpf.BpfObjects
	sslHooks           *sslHooksManager
	perfFoundOpenssl   *ebpf.Map
	perfFoundCgroup    *ebpf.Map
	perfCgroupSignal   *ebpf.Map
	readerFoundOpenssl *perf.Reader
	readerFoundCgroup  *perf.Reader
	readerCgroupSignal *perf.Reader

	cgroupsController cgroup.CgroupsController
	pids              *pids
}

func NewInternalEventsDiscoverer(procfs string, bpfObjects *bpf.BpfObjects, cgroupsController cgroup.CgroupsController) (InternalEventsDiscoverer, error) {
	impl := InternalEventsDiscovererImpl{
		bpfObjects:        bpfObjects,
		perfFoundOpenssl:  bpfObjects.BpfObjs.PerfFoundOpenssl,
		perfFoundCgroup:   bpfObjects.BpfObjs.PerfFoundCgroup,
		perfCgroupSignal:  bpfObjects.BpfObjs.PerfCgroupSignal,
		sslHooks:          newSslHooksManager(bpfObjects),
		cgroupsController: cgroupsController,
	}
	var err error
	impl.pids, err = newPids(procfs, bpfObjects, impl.cgroupsController)
	if err != nil {
		return nil, err
	}
	if impl.pids == nil {
		return nil, fmt.Errorf("no pids created: %v", err)
	}
	return &impl, nil
}

//TODO: Stop method

func (e *InternalEventsDiscovererImpl) Start() error {
	var err error

	isCgroupV2, err := utils.IsCgroupV2()
	if err != nil {
		return errors.Wrap(err, 0)
	}

	bufferSize := os.Getpagesize() * 10

	e.readerFoundOpenssl, err = perf.NewReader(e.perfFoundOpenssl, bufferSize)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	e.readerFoundCgroup, err = perf.NewReader(e.perfFoundCgroup, bufferSize)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	e.readerCgroupSignal, err = perf.NewReader(e.perfCgroupSignal, bufferSize)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	go e.handleFoundOpenssl()
	go e.handleFoundCgroup(isCgroupV2)

	go e.pids.handleFoundNewPIDs()

	go e.handleCgroupSignal()

	e.scanExistingCgroups(isCgroupV2)

	if err = e.pids.scanExistingPIDs(isCgroupV2); err != nil {
		return errors.Wrap(err, 0)
	}

	return nil
}

func (e *InternalEventsDiscovererImpl) TargetCgroup(cgroupId uint64) {
	e.pids.targetCgroup(cgroupId)
}

func (e *InternalEventsDiscovererImpl) UntargetCgroup(cgroupId uint64) {
	e.pids.untargetCgroup(cgroupId)
}

type foundFileEvent struct {
	path     [4096]byte
	cgroupId uint64
	inode    uint64
	deviceId uint32
	size     uint16
	remove   uint8
}

func (e *InternalEventsDiscovererImpl) scanExistingCgroups(isCgroupsV2 bool) {
	walk := func(s string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}

		if !isCgroupsV2 && !strings.HasPrefix(s, "/sys/fs/cgroup/cpuset") {
			return nil
		}

		if cgroupID, contId, ok := e.cgroupsController.AddCgroupPath(s); ok {
			log.Debug().Uint64("Cgroup ID", cgroupID).Str("Container ID", contId).Msg("Initial cgroup is detected")
		}

		return nil
	}
	_ = filepath.WalkDir("/sys/fs/cgroup", walk)

	// scan all existing pids to find out all opened inodes of sockets
	if err := e.cgroupsController.PopulateSocketsInodes(isCgroupsV2, e.bpfObjects.BpfObjs.Inodemap); err != nil {
		log.Error().Err(err).Msg("Populate sockets inodes failed")
	}
}

func (e *InternalEventsDiscovererImpl) handleFoundOpenssl() {
	for {
		record, err := e.readerFoundOpenssl.Read()

		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Warn().Msg("found openssl handler is closed")
				return
			}

			log.Error().Err(err).Msg("read perf in openssl handler failed")
			return
		}
		if record.LostSamples != 0 {
			log.Warn().Msg(fmt.Sprintf("Buffer is full, dropped %d libssl entry", record.LostSamples))
			continue
		}

		const expectSize = 4124
		data := record.RawSample
		if len(data) != expectSize {
			log.Error().Msg(fmt.Sprintf("bad event: size %v expected: %v\n", len(data), expectSize))
			return
		}
		p := (*foundFileEvent)(unsafe.Pointer(&data[0]))
		if p.size < 1 {
			log.Error().Msg(fmt.Sprintf("wrong size received: %v\n", p.size))
			return
		}
		log.Debug().Uint32("Device ID", p.deviceId).Uint16("Size", p.size).Uint8("Remove", p.remove).Str("Path", string(p.path[:p.size-1])).Uint64("Cgroup ID", p.cgroupId).Str("inode", fmt.Sprintf("%x", p.inode)).Msg("Got file found event")
		if err = e.sslHooks.attachFile(p.cgroupId, p.deviceId, string(p.path[:p.size-1])); err != nil {
			log.Error().Err(err).Msg("hook openSSL failed")
			return
		}
	}
}

func (e *InternalEventsDiscovererImpl) handleCgroupSignal() {
	for {
		record, err := e.readerCgroupSignal.Read()

		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Warn().Msg("cgroup signal handler is closed")
				return
			}

			log.Error().Err(err).Msg("read perf in cgroup signal handler failed")
			return
		}
		if record.LostSamples != 0 {
			log.Warn().Msg(fmt.Sprintf("Buffer is full, dropped %d libssl entry", record.LostSamples))
			continue
		}

		data := record.RawSample
		p := (*bpf.TracerCgroupSignal)(unsafe.Pointer(&data[0]))
		if p.Remove != 0 {
			if err = e.sslHooks.detachFile(p.CgroupId); err != nil {
				log.Error().Err(err).Msg("detash openSSL hook failed")
				return
			}
		}
	}
}

// TODO: reimplement based on "raw_tracepoint/cgroup_mkdir_signal"
func (e *InternalEventsDiscovererImpl) handleFoundCgroup(isCgroupsV2 bool) {
	for {
		record, err := e.readerFoundCgroup.Read()

		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Error().Msg("found cgroupv2 handler is closed")
				return
			}

			log.Error().Err(err).Msg("read perf in cgroupv2 handler failed")
			return
		}
		if record.LostSamples != 0 {
			log.Warn().Msg(fmt.Sprintf("Buffer is full, dropped %d cgroupv2 entry", record.LostSamples))
			continue
		}

		const expectSize = 4124
		data := record.RawSample
		if len(data) != expectSize {
			log.Error().Msg(fmt.Sprintf("bad event: size %v expected: %v\n", len(data), expectSize))
			return
		}
		p := (*foundFileEvent)(unsafe.Pointer(&data[0]))
		if p.size < 1 {
			log.Error().Msg(fmt.Sprintf("wrong size received: %v\n", p.size))
			return
		}

		cgroupPath := string(p.path[:p.size-1])

		if !isCgroupsV2 && !strings.HasPrefix(cgroupPath, "/sys/fs/cgroup/cpuset") {
			return
		}

		if cgroupID, contId, ok := e.cgroupsController.AddCgroupPath(cgroupPath); ok {
			log.Debug().Uint64("Cgroup ID", cgroupID).Str("Container ID", contId).Msg("New cgroup is detected")
		}
	}
}
