package discoverer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/go-errors/errors"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/cgroup"
	sslHooks "github.com/kubeshark/tracer/pkg/hooks/ssl"
	"github.com/kubeshark/tracer/pkg/utils"

	"github.com/rs/zerolog/log"
)

// ----------------------------------------------------------------------

type InternalEventsDiscoverer interface {
	Start() error
	TargetCgroup(cgroupId uint64)
	UntargetCgroup(cgroupId uint64)
}

type InternalEventsDiscovererImpl struct {
	bpfObjects         *bpf.BpfObjects
	isCgroupV2         bool
	sslHooks           map[string]sslHooks.SslHooks
	perfFoundOpenssl   *ebpf.Map
	perfFoundCgroup    *ebpf.Map
	readerFoundOpenssl *perf.Reader
	readerFoundCgroup  *perf.Reader

	cgroupsController cgroup.CgroupsController
	containersInfoMtx sync.Mutex
	pids              *pids
}

func NewInternalEventsDiscoverer(procfs string, bpfObjects *bpf.BpfObjects, cgroupsController cgroup.CgroupsController) InternalEventsDiscoverer {
	impl := InternalEventsDiscovererImpl{
		bpfObjects:        bpfObjects,
		isCgroupV2:        bpfObjects.IsCgroupV2,
		perfFoundOpenssl:  bpfObjects.BpfObjs.PerfFoundOpenssl,
		perfFoundCgroup:   bpfObjects.BpfObjs.PerfFoundCgroup,
		sslHooks:          make(map[string]sslHooks.SslHooks),
		cgroupsController: cgroupsController,
	}
	var err error
	impl.pids, err = newPids(procfs, bpfObjects, impl.cgroupsController)
	if err != nil {
		return nil
	}
	if impl.pids == nil {
		return nil
	}
	return &impl
}

//TODO: Stop method

func (e *InternalEventsDiscovererImpl) Start() error {
	var err error

	isCgroupV2, err := utils.IsCgroupV2()
	if err != nil {
		return errors.Wrap(err, 0)
	}

	bufferSize := os.Getpagesize() * 100

	e.readerFoundOpenssl, err = perf.NewReader(e.perfFoundOpenssl, bufferSize)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	e.readerFoundCgroup, err = perf.NewReader(e.perfFoundCgroup, bufferSize)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	go e.handleFoundOpenssl()
	go e.handleFoundCgroup(isCgroupV2)

	go e.pids.handleFoundNewPIDs()

	e.scanExistingCgroups(isCgroupV2)

	if err = e.pids.scanExistingPIDs(e.isCgroupV2); err != nil {
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

		if cgroupID, contId, ok := e.cgroupsController.AddCgroupPath(s); ok {
			log.Debug().Uint64("Cgroup ID", cgroupID).Str("Container ID", contId).Msg("Initial cgroup is detected")
		}

		return nil
	}
	_ = filepath.WalkDir("/sys/fs/cgroup", walk)
}

func (e *InternalEventsDiscovererImpl) handleFoundOpenssl() {
	for {
		record, err := e.readerFoundOpenssl.Read()

		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Info().Msg("found openssl handler is closed")
				return
			}

			log.Error().Err(err).Msg("read perf in openssl handler failed")
			return
		}
		if record.LostSamples != 0 {
			log.Info().Msg(fmt.Sprintf("Buffer is full, dropped %d libssl entry", record.LostSamples))
			continue
		}

		const expectSize = 4108
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

		// TODO: check what so big device ID number means
		if p.deviceId > 0xffff {
			continue
		}

		mountPoint, err := getMountPointByDeviceId(p.deviceId)
		if err != nil {
			log.Warn().Uint32("Device ID", p.deviceId).Msg(fmt.Sprintf("get mount point failed: %v", err))
			continue
		}
		if mountPoint == "" {
			log.Warn().Uint32("Device ID", p.deviceId).Msg("mount point can not be found:")
			continue
		}
		var installPaths []string
		installPaths = append(installPaths, string(p.path[:p.size-1]))
		installPaths = append(installPaths, filepath.Join("/hostroot", mountPoint, string(p.path[:p.size-1])))

		for _, installPath := range installPaths {
			if p.remove == 0 {
				if _, ok := e.sslHooks[installPath]; ok {
					log.Debug().Str("path", installPath).Msg("ssl hook already exists")
					continue
				}
				hook := sslHooks.SslHooks{}
				err = hook.InstallUprobes(e.bpfObjects, installPath)
				if err != nil {
					log.Debug().Err(err).Uint16("size", p.size).Str("path", installPath).Msg("Install uprobe missed")
				} else {
					e.sslHooks[installPath] = hook
					log.Debug().Uint16("size", p.size).Str("path", installPath).Msg("New ssl hook is installed")
				}
			}
		}
		//TODO: check cases when existing hook can be deleted:
		/*
			log.Debug().Str("path", installPath).Msg("deleteing ssl hook")
			delete(e.sslHooks, installPath)
		*/
	}
}

func (e *InternalEventsDiscovererImpl) handleFoundCgroup(isCgroupsV2 bool) {
	for {
		record, err := e.readerFoundCgroup.Read()

		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Info().Msg("found cgroupv2 handler is closed")
				return
			}

			log.Error().Err(err).Msg("read perf in cgroupv2 handler failed")
			return
		}
		if record.LostSamples != 0 {
			log.Info().Msg(fmt.Sprintf("Buffer is full, dropped %d cgroupv2 entry", record.LostSamples))
			continue
		}

		const expectSize = 4108
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
