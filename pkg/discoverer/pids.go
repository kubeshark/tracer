package discoverer

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/kubeshark/tracer/pkg/bpf"
	goHooks "github.com/kubeshark/tracer/pkg/hooks/go"
	"github.com/rs/zerolog/log"
)

type foundPidEvent struct {
	cgroup uint64
	pid    uint32
}

type pidInfo struct {
	gHooks   *goHooks.GoHooks
	cgroupId uint64
	path     string
}

type pids struct {
	procfs          string
	bpfObjs         *bpf.BpfObjects
	containersInfo  *lru.Cache[ContainerID, CgroupData]
	readerFoundPid  *perf.Reader
	discoveredPIDs  *lru.Cache[uint32, *pidInfo]
	targetedPIDs    *lru.Cache[uint32, *pidInfo]
	targetedCgroups *lru.Cache[uint64, struct{}]
	scanGolangQueue chan foundPidEvent
}

func newPids(procfs string, bpfObjs *bpf.BpfObjects, containersInfo *lru.Cache[ContainerID, CgroupData]) (*pids, error) {

	discoveredPids, err := lru.New[uint32, *pidInfo](16384)
	if err != nil {
		return nil, err
	}
	targetedPids, err := lru.New[uint32, *pidInfo](16384)
	if err != nil {
		return nil, err
	}
	targetedCgroups, err := lru.New[uint64, struct{}](16384)
	if err != nil {
		return nil, err
	}

	bufferSize := os.Getpagesize() * 100
	readerFoundPid, err := perf.NewReader(bpfObjs.BpfObjs.PerfFoundPid, bufferSize)
	if err != nil {
		return nil, err
	}

	p := &pids{
		procfs:          procfs,
		bpfObjs:         bpfObjs,
		containersInfo:  containersInfo,
		readerFoundPid:  readerFoundPid,
		discoveredPIDs:  discoveredPids,
		targetedPIDs:    targetedPids,
		targetedCgroups: targetedCgroups,
		scanGolangQueue: make(chan foundPidEvent, 8192),
	}

	go p.scanPids()

	return p, nil
}

func (p *pids) targetCgroup(cgroupId uint64) {
	p.targetedCgroups.Add(cgroupId, struct{}{})
	for _, pid := range p.discoveredPIDs.Keys() {
		pi, ok := p.discoveredPIDs.Get(pid)
		if !ok || pi.cgroupId != cgroupId || pi.gHooks != nil {
			continue
		}

		ex, err := link.OpenExecutable(pi.path)
		if err != nil {
			// process can be already terminated
			log.Debug().Err(err).Uint32("pid", pid).Uint64("cgroup", pi.cgroupId).Msg("Open executable failed")
			return
		}

		offsets, err := goHooks.FindGoOffsets(pi.path)
		if err != nil {
			return
		}
		hooks := goHooks.GoHooks{}

		err = hooks.InstallHooks(p.bpfObjs, ex, offsets)
		if err != nil {
			log.Warn().Err(err).Uint32("pid", pid).Uint64("cgroup", cgroupId).Msg("install go hook failed")
			return
		}
		pi.gHooks = &hooks

		log.Info().Uint32("pid", pid).Uint64("cgroup", pi.cgroupId).Msg("go hook installed")
	}
}

func (p *pids) untargetCgroup(cgroupId uint64) {
	p.targetedCgroups.Remove(cgroupId)
}

func (p *pids) handleFoundNewPIDs() {
	for {
		record, err := p.readerFoundPid.Read()

		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Info().Msg("found pid handler is closed")
				return
			}

			log.Error().Err(err).Msg("read perf in pid handler failed")
			return
		}
		if record.LostSamples != 0 {
			log.Info().Msg(fmt.Sprintf("Buffer is full, dropped %d pid found entry", record.LostSamples))
			continue
		}

		const expectSize = 20
		data := record.RawSample
		if len(data) != expectSize {
			log.Error().Msg(fmt.Sprintf("bad event: size %v expected: %v\n", len(data), expectSize))
			return
		}
		pEvent := (*foundPidEvent)(unsafe.Pointer(&data[0]))
		p.newPidFound(pEvent)
		log.Debug().Uint64("Cgroup ID", pEvent.cgroup).Uint32("PID", pEvent.pid).Msg("New process is detected")
	}
}

func (p *pids) scanExistingPIDs(isCgroupV2 bool) error {
	if isCgroupV2 {
		if err := p.scanPidsV2(); err != nil {
			return err
		}
	} else {
		if err := p.scanPidsV1(); err != nil {
			return err
		}
	}

	return nil
}

func (p *pids) newPidFound(pEvent *foundPidEvent) {
	p.scanGolangQueue <- *pEvent // TODO: async channel
}

func (p *pids) scanPids() {
	for e := range p.scanGolangQueue {
		p.installGoHook(e)
	}
}

func (p *pids) installGoHook(e foundPidEvent) {
	if _, ok := p.discoveredPIDs.Get(e.pid); ok {
		return
	}

	log.Debug().Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Msg("Install go hook begin")
	defer func() {
		log.Debug().Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Msg("Install go hook end")
	}()

	path, err := findLibraryByPid(p.procfs, e.pid, "")
	if err != nil {
		return
	}

	ex, err := link.OpenExecutable(path)
	if err != nil {
		log.Debug().Err(err).Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Msg("Open executable failed")
		return
	}

	pi := pidInfo{
		cgroupId: e.cgroup,
		path:     path,
	}
	p.discoveredPIDs.Add(e.pid, &pi)
	if _, ok := p.targetedCgroups.Get(pi.cgroupId); !ok {
		return
	}

	offsets, err := goHooks.FindGoOffsets(path)
	if err != nil {
		return
	}
	hooks := goHooks.GoHooks{}

	err = hooks.InstallHooks(p.bpfObjs, ex, offsets)
	if err != nil {
		log.Warn().Err(err).Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Msg("install go hook failed")
		return
	}

	pi.gHooks = &hooks
	p.discoveredPIDs.Add(e.pid, &pi)
	log.Info().Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Msg("Install go hook success") //TODO: debug?
}

var numberRegex = regexp.MustCompile("[0-9]+")

func (p *pids) scanPidsV2() error {
	allPids, err := os.ReadDir(p.procfs)
	if err != nil {
		return err
	}

	for _, pid := range allPids {
		if !numberRegex.MatchString(pid.Name()) {
			continue
		}

		fpath := fmt.Sprintf("%s/%s/cgroup", p.procfs, pid.Name())

		bytes, err := os.ReadFile(fpath)
		if err != nil {
			log.Debug().Err(err).Str("pid", pid.Name()).Msg("Couldn't read cgroup file.")
			continue
		}

		n, err := strconv.ParseUint(pid.Name(), 10, 32)
		if err != nil {
			log.Warn().Err(err).Str("pid", pid.Name()).Msg("Couldn't parse pid number.")
			continue
		}
		lines := strings.Split(string(bytes), "\n")
		parts := strings.Split(lines[0], ":")
		cgroupPath := parts[len(parts)-1]

		parts = strings.Split(cgroupPath, "/")
		parts = strings.Split(parts[len(parts)-1], "-")
		parts = strings.Split(parts[len(parts)-1], ".")

		id := GetContainerIdFromCgroupPath(normalyzeCgroupV2Path(cgroupPath))
		if id == "" {
			continue
		}
		ci, ok := p.containersInfo.Get(ContainerID(id))
		if !ok {
			continue
		}

		pEvent := foundPidEvent{
			cgroup: uint64(ci.CgroupID),
			pid:    uint32(n),
		}

		p.newPidFound(&pEvent)
	}

	return nil
}

func (p *pids) scanPidsV1() error {
	allPids, err := os.ReadDir(p.procfs)
	if err != nil {
		return err
	}

	for _, pid := range allPids {
		if !numberRegex.MatchString(pid.Name()) {
			continue
		}

		fpath := fmt.Sprintf("%s/%s/cgroup", p.procfs, pid.Name())

		bytes, err := os.ReadFile(fpath)
		if err != nil {
			log.Debug().Err(err).Str("pid", pid.Name()).Msg("Couldn't read cgroup file.")
			continue
		}

		n, err := strconv.ParseUint(pid.Name(), 10, 32)
		if err != nil {
			log.Warn().Err(err).Str("pid", pid.Name()).Msg("Couldn't parse pid number.")
			continue
		}
		lines := strings.Split(string(bytes), "\n")

		var cgroupPath string
		if len(lines) == 1 {
			parts := strings.Split(lines[0], ":")
			cgroupPath = parts[len(parts)-1]
		} else {
			for _, line := range lines {
				if strings.Contains(line, ":pids:") {
					parts := strings.Split(line, ":")
					cgroupPath = parts[len(parts)-1]
				}
			}
		}

		if cgroupPath == "" {
			log.Warn().Str("pid", pid.Name()).Msg(fmt.Sprintf("Cgroup path not found. Lines: %v", lines))
			continue
		}

		id := GetContainerIdFromCgroupPath(cgroupPath)
		if id == "" {
			continue
		}

		ci, ok := p.containersInfo.Get(ContainerID(id))
		if !ok {
			continue
		}

		pEvent := foundPidEvent{
			cgroup: uint64(ci.CgroupID),
			pid:    uint32(n),
		}

		p.newPidFound(&pEvent)
	}

	return nil
}

func normalyzeCgroupV2Path(path string) string {
	normalizedPath := strings.ReplaceAll(path, "../", "")
	if normalizedPath[0] == '/' {
		normalizedPath = normalizedPath[1:]
	}
	return normalizedPath
}
