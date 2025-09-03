package discoverer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/cgroup"
	goHooks "github.com/kubeshark/tracer/pkg/hooks/go"
	sslHooks "github.com/kubeshark/tracer/pkg/hooks/ssl"
	"github.com/rs/zerolog/log"
)

type foundPidEvent struct {
	cgroup uint64
	pid    uint32
}

type pidInfo struct {
	cgroupId uint64
	goHook   *goHooks.GoHooks
	sslHook  *sslHooks.SslHooks
	goPath   string
	sslPath  string
}

type pids struct {
	procfs            string
	bpfObjs           *bpf.BpfObjects
	cgroupsController cgroup.CgroupsController
	readerFoundPid    *perf.Reader
	discoveredPIDs    *lru.Cache[uint32, *pidInfo]
	targetedPIDs      *lru.Cache[uint32, *pidInfo]
	targetedCgroups   *lru.Cache[uint64, struct{}]
	scanGolangQueue   chan foundPidEvent
}

func newPids(procfs string, bpfObjs *bpf.BpfObjects, cgroupsController cgroup.CgroupsController) (*pids, error) {
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
		procfs:            procfs,
		bpfObjs:           bpfObjs,
		cgroupsController: cgroupsController,
		readerFoundPid:    readerFoundPid,
		discoveredPIDs:    discoveredPids,
		targetedPIDs:      targetedPids,
		targetedCgroups:   targetedCgroups,
		scanGolangQueue:   make(chan foundPidEvent, 8192),
	}

	go p.scanPids()

	return p, nil
}

func (p *pids) targetCgroup(cgroupId uint64) {
	p.targetedCgroups.Add(cgroupId, struct{}{})
	for _, pid := range p.discoveredPIDs.Keys() {
		pi, ok := p.discoveredPIDs.Get(pid)

		if !ok || pi.cgroupId != cgroupId {
			continue
		}

		if pi.goHook == nil && pi.goPath != "" {
			ex, err := link.OpenExecutable(pi.goPath)
			if err != nil {
				// process can be already terminated
				log.Debug().Err(err).Uint32("pid", pid).Uint64("cgroup", pi.cgroupId).Msg("Open executable failed")
				continue
			}

			offsets, err := goHooks.FindGoOffsets(pi.goPath)
			if err != nil {
				continue
			}
			hook := goHooks.GoHooks{}

			err = hook.InstallHooks(p.bpfObjs, ex, offsets)
			if err != nil {
				log.Debug().Uint32("pid", pid).Uint64("cgroup", cgroupId).Msg(fmt.Sprintf("install go hook failed: %v", err))
				continue
			}
			pi.goHook = &hook

			log.Info().Uint32("pid", pid).Uint64("cgroup", pi.cgroupId).Msg("go hook installed")
		}

		if pi.sslHook == nil && pi.sslPath != "" {
			hook := sslHooks.SslHooks{}

			err := hook.InstallUprobes(p.bpfObjs, pi.sslPath)
			if err != nil {
				log.Debug().Err(err).Uint32("pid", pid).Uint64("cgroup", cgroupId).Msg("install ssl hook failed")
				continue
			}
			pi.sslHook = &hook

			log.Info().Uint32("pid", pid).Uint64("cgroup", pi.cgroupId).Msg("ssl hook installed")
		}

		p.discoveredPIDs.Add(pid, pi)
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
			log.Warn().Msg(fmt.Sprintf("Buffer is full, dropped %d pid found entry", record.LostSamples))
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
	select {
	case p.scanGolangQueue <- *pEvent:
		break
	default:
		log.Warn().Msg("PID found channel is full")
	}
}

func (p *pids) scanPids() {
	for e := range p.scanGolangQueue {
		p.installHooks(e)
	}
}

func (p *pids) installHooks(e foundPidEvent) {
	if _, ok := p.discoveredPIDs.Get(e.pid); ok {
		return
	}

	log.Debug().Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Msg("Install go hook begin")
	defer func() {
		log.Debug().Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Msg("Install go hook end")
	}()

	var sslHook *sslHooks.SslHooks
	var sslPath string
	goHook, goPath, envoyPath := p.installGoHook(e)
	if len(envoyPath) > 0 {
		sslHook = p.installEnvoysslHook(e, envoyPath)
		sslPath = envoyPath
	} else {
		sslHook, sslPath = p.installOpensslHook(e)
	}
	pi := pidInfo{
		cgroupId: e.cgroup,
		goHook:   goHook,
		sslHook:  sslHook,
		goPath:   goPath,
		sslPath:  sslPath,
	}
	p.discoveredPIDs.Add(e.pid, &pi)
}

func (p *pids) installGoHook(e foundPidEvent) (goHook *goHooks.GoHooks, goPath, envoyPath string) {
	path, err := findLibraryByPid(p.procfs, e.pid, "")
	if err != nil {
		return goHook, goPath, envoyPath
	}

	if filepath.Base(path) == "envoy" {
		envoyPath = path
	}

	ex, err := link.OpenExecutable(path)
	if err != nil {
		log.Debug().Err(err).Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Str("path", path).Msg("Open executable failed")
		return goHook, goPath, envoyPath
	}

	offsets, err := goHooks.FindGoOffsets(path)
	if err != nil {
		log.Debug().Err(err).Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Msg("find offsets failed")
		return goHook, goPath, envoyPath
	}
	log.Debug().Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Str("path", path).Msg("gotls found")
	if _, ok := p.targetedCgroups.Get(e.cgroup); !ok {
		goPath = path
		return goHook, goPath, envoyPath
	}
	hook := goHooks.GoHooks{}

	err = hook.InstallHooks(p.bpfObjs, ex, offsets)
	if err != nil {
		log.Debug().Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Msg(fmt.Sprintf("install go hook failed: %v", err))
		return goHook, goPath, envoyPath
	}

	log.Debug().Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Msg("go hook installed")
	goHook = &hook
	goPath = path
	return goHook, goPath, envoyPath
}

func (p *pids) installOpensslHook(e foundPidEvent) (*sslHooks.SslHooks, string) {
	path, err := findLibraryByPid(p.procfs, e.pid, "libssl.so")
	if err != nil {
		return nil, ""
	}

	log.Debug().Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Str("path", path).Msg("openssl found")
	if _, ok := p.targetedCgroups.Get(e.cgroup); !ok {
		return nil, path
	}

	hook := sslHooks.SslHooks{}
	err = hook.InstallUprobes(p.bpfObjs, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("Install ssl hook failed")
		return nil, ""
	}

	log.Debug().Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Msg("openssl hook installed")
	return &hook, path
}

func (p *pids) installEnvoysslHook(e foundPidEvent, path string) *sslHooks.SslHooks {
	if _, ok := p.targetedCgroups.Get(e.cgroup); !ok {
		return nil
	}

	hook := sslHooks.SslHooks{}
	err := hook.InstallUprobes(p.bpfObjs, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("Install ssl hook failed")
		return nil
	}

	log.Debug().Uint32("pid", e.pid).Uint64("cgroup", e.cgroup).Msg("openssl hook installed")
	return &hook
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
			log.Warn().Str("pid", pid.Name()).Msg(fmt.Sprintf("Couldn't parse pid number: %v", err))
			continue
		}
		lines := strings.Split(string(bytes), "\n")
		parts := strings.Split(lines[0], ":")
		cgroupPath := parts[len(parts)-1]

		for _, ci := range p.cgroupsController.GetExistingCgroupsByCgroupPath(normalyzeCgroupV2Path(cgroupPath)) {
			pEvent := foundPidEvent{
				cgroup: uint64(ci.CgroupID),
				pid:    uint32(n),
			}

			p.newPidFound(&pEvent)
		}
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
			log.Warn().Str("pid", pid.Name()).Msg(fmt.Sprintf("Couldn't parse pid number: %v", err))
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

		for _, ci := range p.cgroupsController.GetExistingCgroupsByCgroupPath(cgroupPath) {
			pEvent := foundPidEvent{
				cgroup: uint64(ci.CgroupID),
				pid:    uint32(n),
			}

			p.newPidFound(&pEvent)
		}
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
