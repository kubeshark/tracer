package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/go-errors/errors"
	"github.com/rs/zerolog/log"
)

type probesLibSsl struct {
	pid        uint32
	sslLibrary string
	sslHooks   sslHooks
}

type probesGoTls struct {
	pid        uint32
	exePath    string
	goGooks    goHooks
	pidOffsets []pidOffset
}

type tlsProbe interface {
	InstallProbes(procfs string, bpfObjects *tracerObjects) (bool, error)
	UninstallProbes(bpfObjects *tracerObjects) error

	Target(bpfObjects *tracerObjects) error
	Untarget(bpfObjects *tracerObjects) error
}

type podWatcher struct {
	pid       uint32
	tlsProbes []tlsProbe
}

func NewPodWatcher(procfs string, bpfObjects *tracerObjects, pid uint32) (*podWatcher, error) {
	pw := podWatcher{
		pid: pid,
		tlsProbes: []tlsProbe{
			&probesLibSsl{pid: pid},
			&probesGoTls{pid: pid},
		},
	}

	if err := pw.tryInstallProbes(procfs, bpfObjects); err != nil {
		return nil, err
	}

	if len(pw.tlsProbes) == 0 {
		return nil, nil
	}

	return &pw, nil
}

func (p *podWatcher) tryInstallProbes(procfs string, bpfObjects *tracerObjects) error {
	var activeTlsProbes []tlsProbe
	for _, probe := range p.tlsProbes {
		installed, err := probe.InstallProbes(procfs, bpfObjects)
		if err != nil {
			return err
		}
		if installed {
			activeTlsProbes = append(activeTlsProbes, probe)
		}
	}
	p.tlsProbes = activeTlsProbes
	return nil
}

func (p *podWatcher) Target(bpfObjects *tracerObjects) (err error) {
	for _, probe := range p.tlsProbes {
		if err = probe.Target(bpfObjects); err != nil {
			return
		}
	}
	return
}

func (p *podWatcher) Untarget(bpfObjects *tracerObjects) (err error) {
	for _, probe := range p.tlsProbes {
		if err = probe.Untarget(bpfObjects); err != nil {
			return
		}
	}
	return
}

func (p *podWatcher) RemoveProbes(bpfObjects *tracerObjects) (err error) {
	for _, probe := range p.tlsProbes {
		if err = probe.UninstallProbes(bpfObjects); err != nil {
			return
		}
	}
	return
}

func (p *probesLibSsl) InstallProbes(procfs string, bpfObjects *tracerObjects) (bool, error) {
	sslLibrary, err := findSsllib(procfs, p.pid)

	if err != nil {
		log.Trace().Err(err).Int("pid", int(p.pid)).Msg("PID skipped no libssl.so found:")
		return false, nil // hide the error on purpose, it's OK for a process to not use libssl.so
	} else {
		log.Info().Str("path", sslLibrary).Int("pid", int(p.pid)).Msg("Found libssl.so:")
	}
	p.sslLibrary = sslLibrary

	if err = p.sslHooks.installUprobes(bpfObjects, sslLibrary); err != nil {
		return false, err
	}

	if err := watchPidMap(bpfObjects, p.pid); err != nil {
		return false, err
	}

	log.Info().Msg(fmt.Sprintf("Watching TLS (pid: %v) (libssl: %v)", p.pid, p.sslLibrary))

	return true, nil
}

func (p *probesLibSsl) UninstallProbes(bpfObjects *tracerObjects) error {
	errs := p.sslHooks.close()

	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	if err := unwatchPidMap(bpfObjects, p.pid); err != nil {
		return err
	}

	log.Info().Msg(fmt.Sprintf("Unwatching TLS (pid: %v) (libssl: %v)", p.pid, p.sslLibrary))
	return nil
}

func (p *probesLibSsl) Target(bpfObjects *tracerObjects) error {
	if err := targetPidMap(bpfObjects, p.pid); err != nil {
		return err
	}
	log.Info().Msg(fmt.Sprintf("Targeting TLS (pid: %v) (libssl: %v)", p.pid, p.sslLibrary))
	return nil
}

func (p *probesLibSsl) Untarget(bpfObjects *tracerObjects) error {
	if err := untargetPidMap(bpfObjects, p.pid); err != nil {
		return err
	}
	log.Info().Msg(fmt.Sprintf("Untargeting TLS (pid: %v) (libssl: %v)", p.pid, p.sslLibrary))
	return nil
}

func (p *probesGoTls) InstallProbes(procfs string, bpfObjects *tracerObjects) (bool, error) {
	exePath, err := findLibraryByPid(procfs, p.pid, "")
	if err != nil {
		return false, err
	}

	p.exePath = exePath

	offsets, err := p.goGooks.installUprobes(bpfObjects, exePath)
	if err != nil {
		log.Info().Msg(fmt.Sprintf("PID skipped not a Go binary or symbol table is stripped pid: %v %v err: %v", p.pid, exePath, err))
		return false, nil // hide the error on purpose, its OK for a process to be not a Go binary or stripped Go binary
	}

	pidsInfo := bpfObjects.tracerMaps.PidsInfo

	p.pidOffsets = make([]pidOffset, 0)
	for _, ncOffset := range offsets.NetConnOffsets {
		offset := pidOffset{
			pid:    uint64(p.pid),
			offset: ncOffset.symbolOffset,
		}
		pi := pidInfo{
			sysFdOffset: ncOffset.socketSysFdOffset,
			isInterface: uint64(ncOffset.isGoInterface),
		}
		if err := pidsInfo.Put(offset, pi); err != nil {
			return false, errors.Wrap(err, 0)
		}
		p.pidOffsets = append(p.pidOffsets, offset)
	}

	if err := watchPidMap(bpfObjects, p.pid); err != nil {
		return false, err
	}

	log.Info().Msg(fmt.Sprintf("Watching TLS (pid: %v) (Go: %v)", p.pid, p.exePath))

	return true, nil
}

func (p *probesGoTls) UninstallProbes(bpfObjects *tracerObjects) error {
	pidsInfo := bpfObjects.tracerMaps.PidsInfo

	for _, offset := range p.pidOffsets {
		if err := pidsInfo.Delete(offset); err != nil {
			return errors.Wrap(err, 0)
		}
	}

	errs := p.goGooks.close()

	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	if err := unwatchPidMap(bpfObjects, p.pid); err != nil {
		return err
	}

	log.Info().Msg(fmt.Sprintf("Unwatching TLS (pid: %v) (Go: %v)", p.pid, p.exePath))
	return nil
}

func (p *probesGoTls) Target(bpfObjects *tracerObjects) error {
	if err := targetPidMap(bpfObjects, p.pid); err != nil {
		return err
	}
	log.Info().Msg(fmt.Sprintf("Targeting TLS (pid: %v) (Go: %v)", p.pid, p.exePath))

	return nil
}

func (p *probesGoTls) Untarget(bpfObjects *tracerObjects) error {
	if err := untargetPidMap(bpfObjects, p.pid); err != nil {
		return err
	}
	log.Info().Msg(fmt.Sprintf("Untargeting TLS (pid: %v) (Go: %v)", p.pid, p.exePath))

	return nil
}

func targetPidMap(bpfObjects *tracerObjects, pid uint32) error {
	return addPidToMap(bpfObjects.tracerMaps.TargetPidsMap, pid)
}
func untargetPidMap(bpfObjects *tracerObjects, pid uint32) error {
	return delPidFromMap(bpfObjects.tracerMaps.TargetPidsMap, pid)
}

func watchPidMap(bpfObjects *tracerObjects, pid uint32) error {
	return addPidToMap(bpfObjects.tracerMaps.WatchPidsMap, pid)
}
func unwatchPidMap(bpfObjects *tracerObjects, pid uint32) error {
	return delPidFromMap(bpfObjects.tracerMaps.WatchPidsMap, pid)
}

func addPidToMap(pidmap *ebpf.Map, pid uint32) error {
	if err := pidmap.Put(pid, uint32(1)); err != nil {
		return errors.Wrap(err, 0)
	}
	return nil
}

func delPidFromMap(pidmap *ebpf.Map, pid uint32) error {
	if err := pidmap.Delete(pid); err != nil {
		return errors.Wrap(err, 0)
	}
	return nil
}
