package main

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/cilium/ebpf/rlimit"
	"github.com/go-errors/errors"
	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/rs/zerolog/log"
)

const GlobalWorkerPid = 0

// TODO: cilium/ebpf does not support .kconfig Therefore; for now, we build object files per kernel version.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.9.1 -target $BPF_TARGET -cflags $BPF_CFLAGS -type tls_chunk -type goid_offsets tracer bpf/tracer.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.9.1 -target $BPF_TARGET -cflags "${BPF_CFLAGS} -DKERNEL_BEFORE_4_6" -type tls_chunk -type goid_offsets tracer46 bpf/tracer.c

type Tracer struct {
	bpfObjects      tracerObjects
	syscallHooks    syscallHooks
	tcpKprobeHooks  tcpKprobeHooks
	sslHooksStructs []sslHooks
	goHooksStructs  []goHooks
	poller          *tlsPoller
	bpfLogger       *bpfLogger
	registeredPids  sync.Map
	procfs          string
}

func (t *Tracer) Init(
	chunksBufferSize int,
	logBufferSize int,
	procfs string,
) error {
	log.Info().Msg(fmt.Sprintf("Initializing tracer (chunksSize: %d) (logSize: %d)", chunksBufferSize, logBufferSize))

	var err error
	err = setupRLimit()
	if err != nil {
		return err
	}

	var kernelVersion *kernel.VersionInfo
	kernelVersion, err = kernel.GetKernelVersion()
	if err != nil {
		return err
	}

	log.Info().Msg(fmt.Sprintf("Detected Linux kernel version: %s", kernelVersion))

	t.bpfObjects = tracerObjects{}
	// TODO: cilium/ebpf does not support .kconfig Therefore; for now, we load object files according to kernel version.
	if kernel.CompareKernelVersion(*kernelVersion, kernel.VersionInfo{Kernel: 4, Major: 6, Minor: 0}) < 1 {
		if err := loadTracer46Objects(&t.bpfObjects, nil); err != nil {
			return errors.Wrap(err, 0)
		}
	} else {
		if err := loadTracerObjects(&t.bpfObjects, nil); err != nil {
			return errors.Wrap(err, 0)
		}
	}

	t.syscallHooks = syscallHooks{}
	if err := t.syscallHooks.installSyscallHooks(&t.bpfObjects); err != nil {
		return err
	}

	t.tcpKprobeHooks = tcpKprobeHooks{}
	if err := t.tcpKprobeHooks.installTcpKprobeHooks(&t.bpfObjects); err != nil {
		return err
	}

	t.sslHooksStructs = make([]sslHooks, 0)

	t.bpfLogger = newBpfLogger()
	if err := t.bpfLogger.init(&t.bpfObjects, logBufferSize); err != nil {
		return err
	}

	t.poller, err = newTlsPoller(
		t,
		procfs,
	)

	if err != nil {
		return err
	}

	return t.poller.init(&t.bpfObjects, chunksBufferSize)
}

func (t *Tracer) Poll(streamsMap *TcpStreamMap) {
	t.poller.poll(streamsMap)
}

func (t *Tracer) PollForLogging() {
	t.bpfLogger.poll()
}

func (t *Tracer) GlobalSSLLibTarget(procfs string, pid string) error {
	_pid, err := strconv.Atoi(pid)
	if err != nil {
		return err
	}

	return t.AddSSLLibPid(procfs, uint32(_pid))
}

func (t *Tracer) GlobalGoTarget(procfs string, pid string) error {
	_pid, err := strconv.Atoi(pid)
	if err != nil {
		return err
	}

	return t.targetGoPid(procfs, uint32(_pid))
}

func (t *Tracer) AddSSLLibPid(procfs string, pid uint32) error {
	sslLibrary, err := findSsllib(procfs, pid)

	if err != nil {
		log.Warn().Err(err).Int("pid", int(pid)).Msg("PID skipped no libssl.so found:")
		return nil // hide the error on purpose, it's OK for a process to not use libssl.so
	} else {
		log.Info().Str("path", sslLibrary).Int("pid", int(pid)).Msg("Found libssl.so:")
	}

	return t.targetSSLLibPid(pid, sslLibrary)
}

func (t *Tracer) AddGoPid(procfs string, pid uint32) error {
	return t.targetGoPid(procfs, pid)
}

func (t *Tracer) RemovePid(pid uint32) error {
	log.Info().Msg(fmt.Sprintf("Removing PID (pid: %v)", pid))

	pids := t.bpfObjects.tracerMaps.PidsMap

	if err := pids.Delete(pid); err != nil {
		return errors.Wrap(err, 0)
	}

	return nil
}

func (t *Tracer) ClearPids() {
	t.registeredPids.Range(func(key, v interface{}) bool {
		pid := key.(uint32)
		if pid == GlobalWorkerPid {
			return true
		}

		if err := t.RemovePid(pid); err != nil {
			LogError(err)
		}
		t.registeredPids.Delete(key)
		return true
	})
}

func (t *Tracer) Close() []error {
	returnValue := make([]error, 0)

	if err := t.bpfObjects.Close(); err != nil {
		returnValue = append(returnValue, err)
	}

	returnValue = append(returnValue, t.syscallHooks.close()...)

	returnValue = append(returnValue, t.tcpKprobeHooks.close()...)

	for _, sslHooks := range t.sslHooksStructs {
		returnValue = append(returnValue, sslHooks.close()...)
	}

	for _, goHooks := range t.goHooksStructs {
		returnValue = append(returnValue, goHooks.close()...)
	}

	if err := t.bpfLogger.close(); err != nil {
		returnValue = append(returnValue, err)
	}

	if err := t.poller.close(); err != nil {
		returnValue = append(returnValue, err)
	}

	return returnValue
}

func setupRLimit() error {
	err := rlimit.RemoveMemlock()

	if err != nil {
		return errors.New(fmt.Sprintf("%s: %v", "SYS_RESOURCE is required to change rlimits for eBPF", err))
	}

	return nil
}

func (t *Tracer) targetSSLLibPid(pid uint32, sslLibrary string) error {
	newSsl := sslHooks{}

	if err := newSsl.installUprobes(&t.bpfObjects, sslLibrary); err != nil {
		return err
	}

	log.Info().Msg(fmt.Sprintf("Targeting TLS (pid: %v) (libssl: %v)", pid, sslLibrary))

	t.sslHooksStructs = append(t.sslHooksStructs, newSsl)

	pids := t.bpfObjects.tracerMaps.PidsMap

	if err := pids.Put(pid, uint32(1)); err != nil {
		return errors.Wrap(err, 0)
	}

	t.registeredPids.Store(pid, true)

	return nil
}

func (t *Tracer) targetGoPid(procfs string, pid uint32) error {
	exePath, err := findLibraryByPid(procfs, pid, "")
	if err != nil {
		return err
	}

	hooks := goHooks{}

	if err := hooks.installUprobes(&t.bpfObjects, exePath); err != nil {
		log.Info().Msg(fmt.Sprintf("PID skipped not a Go binary or symbol table is stripped (pid: %v) %v", pid, exePath))
		return nil // hide the error on purpose, its OK for a process to be not a Go binary or stripped Go binary
	}

	log.Info().Msg(fmt.Sprintf("Targeting TLS (pid: %v) (Go: %v)", pid, exePath))

	t.goHooksStructs = append(t.goHooksStructs, hooks)

	pids := t.bpfObjects.tracerMaps.PidsMap

	if err := pids.Put(pid, uint32(1)); err != nil {
		return errors.Wrap(err, 0)
	}

	t.registeredPids.Store(pid, true)

	return nil
}

func LogError(err error) {
	var e *errors.Error
	if errors.As(err, &e) {
		log.Error().Str("stack", e.ErrorStack()).Send()
	} else {
		log.Error().Err(err).Send()
	}
}
