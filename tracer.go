package main

import (
	"fmt"
	"strconv"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-errors/errors"
	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/types"
)

const GlobalWorkerPid = 0

// TODO: cilium/ebpf does not support .kconfig Therefore; for now, we build object files per kernel version.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target $BPF_TARGET -cflags $BPF_CFLAGS -type tls_chunk -type goid_offsets tracer bpf/tracer.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target $BPF_TARGET -cflags "${BPF_CFLAGS} -DKERNEL_BEFORE_4_6" -type tls_chunk -type goid_offsets tracer46 bpf/tracer.c

type Tracer struct {
	bpfObjects           tracerObjects
	syscallHooks         syscallHooks
	tcpKprobeHooks       tcpKprobeHooks
	sslHooksStructs      []sslHooks
	goHooksStructs       []goHooks
	poller               *tlsPoller
	bpfLogger            *bpfLogger
	registeredPids       sync.Map
	registeredPidOffsets sync.Map
	procfs               string
	isCgroupV2           bool
	watchingPods         map[types.UID]*podWatcher
}

// struct pid_info from maps.h
type pidInfo struct {
	sysFdOffset int64
	isInterface uint64
}

// struct fd_offset from maps.h
type pidOffset struct {
	pid    uint64
	offset uint64
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

	cgroupsVersion := "1"
	const cgroupV2MagicNumber = 0x63677270
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/cgroup/", &stat); err != nil {
		log.Error().Err(err).Msg("read cgroups information failed:")
	} else if stat.Type == cgroupV2MagicNumber {
		t.isCgroupV2 = true
		cgroupsVersion = "2"
	}

	log.Info().Msg(fmt.Sprintf("Detected Linux kernel version: %s cgroups version: %v", kernelVersion, cgroupsVersion))

	t.bpfObjects = tracerObjects{}
	// TODO: cilium/ebpf does not support .kconfig Therefore; for now, we load object files according to kernel version.
	if kernel.CompareKernelVersion(*kernelVersion, kernel.VersionInfo{Kernel: 4, Major: 6, Minor: 0}) < 1 {
		if err := loadTracer46Objects(&t.bpfObjects, nil); err != nil {
			return errors.Wrap(err, 0)
		}
	} else {
		opts := ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: ebpf.DefaultVerifierLogSize * 32,
			},
		}
		if err := loadTracerObjects(&t.bpfObjects, &opts); err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				log.Error().Msg(fmt.Sprintf("Got verifier error: %+v", ve))
			}
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

	t.bpfLogger, err = newBpfLogger(&t.bpfObjects, logBufferSize)
	if err != nil {
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

func (t *Tracer) poll(streamsMap *TcpStreamMap) {
	t.poller.poll(streamsMap)
}

func (t *Tracer) pollForLogging() {
	t.bpfLogger.poll()
}

var globalProbeSSL *probesLibSsl

func (t *Tracer) globalSSLLibTarget(procfs string, pid string) error {
	_pid, err := strconv.Atoi(pid)
	if err != nil {
		return err
	}

	globalProbeSSL = &probesLibSsl{pid: uint32(_pid)}
	installed, err := globalProbeSSL.InstallProbes(procfs, &tracer.bpfObjects)
	if err != nil {
		return err
	}
	if !installed {
		return fmt.Errorf("install global ssllib failed")
	}
	return globalProbeSSL.Target(&tracer.bpfObjects)
}

var globalProbeGoTls *probesGoTls

func (t *Tracer) globalGoTarget(procfs string, pid string) error {
	_pid, err := strconv.Atoi(pid)
	if err != nil {
		return err
	}

	globalProbeGoTls = &probesGoTls{pid: uint32(_pid)}
	installed, err := globalProbeGoTls.InstallProbes(procfs, &tracer.bpfObjects)
	if err != nil {
		return err
	}
	if !installed {
		return fmt.Errorf("install global GoTls failed")
	}
	return globalProbeSSL.Target(&tracer.bpfObjects)
}

func (t *Tracer) close() []error {
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

func logError(err error) {
	var e *errors.Error
	if errors.As(err, &e) {
		log.Error().Str("stack", e.ErrorStack()).Send()
	} else {
		log.Error().Err(err).Send()
	}
}
