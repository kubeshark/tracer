package main

import (
	"fmt"

	"bytes"
	"os"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-errors/errors"
	"github.com/jinzhu/copier"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/socket"
	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/types"
)

const GlobalWorkerPid = 0

// TODO: cilium/ebpf does not support .kconfig Therefore; for now, we build object files per kernel version.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target $BPF_TARGET -cflags $BPF_CFLAGS -type tls_chunk -type goid_offsets tracer bpf/tracer.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target $BPF_TARGET -cflags "${BPF_CFLAGS} -DEBPF_FALLBACK" -type tls_chunk -type goid_offsets tracerNoSniff bpf/tracer.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target $BPF_TARGET -cflags "${BPF_CFLAGS} -DKERNEL_BEFORE_4_6" -type tls_chunk -type goid_offsets tracer46 bpf/tracer.c

type Tracer struct {
	bpfObjects        tracerObjects
	syscallHooks      syscallHooks
	tcpKprobeHooks    tcpKprobeHooks
	sslHooksStructs   []sslHooks
	goHooksStructs    []goHooks
	poller            *tlsPoller
	pktsPoller        *pktsPoller
	bpfLogger         *bpfLogger
	packetFilter      *packetFilter
	procfs            string
	isCgroupV2        bool
	pktSnifDisabled   bool
	watchingPods      map[types.UID]*watchingPodsInfo
	targetedCgroupIDs map[uint64]struct{}
}

type watchingPodsInfo struct {
	tlsPids   []*pidWatcher
	cgroupIDs []uint64
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

type BpfObjectsImpl struct {
	bpfObjs interface{}
	specs   *ebpf.CollectionSpec
}

func (objs *BpfObjectsImpl) loadBpfObjects(bpfConstants map[string]uint64, reader *bytes.Reader) error {
	var err error
	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize * 32,
		},
	}

	objs.specs, err = ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return err
	}

	consts := make(map[string]interface{})
	for k, v := range bpfConstants {
		consts[k] = v
	}
	err = objs.specs.RewriteConstants(consts)
	if err != nil {
		return err
	}

	err = objs.specs.LoadAndAssign(objs.bpfObjs, &opts)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			errStr := fmt.Sprintf("%+v", ve)
			if len(errStr) > 1024 {
				errStr = "(truncated) " + errStr[len(errStr)-1024:]
			}
			log.Warn().Msg(fmt.Sprintf("Got verifier error: %v", errStr))
		}
	}
	return err
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

	t.isCgroupV2, err = isCgroupV2()
	if err != nil {
		log.Error().Err(err).Msg("read cgroups information failed:")
	}

	log.Info().Msg(fmt.Sprintf("Detected Linux kernel version: %s cgroups version2: %v", kernelVersion, t.isCgroupV2))

	t.bpfObjects = tracerObjects{}
	// TODO: cilium/ebpf does not support .kconfig Therefore; for now, we load object files according to kernel version.
	if kernel.CompareKernelVersion(*kernelVersion, kernel.VersionInfo{Kernel: 4, Major: 6, Minor: 0}) < 1 {
		if err := loadTracer46Objects(&t.bpfObjects, nil); err != nil {
			return errors.Wrap(err, 0)
		}
	} else {
		var hostProcIno uint64
		fileInfo, err := os.Stat("/hostproc/1/ns/pid")
		if err != nil {
			// services like "apparmor" on EKS can reject access to system pid information
			log.Warn().Err(err).Msg("Get host netns failed")
		} else {
			hostProcIno = fileInfo.Sys().(*syscall.Stat_t).Ino
			log.Info().Uint64("ns", hostProcIno).Msg("Setting host ns")
		}

		objs := &BpfObjectsImpl{
			bpfObjs: &tracerObjects{},
		}

		bpfConsts := map[string]uint64{
			"TRACER_NS_INO": hostProcIno,
		}

		var ve *ebpf.VerifierError
		err = objs.loadBpfObjects(bpfConsts, bytes.NewReader(_TracerBytes))
		if err == nil {
			t.bpfObjects = *objs.bpfObjs.(*tracerObjects)
		} else if err != nil && errors.As(err, &ve) {
			t.pktSnifDisabled = true
			CompatibleMode = true
			log.Warn().Msg(fmt.Sprintf("eBPF packets capture and syscall events are disabled"))

			objsNoSniff := &BpfObjectsImpl{
				bpfObjs: &tracerNoSniffObjects{},
			}
			err = objsNoSniff.loadBpfObjects(bpfConsts, bytes.NewReader(_TracerNoSniffBytes))

			if err == nil {
				o := objsNoSniff.bpfObjs.(*tracerNoSniffObjects)
				if err = copier.Copy(&t.bpfObjects.tracerPrograms, &o.tracerNoSniffPrograms); err != nil {
					return err
				}
				if err = copier.Copy(&t.bpfObjects.tracerMaps, &o.tracerNoSniffMaps); err != nil {
					return err
				}
			}
		}

		if err != nil {
			log.Error().Msg(fmt.Sprintf("load bpf objects failed: %v", err))
			return err
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

	t.bpfLogger, err = newBpfLogger(&t.bpfObjects, logBufferSize, *disableTlsLog)
	if err != nil {
		return err
	}

	sortedPackets := make(chan *SortedPacket, misc.PacketChannelBufferSize)
	sorter := NewPacketSorter(sortedPackets, t.isCgroupV2)

	t.poller, err = newTlsPoller(
		t,
		procfs,
		sorter,
	)

	if err != nil {
		return err
	}

	err = t.poller.init(&t.bpfObjects, chunksBufferSize)
	if err != nil {
		return err
	}

	if !*disableEbpfCapture && t.isCgroupV2 && !t.pktSnifDisabled {
		t.packetFilter, err = newPacketFilter(t.bpfObjects.FilterIngressPackets, t.bpfObjects.FilterEgressPackets, t.bpfObjects.PacketPullIngress, t.bpfObjects.PacketPullEgress, t.bpfObjects.TraceCgroupConnect4, t.bpfObjects.CgroupIds)
		if err != nil {
			return err
		}

		t.pktsPoller, err = newPktsPoller(t, procfs, sorter)
		if err != nil {
			return err
		}

		err = t.pktsPoller.init(&t.bpfObjects, chunksBufferSize)
		if err != nil {
			return err
		}
	}

	if !CompatibleMode {
		syscallEventsTracer, err := newSyscallEventsTracer(t.bpfObjects.SyscallEvents, os.Getpagesize(), socket.NewSocketEvent(misc.GetSyscallEventSocketPath()))
		if err != nil {
			log.Error().Err(err).Msg("Syscall events tracer create failed")
		} else {
			if err = syscallEventsTracer.start(); err != nil {
				log.Error().Err(err).Msg("Syscall events tracer start failed")
			}
		}
	}
	return nil
}

func (t *Tracer) checkCgroupID(cID uint64) bool {
	_, ok := t.targetedCgroupIDs[cID]
	return ok
}

func (t *Tracer) poll(streamsMap *TcpStreamMap) {
	if t.pktsPoller != nil {
		go t.pktsPoller.poll()
	}
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
	if t.packetFilter != nil {
		t.packetFilter.close()
	}

	if t.pktsPoller != nil {
		t.pktsPoller.close()
	}

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
