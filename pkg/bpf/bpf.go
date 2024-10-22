package bpf

import (
	"fmt"

	"bytes"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/go-errors/errors"
	"github.com/kubeshark/tracer/pkg/utils"
	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/rs/zerolog/log"
)

// TODO: cilium/ebpf does not support .kconfig Therefore; for now, we build object files per kernel version.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target $BPF_TARGET -cflags $BPF_CFLAGS -type tls_chunk -type goid_offsets Tracer ../../bpf/tracer.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target $BPF_TARGET -cflags "${BPF_CFLAGS} -DKERNEL_BEFORE_4_6" -type tls_chunk -type goid_offsets Tracer46 ../../bpf/tracer.c

type BpfObjectsImpl struct {
	bpfObjs interface{}
	specs   *ebpf.CollectionSpec
}

func (objs *BpfObjectsImpl) loadBpfObjects(bpfConstants map[string]uint64, reader *bytes.Reader) error {
	var err error

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

	err = objs.specs.LoadAndAssign(objs.bpfObjs, nil)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			errStr := fmt.Sprintf("%+v", ve)
			if len(errStr) > 2048 {
				//XXX errStr = "(truncated) " + errStr[len(errStr)-1024:]
			}
			log.Warn().Msg(fmt.Sprintf("Got verifier error: %v", errStr))
		}
	}
	return err
}

type BpfObjects struct {
	BpfObjs    TracerObjects
	IsCgroupV2 bool
}

func programHelperExists(pt ebpf.ProgramType, helper asm.BuiltinFunc) uint64 {
	if features.HaveProgramHelper(pt, helper) == nil {
		return 1
	}
	return 0
}

func NewBpfObjects(disableEbpfCapture bool) (*BpfObjects, error) {
	var err error

	objs := BpfObjects{}

	var kernelVersion *kernel.VersionInfo
	kernelVersion, err = kernel.GetKernelVersion()
	if err != nil {
		return nil, err
	}

	cgroupV1 := uint64(1)
	objs.IsCgroupV2, err = utils.IsCgroupV2()
	if err != nil {
		log.Error().Err(err).Msg("read cgroups information failed:")
	}
	if objs.IsCgroupV2 {
		cgroupV1 = 0
	}

	log.Info().Msg(fmt.Sprintf("Detected Linux kernel version: %s cgroups version2: %v", kernelVersion, objs.IsCgroupV2))
	kernelVersionInt := uint64(1_000_000)*uint64(kernelVersion.Kernel) + uint64(1_000)*uint64(kernelVersion.Major) + uint64(kernelVersion.Minor)

	// TODO: cilium/ebpf does not support .kconfig Therefore; for now, we load object files according to kernel version.
	if kernel.CompareKernelVersion(*kernelVersion, kernel.VersionInfo{Kernel: 4, Major: 6, Minor: 0}) < 1 {
		if err := LoadTracer46Objects(&objs.BpfObjs, nil); err != nil {
			return nil, errors.Wrap(err, 0)
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

		objects := &BpfObjectsImpl{
			bpfObjs: &TracerObjects{},
		}

		disableCapture := uint64(0)
		if disableEbpfCapture {
			disableCapture = 1
		}

		bpfConsts := map[string]uint64{
			"KERNEL_VERSION": kernelVersionInt,
			"TRACER_NS_INO":  hostProcIno,
			//"HELPER_EXISTS_KPROBE_bpf_strncmp":          programHelperExists(ebpf.Kprobe, asm.FnStrncmp),
			"CGROUP_V1": cgroupV1,
			"HELPER_EXISTS_UPROBE_bpf_ktime_get_tai_ns": programHelperExists(ebpf.TracePoint, asm.FnKtimeGetTaiNs),
			"DISABLE_EBPF_CAPTURE":                      disableCapture,
		}

		err = objects.loadBpfObjects(bpfConsts, bytes.NewReader(_TracerBytes))
		if err == nil {
			objs.BpfObjs = *objects.bpfObjs.(*TracerObjects)
		}

		if err != nil {
			log.Error().Msg(fmt.Sprintf("load bpf objects failed: %v", err))
			return nil, err
		}
	}

	return &objs, nil
}
