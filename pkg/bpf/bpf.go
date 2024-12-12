package bpf

import (
	"fmt"
	"path/filepath"
	"strings"

	"bytes"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/go-errors/errors"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/utils"
	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/rs/zerolog/log"
)

const (
	PinPath             = "/sys/fs/bpf/kubeshark"
	PinNamePlainPackets = "packets_plain"
	PinNameTLSPackets   = "packets_tls"
)

// TODO: cilium/ebpf does not support .kconfig Therefore; for now, we build object files per kernel version.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target amd64 -cflags $BPF_CFLAGS -type tls_chunk -type goid_offsets Tracer ../../bpf/tracer.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target arm64 -cflags $BPF_CFLAGS -type tls_chunk -type goid_offsets Tracer ../../bpf/tracer.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target amd64 -cflags "${BPF_CFLAGS} -DKERNEL_BEFORE_4_6" -type tls_chunk -type goid_offsets Tracer46 ../../bpf/tracer.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target arm64 -cflags "${BPF_CFLAGS} -DKERNEL_BEFORE_4_6" -type tls_chunk -type goid_offsets Tracer46 ../../bpf/tracer.c

type BpfObjectsImpl struct {
	bpfObjs interface{}
	specs   *ebpf.CollectionSpec
}

func (objs *BpfObjectsImpl) loadBpfObjects(bpfConstants map[string]uint64, mapReplacements map[string]*ebpf.Map, reader *bytes.Reader) error {
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

	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}
	err = objs.specs.LoadAndAssign(objs.bpfObjs, &opts)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			errStr := fmt.Sprintf("%+v", ve)
			if len(errStr) > 2048 {
				errStr = "(truncated) " + errStr[len(errStr)-1024:]
			}
			log.Warn().Msg(fmt.Sprintf("Got verifier error: %v", errStr))
		}
	}
	return err
}

type BpfObjects struct {
	BpfObjs TracerObjects
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
	isCgroupV2, err := utils.IsCgroupV2()
	if err != nil {
		log.Error().Err(err).Msg("read cgroups information failed:")
	}
	if isCgroupV2 {
		cgroupV1 = 0
	}

	mapReplacements := make(map[string]*ebpf.Map)
	plainPath := filepath.Join(PinPath, PinNamePlainPackets)
	tlsPath := filepath.Join(PinPath, PinNameTLSPackets)

	if !kernel.CheckKernelVersion(5, 4, 0) {
		disableEbpfCapture = true
	}

	markDisabledEBPF := func() error {
		pathNoEbpf := filepath.Join(misc.GetDataDir(), "noebpf")
		file, err := os.Create(pathNoEbpf)
		if err != nil {
			return err
		}
		file.Close()
		return nil
	}

	ebpfBackendStatus := "enabled"
	if disableEbpfCapture {
		ebpfBackendStatus = "disabled"
		if err = markDisabledEBPF(); err != nil {
			return nil, err
		}
	}

	log.Info().Msg(fmt.Sprintf("Detected Linux kernel version: %s cgroups version2: %v, eBPF backend %v", kernelVersion, isCgroupV2, ebpfBackendStatus))
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

		pktsBuffer, err := ebpf.LoadPinnedMap(plainPath, nil)
		if err == nil {
			mapReplacements["pkts_buffer"] = pktsBuffer
			log.Info().Str("path", tlsPath).Msg("loaded plain packets buffer")
		} else if !errors.Is(err, os.ErrNotExist) {
			log.Error().Msg(fmt.Sprintf("load plain packets map failed: %v", err))
		}

		chunksBuffer, err := ebpf.LoadPinnedMap(tlsPath, nil)
		if err == nil {
			mapReplacements["chunks_buffer"] = chunksBuffer
			log.Info().Str("path", tlsPath).Msg("loaded tls packets buffer")
		} else if !errors.Is(err, os.ErrNotExist) {
			log.Error().Msg(fmt.Sprintf("load tls packets map failed: %v", err))
		}

		err = objects.loadBpfObjects(bpfConsts, mapReplacements, bytes.NewReader(_TracerBytes))
		if err == nil {
			objs.BpfObjs = *objects.bpfObjs.(*TracerObjects)
		} else if err != nil {
			log.Error().Msg(fmt.Sprintf("load bpf objects failed: %v", err))
			return nil, err
		}
	}

	// Pin packet perf maps:

	defer func() {
		if os.IsPermission(err) || strings.Contains(fmt.Sprintf("%v", err), "permission") {
			log.Warn().Msg(fmt.Sprintf("There are no enough permissions to activate eBPF. Error: %v", err))
			if err = markDisabledEBPF(); err != nil {
				log.Error().Err(err).Msg("disable ebpf failed")
			} else {
				err = nil
			}
		}
	}()

	if err = os.MkdirAll(PinPath, 0700); err != nil {
		log.Error().Msg(fmt.Sprintf("mkdir pin path failed: %v", err))
		return nil, err
	}

	pinMap := func(mapName, path string, mapObj *ebpf.Map) error {
		if _, ok := mapReplacements[mapName]; !ok {
			if err = mapObj.Pin(path); err != nil {
				log.Error().Err(err).Str("path", path).Msg("pin perf buffer failed")
				return err
			} else {
				log.Info().Str("path", path).Msg("pinned perf buffer")
			}
		}
		return nil
	}

	if !disableEbpfCapture {
		if err = pinMap("pkts_buffer", plainPath, objs.BpfObjs.PktsBuffer); err != nil {
			return nil, err
		}
	}

	if err = pinMap("chunks_buffer", tlsPath, objs.BpfObjs.ChunksBuffer); err != nil {
		return nil, err
	}

	return &objs, nil
}
