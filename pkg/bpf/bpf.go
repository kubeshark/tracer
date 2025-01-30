package bpf

import (
	"bufio"
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
	"github.com/jinzhu/copier"
	"github.com/kubeshark/tracer/pkg/utils"
	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/rs/zerolog/log"
)

const (
	PinPath                      = "/sys/fs/bpf/kubeshark"
	PinNamePlainPackets          = "packets_plain"
	PinNameTLSPackets            = "packets_tls"
	PinNameProgramsConfiguration = "progs_config"

	TlsBackendSupportedFile      = "tracer_tls_supported"
	TlsBackendNotSupportedFile   = "tracer_tls_not_supported"
	PlainBackendSupportedFile    = "tracer_plain_supported"
	PlainBackendNotSupportedFile = "tracer_plain_not_supported"
)

var (
	ErrBpfMountFailed     = errors.New("bpf fs mount failed")
	ErrBpfOperationFailed = errors.New("bpf fs operation failed")
)

// TODO: cilium/ebpf does not support .kconfig Therefore; for now, we build object files per kernel version.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target amd64 -cflags "$BPF_CFLAGS" -type tls_chunk -type goid_offsets Tracer ../../bpf/tracer.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target arm64 -cflags "$BPF_CFLAGS" -type tls_chunk -type goid_offsets Tracer ../../bpf/tracer.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target amd64 -cflags "$BPF_CFLAGS -DDISABLE_EBPF_CAPTURE_BACKEND" -type tls_chunk -type goid_offsets TracerNoEbpf ../../bpf/tracer.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target arm64 -cflags "$BPF_CFLAGS -DDISABLE_EBPF_CAPTURE_BACKEND" -type tls_chunk -type goid_offsets TracerNoEbpf ../../bpf/tracer.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target amd64 -cflags "${BPF_CFLAGS} -DKERNEL_BEFORE_4_6 -DDISABLE_EBPF_CAPTURE_BACKEND" -type tls_chunk -type goid_offsets Tracer46 ../../bpf/tracer.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target arm64 -cflags "${BPF_CFLAGS} -DKERNEL_BEFORE_4_6 -DDISABLE_EBPF_CAPTURE_BACKEND" -type tls_chunk -type goid_offsets Tracer46 ../../bpf/tracer.c

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
	BpfObjs              TracerObjects
	DisabledPlainBackend bool
	DisabledTlsBackend   bool
}

func programHelperExists(pt ebpf.ProgramType, helper asm.BuiltinFunc) uint64 {
	if features.HaveProgramHelper(pt, helper) == nil {
		return 1
	}
	return 0
}

func NewBpfObjects(preferCgroupV1, isCgroupV2 bool, kernelVersion *kernel.VersionInfo) (pObjs *BpfObjects, tlsEnabled, plainEnabled bool, err error) {
	var mounted bool
	mounted, err = isMounted("/sys/fs/bpf")
	if err != nil {
		err = fmt.Errorf("%w: mount check failed: %v", ErrBpfMountFailed, err)
		return
	}
	if !mounted {
		err = fmt.Errorf("%w: /sys/fs/bpf is not mounted", ErrBpfMountFailed)
		return
	}

	if err = os.MkdirAll(PinPath, 0700); err != nil {
		err = fmt.Errorf("%w: mkdir pin path failed: %v", ErrBpfOperationFailed, err)
		return
	}

	var files []string
	if files, err = utils.RemoveAllFilesInDir(PinPath); err != nil {
		err = fmt.Errorf("%w: bpf fs directory cleanup failed: %v", ErrBpfOperationFailed, err)
		return
	} else {
		for _, file := range files {
			log.Debug().Str("path", file).Msg("removed bpf entry")
		}
	}

	objs := BpfObjects{}

	var errLoadPlain error
	var errLoadTls error

	pinMap := func(mapName string, mapObj *ebpf.Map) error {
		if err = mapObj.Pin(filepath.Join(PinPath, mapName)); err != nil {
			return err
		}
		return nil
	}

	defer func() {

		if errLoadPlain != nil {
			log.Warn().Msg(fmt.Sprintf("eBPF plain load error: %v", errLoadPlain))
		}

		if errLoadTls != nil {
			log.Warn().Msg(fmt.Sprintf("eBPF tls load error: %v", errLoadTls))
		}
	}()

	kernelVersionInt := uint64(1_000_000)*uint64(kernelVersion.Kernel) + uint64(1_000)*uint64(kernelVersion.Major) + uint64(kernelVersion.Minor)

	// TODO: cilium/ebpf does not support .kconfig Therefore; for now, we load object files according to kernel version.
	if kernel.CompareKernelVersion(*kernelVersion, kernel.VersionInfo{Kernel: 4, Major: 6, Minor: 0}) < 1 {
		if errLoadTls = LoadTracer46Objects(&objs.BpfObjs, nil); errLoadTls == nil {
			tlsEnabled = true
		} else {
			err = fmt.Errorf("%w: load tracer 4.6 objects failed", ErrBpfOperationFailed)
			return
		}
	} else {
		var hostProcIno uint64
		var fileInfo os.FileInfo
		fileInfo, err = os.Stat("/hostproc/1/ns/pid")
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

		objectsNoEbpf := &BpfObjectsImpl{
			bpfObjs: &TracerNoEbpfObjects{},
		}

		preferCgroupV1Capture := uint64(0)
		if preferCgroupV1 {
			preferCgroupV1Capture = 1
		}

		cgroupV1 := uint64(1)
		if isCgroupV2 {
			cgroupV1 = 0
		}
		bpfConsts := map[string]uint64{
			"KERNEL_VERSION": kernelVersionInt,
			"TRACER_NS_INO":  hostProcIno,
			//"HELPER_EXISTS_KPROBE_bpf_strncmp":          programHelperExists(ebpf.Kprobe, asm.FnStrncmp),
			"CGROUP_V1":                                 cgroupV1,
			"PREFER_CGROUP_V1_EBPF_CAPTURE":             preferCgroupV1Capture,
			"HELPER_EXISTS_UPROBE_bpf_ktime_get_tai_ns": programHelperExists(ebpf.TracePoint, asm.FnKtimeGetTaiNs),
		}

		loadTracer := func(obj *TracerObjects) (err error) {
			if err = objects.loadBpfObjects(bpfConsts, nil, bytes.NewReader(_TracerBytes)); err != nil {
				err = fmt.Errorf("load tracer objects failed: %v", err)
				return
			}
			*obj = *objects.bpfObjs.(*TracerObjects)
			return
		}

		loadTracerNoEbpf := func(obj *TracerObjects) (err error) {
			if err = objectsNoEbpf.loadBpfObjects(bpfConsts, nil, bytes.NewReader(_TracerNoEbpfBytes)); err != nil {
				err = fmt.Errorf("load tracer noBpf objects failed: %v", err)
				return
			}

			o := objectsNoEbpf.bpfObjs.(*TracerNoEbpfObjects)
			if err = copier.Copy(&obj.TracerPrograms, &o.TracerNoEbpfPrograms); err != nil {
				err = fmt.Errorf("copy program objects failed: %v", err)
				return
			}
			if err = copier.Copy(&obj.TracerMaps, &o.TracerNoEbpfMaps); err != nil {
				err = fmt.Errorf("copy map objects failed: %v", err)
				return
			}
			return
		}

		if errLoadPlain = loadTracer(&objs.BpfObjs); errLoadPlain != nil {
			objs = BpfObjects{}
			if errLoadTls = loadTracerNoEbpf(&objs.BpfObjs); errLoadTls == nil {
				tlsEnabled = true
			} else {
				err = fmt.Errorf("%w: load tracer objects failed", ErrBpfOperationFailed)
				return
			}
		} else {
			plainEnabled = true
			tlsEnabled = true
		}
	}

	if plainEnabled {
		if err = pinMap(PinNamePlainPackets, objs.BpfObjs.PktsBuffer); err != nil {
			err = fmt.Errorf("%w: pin packets buffer failed: %v", ErrBpfOperationFailed, err)
			return
		}
	}

	if tlsEnabled {
		if err = pinMap(PinNameTLSPackets, objs.BpfObjs.ChunksBuffer); err != nil {
			err = fmt.Errorf("%w: pin tls buffer failed: %v", ErrBpfOperationFailed, err)
			return
		}
	}

	if plainEnabled || tlsEnabled {
		if err = pinMap(PinNameProgramsConfiguration, objs.BpfObjs.ProgramsConfiguration); err != nil {
			err = fmt.Errorf("%w: pin programs configuration failed: %v", ErrBpfOperationFailed, err)
			return
		}
	}

	pObjs = &objs
	return
}

func isMounted(target string) (bool, error) {
	file, err := os.Open("/hostproc/mounts")
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		mountPoint := fields[1]
		if mountPoint == target {
			return true, nil
		}
	}
	return false, scanner.Err()
}
