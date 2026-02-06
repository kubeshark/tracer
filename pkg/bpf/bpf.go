package bpf

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	PinNameFlows                 = "flows"

	TlsBackendSupportedFile      = "tracer_tls_supported"
	TlsBackendNotSupportedFile   = "tracer_tls_not_supported"
	PlainBackendSupportedFile    = "tracer_plain_supported"
	PlainBackendNotSupportedFile = "tracer_plain_not_supported"
)

var (
	ErrBpfMountFailed     = errors.New("bpf fs mount failed")
	ErrBpfOperationFailed = errors.New("bpf fs operation failed")
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target amd64 -cflags "$BPF_CFLAGS" -type tls_chunk -type goid_offsets Tracer ../../bpf/tracer.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target arm64 -cflags "$BPF_CFLAGS" -type tls_chunk -type goid_offsets Tracer ../../bpf/tracer.c

// Ringbuf variant (Linux >= 5.8).
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target amd64 -cflags "$BPF_CFLAGS -DUSE_RINGBUF" -type tls_chunk -type goid_offsets TracerRingbuf ../../bpf/tracer.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.12.3 -target arm64 -cflags "$BPF_CFLAGS -DUSE_RINGBUF" -type tls_chunk -type goid_offsets TracerRingbuf ../../bpf/tracer.c

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

	for k, v := range bpfConstants {
		if spec, exists := objs.specs.Variables[k]; exists {
			if err := spec.Set(v); err != nil {
				return err
			}
		}
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

func NewBpfObjects(procfs string, preferCgroupV1, isCgroupV2 bool, kernelVersion *kernel.VersionInfo) (pObjs *BpfObjects, tlsEnabled, plainEnabled bool, err error) {
	mounted, err := isMounted(procfs, "/sys/fs/bpf")
	if err != nil {
		return nil, false, false, fmt.Errorf("%w: mount check failed: %v", ErrBpfMountFailed, err)
	}
	if !mounted {
		return nil, false, false, fmt.Errorf("%w: /sys/fs/bpf is not mounted", ErrBpfMountFailed)
	}

	if err = os.MkdirAll(PinPath, 0o700); err != nil {
		return nil, false, false, fmt.Errorf("%w: mkdir pin path failed: %v", ErrBpfOperationFailed, err)
	}

	files, err := utils.RemoveAllFilesInDir(PinPath)
	if err != nil {
		return nil, false, false, fmt.Errorf("%w: bpf fs directory cleanup failed: %v", ErrBpfOperationFailed, err)
	}
	for _, file := range files {
		log.Debug().Str("path", file).Msg("removed bpf entry")
	}

	objs := BpfObjects{}

	pinMap := func(mapName string, mapObj *ebpf.Map) error {
		p := filepath.Join(PinPath, mapName)
		if rmErr := os.Remove(p); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return fmt.Errorf("%w: remove pinned map failed (%s): %v", ErrBpfOperationFailed, mapName, rmErr)
		}
		return mapObj.Pin(p)
	}

	pinEnabledMaps := func() error {
		if plainEnabled {
			if err := pinMap(PinNamePlainPackets, objs.BpfObjs.PktsBuffer); err != nil {
				return fmt.Errorf("%w: pin packets buffer failed: %v", ErrBpfOperationFailed, err)
			}
			if err := pinMap(PinNameFlows, objs.BpfObjs.AllFlowsStats); err != nil {
				return fmt.Errorf("%w: pin flows failed: %v", ErrBpfOperationFailed, err)
			}
		}

		if tlsEnabled {
			if err := pinMap(PinNameTLSPackets, objs.BpfObjs.ChunksBuffer); err != nil {
				return fmt.Errorf("%w: pin tls buffer failed: %v", ErrBpfOperationFailed, err)
			}
		}

		if plainEnabled || tlsEnabled {
			if err := pinMap(PinNameProgramsConfiguration, objs.BpfObjs.ProgramsConfiguration); err != nil {
				return fmt.Errorf("%w: pin programs configuration failed: %v", ErrBpfOperationFailed, err)
			}
		}

		return nil
	}

	// Kernel version int for BPF constants.
	kernelVersionInt := uint64(1_000_000)*uint64(kernelVersion.Kernel) +
		uint64(1_000)*uint64(kernelVersion.Major) +
		uint64(kernelVersion.Minor)

	// --- kernel < 4.6 special-case: TLS-only (no plain capture backend) ---
	if kernel.CompareKernelVersion(*kernelVersion, kernel.VersionInfo{Kernel: 4, Major: 6, Minor: 0}) < 1 {
		if err := LoadTracer46Objects(&objs.BpfObjs, nil); err != nil {
			return nil, false, false, fmt.Errorf("%w: load tracer 4.6 objects failed", ErrBpfOperationFailed)
		}

		tlsEnabled = true
		plainEnabled = false

		if err := pinEnabledMaps(); err != nil {
			return nil, tlsEnabled, plainEnabled, err
		}
		return &objs, tlsEnabled, plainEnabled, nil
	}

	// --- kernel >= 4.6: decide between ringbuf, perf, and fallback no-ebpf (TLS-only) ---
	// Resolve host namespace inode (best-effort).
	var procIno uint64
	if fi, statErr := os.Stat(fmt.Sprintf("%s/1/ns/pid", procfs)); statErr != nil {
		log.Warn().Err(statErr).Msg("Get host netns failed")
	} else {
		procIno = fi.Sys().(*syscall.Stat_t).Ino
		log.Info().Uint64("ns", procIno).Msg("Setting host ns")
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
		"KERNEL_VERSION":                kernelVersionInt,
		"TRACER_NS_INO":                 procIno,
		"CGROUP_V1":                     cgroupV1,
		"PREFER_CGROUP_V1_EBPF_CAPTURE": preferCgroupV1Capture,
		"HELPER_EXISTS_UPROBE_bpf_ktime_get_tai_ns": programHelperExists(ebpf.TracePoint, asm.FnKtimeGetTaiNs),
	}

	// Loaders (kept as small units; used by the candidates list below).
	loadPerf := func(dst *TracerObjects) error {
		impl := &BpfObjectsImpl{bpfObjs: dst}
		if err := impl.loadBpfObjects(bpfConsts, nil, bytes.NewReader(_TracerBytes)); err != nil {
			return fmt.Errorf("load tracer objects failed: %v", err)
		}
		return nil
	}

	loadRingbuf := func(dst *TracerObjects) error {
		tmp := &TracerRingbufObjects{}
		impl := &BpfObjectsImpl{bpfObjs: tmp}
		if err := impl.loadBpfObjects(bpfConsts, nil, bytes.NewReader(_TracerRingbufBytes)); err != nil {
			return fmt.Errorf("load tracer ringbuf objects failed: %v", err)
		}
		if err := copier.Copy(&dst.TracerPrograms, &tmp.TracerRingbufPrograms); err != nil {
			return fmt.Errorf("copy ringbuf program objects failed: %v", err)
		}
		if err := copier.Copy(&dst.TracerMaps, &tmp.TracerRingbufMaps); err != nil {
			return fmt.Errorf("copy ringbuf map objects failed: %v", err)
		}
		return nil
	}

	loadNoEbpf := func(dst *TracerObjects) error {
		tmp := &TracerNoEbpfObjects{}
		impl := &BpfObjectsImpl{bpfObjs: tmp}
		if err := impl.loadBpfObjects(bpfConsts, nil, bytes.NewReader(_TracerNoEbpfBytes)); err != nil {
			return fmt.Errorf("load tracer no-ebpf objects failed: %v", err)
		}
		if err := copier.Copy(&dst.TracerPrograms, &tmp.TracerNoEbpfPrograms); err != nil {
			return fmt.Errorf("copy no-ebpf program objects failed: %v", err)
		}
		if err := copier.Copy(&dst.TracerMaps, &tmp.TracerNoEbpfMaps); err != nil {
			return fmt.Errorf("copy no-ebpf map objects failed: %v", err)
		}
		return nil
	}

	tryRingbuf := kernel.CompareKernelVersion(*kernelVersion, kernel.VersionInfo{Kernel: 5, Major: 8, Minor: 0}) >= 0 &&
		features.HaveMapType(ebpf.RingBuf) == nil

	type candidate struct {
		name    string
		load    func(dst *TracerObjects) error
		tls     bool
		plain   bool
		skip    bool
		skipMsg string
	}

	candidates := []candidate{
		{
			name:    "ringbuf",
			load:    loadRingbuf,
			tls:     true,
			plain:   true,
			skip:    !tryRingbuf,
			skipMsg: "ringbuf not supported (kernel < 5.8 or map type unavailable)",
		},
		{
			name:  "perf",
			load:  loadPerf,
			tls:   true,
			plain: true,
		},
		{
			name:  "no-ebpf (TLS only)",
			load:  loadNoEbpf,
			tls:   true,
			plain: false,
		},
	}

	var lastErr error
	for _, c := range candidates {
		if c.skip {
			log.Debug().Str("backend", c.name).Msg(c.skipMsg)
			continue
		}

		// Reset objects each attempt to avoid partial state.
		objs = BpfObjects{}
		tlsEnabled = false
		plainEnabled = false

		log.Info().Str("backend", c.name).Msg("Attempting to load tracer backend")
		if err := c.load(&objs.BpfObjs); err != nil {
			lastErr = err
			log.Warn().Err(err).Str("backend", c.name).Msg("Tracer backend load failed")
			continue
		}

		plainEnabled = c.plain
		tlsEnabled = c.tls

		if err := pinEnabledMaps(); err != nil {
			return nil, tlsEnabled, plainEnabled, err
		}

		log.Info().
			Str("backend", c.name).
			Bool("plain_enabled", plainEnabled).
			Bool("tls_enabled", tlsEnabled).
			Msg("Tracer backend loaded successfully")

		return &objs, tlsEnabled, plainEnabled, nil
	}

	if lastErr != nil {
		return nil, false, false, fmt.Errorf("%w: load tracer objects failed: %v", ErrBpfOperationFailed, lastErr)
	}
	return nil, false, false, fmt.Errorf("%w: load tracer objects failed", ErrBpfOperationFailed)
}

func isMounted(procfs string, target string) (bool, error) {
	file, err := os.Open(fmt.Sprintf("%s/mounts", procfs))
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
