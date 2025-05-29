package ssl

import (
	"debug/elf"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf/link"
	"github.com/go-errors/errors"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/kubeshark/offsetdb/hasher"
	"github.com/kubeshark/offsetdb/models"
	"github.com/kubeshark/offsetdb/store"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/utils"
)

const (
	offsetdb = "/app/offsets.json"
)

var offStore = store.NewOffsetStore()

type SslHooks struct {
	links []link.Link
}

// TODO: incapsulate, add devuce id to the key, delete on file is deleted
var hookInodes, _ = lru.New[uint64, uint32](16384)

func init() {
	if err := offStore.LoadOffsets(offsetdb); err != nil {
		panic(err)
	}
}

func (s *SslHooks) InstallUprobes(bpfObjects *bpf.BpfObjects, sslLibraryPath string) error {
	var isEnvoy bool
	if filepath.Base(sslLibraryPath) == "envoy" {
		isEnvoy = true
	}

	ino, err := utils.GetInode(sslLibraryPath)
	if err != nil {
		return err
	}
	if ok, _ := hookInodes.ContainsOrAdd(ino, 0); ok {
		return nil
	}

	sslLibrary, err := link.OpenExecutable(sslLibraryPath)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	if isEnvoy {
		// Compute the has of the binary
		hash, err := hasher.ComputeFileSHA256(sslLibraryPath)
		if err != nil {
			return fmt.Errorf("fallback: sha256 failed: %w", err)
		}

		// Check if the hash is in the offset store
		info, found := offStore.GetOffsets(hash)
		if !found {
			// Try to install the hooks by symbols
			return s.installEnvoySslHooks(bpfObjects, sslLibrary)
		}

		return s.installEnvoySslHooksWithOffset(bpfObjects, sslLibrary, sslLibraryPath, info)
	}

	return s.installSslHooks(bpfObjects, sslLibrary)
}

func (s *SslHooks) installSslHooks(bpfObjects *bpf.BpfObjects, sslLibrary *link.Executable) error {
	var err error
	sslWriteProbe, err := sslLibrary.Uprobe("SSL_write", bpfObjects.BpfObjs.SslWrite, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslWriteProbe)

	sslWriteRetProbe, err := sslLibrary.Uretprobe("SSL_write", bpfObjects.BpfObjs.SslRetWrite, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslWriteRetProbe)

	sslReadProbe, err := sslLibrary.Uprobe("SSL_read", bpfObjects.BpfObjs.SslRead, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslReadProbe)

	sslReadRetProbe, err := sslLibrary.Uretprobe("SSL_read", bpfObjects.BpfObjs.SslRetRead, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslReadRetProbe)

	sslWriteExProbe, err := sslLibrary.Uprobe("SSL_write_ex", bpfObjects.BpfObjs.SslWriteEx, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslWriteExProbe)

	sslWriteExRetProbe, err := sslLibrary.Uretprobe("SSL_write_ex", bpfObjects.BpfObjs.SslRetWriteEx, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslWriteExRetProbe)

	sslReadExProbe, err := sslLibrary.Uprobe("SSL_read_ex", bpfObjects.BpfObjs.SslReadEx, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslReadExProbe)

	sslReadExRetProbe, err := sslLibrary.Uretprobe("SSL_read_ex", bpfObjects.BpfObjs.SslRetReadEx, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslReadExRetProbe)

	sslPendingProbe, err := sslLibrary.Uprobe("SSL_pending", bpfObjects.BpfObjs.SslPending, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslPendingProbe)

	return nil
}

func (s *SslHooks) installEnvoySslHooks(bpfObjects *bpf.BpfObjects, sslLibrary *link.Executable) error {
	var err error

	sslWriteProbe, err := sslLibrary.Uprobe("SSL_write", bpfObjects.BpfObjs.SslWrite, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslWriteProbe)

	sslWriteRetProbe, err := sslLibrary.Uretprobe("SSL_write", bpfObjects.BpfObjs.SslRetWrite, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslWriteRetProbe)

	sslReadProbe, err := sslLibrary.Uprobe("SSL_read", bpfObjects.BpfObjs.SslRead, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslReadProbe)

	sslReadRetProbe, err := sslLibrary.Uretprobe("SSL_read", bpfObjects.BpfObjs.SslRetRead, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, sslReadRetProbe)

	return nil
}

func (s *SslHooks) Close() []error {
	returnValue := make([]error, 0)

	for _, l := range s.links {
		if err := l.Close(); err != nil {
			returnValue = append(returnValue, err)
		}
	}
	s.links = []link.Link{}

	return returnValue
}

func (s *SslHooks) installEnvoySslHooksWithOffset(
	bpfObjects *bpf.BpfObjects,
	sslLibrary *link.Executable,
	sslLibraryPath string,
	info *models.OffsetInfo,
) error {
	var err error
	var relativeOffset, baseOffset, absoluteOffset uint64

	baseOffset, err = findStrippedExecutableSegmentOffset(sslLibraryPath)
	if err != nil {
		return fmt.Errorf("failed to find base offset in SSL library '%s': %w", sslLibraryPath, err)
	}

	// --- SSL_write ---
	if relativeOffset, err = parseOffset(info.SSLWriteOffset); err != nil {
		return fmt.Errorf("parsing SSLWriteOffset: %w", err)
	}
	absoluteOffset = baseOffset + relativeOffset

	// ENTRY SSL_write
	upWrite, err := sslLibrary.Uprobe(
		"",
		bpfObjects.BpfObjs.SslWrite,
		&link.UprobeOptions{Address: absoluteOffset},
	)
	if err != nil {
		return fmt.Errorf("attaching SSL_write uprobe at offset 0x%x : %w", absoluteOffset, err)
	}
	s.links = append(s.links, upWrite)

	// EXIT SSL_write (uses the same address as the entry)
	urWrite, err := sslLibrary.Uretprobe(
		"",
		bpfObjects.BpfObjs.SslRetWrite,
		&link.UprobeOptions{Address: absoluteOffset},
	)
	if err != nil {
		return fmt.Errorf("attaching SSL_write uretprobe at offset 0x%x : %w", absoluteOffset, err)
	}
	s.links = append(s.links, urWrite)

	// --- SSL_read ---
	if relativeOffset, err = parseOffset(info.SSLReadOffset); err != nil {
		return fmt.Errorf("parsing SSLReadOffset: %w", err)
	}
	absoluteOffset = baseOffset + relativeOffset

	// ENTRY SSL_read
	upRead, err := sslLibrary.Uprobe(
		"",
		bpfObjects.BpfObjs.SslRead,
		&link.UprobeOptions{Address: absoluteOffset},
	)
	if err != nil {
		return fmt.Errorf("attaching SSL_read uprobe at offset 0x%x : %w", absoluteOffset, err)
	}
	s.links = append(s.links, upRead)

	// EXIT SSL_read (uses the same address as the entry)
	urRead, err := sslLibrary.Uretprobe(
		"",
		bpfObjects.BpfObjs.SslRetRead,
		&link.UprobeOptions{Address: absoluteOffset},
	)
	if err != nil {
		return fmt.Errorf("attaching SSL_read uretprobe at offset 0x%x : %w", absoluteOffset, err)
	}
	s.links = append(s.links, urRead)

	return nil
}

// parseOffset turns a hex- or dec-formatted string into a uint64
func parseOffset(s string) (uint64, error) {
	// Let strconv auto-detect the base from “0x…” prefix or plain digits
	val, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid offset %q: %w", s, err)
	}
	return val, nil
}

// findStrippedExecutableSegmentOffset finds the file offset of the first executable segment
// or the .text section in an ELF file.
func findStrippedExecutableSegmentOffset(path string) (uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, fmt.Errorf("elf.Open %s: %w", path, err)
	}
	defer f.Close()

	// Prefer .text section offset when available
	if sec := f.Section(".text"); sec != nil && sec.Offset != 0 {
		return sec.Offset, nil
	}

	// Otherwise, pick the first executable PT_LOAD
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD && (prog.Flags&elf.PF_X) != 0 {
			return prog.Off, nil
		}
	}
	return 0, errors.New("no executable segment or .text section found")
}
