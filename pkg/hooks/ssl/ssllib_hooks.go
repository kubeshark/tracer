package ssl

import (
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
	"github.com/rs/zerolog/log"
)

type SslHooks struct {
	links []link.Link
}

// TODO: incapsulate, add devuce id to the key, delete on file is deleted
var hookInodes, _ = lru.New[uint64, uint32](16384)

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
		if err := s.installEnvoySslHooks(bpfObjects, sslLibrary); err != nil {
			return nil
		}
		log.Warn().Msgf("Trying to install envoy ssl hooks by offset")

		hash, err := hasher.ComputeFileSHA256(sslLibraryPath)
		if err != nil {
			return fmt.Errorf("fallback: sha256 failed: %w", err)
		}
		store := store.NewOffsetStore()
		if err := store.LoadOffsets(); err != nil {
			return fmt.Errorf("failed to load store: %w", err)
		}
		info, found := store.GetOffsets(hash)
		if !found {
			return fmt.Errorf("failed to find offsets for hash %s", hash)
		}

		return s.installEnvoySslHooksWithOffset(bpfObjects, sslLibrary, info)
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
	info *models.OffsetInfo,
) error {
	var err error
	var addr uint64

	if addr, err = parseOffset(info.SSLWriteOffset); err != nil {
		return err
	}

	// ENTRY SSL_write
	upWrite, err := sslLibrary.Uprobe(
		"", // no symbol lookup
		bpfObjects.BpfObjs.SslWrite,
		&link.UprobeOptions{Address: addr},
	)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, upWrite)

	// EXIT SSL_write
	urWrite, err := sslLibrary.Uretprobe(
		"",
		bpfObjects.BpfObjs.SslRetWrite,
		&link.UprobeOptions{Address: addr},
	)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, urWrite)

	if addr, err = parseOffset(info.SSLReadOffset); err != nil {
		return err
	}

	// ENTRY SSL_read
	upRead, err := sslLibrary.Uprobe(
		"",
		bpfObjects.BpfObjs.SslRead,
		&link.UprobeOptions{Address: addr},
	)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	s.links = append(s.links, upRead)

	// EXIT SSL_read
	urRead, err := sslLibrary.Uretprobe(
		"",
		bpfObjects.BpfObjs.SslRetRead,
		&link.UprobeOptions{Address: addr},
	)
	if err != nil {
		return errors.Wrap(err, 0)
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
