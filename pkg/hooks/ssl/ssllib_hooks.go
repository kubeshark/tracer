package ssl

import (
	"path/filepath"

	"github.com/cilium/ebpf/link"
	"github.com/go-errors/errors"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/utils"
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
		return s.installEnvoySslHooks(bpfObjects, sslLibrary)
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
