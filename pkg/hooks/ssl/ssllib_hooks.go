package ssl

import (
	"github.com/cilium/ebpf/link"
	"github.com/go-errors/errors"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/utils"
	"github.com/rs/zerolog/log"
)

type SslHooks struct {
	sslWriteProbe       link.Link
	sslWriteRetProbe    link.Link
	sslReadProbe        link.Link
	sslReadRetProbe     link.Link
	sslWriteExProbe     link.Link
	sslWriteExRetProbe  link.Link
	sslReadExProbe      link.Link
	sslReadExRetProbe   link.Link
	sslBioReadProbe     link.Link
	sslBioReadRetProbe  link.Link
	sslBioWriteProbe    link.Link
	sslBioWriteRetProbe link.Link
}

// TODO: incapsulate, add devuce id to the key, delete on file is deleted
var hookInodes, _ = lru.New[uint64, uint32](16384)

func (s *SslHooks) InstallUprobes(bpfObjects *bpf.BpfObjects, sslLibraryPath string) error {
	ino, err := utils.GetInode(sslLibraryPath)
	if err != nil {
		return err
	}
	log.Warn().Msgf("Got inode %v", ino)
	if ok, _ := hookInodes.ContainsOrAdd(ino, 0); ok {
		return nil
	}
	log.Warn().Msg("Got past ContainsOrAdd.")

	sslLibrary, err := link.OpenExecutable(sslLibraryPath)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("Calling installSslHooks.")

	return s.installSslHooks(bpfObjects, sslLibrary)
}

func (s *SslHooks) InstallEnvoyUprobes(bpfObjects *bpf.BpfObjects, sslLibraryPath string) error {
	ino, err := utils.GetInode(sslLibraryPath)
	if err != nil {
		return err
	}
	log.Warn().Msgf("Got inode %v", ino)
	if ok, _ := hookInodes.ContainsOrAdd(ino, 0); ok {
		return nil
	}
	log.Warn().Msg("Got past ContainsOrAdd.")

	sslLibrary, err := link.OpenExecutable(sslLibraryPath)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("Calling installSslHooks.")

	return s.installEnvoySslHooks(bpfObjects, sslLibrary)
}

func (s *SslHooks) installSslHooks(bpfObjects *bpf.BpfObjects, sslLibrary *link.Executable) error {
	var err error

	if s.sslWriteProbe != nil {
		log.Warn().Msgf("ssl read probe link is %v", s.sslWriteProbe)
	}

	s.sslWriteProbe, err = sslLibrary.Uprobe("SSL_write", bpfObjects.BpfObjs.SslWrite, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("sslWriteProbe installed.")

	s.sslWriteRetProbe, err = sslLibrary.Uretprobe("SSL_write", bpfObjects.BpfObjs.SslRetWrite, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("sslWriteRetProbe installed.")

	if s.sslReadProbe != nil {
		log.Warn().Msgf("ssl read probe link is %v", s.sslReadProbe)
	}

	s.sslReadProbe, err = sslLibrary.Uprobe("SSL_read", bpfObjects.BpfObjs.SslRead, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("sslReadProbe installed.")

	s.sslReadRetProbe, err = sslLibrary.Uretprobe("SSL_read", bpfObjects.BpfObjs.SslRetRead, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("sslReadRetProbe installed.")

	s.sslWriteExProbe, err = sslLibrary.Uprobe("SSL_write_ex", bpfObjects.BpfObjs.SslWriteEx, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("sslWriteExProbe installed.")

	s.sslWriteExRetProbe, err = sslLibrary.Uretprobe("SSL_write_ex", bpfObjects.BpfObjs.SslRetWriteEx, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("sslWriteExRetProbe installed.")

	s.sslReadExProbe, err = sslLibrary.Uprobe("SSL_read_ex", bpfObjects.BpfObjs.SslReadEx, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("sslReadExProbe installed.")

	s.sslReadExRetProbe, err = sslLibrary.Uretprobe("SSL_read_ex", bpfObjects.BpfObjs.SslRetReadEx, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("sslReadExRetProbe installed.")

	return nil
}

func (s *SslHooks) installEnvoySslHooks(bpfObjects *bpf.BpfObjects, sslLibrary *link.Executable) error {
	var err error

	if s.sslWriteProbe != nil {
		log.Warn().Msgf("ssl read probe link is %v", s.sslWriteProbe)
	}

	s.sslWriteProbe, err = sslLibrary.Uprobe("SSL_write", bpfObjects.BpfObjs.SslWrite, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("sslWriteProbe installed.")

	s.sslWriteRetProbe, err = sslLibrary.Uretprobe("SSL_write", bpfObjects.BpfObjs.SslRetWrite, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	if s.sslReadProbe != nil {
		log.Warn().Msgf("ssl read probe link is %v", s.sslReadProbe)
	}

	log.Warn().Msg("sslWriteRetProbe installed.")

	s.sslReadProbe, err = sslLibrary.Uprobe("SSL_read", bpfObjects.BpfObjs.SslRead, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("sslReadProbe installed.")

	s.sslReadRetProbe, err = sslLibrary.Uretprobe("SSL_read", bpfObjects.BpfObjs.SslRetRead, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	log.Warn().Msg("sslReadRetProbe installed.")

	// Install BIO_write probes
	/*s.sslBioReadProbe, err = sslLibrary.Uprobe("BIO_read", bpfObjects.BpfObjs.BioRead, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	log.Warn().Msg("bioReadProbe installed.")

	s.sslBioReadRetProbe, err = sslLibrary.Uretprobe("BIO_read", bpfObjects.BpfObjs.BioRetRead, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	log.Warn().Msg("bioReadRetProbe installed.")

	s.sslBioWriteProbe, err = sslLibrary.Uprobe("BIO_write", bpfObjects.BpfObjs.BioWrite, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	log.Warn().Msg("bioReadProbe installed.")

	s.sslBioWriteRetProbe, err = sslLibrary.Uretprobe("BIO_write", bpfObjects.BpfObjs.BioRetWrite, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	log.Warn().Msg("bioReadRetProbe installed.")*/

	return nil
}

func (s *SslHooks) Close() []error {
	returnValue := make([]error, 0)
	log.Warn().Msg("Close called removing all the hooks")
	if err := s.sslWriteProbe.Close(); err != nil {
		returnValue = append(returnValue, err)
	}

	if err := s.sslWriteRetProbe.Close(); err != nil {
		returnValue = append(returnValue, err)
	}

	if err := s.sslReadProbe.Close(); err != nil {
		returnValue = append(returnValue, err)
	}

	if err := s.sslReadRetProbe.Close(); err != nil {
		returnValue = append(returnValue, err)
	}

	if s.sslWriteExProbe != nil {
		if err := s.sslWriteExProbe.Close(); err != nil {
			returnValue = append(returnValue, err)
		}
	}

	if s.sslWriteExRetProbe != nil {
		if err := s.sslWriteExRetProbe.Close(); err != nil {
			returnValue = append(returnValue, err)
		}
	}

	if s.sslReadExProbe != nil {
		if err := s.sslReadExProbe.Close(); err != nil {
			returnValue = append(returnValue, err)
		}
	}

	if s.sslReadExRetProbe != nil {
		if err := s.sslReadExRetProbe.Close(); err != nil {
			returnValue = append(returnValue, err)
		}
	}

	return returnValue
}
