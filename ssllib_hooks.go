package main

import (
	"github.com/cilium/ebpf/link"
	"github.com/go-errors/errors"
)

type sslHooks struct {
	sslWriteProbe      link.Link
	sslWriteRetProbe   link.Link
	sslReadProbe       link.Link
	sslReadRetProbe    link.Link
	sslWriteExProbe    link.Link
	sslWriteExRetProbe link.Link
	sslReadExProbe     link.Link
	sslReadExRetProbe  link.Link
}

func (s *sslHooks) installUprobes(bpfObjects *tracerObjects, sslLibraryPath string) error {
	sslLibrary, err := link.OpenExecutable(sslLibraryPath)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	if err != nil {
		return errors.Wrap(err, 0)
	}

	return s.installSslHooks(bpfObjects, sslLibrary)
}

func (s *sslHooks) installSslHooks(bpfObjects *tracerObjects, sslLibrary *link.Executable) error {
	var err error

	s.sslWriteProbe, err = sslLibrary.Uprobe("SSL_write", bpfObjects.SslWrite, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.sslWriteRetProbe, err = sslLibrary.Uretprobe("SSL_write", bpfObjects.SslRetWrite, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.sslReadProbe, err = sslLibrary.Uprobe("SSL_read", bpfObjects.SslRead, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.sslReadRetProbe, err = sslLibrary.Uretprobe("SSL_read", bpfObjects.SslRetRead, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.sslWriteExProbe, err = sslLibrary.Uprobe("SSL_write_ex", bpfObjects.SslWriteEx, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.sslWriteExRetProbe, err = sslLibrary.Uretprobe("SSL_write_ex", bpfObjects.SslRetWriteEx, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.sslReadExProbe, err = sslLibrary.Uprobe("SSL_read_ex", bpfObjects.SslReadEx, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.sslReadExRetProbe, err = sslLibrary.Uretprobe("SSL_read_ex", bpfObjects.SslRetReadEx, nil)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	return nil
}

func (s *sslHooks) close() []error {
	returnValue := make([]error, 0)

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
