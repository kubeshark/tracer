package main

import (
	"github.com/cilium/ebpf/link"
	"github.com/go-errors/errors"
)

type goHooks struct {
	goWriteProbe    link.Link
	goWriteExProbes []link.Link
	goReadProbe     link.Link
	goReadExProbes  []link.Link
}

func (s *goHooks) installUprobes(bpfObjects *tracerObjects, fpath string) error {
	ex, err := link.OpenExecutable(fpath)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	offsets, err := findGoOffsets(fpath)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	return s.installHooks(bpfObjects, ex, offsets)
}

func (s *goHooks) installHooks(bpfObjects *tracerObjects, ex *link.Executable, offsets goOffsets) error {
	var err error

	goCryptoTlsWrite := bpfObjects.GoCryptoTlsAbiInternalWrite
	goCryptoTlsWriteEx := bpfObjects.GoCryptoTlsAbiInternalWriteEx
	goCryptoTlsRead := bpfObjects.GoCryptoTlsAbiInternalRead
	goCryptoTlsReadEx := bpfObjects.GoCryptoTlsAbiInternalReadEx

	if offsets.Abi == ABI0 {
		goCryptoTlsWrite = bpfObjects.GoCryptoTlsAbi0Write
		goCryptoTlsWriteEx = bpfObjects.GoCryptoTlsAbi0WriteEx
		goCryptoTlsRead = bpfObjects.GoCryptoTlsAbi0Read
		goCryptoTlsReadEx = bpfObjects.GoCryptoTlsAbi0ReadEx

		// Pass goid and g struct offsets to an eBPF map to retrieve it in eBPF context
		if err := bpfObjects.tracerMaps.GoidOffsetsMap.Put(
			uint32(0),
			tracerGoidOffsets{
				G_addrOffset: offsets.GStructOffset,
				GoidOffset:   offsets.GoidOffset,
			},
		); err != nil {
			return errors.Wrap(err, 0)
		}
	}

	// Symbol points to
	// [`crypto/tls.(*Conn).Write`](https://github.com/golang/go/blob/go1.17.6/src/crypto/tls/conn.go#L1099)
	s.goWriteProbe, err = ex.Uprobe(goWriteSymbol, goCryptoTlsWrite, &link.UprobeOptions{
		Address: offsets.GoWriteOffset.enter,
	})

	if err != nil {
		return errors.Wrap(err, 0)
	}

	for _, offset := range offsets.GoWriteOffset.exits {
		probe, err := ex.Uprobe(goWriteSymbol, goCryptoTlsWriteEx, &link.UprobeOptions{
			Address: offset,
		})

		if err != nil {
			return errors.Wrap(err, 0)
		}

		s.goWriteExProbes = append(s.goWriteExProbes, probe)
	}

	// Symbol points to
	// [`crypto/tls.(*Conn).Read`](https://github.com/golang/go/blob/go1.17.6/src/crypto/tls/conn.go#L1263)
	s.goReadProbe, err = ex.Uprobe(goReadSymbol, goCryptoTlsRead, &link.UprobeOptions{
		Address: offsets.GoReadOffset.enter,
	})

	if err != nil {
		return errors.Wrap(err, 0)
	}

	for _, offset := range offsets.GoReadOffset.exits {
		probe, err := ex.Uprobe(goReadSymbol, goCryptoTlsReadEx, &link.UprobeOptions{
			Address: offset,
		})

		if err != nil {
			return errors.Wrap(err, 0)
		}

		s.goReadExProbes = append(s.goReadExProbes, probe)
	}

	return nil
}

func (s *goHooks) close() []error {
	errors := make([]error, 0)

	if err := s.goWriteProbe.Close(); err != nil {
		errors = append(errors, err)
	}

	for _, probe := range s.goWriteExProbes {
		if err := probe.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if err := s.goReadProbe.Close(); err != nil {
		errors = append(errors, err)
	}

	for _, probe := range s.goReadExProbes {
		if err := probe.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	return errors
}
