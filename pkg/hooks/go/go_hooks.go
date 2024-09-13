package gohooks

import (
	"github.com/cilium/ebpf/link"
	"github.com/go-errors/errors"
	"github.com/kubeshark/tracer/pkg/bpf"
)

type GoHooks struct {
	goWriteProbe    link.Link
	goWriteExProbes []link.Link
	goReadProbe     link.Link
	goReadExProbes  []link.Link
}

func (s *GoHooks) InstallUprobes(bpfObjects *bpf.BpfObjects, fpath string) (offsets goOffsets, err error) {
	ex, err := link.OpenExecutable(fpath)

	if err != nil {
		err = errors.Wrap(err, 0)
		return
	}

	offsets, err = findGoOffsets(fpath)

	if err != nil {
		err = errors.Wrap(err, 0)
		return
	}

	err = s.installHooks(bpfObjects, ex, offsets)
	return
}

func (s *GoHooks) installHooks(bpfObjects *bpf.BpfObjects, ex *link.Executable, offsets goOffsets) error {
	var err error

	goCryptoTlsWrite := bpfObjects.BpfObjs.GoCryptoTlsAbiInternalWrite
	goCryptoTlsWriteEx := bpfObjects.BpfObjs.GoCryptoTlsAbiInternalWriteEx
	goCryptoTlsRead := bpfObjects.BpfObjs.GoCryptoTlsAbiInternalRead
	goCryptoTlsReadEx := bpfObjects.BpfObjs.GoCryptoTlsAbiInternalReadEx

	if offsets.Abi == ABI0 {
		goCryptoTlsWrite = bpfObjects.BpfObjs.GoCryptoTlsAbi0Write
		goCryptoTlsWriteEx = bpfObjects.BpfObjs.GoCryptoTlsAbi0WriteEx
		goCryptoTlsRead = bpfObjects.BpfObjs.GoCryptoTlsAbi0Read
		goCryptoTlsReadEx = bpfObjects.BpfObjs.GoCryptoTlsAbi0ReadEx

		// Pass goid and g struct offsets to an eBPF map to retrieve it in eBPF context
		if err := bpfObjects.BpfObjs.GoidOffsetsMap.Put(
			uint32(0),
			bpf.TracerGoidOffsets{
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

func (s *GoHooks) Close() []error {
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
