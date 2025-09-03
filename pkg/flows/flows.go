package flows

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/packet"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/host"
)

var ErrNotReady = errors.New("flows not ready")

type FlowKey struct {
	bpf.TracerFlowKeyT
}

type FlowValue struct {
	bpf.TracerFlowValueT
}

type Flow struct {
	Key FlowKey
	Val FlowValue
}

func (f *Flow) IpLocal() net.IP {
	return convertToNetIP(f.Key.IpVersion, f.Key.IpLocal)
}

func (f *Flow) IpRemote() net.IP {
	return convertToNetIP(f.Key.IpVersion, f.Key.IpRemote)
}

func convertToNetIP(ipVersion uint8, ip [16]uint8) net.IP {
	switch ipVersion {
	case 4:
		return net.IP(ip[0:4])
	case 6:
		return net.IP(ip[:])
	default:
		return nil
	}
}

type FlowsReaderFunc func(flow Flow) error

type FlowsReader interface {
	// ReadFlows reads flows from the eBPF map and calls the callback function for each flow.
	ReadFlows(FlowsReaderFunc) error
}

func NewFlowsReader(dataDir string) (FlowsReader, error) {
	bootSec, err := host.BootTime()
	if err != nil {
		return nil, errors.New("failed to get boot time")
	}
	fr := FlowsReaderImpl{
		bootNsec: bootSec * 1e9,
	}
	go fr.openFlows(dataDir)
	return &fr, nil
}

type FlowsReaderImpl struct {
	m        *ebpf.Map
	err      error
	ready    atomic.Bool
	bootNsec uint64
}

// ReadFlows reads flows from the eBPF map and calls the callback function for each flow.
func (f *FlowsReaderImpl) ReadFlows(flowsReaderFunc FlowsReaderFunc) error {
	if !f.ready.Load() {
		return ErrNotReady
	}
	if f.err != nil {
		return f.err
	}
	values := make([]FlowValue, runtime.NumCPU())
	key := FlowKey{}
	var err error
	it := f.m.Iterate()
	var counterKeys uint64
	var counter uint64
	for it.Next(&key, &values) {
		if len(values) == 0 {
			return fmt.Errorf("no values found for key: %v", key)
		}
		counterKeys++
		value := values[0]
		if value.FirstUpdateTime == 0 {
			value.FirstUpdateTime = ^uint64(0)
		}
		for i := 1; i < len(values); i++ {
			v := values[i]
			if v.FirstUpdateTime == 0 || v.LastUpdateTime == 0 {
				continue
			}
			if v.FirstUpdateTime < value.FirstUpdateTime {
				value.FirstUpdateTime = v.FirstUpdateTime
			}
			if v.LastUpdateTime > value.LastUpdateTime {
				value.LastUpdateTime = v.LastUpdateTime
			}
			value.PktsSent += v.PktsSent
			value.PktsRecv += v.PktsRecv
			value.BytesSent += v.BytesSent
			value.BytesRecv += v.BytesRecv
			counter++
		}

		value.FirstUpdateTime += f.bootNsec
		value.LastUpdateTime += f.bootNsec

		if err = flowsReaderFunc(Flow{key, value}); err != nil {
			return fmt.Errorf("callback failed: %v", err)
		}
	}
	if err = it.Err(); err != nil {
		return fmt.Errorf("iterate failed: %v", err)
	}

	return nil
}

func (f *FlowsReaderImpl) openFlows(dataDir string) {
	if supported, err := packet.IsPlainPacketCaptureSupported(filepath.Join(dataDir, bpf.PlainBackendSupportedFile), filepath.Join(dataDir, bpf.PlainBackendNotSupportedFile)); err != nil {
		f.err = fmt.Errorf("check file %v existence failed: %w", filepath.Join(dataDir, bpf.PlainBackendSupportedFile), err)
		return
	} else if !supported {
		f.err = fmt.Errorf("plain packet capture not supported")
		return
	}

	flowsPath := filepath.Join(bpf.PinPath, bpf.PinNameFlows)
	var err error
	log.Info().Str("path", flowsPath).Msg("Opening flows map")
	f.m, err = ebpf.LoadPinnedMap(flowsPath, nil)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		f.err = fmt.Errorf("load pinned map %v failed: %v", flowsPath, err)
	}

	f.ready.Store(true)
}
