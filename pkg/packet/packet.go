package packet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/poller/packets"
	"github.com/kubeshark/tracer/pkg/rawcapture"
	"github.com/kubeshark/tracer/pkg/rawpacket"
)

var ErrNotSupported = errors.New("source is not supported")

type PacketData struct {
	Timestamp uint64
	Data      []byte
}

type PacketSource interface {
	NextPacket() (gopacket.Packet, error)
	Start() error
	Stop() error
	Stats() (packetsGot, packetsLost, chunksLost uint64)
	ExtendedStats() interface{}
	Pause()
	Resume()
}

type PacketsPoller interface {
	Start()
	Stop() error
	GetReceivedPackets() uint64
	GetLostChunks() uint64
	GetExtendedStats() interface{}
	Pause()
	Resume()
}

type PacketSourceImpl struct {
	perfBuffer     *ebpf.Map
	poller         PacketsPoller
	pktCh          chan gopacket.Packet
	captureManager *rawcapture.Manager
}

type createPollerFunc func(*ebpf.Map, bpf.GopacketWriter, rawpacket.RawPacketWriter) (PacketsPoller, error)

type enableCaptureFunc func(programsConfiguration *ebpf.Map, feature uint32) error

func newPacketSource(perfName string, enableCaptureName string, createPoller createPollerFunc, enableCapture enableCaptureFunc, captureMask uint32, pathSupported string, pathNotSupported string, captureManager *rawcapture.Manager) (PacketSource, error) {
	perfPath := filepath.Join(bpf.PinPath, perfName)
	enableCapturePath := filepath.Join(bpf.PinPath, enableCaptureName)

	var err error
	var perfBuffer *ebpf.Map
	var enableCaptureMap *ebpf.Map

	if supported, err := IsPlainPacketCaptureSupported(pathSupported, pathNotSupported); err != nil {
		return nil, err
	} else if !supported {
		return nil, ErrNotSupported
	}

	perfBuffer, err = ebpf.LoadPinnedMap(perfPath, nil)
	if err != nil {
		return nil, fmt.Errorf("load pinned map %v failed: %v", perfPath, err)
	}

	enableCaptureMap, err = ebpf.LoadPinnedMap(enableCapturePath, nil)
	if err != nil {
		return nil, fmt.Errorf("load pinned map %v failed: %v", enableCapturePath, err)
	}
	defer enableCaptureMap.Close()

	p := PacketSourceImpl{
		perfBuffer:     perfBuffer,
		pktCh:          make(chan gopacket.Packet),
		captureManager: captureManager,
	}

	if p.poller, err = createPoller(p.perfBuffer, p.WritePacket, p.WriteRawPacket); err != nil {
		return nil, fmt.Errorf("poller create failed: %v", err)
	}

	if err = enableCapture(enableCaptureMap, captureMask); err != nil {
		return nil, fmt.Errorf("enable capture failed: %v", err)
	}

	return &p, nil
}

// #define PROGRAM_DOMAIN_CAPTURE_TLS (1 << 0)
// #define PROGRAM_DOMAIN_CAPTURE_PLAIN (1 << 1)
const (
	programCaptureTls   = (1 << 0)
	programCapturePlain = (1 << 1)
)

var captureMtx sync.Mutex

func enableCapture(programsConfiguration *ebpf.Map, feature uint32) error {
	captureMtx.Lock()
	defer captureMtx.Unlock()

	var mask uint32
	if err := programsConfiguration.Lookup(uint32(0), &mask); err != nil {
		return fmt.Errorf("programs configuration lookup failed: %v", err)
	}
	mask = mask | feature
	if err := programsConfiguration.Update(uint32(0), mask, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("programs configuration update failed: %v", err)
	}
	return nil
}

func getPacketsPerfBufferSize() int {
	// 64 Mb for all CPUs
	return 64 * 1024 * 1024 / runtime.NumCPU()
}

func NewTLSPacketSource(dataDir string, captureManager *rawcapture.Manager) (PacketSource, error) {
	poller := func(m *ebpf.Map, goWr bpf.GopacketWriter, rawWr rawpacket.RawPacketWriter) (PacketsPoller, error) {
		return bpf.NewTlsPoller(m, goWr, rawWr, getPacketsPerfBufferSize())
	}

	return newPacketSource(bpf.PinNameTLSPackets, bpf.PinNameProgramsConfiguration, poller, enableCapture, programCaptureTls, filepath.Join(dataDir, bpf.TlsBackendSupportedFile), filepath.Join(dataDir, bpf.TlsBackendNotSupportedFile), captureManager)
}

func NewPlainPacketSource(dataDir string, captureManager *rawcapture.Manager) (PacketSource, error) {
	poller := func(m *ebpf.Map, goWr bpf.GopacketWriter, rawWr rawpacket.RawPacketWriter) (PacketsPoller, error) {
		return packets.NewPacketsPoller(m, goWr, rawWr, getPacketsPerfBufferSize())
	}

	return newPacketSource(bpf.PinNamePlainPackets, bpf.PinNameProgramsConfiguration, poller, enableCapture, programCapturePlain, filepath.Join(dataDir, bpf.PlainBackendSupportedFile), filepath.Join(dataDir, bpf.PlainBackendNotSupportedFile), captureManager)
}

func (p *PacketSourceImpl) WritePacket(pkt gopacket.Packet, dissectionDisabled bool) {
	if dissectionDisabled {
		return
	}

	pkt.Metadata().CaptureInfo.Done = make(chan struct{})
	p.pktCh <- pkt
	<-pkt.Metadata().CaptureInfo.Done
}

func (p *PacketSourceImpl) WriteRawPacket(timestamp uint64, pkt []byte) {
	if p.captureManager != nil {
		p.captureManager.EnqueuePacket(timestamp, pkt)
	}
}

func (p *PacketSourceImpl) Start() error {
	p.poller.Start()
	return nil
}

func (p *PacketSourceImpl) Stop() error {
	return p.poller.Stop()
}

func (p *PacketSourceImpl) Pause() {
	p.poller.Pause()
}

func (p *PacketSourceImpl) Resume() {
	p.poller.Resume()
}

func (p *PacketSourceImpl) Stats() (packetsGot, packetsLost, chunksLost uint64) {
	packetsGot = p.poller.GetReceivedPackets()
	chunksLost = p.poller.GetLostChunks()
	return packetsGot, packetsLost, chunksLost
}

func (p *PacketSourceImpl) NextPacket() (gopacket.Packet, error) {
	pkt := <-p.pktCh
	return pkt, nil
}

func (p *PacketSourceImpl) ExtendedStats() interface{} {
	return p.poller.GetExtendedStats()
}

func IsPlainPacketCaptureSupported(pathSupported, pathNotSupported string) (supported bool, err error) {
	expireTime := time.Now().Add(15 * time.Second)
	for time.Now().Before(expireTime) {
		var file *os.File
		if file, err = os.Open(pathNotSupported); err == nil {
			file.Close()
			return supported, err
		} else if !errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("check file %v existence failed: %w", pathNotSupported, err)
			return supported, err
		}

		if file, err = os.Open(pathSupported); err == nil {
			file.Close()
			supported = true
			return supported, err
		} else if !errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("check file %v existence failed: %w", pathSupported, err)
			return supported, err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return supported, err
}
