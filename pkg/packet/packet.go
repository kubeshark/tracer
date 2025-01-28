package packet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/poller/packets"
	"github.com/rs/zerolog/log"
)

var (
	ErrNotSupported = errors.New("source is not supported")
)

type PacketData struct {
	Timestamp uint64
	Data      []byte
}

type PacketSource interface {
	NextPacket() (gopacket.Packet, error)
	Start() error
	Stop() error
	Stats() (packetsGot, packetsLost uint64)
}

type PacketsPoller interface {
	Start()
	Stop() error
	GetReceivedPackets() uint64
	GetLostChunks() uint64
}

type PacketSourceImpl struct {
	perfBuffer *ebpf.Map
	poller     PacketsPoller
	pktCh      chan gopacket.Packet
}

type createPollerFunc func(*ebpf.Map, bpf.RawWriter, bpf.GopacketWriter) (PacketsPoller, error)

type enableCaptureFunc func(programsConfiguration *ebpf.Map, feature uint32) error

func newPacketSource(perfName string, enableCaptureName string, createPoller createPollerFunc, enableCapture enableCaptureFunc, captureMask uint32, pathSupported string, pathNotSupported string) (PacketSource, error) {
	perfPath := filepath.Join(bpf.PinPath, perfName)
	enableCapturePath := filepath.Join(bpf.PinPath, enableCaptureName)

	var err error
	var perfBuffer *ebpf.Map
	var enableCaptureMap *ebpf.Map

	expireTime := time.Now().Add(15 * time.Second)
	supported := false
	for time.Now().Before(expireTime) {
		if file, err := os.Open(pathNotSupported); err == nil {
			file.Close()
			return nil, ErrNotSupported
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("check file %v existence failed: %v", pathNotSupported, err)
		}

		if file, err := os.Open(pathSupported); err == nil {
			file.Close()
			supported = true
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("check file %v existence failed: %v", pathSupported, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !supported {
		// time is up but no file was found
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
		perfBuffer: perfBuffer,
		pktCh:      make(chan gopacket.Packet),
	}

	if p.poller, err = createPoller(p.perfBuffer, nil, p.WritePacket); err != nil {
		return nil, fmt.Errorf("poller create failed: %v", err)
	}

	if err = enableCapture(enableCaptureMap, captureMask); err != nil {
		return nil, fmt.Errorf("enable capture failed: %v", err)
	}

	return &p, nil
}

// #define PROGRAM_DOMAIN_CAPTURE_TLS (1 << 1)
// #define PROGRAM_DOMAIN_CAPTURE_PLAIN (1 << 2)
const (
	programCaptureTls   = (1 << 1)
	programCapturePlain = (1 << 2)
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

func NewTLSPacketSource(dataDir string) (PacketSource, error) {
	poller := func(m *ebpf.Map, wr bpf.RawWriter, goWr bpf.GopacketWriter) (PacketsPoller, error) {
		return bpf.NewTlsPoller(m, wr, goWr)
	}

	return newPacketSource(bpf.PinNameTLSPackets, bpf.PinNameProgramsConfiguration, poller, enableCapture, programCaptureTls, filepath.Join(dataDir, bpf.TlsBackendSupportedFile), filepath.Join(dataDir, bpf.TlsBackendNotSupportedFile))
}

func NewPlainPacketSource(dataDir string) (PacketSource, error) {
	poller := func(m *ebpf.Map, wr bpf.RawWriter, goWr bpf.GopacketWriter) (PacketsPoller, error) {
		return packets.NewPacketsPoller(m, wr, goWr)
	}

	return newPacketSource(bpf.PinNamePlainPackets, bpf.PinNameProgramsConfiguration, poller, enableCapture, programCapturePlain, filepath.Join(dataDir, bpf.PlainBackendSupportedFile), filepath.Join(dataDir, bpf.PlainBackendNotSupportedFile))
}

func (p *PacketSourceImpl) WritePacket(pkt gopacket.Packet) error {
	p.pktCh <- pkt
	return nil
}

func (p *PacketSourceImpl) Start() error {
	p.poller.Start()
	return nil
}

func (p *PacketSourceImpl) Stop() error {
	return p.poller.Stop()
}

func (p *PacketSourceImpl) Stats() (packetsGot, packetsLost uint64) {
	packetsGot = p.poller.GetReceivedPackets()
	// Using chunks instead of packets:
	packetsLost = p.poller.GetLostChunks()
	return
}

func (p *PacketSourceImpl) NextPacket() (gopacket.Packet, error) {
	pkt := <-p.pktCh
	return pkt, nil
}
