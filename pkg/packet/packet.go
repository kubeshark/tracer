package packet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/poller/packets"
	"github.com/rs/zerolog/log"
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

func newPacketSource(perfName string, createPoller createPollerFunc, pathNotSupported string) (PacketSource, error) {
	path := filepath.Join(bpf.PinPath, perfName)

	var err error
	var perfBuffer *ebpf.Map
	for {
		perfBuffer, err = ebpf.LoadPinnedMap(path, nil)
		if errors.Is(err, os.ErrNotExist) {
			if file, errStat := os.Open(pathNotSupported); errStat == nil {
				return nil, ErrNotSupported
			} else {
				file.Close()
			}
			time.Sleep(100 * time.Millisecond)
		} else if err != nil {
			return nil, err
		} else {
			break
		}
	}

	p := PacketSourceImpl{
		perfBuffer: perfBuffer,
		pktCh:      make(chan gopacket.Packet),
	}

	if p.poller, err = createPoller(p.perfBuffer, nil, p.WritePacket); err != nil {
		return nil, fmt.Errorf("poller create failed: %v", err)
	}

	return &p, nil
}

func NewTLSPacketSource(dataDir string) (PacketSource, error) {
	poller := func(m *ebpf.Map, wr bpf.RawWriter, goWr bpf.GopacketWriter) (PacketsPoller, error) {
		return bpf.NewTlsPoller(m, wr, goWr)
	}

	return newPacketSource(bpf.PinNameTLSPackets, poller, "")
}

func NewPlainPacketSource(dataDir string) (PacketSource, error) {
	poller := func(m *ebpf.Map, wr bpf.RawWriter, goWr bpf.GopacketWriter) (PacketsPoller, error) {
		return packets.NewPacketsPoller(m, wr, goWr)
	}

	return newPacketSource(bpf.PinNamePlainPackets, poller, filepath.Join(dataDir, "noebpf"))
}

func (p *PacketSourceImpl) WritePacket(pkt gopacket.Packet) error {
	log.Warn().Msgf("Write packet %v", pkt)
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
	log.Warn().Msgf("Got request for next packet returning %v", pkt)
	return pkt, nil
}
