package bpf

import (
	"sync"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/socket"
	"github.com/rs/zerolog/log"
)

type SortedPacket struct {
	CI   gopacket.CaptureInfo
	Data []byte
}

func (s *PacketSorter) WriteTLSPacket(timestamp uint64, cgroupId uint64, direction uint8, firstLayerType gopacket.LayerType, l ...gopacket.SerializableLayer) (err error) {
	if !s.cgroupEnabled {
		cgroupId = 0
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, l...)
	if err != nil {
		log.Error().Err(err).Msg("Error serializing packet:")
		return
	}

	s.Lock()
	defer s.Unlock()

	if s.writer != nil {
		data := buf.Bytes()
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now().UTC(),
			Length:        len(data),
			CaptureLength: len(data),
		}

		err = s.writer.WritePacket(ci, data)
	}

	if s.socketsTLS != nil {
		err = s.socketsTLS.WritePacket(timestamp, cgroupId, direction, buf)
	}

	return
}

func (s *PacketSorter) WritePlanePacket(timestamp uint64, cgroupId uint64, pktDirection uint8, firstLayerType gopacket.LayerType, l ...gopacket.SerializableLayer) (err error) {
	if !s.cgroupEnabled {
		cgroupId = 0
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, l...)
	if err != nil {
		log.Error().Err(err).Msg("Error serializing packet:")
		return
	}

	err = s.socketsPlain.WritePacket(timestamp, cgroupId, pktDirection, buf)

	return
}

type PacketSorter struct {
	socketsTLS    *socket.SocketPcap
	socketsPlain  *socket.SocketPcap
	sortedPackets chan<- *SortedPacket
	cgroupEnabled bool
	writer        *pcapgo.Writer
	sync.Mutex
}

func NewPacketSorter(
	sortedPackets chan<- *SortedPacket,
	cgroupEnabled bool,
) *PacketSorter {
	s := &PacketSorter{
		sortedPackets: sortedPackets,
		cgroupEnabled: cgroupEnabled,
	}

	s.initSocketPcap()

	return s
}

func (s *PacketSorter) initSocketPcap() {
	s.socketsTLS = socket.NewSocketPcap(misc.GetTLSSocketPath())
	s.socketsPlain = socket.NewSocketPcap(misc.GetPlainSocketPath())
}

func (s *PacketSorter) Close() {
	if s.sortedPackets != nil {
		close(s.sortedPackets)
	}
}
