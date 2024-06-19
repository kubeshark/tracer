package socket

import (
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracerproto/pkg/unixpacket"
	"github.com/rs/zerolog/log"
)

type SocketPcap struct {
	*Socket
	maxPktSize int
}

func NewSocketPcap(unixSocketFileName string) *SocketPcap {
	s := NewSocket(unixSocketFileName)
	return &SocketPcap{
		Socket: s,
	}
}

func (s *SocketPcap) WritePacket(cgroupId uint64, direction uint8, pkt gopacket.SerializeBuffer) error {
	s.Lock()
	defer s.Unlock()
	defer func() {
		s.counter++
	}()
	if len(s.connections) == 0 {
		return nil
	}

	hdrBytes, err := pkt.PrependBytes(unixpacket.PacketHeaderSize)
	if err != nil {
		return err
	}

	p := unixpacket.PacketUnixSocket(hdrBytes)
	hdr := p.GetHeader()
	hdr.Timestamp = uint64(time.Now().UnixNano())
	hdr.CgroupID = cgroupId
	hdr.Direction = unixpacket.PacketDirection(direction)
	// clear buffer at the end as soon as it is prepended with specific data
	defer func() {
		_ = pkt.Clear()
	}()

	buf := pkt.Bytes()
	if len(buf) > s.maxPktSize {
		s.maxPktSize = len(buf)
		// temorary logging
		log.Info().Str("Name", s.name).Int("len", s.maxPktSize).Msg("Max packet size:")
	}
	for _, conn := range s.connections {
		copyBuf := make([]byte, len(buf))
		copy(copyBuf, buf)
		p = unixpacket.PacketUnixSocket(copyBuf)
		hdr = p.GetHeader()
		hdr.PacketCounter = conn.counter
		conn.counter++

		if conn.writeChannel.Write(copyBuf) {
			conn.packetSent++
		} else {
			conn.packetDropped++
		}
	}
	return nil
}
