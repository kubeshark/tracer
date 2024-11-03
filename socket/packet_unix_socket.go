package socket

import (
	"sync"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracerproto/pkg/unixpacket"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

type SocketPcap struct {
	*Socket
	maxPktSize int
	tai        int32
	taiMtx     sync.RWMutex
}

func NewSocketPcap(unixSocketFileName string) *SocketPcap {
	s := NewSocket(unixSocketFileName)
	spcap := &SocketPcap{
		Socket: s,
	}
	spcap.assignTAI()
	go spcap.updateTAI()
	return spcap
}

func (s *SocketPcap) WritePacket(timestamp uint64, cgroupId uint64, direction uint8, pkt gopacket.SerializeBuffer) error {
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
	if timestamp != 0 {
		hdr.Timestamp = timestamp - s.getTAIOffset()
	} else {
		hdr.Timestamp = uint64(time.Now().UnixNano())
	}
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

		//log.Warn().Msgf("To WriteChn %v", hex.Dump(copyBuf))
		if conn.writeChannel.Write(copyBuf) {
			conn.packetSent++
		} else {
			conn.packetDropped++
		}
	}
	return nil
}

func (s *SocketPcap) updateTAI() {
	ticker := time.NewTicker(30 * time.Second)
	for {
		<-ticker.C
		s.assignTAI()
	}
}

func (s *SocketPcap) getTAIOffset() uint64 {
	s.taiMtx.RLock()
	defer s.taiMtx.RUnlock()
	return uint64(s.tai) * 1e9
}

func (s *SocketPcap) assignTAI() {
	tai, err := getTAIOffset()
	if err != nil {
		log.Error().Err(err).Msg("Get TAI failed:")
		return
	}
	s.taiMtx.Lock()
	s.tai = tai
	s.taiMtx.Unlock()
}

// getTAIOffset retrieves the current TAI offset from the system.
func getTAIOffset() (int32, error) {
	var timex unix.Timex

	if _, err := unix.Adjtimex(&timex); err != nil {
		return 0, err
	}

	return timex.Tai, nil
}
