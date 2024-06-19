package main

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/socket"
	"github.com/rs/zerolog/log"
)

type SortedPacket struct {
	CI   gopacket.CaptureInfo
	Data []byte
}

func (s *PacketSorter) WriteTLSPacket(cgroupId uint64, direction uint8, firstLayerType gopacket.LayerType, l ...gopacket.SerializableLayer) (err error) {
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

		if err == nil && s.cbufPcap != nil {
			s.cbufPcap.WritePacket(ci, data)
		}
	}

	if s.socketsTLS != nil {
		err = s.socketsTLS.WritePacket(cgroupId, direction, buf)
	}

	return
}

func (s *PacketSorter) WritePlanePacket(cgroupId uint64, pktDirection uint8, firstLayerType gopacket.LayerType, l ...gopacket.SerializableLayer) (err error) {
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

	err = s.socketsPlain.WritePacket(cgroupId, pktDirection, buf)

	return
}

type PacketSorter struct {
	cbufPcap      *CbufPcap
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

	// pcap pipe is opens in sync mode, so do it in a separate goroutine
	go s.initMasterPcap()

	s.initCbufPcap()
	s.initSocketPcap()

	return s
}

func (s *PacketSorter) initMasterPcap() {
	var err error
	var file *os.File
	if _, err = os.Stat(misc.GetMasterPcapPath()); errors.Is(err, os.ErrNotExist) {
		err = syscall.Mkfifo(misc.GetMasterPcapPath(), 0666)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't create the named pipe:")
		}
		file, err = os.OpenFile(misc.GetMasterPcapPath(), os.O_APPEND|os.O_WRONLY, os.ModeNamedPipe)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't create master PCAP:")
		} else {
			s.Lock()
			defer s.Unlock()
			s.writer = pcapgo.NewWriter(file)
			err = s.writer.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeEthernet)
			if err != nil {
				log.Error().Err(err).Msg("While writing the PCAP header:")
			}
		}
	} else {
		file, err = os.OpenFile(misc.GetMasterPcapPath(), os.O_APPEND|os.O_WRONLY, os.ModeNamedPipe)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't open master PCAP:")
		} else {
			s.Lock()
			defer s.Unlock()
			s.writer = pcapgo.NewWriter(file)
		}
	}
}

func (s *PacketSorter) initCbufPcap() {
	if *globCbuf == 0 {
		return
	}
	if *globCbuf < 0 || *globCbuf > globCbufMax {
		log.Error().Msg(fmt.Sprintf("Circullar buffer size can not be greater than %v", globCbufMax))
		return
	}

	if _, err := os.Stat(misc.GetCbufPcapPath()); errors.Is(err, os.ErrNotExist) {
		err = syscall.Mkfifo(misc.GetCbufPcapPath(), 0666)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't create the named pipe:")
		}
	}

	s.cbufPcap = NewCbufPcap(*globCbuf)

	go func() {
		for {
			file, err := os.OpenFile(misc.GetCbufPcapPath(), os.O_APPEND|os.O_WRONLY, os.ModeNamedPipe)
			if err != nil {
				log.Error().Err(err).Msg("Couldn't create cbuf PCAP:")
				break
			}
			err = s.cbufPcap.DumptoPcapFile(file, *globCbuf)
			if err != nil {
				log.Error().Err(err).Msg("Couldn't dump cbuf PCAP:")
			}
			file.Close()
			// wait read side to close the file
			time.Sleep(100 * time.Millisecond)
		}
	}()

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
