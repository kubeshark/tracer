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
	"github.com/rs/zerolog/log"
)

type SortedPacket struct {
	CI   gopacket.CaptureInfo
	Data []byte
}

type MasterPcap struct {
	file   *os.File
	writer *pcapgo.Writer
	sync.Mutex
}

func (m *MasterPcap) WritePacket(ci gopacket.CaptureInfo, data []byte) (err error) {
	m.Lock()
	err = m.writer.WritePacket(ci, data)
	m.Unlock()
	return
}

type PacketSorter struct {
	masterPcap    *MasterPcap
	cbufPcap      *CbufPcap
	sortedPackets chan<- *SortedPacket
}

func NewPacketSorter(
	sortedPackets chan<- *SortedPacket,
) *PacketSorter {
	s := &PacketSorter{
		sortedPackets: sortedPackets,
	}

	s.initMasterPcap()
	s.initCbufPcap()

	return s
}

func (s *PacketSorter) initMasterPcap() {
	var err error
	var file *os.File
	var writer *pcapgo.Writer
	if _, err = os.Stat(misc.GetMasterPcapPath()); errors.Is(err, os.ErrNotExist) {
		err = syscall.Mkfifo(misc.GetMasterPcapPath(), 0666)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't create the named pipe:")
		}
		file, err = os.OpenFile(misc.GetMasterPcapPath(), os.O_APPEND|os.O_WRONLY, os.ModeNamedPipe)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't create master PCAP:")
		} else {
			writer = pcapgo.NewWriter(file)
			s.masterPcap = &MasterPcap{
				file:   file,
				writer: writer,
			}
			err = writer.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeEthernet)
			if err != nil {
			   log.Error().Err(err).Msg("While writing the PCAP header:")		
			}
		}
	} else {
		file, err = os.OpenFile(misc.GetMasterPcapPath(), os.O_APPEND|os.O_WRONLY, os.ModeNamedPipe)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't open master PCAP:")
		} else {
			writer = pcapgo.NewWriter(file)
			s.masterPcap = &MasterPcap{
				file:   file,
				writer: writer,
			}
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

func (s *PacketSorter) getMasterPcap() *MasterPcap {
	return s.masterPcap
}

func (s *PacketSorter) getCbufPcap() *CbufPcap {
	return s.cbufPcap
}

func (s *PacketSorter) Close() {
	if s.sortedPackets != nil {
		close(s.sortedPackets)
	}
}
