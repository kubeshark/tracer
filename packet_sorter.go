package main

import (
	"errors"
	"os"
	"sync"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/tracer/misc"
	"github.com/rs/zerolog/log"
)

type SortedPacket struct {
	PCAP string
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
	sortedPackets chan<- *SortedPacket
}

func NewPacketSorter(
	sortedPackets chan<- *SortedPacket,
) *PacketSorter {
	s := &PacketSorter{
		sortedPackets: sortedPackets,
	}

	s.initMasterPcap()

	return s
}

func (s *PacketSorter) initMasterPcap() {
	var err error
	var file *os.File
	var writer *pcapgo.Writer
	if _, err = os.Stat(misc.GetMasterPcapPath()); errors.Is(err, os.ErrNotExist) {
		file, err = os.OpenFile(misc.GetMasterPcapPath(), os.O_CREATE|os.O_WRONLY, 0644)
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
		file, err = os.OpenFile(misc.GetMasterPcapPath(), os.O_APPEND|os.O_WRONLY, 0644)
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

func (s *PacketSorter) SendSortedPacket(sortedPacket *SortedPacket) {
	s.sortedPackets <- sortedPacket
}

func (s *PacketSorter) GetMasterPcap() *MasterPcap {
	return s.masterPcap
}

func (s *PacketSorter) Close() {
	if s.sortedPackets != nil {
		close(s.sortedPackets)
	}
}
