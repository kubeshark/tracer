package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kubeshark/tracer/misc"
	"github.com/rs/zerolog/log"
)

type PacketConsumer struct {
}

func NewPacketConsumer(pcapFile string) *PacketConsumer {
	pc := PacketConsumer{}
	masterPcap := misc.GetMasterPcapPath()

	var err error
	var pcapHandle *os.File

	if pcapFile != "" {
		if pcapHandle, err = os.OpenFile(pcapFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); err != nil {
			log.Error().Err(err).Msg("Couldn't open pcap for writing:")
			return nil
		}
	}

	if err = os.Remove(masterPcap); err != nil {
		log.Error().Err(err).Msg("Couldn't remove master pcap:")
	}

	go pc.consumePackets(masterPcap, pcapHandle)

	return &pc
}

func (pc *PacketConsumer) consumePackets(pcapName string, pcapHandle *os.File) {
	select {
	case <-time.After(1 * time.Second):
		_, err := os.Stat(misc.GetMasterPcapPath())
		if err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			log.Error().Err(err).Msg("Couldn't locate pcap:")
			return
		}
	}

	if pcapHandle != nil {
		defer pcapHandle.Close()
	}

	file, err := os.OpenFile(misc.GetMasterPcapPath(), os.O_RDONLY, 0)
	if err != nil {
		log.Error().Err(err).Msg("Couldn't open master pcap:")
	} else {
		var total int
		for {
			buf := make([]byte, 1024)
			n, err := file.Read(buf)
			if err != nil && err != io.EOF {
				log.Error().Err(err).Msg("Couldn't read master pcap:")
				return
			}
			total += n
			if pcapHandle != nil {
				if _, err = pcapHandle.Write(buf[0:n]); err != nil {
					log.Error().Err(err).Msg("Couldn't write pcap:")
					return
				}
			}
			if err == io.EOF {
				log.Info().Msg(fmt.Sprintf("Read master pcap complete. Total: %v bytes", total))
				return
			}
		}
	}
}
