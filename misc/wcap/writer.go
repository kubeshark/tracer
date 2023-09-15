package wcap

import (
	"errors"
	"os"
	"sync"
	"time"

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

func openPcap(path string) (file *os.File, err error) {
	if _, err = os.Stat(path); errors.Is(err, os.ErrNotExist) {
		file, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
	} else {
		file, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
	}

	return
}

type Writer struct {
	context string
	files   map[string]time.Time
	sync.Mutex
}

func NewWriter(context string) (w *Writer, err error) {
	err = os.MkdirAll(misc.GetContextPath(context), os.ModePerm)
	if err != nil {
		return
	}
	w = &Writer{
		context: context,
		files:   make(map[string]time.Time),
	}

	if context == misc.DefaultContext {
		go w.MasterClean()
	}

	return
}

func (w *Writer) Write(sortedPackets <-chan *SortedPacket) {
	for sortedPacket := range sortedPackets {
		pcapPath := misc.GetPcapPath(sortedPacket.PCAP, w.context)

		if w.context == misc.DefaultContext {
			w.Lock()
			w.files[pcapPath] = time.Now().Add(misc.PcapTTL)
			w.Unlock()
		}

		file, err := openPcap(pcapPath)
		if err != nil {
			log.Error().Str("pcap", pcapPath).Err(err).Msg("Couldn't open PCAP:")
			continue
		}

		stat, err := file.Stat()
		if err != nil {
			log.Error().Str("pcap", pcapPath).Err(err).Msg("Cloudn't get file stats:")
			continue
		}

		pcapWriter := pcapgo.NewWriter(file)
		if stat.Size() == 0 {
			err = pcapWriter.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeEthernet)
			if err != nil {
				log.Error().Err(err).Msg("While writing the PCAP header:")
				continue
			}
		}

		if err := pcapWriter.WritePacket(sortedPacket.CI, sortedPacket.Data); err != nil {
			log.Error().Str("pcap", pcapPath).Err(err).Msg("Couldn't write the packet:")
		}

		file.Close()
	}
}

func (w *Writer) Clean() {
	os.RemoveAll(misc.GetContextPath(w.context))
}

func (w *Writer) MasterClean() {
	for range time.Tick(misc.PcapTTL) {
		w.Lock()
		for pcapPath, ttl := range w.files {
			if time.Now().After(ttl) {
				// TODO: Add a hook here named beforePcapRemoval(path string, ttl time.Time)
				err := os.Remove(pcapPath)
				if err != nil {
					log.Debug().Err(err).Send()
				}
				// TODO: Add a hook here named afterPcapRemoval(path string, ttl time.Time)
				delete(w.files, pcapPath)
			}
		}
		w.Unlock()
	}
}
