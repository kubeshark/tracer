package packets

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/go-errors/errors"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/tracer/internal/tai"
	"github.com/kubeshark/tracer/misc/ethernet"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracerproto/pkg/unixpacket"
	"github.com/rs/zerolog/log"
)

type tracerPacketsData struct {
	Timestamp uint64
	CgroupID  uint64
	ID        uint64
	Len       uint32
	TotLen    uint32
	Counter   uint32
	Num       uint16
	Last      uint16
	IPHdrType uint16
	Direction uint8
	Data      [4096]uint8
}

type tracerPktChunk struct {
	cpu int
	buf []byte
}

type pktBuffer struct {
	id  uint64
	num uint16
	len uint32
	buf [64 * 1024]byte
}

type PacketsPoller struct {
	ethernetDecoder gopacket.Decoder
	ethhdr          *layers.Ethernet
	mtx             sync.Mutex
	chunksReader    *perf.Reader
	rawWriter       bpf.RawWriter
	gopacketWriter  bpf.GopacketWriter
	pktsMap         map[uint64]*pktBuffer // packet id to packet
	receivedPackets uint64
	lostChunks      uint64
	tai             tai.TaiInfo
}

func NewPacketsPoller(
	perfBuffer *ebpf.Map,
	rawWriter bpf.RawWriter,
	gopacketWriter bpf.GopacketWriter,
) (*PacketsPoller, error) {
	var err error
	log.Info().Msgf("Creating NewPacketsPoller")

	ethernetDecoder := gopacket.DecodersByLayerName["Ethernet"]
	if ethernetDecoder == nil {
		return nil, errors.New("Failed to get Ethernet decoder")
	}

	// ethhdrContent := make([]byte, 14)
	// binary.BigEndian.PutUint16(ethhdrContent[12:14], uint16(layers.EthernetTypeIPv4))

	poller := &PacketsPoller{
		ethernetDecoder: ethernetDecoder,
		ethhdr:          &layers.Ethernet{},
		rawWriter:       rawWriter,
		gopacketWriter:  gopacketWriter,
		pktsMap:         make(map[uint64]*pktBuffer),
		tai:             tai.NewTaiInfo(),
	}

	poller.chunksReader, err = perf.NewReader(perfBuffer, os.Getpagesize()*10000)
	if err != nil {
		return nil, errors.Wrap(err, 0)
	}

	return poller, nil
}

func (p *PacketsPoller) Stop() error {
	return p.chunksReader.Close()
}

func (p *PacketsPoller) Start() {
	go p.poll()
}

func (p *PacketsPoller) GetLostChunks() uint64 {
	return p.lostChunks
}

func (p *PacketsPoller) GetReceivedPackets() uint64 {
	return p.receivedPackets
}

func (p *PacketsPoller) poll() {
	// tracerPktsChunk is generated by bpf2go.

	go p.pollChunksPerfBuffer()
	go p.checkBuffers()
}

func (p *PacketsPoller) handlePktChunk(chunk tracerPktChunk) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	// log.Info().Msgf("Processing %v", hex.Dump(chunk.buf))

	data := chunk.buf
	if len(data) == 4 {
		// zero packet to reset
		log.Info().Msg("Resetting plain packets buffer")
		p.pktsMap = make(map[uint64]*pktBuffer)
		return nil
	}
	const expectedChunkSize = 4148
	if len(data) != expectedChunkSize {
		return fmt.Errorf("bad pkt chunk: size %v expected: %v", len(data), expectedChunkSize)
	}

	ptr := (*tracerPacketsData)(unsafe.Pointer(&data[0]))

	pkts, ok := p.pktsMap[ptr.ID]
	if !ok {
		p.pktsMap[ptr.ID] = &pktBuffer{}
		pkts = p.pktsMap[ptr.ID]
	}
	if ptr.Num != pkts.num {
		return fmt.Errorf("lost packet message id: (%v %v) num: (%v %v) len: %v last: %v dir: %v tot_len: %v cpu: %v", pkts.id, ptr.ID, pkts.num, ptr.Num, ptr.Len, ptr.Last, ptr.Direction, ptr.TotLen, chunk.cpu)
	}

	copy(pkts.buf[pkts.len:], ptr.Data[:ptr.Len])
	pkts.len += uint32(ptr.Len)

	// log.Info().Msgf("Processing %v", hex.Dump(pkts.buf[:]))

	if ptr.Last != 0 {
		p.receivedPackets++

		// Check first byte of packet data to determine IP version
		p.ethhdr = ethernet.NewEthernetLayer(layers.EthernetType(ptr.IPHdrType))

		if p.rawWriter != nil {
			err := p.rawWriter(ptr.Timestamp, ptr.CgroupID, ptr.Direction, layers.LayerTypeEthernet, p.ethhdr, gopacket.Payload(pkts.buf[:pkts.len]))
			if err != nil {
				return err
			}
		}

		ethhdrContent := make([]byte, 14)
		binary.BigEndian.PutUint16(ethhdrContent[12:14], ptr.IPHdrType)

		if p.gopacketWriter != nil {
			pktBuf := append(ethhdrContent, pkts.buf[:pkts.len]...)
			pkt := gopacket.NewPacket(pktBuf, p.ethernetDecoder, gopacket.NoCopy, ptr.CgroupID, unixpacket.PacketDirection(ptr.Direction))
			m := pkt.Metadata()
			ci := &m.CaptureInfo
			if ptr.Timestamp != 0 {
				ci.Timestamp = time.Unix(0, int64(ptr.Timestamp)-int64(p.tai.GetTAIOffset()))
			} else {
				ci.Timestamp = time.Now()
			}
			ci.CaptureLength = len(pktBuf)
			ci.Length = len(pktBuf)
			ci.CaptureBackend = gopacket.CaptureBackendEbpf

			err := p.gopacketWriter(pkt)
			if err != nil {
				return err
			}
		}

		delete(p.pktsMap, ptr.ID)
	} else {
		pkts.num++
	}

	return nil
}

func (p *PacketsPoller) pollChunksPerfBuffer() {
	log.Info().Msg("Start polling for packet events")

	// remove all existing records

	p.chunksReader.SetDeadline(time.Unix(1, 0))
	var emptyRecord perf.Record
	for {
		err := p.chunksReader.ReadInto(&emptyRecord)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		} else if err != nil {
			log.Error().Err(err).Msg("Error reading chunks from pkts perf, aborting!")
			return
		}
	}
	p.chunksReader.SetDeadline(time.Time{})

	for {
		record, err := p.chunksReader.Read()
		// log.Info().Msgf("Processing Record %v", hex.Dump(record.RawSample))
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			log.Error().Err(err).Msg("Error reading chunks from pkts perf, aborting!")
			return
		}
		if record.LostSamples != 0 {
			log.Info().Msg(fmt.Sprintf("Buffer is full, dropped %d pkt chunks", record.LostSamples))
			p.lostChunks++
			continue
		}

		chunk := tracerPktChunk{
			cpu: record.CPU,
			buf: record.RawSample,
		}

		if err = p.handlePktChunk(chunk); err != nil {
			log.Error().Err(err).Msg("handle chunk failed")
		}
	}
}

func (p *PacketsPoller) checkBuffers() {
	// only bug in eBPF code can cause pktsMap overflow

	for {
		p.mtx.Lock()
		plen := len(p.pktsMap)
		p.mtx.Unlock()

		log.Debug().Int("size", plen).Msg("packets map size")
		if plen > 1024 {
			log.Error().Int("size", plen).Msg("packets map is too big, removig elements")
			p.mtx.Lock()
			for i := range p.pktsMap {
				delete(p.pktsMap, i)
				if len(p.pktsMap) <= 1024 {
					break
				}
			}
			p.mtx.Unlock()
		}
		time.Sleep(5 * time.Second)
	}
}
