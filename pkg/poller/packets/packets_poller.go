package packets

import (
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/go-errors/errors"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/tracer/misc/ethernet"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/utils"
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
	ethhdr       *layers.Ethernet
	mtx          sync.Mutex
	chunksReader *perf.Reader
	sorter       *bpf.PacketSorter
	pktsMap      map[uint64]*pktBuffer // packet id to packet
}

func NewPacketsPoller(
	bpfObjs *bpf.BpfObjects,
	sorter *bpf.PacketSorter,
) (*PacketsPoller, error) {
	var err error
	poller := &PacketsPoller{
		ethhdr:  ethernet.NewEthernetLayer(layers.EthernetTypeIPv4),
		sorter:  sorter,
		pktsMap: make(map[uint64]*pktBuffer),
	}

	poller.chunksReader, err = perf.NewReader(bpfObjs.BpfObjs.PktsBuffer, os.Getpagesize()*10000)

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

func (p *PacketsPoller) poll() {
	// tracerPktsChunk is generated by bpf2go.

	go p.pollChunksPerfBuffer()
	go p.checkBuffers()
}

func (p *PacketsPoller) handlePktChunk(chunk tracerPktChunk) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	const expectedChunkSize = 4148
	data := chunk.buf
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

	if ptr.Last != 0 {
		err := p.sorter.WritePlanePacket(ptr.Timestamp, ptr.CgroupID, ptr.Direction, layers.LayerTypeEthernet, p.ethhdr, gopacket.Payload(pkts.buf[:pkts.len]))
		if err != nil {
			return err
		}

		delete(p.pktsMap, ptr.ID)
	} else {
		pkts.num++
	}

	return nil
}

func (p *PacketsPoller) pollChunksPerfBuffer() {
	log.Info().Msg("Start polling for tls events")

	for {
		record, err := p.chunksReader.Read()

		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			utils.LogError(errors.Errorf("Error reading chunks from pkts perf, aborting! %v", err))
			return
		}
		if record.LostSamples != 0 {
			log.Info().Msg(fmt.Sprintf("Buffer is full, dropped %d pkt chunks", record.LostSamples))
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
