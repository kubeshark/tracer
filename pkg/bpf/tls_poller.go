package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/go-errors/errors"
	"github.com/hashicorp/golang-lru/simplelru"
	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracer/internal/tai"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/utils"
	"github.com/rs/zerolog/log"
)

const (
	fdCachedItemAvgSize = 40
	fdCacheMaxItems     = 500000 / fdCachedItemAvgSize
)

type RawWriter func(timestamp uint64, cgroupId uint64, direction uint8, firstLayerType gopacket.LayerType, l ...gopacket.SerializableLayer) (err error)
type GopacketWriter func(packet gopacket.Packet) (err error)

type TlsPoller struct {
	streams         map[string]*TlsStream
	closeStreams    chan string
	chunksReader    *perf.Reader
	fdCache         *simplelru.LRU // Actual type is map[string]addressPair
	evictedCounter  int
	rawWriter       RawWriter
	gopacketWriter  GopacketWriter
	receivedPackets uint64
	lostChunks      uint64
	lastLostChunks      uint64
	lastLostCheck  time.Time
	tai             tai.TaiInfo
}

func NewTlsPoller(
	perfBuffer *ebpf.Map,
	rawWriter RawWriter,
	gopacketWriter GopacketWriter,
	perfBufferSize int,
) (*TlsPoller, error) {
	poller := &TlsPoller{
		streams:        make(map[string]*TlsStream),
		closeStreams:   make(chan string, misc.TlsCloseChannelBufferSize),
		chunksReader:   nil,
		rawWriter:      rawWriter,
		gopacketWriter: gopacketWriter,
		tai:            tai.NewTaiInfo(),
	}

	fdCache, err := simplelru.NewLRU(fdCacheMaxItems, poller.fdCacheEvictCallback)
	if err != nil {
		return nil, errors.Wrap(err, 0)
	}
	poller.fdCache = fdCache

	poller.chunksReader, err = perf.NewReader(perfBuffer, perfBufferSize)

	if err != nil {
		return nil, errors.Wrap(err, 0)
	}

	return poller, nil
}

func (p *TlsPoller) Stop() error {
	return p.chunksReader.Close()
}

func (p *TlsPoller) Start() {
	// tracerTlsChunk is generated by bpf2go.
	streamsMap := NewTcpStreamMap()
	chunks := make(chan *TracerTlsChunk)

	go p.pollChunksPerfBuffer(chunks)

	go func() {
		for {
			select {
			case chunk, ok := <-chunks:
				if !ok {
					return
				}

				if err := p.handleTlsChunk(chunk, streamsMap); err != nil {
					utils.LogError(err)
				}
			case key := <-p.closeStreams:
				delete(p.streams, key)
			}
		}
	}()
}

func (p *TlsPoller) GetLostChunks() uint64 {
	return p.lostChunks
}

func (p *TlsPoller) GetReceivedPackets() uint64 {
	return p.receivedPackets
}

func (p *TlsPoller) pollChunksPerfBuffer(chunks chan<- *TracerTlsChunk) {
	log.Info().Msg("Start polling for tls events")

	p.chunksReader.SetDeadline(time.Unix(1, 0))
	var emptyRecord perf.Record
	for {
		err := p.chunksReader.ReadInto(&emptyRecord)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		} else if err != nil {
			log.Fatal().Err(err).Msg("Error reading chunks from pkts perf, aborting!")
			return
		}
	}
	p.chunksReader.SetDeadline(time.Time{})

	for {
		if time.Since(p.lastLostCheck) > time.Minute  && p.lastLostChunks != p.lostChunks {
			log.Warn().Msg(fmt.Sprintf("Buffer is full, dropped %d chunks", p.lostChunks - p.lastLostChunks))
			p.lastLostChunks = p.lostChunks
			p.lastLostCheck = time.Now()
		}

		record, err := p.chunksReader.Read()

		if err != nil {
			close(chunks)

			if errors.Is(err, perf.ErrClosed) {
				log.Info().Err(err).Msg("perf buffer is closed")
				return
			}

			log.Fatal().Err(err).Msg("Error reading chunks from pkts perf, aborting!")
			return
		}

		if record.LostSamples != 0 {
			p.lostChunks += record.LostSamples
			continue
		}

		buffer := bytes.NewReader(record.RawSample)

		var chunk TracerTlsChunk

		if err := binary.Read(buffer, binary.LittleEndian, &chunk); err != nil {
			log.Error().Err(err).Msg("Error parsing chunk")
			continue
		}

		chunks <- &chunk
	}
}

func (p *TlsPoller) handleTlsChunk(chunk *TracerTlsChunk, streamsMap *TcpStreamMap) error {
	address := chunk.GetAddressPair()

	// Creates one *tlsStream per TCP stream
	key := buildTlsKey(address, chunk.IsRequest())
	stream, streamExists := p.streams[key]
	if !streamExists {
		stream = NewTlsStream(p, key)
		stream.SetId(streamsMap.NextId())
		streamsMap.Store(stream.GetId(), stream)
		p.streams[key] = stream

		stream.Client = NewTlsReader(p.buildTcpId(address, chunk.IsClient()), stream, true)
		stream.Server = NewTlsReader(p.buildTcpId(address, !chunk.IsClient()), stream, false)
	}

	reader := chunk.GetReader(stream)
	reader.NewChunk(chunk)

	return nil
}

func buildTlsKey(address *AddressPair, isRequest bool) string {
	if isRequest {
		return fmt.Sprintf("%s:%d>%s:%d", address.SrcIp, address.SrcPort, address.DstIp, address.DstPort)
	} else {
		return fmt.Sprintf("%s:%d>%s:%d", address.DstIp, address.DstPort, address.SrcIp, address.SrcPort)
	}
}

func (p *TlsPoller) buildTcpId(address *AddressPair, isRequest bool) *TcpID {
	if isRequest {
		return &TcpID{
			SrcIP:   address.SrcIp.String(),
			DstIP:   address.DstIp.String(),
			SrcPort: strconv.FormatUint(uint64(address.SrcPort), 10),
			DstPort: strconv.FormatUint(uint64(address.DstPort), 10),
		}
	} else {
		return &TcpID{
			SrcIP:   address.DstIp.String(),
			DstIP:   address.SrcIp.String(),
			SrcPort: strconv.FormatUint(uint64(address.DstPort), 10),
			DstPort: strconv.FormatUint(uint64(address.SrcPort), 10),
		}
	}
}

func (p *TlsPoller) fdCacheEvictCallback(key interface{}, value interface{}) {
	p.evictedCounter = p.evictedCounter + 1

	if p.evictedCounter%1000000 == 0 {
		log.Info().Msg(fmt.Sprintf("Tls fdCache evicted %d items", p.evictedCounter))
	}
}
