package bpf

import (
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/go-errors/errors"
	"github.com/hashicorp/golang-lru/simplelru"
	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracer/internal/tai"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/decodedpacket"
	"github.com/kubeshark/tracer/pkg/rawpacket"
	"github.com/kubeshark/tracer/pkg/utils"
	"github.com/rs/zerolog/log"
)

const (
	fdCachedItemAvgSize = 40
	fdCacheMaxItems     = 500000 / fdCachedItemAvgSize

	tlsDiagInterval = 5 * time.Second
)

type (
	RawWriter      func(timestamp uint64, cgroupId uint64, direction uint8, firstLayerType gopacket.LayerType, l ...gopacket.SerializableLayer) (err error)
	GopacketWriter func(packet gopacket.Packet, dissectionDisabled bool)
)

type ringbufReader interface {
	Read() (any, error)
	Close() error
}

type ringbufReaderWrapper struct {
	r *ringbuf.Reader
}

func (w *ringbufReaderWrapper) Read() (any, error) { return w.r.Read() }
func (w *ringbufReaderWrapper) Close() error       { return w.r.Close() }

func atomicMaxUint64(addr *uint64, v uint64) {
	for {
		old := atomic.LoadUint64(addr)
		if v <= old {
			return
		}
		if atomic.CompareAndSwapUint64(addr, old, v) {
			return
		}
	}
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

var (
	// Full struct size (includes Data[CHUNK_SIZE]).
	tlsChunkSize = int(unsafe.Sizeof(TracerTlsChunk{}))

	// Header size up to (but not including) Data[].
	// This must match C-side TLS_CHUNK_HDR_SIZE.
	tlsChunkHdrSize = int(unsafe.Offsetof(TracerTlsChunk{}.Data))
)

// parseTracerTlsChunk parses a TLS chunk from either:
// - perf buffer samples (typically full struct size)
// - ringbuf samples (variable size: header + recorded)
//
// It copies raw bytes into a zeroed TracerTlsChunk and validates Recorded vs sample length.
func parseTracerTlsChunk(raw []byte) (*TracerTlsChunk, error) {
	if len(raw) < tlsChunkHdrSize {
		return nil, fmt.Errorf("bad TLS chunk: size %d < hdr %d", len(raw), tlsChunkHdrSize)
	}

	chunk := new(TracerTlsChunk)

	// Copy as much as we have (variable-size samples are expected).
	n := len(raw)
	if n > tlsChunkSize {
		n = tlsChunkSize
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(chunk)), tlsChunkSize)
	copy(dst[:n], raw[:n])

	// Validate/clamp Recorded
	recorded := int(chunk.Recorded)
	if recorded < 0 {
		return nil, fmt.Errorf("bad TLS chunk: negative recorded=%d", recorded)
	}
	if recorded > len(chunk.Data) {
		// Clamp to struct capacity; this should never happen in healthy data.
		recorded = len(chunk.Data)
		chunk.Recorded = uint32(recorded)
	}

	// If kernel sent variable-size (hdr + recorded), raw should include at least that.
	expectedMin := tlsChunkHdrSize + recorded
	if len(raw) < expectedMin {
		// Truncated sample; clamp recorded to what we actually received.
		avail := len(raw) - tlsChunkHdrSize
		if avail < 0 {
			avail = 0
		}
		if avail < recorded {
			chunk.Recorded = uint32(avail)
		}
	}

	return chunk, nil
}

type TlsPoller struct {
	streams      map[string]*TlsStream
	closeStreams chan string

	chunksReader *perf.Reader
	ringReader   ringbufReader
	useRingbuf   bool

	fdCache         *simplelru.LRU // Actual type is map[string]addressPair
	evictedCounter  int
	gopacketWriter  GopacketWriter
	rawPacketWriter rawpacket.RawPacketWriter
	receivedPackets uint64
	lostChunks      uint64
	lastLostChunks  uint64
	lastLostCheck   time.Time
	tai             tai.TaiInfo
	stats           TlsPollerStats

	// Reusable record to avoid allocations
	reusableRecord perf.Record

	// LayerParser for efficient packet decoding
	layerParser *decodedpacket.LayerParser

	// Reusable buffer for packet data
	pktBuf             []byte
	dissectionDisabled bool

	diagChunksGot     uint64
	diagChunksHandled uint64
	diagChunksLost    uint64
	diagPacketsGot    uint64
	diagBytesWritten  uint64

	diagParseNanos uint64
	diagParseCalls uint64
	diagMaxParseNs uint64

	diagSendNanos uint64
	diagSendCalls uint64
	diagMaxSendNs uint64

	diagHandleNanos uint64
	diagHandleCalls uint64
	diagMaxHandleNs uint64

	lastDiagTime time.Time

	lastDiagChunksGot     uint64
	lastDiagChunksHandled uint64
	lastDiagChunksLost    uint64
	lastDiagPacketsGot    uint64
	lastDiagBytesWritten  uint64

	lastDiagParseNanos uint64
	lastDiagParseCalls uint64

	lastDiagSendNanos uint64
	lastDiagSendCalls uint64

	lastDiagHandleNanos uint64
	lastDiagHandleCalls uint64
}

type TlsPollerStats struct {
	tlsStreamStats
	ChunksGot     uint64
	ChunksHandled uint64
	ChunksLost    uint64
}

func NewTlsPoller(
	perfBuffer *ebpf.Map,
	gopacketWriter GopacketWriter,
	rawPacketWriter rawpacket.RawPacketWriter,
	perfBufferSize int,
) (*TlsPoller, error) {
	poller := &TlsPoller{
		streams:            make(map[string]*TlsStream),
		closeStreams:       make(chan string, misc.TlsCloseChannelBufferSize),
		chunksReader:       nil,
		ringReader:         nil,
		useRingbuf:         false,
		rawPacketWriter:    rawPacketWriter,
		gopacketWriter:     gopacketWriter,
		tai:                tai.NewTaiInfo(),
		layerParser:        decodedpacket.NewLayerParser(),
		pktBuf:             make([]byte, 0, 14+64*1024),
		dissectionDisabled: false,
		lastDiagTime:       time.Now(),
	}

	fdCache, err := simplelru.NewLRU(fdCacheMaxItems, poller.fdCacheEvictCallback)
	if err != nil {
		return nil, errors.Wrap(err, 0)
	}
	poller.fdCache = fdCache

	if rr, rerr := ringbuf.NewReader(perfBuffer); rerr == nil {
		log.Info().Msg("Using ring buffer for TLS polling")
		poller.useRingbuf = true
		poller.ringReader = &ringbufReaderWrapper{r: rr}
		log.Info().Msg("Initialized ring buffer for TLS polling")
	} else {
		poller.chunksReader, err = perf.NewReader(perfBuffer, perfBufferSize)
		if err != nil {
			return nil, errors.Wrap(
				fmt.Errorf("failed to create ringbuf reader: %v; failed to create perf reader: %w", rerr, err),
				0,
			)
		}
		log.Info().Msg("Using perf buffer for TLS polling")
	}

	return poller, nil
}

func (p *TlsPoller) Stop() error {
	if p.useRingbuf {
		if p.ringReader != nil {
			return p.ringReader.Close()
		}
		return nil
	}
	if p.chunksReader != nil {
		return p.chunksReader.Close()
	}
	return nil
}

func (p *TlsPoller) Start() {
	streamsMap := NewTcpStreamMap()
	chunks := make(chan *TracerTlsChunk)

	go p.pollChunks(chunks)

	go func() {
		for {
			select {
			case chunk, ok := <-chunks:
				if !ok {
					return
				}

				handleStart := time.Now()
				err := p.handleTlsChunk(chunk, streamsMap)
				dtHandle := time.Since(handleStart)

				atomic.AddUint64(&p.diagHandleNanos, uint64(dtHandle))
				atomic.AddUint64(&p.diagHandleCalls, 1)
				atomicMaxUint64(&p.diagMaxHandleNs, uint64(dtHandle))

				if err != nil {
					utils.LogError(err)
				} else {
					p.stats.ChunksHandled++
					atomic.AddUint64(&p.diagChunksHandled, 1)
				}

				p.logPeriodicDiagnostics()

			case key := <-p.closeStreams:
				delete(p.streams, key)
				p.logPeriodicDiagnostics()
			}
		}
	}()
}

func (p *TlsPoller) GetLostChunks() uint64         { return p.lostChunks }
func (p *TlsPoller) GetReceivedPackets() uint64    { return p.receivedPackets }
func (p *TlsPoller) GetExtendedStats() interface{} { return p.stats }

func (p *TlsPoller) Pause()  { p.dissectionDisabled = true }
func (p *TlsPoller) Resume() { p.dissectionDisabled = false }

func (p *TlsPoller) logPeriodicDiagnostics() {
	now := time.Now()
	if now.Sub(p.lastDiagTime) < tlsDiagInterval {
		return
	}

	elapsed := now.Sub(p.lastDiagTime).Seconds()
	if elapsed <= 0 {
		p.lastDiagTime = now
		return
	}

	got := atomic.LoadUint64(&p.diagChunksGot)
	handled := atomic.LoadUint64(&p.diagChunksHandled)
	lost := atomic.LoadUint64(&p.diagChunksLost)
	pkts := atomic.LoadUint64(&p.diagPacketsGot)
	bytesW := atomic.LoadUint64(&p.diagBytesWritten)

	parseN := atomic.LoadUint64(&p.diagParseNanos)
	parseC := atomic.LoadUint64(&p.diagParseCalls)

	sendN := atomic.LoadUint64(&p.diagSendNanos)
	sendC := atomic.LoadUint64(&p.diagSendCalls)

	handleN := atomic.LoadUint64(&p.diagHandleNanos)
	handleC := atomic.LoadUint64(&p.diagHandleCalls)

	dGot := got - p.lastDiagChunksGot
	dHandled := handled - p.lastDiagChunksHandled
	dLost := lost - p.lastDiagChunksLost
	dPkts := pkts - p.lastDiagPacketsGot
	dBytes := bytesW - p.lastDiagBytesWritten

	dParseN := parseN - p.lastDiagParseNanos
	dParseC := parseC - p.lastDiagParseCalls

	dSendN := sendN - p.lastDiagSendNanos
	dSendC := sendC - p.lastDiagSendCalls

	dHandleN := handleN - p.lastDiagHandleNanos
	dHandleC := handleC - p.lastDiagHandleCalls

	p.lastDiagTime = now
	p.lastDiagChunksGot = got
	p.lastDiagChunksHandled = handled
	p.lastDiagChunksLost = lost
	p.lastDiagPacketsGot = pkts
	p.lastDiagBytesWritten = bytesW
	p.lastDiagParseNanos = parseN
	p.lastDiagParseCalls = parseC
	p.lastDiagSendNanos = sendN
	p.lastDiagSendCalls = sendC
	p.lastDiagHandleNanos = handleN
	p.lastDiagHandleCalls = handleC

	avgUs := func(nanos, calls uint64) float64 {
		if calls == 0 {
			return 0
		}
		return float64(nanos) / float64(calls) / 1000.0
	}

	parseMaxMs := float64(atomic.LoadUint64(&p.diagMaxParseNs)) / 1e6
	sendMaxMs := float64(atomic.LoadUint64(&p.diagMaxSendNs)) / 1e6
	handleMaxMs := float64(atomic.LoadUint64(&p.diagMaxHandleNs)) / 1e6

	slow := false
	if dLost > 0 {
		slow = true
	}
	if dSendC > 0 && avgUs(dSendN, dSendC) > 5000.0 {
		slow = true
	}
	if dHandleC > 0 && avgUs(dHandleN, dHandleC) > 5000.0 {
		slow = true
	}

	ev := log.Info()
	if slow {
		ev = log.Warn()
	}

	ev.
		Bool("use_ringbuf", p.useRingbuf).
		Int("streams_open", len(p.streams)).
		Float64("chunks_per_sec", float64(dGot)/elapsed).
		Float64("chunks_handled_per_sec", float64(dHandled)/elapsed).
		Uint64("chunks_lost_5s", dLost).
		Float64("packets_per_sec", float64(dPkts)/elapsed).
		Str("bytes_written_per_sec", formatBytes(uint64(float64(dBytes)/elapsed))).
		Float64("parse_avg_us_5s", avgUs(dParseN, dParseC)).
		Float64("send_blocked_avg_us_5s", avgUs(dSendN, dSendC)).
		Float64("handle_avg_us_5s", avgUs(dHandleN, dHandleC)).
		Float64("parse_max_ms", parseMaxMs).
		Float64("send_blocked_max_ms", sendMaxMs).
		Float64("handle_max_ms", handleMaxMs).
		Msg("TlsPoller diagnostics")
}

func (p *TlsPoller) pollChunks(chunks chan<- *TracerTlsChunk) {
	if p.useRingbuf {
		p.pollChunksRingBuffer(chunks)
		return
	}
	p.pollChunksPerfBuffer(chunks)
}

func (p *TlsPoller) pollChunksPerfBuffer(chunks chan<- *TracerTlsChunk) {
	log.Info().Msg("Start polling for TLS events")

	p.chunksReader.SetDeadline(time.Unix(1, 0))
	var emptyRecord perf.Record
	for {
		err := p.chunksReader.ReadInto(&emptyRecord)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		} else if err != nil {
			log.Fatal().Err(err).Msg("Error reading chunks from TLS perf, aborting!")
			return
		}
	}
	p.chunksReader.SetDeadline(time.Time{})

	for {
		if time.Since(p.lastLostCheck) > time.Minute && p.lastLostChunks != p.lostChunks {
			log.Warn().Msg(fmt.Sprintf("Buffer is full, dropped %d TLS chunks", p.lostChunks-p.lastLostChunks))
			p.lastLostChunks = p.lostChunks
			p.lastLostCheck = time.Now()
		}

		err := p.chunksReader.ReadInto(&p.reusableRecord)
		if err != nil {
			close(chunks)

			if errors.Is(err, perf.ErrClosed) {
				log.Info().Err(err).Msg("TLS perf buffer is closed")
				return
			}

			log.Fatal().Err(err).Msg("Error reading chunks from TLS perf, aborting!")
			return
		}

		if p.reusableRecord.LostSamples != 0 {
			p.lostChunks += p.reusableRecord.LostSamples
			p.stats.ChunksLost += p.reusableRecord.LostSamples
			atomic.AddUint64(&p.diagChunksLost, p.reusableRecord.LostSamples)
			continue
		}

		p.stats.ChunksGot++
		atomic.AddUint64(&p.diagChunksGot, 1)

		raw := p.reusableRecord.RawSample

		parseStart := time.Now()
		chunk, perr := parseTracerTlsChunk(raw)
		dtParse := time.Since(parseStart)

		atomic.AddUint64(&p.diagParseNanos, uint64(dtParse))
		atomic.AddUint64(&p.diagParseCalls, 1)
		atomicMaxUint64(&p.diagMaxParseNs, uint64(dtParse))

		if perr != nil {
			log.Error().Err(perr).Msg("Error parsing TLS chunk (perf)")
			continue
		}

		sendStart := time.Now()
		chunks <- chunk
		dtSend := time.Since(sendStart)

		atomic.AddUint64(&p.diagSendNanos, uint64(dtSend))
		atomic.AddUint64(&p.diagSendCalls, 1)
		atomicMaxUint64(&p.diagMaxSendNs, uint64(dtSend))
	}
}

func (p *TlsPoller) pollChunksRingBuffer(chunks chan<- *TracerTlsChunk) {
	log.Info().Msg("Start polling for TLS events (ringbuf)")

	for {
		recAny, err := p.ringReader.Read()
		if err != nil {
			close(chunks)

			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info().Err(err).Msg("TLS ringbuf is closed")
				return
			}

			log.Fatal().Err(err).Msg("Error reading chunks from TLS ringbuf, aborting!")
			return
		}

		var raw []byte
		switch rec := recAny.(type) {
		case ringbuf.Record:
			raw = rec.RawSample
		case *ringbuf.Record:
			raw = rec.RawSample
		default:
			log.Fatal().Msgf("Unexpected TLS ringbuf record type: %T", recAny)
			return
		}

		p.stats.ChunksGot++
		atomic.AddUint64(&p.diagChunksGot, 1)

		parseStart := time.Now()
		chunk, perr := parseTracerTlsChunk(raw)
		dtParse := time.Since(parseStart)

		atomic.AddUint64(&p.diagParseNanos, uint64(dtParse))
		atomic.AddUint64(&p.diagParseCalls, 1)
		atomicMaxUint64(&p.diagMaxParseNs, uint64(dtParse))

		if perr != nil {
			log.Error().Err(perr).Msg("Error parsing TLS chunk (ringbuf)")
			continue
		}

		sendStart := time.Now()
		chunks <- chunk
		dtSend := time.Since(sendStart)

		atomic.AddUint64(&p.diagSendNanos, uint64(dtSend))
		atomic.AddUint64(&p.diagSendCalls, 1)
		atomicMaxUint64(&p.diagMaxSendNs, uint64(dtSend))
	}
}

func (p *TlsPoller) handleTlsChunk(chunk *TracerTlsChunk, streamsMap *TcpStreamMap) error {
	address := chunk.GetAddressPair()

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

	pktsGotDelta := stream.stats.PacketsGot
	p.stats.PacketsGot += pktsGotDelta
	stream.stats.PacketsGot = 0
	atomic.AddUint64(&p.diagPacketsGot, pktsGotDelta)

	dataWrittenDelta := stream.stats.DataWritten
	p.stats.DataWritten += dataWrittenDelta
	stream.stats.DataWritten = 0
	atomic.AddUint64(&p.diagBytesWritten, dataWrittenDelta)

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
