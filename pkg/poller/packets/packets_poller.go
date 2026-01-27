package packets

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/go-errors/errors"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/tracer/internal/tai"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/decodedpacket"
	"github.com/kubeshark/tracer/pkg/rawpacket"
	"github.com/kubeshark/tracerproto/pkg/unixpacket"
	"github.com/rs/zerolog/log"
)

type ringbufReader interface {
	Read() (any, error)
	Close() error
}

type ringbufReaderWrapper struct {
	r *ringbuf.Reader
}

func (w *ringbufReaderWrapper) Read() (any, error) {
	return w.r.Read()
}

func (w *ringbufReaderWrapper) Close() error {
	return w.r.Close()
}

type perfReader interface {
	ReadInto(r *perf.Record) error
	Close() error
	SetDeadline(t time.Time)
}

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

// Buffer pool for pktBuffer objects to avoid large allocations
var pktBufferPool = sync.Pool{
	New: func() interface{} {
		return &pktBuffer{
			layerParser: decodedpacket.NewLayerParser(),
		}
	},
}

// Worker pool for packet processing
type packetJob struct {
	seq  uint64
	pkt  gopacket.Packet
	pkts *pktBuffer
}

// startWorkerPool starts worker goroutines for packet processing
func (p *PacketsPoller) startWorkerPool() {
	shards := runtime.GOMAXPROCS(0)
	if shards < 1 {
		shards = 1
	}

	p.packetJobs = make([]chan packetJob, shards)
	p.workerPool = make([]chan struct{}, shards)

	for i := 0; i < shards; i++ {
		p.packetJobs[i] = make(chan packetJob, 1024)
		p.workerPool[i] = make(chan struct{})

		jobs := p.packetJobs[i]
		done := p.workerPool[i]

		go func() {
			defer close(done)
			for job := range jobs {
				if p.gopacketWriter != nil {
					t0 := time.Now()
					p.gopacketWriter(job.pkt, p.dissectionDisabled)
					dt := time.Since(t0)

					atomic.AddUint64(&p.diagWriterNanos, uint64(dt))
					atomic.AddUint64(&p.diagWriterCalls, 1)
					atomicMaxUint64(&p.diagMaxWriterNs, uint64(dt))
				}
				pktBufferPool.Put(job.pkts)
			}
		}()
	}
}

// stopWorkerPool stops all worker goroutines
func (p *PacketsPoller) stopWorkerPool() {
	for _, ch := range p.packetJobs {
		close(ch)
	}
	for _, done := range p.workerPool {
		<-done
	}
}

// preWarmPool pre-warms the pktBuffer pool with some initial objects
func preWarmPool() {
	// Pre-allocate a few pktBuffer objects to reduce initial allocation pressure
	for i := 0; i < 512; i++ {
		// Use pool's Get to create properly initialized pktBuffer (with layerParser)
		pkt := pktBufferPool.Get().(*pktBuffer)
		pktBufferPool.Put(pkt)
	}
}

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

type pktBuffer struct {
	id             uint64
	num            uint16
	len            uint32
	buf            [64 * 1024]byte
	layerParser    *decodedpacket.LayerParser
	reusableRecord perf.Record
	firstSeen      time.Time // Timestamp when buffer was first created for incomplete packet tracking
}

// reset resets the pktBuffer for reuse
func (p *pktBuffer) reset() {
	p.id = 0
	p.num = 0
	// Only clear the portion of the buffer that was actually used
	// This is more efficient than clearing the entire 64KB buffer
	if p.len > 0 {
		clear(p.buf[:p.len])
		p.len = 0
	}
}

type PacketsPoller struct {
	ethernetDecoder gopacket.Decoder
	ethhdrContent   []byte
	// Worker pool fields
	packetJobs []chan packetJob
	workerPool []chan struct{}
	// Per-CPU packet maps to avoid contention
	pktsMaps []map[uint64]*pktBuffer // one map per CPU
	maxCPUs  int
	// Cleanup mechanism
	stopCleanup chan struct{} // Signal channel to stop cleanup goroutine
	// Original fields
	// chunksReader is used when the pinned map is a PERF_EVENT_ARRAY.
	chunksReader perfReader
	// ringReader is used when the pinned map is a RINGBUF.
	ringReader           ringbufReader
	useRingbuf           bool
	forceCopySingleChunk bool
	gopacketWriter       bpf.GopacketWriter
	rawPacketWriter      rawpacket.RawPacketWriter
	receivedPackets      uint64
	lostChunks           uint64
	lastLostChunks       uint64
	lastLostCheck        time.Time
	lastStatsTime        time.Time
	lastStats            PacketsPollerStats
	tai                  tai.TaiInfo
	stats                PacketsPollerStats

	dissectionDisabled bool

	diagMaxQueueLen uint64

	diagBlockedEnqueueNanos  uint64
	diagBlockedEnqueueEvents uint64
	diagMaxBlockedEnqueueNs  uint64

	diagDecodeNanos uint64
	diagDecodeCalls uint64
	diagMaxDecodeNs uint64

	diagWriterNanos uint64
	diagWriterCalls uint64
	diagMaxWriterNs uint64

	lastDiagBlockedEnqueueNanos  uint64
	lastDiagBlockedEnqueueEvents uint64
	lastDiagDecodeNanos          uint64
	lastDiagDecodeCalls          uint64
	lastDiagWriterNanos          uint64
	lastDiagWriterCalls          uint64
}

type PacketsPollerStats struct {
	ChunksGot      uint64
	ChunksHandled  uint64
	ChunksLost     uint64
	PacketsGot     uint64
	PacketsError   uint64
	BytesProcessed uint64
}

func NewPacketsPoller(
	perfBuffer *ebpf.Map,
	gopacketWriter bpf.GopacketWriter,
	rawPacketWriter rawpacket.RawPacketWriter,
	perfBufferSize int,
) (*PacketsPoller, error) {
	var err error

	ethernetDecoder := gopacket.DecodersByLayerName["Ethernet"]
	if ethernetDecoder == nil {
		return nil, errors.New("Failed to get Ethernet decoder")
	}

	ethhdrContent := make([]byte, 14)

	// Get number of CPUs for per-CPU maps
	maxCPUs := runtime.NumCPU()

	poller := &PacketsPoller{
		ethernetDecoder: ethernetDecoder,
		ethhdrContent:   ethhdrContent,
		gopacketWriter:  gopacketWriter,
		rawPacketWriter: rawPacketWriter,
		maxCPUs:         maxCPUs,
		pktsMaps:        make([]map[uint64]*pktBuffer, maxCPUs),
		stopCleanup:     make(chan struct{}),
		tai:             tai.NewTaiInfo(),
		lastStatsTime:   time.Now(),

		dissectionDisabled: false,
	}

	// Initialize per-CPU maps
	for i := 0; i < maxCPUs; i++ {
		poller.pktsMaps[i] = make(map[uint64]*pktBuffer)
	}

	// Decide which userspace reader to use.
	if rr, rerr := ringbuf.NewReader(perfBuffer); rerr == nil {
		log.Info().Msg("Using ring buffer for packets polling")
		poller.useRingbuf = true
		poller.forceCopySingleChunk = true
		poller.ringReader = &ringbufReaderWrapper{r: rr}
		log.Info().Msg("Initialized ring buffer for packets polling")
	} else {
		log.Info().Msg("Using perf buffer for packets polling")
		poller.chunksReader, err = perf.NewReader(perfBuffer, perfBufferSize)
		if err != nil {
			return nil, errors.Wrap(
				fmt.Errorf("failed to create ringbuf reader: %v; failed to create perf reader: %w", rerr, err),
				0,
			)
		}
	}

	// Pre-warm the pool to reduce initial allocation pressure
	preWarmPool()

	// Start worker pool for packet processing
	poller.startWorkerPool()

	return poller, nil
}

func (p *PacketsPoller) Stop() error {
	// Signal cleanup goroutine to stop
	close(p.stopCleanup)

	// Clean up all pending buffers in pktsMaps before shutdown
	for i := 0; i < p.maxCPUs; i++ {
		for _, pkts := range p.pktsMaps[i] {
			pktBufferPool.Put(pkts)
		}
		p.pktsMaps[i] = nil
	}

	p.stopWorkerPool()
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

// cleanupStalePackets periodically removes incomplete packets that have been waiting too long
// this can happen only because of bug in bpf code
func (p *PacketsPoller) cleanupStalePackets() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	const staleThreshold = 30 * time.Second // Consider packets stale after 30 seconds

	for {
		select {
		case <-ticker.C:
			threshold := time.Now().Add(-staleThreshold)
			cleanedCount := 0
			loggedCount := 0

			for i := 0; i < p.maxCPUs; i++ {
				for id, pkts := range p.pktsMaps[i] {
					if pkts.firstSeen.Before(threshold) {
						// Log detailed info for first 10 cleaned packets
						if loggedCount < 10 {
							// XXX logStalePacketDetails(pkts, id, i)
							loggedCount++
						}
						pktBufferPool.Put(pkts)
						delete(p.pktsMaps[i], id)
						cleanedCount++
					}
				}
			}

			if cleanedCount > 0 {
				log.Warn().Int("cleaned", cleanedCount).Msg("Cleaned up stale incomplete packets")
			}
		case <-p.stopCleanup:
			return
		}
	}
}

func (p *PacketsPoller) Start() {
	go p.poll()
	go p.cleanupStalePackets() // Start background cleanup goroutine
}

func (p *PacketsPoller) GetLostChunks() uint64 {
	return p.lostChunks
}

func (p *PacketsPoller) GetReceivedPackets() uint64 {
	return p.receivedPackets
}

func (p *PacketsPoller) GetExtendedStats() interface{} {
	return p.stats
}

func (p *PacketsPoller) Pause() {
	p.dissectionDisabled = true
}

func (p *PacketsPoller) Resume() {
	p.dissectionDisabled = false
}

// formatBytes formats bytes into human readable format with K/M suffixes
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

// logPeriodicStats logs statistics every 5 seconds
func (p *PacketsPoller) logPeriodicStats() {
	now := time.Now()
	elapsed := now.Sub(p.lastStatsTime).Seconds()

	if elapsed >= 5.0 {
		// Calculate deltas
		chunksDelta := p.stats.ChunksGot - p.lastStats.ChunksGot
		packetsDelta := p.stats.PacketsGot - p.lastStats.PacketsGot
		bytesDelta := p.stats.BytesProcessed - p.lastStats.BytesProcessed

		// Calculate rates per second
		chunksPerSec := float64(chunksDelta) / elapsed
		packetsPerSec := float64(packetsDelta) / elapsed
		bytesPerSec := float64(bytesDelta) / elapsed

		log.Debug().
			Float64("chunks_per_sec", chunksPerSec).
			Float64("packets_per_sec", packetsPerSec).
			Str("bytes_per_sec", formatBytes(uint64(bytesPerSec))).
			Msg("PacketsPoller stats")

		qLen := 0
		qCap := 0
		for _, ch := range p.packetJobs {
			qLen += len(ch)
			qCap += cap(ch)
		}
		qMax := atomic.LoadUint64(&p.diagMaxQueueLen)

		blkN := atomic.LoadUint64(&p.diagBlockedEnqueueNanos)
		blkE := atomic.LoadUint64(&p.diagBlockedEnqueueEvents)
		decN := atomic.LoadUint64(&p.diagDecodeNanos)
		decC := atomic.LoadUint64(&p.diagDecodeCalls)
		wrN := atomic.LoadUint64(&p.diagWriterNanos)
		wrC := atomic.LoadUint64(&p.diagWriterCalls)

		dBlkN := blkN - p.lastDiagBlockedEnqueueNanos
		dBlkE := blkE - p.lastDiagBlockedEnqueueEvents
		dDecN := decN - p.lastDiagDecodeNanos
		dDecC := decC - p.lastDiagDecodeCalls
		dWrN := wrN - p.lastDiagWriterNanos
		dWrC := wrC - p.lastDiagWriterCalls

		p.lastDiagBlockedEnqueueNanos = blkN
		p.lastDiagBlockedEnqueueEvents = blkE
		p.lastDiagDecodeNanos = decN
		p.lastDiagDecodeCalls = decC
		p.lastDiagWriterNanos = wrN
		p.lastDiagWriterCalls = wrC

		avgUs := func(nanos, calls uint64) float64 {
			if calls == 0 {
				return 0
			}
			return float64(nanos) / float64(calls) / 1000.0
		}

		saturated := false
		if qCap > 0 && qLen*100/qCap >= 80 {
			saturated = true
		}
		if dBlkE > 0 {
			saturated = true
		}

		ev := log.Info()
		if saturated {
			ev = log.Warn()
		}

		ev.
			Int("job_queue_len", qLen).
			Int("job_queue_cap", qCap).
			Uint64("job_queue_max", qMax).
			Uint64("enqueue_blocked_events_5s", dBlkE).
			Float64("enqueue_blocked_avg_us_5s", avgUs(dBlkN, dBlkE)).
			Float64("decode_avg_us_5s", avgUs(dDecN, dDecC)).
			Float64("writer_avg_us_5s", avgUs(dWrN, dWrC)).
			Float64("decode_max_ms", float64(atomic.LoadUint64(&p.diagMaxDecodeNs))/1e6).
			Float64("writer_max_ms", float64(atomic.LoadUint64(&p.diagMaxWriterNs))/1e6).
			Float64("enqueue_blocked_max_ms", float64(atomic.LoadUint64(&p.diagMaxBlockedEnqueueNs))/1e6).
			Msg("PacketsPoller diagnostics")

		// Update last stats and time
		p.lastStats = p.stats
		p.lastStatsTime = now
	}
}

func (p *PacketsPoller) poll() {
	// tracerPktsChunk is generated by bpf2go.
	if p.useRingbuf {
		p.pollChunksRingBuffer()
		return
	}

	p.pollChunksPerfBuffer()
}

func (p *PacketsPoller) handlePktChunk(chunk *pktBuffer) (bool, error) {
	data := chunk.reusableRecord.RawSample
	cpu := chunk.reusableRecord.CPU
	if len(data) == 4 {
		// zero packet to reset - return all pktBuffers to pool
		log.Info().Msg("Resetting plain packets buffer")
		for i := 0; i < p.maxCPUs; i++ {
			for _, pkts := range p.pktsMaps[i] {
				pktBufferPool.Put(pkts)
			}
			p.pktsMaps[i] = make(map[uint64]*pktBuffer)
		}
		pktBufferPool.Put(chunk)
		return false, nil
	}

	expectedChunkSize := int(unsafe.Sizeof(tracerPacketsData{}))
	if len(data) < expectedChunkSize {
		pktBufferPool.Put(chunk)
		return false, fmt.Errorf("bad pkt chunk: size %v expected at least: %v", len(data), expectedChunkSize)
	}
	if len(data) != expectedChunkSize {
		data = data[:expectedChunkSize]
	}

	ptr := (*tracerPacketsData)(unsafe.Pointer(&data[0]))

	if ptr.Num == 0 && ptr.Last != 0 {
		// Fast path - single-chunk packet.
		if p.forceCopySingleChunk {
			if ptr.Len > uint32(len(chunk.buf)) {
				pktBufferPool.Put(chunk)
				return false, fmt.Errorf("packet too large for buffer: %d", ptr.Len)
			}
			copy(chunk.buf[:ptr.Len], ptr.Data[:ptr.Len])
			chunk.len = ptr.Len
			p.writeRawPacket(ptr.Timestamp, chunk.buf[:chunk.len])
		} else {
			p.writeRawPacket(ptr.Timestamp, ptr.Data[:ptr.Len])
		}
		if _, err := p.writePacket(chunk, ptr); err != nil {
			pktBufferPool.Put(chunk)
		}
		// packet will be released by writePacket
		return true, nil
	}

	if cpu < 0 || cpu >= p.maxCPUs {
		log.Fatal().Int("cpu", cpu).Msg("Invalid CPU number")
		pktBufferPool.Put(chunk)
		return false, nil
	}
	cpuMap := p.pktsMaps[cpu]

	pkts, ok := cpuMap[ptr.ID]
	if !ok {
		// Get pktBuffer from pool and initialize it
		pkts = pktBufferPool.Get().(*pktBuffer)
		// Safety: ensure layerParser exists for pre-warmed buffers created before initialization change
		if pkts.layerParser == nil {
			pkts.layerParser = decodedpacket.NewLayerParser()
		}
		pkts.reset()
		pkts.id = ptr.ID
		pkts.firstSeen = time.Now() // Track when incomplete packet was created
		cpuMap[ptr.ID] = pkts
	}
	if ptr.Num != pkts.num {
		// chunk was lost
		log.Debug().Msgf("lost packet message id: (%v %v) num: (%v %v) len: %v last: %v dir: %v tot_len: %v cpu: %v", pkts.id, ptr.ID, pkts.num, ptr.Num, ptr.Len, ptr.Last, ptr.Direction, ptr.TotLen, cpu)
		pktBufferPool.Put(chunk)
		return false, nil
	}

	copy(pkts.buf[pkts.len:], ptr.Data[:ptr.Len])
	pkts.len += uint32(ptr.Len)
	pktBufferPool.Put(chunk)

	if ptr.Last != 0 {
		p.receivedPackets++

		binary.BigEndian.PutUint16(p.ethhdrContent[12:14], ptr.IPHdrType)

		p.writeRawPacket(ptr.Timestamp, pkts.buf[:pkts.len])
		if !p.dissectionDisabled {
			if _, err := p.writePacket(pkts, ptr); err != nil {
				pktBufferPool.Put(pkts)
				return false, fmt.Errorf("write packet failed: %w", err)
			}
		} else {
			pktBufferPool.Put(pkts)
		}
		delete(cpuMap, ptr.ID)
	} else {
		pkts.num++
	}

	return true, nil
}

func (p *PacketsPoller) writePacket(pktBuf *pktBuffer, ptr *tracerPacketsData) (bool, error) {
	if p.gopacketWriter == nil {
		pktBufferPool.Put(pktBuf)
		return false, nil
	}

	// Calculate timestamp once
	var timestamp time.Time
	if ptr.Timestamp != 0 {
		timestamp = time.Unix(0, int64(ptr.Timestamp)-int64(p.tai.GetTAIOffset()))
	} else {
		timestamp = time.Now()
	}

	var pkt []byte
	if pktBuf.len > 0 {
		pkt = pktBuf.buf[:pktBuf.len]
	} else {
		pkt = ptr.Data[:ptr.Len]
	}

	// Use LayerParser for efficient packet decoding
	ci := gopacket.CaptureInfo{
		Timestamp:      timestamp,
		CaptureLength:  len(pkt),
		Length:         len(pkt),
		CaptureBackend: gopacket.CaptureBackendEbpf,
		CgroupID:       ptr.CgroupID,
		Direction:      unixpacket.PacketDirection(ptr.Direction),
	}

	decodeOptions := gopacket.DecodeOptions{
		Lazy:                     false,
		NoCopy:                   true,
		SkipDecodeRecovery:       false,
		DecodeStreamsAsDatagrams: false,
	}

	decodeStart := time.Now()
	packet, parseErr := pktBuf.layerParser.CreatePacket(pkt, ptr.CgroupID, unixpacket.PacketDirection(ptr.Direction), ci, decodeOptions)
	dtDecode := time.Since(decodeStart)

	atomic.AddUint64(&p.diagDecodeNanos, uint64(dtDecode))
	atomic.AddUint64(&p.diagDecodeCalls, 1)
	atomicMaxUint64(&p.diagMaxDecodeNs, uint64(dtDecode))

	if parseErr != nil {
		log.Debug().Err(parseErr).Msg("DecodingLayerParser failed")
		p.stats.PacketsError++
		pktBufferPool.Put(pktBuf)
		// gopacket.NewPacket is recovers in case of errors, so we can return nil
		return false, nil
	}
	p.stats.PacketsGot++
	p.stats.BytesProcessed += uint64(len(pkt))

	job := packetJob{pkt: packet, pkts: pktBuf}

	shard := int(flowHash(packet) % uint64(len(p.packetJobs)))
	q := p.packetJobs[shard]

	qlen := len(p.packetJobs)
	atomicMaxUint64(&p.diagMaxQueueLen, uint64(qlen))

	select {
	case q <- job:
	default:
		t0 := time.Now()
		q <- job
		dt := time.Since(t0)

		atomic.AddUint64(&p.diagBlockedEnqueueNanos, uint64(dt))
		atomic.AddUint64(&p.diagBlockedEnqueueEvents, 1)
		atomicMaxUint64(&p.diagMaxBlockedEnqueueNs, uint64(dt))
	}

	return true, nil
}

func (p *PacketsPoller) writeRawPacket(timestamp uint64, pkt []byte) {
	if p.rawPacketWriter == nil {
		return
	}
	var ts time.Time
	if timestamp != 0 {
		ts = time.Unix(0, int64(timestamp)-int64(p.tai.GetTAIOffset()))
	} else {
		ts = time.Now()
	}

	p.rawPacketWriter(uint64(ts.UnixNano()), pkt)
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
			log.Fatal().Err(err).Msg("Error reading chunks from pkts perf, aborting!")
			return
		}
	}
	p.chunksReader.SetDeadline(time.Time{})

	for {
		// Log periodic statistics every 5 seconds
		p.logPeriodicStats()

		if time.Since(p.lastLostCheck) > time.Minute && p.lastLostChunks != p.lostChunks {
			log.Warn().Msg(fmt.Sprintf("Buffer is full, dropped %d chunks", p.lostChunks-p.lastLostChunks))
			p.lastLostChunks = p.lostChunks
			p.lastLostCheck = time.Now()
		}

		// Get a pktBuffer from the pool to use its reusableRecord
		readBuffer := pktBufferPool.Get().(*pktBuffer)
		readBuffer.reset()

		err := p.chunksReader.ReadInto(&readBuffer.reusableRecord)
		if err != nil {
			// Return the buffer to pool before handling error
			pktBufferPool.Put(readBuffer)
			if errors.Is(err, perf.ErrClosed) {
				log.Info().Err(err).Msg("perf buffer is closed")
				return
			}

			log.Fatal().Err(err).Msg("Error reading chunks from pkts perf, aborting!")
			return
		}
		if readBuffer.reusableRecord.LostSamples != 0 {
			p.lostChunks += readBuffer.reusableRecord.LostSamples
			p.stats.ChunksLost += readBuffer.reusableRecord.LostSamples
			// Cleanup per-CPU packet state for the CPU that experienced the loss
			cpu := readBuffer.reusableRecord.CPU
			if cpu >= 0 && cpu < p.maxCPUs {
				for _, pkts := range p.pktsMaps[cpu] {
					pktBufferPool.Put(pkts)
				}
				p.pktsMaps[cpu] = make(map[uint64]*pktBuffer)
			}
			// Return buffer to pool before continuing
			pktBufferPool.Put(readBuffer)
			continue
		}
		p.stats.ChunksGot++

		var ok bool
		if ok, err = p.handlePktChunk(readBuffer); err != nil {
			log.Error().Err(err).Msg("handle chunk failed")
		} else if ok {
			p.stats.ChunksHandled++
		}
	}
}

func (p *PacketsPoller) pollChunksRingBuffer() {
	log.Info().Msg("Start polling for packet events (ringbuf)")

	for {
		// Log periodic statistics every 5 seconds
		p.logPeriodicStats()

		recAny, err := p.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info().Err(err).Msg("ringbuf is closed")
				return
			}
			log.Fatal().Err(err).Msg("Error reading chunks from pkts ringbuf, aborting!")
			return
		}

		var rawSample []byte
		switch rec := recAny.(type) {
		case ringbuf.Record:
			rawSample = rec.RawSample
		case *ringbuf.Record:
			rawSample = rec.RawSample
		default:
			log.Fatal().Msgf("Unexpected ringbuf record type: %T", recAny)
			return
		}

		// Get a pktBuffer from the pool and use it to hold the record while the
		// packet is being processed.
		readBuffer := pktBufferPool.Get().(*pktBuffer)
		readBuffer.reset()
		// Populate the reusableRecord fields expected by handlePktChunk.
		readBuffer.reusableRecord.RawSample = rawSample
		readBuffer.reusableRecord.CPU = 0
		readBuffer.reusableRecord.LostSamples = 0

		p.stats.ChunksGot++

		var ok bool
		if ok, err = p.handlePktChunk(readBuffer); err != nil {
			log.Error().Err(err).Msg("handle chunk failed")
		} else if ok {
			p.stats.ChunksHandled++
		}
	}
}

func hashBytes(h uint64, b []byte) uint64 {
	const prime = 1099511628211
	for _, c := range b {
		h ^= uint64(c)
		h *= prime
	}
	return h
}

func endpointLess(ipA [16]byte, portA uint16, ipB [16]byte, portB uint16) bool {
	if c := bytes.Compare(ipA[:], ipB[:]); c != 0 {
		return c < 0
	}
	return portA < portB
}

func flowHash(pkt gopacket.Packet) uint64 {
	ci := pkt.Metadata().CaptureInfo

	var srcIP, dstIP [16]byte
	var srcPort, dstPort uint16
	var proto uint8

	if nl := pkt.NetworkLayer(); nl != nil {
		switch ip := nl.(type) {
		case *layers.IPv4:
			copy(srcIP[12:], ip.SrcIP)
			copy(dstIP[12:], ip.DstIP)
			proto = uint8(ip.Protocol)
		case *layers.IPv6:
			copy(srcIP[:], ip.SrcIP)
			copy(dstIP[:], ip.DstIP)
			proto = uint8(ip.NextHeader)
		}
	}

	if tl := pkt.TransportLayer(); tl != nil {
		switch t := tl.(type) {
		case *layers.TCP:
			srcPort = uint16(t.SrcPort)
			dstPort = uint16(t.DstPort)
		case *layers.UDP:
			srcPort = uint16(t.SrcPort)
			dstPort = uint16(t.DstPort)
		case *layers.SCTP:
			srcPort = uint16(t.SrcPort)
			dstPort = uint16(t.DstPort)
		}
	}

	// Canonicalize endpoints so both directions map to the same shard
	if endpointLess(dstIP, dstPort, srcIP, srcPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	// FNV-1a-ish
	h := uint64(1469598103934665603)
	// include cgroup so same 5‑tuple in different pods doesn’t collide
	h ^= ci.CgroupID
	h *= 1099511628211

	h = hashBytes(h, srcIP[:])
	h ^= uint64(srcPort)
	h *= 1099511628211

	h = hashBytes(h, dstIP[:])
	h ^= uint64(dstPort)
	h *= 1099511628211

	h ^= uint64(proto)
	h *= 1099511628211

	return h
}
