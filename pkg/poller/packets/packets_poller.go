package packets

import (
	"bufio"
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
	"github.com/go-errors/errors"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracer/internal/tai"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/decodedpacket"
	"github.com/kubeshark/tracer/pkg/rawpacket"
	"github.com/kubeshark/tracerproto/pkg/unixpacket"
	"github.com/rs/zerolog/log"
)

type perfReader interface {
	ReadInto(r *perf.Record) error
	Close() error
	SetDeadline(t time.Time)
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
	pkt  gopacket.Packet
	pkts *pktBuffer
}

// atomicMaxUint64 updates *addr to max(*addr, v).
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

// startWorkerPool starts worker goroutines for packet processing
func (p *PacketsPoller) startWorkerPool() {
	p.packetJobs = make(chan packetJob, runtime.NumCPU()*1024) // Buffered channel for jobs
	p.workerPool = make([]chan struct{}, runtime.NumCPU())

	for i := 0; i < runtime.NumCPU(); i++ {
		p.workerPool[i] = make(chan struct{})
		go func(workerID int) {
			defer close(p.workerPool[workerID])
			for job := range p.packetJobs {
				wStart := time.Now()
				p.gopacketWriter(job.pkt, p.dissectionDisabled)
				wDt := time.Since(wStart)

				atomic.AddUint64(&p.diagWriterCalls, 1)
				atomic.AddUint64(&p.diagWriterNanos, uint64(wDt))
				atomicMaxUint64(&p.diagMaxWriterNs, uint64(wDt))

				pktBufferPool.Put(job.pkts)
			}
		}(i)
	}
}

// stopWorkerPool stops all worker goroutines
func (p *PacketsPoller) stopWorkerPool() {
	close(p.packetJobs)
	// Wait for all workers to finish
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
	packetJobs chan packetJob
	workerPool []chan struct{}

	// Per-CPU packet maps to avoid contention
	pktsMaps []map[uint64]*pktBuffer // one map per CPU
	maxCPUs  int

	// Cleanup mechanism
	stopCleanup chan struct{} // Signal channel to stop cleanup goroutine

	// Original fields
	chunksReader    perfReader
	gopacketWriter  bpf.GopacketWriter
	rawPacketWriter rawpacket.RawPacketWriter
	receivedPackets uint64
	lostChunks      uint64
	lastLostChunks  uint64
	lastLostCheck   time.Time
	lastStatsTime   time.Time
	lastStats       PacketsPollerStats
	tai             tai.TaiInfo
	stats           PacketsPollerStats

	dissectionDisabled bool

	// --- Diagnostics output file (instead of logs) ---
	diagFilePath string
	diagFile     *os.File
	diagBuf      *bufio.Writer

	// --- Diagnostics counters (atomic; updated from poll goroutine + workers) ---
	diagDecodeNanos uint64
	diagDecodeCalls uint64
	diagMaxDecodeNs uint64

	diagWriterNanos uint64
	diagWriterCalls uint64
	diagMaxWriterNs uint64

	diagBlockedEnqueueNanos uint64
	diagBlockedEnqueueCalls uint64
	diagMaxBlockedEnqueueNs uint64
	diagMaxQueueLen         uint64
	diagHandleNanos         uint64
	diagHandleCalls         uint64
	diagMaxHandleNs         uint64
	lastDiagDecodeNanos     uint64
	lastDiagDecodeCalls     uint64
	lastDiagWriterNanos     uint64
	lastDiagWriterCalls     uint64
	lastDiagBlockedEnqNanos uint64
	lastDiagBlockedEnqCalls uint64
	lastDiagHandleNanos     uint64
	lastDiagHandleCalls     uint64
}

type PacketsPollerStats struct {
	ChunksGot      uint64
	ChunksHandled  uint64
	ChunksLost     uint64
	PacketsGot     uint64
	PacketsError   uint64
	BytesProcessed uint64
}

func (p *PacketsPoller) initDiagFile() {
	// If you want to override the path:
	//   export KUBESHARK_PACKETS_DIAG_FILE=/path/to/file.log
	// To disable:
	//   export KUBESHARK_PACKETS_DIAG_FILE=disabled
	path := os.Getenv("KUBESHARK_PACKETS_DIAG_FILE")
	switch path {
	case "disabled", "disable", "off", "0":
		return
	}
	if path == "" {
		path = fmt.Sprintf("/tmp/kubeshark_packets_poller_diag.%d.log", os.Getpid())
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		// We keep running without diagnostics if the file can't be created.
		log.Error().Err(err).Str("path", path).Msg("PacketsPoller: failed to open diagnostics file")
		return
	}

	p.diagFilePath = path
	p.diagFile = f
	p.diagBuf = bufio.NewWriterSize(f, 64*1024)

	// Header (one-time)
	_, _ = fmt.Fprintf(p.diagBuf, "# PacketsPoller diagnostics\n")
	_, _ = fmt.Fprintf(p.diagBuf, "# started=%s pid=%d\n", time.Now().UTC().Format(time.RFC3339Nano), os.Getpid())
	_, _ = fmt.Fprintf(p.diagBuf, "# fields: ts dissection_disabled chunks_per_sec chunks_handled_per_sec chunks_lost_5s packets_per_sec bytes_per_sec packet_errors_5s decode_avg_us_5s writer_avg_us_5s enqueue_blocked_avg_us_5s enqueue_blocked_events_5s handle_avg_us_5s decode_max_ms writer_max_ms enqueue_blocked_max_ms handle_max_ms max_queue_len\n")
	_ = p.diagBuf.Flush()
}

func (p *PacketsPoller) diagWriteLine(line string) {
	if p.diagBuf == nil {
		return
	}
	_, _ = p.diagBuf.WriteString(line)
	_ = p.diagBuf.WriteByte('\n')
	_ = p.diagBuf.Flush()
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

	poller.chunksReader, err = perf.NewReader(perfBuffer, perfBufferSize)
	if err != nil {
		return nil, errors.Wrap(err, 0)
	}

	// Diagnostics file (instead of periodic logs)
	poller.initDiagFile()

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

	// Close diagnostics file
	if p.diagBuf != nil {
		_ = p.diagBuf.Flush()
	}
	if p.diagFile != nil {
		_ = p.diagFile.Close()
		p.diagFile = nil
		p.diagBuf = nil
	}

	return p.chunksReader.Close()
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

// logPeriodicStats writes statistics every 5 seconds into the diagnostics file.
func (p *PacketsPoller) logPeriodicStats() {
	now := time.Now()
	elapsed := now.Sub(p.lastStatsTime).Seconds()
	if elapsed < 5.0 {
		return
	}

	// Throughput deltas (single goroutine)
	chunksDelta := p.stats.ChunksGot - p.lastStats.ChunksGot
	handledDelta := p.stats.ChunksHandled - p.lastStats.ChunksHandled
	lostDelta := p.stats.ChunksLost - p.lastStats.ChunksLost
	packetsDelta := p.stats.PacketsGot - p.lastStats.PacketsGot
	bytesDelta := p.stats.BytesProcessed - p.lastStats.BytesProcessed
	errorsDelta := p.stats.PacketsError - p.lastStats.PacketsError

	chunksPerSec := float64(chunksDelta) / elapsed
	handledPerSec := float64(handledDelta) / elapsed
	packetsPerSec := float64(packetsDelta) / elapsed
	bytesPerSec := float64(bytesDelta) / elapsed

	// Diag deltas (atomic)
	decodeN := atomic.LoadUint64(&p.diagDecodeNanos)
	decodeC := atomic.LoadUint64(&p.diagDecodeCalls)

	writerN := atomic.LoadUint64(&p.diagWriterNanos)
	writerC := atomic.LoadUint64(&p.diagWriterCalls)

	enqN := atomic.LoadUint64(&p.diagBlockedEnqueueNanos)
	enqC := atomic.LoadUint64(&p.diagBlockedEnqueueCalls)

	handleN := atomic.LoadUint64(&p.diagHandleNanos)
	handleC := atomic.LoadUint64(&p.diagHandleCalls)

	dDecodeN := decodeN - p.lastDiagDecodeNanos
	dDecodeC := decodeC - p.lastDiagDecodeCalls
	dWriterN := writerN - p.lastDiagWriterNanos
	dWriterC := writerC - p.lastDiagWriterCalls
	dEnqN := enqN - p.lastDiagBlockedEnqNanos
	dEnqC := enqC - p.lastDiagBlockedEnqCalls
	dHandleN := handleN - p.lastDiagHandleNanos
	dHandleC := handleC - p.lastDiagHandleCalls

	avgUs := func(nanos, calls uint64) float64 {
		if calls == 0 {
			return 0
		}
		return float64(nanos) / float64(calls) / 1000.0
	}

	// One line, easy diffing/grepping
	p.diagWriteLine(fmt.Sprintf(
		"ts=%s dissection_disabled=%t chunks_per_sec=%.2f chunks_handled_per_sec=%.2f chunks_lost_5s=%d packets_per_sec=%.2f bytes_per_sec=%s packet_errors_5s=%d decode_avg_us_5s=%.2f writer_avg_us_5s=%.2f enqueue_blocked_avg_us_5s=%.2f enqueue_blocked_events_5s=%d handle_avg_us_5s=%.2f decode_max_ms=%.3f writer_max_ms=%.3f enqueue_blocked_max_ms=%.3f handle_max_ms=%.3f max_queue_len=%d",
		now.UTC().Format(time.RFC3339Nano),
		p.dissectionDisabled,
		chunksPerSec,
		handledPerSec,
		lostDelta,
		packetsPerSec,
		formatBytes(uint64(bytesPerSec)),
		errorsDelta,
		avgUs(dDecodeN, dDecodeC),
		avgUs(dWriterN, dWriterC),
		avgUs(dEnqN, dEnqC),
		dEnqC,
		avgUs(dHandleN, dHandleC),
		float64(atomic.LoadUint64(&p.diagMaxDecodeNs))/1e6,
		float64(atomic.LoadUint64(&p.diagMaxWriterNs))/1e6,
		float64(atomic.LoadUint64(&p.diagMaxBlockedEnqueueNs))/1e6,
		float64(atomic.LoadUint64(&p.diagMaxHandleNs))/1e6,
		atomic.LoadUint64(&p.diagMaxQueueLen),
	))

	// Update last stats/time
	p.lastStats = p.stats
	p.lastStatsTime = now

	// Update last diag snapshots
	p.lastDiagDecodeNanos = decodeN
	p.lastDiagDecodeCalls = decodeC
	p.lastDiagWriterNanos = writerN
	p.lastDiagWriterCalls = writerC
	p.lastDiagBlockedEnqNanos = enqN
	p.lastDiagBlockedEnqCalls = enqC
	p.lastDiagHandleNanos = handleN
	p.lastDiagHandleCalls = handleC
}

func (p *PacketsPoller) poll() {
	// tracerPktsChunk is generated by bpf2go.
	go p.pollChunksPerfBuffer()
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
	const expectedChunkSize = 4148
	if len(data) != expectedChunkSize {
		pktBufferPool.Put(chunk)
		return false, fmt.Errorf("bad pkt chunk: size %v expected: %v", len(data), expectedChunkSize)
	}

	ptr := (*tracerPacketsData)(unsafe.Pointer(&data[0]))

	if ptr.Num == 0 && ptr.Last != 0 {
		// Fast path - packet can be processed without copying
		p.writeRawPacket(ptr.Timestamp, ptr.Data[:ptr.Len])
		if !p.dissectionDisabled {
			if _, err := p.writePacket(chunk, ptr); err != nil {
				pktBufferPool.Put(chunk)
				return false, fmt.Errorf("write packet failed: %w", err)
			}
		} else {
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

	dStart := time.Now()
	packet, parseErr := pktBuf.layerParser.CreatePacket(pkt, ptr.CgroupID, unixpacket.PacketDirection(ptr.Direction), ci, decodeOptions)
	dDt := time.Since(dStart)

	atomic.AddUint64(&p.diagDecodeCalls, 1)
	atomic.AddUint64(&p.diagDecodeNanos, uint64(dDt))
	atomicMaxUint64(&p.diagMaxDecodeNs, uint64(dDt))

	if parseErr != nil {
		log.Debug().Err(parseErr).Msg("DecodingLayerParser failed")
		p.stats.PacketsError++
		pktBufferPool.Put(pktBuf)
		// gopacket.NewPacket is recovers in case of errors, so we can return nil
		return false, nil
	}
	p.stats.PacketsGot++
	p.stats.BytesProcessed += uint64(len(pkt))

	// Track queue depth + enqueue blocking (only measure blocking when it actually blocks)
	qlen := len(p.packetJobs)
	atomicMaxUint64(&p.diagMaxQueueLen, uint64(qlen))

	job := packetJob{pkt: packet, pkts: pktBuf}
	select {
	case p.packetJobs <- job:
	default:
		t0 := time.Now()
		p.packetJobs <- job
		dt := time.Since(t0)

		atomic.AddUint64(&p.diagBlockedEnqueueCalls, 1)
		atomic.AddUint64(&p.diagBlockedEnqueueNanos, uint64(dt))
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
		// Write periodic stats to file every 5 seconds
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

		handleStart := time.Now()
		ok, herr := p.handlePktChunk(readBuffer)
		handleDt := time.Since(handleStart)

		atomic.AddUint64(&p.diagHandleCalls, 1)
		atomic.AddUint64(&p.diagHandleNanos, uint64(handleDt))
		atomicMaxUint64(&p.diagMaxHandleNs, uint64(handleDt))

		if herr != nil {
			log.Error().Err(herr).Msg("handle chunk failed")
		} else if ok {
			p.stats.ChunksHandled++
		}
	}
}
