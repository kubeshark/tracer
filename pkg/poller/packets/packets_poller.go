package packets

import (
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
	"github.com/kubeshark/tracer/internal/tai"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/decodedpacket"
	"github.com/kubeshark/tracer/pkg/rawpacket"
	"github.com/kubeshark/tracerproto/pkg/unixpacket"
	"github.com/rs/zerolog/log"
)

const (
	defaultPktBufCap = 64 * 1024
	maxRingbufPktLen = 256 * 1024
	workerQueueDepth = 1024

	stalePktCleanupInterval = 30 * time.Second
	stalePktThreshold       = 30 * time.Second

	diagInterval = 5 * time.Second
)

type ringbufPktEventHdr struct {
	Timestamp uint64
	CgroupID  uint64
	ID        uint64
	Len       uint32
	IPHdrType uint16
	Direction uint8
	_Pad      uint8
}

const ringbufPktEventHdrSize = int(unsafe.Sizeof(ringbufPktEventHdr{}))

type ringbufReader interface {
	Read() (any, error)
	Close() error
}

type ringbufReaderWrapper struct {
	r *ringbuf.Reader
}

func (w *ringbufReaderWrapper) Read() (any, error) { return w.r.Read() }
func (w *ringbufReaderWrapper) Close() error       { return w.r.Close() }

type perfReader interface {
	ReadInto(r *perf.Record) error
	Close() error
	SetDeadline(t time.Time)
}

// Must match C struct pkt (perf backend payload).
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
	id        uint64
	num       uint16
	buf       []byte
	timestamp uint64
	cgroupID  uint64
	direction uint8

	layerParser *decodedpacket.LayerParser
	reusableRec perf.Record
	firstSeen   time.Time
}

func (p *pktBuffer) reset() {
	p.id = 0
	p.num = 0
	p.timestamp = 0
	p.cgroupID = 0
	p.direction = 0
	p.firstSeen = time.Time{}
	p.buf = p.buf[:0]
}

var pktBufferPool = sync.Pool{
	New: func() interface{} {
		return &pktBuffer{
			buf:         make([]byte, 0, defaultPktBufCap),
			layerParser: decodedpacket.NewLayerParser(),
		}
	},
}

type PacketsPoller struct {
	// Readers
	chunksReader perfReader
	ringReader   ringbufReader
	useRingbuf   bool

	// Assembly state (perf only)
	pktsMaps []map[uint64]*pktBuffer
	maxCPUs  int

	// Worker pool (sharded)
	workers     []chan *pktBuffer
	workerCount int
	workersWg   sync.WaitGroup

	// Control
	stopPoll    chan struct{}
	stopCleanup chan struct{}

	// Writers
	gopacketWriter  bpf.GopacketWriter
	rawPacketWriter rawpacket.RawPacketWriter

	// Stats
	receivedPackets uint64
	lostChunks      uint64
	stats           PacketsPollerStats
	lastStats       PacketsPollerStats
	lastStatsTime   time.Time

	// Diagnostics
	diagBlockedEnqueueNanos  uint64
	diagBlockedEnqueueEvents uint64
	diagMaxBlockedEnqueueNs  uint64

	diagMaxQueueLen uint64
	diagDecodeNanos uint64
	diagDecodeCalls uint64
	diagMaxDecodeNs uint64

	diagWriterNanos uint64
	diagWriterCalls uint64
	diagMaxWriterNs uint64

	tai tai.TaiInfo
}

type PacketsPollerStats struct {
	ChunksGot      uint64
	ChunksHandled  uint64
	ChunksLost     uint64
	PacketsGot     uint64
	PacketsError   uint64
	BytesProcessed uint64
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

func NewPacketsPoller(
	perfBuffer *ebpf.Map,
	gopacketWriter bpf.GopacketWriter,
	rawPacketWriter rawpacket.RawPacketWriter,
	perfBufferSize int,
) (*PacketsPoller, error) {

	p := &PacketsPoller{
		gopacketWriter:  gopacketWriter,
		rawPacketWriter: rawPacketWriter,
		maxCPUs:         runtime.NumCPU(),
		pktsMaps:        make([]map[uint64]*pktBuffer, runtime.NumCPU()),
		stopPoll:        make(chan struct{}),
		stopCleanup:     make(chan struct{}),
		lastStatsTime:   time.Now(),
		tai:             tai.NewTaiInfo(),
	}

	for i := 0; i < p.maxCPUs; i++ {
		p.pktsMaps[i] = make(map[uint64]*pktBuffer)
	}

	if rr, err := ringbuf.NewReader(perfBuffer); err == nil {
		p.useRingbuf = true
		p.ringReader = &ringbufReaderWrapper{r: rr}
		log.Info().Msg("PacketsPoller: using ringbuf backend")
	} else {
		pr, err := perf.NewReader(perfBuffer, perfBufferSize)
		if err != nil {
			return nil, err
		}
		p.chunksReader = pr
		log.Info().Msg("PacketsPoller: using perf backend")
	}

	p.startWorkerPool()
	return p, nil
}

func (p *PacketsPoller) startWorkerPool() {
	p.workerCount = runtime.NumCPU()
	if p.workerCount < 1 {
		p.workerCount = 1
	}
	p.workers = make([]chan *pktBuffer, p.workerCount)

	for i := 0; i < p.workerCount; i++ {
		ch := make(chan *pktBuffer, workerQueueDepth)
		p.workers[i] = ch
		p.workersWg.Add(1)

		go func(c <-chan *pktBuffer) {
			defer p.workersWg.Done()
			for pkt := range c {
				p.processPacket(pkt)
			}
		}(ch)
	}
}

func (p *PacketsPoller) stopWorkerPool() {
	for _, ch := range p.workers {
		close(ch)
	}
	p.workersWg.Wait()
}

func (p *PacketsPoller) toUnixTime(ts uint64) time.Time {
	if ts == 0 {
		return time.Now()
	}
	// compat_get_uprobe_timestamp() returns TAI-ish time; adjust to Unix.
	return time.Unix(0, int64(ts)-int64(p.tai.GetTAIOffset()))
}

func (p *PacketsPoller) processPacket(pkt *pktBuffer) {
	// Fast bailouts
	if p.rawPacketWriter == nil && p.gopacketWriter == nil {
		pktBufferPool.Put(pkt)
		return
	}

	timestamp := p.toUnixTime(pkt.timestamp)

	// Raw writer (if enabled)
	if p.rawPacketWriter != nil {
		p.rawPacketWriter(uint64(timestamp.UnixNano()), pkt.buf)
	}

	// Gopacket writer (if enabled)
	if p.gopacketWriter == nil {
		pktBufferPool.Put(pkt)
		return
	}

	ci := gopacket.CaptureInfo{
		Timestamp:      timestamp,
		CaptureLength:  len(pkt.buf),
		Length:         len(pkt.buf),
		CaptureBackend: gopacket.CaptureBackendEbpf,
		CgroupID:       pkt.cgroupID,
		Direction:      unixpacket.PacketDirection(pkt.direction),
	}

	decodeOptions := gopacket.DecodeOptions{
		Lazy:                     false,
		NoCopy:                   true,
		SkipDecodeRecovery:       false,
		DecodeStreamsAsDatagrams: false,
	}

	if pkt.layerParser == nil {
		pkt.layerParser = decodedpacket.NewLayerParser()
	}

	decodeStart := time.Now()
	packet, err := pkt.layerParser.CreatePacket(
		pkt.buf,
		pkt.cgroupID,
		unixpacket.PacketDirection(pkt.direction),
		ci,
		decodeOptions,
	)
	dtDecode := time.Since(decodeStart)

	atomic.AddUint64(&p.diagDecodeCalls, 1)
	atomic.AddUint64(&p.diagDecodeNanos, uint64(dtDecode))
	atomicMaxUint64(&p.diagMaxDecodeNs, uint64(dtDecode))

	if err != nil {
		atomic.AddUint64(&p.stats.PacketsError, 1)
		pktBufferPool.Put(pkt)
		return
	}

	atomic.AddUint64(&p.stats.PacketsGot, 1)
	atomic.AddUint64(&p.stats.BytesProcessed, uint64(len(pkt.buf)))

	writerStart := time.Now()
	p.gopacketWriter(packet, false)
	dtWriter := time.Since(writerStart)

	atomic.AddUint64(&p.diagWriterCalls, 1)
	atomic.AddUint64(&p.diagWriterNanos, uint64(dtWriter))
	atomicMaxUint64(&p.diagMaxWriterNs, uint64(dtWriter))

	pktBufferPool.Put(pkt)
}

// flowShard hashes a packet into a worker shard. Goal: keep per-flow ordering
// while allowing parallelism across flows.
//
// This is intentionally light-weight: IP version + src/dst IPs.
func flowShard(pkt []byte, cgroupID uint64, shards int) int {
	if shards <= 1 || len(pkt) < 1 {
		return int(cgroupID % uint64(shards))
	}

	ipVer := pkt[0] >> 4
	h := uint64(1469598103934665603)

	hash := func(b byte) {
		h ^= uint64(b)
		h *= 1099511628211
	}

	hash(byte(ipVer))

	switch ipVer {
	case 4:
		if len(pkt) < 20 {
			break
		}
		for i := 12; i < 20; i++ {
			hash(pkt[i])
		}
	case 6:
		if len(pkt) < 40 {
			break
		}
		for i := 8; i < 40; i++ {
			hash(pkt[i])
		}
	}

	return int(h % uint64(shards))
}

func (p *PacketsPoller) enqueuePacket(shard int, pkt *pktBuffer) {
	ch := p.workers[shard]

	// Record queue pressure (best-effort)
	qlenAfter := len(ch) + 1
	atomicMaxUint64(&p.diagMaxQueueLen, uint64(qlenAfter))

	select {
	case ch <- pkt:
		atomic.AddUint64(&p.stats.ChunksHandled, 1)
	default:
		// backpressure: measure how long we block
		t0 := time.Now()
		ch <- pkt
		dt := time.Since(t0)

		atomic.AddUint64(&p.stats.ChunksHandled, 1)
		atomic.AddUint64(&p.diagBlockedEnqueueEvents, 1)
		atomic.AddUint64(&p.diagBlockedEnqueueNanos, uint64(dt))
		atomicMaxUint64(&p.diagMaxBlockedEnqueueNs, uint64(dt))
	}
}

func (p *PacketsPoller) resetPerfState() {
	for i := 0; i < p.maxCPUs; i++ {
		for _, pb := range p.pktsMaps[i] {
			pktBufferPool.Put(pb)
		}
		p.pktsMaps[i] = make(map[uint64]*pktBuffer)
	}
}

func (p *PacketsPoller) cleanupStalePackets() {
	ticker := time.NewTicker(stalePktCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			threshold := time.Now().Add(-stalePktThreshold)
			cleaned := 0

			for cpu := 0; cpu < p.maxCPUs; cpu++ {
				m := p.pktsMaps[cpu]
				for id, pb := range m {
					if !pb.firstSeen.IsZero() && pb.firstSeen.Before(threshold) {
						pktBufferPool.Put(pb)
						delete(m, id)
						cleaned++
					}
				}
			}

			if cleaned > 0 {
				log.Warn().Int("cleaned", cleaned).Msg("PacketsPoller: cleaned stale perf-assembly packets")
			}

		case <-p.stopCleanup:
			return
		}
	}
}

func (p *PacketsPoller) logPeriodicDiagnosticsLoop() {
	ticker := time.NewTicker(diagInterval)
	defer ticker.Stop()

	lastTime := time.Now()

	var lastStats PacketsPollerStats
	var lastBlkN, lastBlkE uint64
	var lastDecN, lastDecC uint64
	var lastWrN, lastWrC uint64

	avgUs := func(nanos, calls uint64) float64 {
		if calls == 0 {
			return 0
		}
		return float64(nanos) / float64(calls) / 1000.0
	}

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(lastTime).Seconds()
			if elapsed <= 0 {
				lastTime = now
				continue
			}

			curr := PacketsPollerStats{
				ChunksGot:      atomic.LoadUint64(&p.stats.ChunksGot),
				ChunksHandled:  atomic.LoadUint64(&p.stats.ChunksHandled),
				ChunksLost:     atomic.LoadUint64(&p.stats.ChunksLost),
				PacketsGot:     atomic.LoadUint64(&p.stats.PacketsGot),
				PacketsError:   atomic.LoadUint64(&p.stats.PacketsError),
				BytesProcessed: atomic.LoadUint64(&p.stats.BytesProcessed),
			}

			dChunksGot := curr.ChunksGot - lastStats.ChunksGot
			dChunksHandled := curr.ChunksHandled - lastStats.ChunksHandled
			dChunksLost := curr.ChunksLost - lastStats.ChunksLost
			dPkts := curr.PacketsGot - lastStats.PacketsGot
			dPktsErr := curr.PacketsError - lastStats.PacketsError
			dBytes := curr.BytesProcessed - lastStats.BytesProcessed

			blkN := atomic.LoadUint64(&p.diagBlockedEnqueueNanos)
			blkE := atomic.LoadUint64(&p.diagBlockedEnqueueEvents)

			decN := atomic.LoadUint64(&p.diagDecodeNanos)
			decC := atomic.LoadUint64(&p.diagDecodeCalls)

			wrN := atomic.LoadUint64(&p.diagWriterNanos)
			wrC := atomic.LoadUint64(&p.diagWriterCalls)

			dBlkN := blkN - lastBlkN
			dBlkE := blkE - lastBlkE
			dDecN := decN - lastDecN
			dDecC := decC - lastDecC
			dWrN := wrN - lastWrN
			dWrC := wrC - lastWrC

			lastBlkN, lastBlkE = blkN, blkE
			lastDecN, lastDecC = decN, decC
			lastWrN, lastWrC = wrN, wrC

			// Snapshot queue occupancy (safe to call len/cap concurrently)
			maxQLen := 0
			maxQCap := 0
			totalQLen := 0
			for _, ch := range p.workers {
				l := len(ch)
				c := cap(ch)
				totalQLen += l
				if l > maxQLen {
					maxQLen = l
					maxQCap = c
				}
			}

			// Max queue len observed during enqueue attempts in the last interval
			queueMaxSeen := atomic.SwapUint64(&p.diagMaxQueueLen, 0)

			// Global max latencies since start
			decodeMaxMs := float64(atomic.LoadUint64(&p.diagMaxDecodeNs)) / 1e6
			writerMaxMs := float64(atomic.LoadUint64(&p.diagMaxWriterNs)) / 1e6
			blockMaxMs := float64(atomic.LoadUint64(&p.diagMaxBlockedEnqueueNs)) / 1e6

			bytesPerSec := uint64(float64(dBytes) / elapsed)

			saturated := false
			if maxQCap > 0 && maxQLen*100/maxQCap >= 80 {
				saturated = true
			}
			if dBlkE > 0 {
				saturated = true
			}
			if dChunksLost > 0 {
				saturated = true
			}

			log.Info().
				Bool("use_ringbuf", p.useRingbuf).
				Int("workers", p.workerCount).
				Bool("saturated", saturated).
				Float64("chunks_per_sec", float64(dChunksGot)/elapsed).
				Float64("chunks_handled_per_sec", float64(dChunksHandled)/elapsed).
				Uint64("chunks_lost_5s", dChunksLost).
				Float64("packets_per_sec", float64(dPkts)/elapsed).
				Uint64("packets_error_5s", dPktsErr).
				Str("bytes_per_sec", formatBytes(bytesPerSec)).
				Int("worker_queue_max_len", maxQLen).
				Int("worker_queue_max_cap", maxQCap).
				Int("worker_queue_total_len", totalQLen).
				Uint64("worker_queue_max_seen_5s", queueMaxSeen).
				Uint64("enqueue_blocked_events_5s", dBlkE).
				Float64("enqueue_blocked_avg_us_5s", avgUs(dBlkN, dBlkE)).
				Float64("decode_avg_us_5s", avgUs(dDecN, dDecC)).
				Float64("writer_avg_us_5s", avgUs(dWrN, dWrC)).
				Float64("enqueue_blocked_max_ms", blockMaxMs).
				Float64("decode_max_ms", decodeMaxMs).
				Float64("writer_max_ms", writerMaxMs).
				Msg("PacketsPoller diagnostics")

			lastStats = curr
			lastTime = now

		case <-p.stopPoll:
			return
		}
	}
}

func (p *PacketsPoller) poll() {
	if p.useRingbuf {
		p.pollRingbuf()
	} else {
		p.pollPerf()
	}
}

func (p *PacketsPoller) pollRingbuf() {
	for {
		select {
		case <-p.stopPoll:
			return
		default:
		}

		recAny, err := p.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Fatal().Err(err).Msg("ringbuf read failed")
			return
		}

		var raw []byte
		switch rec := recAny.(type) {
		case ringbuf.Record:
			raw = rec.RawSample
		case *ringbuf.Record:
			raw = rec.RawSample
		default:
			log.Fatal().Msgf("Unexpected ringbuf record type: %T", recAny)
			return
		}

		atomic.AddUint64(&p.stats.ChunksGot, 1)

		// Optional reset marker (kept for compatibility)
		if len(raw) == 4 {
			p.resetPerfState()
			continue
		}

		if len(raw) < ringbufPktEventHdrSize {
			continue
		}

		hdr := (*ringbufPktEventHdr)(unsafe.Pointer(&raw[0]))
		pktLen := int(hdr.Len)

		if pktLen < 0 || pktLen > maxRingbufPktLen {
			continue
		}
		if ringbufPktEventHdrSize+pktLen > len(raw) {
			continue
		}

		payload := raw[ringbufPktEventHdrSize : ringbufPktEventHdrSize+pktLen]

		pkt := pktBufferPool.Get().(*pktBuffer)
		pkt.reset()

		if cap(pkt.buf) < len(payload) {
			// allocate a larger backing array once; reuse thereafter
			pkt.buf = make([]byte, 0, len(payload))
		}
		pkt.buf = pkt.buf[:len(payload)]
		copy(pkt.buf, payload)

		pkt.timestamp = hdr.Timestamp
		pkt.cgroupID = hdr.CgroupID
		pkt.direction = hdr.Direction

		atomic.AddUint64(&p.receivedPackets, 1)

		shard := flowShard(pkt.buf, pkt.cgroupID, p.workerCount)
		p.enqueuePacket(shard, pkt)
	}
}

func (p *PacketsPoller) pollPerf() {
	log.Info().Msg("PacketsPoller: start polling perf buffer")

	// Drain old samples
	p.chunksReader.SetDeadline(time.Unix(1, 0))
	var empty perf.Record
	for {
		if err := p.chunksReader.ReadInto(&empty); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			log.Fatal().Err(err).Msg("perf drain failed")
			return
		}
	}
	p.chunksReader.SetDeadline(time.Time{})

	expected := int(unsafe.Sizeof(tracerPacketsData{}))

	for {
		select {
		case <-p.stopPoll:
			return
		default:
		}

		var rec perf.Record
		if err := p.chunksReader.ReadInto(&rec); err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Fatal().Err(err).Msg("perf read failed")
			return
		}

		if rec.LostSamples > 0 {
			atomic.AddUint64(&p.lostChunks, rec.LostSamples)
			atomic.AddUint64(&p.stats.ChunksLost, rec.LostSamples)

			cpu := rec.CPU
			if cpu >= 0 && cpu < p.maxCPUs {
				for _, pb := range p.pktsMaps[cpu] {
					pktBufferPool.Put(pb)
				}
				p.pktsMaps[cpu] = make(map[uint64]*pktBuffer)
			}
			continue
		}

		raw := rec.RawSample
		atomic.AddUint64(&p.stats.ChunksGot, 1)

		// Reset marker
		if len(raw) == 4 {
			p.resetPerfState()
			continue
		}

		if len(raw) < expected {
			continue
		}

		ptr := (*tracerPacketsData)(unsafe.Pointer(&raw[0]))

		cpu := rec.CPU
		if cpu < 0 || cpu >= p.maxCPUs {
			continue
		}

		cpuMap := p.pktsMaps[cpu]
		pb, ok := cpuMap[ptr.ID]
		if !ok {
			pb = pktBufferPool.Get().(*pktBuffer)
			pb.reset()
			pb.id = ptr.ID
			pb.timestamp = ptr.Timestamp
			pb.cgroupID = ptr.CgroupID
			pb.direction = ptr.Direction
			pb.firstSeen = time.Now()
			cpuMap[ptr.ID] = pb
		}

		// Reassembly ordering check
		if ptr.Num != pb.num {
			pktBufferPool.Put(pb)
			delete(cpuMap, ptr.ID)
			continue
		}

		// Append payload chunk
		need := int(ptr.Len)
		if need < 0 || need > len(ptr.Data) {
			pktBufferPool.Put(pb)
			delete(cpuMap, ptr.ID)
			continue
		}

		if cap(pb.buf) < len(pb.buf)+need {
			newCap := len(pb.buf) + need
			nb := make([]byte, len(pb.buf), newCap)
			copy(nb, pb.buf)
			pb.buf = nb
		}
		pb.buf = pb.buf[:len(pb.buf)+need]
		copy(pb.buf[len(pb.buf)-need:], ptr.Data[:need])

		if ptr.Last != 0 {
			atomic.AddUint64(&p.receivedPackets, 1)
			delete(cpuMap, ptr.ID)

			shard := flowShard(pb.buf, pb.cgroupID, p.workerCount)
			p.enqueuePacket(shard, pb)
		} else {
			pb.num++
		}
	}
}

func (p *PacketsPoller) Start() {
	go p.poll()
	go p.cleanupStalePackets()

	go p.logPeriodicDiagnosticsLoop()
}

func (p *PacketsPoller) Stop() error {
	// Stop cleanup first (it touches pktsMaps)
	close(p.stopCleanup)

	// Stop poll loop + diagnostics loop (they select on this)
	close(p.stopPoll)

	// Close reader to unblock Read() / ReadInto()
	if p.useRingbuf {
		if p.ringReader != nil {
			_ = p.ringReader.Close()
		}
	} else {
		if p.chunksReader != nil {
			_ = p.chunksReader.Close()
		}
	}

	// Return any still-assembled perf packets to pool
	for i := 0; i < p.maxCPUs; i++ {
		for _, pb := range p.pktsMaps[i] {
			pktBufferPool.Put(pb)
		}
		p.pktsMaps[i] = nil
	}

	// Stop workers last (they release pktBuffers)
	p.stopWorkerPool()

	return nil
}

func (p *PacketsPoller) GetReceivedPackets() uint64 {
	return atomic.LoadUint64(&p.receivedPackets)
}

func (p *PacketsPoller) GetLostChunks() uint64 {
	return atomic.LoadUint64(&p.lostChunks)
}

func (p *PacketsPoller) GetExtendedStats() interface{} {
	return p.stats
}

<<<<<<< HEAD
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

	if elapsed < 5.0 {
		return
	}

	chunksDelta := p.stats.ChunksGot - p.lastStats.ChunksGot
	packetsDelta := p.stats.PacketsGot - p.lastStats.PacketsGot
	bytesDelta := p.stats.BytesProcessed - p.lastStats.BytesProcessed

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
	qMax := atomic.LoadUint64(&p.diagMaxQueueLen)

	blkN := atomic.LoadUint64(&p.diagBlockedEnqueueNanos)
	blkE := atomic.LoadUint64(&p.diagBlockedEnqueueEvents)

	decN := atomic.LoadUint64(&p.diagDecodeNanos)
	decC := atomic.LoadUint64(&p.diagDecodeCalls)

	wrN := atomic.LoadUint64(&p.diagWriterNanos)
	wrC := atomic.LoadUint64(&p.diagWriterCalls)

	cpN := atomic.LoadUint64(&p.diagCopyNanos)
	cpC := atomic.LoadUint64(&p.diagCopyCalls)

	dBlkN := blkN - p.lastDiagBlockedEnqueueNanos
	dBlkE := blkE - p.lastDiagBlockedEnqueueEvents
	dDecN := decN - p.lastDiagDecodeNanos
	dDecC := decC - p.lastDiagDecodeCalls
	dWrN := wrN - p.lastDiagWriterNanos
	dWrC := wrC - p.lastDiagWriterCalls
	dCpN := cpN - p.lastDiagCopyNanos
	dCpC := cpC - p.lastDiagCopyCalls

	p.lastDiagBlockedEnqueueNanos = blkN
	p.lastDiagBlockedEnqueueEvents = blkE
	p.lastDiagDecodeNanos = decN
	p.lastDiagDecodeCalls = decC
	p.lastDiagWriterNanos = wrN
	p.lastDiagWriterCalls = wrC
	p.lastDiagCopyNanos = cpN
	p.lastDiagCopyCalls = cpC

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
		Bool("use_ringbuf", p.useRingbuf).
		Int("job_queue_len", qLen).
		Int("job_queue_cap", qCap).
		Uint64("job_queue_max", qMax).
		Uint64("enqueue_blocked_events_5s", dBlkE).
		Float64("enqueue_blocked_avg_us_5s", avgUs(dBlkN, dBlkE)).
		Float64("copy_avg_us_5s", avgUs(dCpN, dCpC)).
		Float64("decode_avg_us_5s", avgUs(dDecN, dDecC)).
		Float64("writer_avg_us_5s", avgUs(dWrN, dWrC)).
		Float64("copy_max_ms", float64(atomic.LoadUint64(&p.diagMaxCopyNs))/1e6).
		Float64("decode_max_ms", float64(atomic.LoadUint64(&p.diagMaxDecodeNs))/1e6).
		Float64("writer_max_ms", float64(atomic.LoadUint64(&p.diagMaxWriterNs))/1e6).
		Float64("enqueue_blocked_max_ms", float64(atomic.LoadUint64(&p.diagMaxBlockedEnqueueNs))/1e6).
		Msg("PacketsPoller diagnostics")

	p.lastStats = p.stats
	p.lastStatsTime = now
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

	t0 := time.Now()
	p.gopacketWriter(packet, p.dissectionDisabled)
	dtWriter := time.Since(t0)

	atomic.AddUint64(&p.diagWriterNanos, uint64(dtWriter))
	atomic.AddUint64(&p.diagWriterCalls, 1)
	atomicMaxUint64(&p.diagMaxWriterNs, uint64(dtWriter))

	pktBufferPool.Put(pktBuf)
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

func (p *PacketsPoller) resetPerfState() {
	log.Info().Msg("Resetting plain packets buffer")
	for i := 0; i < p.maxCPUs; i++ {
		for _, pkts := range p.pktsMaps[i] {
			pktBufferPool.Put(pkts)
		}
		p.pktsMaps[i] = make(map[uint64]*pktBuffer)
	}
}

func (p *PacketsPoller) writePacketBytes(pktBuf *pktBuffer, ts uint64, cgroupID uint64, direction uint8, pkt []byte) (bool, error) {
	if p.gopacketWriter == nil {
		pktBufferPool.Put(pktBuf)
		return false, nil
	}

	var timestamp time.Time
	if ts != 0 {
		timestamp = time.Unix(0, int64(ts)-int64(p.tai.GetTAIOffset()))
	} else {
		timestamp = time.Now()
	}

	ci := gopacket.CaptureInfo{
		Timestamp:      timestamp,
		CaptureLength:  len(pkt),
		Length:         len(pkt),
		CaptureBackend: gopacket.CaptureBackendEbpf,
		CgroupID:       cgroupID,
		Direction:      unixpacket.PacketDirection(direction),
	}

	decodeOptions := gopacket.DecodeOptions{
		Lazy:                     false,
		NoCopy:                   true,
		SkipDecodeRecovery:       false,
		DecodeStreamsAsDatagrams: false,
	}

	decodeStart := time.Now()
	packet, parseErr := pktBuf.layerParser.CreatePacket(pkt, cgroupID, unixpacket.PacketDirection(direction), ci, decodeOptions)
	dtDecode := time.Since(decodeStart)

	atomic.AddUint64(&p.diagDecodeNanos, uint64(dtDecode))
	atomic.AddUint64(&p.diagDecodeCalls, 1)
	atomicMaxUint64(&p.diagMaxDecodeNs, uint64(dtDecode))

	if parseErr != nil {
		log.Debug().Err(parseErr).Msg("DecodingLayerParser failed")
		p.stats.PacketsError++
		pktBufferPool.Put(pktBuf)
		return false, nil
	}

	p.stats.PacketsGot++
	p.stats.BytesProcessed += uint64(len(pkt))

	t0 := time.Now()
	p.gopacketWriter(packet, p.dissectionDisabled)
	dtWriter := time.Since(t0)

	atomic.AddUint64(&p.diagWriterNanos, uint64(dtWriter))
	atomic.AddUint64(&p.diagWriterCalls, 1)
	atomicMaxUint64(&p.diagMaxWriterNs, uint64(dtWriter))

	pktBufferPool.Put(pktBuf)
	return true, nil
}

func (p *PacketsPoller) handleRingbufPacket(raw []byte) (bool, error) {
	if len(raw) < ringbufPktEventHdrSize {
		return false, fmt.Errorf("bad ringbuf pkt record: size %d < hdr %d", len(raw), ringbufPktEventHdrSize)
	}

	hdr := (*ringbufPktEventHdr)(unsafe.Pointer(&raw[0]))
	pktLen := int(hdr.Len)

	if pktLen < 0 || ringbufPktEventHdrSize+pktLen > len(raw) {
		return false, fmt.Errorf("bad ringbuf pkt record: hdrLen=%d pktLen=%d total=%d", ringbufPktEventHdrSize, pktLen, len(raw))
	}

	payload := raw[ringbufPktEventHdrSize : ringbufPktEventHdrSize+pktLen]

	// Copy to a reusable scratch buffer (consistent with NoCopy decoding assumption and record lifetime safety)
	t0 := time.Now()
	if cap(p.ringScratch) < pktLen {
		p.ringScratch = make([]byte, pktLen)
	}
	p.ringScratch = p.ringScratch[:pktLen]
	copy(p.ringScratch, payload)
	dtCopy := time.Since(t0)

	atomic.AddUint64(&p.diagCopyNanos, uint64(dtCopy))
	atomic.AddUint64(&p.diagCopyCalls, 1)
	atomicMaxUint64(&p.diagMaxCopyNs, uint64(dtCopy))

	p.receivedPackets++
	binary.BigEndian.PutUint16(p.ethhdrContent[12:14], hdr.IPHdrType)

	p.writeRawPacket(hdr.Timestamp, p.ringScratch)

	// Use a pooled pktBuffer just for its LayerParser reuse
	pktBuf := pktBufferPool.Get().(*pktBuffer)
	if pktBuf.layerParser == nil {
		pktBuf.layerParser = decodedpacket.NewLayerParser()
	}
	pktBuf.reset()

	ok, err := p.writePacketBytes(pktBuf, hdr.Timestamp, hdr.CgroupID, hdr.Direction, p.ringScratch)
	// writePacketBytes returns pktBuf to pool itself
	return ok, err
}

func (p *PacketsPoller) pollChunksRingBuffer() {
	log.Info().Msg("Start polling for packet events (ringbuf)")

	for {
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

		p.stats.ChunksGot++

		// reset marker (kept for compatibility)
		if len(rawSample) == 4 {
			p.resetPerfState()
			continue
		}

		ok, herr := p.handleRingbufPacket(rawSample)
		if herr != nil {
			log.Error().Err(herr).Msg("handle ringbuf packet failed")
			continue
		}
		if ok {
			p.stats.ChunksHandled++
		}
	}
}
=======
func (p *PacketsPoller) Pause()  {}
func (p *PacketsPoller) Resume() {}
>>>>>>> ca13101 (Address bottleneck issue)
