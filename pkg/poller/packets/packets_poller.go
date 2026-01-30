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
	maxRingbufPktLen = 64 * 1024
	workerQueueDepth = 4096

	stalePktCleanupInterval = 30 * time.Second
	stalePktThreshold       = 30 * time.Second

	statsInterval = 5 * time.Second
)

// Ringbuf variable-size packet record header (must match C struct pkt_event_hdr)
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
	pktsMaps   []map[uint64]*pktBuffer
	pktsMapsMu []sync.Mutex
	maxCPUs    int

	// Worker pool (sharded, preserves ordering within shard)
	workers     []chan *pktBuffer
	workerCount int
	workersWg   sync.WaitGroup

	// Control
	stopPoll    chan struct{}
	stopCleanup chan struct{}
	runWg       sync.WaitGroup

	// Writers
	gopacketWriter  bpf.GopacketWriter
	rawPacketWriter rawpacket.RawPacketWriter

	// Stats
	receivedPackets uint64
	lostChunks      uint64
	stats           PacketsPollerStats

	lastLostChunks uint64
	lastLostCheck  time.Time

	dissectionDisabled uint32

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

	maxCPUs := runtime.NumCPU()
	if maxCPUs < 1 {
		maxCPUs = 1
	}

	p := &PacketsPoller{
		gopacketWriter:  gopacketWriter,
		rawPacketWriter: rawPacketWriter,

		maxCPUs:    maxCPUs,
		pktsMaps:   make([]map[uint64]*pktBuffer, maxCPUs),
		pktsMapsMu: make([]sync.Mutex, maxCPUs),

		stopPoll:    make(chan struct{}),
		stopCleanup: make(chan struct{}),

		tai:           tai.NewTaiInfo(),
		lastLostCheck: time.Now(),
	}

	for i := 0; i < p.maxCPUs; i++ {
		p.pktsMaps[i] = make(map[uint64]*pktBuffer)
	}

	// Decide backend
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

func (p *PacketsPoller) Pause()  { atomic.StoreUint32(&p.dissectionDisabled, 1) }
func (p *PacketsPoller) Resume() { atomic.StoreUint32(&p.dissectionDisabled, 0) }

func (p *PacketsPoller) dissectionOff() bool {
	return atomic.LoadUint32(&p.dissectionDisabled) != 0
}

func (p *PacketsPoller) toUnixTime(ts uint64) time.Time {
	if ts == 0 {
		return time.Now()
	}
	// compat_get_uprobe_timestamp() returns TAI-ish time; adjust to Unix.
	return time.Unix(0, int64(ts)-int64(p.tai.GetTAIOffset()))
}

// IMPORTANT: raw writing is done in poll goroutine (single-threaded) to preserve master behavior.
func (p *PacketsPoller) writeRawPacket(bpfTimestamp uint64, pkt []byte) {
	if p.rawPacketWriter == nil {
		return
	}
	ts := p.toUnixTime(bpfTimestamp)
	p.rawPacketWriter(uint64(ts.UnixNano()), pkt)
}

func (p *PacketsPoller) processPacket(pkt *pktBuffer) {
	// By construction, we only enqueue when gopacketWriter != nil and dissection is ON.
	// Still keep this defensive.
	if p.gopacketWriter == nil {
		pktBufferPool.Put(pkt)
		return
	}

	timestamp := p.toUnixTime(pkt.timestamp)

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

	packet, err := pkt.layerParser.CreatePacket(
		pkt.buf,
		pkt.cgroupID,
		unixpacket.PacketDirection(pkt.direction),
		ci,
		decodeOptions,
	)
	if err != nil {
		atomic.AddUint64(&p.stats.PacketsError, 1)
		pktBufferPool.Put(pkt)
		return
	}

	atomic.AddUint64(&p.stats.PacketsGot, 1)
	atomic.AddUint64(&p.stats.BytesProcessed, uint64(len(pkt.buf)))

	p.gopacketWriter(packet, p.dissectionOff())

	pktBufferPool.Put(pkt)
}

// flowShard hashes a packet into a worker shard.
// Goal: keep per-flow ordering (including both directions) while allowing parallelism across flows.
//
// We normalize endpoints so A<->B maps to same shard in both directions.
func flowShard(pkt []byte, cgroupID uint64, shards int) int {
	if shards <= 1 || len(pkt) < 1 {
		return int(cgroupID % uint64(shards))
	}

	// FNV-1a
	h := uint64(1469598103934665603)
	hash := func(b byte) {
		h ^= uint64(b)
		h *= 1099511628211
	}

	ipVer := pkt[0] >> 4
	hash(byte(ipVer))

	var a, b []byte

	switch ipVer {
	case 4:
		if len(pkt) < 20 {
			return int(cgroupID % uint64(shards))
		}
		// src(12:16), dst(16:20)
		s := pkt[12:16]
		d := pkt[16:20]
		// normalize order
		if string(s) <= string(d) {
			a, b = s, d
		} else {
			a, b = d, s
		}
	case 6:
		if len(pkt) < 40 {
			return int(cgroupID % uint64(shards))
		}
		// src(8:24), dst(24:40)
		s := pkt[8:24]
		d := pkt[24:40]
		if string(s) <= string(d) {
			a, b = s, d
		} else {
			a, b = d, s
		}
	default:
		return int(cgroupID % uint64(shards))
	}

	for _, bb := range a {
		hash(bb)
	}
	for _, bb := range b {
		hash(bb)
	}

	return int(h % uint64(shards))
}

func (p *PacketsPoller) enqueuePacket(shard int, pkt *pktBuffer) {
	ch := p.workers[shard]
	select {
	case ch <- pkt:
	default:
		// backpressure: measure how long we block
		ch <- pkt
	}
}

func (p *PacketsPoller) resetPerfState() {
	for cpu := 0; cpu < p.maxCPUs; cpu++ {
		p.pktsMapsMu[cpu].Lock()
		for _, pb := range p.pktsMaps[cpu] {
			pktBufferPool.Put(pb)
		}
		p.pktsMaps[cpu] = make(map[uint64]*pktBuffer)
		p.pktsMapsMu[cpu].Unlock()
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
				p.pktsMapsMu[cpu].Lock()
				m := p.pktsMaps[cpu]
				for id, pb := range m {
					if !pb.firstSeen.IsZero() && pb.firstSeen.Before(threshold) {
						pktBufferPool.Put(pb)
						delete(m, id)
						cleaned++
					}
				}
				p.pktsMapsMu[cpu].Unlock()
			}

			if cleaned > 0 {
				log.Warn().Int("cleaned", cleaned).Msg("PacketsPoller: cleaned stale perf-assembly packets")
			}

		case <-p.stopCleanup:
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
			pkt.buf = make([]byte, 0, len(payload))
		}
		pkt.buf = pkt.buf[:len(payload)]
		copy(pkt.buf, payload)

		pkt.timestamp = hdr.Timestamp
		pkt.cgroupID = hdr.CgroupID
		pkt.direction = hdr.Direction

		atomic.AddUint64(&p.receivedPackets, 1)

		// Raw write is always allowed (even if dissection disabled), and serialized here.
		p.writeRawPacket(pkt.timestamp, pkt.buf)

		// Restore master behavior: do NOT decode / do NOT write gopacket when dissection is disabled.
		if p.dissectionOff() || p.gopacketWriter == nil {
			pktBufferPool.Put(pkt)
			atomic.AddUint64(&p.stats.ChunksHandled, 1)
			continue
		}

		shard := flowShard(pkt.buf, pkt.cgroupID, p.workerCount)
		p.enqueuePacket(shard, pkt)
		atomic.AddUint64(&p.stats.ChunksHandled, 1)
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
				p.pktsMapsMu[cpu].Lock()
				for _, pb := range p.pktsMaps[cpu] {
					pktBufferPool.Put(pb)
				}
				p.pktsMaps[cpu] = make(map[uint64]*pktBuffer)
				p.pktsMapsMu[cpu].Unlock()
			}

			// Keep the warning behavior (but periodic stats go to file)
			lost := atomic.LoadUint64(&p.lostChunks)
			if time.Since(p.lastLostCheck) > time.Minute && p.lastLostChunks != lost {
				log.Warn().Msgf("Perf buffer dropped %d chunks", lost-p.lastLostChunks)
				p.lastLostChunks = lost
				p.lastLostCheck = time.Now()
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

		// Handle perf chunk under CPU lock to avoid map races with cleanup.
		var completed *pktBuffer
		var completedTS uint64

		p.pktsMapsMu[cpu].Lock()
		cpuMap := p.pktsMaps[cpu]

		pb, ok := cpuMap[ptr.ID]
		if !ok {
			pb = pktBufferPool.Get().(*pktBuffer)
			pb.reset()
			pb.id = ptr.ID
			pb.num = 0
			pb.timestamp = ptr.Timestamp
			pb.cgroupID = ptr.CgroupID
			pb.direction = ptr.Direction
			pb.firstSeen = time.Now()
			cpuMap[ptr.ID] = pb
		}

		// Ordering check
		if ptr.Num != pb.num {
			// Drop assembly state for this packet ID
			delete(cpuMap, ptr.ID)
			p.pktsMapsMu[cpu].Unlock()
			pktBufferPool.Put(pb)
			atomic.AddUint64(&p.stats.ChunksHandled, 1)
			continue
		}

		need := int(ptr.Len)
		if need < 0 || need > len(ptr.Data) {
			delete(cpuMap, ptr.ID)
			p.pktsMapsMu[cpu].Unlock()
			pktBufferPool.Put(pb)
			atomic.AddUint64(&p.stats.ChunksHandled, 1)
			continue
		}

		// Append chunk
		if cap(pb.buf) < len(pb.buf)+need {
			newCap := len(pb.buf) + need
			nb := make([]byte, len(pb.buf), newCap)
			copy(nb, pb.buf)
			pb.buf = nb
		}
		oldLen := len(pb.buf)
		pb.buf = pb.buf[:oldLen+need]
		copy(pb.buf[oldLen:], ptr.Data[:need])

		if ptr.Last != 0 {
			atomic.AddUint64(&p.receivedPackets, 1)
			// detach from map before unlocking
			delete(cpuMap, ptr.ID)
			completed = pb
			completedTS = ptr.Timestamp
		} else {
			pb.num++
		}

		p.pktsMapsMu[cpu].Unlock()

		atomic.AddUint64(&p.stats.ChunksHandled, 1)

		if completed == nil {
			continue
		}

		// Raw write (serialized here)
		p.writeRawPacket(completedTS, completed.buf)

		// Restore master behavior: if dissection disabled, do not decode/write.
		if p.dissectionOff() || p.gopacketWriter == nil {
			pktBufferPool.Put(completed)
			continue
		}

		shard := flowShard(completed.buf, completed.cgroupID, p.workerCount)
		p.enqueuePacket(shard, completed)
	}
}

func (p *PacketsPoller) Start() {
	p.runWg.Add(3)

	go func() {
		defer p.runWg.Done()
		p.poll()
	}()

	go func() {
		defer p.runWg.Done()
		p.cleanupStalePackets()
	}()
}

func (p *PacketsPoller) Stop() error {
	// Signal goroutines
	close(p.stopCleanup)
	close(p.stopPoll)

	// Close readers to unblock Read/ReadInto
	if p.useRingbuf {
		if p.ringReader != nil {
			_ = p.ringReader.Close()
		}
	} else {
		if p.chunksReader != nil {
			_ = p.chunksReader.Close()
		}
	}

	// Wait for poll/cleanup/stats loops to exit (prevents enqueue-after-close panics)
	p.runWg.Wait()

	// Return any still-assembled perf packets to pool
	for cpu := 0; cpu < p.maxCPUs; cpu++ {
		p.pktsMapsMu[cpu].Lock()
		for _, pb := range p.pktsMaps[cpu] {
			pktBufferPool.Put(pb)
		}
		p.pktsMaps[cpu] = nil
		p.pktsMapsMu[cpu].Unlock()
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
