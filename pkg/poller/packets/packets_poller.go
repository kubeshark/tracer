package packets

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"sync"
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

// startWorkerPool starts 16 worker goroutines for packet processing
func (p *PacketsPoller) startWorkerPool() {
	p.packetJobs = make(chan packetJob, 16*1000) // Buffered channel for jobs
	p.workerPool = make([]chan struct{}, 16)     // 16 worker goroutines

	for i := 0; i < 16; i++ {
		p.workerPool[i] = make(chan struct{})
		go func(workerID int) {
			defer close(p.workerPool[workerID])
			for job := range p.packetJobs {
				p.gopacketWriter(job.pkt)
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

type tracerPktChunk struct {
	cpu int
	buf []byte
}

type pktBuffer struct {
	id             uint64
	num            uint16
	len            uint32
	buf            [64 * 1024]byte
	layerParser    *decodedpacket.LayerParser
	reusableRecord perf.Record
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
	// Reset the reusable record
	// p.reusableRecord = perf.Record{}
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
	// Original fields
	mtx             sync.Mutex
	chunksReader    *perf.Reader
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
	// pktBuf         []byte
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
		tai:             tai.NewTaiInfo(),
		lastStatsTime:   time.Now(),
		// pktBuf:          make([]byte, 0, 14+64*1024),
	}

	// Initialize per-CPU maps
	for i := 0; i < maxCPUs; i++ {
		poller.pktsMaps[i] = make(map[uint64]*pktBuffer)
	}

	poller.chunksReader, err = perf.NewReader(perfBuffer, perfBufferSize)
	//poller.chunksReader, err = perf.NewReaderWithOptions(perfBuffer, perfBufferSize, perf.ReaderOptions{
	//	Watermark: 65536 * 2, // TODO: align constant
	//})
	if err != nil {
		return nil, errors.Wrap(err, 0)
	}

	// Pre-warm the pool to reduce initial allocation pressure
	preWarmPool()

	// Start worker pool for packet processing
	poller.startWorkerPool()

	return poller, nil
}

func (p *PacketsPoller) Stop() error {
	p.stopWorkerPool()
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

func (p *PacketsPoller) GetExtendedStats() interface{} {
	return p.stats
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

		log.Info().
			Float64("chunks_per_sec", chunksPerSec).
			Float64("packets_per_sec", packetsPerSec).
			Str("bytes_per_sec", formatBytes(uint64(bytesPerSec))).
			Msg("PacketsPoller statistics")

		// Update last stats and time
		p.lastStats = p.stats
		p.lastStatsTime = now
	}
}

func (p *PacketsPoller) poll() {
	// tracerPktsChunk is generated by bpf2go.

	go p.pollChunksPerfBuffer()
	go p.checkBuffers()
}

func (p *PacketsPoller) handlePktChunk(chunk *pktBuffer) (bool, error) {
	// XXX p.mtx.Lock()
	// XXX defer p.mtx.Unlock()

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

		if p.rawPacketWriter != nil {
			/*
				var timestamp time.Time
				if ptr.Timestamp != 0 {
					timestamp = time.Unix(0, int64(ptr.Timestamp)-int64(p.tai.GetTAIOffset()))
				} else {
					timestamp = time.Now()
				}
			*/

			// p.rawPacketWriter(uint64(timestamp.UnixNano()), ptr.Data[:ptr.Len])
			p.rawPacketWriter(uint64(time.Now().UnixNano()), ptr.Data[:ptr.Len])
		}
		p.writePacket(chunk, ptr)
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

		if p.rawPacketWriter != nil {
			var timestamp time.Time
			if ptr.Timestamp != 0 {
				timestamp = time.Unix(0, int64(ptr.Timestamp)-int64(p.tai.GetTAIOffset()))
			} else {
				timestamp = time.Now()
			}

			p.rawPacketWriter(uint64(timestamp.UnixNano()), pkts.buf[:pkts.len])
		}
		p.writePacket(pkts, ptr)
		/*
			if p.gopacketWriter != nil {

				// Calculate timestamp once
				var timestamp time.Time
				if ptr.Timestamp != 0 {
					timestamp = time.Unix(0, int64(ptr.Timestamp)-int64(p.tai.GetTAIOffset()))
				} else {
					timestamp = time.Now()
				}

				// Use LayerParser for efficient packet decoding
				ci := gopacket.CaptureInfo{
					Timestamp: timestamp,
					// CaptureLength:  len(p.pktBuf),
					// Length:         len(p.pktBuf),
					CaptureLength:  int(pkts.len),
					Length:         int(pkts.len),
					CaptureBackend: gopacket.CaptureBackendEbpf,
				}

				decodeOptions := gopacket.DecodeOptions{
					Lazy:                     false,
					NoCopy:                   true,
					SkipDecodeRecovery:       false,
					DecodeStreamsAsDatagrams: false,
				}

				pkt, parseErr := pkts.layerParser.CreatePacket(pkts.buf[:pkts.len], ptr.CgroupID, unixpacket.PacketDirection(ptr.Direction), ci, decodeOptions)
				if parseErr != nil {
					log.Error().Err(parseErr).Msg("DecodingLayerParser failed")
					p.stats.PacketsError++
					return false, parseErr
				}
				p.stats.PacketsGot++
				// log.Info().Msgf("PacketsPoller: packet got: %v", pkt.Metadata().Length) // XXX

				// Send packet job to worker pool
				p.packetJobs <- packetJob{pkt: pkt, pkts: pkts}
				// log.Info().Msgf("PacketsPoller: packet written: %v", pkt.Metadata().Length) // XXX
			}
		*/

		// Return pktBuffer to pool for reuse
		// pktBufferPool.Put(pkts)
		delete(cpuMap, ptr.ID)
	} else {
		pkts.num++
	}

	return true, nil
}

func (p *PacketsPoller) writePacket(pktBuf *pktBuffer, ptr *tracerPacketsData) (bool, error) {
	if p.gopacketWriter == nil {
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
		Timestamp: timestamp,
		// CaptureLength:  len(p.pktBuf),
		// Length:         len(p.pktBuf),
		CaptureLength:  len(pkt),
		Length:         len(pkt),
		CaptureBackend: gopacket.CaptureBackendEbpf,
	}

	decodeOptions := gopacket.DecodeOptions{
		Lazy:                     false,
		NoCopy:                   true,
		SkipDecodeRecovery:       false,
		DecodeStreamsAsDatagrams: false,
	}

	packet, parseErr := pktBuf.layerParser.CreatePacket(pkt, ptr.CgroupID, unixpacket.PacketDirection(ptr.Direction), ci, decodeOptions)
	if parseErr != nil {
		log.Error().Err(parseErr).Msg("DecodingLayerParser failed")
		p.stats.PacketsError++
		return false, parseErr
	}
	p.stats.PacketsGot++
	p.stats.BytesProcessed += uint64(len(pkt))
	// log.Info().Msgf("PacketsPoller: packet got: %v", pkt.Metadata().Length) // XXX

	// Send packet job to worker pool
	p.packetJobs <- packetJob{pkt: packet, pkts: pktBuf}
	return true, nil
	// log.Info().Msgf("PacketsPoller: packet written: %v", pkt.Metadata().Length) // XXX
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

		// log.Info().Msgf("PacketsPoller: reading chunk") // XXX
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

		/*
			chunk := tracerPktChunk{
				cpu: readBuffer.reusableRecord.CPU,
				buf: readBuffer.reusableRecord.RawSample,
			}
		*/

		var ok bool
		if ok, err = p.handlePktChunk(readBuffer); err != nil {
			log.Error().Err(err).Msg("handle chunk failed")
		} else if ok {
			p.stats.ChunksHandled++
		}

	}
}

func (p *PacketsPoller) checkBuffers() {
	return // XXX
	// only bug in eBPF code can cause pktsMap overflow

	for {
		p.mtx.Lock()
		totalLen := 0
		for i := 0; i < p.maxCPUs; i++ {
			totalLen += len(p.pktsMaps[i])
		}
		p.mtx.Unlock()

		log.Debug().Int("size", totalLen).Msg("packets map size")
		if totalLen > 1024 {
			log.Error().Int("size", totalLen).Msg("packets map is too big, removing elements")
			p.mtx.Lock()
			for i := 0; i < p.maxCPUs; i++ {
				for id, pkts := range p.pktsMaps[i] {
					pktBufferPool.Put(pkts)
					delete(p.pktsMaps[i], id)
					totalLen--
					if totalLen <= 1024 {
						break
					}
				}
				if totalLen <= 1024 {
					break
				}
			}
			p.mtx.Unlock()
		}
		time.Sleep(5 * time.Second)
	}
}
