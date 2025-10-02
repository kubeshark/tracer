package packets

import (
	"encoding/binary"
	"fmt"
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
		return &pktBuffer{}
	},
}

// preWarmPool pre-warms the pktBuffer pool with some initial objects
func preWarmPool() {
	// Pre-allocate a few pktBuffer objects to reduce initial allocation pressure
	for i := 0; i < 10; i++ {
		pktBufferPool.Put(&pktBuffer{})
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
	id  uint64
	num uint16
	len uint32
	buf [64 * 1024]byte
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
	// LayerParser for efficient packet decoding
	layerParser []*decodedpacket.LayerParser
	// CPU-specific readers
	cpuReaders      map[int]*perf.Reader
	gopacketWriter  bpf.GopacketWriter
	rawPacketWriter rawpacket.RawPacketWriter
	// Per-CPU state (no locking needed)
	mtxs            []sync.Mutex
	pktsMap         []map[uint64]*pktBuffer // packet id to packet
	receivedPackets []uint64                // per-CPU received packets
	lostChunks      []uint64                // per-CPU lost chunks
	lastLostChunks  []uint64                // per-CPU last lost chunks
	lastLostCheck   []time.Time             // per-CPU last lost check
	tai             tai.TaiInfo
	stats           []PacketsPollerStats // per-CPU stats
	// Reusable records per CPU to avoid allocations
	reusableRecords map[int]*perf.Record
	pktBuf          []byte
}

type PacketsPollerStats struct {
	ChunksGot     uint64
	ChunksHandled uint64
	ChunksLost    uint64
	PacketsGot    uint64
	PacketsError  uint64
}

func NewPacketsPoller(
	perfBuffer *ebpf.Map,
	gopacketWriter bpf.GopacketWriter,
	rawPacketWriter rawpacket.RawPacketWriter,
	perfBufferSize int,
) (*PacketsPoller, error) {
	return NewPacketsPollerWithCPUs(perfBuffer, gopacketWriter, rawPacketWriter, perfBufferSize, nil)
}

func NewPacketsPollerWithCPUs(
	perfBuffer *ebpf.Map,
	gopacketWriter bpf.GopacketWriter,
	rawPacketWriter rawpacket.RawPacketWriter,
	perfBufferSize int,
	targetCPUs []int,
) (*PacketsPoller, error) {
	ethernetDecoder := gopacket.DecodersByLayerName["Ethernet"]
	if ethernetDecoder == nil {
		return nil, errors.New("Failed to get Ethernet decoder")
	}

	ethhdrContent := make([]byte, 14)

	// Default to all available CPUs if none specified
	if targetCPUs == nil || len(targetCPUs) == 0 {
		targetCPUs = make([]int, runtime.NumCPU())
		for i := range targetCPUs {
			targetCPUs[i] = i
		}
	}

	poller := &PacketsPoller{
		ethernetDecoder: ethernetDecoder,
		ethhdrContent:   ethhdrContent,
		cpuReaders:      make(map[int]*perf.Reader),
		gopacketWriter:  gopacketWriter,
		rawPacketWriter: rawPacketWriter,
		mtxs:            make([]sync.Mutex, len(targetCPUs)),
		pktsMap:         make([]map[uint64]*pktBuffer, len(targetCPUs)),
		receivedPackets: make([]uint64, len(targetCPUs)),
		lostChunks:      make([]uint64, len(targetCPUs)),
		lastLostChunks:  make([]uint64, len(targetCPUs)),
		lastLostCheck:   make([]time.Time, len(targetCPUs)),
		tai:             tai.NewTaiInfo(),
		stats:           make([]PacketsPollerStats, len(targetCPUs)),
		layerParser:     make([]*decodedpacket.LayerParser, len(targetCPUs)),
		reusableRecords: make(map[int]*perf.Record),
		pktBuf:          make([]byte, 0, 14+64*1024),
	}

	for i := range targetCPUs {
		poller.layerParser[i] = decodedpacket.NewLayerParser()
		poller.pktsMap[i] = make(map[uint64]*pktBuffer)
	}

	// Create a separate reader for each target CPU
	j := 0
	for range targetCPUs {
		for i := 0; i < 16; i++ { // TODO: align constant
			reader, err := perf.NewReader(perfBuffer, perfBufferSize)
			if err != nil {
				// Clean up already created readers
				for _, r := range poller.cpuReaders {
					r.Close()
				}
				return nil, fmt.Errorf("failed to create reader for CPU %d: %w", j, err)
			}

			poller.cpuReaders[j] = reader
			poller.reusableRecords[j] = &perf.Record{}
			j++
		}
	}

	// Pre-warm the pool to reduce initial allocation pressure
	preWarmPool()

	return poller, nil
}

func (p *PacketsPoller) Stop() error {
	var lastErr error
	for cpu, reader := range p.cpuReaders {
		if err := reader.Close(); err != nil {
			log.Error().Int("cpu", cpu).Err(err).Msg("Failed to close CPU reader")
			lastErr = err
		}
	}
	return lastErr
}

func (p *PacketsPoller) Start() {
	// Start a goroutine for each CPU-specific reader
	for cpu, reader := range p.cpuReaders {
		go p.pollChunksPerfBufferForCPU(cpu, reader)
	}
	go p.checkBuffers()
}

func (p *PacketsPoller) GetLostChunks() uint64 {
	var total uint64
	for _, lost := range p.lostChunks {
		total += lost
	}
	return total
}

func (p *PacketsPoller) GetReceivedPackets() uint64 {
	var total uint64
	for _, received := range p.receivedPackets {
		total += received
	}
	return total
}

func (p *PacketsPoller) GetExtendedStats() interface{} {
	// Aggregate stats from all CPUs
	var totalStats PacketsPollerStats
	for _, stats := range p.stats {
		totalStats.ChunksGot += stats.ChunksGot
		totalStats.ChunksHandled += stats.ChunksHandled
		totalStats.ChunksLost += stats.ChunksLost
		totalStats.PacketsGot += stats.PacketsGot
		totalStats.PacketsError += stats.PacketsError
	}
	return totalStats
}

func (p *PacketsPoller) GetCPUStats(cpu int) PacketsPollerStats {
	if cpu < 0 || cpu >= len(p.stats) {
		return PacketsPollerStats{}
	}
	return p.stats[cpu]
}

func (p *PacketsPoller) GetCPULostChunks(cpu int) uint64 {
	if cpu < 0 || cpu >= len(p.lostChunks) {
		return 0
	}
	return p.lostChunks[cpu]
}

func (p *PacketsPoller) GetCPUReceivedPackets(cpu int) uint64 {
	if cpu < 0 || cpu >= len(p.receivedPackets) {
		return 0
	}
	return p.receivedPackets[cpu]
}

func (p *PacketsPoller) poll() {
	// This method is kept for backward compatibility but is no longer used
	// The new implementation uses pollChunksPerfBufferForCPU directly
	log.Warn().Msg("Using deprecated poll() method. Consider using CPU-specific polling.")
}

func (p *PacketsPoller) handlePktChunk(chunk tracerPktChunk, pktsMap map[uint64]*pktBuffer, cpu int) (bool, error) {
	data := chunk.buf
	if len(data) == 4 {
		return false, nil // TODO: remove all the if branch and from eBPF code
		/*
			// zero packet to reset - return all pktBuffers to pool
			log.Info().Msg("Resetting plain packets buffer")
			for _, pkts := range pktsMap {
				pktBufferPool.Put(pkts)
			}
			p.pktsMap = make(map[uint64]*pktBuffer)
			return false, nil
		*/
	}
	const expectedChunkSize = 4148
	if len(data) != expectedChunkSize {
		return false, fmt.Errorf("bad pkt chunk: size %v expected: %v", len(data), expectedChunkSize)
	}

	ptr := (*tracerPacketsData)(unsafe.Pointer(&data[0]))

	pkts, ok := pktsMap[ptr.ID]
	if !ok {
		if ptr.Num != 0 {
			// packet is captured not from zero chunk
			// need to skip untill the next zero chunk
			log.Error().Msgf("packet is captured not from zero chunk: id: %v num: %v len: %v last: %v dir: %v tot_len: %v cpu: %v", ptr.ID, ptr.Num, ptr.Len, ptr.Last, ptr.Direction, ptr.TotLen, chunk.cpu) // TODO: remove
			return false, nil
		}
		// Get pktBuffer from pool and initialize it
		pkts = pktBufferPool.Get().(*pktBuffer)
		pkts.reset()
		pkts.id = ptr.ID
		pktsMap[ptr.ID] = pkts
	}
	if ptr.Num != pkts.num {
		// chunk was lost
		// TODO: Debug
		log.Error().Msgf("lost packet message id: (%v %v) num: (%v %v) len: %v last: %v dir: %v tot_len: %v cpu: %v", pkts.id, ptr.ID, pkts.num, ptr.Num, ptr.Len, ptr.Last, ptr.Direction, ptr.TotLen, chunk.cpu)
		return false, nil
	}

	copy(pkts.buf[pkts.len:], ptr.Data[:ptr.Len])
	pkts.len += uint32(ptr.Len)

	if ptr.Last != 0 {
		p.receivedPackets[cpu]++

		binary.BigEndian.PutUint16(p.ethhdrContent[12:14], ptr.IPHdrType)

		if p.rawPacketWriter != nil {
			p.rawPacketWriter(ptr.Timestamp, pkts.buf[:pkts.len])
		}
		if p.gopacketWriter != nil {
			totalLen := 14 + int(pkts.len)
			if cap(p.pktBuf) < totalLen {
				// If pooled buffer is too small, allocate a new one
				p.pktBuf = make([]byte, totalLen)
			} else {
				p.pktBuf = p.pktBuf[:totalLen]
			}
			copy(p.pktBuf[:14], p.ethhdrContent)
			copy(p.pktBuf[14:], pkts.buf[:pkts.len])

			// Calculate timestamp once
			var timestamp time.Time
			if ptr.Timestamp != 0 {
				timestamp = time.Unix(0, int64(ptr.Timestamp)-int64(p.tai.GetTAIOffset()))
			} else {
				timestamp = time.Now()
			}

			// Use LayerParser for efficient packet decoding
			ci := gopacket.CaptureInfo{
				Timestamp:      timestamp,
				CaptureLength:  len(p.pktBuf),
				Length:         len(p.pktBuf),
				CaptureBackend: gopacket.CaptureBackendEbpf,
			}

			decodeOptions := gopacket.DecodeOptions{
				Lazy:                     false,
				NoCopy:                   true,
				SkipDecodeRecovery:       false,
				DecodeStreamsAsDatagrams: false,
			}

			pkt, parseErr := p.layerParser[chunk.cpu].CreatePacket(p.pktBuf, ptr.CgroupID, unixpacket.PacketDirection(ptr.Direction), ci, decodeOptions)
			if parseErr != nil {
				log.Error().Err(parseErr).Msg("DecodingLayerParser failed")
				p.stats[cpu].PacketsError++
				return false, parseErr
			}
			p.stats[cpu].PacketsGot++
			p.gopacketWriter(pkt)
		}

		// Return pktBuffer to pool for reuse
		pktBufferPool.Put(pkts)
		delete(pktsMap, ptr.ID)
	} else {
		pkts.num++
	}

	// Cleanup pktsMap to avoid memory leak:
	// only bug in eBPF code can cause pktsMap overflow
	plen := len(pktsMap)
	log.Debug().Int("size", plen).Msg("packets map size")
	if plen > 1024 {
		log.Error().Int("size", plen).Int("cpu", cpu).Msg("packets map is too big, removig elements")
		for i, pkts := range pktsMap {
			pktBufferPool.Put(pkts)
			delete(pktsMap, i)
			if len(pktsMap) <= 1024 {
				break
			}
		}
	}

	return true, nil
}

func (p *PacketsPoller) pollChunksPerfBuffer() {
	// This method is deprecated and kept for backward compatibility
	// It now uses the CPU-specific readers
	log.Warn().Msg("Using deprecated pollChunksPerfBuffer() method. Consider using CPU-specific polling.")

	// Use the first available CPU reader as a fallback
	for cpu, reader := range p.cpuReaders {
		log.Info().Int("cpu", cpu).Msg("Using fallback single CPU reader")
		p.pollChunksPerfBufferForCPU(cpu, reader)
		return
	}

	log.Error().Msg("No CPU readers available")
}

func (p *PacketsPoller) pollChunksPerfBufferForCPU(num int, reader *perf.Reader) {
	log.Info().Int("num", num).Msg("Start polling for packet events")

	/*
		// remove all existing records
		reader.SetDeadline(time.Unix(1, 0))
		var emptyRecord perf.Record
		for {
			err := reader.ReadInto(&emptyRecord)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			} else if err != nil {
				log.Fatal().Int("cpu", cpu).Err(err).Msg("Error reading chunks from pkts perf, aborting!")
				return
			}
		}
		reader.SetDeadline(time.Time{})
	*/

	for {
		p.pollBufferForCPU(reader, p.reusableRecords[num])
	}
}

func (p *PacketsPoller) pollBufferForCPU(reader *perf.Reader, reusableRecord *perf.Record) {
	err := reader.ReadInto(reusableRecord)
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			log.Info().Err(err).Msg("perf buffer is closed")
			return
		}

		log.Fatal().Err(err).Msg("Error reading chunks from pkts perf, aborting!")
		return
	}
	cpu := reusableRecord.CPU
	if cpu < 0 || cpu >= len(p.mtxs) {
		log.Fatal().Int("cpu", cpu).Msg("Invalid CPU number")
		return
	}
	p.mtxs[cpu].Lock()
	defer p.mtxs[cpu].Unlock()

	if time.Since(p.lastLostCheck[cpu]) > time.Minute && p.lastLostChunks[cpu] != p.lostChunks[cpu] {
		log.Warn().Int("cpu", cpu).Msg(fmt.Sprintf("Buffer is full, dropped %d chunks", p.lostChunks[cpu]-p.lastLostChunks[cpu]))
		p.lastLostChunks[cpu] = p.lostChunks[cpu]
		p.lastLostCheck[cpu] = time.Now()
	}

	if reusableRecord.LostSamples != 0 {
		p.lostChunks[cpu] += reusableRecord.LostSamples
		p.stats[cpu].ChunksLost += reusableRecord.LostSamples
		// lost found, invalidate pktsMap
		p.pktsMap[cpu] = make(map[uint64]*pktBuffer)
		log.Error().Int("cpu", cpu).Int("lost", int(reusableRecord.LostSamples)).Int("remaining", int(reusableRecord.Remaining)).Msg("lost found, invalidating pktsMap") // XXX
		for i := 0; i < reusableRecord.Remaining; i++ {
			err := reader.ReadInto(reusableRecord)
			if err != nil {
				log.Fatal().Int("cpu", cpu).Err(err).Msg("Error reading chunks from pkts perf, aborting!")
				return
			}
		}
		return
	}
	p.stats[cpu].ChunksGot++

	chunk := tracerPktChunk{
		cpu: reusableRecord.CPU, // This should match the CPU we're reading from
		buf: reusableRecord.RawSample,
	}

	var ok bool
	if ok, err = p.handlePktChunk(chunk, p.pktsMap[cpu], cpu); err != nil {
		log.Error().Int("num", cpu).Int("cpu", cpu).Err(err).Msg("handle chunk failed")
	} else if ok {
		p.stats[cpu].ChunksHandled++
	}
}

func (p *PacketsPoller) checkBuffers() {
	// only bug in eBPF code can cause pktsMap overflow

	/*
		for {
			p.mtx.Lock()
			plen := len(p.pktsMap)
			p.mtx.Unlock()

			log.Debug().Int("size", plen).Msg("packets map size")
			if plen > 1024 {
				log.Error().Int("size", plen).Msg("packets map is too big, removig elements")
				p.mtx.Lock()
				for i, pkts := range p.pktsMap {
					pktBufferPool.Put(pkts)
					delete(p.pktsMap, i)
					if len(p.pktsMap) <= 1024 {
						break
					}
				}
				p.mtx.Unlock()
			}
			time.Sleep(5 * time.Second)
		}
	*/
}
