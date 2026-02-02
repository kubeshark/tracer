package packets

import (
	"bytes"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracer/internal/tai"
)

type fakePerfReader struct {
	mu       sync.Mutex
	records  []perf.Record
	idx      int
	closed   bool
	deadline time.Time
}

func (f *fakePerfReader) ReadInto(r *perf.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.deadline.IsZero() {
		return os.ErrDeadlineExceeded
	}

	if f.closed {
		return perf.ErrClosed
	}
	if f.idx >= len(f.records) {
		f.closed = true
		return perf.ErrClosed
	}

	*r = f.records[f.idx]
	f.idx++
	return nil
}

func (f *fakePerfReader) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakePerfReader) SetDeadline(t time.Time) {
	f.mu.Lock()
	f.deadline = t
	f.mu.Unlock()
}

type fakeRingbufReader struct {
	mu      sync.Mutex
	samples [][]byte
	idx     int
	closed  bool
}

func (f *fakeRingbufReader) Read() (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return nil, ringbuf.ErrClosed
	}
	if f.idx >= len(f.samples) {
		f.closed = true
		return nil, ringbuf.ErrClosed
	}

	s := f.samples[f.idx]
	f.idx++
	return ringbuf.Record{RawSample: s}, nil
}

func (f *fakeRingbufReader) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func chunkWireSize() int {
	return int(unsafe.Sizeof(tracerPacketsData{}))
}

func makeChunk(tpd tracerPacketsData) []byte {
	b := make([]byte, chunkWireSize())
	h := (*tracerPacketsData)(unsafe.Pointer(&b[0]))
	*h = tpd
	return b
}

func makeChunkWithPadding(tpd tracerPacketsData, pad int) []byte {
	b := make([]byte, chunkWireSize()+pad)
	h := (*tracerPacketsData)(unsafe.Pointer(&b[0]))
	*h = tpd
	for i := chunkWireSize(); i < len(b); i++ {
		b[i] = 0xAA
	}
	return b
}

func makeRingbufSample(payload []byte, ts uint64, cgroup uint64, direction uint8) []byte {
	b := make([]byte, ringbufPktEventHdrSize+len(payload))
	h := (*ringbufPktEventHdr)(unsafe.Pointer(&b[0]))
	h.Timestamp = ts
	h.CgroupID = cgroup
	h.ID = 0
	h.Len = uint32(len(payload))
	h.IPHdrType = 0
	h.Direction = direction
	copy(b[ringbufPktEventHdrSize:], payload)
	return b
}

func newTestPoller(t *testing.T) *PacketsPoller {
	t.Helper()

	maxCPUs := 2
	p := &PacketsPoller{
		maxCPUs:       maxCPUs,
		pktsMaps:      make([]map[uint64]*pktBuffer, maxCPUs),
		pktsMapsMu:    make([]sync.Mutex, maxCPUs),
		stopPoll:      make(chan struct{}),
		stopCleanup:   make(chan struct{}),
		tai:           tai.NewTaiInfo(),
		lastLostCheck: time.Now(),
	}

	for i := 0; i < maxCPUs; i++ {
		p.pktsMaps[i] = make(map[uint64]*pktBuffer)
	}

	p.chunksReader = &fakePerfReader{}
	p.startWorkerPool()
	return p
}

func stopPoller(t *testing.T, p *PacketsPoller) {
	t.Helper()
	_ = p.Stop()
}

func ipv4Header(proto uint8, totalLen uint16) []byte {
	h := make([]byte, 20)
	h[0] = 0x45 // v4, IHL=5
	h[2] = byte(totalLen >> 8)
	h[3] = byte(totalLen & 0xff)
	h[6] = 0x40
	h[8] = 64
	h[9] = proto
	return h
}

// tcpHeader builds a TCP header with dataOffset (in 32-bit words) and options payload.
func tcpHeader(dataOffset uint8, options []byte) []byte {
	hLen := int(dataOffset) * 4
	if hLen < 20 {
		hLen = 20
	}
	h := make([]byte, hLen)
	h[12] = (dataOffset << 4) & 0xF0
	if hLen > 20 && len(options) > 0 {
		copy(h[20:], options)
	}
	return h
}

func tcpHeaderWithBadDataOffset(offset uint8) []byte {
	h := make([]byte, 20)
	h[12] = (offset << 4) & 0xF0
	return h
}

func udpHeader() []byte {
	h := make([]byte, 8)
	h[4], h[5] = 0, 8
	return h
}

// makeIPv4Packet concatenates ipHdr + l4Hdr (+payload if provided) and sets ip total length.
func makeIPv4Packet(l4proto uint8, l4 []byte, payload []byte) []byte {
	total := 20 + len(l4) + len(payload)
	ip := ipv4Header(l4proto, uint16(total))
	pkt := append(ip, l4...)
	if len(payload) > 0 {
		pkt = append(pkt, payload...)
	}
	return pkt
}

func waitUntil(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(1 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", msg)
}

func TestPerfResetMarkerClearsBuffers(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	pb := pktBufferPool.Get().(*pktBuffer)
	pb.reset()
	p.pktsMaps[0][123] = pb

	p.chunksReader = &fakePerfReader{
		records: []perf.Record{
			{RawSample: []byte{0, 0, 0, 0}, CPU: 0}, // reset marker
		},
	}

	p.pollPerf()

	if len(p.pktsMaps[0]) != 0 {
		t.Fatalf("expected CPU0 map cleared; got %d entries", len(p.pktsMaps[0]))
	}
	if len(p.pktsMaps[1]) != 0 {
		t.Fatalf("expected CPU1 map cleared; got %d entries", len(p.pktsMaps[1]))
	}
}

func TestPerfLostSamplesAccountingAndCleanup(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	pb := pktBufferPool.Get().(*pktBuffer)
	pb.reset()
	p.pktsMaps[1][77] = pb

	p.chunksReader = &fakePerfReader{
		records: []perf.Record{
			{LostSamples: 5, CPU: 1},
		},
	}

	p.pollPerf()

	if got := atomic.LoadUint64(&p.lostChunks); got != 5 {
		t.Fatalf("lostChunks wrong: got=%d want=5", got)
	}
	if got := atomic.LoadUint64(&p.stats.ChunksLost); got != 5 {
		t.Fatalf("stats.ChunksLost wrong: got=%d want=5", got)
	}
	if len(p.pktsMaps[1]) != 0 {
		t.Fatalf("expected CPU1 map cleared after loss")
	}
}

func TestPerfSingleChunk_RawWritten_NoDecodeWhenNoWriter(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	p.gopacketWriter = nil // disable decode/write

	pktBytes := makeIPv4Packet(17, udpHeader(), []byte{1, 2, 3})

	rawCh := make(chan []byte, 1)
	p.rawPacketWriter = func(ts uint64, b []byte) {
		cp := append([]byte(nil), b...)
		select {
		case rawCh <- cp:
		default:
		}
	}

	td := tracerPacketsData{
		Timestamp: uint64(time.Now().UnixNano()),
		CgroupID:  7,
		ID:        1,
		Len:       uint32(len(pktBytes)),
		TotLen:    uint32(len(pktBytes)),
		Num:       0,
		Last:      1,
		Direction: 0,
	}
	copy(td.Data[:], pktBytes)

	p.chunksReader = &fakePerfReader{
		records: []perf.Record{
			{RawSample: makeChunk(td), CPU: 0},
		},
	}

	p.pollPerf()

	if got := atomic.LoadUint64(&p.stats.ChunksHandled); got != 1 {
		t.Fatalf("expected 1 handled chunk, got %d", got)
	}

	select {
	case got := <-rawCh:
		if !bytes.Equal(got, pktBytes) {
			t.Fatalf("raw packet mismatch")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("raw writer not called")
	}

	if got := atomic.LoadUint64(&p.stats.PacketsGot); got != 0 {
		t.Fatalf("PacketsGot should stay 0 when no writer, got %d", got)
	}
	if got := atomic.LoadUint64(&p.stats.BytesProcessed); got != 0 {
		t.Fatalf("BytesProcessed should stay 0 when no writer, got %d", got)
	}
}

func TestPerfPaddedRawSampleAccepted(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	p.gopacketWriter = nil

	pktBytes := makeIPv4Packet(6, tcpHeader(5, nil), nil)

	rawCh := make(chan []byte, 1)
	p.rawPacketWriter = func(ts uint64, b []byte) {
		cp := append([]byte(nil), b...)
		select {
		case rawCh <- cp:
		default:
		}
	}

	td := tracerPacketsData{
		Timestamp: uint64(time.Now().UnixNano()),
		ID:        555,
		Len:       uint32(len(pktBytes)),
		TotLen:    uint32(len(pktBytes)),
		Num:       0,
		Last:      1,
		Direction: 0,
	}
	copy(td.Data[:], pktBytes)

	raw := makeChunkWithPadding(td, 4)

	p.chunksReader = &fakePerfReader{
		records: []perf.Record{
			{RawSample: raw, CPU: 0},
		},
	}

	p.pollPerf()

	select {
	case got := <-rawCh:
		if !bytes.Equal(got, pktBytes) {
			t.Fatalf("raw packet mismatch (padded trailer must be ignored)")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("raw writer not called")
	}
}

func TestPerfUndersizedRawSampleIgnored(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	rawCh := make(chan struct{}, 1)
	p.rawPacketWriter = func(ts uint64, b []byte) { rawCh <- struct{}{} }

	raw := make([]byte, chunkWireSize()-1) // too small

	p.chunksReader = &fakePerfReader{
		records: []perf.Record{
			{RawSample: raw, CPU: 0},
		},
	}

	p.pollPerf()

	if got := atomic.LoadUint64(&p.stats.ChunksGot); got != 1 {
		t.Fatalf("ChunksGot wrong: got=%d want=1", got)
	}
	if got := atomic.LoadUint64(&p.stats.ChunksHandled); got != 0 {
		t.Fatalf("ChunksHandled should remain 0 for undersized sample, got=%d", got)
	}
	select {
	case <-rawCh:
		t.Fatalf("raw writer must NOT be called for undersized sample")
	default:
	}
}

func TestPerfReassemblyTwoChunks_RawWrittenAndStateCleared(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	p.gopacketWriter = nil

	full := makeIPv4Packet(17, udpHeader(), []byte("hello world"))
	id := uint64(42)
	firstLen := len(full) / 2

	rawCh := make(chan []byte, 1)
	p.rawPacketWriter = func(ts uint64, b []byte) {
		cp := append([]byte(nil), b...)
		select {
		case rawCh <- cp:
		default:
		}
	}

	first := tracerPacketsData{
		Timestamp: uint64(time.Now().UnixNano()),
		ID:        id,
		Len:       uint32(firstLen),
		TotLen:    uint32(len(full)),
		Num:       0,
		Last:      0,
		Direction: 0,
	}
	second := tracerPacketsData{
		Timestamp: uint64(time.Now().UnixNano()),
		ID:        id,
		Len:       uint32(len(full) - firstLen),
		TotLen:    uint32(len(full)),
		Num:       1,
		Last:      1,
		Direction: 0,
	}

	copy(first.Data[:first.Len], full[:firstLen])
	copy(second.Data[:second.Len], full[firstLen:])

	p.chunksReader = &fakePerfReader{
		records: []perf.Record{
			{RawSample: makeChunk(first), CPU: 0},
			{RawSample: makeChunk(second), CPU: 0},
		},
	}

	p.pollPerf()

	if got := atomic.LoadUint64(&p.receivedPackets); got != 1 {
		t.Fatalf("expected 1 received packet, got %d", got)
	}

	select {
	case got := <-rawCh:
		if !bytes.Equal(got, full) {
			t.Fatalf("reassembled raw mismatch")
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatalf("raw writer not called")
	}

	if _, ok := p.pktsMaps[0][id]; ok {
		t.Fatalf("expected id=%d to be removed from assembly map after completion", id)
	}
}

func TestPerfOrderingMismatchDropsAssemblyState_NoRawWrite(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	p.gopacketWriter = nil

	full := makeIPv4Packet(17, udpHeader(), []byte("abcdef"))
	id := uint64(999)
	firstLen := len(full) / 2

	rawCh := make(chan struct{}, 1)
	p.rawPacketWriter = func(ts uint64, b []byte) { rawCh <- struct{}{} }

	first := tracerPacketsData{
		ID:     id,
		Len:    uint32(firstLen),
		TotLen: uint32(len(full)),
		Num:    0,
		Last:   0,
	}
	second := tracerPacketsData{
		ID:     id,
		Len:    uint32(len(full) - firstLen),
		TotLen: uint32(len(full)),
		Num:    2, // mismatch: expected 1
		Last:   1,
	}

	copy(first.Data[:first.Len], full[:firstLen])
	copy(second.Data[:second.Len], full[firstLen:])

	p.chunksReader = &fakePerfReader{
		records: []perf.Record{
			{RawSample: makeChunk(first), CPU: 0},
			{RawSample: makeChunk(second), CPU: 0},
		},
	}

	p.pollPerf()

	if got := atomic.LoadUint64(&p.receivedPackets); got != 0 {
		t.Fatalf("receivedPackets must stay 0 on ordering mismatch, got %d", got)
	}
	select {
	case <-rawCh:
		t.Fatalf("raw writer must NOT be called when reassembly is dropped")
	default:
	}
	if _, ok := p.pktsMaps[0][id]; ok {
		t.Fatalf("expected id=%d state dropped from map", id)
	}
}

func TestRingbufSingleRecord_RawWritten_NoDecodeWhenNoWriter(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	p.useRingbuf = true
	p.gopacketWriter = nil

	payload := makeIPv4Packet(17, udpHeader(), []byte{9, 9, 9})

	rawCh := make(chan []byte, 1)
	p.rawPacketWriter = func(ts uint64, b []byte) {
		cp := append([]byte(nil), b...)
		select {
		case rawCh <- cp:
		default:
		}
	}

	p.ringReader = &fakeRingbufReader{
		samples: [][]byte{
			makeRingbufSample(payload, uint64(time.Now().UnixNano()), 123, 0),
		},
	}

	p.pollRingbuf()

	if got := atomic.LoadUint64(&p.stats.ChunksHandled); got != 1 {
		t.Fatalf("expected 1 handled ringbuf record, got %d", got)
	}
	if got := atomic.LoadUint64(&p.receivedPackets); got != 1 {
		t.Fatalf("expected receivedPackets=1, got %d", got)
	}

	select {
	case got := <-rawCh:
		if !bytes.Equal(got, payload) {
			t.Fatalf("raw payload mismatch")
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatalf("raw writer not called")
	}
}

func TestRingbufDissectionDisabled_SkipsDecodeButStillWritesRaw(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	p.useRingbuf = true
	p.Pause() // dissection off

	var writerCalls uint64
	p.gopacketWriter = func(pkt gopacket.Packet, dissectionDisabled bool) {
		atomic.AddUint64(&writerCalls, 1)
	}

	payload := makeIPv4Packet(17, udpHeader(), []byte("hi"))

	rawCh := make(chan struct{}, 1)
	p.rawPacketWriter = func(ts uint64, b []byte) { rawCh <- struct{}{} }

	p.ringReader = &fakeRingbufReader{
		samples: [][]byte{
			makeRingbufSample(payload, uint64(time.Now().UnixNano()), 1, 0),
		},
	}

	p.pollRingbuf()

	select {
	case <-rawCh:
	default:
		t.Fatalf("raw writer must be called even when dissection is disabled")
	}

	if got := atomic.LoadUint64(&writerCalls); got != 0 {
		t.Fatalf("gopacketWriter must NOT be called when dissection is disabled (got %d)", got)
	}
	if got := atomic.LoadUint64(&p.stats.PacketsGot); got != 0 {
		t.Fatalf("PacketsGot must stay 0 when dissection is disabled (got %d)", got)
	}
}

func TestRingbufInvalidPacket_IncrementsPacketsError_NoWriter(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	p.useRingbuf = true

	var writerCalls uint64
	p.gopacketWriter = func(pkt gopacket.Packet, dissectionDisabled bool) {
		atomic.AddUint64(&writerCalls, 1)
	}

	// Intentionally invalid (too short to be a real IPv4 header)
	payload := []byte{0x45, 0x00}

	p.ringReader = &fakeRingbufReader{
		samples: [][]byte{
			makeRingbufSample(payload, uint64(time.Now().UnixNano()), 1, 0),
		},
	}

	beforeErr := atomic.LoadUint64(&p.stats.PacketsError)

	p.pollRingbuf()

	// Worker decode is async; wait for it to bump PacketsError.
	waitUntil(t, 250*time.Millisecond, func() bool {
		return atomic.LoadUint64(&p.stats.PacketsError) >= beforeErr+1
	}, "PacketsError not incremented")

	if got := atomic.LoadUint64(&writerCalls); got != 0 {
		t.Fatalf("writer must NOT be called on decode error (got %d)", got)
	}
}

func TestFlowShard_NormalizesEndpointsBothDirections(t *testing.T) {
	shards := 16

	udp := udpHeader()
	aToB := makeIPv4Packet(17, udp, nil)
	bToA := makeIPv4Packet(17, udp, nil)

	// set src/dst in the IPv4 header
	// A=1.2.3.4, B=5.6.7.8
	copy(aToB[12:16], []byte{1, 2, 3, 4})
	copy(aToB[16:20], []byte{5, 6, 7, 8})

	// reverse
	copy(bToA[12:16], []byte{5, 6, 7, 8})
	copy(bToA[16:20], []byte{1, 2, 3, 4})

	s1 := flowShard(aToB, 0, shards)
	s2 := flowShard(bToA, 0, shards)

	if s1 != s2 {
		t.Fatalf("expected same shard for both directions, got %d vs %d", s1, s2)
	}
}

func TestWorkerPool_PreservesOrderWithinSingleShard(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	const n = 128
	got := make(chan uint64, n)

	p.gopacketWriter = func(pkt gopacket.Packet, _ bool) {
		got <- pkt.Metadata().CaptureInfo.CgroupID
	}

	// Make all packets hash to the same shard (src/dst are zeroed in ipv4Header()).
	pktBytes := makeIPv4Packet(17, udpHeader(), []byte{0})
	shard := flowShard(pktBytes, 0, p.workerCount)

	for i := 0; i < n; i++ {
		pb := pktBufferPool.Get().(*pktBuffer)
		pb.reset()
		pb.cgroupID = uint64(i)
		pb.direction = 0
		pb.timestamp = 0
		pb.buf = append(pb.buf, pktBytes...)

		p.enqueuePacket(shard, pb)
	}

	for i := 0; i < n; i++ {
		select {
		case id := <-got:
			if id != uint64(i) {
				t.Fatalf("packet reordered within shard: got %d want %d", id, i)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("timed out waiting for packets")
		}
	}
}

func TestStopStopsWorkerPool(t *testing.T) {
	p := newTestPoller(t)
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}
}

func TestProcessPacket_DecodeMatrix(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	var writerCalls uint64
	p.gopacketWriter = func(pkt gopacket.Packet, dissectionDisabled bool) {
		atomic.AddUint64(&writerCalls, 1)
	}

	type tc struct {
		name        string
		packet      []byte
		wantWriter  bool
		wantPktGot  bool
		wantErrIncr bool
	}

	tests := []tc{
		{
			name:        "IPv4/TCP valid minimal header (data offset=5)",
			packet:      makeIPv4Packet(6, tcpHeader(5, nil), nil),
			wantWriter:  true,
			wantPktGot:  true,
			wantErrIncr: false,
		},
		{
			name:        "IPv4/TCP invalid data offset < 5",
			packet:      makeIPv4Packet(6, tcpHeaderWithBadDataOffset(3), nil),
			wantWriter:  false,
			wantPktGot:  false,
			wantErrIncr: true,
		},
		{
			name: "IPv4/TCP invalid option length exceeds remaining",
			packet: func() []byte {
				opts := []byte{2, 49, 0xaa, 0xbb}
				tcp := tcpHeader(6, opts)
				return makeIPv4Packet(6, tcp, nil)
			}(),
			wantWriter:  false,
			wantPktGot:  false,
			wantErrIncr: true,
		},
		{
			name:        "IPv4/UDP valid minimal header",
			packet:      makeIPv4Packet(17, udpHeader(), nil),
			wantWriter:  true,
			wantPktGot:  true,
			wantErrIncr: false,
		},
		{
			name: "IPv4/TCP header length says 40 but buffer shorter (truncated)",
			packet: func() []byte {
				tcp := tcpHeader(10, make([]byte, 20)) // 40-byte tcp hdr
				p := makeIPv4Packet(6, tcp, nil)
				return p[:20+30] // truncate tcp hdr
			}(),
			wantWriter:  false,
			wantPktGot:  false,
			wantErrIncr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beforeErr := atomic.LoadUint64(&p.stats.PacketsError)
			beforeGot := atomic.LoadUint64(&p.stats.PacketsGot)
			beforeBytes := atomic.LoadUint64(&p.stats.BytesProcessed)
			beforeWriter := atomic.LoadUint64(&writerCalls)

			pb := pktBufferPool.Get().(*pktBuffer)
			pb.reset()
			pb.cgroupID = 0
			pb.direction = 0
			pb.timestamp = 0
			pb.buf = append(pb.buf, tt.packet...)

			p.processPacket(pb)

			afterErr := atomic.LoadUint64(&p.stats.PacketsError)
			afterGot := atomic.LoadUint64(&p.stats.PacketsGot)
			afterBytes := atomic.LoadUint64(&p.stats.BytesProcessed)
			afterWriter := atomic.LoadUint64(&writerCalls)

			if tt.wantErrIncr && afterErr != beforeErr+1 {
				t.Fatalf("PacketsError not incremented: before=%d after=%d", beforeErr, afterErr)
			}
			if !tt.wantErrIncr && afterErr != beforeErr {
				t.Fatalf("PacketsError changed unexpectedly: before=%d after=%d", beforeErr, afterErr)
			}

			if tt.wantPktGot && afterGot != beforeGot+1 {
				t.Fatalf("PacketsGot not incremented: before=%d after=%d", beforeGot, afterGot)
			}
			if !tt.wantPktGot && afterGot != beforeGot {
				t.Fatalf("PacketsGot changed unexpectedly: before=%d after=%d", beforeGot, afterGot)
			}

			if tt.wantPktGot && afterBytes <= beforeBytes {
				t.Fatalf("BytesProcessed not increased on success")
			}
			if !tt.wantPktGot && afterBytes != beforeBytes {
				t.Fatalf("BytesProcessed changed unexpectedly on failure")
			}

			if tt.wantWriter && afterWriter != beforeWriter+1 {
				t.Fatalf("writer not called: before=%d after=%d", beforeWriter, afterWriter)
			}
			if !tt.wantWriter && afterWriter != beforeWriter {
				t.Fatalf("writer called unexpectedly: before=%d after=%d", beforeWriter, afterWriter)
			}
		})
	}
}
