package packets

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracer/internal/tai"
	"github.com/kubeshark/tracer/pkg/decodedpacket"
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

func makeChunk(tpd tracerPacketsData) []byte {
	const expectedChunkSize = 4148
	b := make([]byte, expectedChunkSize)
	h := (*tracerPacketsData)(unsafe.Pointer(&b[0]))
	*h = tpd
	return b
}

func newTestPoller(t *testing.T) *PacketsPoller {
	t.Helper()

	ether := gopacket.DecodersByLayerName["Ethernet"]
	if ether == nil {
		t.Fatalf("could not get Ethernet decoder")
	}

	p := &PacketsPoller{
		ethernetDecoder: ether,
		ethhdrContent:   make([]byte, 14),
		maxCPUs:         2,
		pktsMaps:        make([]map[uint64]*pktBuffer, 2),
		stopCleanup:     make(chan struct{}), // Initialize the cleanup channel
		tai:             tai.NewTaiInfo(),
		lastStatsTime:   time.Now(),
	}
	for i := 0; i < 2; i++ {
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

// ipv4Header returns a 20-byte IPv4 header with given proto and totalLen.
func ipv4Header(proto uint8, totalLen uint16) []byte {
	h := make([]byte, 20)
	h[0] = 0x45                // v4, IHL=5
	h[1] = 0x00                // DSCP/ECN
	h[2] = byte(totalLen >> 8) // total length
	h[3] = byte(totalLen & 0xff)
	h[6] = 0x40  // flags/frag offset (don't care)
	h[8] = 64    // TTL
	h[9] = proto // protocol
	return h
}

// tcpHeader builds a TCP header with dataOffset (in 32-bit words) and options payload.
func tcpHeader(dataOffset uint8, options []byte) []byte {
	hLen := int(dataOffset) * 4
	if hLen < 20 {
		hLen = 20
	}
	h := make([]byte, hLen)
	// data offset in upper nibble of byte 12
	h[12] = (dataOffset << 4) & 0xF0
	if hLen > 20 && len(options) > 0 {
		copy(h[20:], options)
	}
	return h
}

func tcpHeaderWithBadDataOffset(offset uint8) []byte {
	h := make([]byte, 20)
	h[12] = (offset << 4) & 0xF0 // invalid (<5)
	return h
}

func udpHeader() []byte {
	h := make([]byte, 8)
	// length=8
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

func TestPerfResetPathClearsBuffers(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	// Seed CPU 0 map with a buffer so we can verify it gets cleared
	p.pktsMaps[0][123] = &pktBuffer{layerParser: decodedpacket.NewLayerParser()}

	fr := &fakePerfReader{
		records: []perf.Record{
			// len==4 triggers the reset branch.
			{RawSample: []byte{0, 0, 0, 0}, CPU: 0},
		},
	}
	p.chunksReader = fr

	p.pollChunksPerfBuffer()

	if len(p.pktsMaps[0]) != 0 {
		t.Fatalf("expected CPU0 map to be cleared; got %d entries", len(p.pktsMaps[0]))
	}
}

func TestLostSamplesAccountingAndCleanup(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	// Seed CPU1 with an entry that should be cleared on loss
	p.pktsMaps[1][77] = &pktBuffer{layerParser: decodedpacket.NewLayerParser()}

	fr := &fakePerfReader{
		records: []perf.Record{
			{LostSamples: 5, CPU: 1},
		},
	}
	p.chunksReader = fr

	p.pollChunksPerfBuffer()

	if p.lostChunks != 5 || p.stats.ChunksLost != 5 {
		t.Fatalf("lost accounting wrong: lostChunks=%d ChunksLost=%d", p.lostChunks, p.stats.ChunksLost)
	}
	if len(p.pktsMaps[1]) != 0 {
		t.Fatalf("expected CPU1 map to be cleared after loss")
	}
}

func TestFastPathSingleChunk_NoGopacket(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	// capture raw writes
	done := make(chan struct{}, 1)
	p.rawPacketWriter = func(ts uint64, b []byte) {
		select {
		case done <- struct{}{}:
		default:
		}
	}

	td := tracerPacketsData{
		Timestamp: uint64(time.Now().UnixNano()),
		ID:        1,
		Len:       64,
		TotLen:    64,
		Num:       0,
		Last:      1,      // single-chunk fast path
		IPHdrType: 0x0800, // IPv4
		Direction: 0,
	}
	data := makeChunk(td)

	fr := &fakePerfReader{
		records: []perf.Record{
			{RawSample: data, CPU: 0},
		},
	}
	p.chunksReader = fr

	p.pollChunksPerfBuffer()

	if p.stats.ChunksHandled != 1 {
		t.Fatalf("expected 1 handled chunk, got %d", p.stats.ChunksHandled)
	}
	select {
	case <-done:
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("raw writer not called")
	}
}

func TestReassemblyTwoChunks_NoGopacket(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	gotLen := make(chan int, 1)
	p.rawPacketWriter = func(ts uint64, b []byte) {
		select {
		case gotLen <- len(b):
		default:
		}
	}

	id := uint64(42)

	first := tracerPacketsData{
		ID:        id,
		Len:       32,
		TotLen:    48,
		Num:       0,
		Last:      0,
		IPHdrType: 0x86dd, // IPv6
	}
	second := tracerPacketsData{
		ID:        id,
		Len:       16,
		TotLen:    48,
		Num:       1,
		Last:      1,
		IPHdrType: 0x86dd,
	}

	fr := &fakePerfReader{
		records: []perf.Record{
			{RawSample: makeChunk(first), CPU: 0},
			{RawSample: makeChunk(second), CPU: 0},
		},
	}
	p.chunksReader = fr

	p.pollChunksPerfBuffer()

	if p.receivedPackets != 1 {
		t.Fatalf("expected one reassembled packet, got %d", p.receivedPackets)
	}
	select {
	case n := <-gotLen:
		if want := int(first.Len + second.Len); n != want {
			t.Fatalf("expected reassembled length %d, got %d", want, n)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("raw writer not called")
	}
	if _, ok := p.pktsMaps[0][id]; ok {
		t.Fatalf("expected flow %d to be deleted after Last chunk", id)
	}
}

func TestWritePacket_DecodeMatrix(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	writerHit := make(chan struct{}, 1)
	p.gopacketWriter = func(pkt gopacket.Packet, dissectionDisabled bool) {
		select {
		case writerHit <- struct{}{}:
		default:
		}
	}

	buildPktBuf := func(b []byte) *pktBuffer {
		pb := &pktBuffer{layerParser: decodedpacket.NewLayerParser(), len: uint32(len(b))}
		copy(pb.buf[:len(b)], b)
		return pb
	}

	waitWriter := func(expect bool) error {
		if expect {
			select {
			case <-writerHit:
				return nil
			case <-time.After(60 * time.Millisecond):
				return fmt.Errorf("gopacketWriter not invoked")
			}
		} else {
			select {
			case <-writerHit:
				return fmt.Errorf("gopacketWriter invoked unexpectedly")
			case <-time.After(30 * time.Millisecond):
				return nil
			}
		}
	}

	type tcases struct {
		name        string
		packet      []byte
		wantOK      bool
		wantErr     bool
		errIncr     bool
		wantPktGot  bool
		writerFired bool
	}

	tests := []tcases{
		{
			name:        "IPv4/TCP valid minimal header (data offset = 5, no options)",
			packet:      makeIPv4Packet(6, tcpHeader(5, nil), nil),
			wantOK:      true,
			wantErr:     false,
			errIncr:     false,
			wantPktGot:  true,
			writerFired: true,
		},
		{
			name:        "IPv4/TCP invalid data offset < 5 -> parse error swallowed",
			packet:      makeIPv4Packet(6, tcpHeaderWithBadDataOffset(3), nil),
			wantOK:      false,
			wantErr:     false,
			errIncr:     true,
			writerFired: false,
		},
		{
			name: "IPv4/TCP invalid option length exceeds remaining (matches runtime error) -> swallowed",
			packet: func() []byte {
				opts := []byte{2, 49, 0xaa, 0xbb}
				tcp := tcpHeader(6, opts)
				return makeIPv4Packet(6, tcp, nil)
			}(),
			wantOK:      false,
			wantErr:     false,
			errIncr:     true,
			writerFired: false,
		},
		{
			name:        "IPv4/UDP valid minimal header",
			packet:      makeIPv4Packet(17, udpHeader(), nil),
			wantOK:      true,
			wantErr:     false,
			errIncr:     false,
			wantPktGot:  true,
			writerFired: true,
		},
		{
			name: "IPv4/TCP header length says 40 but buffer shorter (truncated) -> swallowed",
			packet: func() []byte {
				tcp := tcpHeader(10, make([]byte, 20))
				p := makeIPv4Packet(6, tcp, nil)
				return p[:20+30]
			}(),
			wantOK:      false,
			wantErr:     false,
			errIncr:     true,
			writerFired: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			beforeErr := p.stats.PacketsError
			beforeGot := p.stats.PacketsGot
			beforeBytes := p.stats.BytesProcessed

			buf := buildPktBuf(tc.packet)
			td := &tracerPacketsData{
				CgroupID:  0,
				Direction: 0,
				Len:       uint32(len(tc.packet)),
			}

			ok, err := p.writePacket(buf, td)

			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("want ok=%v, got %v", tc.wantOK, ok)
			}
			if tc.errIncr && p.stats.PacketsError != beforeErr+1 {
				t.Fatalf("PacketsError not incremented (before=%d, after=%d)", beforeErr, p.stats.PacketsError)
			}
			if !tc.errIncr && p.stats.PacketsError != beforeErr {
				t.Fatalf("PacketsError changed unexpectedly: before=%d after=%d", beforeErr, p.stats.PacketsError)
			}
			if tc.wantPktGot && p.stats.PacketsGot != beforeGot+1 {
				t.Fatalf("PacketsGot not incremented (before=%d, after=%d)", beforeGot, p.stats.PacketsGot)
			}
			if !tc.wantPktGot && p.stats.PacketsGot != beforeGot {
				t.Fatalf("PacketsGot changed unexpectedly: before=%d after=%d", beforeGot, p.stats.PacketsGot)
			}
			if tc.wantPktGot && p.stats.BytesProcessed <= beforeBytes {
				t.Fatalf("BytesProcessed not increased")
			}
			if err := waitWriter(tc.writerFired); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStartStopWorkerPool(t *testing.T) {
	p := newTestPoller(t)
	if err := p.Stop(); err != nil {
		t.Fatalf("stop returned error: %v", err)
	}
}

func TestLogPeriodicStats(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	p.stats.ChunksGot = 100
	p.stats.PacketsGot = 200
	p.stats.BytesProcessed = 1024 * 1024
	p.lastStatsTime = time.Now().Add(-6 * time.Second)

	p.logPeriodicStats()
	p.logPeriodicStats() // no-op when <5s elapsed
}

func TestHandlePktChunk_InvalidTCPOptionLength_FastPath(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	writerHit := make(chan struct{}, 1)
	p.gopacketWriter = func(pkt gopacket.Packet, dissectionDisabled bool) { writerHit <- struct{}{} }

	opts := []byte{2, 49, 0xaa, 0xbb}
	tcp := tcpHeader(6, opts)
	ipv4 := makeIPv4Packet(6, tcp, nil)

	beforeErr := p.stats.PacketsError

	td := tracerPacketsData{
		Timestamp: uint64(time.Now().UnixNano()),
		ID:        123,
		Len:       uint32(len(ipv4)),
		TotLen:    uint32(len(ipv4)),
		Num:       0,
		Last:      1,
		IPHdrType: 0x0800,
		Direction: 0,
	}
	copy(td.Data[:], ipv4)

	raw := makeChunk(td)

	chunk := pktBufferPool.Get().(*pktBuffer)
	chunk.reset()
	chunk.reusableRecord = perf.Record{
		RawSample:   raw,
		CPU:         0,
		LostSamples: 0,
	}

	ok, err := p.handlePktChunk(chunk)

	if !ok || err != nil {
		t.Fatalf("want ok=true, err=nil; got ok=%v err=%v", ok, err)
	}
	if p.stats.PacketsError != beforeErr+1 {
		t.Fatalf("expected PacketsError incremented by 1 (before=%d, after=%d)", beforeErr, p.stats.PacketsError)
	}
	select {
	case <-writerHit:
		t.Fatalf("writer must NOT be called on parse error")
	default:
	}
}

func TestFastPath_PayloadStart_MisalignedHTTP_Dropped(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	writerHit := make(chan struct{}, 1)
	p.gopacketWriter = func(pkt gopacket.Packet, dissectionDisabled bool) { writerHit <- struct{}{} }

	tcp := tcpHeader(5, nil)
	full := makeIPv4Packet(6, tcp, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	misaligned := full[20+20:]
	beforeErr := p.stats.PacketsError

	td := tracerPacketsData{
		Timestamp: uint64(time.Now().UnixNano()),
		ID:        9003,
		Len:       uint32(len(misaligned)),
		TotLen:    uint32(len(misaligned)),
		Num:       0, Last: 1, IPHdrType: 0x0800,
	}
	copy(td.Data[:], misaligned)

	raw := makeChunk(td)
	chunk := pktBufferPool.Get().(*pktBuffer)
	chunk.reset()
	chunk.reusableRecord = perf.Record{RawSample: raw, CPU: 0}

	ok, err := p.handlePktChunk(chunk)

	if !ok || err != nil {
		t.Fatalf("expected ok=true, err=nil; got ok=%v err=%v", ok, err)
	}
	if p.stats.PacketsError != beforeErr+1 {
		t.Fatalf("PacketsError not incremented on misaligned payload")
	}
	select {
	case <-writerHit:
		t.Fatalf("writer must NOT be called on misaligned payload")
	default:
	}
}

func TestReassembly_ParseError_ReturnsOkTrueAndNoWriter(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	writerHit := make(chan struct{}, 1)
	p.gopacketWriter = func(pkt gopacket.Packet, dissectionDisabled bool) { writerHit <- struct{}{} }

	opts := []byte{2, 49, 0xaa, 0xbb}
	tcp := tcpHeader(6, opts)
	bad := makeIPv4Packet(6, tcp, nil)

	id := uint64(42)
	firstLen := len(bad) / 2

	first := tracerPacketsData{
		ID:        id,
		Len:       uint32(firstLen),
		TotLen:    uint32(len(bad)),
		Num:       0,
		Last:      0,
		IPHdrType: 0x0800,
	}
	second := tracerPacketsData{
		ID:        id,
		Len:       uint32(len(bad) - firstLen),
		TotLen:    uint32(len(bad)),
		Num:       1,
		Last:      1,
		IPHdrType: 0x0800,
	}

	copy(first.Data[:first.Len], bad[:firstLen])
	copy(second.Data[:second.Len], bad[firstLen:])

	fr := &fakePerfReader{
		records: []perf.Record{
			{RawSample: makeChunk(first), CPU: 0},
			{RawSample: makeChunk(second), CPU: 0},
		},
	}
	p.chunksReader = fr

	beforeErr := p.stats.PacketsError

	p.pollChunksPerfBuffer()

	if p.stats.PacketsError != beforeErr+1 {
		t.Fatalf("PacketsError not incremented on parse error after reassembly")
	}
	select {
	case <-writerHit:
		t.Fatalf("writer must NOT be called on parse error")
	default:
	}
}

func TestWritePacket_RecordsExactTCPOptionsErrorStyle(t *testing.T) {
	p := newTestPoller(t)
	defer stopPoller(t, p)

	p.gopacketWriter = func(pkt gopacket.Packet, dissectionDisabled bool) {}

	opts := []byte{2, 49, 0xaa, 0xbb}
	tcp := tcpHeader(6, opts)
	ipv4 := makeIPv4Packet(6, tcp, nil)

	buf := &pktBuffer{layerParser: decodedpacket.NewLayerParser(), len: uint32(len(ipv4))}
	copy(buf.buf[:len(ipv4)], ipv4)

	td := &tracerPacketsData{Len: uint32(len(ipv4))}

	ok, err := p.writePacket(buf, td)
	if ok || err != nil {
		t.Fatalf("expect ok=false, err=nil from writePacket on parse error; got ok=%v err=%v", ok, err)
	}
	_ = strings.Contains
}
