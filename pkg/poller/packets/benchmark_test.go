package packets

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracer/internal/tai"
)

func BenchmarkQueueDepth(b *testing.B) {
	depths := []int{64, 128, 256, 512, 1024, 2048, 4096}

	for _, depth := range depths {
		b.Run(fmt.Sprintf("depth_%d", depth), func(b *testing.B) {
			benchmarkWithQueueDepth(b, depth)
		})
	}
}

func benchmarkWithQueueDepth(b *testing.B, queueDepth int) {
	numWorkers := runtime.NumCPU()
	workers := make([]chan *pktBuffer, numWorkers)
	var wg sync.WaitGroup

	var processed uint64
	var dropped uint64

	// Start workers
	for i := range numWorkers {
		ch := make(chan *pktBuffer, queueDepth)
		workers[i] = ch
		wg.Add(1)
		go func(c <-chan *pktBuffer) {
			defer wg.Done()
			for pkt := range c {
				atomic.AddUint64(&processed, 1)
				pktBufferPool.Put(pkt)
			}
		}(ch)
	}

	// Create test packet data
	testPacket := makeIPv4Packet(6, tcpHeader(5, nil), make([]byte, 100))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		shard := i % numWorkers
		pkt := pktBufferPool.Get().(*pktBuffer)
		pkt.reset()
		pkt.buf = append(pkt.buf, testPacket...)

		select {
		case workers[shard] <- pkt:
		default:
			atomic.AddUint64(&dropped, 1)
			pktBufferPool.Put(pkt)
		}
	}

	b.StopTimer()

	// Close workers and wait
	for _, ch := range workers {
		close(ch)
	}
	wg.Wait()

	droppedCount := atomic.LoadUint64(&dropped)
	processedCount := atomic.LoadUint64(&processed)
	dropRate := float64(droppedCount) / float64(b.N) * 100

	b.ReportMetric(dropRate, "%dropped")
	b.ReportMetric(float64(processedCount), "processed")
}

func BenchmarkPacketSizes(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096, 16384, 32768, 65536}

	for _, sz := range sizes {
		b.Run(fmt.Sprintf("size_%d", sz), func(b *testing.B) {
			benchmarkWithPacketSize(b, sz)
		})
	}
}

func benchmarkWithPacketSize(b *testing.B, payloadSize int) {
	const queueDepth = 1024

	numWorkers := runtime.NumCPU()
	workers := make([]chan *pktBuffer, numWorkers)
	var wg sync.WaitGroup

	var processed uint64
	var dropped uint64

	for i := range numWorkers {
		ch := make(chan *pktBuffer, queueDepth)
		workers[i] = ch
		wg.Add(1)
		go func(c <-chan *pktBuffer) {
			defer wg.Done()
			for pkt := range c {
				atomic.AddUint64(&processed, 1)
				pktBufferPool.Put(pkt)
			}
		}(ch)
	}

	testPacket := makeIPv4Packet(6, tcpHeader(5, nil), make([]byte, payloadSize))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		shard := i % numWorkers
		pkt := pktBufferPool.Get().(*pktBuffer)
		pkt.reset()
		pkt.buf = append(pkt.buf, testPacket...)

		select {
		case workers[shard] <- pkt:
		default:
			atomic.AddUint64(&dropped, 1)
			pktBufferPool.Put(pkt)
		}
	}

	b.StopTimer()

	for _, ch := range workers {
		close(ch)
	}
	wg.Wait()

	droppedCount := atomic.LoadUint64(&dropped)
	processedCount := atomic.LoadUint64(&processed)
	dropRate := float64(droppedCount) / float64(b.N) * 100

	b.ReportMetric(dropRate, "%dropped")
	b.ReportMetric(float64(processedCount), "processed")
	b.ReportMetric(float64(len(testPacket)), "pkt_bytes")
}

// BenchmarkQueueDepthWithLoad simulates high load scenarios
func BenchmarkQueueDepthWithLoad(b *testing.B) {
	depths := []int{128, 256, 512, 1024, 2048}

	for _, depth := range depths {
		b.Run(fmt.Sprintf("depth_%d", depth), func(b *testing.B) {
			benchmarkWithLoad(b, depth)
		})
	}
}

func benchmarkWithLoad(b *testing.B, queueDepth int) {
	numWorkers := runtime.NumCPU()
	workers := make([]chan *pktBuffer, numWorkers)
	var wg sync.WaitGroup

	var processed uint64
	var dropped uint64

	// Start workers with simulated processing delay
	for i := range numWorkers {
		ch := make(chan *pktBuffer, queueDepth)
		workers[i] = ch
		wg.Add(1)
		go func(c <-chan *pktBuffer) {
			defer wg.Done()
			for pkt := range c {
				time.Sleep(50 * time.Microsecond)
				atomic.AddUint64(&processed, 1)
				pktBufferPool.Put(pkt)
			}
		}(ch)
	}

	testPacket := makeIPv4Packet(6, tcpHeader(5, nil), make([]byte, 100))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		shard := i % numWorkers
		pkt := pktBufferPool.Get().(*pktBuffer)
		pkt.reset()
		pkt.buf = append(pkt.buf, testPacket...)

		select {
		case workers[shard] <- pkt:
		default:
			atomic.AddUint64(&dropped, 1)
			pktBufferPool.Put(pkt)
		}
	}

	b.StopTimer()

	for _, ch := range workers {
		close(ch)
	}
	wg.Wait()

	droppedCount := atomic.LoadUint64(&dropped)
	dropRate := float64(droppedCount) / float64(b.N) * 100

	b.ReportMetric(dropRate, "%dropped")
}

// BenchmarkMemoryUsage measures memory usage at different queue depths
func BenchmarkMemoryUsage(b *testing.B) {
	depths := []int{256, 512, 1024, 2048, 4096}

	for _, depth := range depths {
		b.Run(fmt.Sprintf("depth_%d", depth), func(b *testing.B) {
			measureMemoryUsage(b, depth)
		})
	}
}

func measureMemoryUsage(b *testing.B, queueDepth int) {
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	numWorkers := runtime.NumCPU()
	workers := make([]chan *pktBuffer, numWorkers)

	for i := range numWorkers {
		ch := make(chan *pktBuffer, queueDepth)
		workers[i] = ch

		for range queueDepth {
			pkt := pktBufferPool.Get().(*pktBuffer)
			pkt.reset()
			pkt.buf = make([]byte, 0, defaultPktBufCap)
			ch <- pkt
		}
	}

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	for _, ch := range workers {
		close(ch)
		for pkt := range ch {
			pktBufferPool.Put(pkt)
		}
	}

	allocatedMB := float64(m2.Alloc-m1.Alloc) / (1024 * 1024)
	b.ReportMetric(allocatedMB, "MB_allocated")
	b.ReportMetric(float64(numWorkers*queueDepth), "total_buffers")
}

// BenchmarkThroughput measures sustained throughput with different depths
func BenchmarkThroughput(b *testing.B) {
	depths := []int{256, 512, 1024, 2048}

	for _, depth := range depths {
		b.Run(fmt.Sprintf("depth_%d", depth), func(b *testing.B) {
			benchmarkThroughput(b, depth)
		})
	}
}

func benchmarkThroughput(b *testing.B, queueDepth int) {
	numWorkers := runtime.NumCPU()

	p := &PacketsPoller{
		useRingbuf:    true,
		stopPoll:      make(chan struct{}),
		tai:           tai.NewTaiInfo(),
		lastLostCheck: time.Now(),
		workerCount:   numWorkers,
		workers:       make([]chan *pktBuffer, numWorkers),
	}

	var processed uint64

	for i := range numWorkers {
		ch := make(chan *pktBuffer, queueDepth)
		p.workers[i] = ch
		p.workersWg.Add(1)
		go func(c <-chan *pktBuffer) {
			defer p.workersWg.Done()
			for pkt := range c {
				atomic.AddUint64(&processed, 1)
				returnPktBuffer(pkt)
			}
		}(ch)
	}

	// Simulate gopacket writer that does minimal work
	p.gopacketWriter = func(packet gopacket.Packet, dissectionDisabled bool) {}

	testPacket := makeIPv4Packet(6, tcpHeader(5, nil), make([]byte, 500))

	b.ResetTimer()
	start := time.Now()

	for i := 0; i < b.N; i++ {
		pkt := pktBufferPool.Get().(*pktBuffer)
		pkt.reset()
		pkt.buf = append(pkt.buf, testPacket...)
		pkt.cgroupID = uint64(i)

		shard := flowShard(pkt.buf, pkt.cgroupID, p.workerCount)
		p.enqueuePacket(shard, pkt)
	}

	b.StopTimer()
	elapsed := time.Since(start)

	// Close and wait
	for _, ch := range p.workers {
		close(ch)
	}
	p.workersWg.Wait()

	droppedCount := atomic.LoadUint64(&p.stats.PacketsDropped)
	processedCount := atomic.LoadUint64(&processed)

	packetsPerSec := float64(b.N) / elapsed.Seconds()
	dropRate := float64(droppedCount) / float64(b.N) * 100

	b.ReportMetric(packetsPerSec, "pkt/s")
	b.ReportMetric(dropRate, "%dropped")
	b.ReportMetric(float64(processedCount), "processed")
}
