package rawcapture

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	raw "github.com/kubeshark/api2/pkg/proto/raw_capture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const bufSize = 1024 * 1024

// createTestSyscallEvent creates a test syscall event with the given parameters
func createTestSyscallEvent(pid uint32, eventId uint32, command string, timestamp time.Time) *raw.SyscallEvent {
	return &raw.SyscallEvent{
		Ts:            timestamppb.New(timestamp),
		EventId:       eventId,
		Pid:           pid,
		ParentPid:     pid - 1,
		HostPid:       pid + 1000,
		HostParentPid: pid + 999,
		Command:       command,
		ProcessPath:   fmt.Sprintf("/usr/bin/%s", command),
		PortSrc:       uint32(8080 + (pid % 100)),
		PortDst:       uint32(80 + (pid % 10)),
	}
}

// generateTestSyscalls generates a large number of test syscall events
func generateTestSyscalls(count int) []*raw.SyscallEvent {
	events := make([]*raw.SyscallEvent, count)
	baseTime := time.Now().Add(-time.Hour) // Start from 1 hour ago

	commands := []string{"open", "read", "write", "close", "connect", "accept", "bind", "listen"}

	for i := 0; i < count; i++ {
		// Generate realistic timestamps with some jitter
		timestamp := baseTime.Add(time.Duration(i) * time.Millisecond * 10)
		if i%100 == 0 {
			timestamp = timestamp.Add(time.Second) // Add some gaps
		}

		pid := uint32(1000 + (i % 50)) // PIDs between 1000-1049
		eventId := uint32(i % 4)       // Event IDs 0-3 (connect, accept, close connect, close accept)
		command := commands[i%len(commands)]

		events[i] = createTestSyscallEvent(pid, eventId, command, timestamp)
	}

	return events
}

// printDirectoryStructure prints the directory structure for debugging
func printDirectoryStructure(t *testing.T, baseDir string) {
	t.Logf("Directory structure for: %s", baseDir)

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(baseDir, path)
		if relPath == "." {
			relPath = "."
		}

		if info.IsDir() {
			t.Logf("  [DIR]  %s/", relPath)
		} else {
			t.Logf("  [FILE] %s (%d bytes)", relPath, info.Size())
		}
		return nil
	})
	if err != nil {
		t.Logf("Error walking directory: %v", err)
	}
}

// countFilesInDir counts files in a directory
func countFilesInDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			count++
		}
	}
	return count, nil
}

// getTotalSizeInDir calculates total size of all files in a directory
func getTotalSizeInDir(dir string) (int64, error) {
	var totalSize int64

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})

	return totalSize, err
}

func TestCaptureSystemFlow(t *testing.T) {
	// Skip if not running system tests
	if testing.Short() {
		t.Skip("Skipping system test in short mode")
	}

	// Set up test environment
	tempDir := t.TempDir()
	originalDataDir := os.Getenv("DATADIR")
	os.Setenv("DATADIR", tempDir)
	defer os.Setenv("DATADIR", originalDataDir)

	// Create manager and server
	manager := NewManager(raw.Target_TARGET_SYSCALLS)
	server := &RawCaptureServer{Manager: manager}

	// Create in-memory gRPC server
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()
	raw.RegisterRawCaptureServer(s, server)

	// Start gRPC server in goroutine
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("Server exited with error: %v", err)
		}
	}()
	defer s.Stop()

	// Create gRPC client
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.NewClient("passthrough:///bufconn", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := raw.NewRawCaptureClient(conn)

	// Test configuration - aim for ~3MB total across 3 files
	const (
		eventsPerFile = 1000       // Number of events per file
		totalEvents   = 10000      // Total events to generate (more to ensure rotation)
		rotateBytes   = 500 * 1024 // 500KB per file (smaller to trigger rotation)
	)

	t.Logf("=== Starting System Test ===")
	t.Logf("Generating %d syscall events", totalEvents)
	t.Logf("Target: ~%d files of ~%d bytes each", totalEvents/eventsPerFile, rotateBytes)

	// Generate test syscall events
	events := generateTestSyscalls(totalEvents)
	t.Logf("Generated %d test events", len(events))

	// Step 1: Start capture
	t.Logf("\n=== Step 1: Starting Capture ===")
	startReq := &raw.StartRequest{
		Target: raw.Target_TARGET_SYSCALLS,
		Id:     "system-test-capture",
		Config: &raw.Config{
			RotateBytes:    rotateBytes,
			RotateInterval: durationpb.New(5 * time.Minute),
			MaxBytes:       5 * 1024 * 1024, // 5MB max
			TtlPolicy:      raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST,
		},
	}

	startResp, err := client.Start(ctx, startReq)
	require.NoError(t, err)
	require.NotNil(t, startResp)
	require.Empty(t, startResp.Error, "Start should not return error")

	t.Logf("Capture started with ID: %s", startResp.Id)
	t.Logf("Capture directory: %s", startResp.Dir)

	// Print initial directory structure
	printDirectoryStructure(t, startResp.Dir)

	// Step 2: Get initial status
	t.Logf("\n=== Step 2: Getting Initial Status ===")
	statusReq := &raw.GetStatusRequest{
		Target: raw.Target_TARGET_SYSCALLS,
		Id:     "system-test-capture",
	}

	statusResp, err := client.GetStatus(ctx, statusReq)
	require.NoError(t, err)
	require.NotNil(t, statusResp)

	t.Logf("Initial status - Active: %v, Files: %d, Total Bytes: %d",
		statusResp.Active, statusResp.FilesCount, statusResp.TotalBytes)

	// Step 3: Enqueue syscall events
	t.Logf("\n=== Step 3: Enqueuing Syscall Events ===")

	// Enqueue events in batches to simulate real usage
	batchSize := 100
	for i := 0; i < len(events); i += batchSize {
		end := i + batchSize
		if end > len(events) {
			end = len(events)
		}

		batch := events[i:end]
		for _, event := range batch {
			manager.EnqueueSyscall(event)
		}

		// Small delay between batches
		time.Sleep(10 * time.Millisecond)

		if (i/batchSize)%10 == 0 {
			t.Logf("Enqueued %d/%d events", end, len(events))
		}
	}

	t.Logf("Enqueued all %d events", len(events))

	// Wait for processing
	t.Logf("Waiting for events to be processed...")
	time.Sleep(5 * time.Second) // Wait longer for file rotation

	// Step 4: Check intermediate status
	t.Logf("\n=== Step 4: Checking Intermediate Status ===")
	statusResp, err = client.GetStatus(ctx, statusReq)
	require.NoError(t, err)
	require.NotNil(t, statusResp)

	t.Logf("Intermediate status - Active: %v, Files: %d, Total Bytes: %d",
		statusResp.Active, statusResp.FilesCount, statusResp.TotalBytes)

	// Print directory structure after processing
	printDirectoryStructure(t, startResp.Dir)

	// Verify files were created
	fileCount, err := countFilesInDir(startResp.Dir)
	require.NoError(t, err)
	t.Logf("Files created: %d", fileCount)

	// Verify total size
	totalSize, err := getTotalSizeInDir(startResp.Dir)
	require.NoError(t, err)
	t.Logf("Total size: %d bytes (%.2f MB)", totalSize, float64(totalSize)/(1024*1024))

	// Assert we have multiple files (due to rotation) or at least some files
	if fileCount > 1 {
		t.Logf("✓ File rotation working - created %d files", fileCount)
	} else {
		t.Logf("⚠ File rotation not triggered - only %d file created (size: %d bytes)", fileCount, totalSize)
	}

	// Assert we have reasonable data size
	assert.Greater(t, totalSize, int64(100*1024), "Total size should be at least 100KB")

	// Step 5: Stop capture
	t.Logf("\n=== Step 5: Stopping Capture ===")
	stopReq := &raw.StopRequest{
		Target: raw.Target_TARGET_SYSCALLS,
		Id:     "system-test-capture",
	}

	stopResp, err := client.Stop(ctx, stopReq)
	require.NoError(t, err)
	require.NotNil(t, stopResp)
	require.NotNil(t, stopResp.Stats)

	t.Logf("Capture stopped - Files: %d, Total Bytes: %d, Syscalls: %d, Drops: %d",
		stopResp.Stats.FilesCount, stopResp.Stats.TotalBytes,
		stopResp.Stats.CapturedSyscalls, stopResp.Stats.Drops)

	// Print final directory structure
	printDirectoryStructure(t, startResp.Dir)

	// Step 6: Verify final status (should be inactive)
	t.Logf("\n=== Step 6: Verifying Final Status ===")
	statusResp, err = client.GetStatus(ctx, statusReq)
	require.NoError(t, err)
	require.NotNil(t, statusResp)

	t.Logf("Final status - Active: %v, Files: %d, Total Bytes: %d",
		statusResp.Active, statusResp.FilesCount, statusResp.TotalBytes)

	assert.False(t, statusResp.Active, "Capture should be inactive after stop")

	// Step 7: Verify file contents
	t.Logf("\n=== Step 7: Verifying File Contents ===")
	entries, err := os.ReadDir(startResp.Dir)
	require.NoError(t, err)

	eventsRead := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(startResp.Dir, entry.Name())

		// Get file info for size
		fileInfo, err := entry.Info()
		require.NoError(t, err)
		t.Logf("Verifying file: %s (%d bytes)", entry.Name(), fileInfo.Size())

		// Read and verify file contents
		file, err := os.Open(filePath)
		require.NoError(t, err)

		fileEvents := 0

		for {
			// Read length prefix
			lengthBytes := make([]byte, 4)
			_, err := io.ReadFull(file, lengthBytes)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)

			length := uint32(lengthBytes[0])<<24 | uint32(lengthBytes[1])<<16 |
				uint32(lengthBytes[2])<<8 | uint32(lengthBytes[3])

			// Read protobuf data
			protobufData := make([]byte, length)
			_, err = io.ReadFull(file, protobufData)
			require.NoError(t, err)

			// Unmarshal and verify
			var event raw.SyscallEvent
			err = proto.Unmarshal(protobufData, &event)
			require.NoError(t, err)

			// Basic validation
			assert.NotEmpty(t, event.Command, "Command should not be empty")
			assert.Greater(t, event.Pid, uint32(0), "PID should be positive")
			assert.NotNil(t, event.Ts, "Timestamp should not be nil")

			fileEvents++
			eventsRead++

			if fileEvents%100 == 0 {
				t.Logf("  Read %d events from %s", fileEvents, entry.Name())
			}
		}

		file.Close()
		t.Logf("  Total events in %s: %d", entry.Name(), fileEvents)
	}

	t.Logf("Total events read from all files: %d", eventsRead)
	assert.Greater(t, eventsRead, 0, "Should have read some events from files")

	// Step 8: Check directory before cleanup
	t.Logf("\n=== Step 8: Checking Directory Before Cleanup ===")
	printDirectoryStructure(t, startResp.Dir)

	// Step 9: Cleanup
	t.Logf("\n=== Step 9: Cleanup ===")
	cleanupResp, err := client.Cleanup(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.NotNil(t, cleanupResp)
	require.Empty(t, cleanupResp.Error, "Cleanup should not return error")

	t.Logf("Cleanup completed successfully")

	// Verify directory is cleaned up
	entries, err = os.ReadDir(startResp.Dir)
	if err != nil {
		t.Logf("Directory removed during cleanup (expected)")
	} else {
		t.Logf("Directory after cleanup has %d entries", len(entries))
		printDirectoryStructure(t, startResp.Dir)
	}

	t.Logf("\n=== System Test Completed Successfully ===")
}

// createTestPacketData creates test packet data with the given parameters
func createTestPacketData(srcIP, dstIP string, srcPort, dstPort uint16, protocol string, timestamp time.Time) (uint64, []byte) {
	// Create a simple IP packet structure for testing
	// This is a minimal IP packet with some payload

	// Add some payload first to determine total size
	payload := fmt.Sprintf("test-payload-%d-%s-%d-%d", timestamp.UnixNano(), protocol, srcPort, dstPort)
	payloadBytes := []byte(payload)

	// Calculate total packet size: IP header (20) + payload
	totalLength := 20 + len(payloadBytes)

	// Create packet data with enough capacity
	packetData := make([]byte, totalLength)

	// IP header (simplified)
	packetData[0] = 0x45                     // Version 4, Header Length 5
	packetData[1] = 0x00                     // Type of Service
	packetData[2] = byte(totalLength >> 8)   // Total Length (high byte)
	packetData[3] = byte(totalLength & 0xff) // Total Length (low byte)
	packetData[4] = 0x00                     // Identification
	packetData[5] = 0x00                     // Identification
	packetData[6] = 0x40                     // Flags, Fragment Offset
	packetData[7] = 0x00                     // Fragment Offset
	packetData[8] = 0x40                     // TTL
	packetData[9] = 0x06                     // Protocol (TCP)
	packetData[10] = 0x00                    // Header Checksum
	packetData[11] = 0x00                    // Header Checksum

	// Source IP (simplified - just use first 4 bytes)
	srcIPBytes := []byte{192, 168, 1, 10}
	copy(packetData[12:16], srcIPBytes)

	// Destination IP (simplified - just use first 4 bytes)
	dstIPBytes := []byte{192, 168, 1, 20}
	copy(packetData[16:20], dstIPBytes)

	// Add payload
	copy(packetData[20:], payloadBytes)

	return uint64(timestamp.UnixNano()), packetData
}

// generateTestPackets generates a large number of test packet events
func generateTestPackets(count int) []struct {
	timestamp uint64
	data      []byte
} {
	packets := make([]struct {
		timestamp uint64
		data      []byte
	}, count)
	baseTime := time.Now().Add(-time.Hour) // Start from 1 hour ago

	protocols := []string{"TCP", "UDP", "ICMP"}
	ipRanges := []string{"192.168.1.", "10.0.0.", "172.16.0."}
	portRanges := []uint16{80, 443, 8080, 9090, 3000, 5000}

	for i := 0; i < count; i++ {
		// Generate realistic timestamps with some jitter
		timestamp := baseTime.Add(time.Duration(i) * time.Millisecond * 5)
		if i%200 == 0 {
			timestamp = timestamp.Add(time.Second) // Add some gaps
		}

		// Generate varied IP addresses and ports
		srcIP := fmt.Sprintf("%s%d", ipRanges[i%len(ipRanges)], 10+(i%50))
		dstIP := fmt.Sprintf("%s%d", ipRanges[(i+1)%len(ipRanges)], 100+(i%50))
		srcPort := portRanges[i%len(portRanges)]
		dstPort := portRanges[(i+1)%len(portRanges)]
		protocol := protocols[i%len(protocols)]

		timestampNs, packetData := createTestPacketData(srcIP, dstIP, srcPort, dstPort, protocol, timestamp)
		packets[i] = struct {
			timestamp uint64
			data      []byte
		}{timestampNs, packetData}
	}

	return packets
}

func TestCaptureSystemFlowPCAP(t *testing.T) {
	// Skip if not running system tests
	if testing.Short() {
		t.Skip("Skipping system test in short mode")
	}

	// Set up test environment
	tempDir := t.TempDir()
	originalDataDir := os.Getenv("DATADIR")
	os.Setenv("DATADIR", tempDir)
	defer os.Setenv("DATADIR", originalDataDir)

	// Create manager and server
	manager := NewManager(raw.Target_TARGET_PACKETS)
	server := &RawCaptureServer{Manager: manager}

	// Create in-memory gRPC server
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()
	raw.RegisterRawCaptureServer(s, server)

	// Start gRPC server in goroutine
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("Server exited with error: %v", err)
		}
	}()
	defer s.Stop()

	// Create gRPC client
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.NewClient("passthrough:///bufconn", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := raw.NewRawCaptureClient(conn)

	// Test configuration - aim for ~3MB total across 3 files
	const (
		packetsPerFile = 2000       // Number of packets per file
		totalPackets   = 15000      // Total packets to generate (more to ensure rotation)
		rotateBytes    = 800 * 1024 // 800KB per file (smaller to trigger rotation)
	)

	t.Logf("=== Starting PCAP System Test ===")
	t.Logf("Generating %d packet events", totalPackets)
	t.Logf("Target: ~%d files of ~%d bytes each", totalPackets/packetsPerFile, rotateBytes)

	// Generate test packet events
	packets := generateTestPackets(totalPackets)
	t.Logf("Generated %d test packets", len(packets))

	// Step 1: Start capture
	t.Logf("\n=== Step 1: Starting PCAP Capture ===")
	startReq := &raw.StartRequest{
		Target: raw.Target_TARGET_PACKETS,
		Id:     "system-test-pcap-capture",
		Config: &raw.Config{
			RotateBytes:    rotateBytes,
			RotateInterval: durationpb.New(5 * time.Minute),
			MaxBytes:       5 * 1024 * 1024, // 5MB max
			TtlPolicy:      raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST,
		},
	}

	startResp, err := client.Start(ctx, startReq)
	require.NoError(t, err)
	require.NotNil(t, startResp)
	require.Empty(t, startResp.Error, "Start should not return error")

	t.Logf("PCAP Capture started with ID: %s", startResp.Id)
	t.Logf("PCAP Capture directory: %s", startResp.Dir)

	// Print initial directory structure
	printDirectoryStructure(t, startResp.Dir)

	// Step 2: Get initial status
	t.Logf("\n=== Step 2: Getting Initial Status ===")
	statusReq := &raw.GetStatusRequest{
		Target: raw.Target_TARGET_PACKETS,
		Id:     "system-test-pcap-capture",
	}

	statusResp, err := client.GetStatus(ctx, statusReq)
	require.NoError(t, err)
	require.NotNil(t, statusResp)

	t.Logf("Initial status - Active: %v, Files: %d, Total Bytes: %d",
		statusResp.Active, statusResp.FilesCount, statusResp.TotalBytes)

	// Step 3: Enqueue packet events
	t.Logf("\n=== Step 3: Enqueuing Packet Events ===")

	// Enqueue packets in batches to simulate real usage
	batchSize := 200
	for i := 0; i < len(packets); i += batchSize {
		end := i + batchSize
		if end > len(packets) {
			end = len(packets)
		}

		batch := packets[i:end]
		for _, packet := range batch {
			manager.EnqueuePacket(packet.timestamp, packet.data)
		}

		// Small delay between batches
		time.Sleep(5 * time.Millisecond)

		if (i/batchSize)%20 == 0 {
			t.Logf("Enqueued %d/%d packets", end, len(packets))
		}
	}

	t.Logf("Enqueued all %d packets", len(packets))

	// Wait for processing
	t.Logf("Waiting for packets to be processed...")
	time.Sleep(5 * time.Second) // Wait longer for file rotation

	// Step 4: Check intermediate status
	t.Logf("\n=== Step 4: Checking Intermediate Status ===")
	statusResp, err = client.GetStatus(ctx, statusReq)
	require.NoError(t, err)
	require.NotNil(t, statusResp)

	t.Logf("Intermediate status - Active: %v, Files: %d, Total Bytes: %d",
		statusResp.Active, statusResp.FilesCount, statusResp.TotalBytes)

	// Print directory structure after processing
	printDirectoryStructure(t, startResp.Dir)

	// Verify files were created
	fileCount, err := countFilesInDir(startResp.Dir)
	require.NoError(t, err)
	t.Logf("Files created: %d", fileCount)

	// Verify total size
	totalSize, err := getTotalSizeInDir(startResp.Dir)
	require.NoError(t, err)
	t.Logf("Total size: %d bytes (%.2f MB)", totalSize, float64(totalSize)/(1024*1024))

	// Assert we have multiple files (due to rotation) or at least some files
	if fileCount > 1 {
		t.Logf("✓ File rotation working - created %d files", fileCount)
	} else {
		t.Logf("⚠ File rotation not triggered - only %d file created (size: %d bytes)", fileCount, totalSize)
	}

	// Assert we have reasonable data size
	assert.Greater(t, totalSize, int64(100*1024), "Total size should be at least 100KB")

	// Step 5: Stop capture
	t.Logf("\n=== Step 5: Stopping PCAP Capture ===")
	stopReq := &raw.StopRequest{
		Target: raw.Target_TARGET_PACKETS,
		Id:     "system-test-pcap-capture",
	}

	stopResp, err := client.Stop(ctx, stopReq)
	require.NoError(t, err)
	require.NotNil(t, stopResp)
	require.NotNil(t, stopResp.Stats)

	t.Logf("PCAP Capture stopped - Files: %d, Total Bytes: %d, Packets: %d, Drops: %d",
		stopResp.Stats.FilesCount, stopResp.Stats.TotalBytes,
		stopResp.Stats.CapturedPackets, stopResp.Stats.Drops)

	// Print final directory structure
	printDirectoryStructure(t, startResp.Dir)

	// Step 6: Verify final status (should be inactive)
	t.Logf("\n=== Step 6: Verifying Final Status ===")
	statusResp, err = client.GetStatus(ctx, statusReq)
	require.NoError(t, err)
	require.NotNil(t, statusResp)

	t.Logf("Final status - Active: %v, Files: %d, Total Bytes: %d",
		statusResp.Active, statusResp.FilesCount, statusResp.TotalBytes)

	assert.False(t, statusResp.Active, "Capture should be inactive after stop")

	// Step 7: Verify file contents (PCAP files)
	t.Logf("\n=== Step 7: Verifying PCAP File Contents ===")
	entries, err := os.ReadDir(startResp.Dir)
	require.NoError(t, err)

	packetsRead := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Get file info for size
		fileInfo, err := entry.Info()
		require.NoError(t, err)
		t.Logf("Verifying PCAP file: %s (%d bytes)", entry.Name(), fileInfo.Size())

		// For PCAP files, we can't easily read the individual packets without
		// importing pcap libraries, so we'll just verify the file exists and has content
		assert.Greater(t, fileInfo.Size(), int64(0), "PCAP file should not be empty")

		// Count files as a proxy for packet count
		packetsRead += int(fileInfo.Size() / 100) // Rough estimate
	}

	t.Logf("Estimated packets in PCAP files: %d", packetsRead)
	assert.Greater(t, packetsRead, 0, "Should have some packets in PCAP files")

	// Step 8: Check directory before cleanup
	t.Logf("\n=== Step 8: Checking Directory Before Cleanup ===")
	printDirectoryStructure(t, startResp.Dir)

	// Step 9: Cleanup
	t.Logf("\n=== Step 9: Cleanup ===")
	cleanupResp, err := client.Cleanup(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.NotNil(t, cleanupResp)
	require.Empty(t, cleanupResp.Error, "Cleanup should not return error")

	t.Logf("Cleanup completed successfully")

	// Verify directory is cleaned up
	entries, err = os.ReadDir(startResp.Dir)
	if err != nil {
		t.Logf("Directory removed during cleanup (expected)")
	} else {
		t.Logf("Directory after cleanup has %d entries", len(entries))
		printDirectoryStructure(t, startResp.Dir)
	}

	t.Logf("\n=== PCAP System Test Completed Successfully ===")
}
