package rawcapture

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	raw "github.com/kubeshark/api2/pkg/proto/raw_capture"
	"github.com/kubeshark/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewManager(t *testing.T) {
	target := raw.Target_TARGET_SYSCALLS
	manager := NewManager(target)

	assert.NotNil(t, manager)
	assert.Equal(t, target, manager.target)
	assert.NotNil(t, manager.writers)
	assert.Len(t, manager.writers, 0)
}

func TestTTLPolicyConstants(t *testing.T) {
	// Test that constants are properly defined
	assert.Equal(t, 0, int(TTLPolicyUnspecified))
	assert.Equal(t, 1, int(TTLPolicyStop))
	assert.Equal(t, 2, int(TTLPolicyDeleteOldest))
}

func TestDefaultConstants(t *testing.T) {
	assert.Equal(t, uint64(64*1024*1024), uint64(DefaultRotateBytes))
	assert.Equal(t, uint64(2*1024*1024*1024), uint64(DefaultMaxBytes))
}

func TestManagerStartCapturing(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	tests := []struct {
		name           string
		baseDir        string
		id             string
		enabled        bool
		rotateBytes    uint64
		rotateInterval time.Duration
		maxBytes       uint64
		policy         TTLPolicy
		expectError    bool
		errorContains  string
	}{
		{
			name:           "successful start",
			baseDir:        tempDir,
			id:             "test-1",
			enabled:        true,
			rotateBytes:    1024 * 1024,
			rotateInterval: 5 * time.Minute,
			maxBytes:       10 * 1024 * 1024,
			policy:         TTLPolicyDeleteOldest,
			expectError:    false,
		},
		{
			name:           "start with zero values uses defaults",
			baseDir:        tempDir,
			id:             "test-2",
			enabled:        true,
			rotateBytes:    0,
			rotateInterval: 0,
			maxBytes:       0,
			policy:         TTLPolicyUnspecified,
			expectError:    false,
		},
		{
			name:          "duplicate id fails",
			baseDir:       tempDir,
			id:            "test-1", // Same as first test
			enabled:       true,
			expectError:   true,
			errorContains: "capture already started",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.StartCapturing(tt.baseDir, tt.id, tt.enabled, tt.rotateBytes, tt.rotateInterval, tt.maxBytes, tt.policy)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify writer was created
				writer := manager.Get(tt.id)
				assert.NotNil(t, writer)
				assert.Equal(t, tt.baseDir, writer.baseDir)
				assert.Equal(t, tt.id, writer.id)
				assert.Equal(t, tt.enabled, writer.enabled)

				// Check defaults were applied
				if tt.rotateBytes == 0 {
					assert.Equal(t, uint64(DefaultRotateBytes), writer.rotateBytes)
				} else {
					assert.Equal(t, tt.rotateBytes, writer.rotateBytes)
				}

				if tt.maxBytes == 0 {
					assert.Equal(t, uint64(DefaultMaxBytes), writer.maxBytes)
				} else {
					assert.Equal(t, tt.maxBytes, writer.maxBytes)
				}

				if tt.policy == TTLPolicyUnspecified {
					assert.Equal(t, TTLPolicyDeleteOldest, writer.policy)
				} else {
					assert.Equal(t, tt.policy, writer.policy)
				}

				// Clean up
				writer.Destroy()
			}
		})
	}
}

func TestManagerGet(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	// Test getting non-existent writer
	writer := manager.Get("non-existent")
	assert.Nil(t, writer)

	// Start a capture and test getting it
	err := manager.StartCapturing(tempDir, "test-id", true, 0, 0, 0, TTLPolicyDeleteOldest)
	require.NoError(t, err)

	writer = manager.Get("test-id")
	assert.NotNil(t, writer)
	assert.Equal(t, "test-id", writer.id)

	// Clean up
	writer.Destroy()
}

func TestManagerDestroy(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	// Start multiple captures
	ids := []string{"destroy-test-1", "destroy-test-2", "destroy-test-3"}
	for _, id := range ids {
		err := manager.StartCapturing(tempDir, id, true, 0, 0, 0, TTLPolicyDeleteOldest)
		require.NoError(t, err)
	}

	// Verify all writers exist
	for _, id := range ids {
		assert.NotNil(t, manager.Get(id))
	}

	// Destroy all
	manager.Destroy()

	// Verify all writers are gone
	for _, id := range ids {
		assert.Nil(t, manager.Get(id))
	}
}

func TestManagerEnqueueSyscall(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	// Test enqueue with no writers
	event := &raw.SyscallEvent{
		Ts:      timestamppb.New(time.Now()),
		Pid:     12345,
		Command: "open",
	}
	manager.EnqueueSyscall(event) // Should not panic

	// Start a writer and test enqueue
	err := manager.StartCapturing(tempDir, "enqueue-test", true, 0, 0, 0, TTLPolicyDeleteOldest)
	require.NoError(t, err)

	writer := manager.Get("enqueue-test")
	require.NotNil(t, writer)
	defer writer.Destroy()

	// Enqueue should work without error
	manager.EnqueueSyscall(event)

	// Give some time for processing
	time.Sleep(100 * time.Millisecond)
}

func TestManagerEnqueuePacket(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_PACKETS)

	// Test enqueue with no writers
	packet := []byte{0x45, 0x00, 0x00, 0x3c} // Dummy packet data
	timestamp := uint64(time.Now().UnixNano())
	manager.EnqueuePacket(timestamp, packet) // Should not panic

	// Start a writer and test enqueue
	err := manager.StartCapturing(tempDir, "packet-test", true, 0, 0, 0, TTLPolicyDeleteOldest)
	require.NoError(t, err)

	writer := manager.Get("packet-test")
	require.NotNil(t, writer)
	defer writer.Destroy()

	// Enqueue should work without error
	manager.EnqueuePacket(timestamp, packet)

	// Give some time for processing
	time.Sleep(100 * time.Millisecond)
}

func TestWriterApplyConfig(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	err := manager.StartCapturing(tempDir, "config-test", false, 0, 0, 0, TTLPolicyUnspecified)
	require.NoError(t, err)

	writer := manager.Get("config-test")
	require.NotNil(t, writer)
	defer writer.Destroy()

	// Test applying new config
	writer.applyConfig(true, 2*1024*1024, 10*time.Minute, 100*1024*1024, TTLPolicyStop)

	assert.True(t, writer.enabled)
	assert.Equal(t, uint64(2*1024*1024), writer.rotateBytes)
	assert.Equal(t, 10*time.Minute, writer.rotateInterval)
	assert.Equal(t, uint64(100*1024*1024), writer.maxBytes)
	assert.Equal(t, TTLPolicyStop, writer.policy)
}

func TestWriterEnable(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	err := manager.StartCapturing(tempDir, "enable-test", false, 0, 0, 0, TTLPolicyDeleteOldest)
	require.NoError(t, err)

	writer := manager.Get("enable-test")
	require.NotNil(t, writer)
	defer writer.Destroy()

	// Initially disabled
	assert.False(t, writer.enabled)

	// Enable
	writer.Enable(true)
	assert.True(t, writer.enabled)

	// Disable
	writer.Enable(false)
	assert.False(t, writer.enabled)
}

func TestWriterDestroy(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	err := manager.StartCapturing(tempDir, "destroy-writer-test", true, 0, 0, 0, TTLPolicyDeleteOldest)
	require.NoError(t, err)

	writer := manager.Get("destroy-writer-test")
	require.NotNil(t, writer)

	// Writer should be enabled initially
	assert.True(t, writer.enabled)

	// Destroy should disable and cancel context
	writer.Destroy()

	assert.False(t, writer.enabled)
	assert.Nil(t, writer.activeFile)

	// Context should be canceled
	select {
	case <-writer.ctx.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("Context was not canceled")
	}
}

func TestWriterWriteProtoLengthPrefixed(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	err := manager.StartCapturing(tempDir, "write-test", true, 0, 0, 0, TTLPolicyDeleteOldest)
	require.NoError(t, err)

	writer := manager.Get("write-test")
	require.NotNil(t, writer)
	defer writer.Destroy()

	// Test writing nil data
	writer.writeProtoLengthPrefixed(nil)

	// Test writing valid data
	testData := []byte("test data")
	writer.writeProtoLengthPrefixed(testData)

	// Test writing when disabled
	writer.Enable(false)
	writer.writeProtoLengthPrefixed(testData) // Should be ignored

	// Give some time for processing
	time.Sleep(100 * time.Millisecond)
}

func TestWriterWritePacketToPcapFile(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_PACKETS)

	err := manager.StartCapturing(tempDir, "pcap-test", true, 0, 0, 0, TTLPolicyDeleteOldest)
	require.NoError(t, err)

	writer := manager.Get("pcap-test")
	require.NotNil(t, writer)
	defer writer.Destroy()

	// Test writing nil packet
	writer.writePacketToPcapFile(0, nil)

	// Test writing valid packet
	packet := []byte{0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06}
	timestamp := uint64(time.Now().UnixNano())
	writer.writePacketToPcapFile(timestamp, packet)

	// Test with zero timestamp (should use current time)
	writer.writePacketToPcapFile(0, packet)

	// Test writing when disabled
	writer.Enable(false)
	writer.writePacketToPcapFile(timestamp, packet) // Should be ignored

	// Give some time for processing
	time.Sleep(100 * time.Millisecond)
}

func TestWriterFormatPacketForQueue(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_PACKETS)

	err := manager.StartCapturing(tempDir, "format-test", true, 0, 0, 0, TTLPolicyDeleteOldest)
	require.NoError(t, err)

	writer := manager.Get("format-test")
	require.NotNil(t, writer)
	defer writer.Destroy()

	packet := []byte{0x45, 0x00, 0x00, 0x3c}
	timestamp := time.Now()

	// Create gopacket.CaptureInfo
	ci := gopacket.CaptureInfo{
		Timestamp:     timestamp,
		CaptureLength: len(packet),
		Length:        len(packet),
	}

	// Test formatPacketForQueue
	buf := writer.formatPacketForQueue(ci, packet)

	// Verify format: 8 bytes timestamp + 4 bytes length + packet data
	expectedLen := 8 + 4 + len(packet)
	assert.Equal(t, expectedLen, len(buf))

	// Verify timestamp
	extractedTimestamp := binary.BigEndian.Uint64(buf[0:8])
	assert.Equal(t, uint64(timestamp.UnixNano()), extractedTimestamp)

	// Verify length
	extractedLength := binary.BigEndian.Uint32(buf[8:12])
	assert.Equal(t, uint32(len(packet)), extractedLength)

	// Verify packet data
	extractedPacket := buf[12:]
	assert.Equal(t, packet, extractedPacket)
}

func TestManagerStatusFor(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	// Test status for non-existent writer
	status := manager.StatusFor("non-existent")
	assert.Nil(t, status)

	// Start a capture
	err := manager.StartCapturing(tempDir, "status-test", true, 1024*1024, 5*time.Minute, 10*1024*1024, TTLPolicyStop)
	require.NoError(t, err)

	writer := manager.Get("status-test")
	require.NotNil(t, writer)
	defer writer.Destroy()

	// Create some test files in the base directory
	testFile := filepath.Join(tempDir, "test-file.dat")
	testData := make([]byte, 1024)
	err = os.WriteFile(testFile, testData, 0o644)
	require.NoError(t, err)

	// Get status
	status = manager.StatusFor("status-test")
	require.NotNil(t, status)

	assert.Equal(t, tempDir, status.BaseDir)
	assert.Equal(t, uint64(1024*1024), status.RotateBytes)
	assert.Equal(t, 5*time.Minute, status.RotateInterval.AsDuration())
	assert.Equal(t, uint64(10*1024*1024), status.MaxBytes)
	assert.Equal(t, TTLPolicyStop, status.Policy)
	assert.True(t, status.TotalBytes >= 1024) // At least our test file
	assert.True(t, status.FilesCount >= 1)    // At least our test file
}

func TestEnsureQuotaLocked(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	err := manager.StartCapturing(tempDir, "quota-test", true, 0, 0, 1024, TTLPolicyDeleteOldest)
	require.NoError(t, err)

	writer := manager.Get("quota-test")
	require.NotNil(t, writer)
	defer writer.Destroy()

	// Create test files that exceed quota
	testFiles := []string{"2024-01-01T10:00:00.000000000Z", "2024-01-01T11:00:00.000000000Z", "2024-01-01T12:00:00.000000000Z"}
	for _, filename := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		testData := make([]byte, 500) // Each file is 500 bytes
		err = os.WriteFile(filePath, testData, 0o644)
		require.NoError(t, err)
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()

	// Test with incoming data that fits within quota
	err = writer.ensureQuotaLocked(100)
	assert.NoError(t, err)

	// Test with incoming data that exceeds quota - should trigger deletion of oldest files
	err = writer.ensureQuotaLocked(500)
	assert.NoError(t, err)

	// Check that some files were deleted
	entries, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	assert.True(t, len(entries) < len(testFiles), "Some files should have been deleted")
}

func TestEnsureQuotaLockedStopPolicy(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	err := manager.StartCapturing(tempDir, "quota-stop-test", true, 0, 0, 1024, TTLPolicyStop)
	require.NoError(t, err)

	writer := manager.Get("quota-stop-test")
	require.NotNil(t, writer)
	defer writer.Destroy()

	// Create test files that exceed quota
	testFile := filepath.Join(tempDir, "test-file.dat")
	testData := make([]byte, 1000)
	err = os.WriteFile(testFile, testData, 0o644)
	require.NoError(t, err)

	writer.mu.Lock()
	defer writer.mu.Unlock()

	// Test with incoming data that would exceed quota with STOP policy
	err = writer.ensureQuotaLocked(500)
	assert.ErrorIs(t, err, ErrQuotaStop)
}

func TestPathFunctions(t *testing.T) {
	tempDir := t.TempDir()

	// Test captureBaseDir
	baseDir := captureBaseDir(tempDir)
	assert.Contains(t, baseDir, "capture")

	// Test SyscallBaseDir
	syscallDir := SyscallBaseDir(tempDir)
	assert.Contains(t, syscallDir, "syscall_events")
	assert.Contains(t, syscallDir, baseDir)

	// Test SyscallBaseDirFor
	testID := "test-id-123"
	syscallDirForID := SyscallBaseDirFor(tempDir, testID)
	assert.Contains(t, syscallDirForID, testID)
	assert.Contains(t, syscallDirForID, syscallDir)

	// Test PcapBaseDir
	pcapDir := PcapBaseDir(tempDir)
	assert.Contains(t, pcapDir, "pcap")
	assert.Contains(t, pcapDir, baseDir)

	// Test PcapBaseDirFor
	pcapDirForID := PcapBaseDirFor(tempDir, testID)
	assert.Contains(t, pcapDirForID, testID)
	assert.Contains(t, pcapDirForID, pcapDir)
}

func TestWriterLoop(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	err := manager.StartCapturing(tempDir, "loop-test", true, 0, 0, 0, TTLPolicyDeleteOldest)
	require.NoError(t, err)

	writer := manager.Get("loop-test")
	require.NotNil(t, writer)

	// The loop should be running
	assert.NotNil(t, writer.ctx)

	// Test that context cancellation stops the loop
	writer.Destroy()

	// Wait for context to be done
	select {
	case <-writer.ctx.Done():
		// Expected
	case <-time.After(time.Second):
		t.Error("Writer loop did not stop within timeout")
	}
}

func TestCloseActiveLocked(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	err := manager.StartCapturing(tempDir, "close-test", true, 0, 0, 0, TTLPolicyDeleteOldest)
	require.NoError(t, err)

	writer := manager.Get("close-test")
	require.NotNil(t, writer)
	defer writer.Destroy()

	writer.mu.Lock()
	defer writer.mu.Unlock()

	// Create a dummy active file
	testFile := filepath.Join(tempDir, "active-test.dat")
	f, err := os.Create(testFile)
	require.NoError(t, err)

	writer.activeFile = f
	writer.activePath = testFile
	writer.activeSize = 1024

	// Close active file
	writer.closeActiveLocked()

	assert.Nil(t, writer.activeFile)
	assert.Equal(t, "", writer.activePath)
	assert.Equal(t, uint64(0), writer.activeSize)
	assert.Nil(t, writer.pcapWriter)
}
