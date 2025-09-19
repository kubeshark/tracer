package rawcapture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	raw "github.com/kubeshark/api2/pkg/proto/raw_capture"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestToPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    raw.TTLPolicy
		expected TTLPolicy
	}{
		{
			name:     "TTL_POLICY_STOP",
			input:    raw.TTLPolicy_TTL_POLICY_STOP,
			expected: TTLPolicyStop,
		},
		{
			name:     "TTL_POLICY_DELETE_OLDEST",
			input:    raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST,
			expected: TTLPolicyDeleteOldest,
		},
		{
			name:     "Unspecified policy defaults to DELETE_OLDEST",
			input:    raw.TTLPolicy_TTL_POLICY_UNSPECIFIED,
			expected: TTLPolicyDeleteOldest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toPolicy(tt.input)
			if result != tt.expected {
				t.Errorf("toPolicy(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFromPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    TTLPolicy
		expected raw.TTLPolicy
	}{
		{
			name:     "TTLPolicyStop",
			input:    TTLPolicyStop,
			expected: raw.TTLPolicy_TTL_POLICY_STOP,
		},
		{
			name:     "TTLPolicyDeleteOldest",
			input:    TTLPolicyDeleteOldest,
			expected: raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST,
		},
		{
			name:     "TTLPolicyUnspecified defaults to DELETE_OLDEST",
			input:    TTLPolicyUnspecified,
			expected: raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FromPolicy(tt.input)
			if result != tt.expected {
				t.Errorf("FromPolicy(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestStartCapture(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	originalGetDataDir := os.Getenv("DATADIR")
	os.Setenv("DATADIR", tempDir)
	defer os.Setenv("DATADIR", originalGetDataDir)

	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	tests := []struct {
		name        string
		id          string
		cfg         *raw.Config
		expectError bool
	}{
		{
			name: "Start capture with valid config",
			id:   "test-capture-1",
			cfg: &raw.Config{
				TtlPolicy:      raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST,
				RotateBytes:    1024 * 1024,
				RotateInterval: durationpb.New(5 * time.Minute),
				MaxBytes:       10 * 1024 * 1024,
			},
			expectError: false,
		},
		{
			name:        "Start capture with nil config uses defaults",
			id:          "test-capture-2",
			cfg:         nil,
			expectError: false,
		},
		{
			name: "Start capture with empty ID generates default",
			id:   "",
			cfg: &raw.Config{
				TtlPolicy: raw.TTLPolicy_TTL_POLICY_STOP,
			},
			expectError: false,
		},
		{
			name: "Start capture with whitespace ID gets trimmed",
			id:   "  test-capture-3  ",
			cfg: &raw.Config{
				TtlPolicy: raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := StartCapture(manager, tt.id, tt.cfg)
			if err != nil {
				t.Fatalf("StartCapture returned error: %v", err)
			}

			if tt.expectError {
				if resp.Error == "" {
					t.Errorf("Expected error in response, but got none")
				}
			} else {
				if resp.Error != "" {
					t.Errorf("Unexpected error in response: %s", resp.Error)
				}

				// Validate response fields
				if resp.Target != manager.target {
					t.Errorf("Expected target %v, got %v", manager.target, resp.Target)
				}

				if tt.id == "" {
					// If ID was empty, it should have been generated
					if resp.Id == "" {
						t.Errorf("Expected generated ID, but got empty")
					}
				} else {
					expectedID := strings.TrimSpace(tt.id)
					if resp.Id != expectedID {
						t.Errorf("Expected ID %s, got %s", expectedID, resp.Id)
					}
				}

				if resp.StartedAt == nil && resp.Error == "" {
					t.Errorf("Expected StartedAt to be set when no error")
				}

				// Clean up the writer
				if w := manager.Get(resp.Id); w != nil {
					w.Destroy()
				}
			}
		})
	}
}

func TestStopCapture(t *testing.T) {
	tempDir := t.TempDir()
	originalGetDataDir := os.Getenv("DATADIR")
	os.Setenv("DATADIR", tempDir)
	defer os.Setenv("DATADIR", originalGetDataDir)

	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	// Start a capture first
	startResp, err := StartCapture(manager, "stop-test", &raw.Config{})
	if err != nil || startResp.Error != "" {
		t.Fatalf("Failed to start capture for stop test: %v, %s", err, startResp.Error)
	}

	// Test stopping the capture
	stopResp, err := StopCapture(manager, "stop-test")
	if err != nil {
		t.Fatalf("StopCapture returned error: %v", err)
	}

	if stopResp.Target != raw.Target_TARGET_SYSCALLS {
		t.Errorf("Expected target %v, got %v", raw.Target_TARGET_SYSCALLS, stopResp.Target)
	}

	if stopResp.Id != "stop-test" {
		t.Errorf("Expected ID stop-test, got %s", stopResp.Id)
	}

	if stopResp.Stats == nil {
		t.Errorf("Expected stats to be non-nil")
	}

	// Test stopping with whitespace-padded ID
	startResp, err = StartCapture(manager, "stop-test-2", &raw.Config{})
	if err != nil || startResp.Error != "" {
		t.Fatalf("Failed to start capture for second stop test: %v, %s", err, startResp.Error)
	}

	stopResp, err = StopCapture(manager, "  stop-test-2  ")
	if err != nil {
		t.Fatalf("StopCapture with padded ID returned error: %v", err)
	}

	if stopResp.Id != "stop-test-2" {
		t.Errorf("Expected trimmed ID stop-test-2, got %s", stopResp.Id)
	}
}

func TestGetCaptureStatus(t *testing.T) {
	tempDir := t.TempDir()
	originalGetDataDir := os.Getenv("DATADIR")
	os.Setenv("DATADIR", tempDir)
	defer os.Setenv("DATADIR", originalGetDataDir)

	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	tests := []struct {
		name           string
		setupCapture   bool
		captureID      string
		statusID       string
		expectedActive bool
	}{
		{
			name:           "Get status for active capture",
			setupCapture:   true,
			captureID:      "status-test-1",
			statusID:       "status-test-1",
			expectedActive: false, // Writer is enabled but no active file yet
		},
		{
			name:           "Get status for non-existent capture",
			setupCapture:   false,
			captureID:      "",
			statusID:       "non-existent",
			expectedActive: false,
		},
		{
			name:           "Get status with empty ID defaults to 'default'",
			setupCapture:   false,
			captureID:      "",
			statusID:       "",
			expectedActive: false,
		},
		{
			name:           "Get status with whitespace ID gets trimmed",
			setupCapture:   true,
			captureID:      "status-test-2",
			statusID:       "  status-test-2  ",
			expectedActive: false, // Writer is enabled but no active file yet
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupCapture {
				_, err := StartCapture(manager, tt.captureID, &raw.Config{})
				if err != nil {
					t.Fatalf("Failed to start capture: %v", err)
				}
				defer func() {
					if w := manager.Get(tt.captureID); w != nil {
						w.Destroy()
					}
				}()
			}

			status, err := GetCaptureStatus(manager, raw.Target_TARGET_SYSCALLS, tt.statusID)
			if err != nil {
				t.Fatalf("GetCaptureStatus returned error: %v", err)
			}

			if status.Target != raw.Target_TARGET_SYSCALLS {
				t.Errorf("Expected target %v, got %v", raw.Target_TARGET_SYSCALLS, status.Target)
			}

			if status.Active != tt.expectedActive {
				t.Errorf("Expected active=%v, got %v", tt.expectedActive, status.Active)
			}

			expectedID := tt.statusID
			if tt.statusID == "" {
				expectedID = "default"
			} else {
				expectedID = strings.TrimSpace(tt.statusID)
			}

			if status.Id != expectedID {
				t.Errorf("Expected ID %s, got %s", expectedID, status.Id)
			}
		})
	}
}

func TestCleanupCaptures(t *testing.T) {
	tempDir := t.TempDir()
	originalGetDataDir := os.Getenv("DATADIR")
	os.Setenv("DATADIR", tempDir)
	defer os.Setenv("DATADIR", originalGetDataDir)

	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	// Start multiple captures
	for i := 0; i < 3; i++ {
		id := t.Name() + "-cleanup-" + string(rune('0'+i))
		_, err := StartCapture(manager, id, &raw.Config{})
		if err != nil {
			t.Fatalf("Failed to start capture %s: %v", id, err)
		}
	}

	// Perform cleanup
	resp, err := CleanupCaptures(manager)
	if err != nil {
		t.Fatalf("CleanupCaptures returned error: %v", err)
	}

	if resp.Error != "" {
		t.Errorf("Unexpected error in cleanup response: %s", resp.Error)
	}

	// Verify all writers are destroyed
	manager.mu.RLock()
	writerCount := len(manager.writers)
	manager.mu.RUnlock()

	if writerCount != 0 {
		t.Errorf("Expected 0 writers after cleanup, got %d", writerCount)
	}
}

func TestGatherStats(t *testing.T) {
	tempDir := t.TempDir()
	originalGetDataDir := os.Getenv("DATADIR")
	os.Setenv("DATADIR", tempDir)
	defer os.Setenv("DATADIR", originalGetDataDir)

	manager := NewManager(raw.Target_TARGET_SYSCALLS)

	// Create test directory with mock files
	testID := "stats-test"
	testDir := SyscallBaseDirFor(testID)
	if err := os.MkdirAll(testDir, 0o755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create test files with known timestamps
	testFiles := []struct {
		name    string
		size    int
		content []byte
	}{
		{
			name:    "2024-01-01T10:00:00.000000000Z",
			size:    1024,
			content: make([]byte, 1024),
		},
		{
			name:    "2024-01-01T11:00:00.000000000Z",
			size:    2048,
			content: make([]byte, 2048),
		},
		{
			name:    "2024-01-01T12:00:00.000000000Z",
			size:    512,
			content: make([]byte, 512),
		},
	}

	for _, tf := range testFiles {
		filePath := filepath.Join(testDir, tf.name)
		if err := os.WriteFile(filePath, tf.content, 0o644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", tf.name, err)
		}
	}

	// Start a capture to set up the writer
	_, err := StartCapture(manager, testID, &raw.Config{})
	if err != nil {
		t.Fatalf("Failed to start capture: %v", err)
	}
	defer func() {
		if w := manager.Get(testID); w != nil {
			w.Destroy()
		}
	}()

	// Test gatherStats
	stats := gatherStats(manager, testID)

	if stats.FilesCount != uint32(len(testFiles)) {
		t.Errorf("Expected FilesCount=%d, got %d", len(testFiles), stats.FilesCount)
	}

	expectedBytes := uint64(1024 + 2048 + 512)
	if stats.TotalBytes != expectedBytes {
		t.Errorf("Expected TotalBytes=%d, got %d", expectedBytes, stats.TotalBytes)
	}

	// Check timestamps
	if stats.FirstTs != nil {
		firstTime, _ := time.Parse(time.RFC3339Nano, testFiles[0].name)
		if !stats.FirstTs.AsTime().Equal(firstTime.UTC()) {
			t.Errorf("Expected FirstTs=%v, got %v", firstTime.UTC(), stats.FirstTs.AsTime())
		}
	} else {
		t.Errorf("Expected FirstTs to be set")
	}

	if stats.LastTs != nil {
		lastTime, _ := time.Parse(time.RFC3339Nano, testFiles[len(testFiles)-1].name)
		if !stats.LastTs.AsTime().Equal(lastTime.UTC()) {
			t.Errorf("Expected LastTs=%v, got %v", lastTime.UTC(), stats.LastTs.AsTime())
		}
	} else {
		t.Errorf("Expected LastTs to be set")
	}

	// Test with empty ID (should default to "default")
	emptyStats := gatherStats(manager, "")
	if emptyStats == nil {
		t.Errorf("Expected non-nil stats for empty ID")
	}

	// Test with whitespace ID
	whitespaceStats := gatherStats(manager, "   ")
	if whitespaceStats == nil {
		t.Errorf("Expected non-nil stats for whitespace ID")
	}
}

func TestSyscallBaseDirFor(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		expected string
	}{
		{
			name:     "Normal ID",
			id:       "test-id",
			expected: filepath.Join(SyscallBaseDir(), "test-id"),
		},
		{
			name:     "ID with spaces",
			id:       "test id with spaces",
			expected: filepath.Join(SyscallBaseDir(), "test id with spaces"),
		},
		{
			name:     "Empty ID",
			id:       "",
			expected: SyscallBaseDir(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SyscallBaseDirFor(tt.id)
			if result != tt.expected {
				t.Errorf("SyscallBaseDirFor(%q) = %q, want %q", tt.id, result, tt.expected)
			}
		})
	}
}
