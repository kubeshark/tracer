package rawcapture

import (
	"context"
	"testing"

	raw "github.com/kubeshark/api2/pkg/proto/raw_capture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestRawCaptureServer_Start(t *testing.T) {
	manager := NewManager(raw.Target_TARGET_SYSCALLS)
	server := &RawCaptureServer{Manager: manager}

	tests := []struct {
		name        string
		request     *raw.StartRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful start",
			request: &raw.StartRequest{
				Target: raw.Target_TARGET_SYSCALLS,
				Id:     "test-start-1",
				Config: &raw.Config{
					TtlPolicy: raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST,
				},
			},
			expectError: false,
		},
		{
			name: "target mismatch",
			request: &raw.StartRequest{
				Target: raw.Target_TARGET_PACKETS, // Different from manager target
				Id:     "test-start-2",
				Config: &raw.Config{},
			},
			expectError: true,
			errorMsg:    "target mismatch",
		},
		{
			name: "nil config handled gracefully",
			request: &raw.StartRequest{
				Target: raw.Target_TARGET_SYSCALLS,
				Id:     "test-start-3",
				Config: nil,
			},
			expectError: false,
		},
		{
			name: "empty id generates default",
			request: &raw.StartRequest{
				Target: raw.Target_TARGET_SYSCALLS,
				Id:     "",
				Config: &raw.Config{},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := server.Start(context.Background(), tt.request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, manager.target, resp.Target)

				// Clean up if capture was started
				if resp != nil && resp.Error == "" {
					writer := manager.Get(resp.Id)
					if writer != nil {
						writer.Destroy()
					}
				}
			}
		})
	}
}

func TestRawCaptureServer_Stop(t *testing.T) {
	manager := NewManager(raw.Target_TARGET_SYSCALLS)
	server := &RawCaptureServer{Manager: manager}

	// Start a capture first
	startReq := &raw.StartRequest{
		Target: raw.Target_TARGET_SYSCALLS,
		Id:     "stop-test",
		Config: &raw.Config{},
	}
	startResp, err := server.Start(context.Background(), startReq)
	require.NoError(t, err)
	require.NotNil(t, startResp)
	require.Equal(t, "", startResp.Error)

	tests := []struct {
		name        string
		request     *raw.StopRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful stop",
			request: &raw.StopRequest{
				Target: raw.Target_TARGET_SYSCALLS,
				Id:     "stop-test",
			},
			expectError: false,
		},
		{
			name: "target mismatch",
			request: &raw.StopRequest{
				Target: raw.Target_TARGET_PACKETS, // Different from manager target
				Id:     "stop-test",
			},
			expectError: true,
			errorMsg:    "target mismatch",
		},
		{
			name: "stop non-existent capture",
			request: &raw.StopRequest{
				Target: raw.Target_TARGET_SYSCALLS,
				Id:     "non-existent",
			},
			expectError: false, // Should not error, just return stats
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := server.Stop(context.Background(), tt.request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, raw.Target_TARGET_SYSCALLS, resp.Target)
				assert.NotNil(t, resp.Stats)
			}
		})
	}
}

func TestRawCaptureServer_GetStatus(t *testing.T) {
	manager := NewManager(raw.Target_TARGET_SYSCALLS)
	server := &RawCaptureServer{Manager: manager}

	// Start a capture first
	startReq := &raw.StartRequest{
		Target: raw.Target_TARGET_SYSCALLS,
		Id:     "status-test",
		Config: &raw.Config{},
	}
	startResp, err := server.Start(context.Background(), startReq)
	require.NoError(t, err)
	require.NotNil(t, startResp)
	require.Equal(t, "", startResp.Error)

	// Clean up after test
	defer func() {
		writer := manager.Get("status-test")
		if writer != nil {
			writer.Destroy()
		}
	}()

	tests := []struct {
		name        string
		request     *raw.GetStatusRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful get status for active capture",
			request: &raw.GetStatusRequest{
				Target: raw.Target_TARGET_SYSCALLS,
				Id:     "status-test",
			},
			expectError: false,
		},
		{
			name: "target mismatch",
			request: &raw.GetStatusRequest{
				Target: raw.Target_TARGET_PACKETS, // Different from manager target
				Id:     "status-test",
			},
			expectError: true,
			errorMsg:    "target mismatch",
		},
		{
			name: "get status for non-existent capture",
			request: &raw.GetStatusRequest{
				Target: raw.Target_TARGET_SYSCALLS,
				Id:     "non-existent",
			},
			expectError: false, // Should return inactive status
		},
		{
			name: "empty id defaults to 'default'",
			request: &raw.GetStatusRequest{
				Target: raw.Target_TARGET_SYSCALLS,
				Id:     "",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := server.GetStatus(context.Background(), tt.request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tt.request.Target, resp.Target)

				// Check specific cases
				if tt.request.Id == "status-test" {
					// Writer is enabled but no active file yet, so not "active"
					assert.False(t, resp.Active, "Capture without active file should show as inactive")
				} else if tt.request.Id == "non-existent" {
					assert.False(t, resp.Active, "Non-existent capture should show as inactive")
				} else if tt.request.Id == "" {
					assert.Equal(t, "default", resp.Id, "Empty ID should default to 'default'")
				}
			}
		})
	}
}

func TestRawCaptureServer_Cleanup(t *testing.T) {
	manager := NewManager(raw.Target_TARGET_SYSCALLS)
	server := &RawCaptureServer{Manager: manager}

	// Start multiple captures
	captureIDs := []string{"cleanup-test-1", "cleanup-test-2", "cleanup-test-3"}
	for _, id := range captureIDs {
		startReq := &raw.StartRequest{
			Target: raw.Target_TARGET_SYSCALLS,
			Id:     id,
			Config: &raw.Config{},
		}
		startResp, err := server.Start(context.Background(), startReq)
		require.NoError(t, err)
		require.NotNil(t, startResp)
	}

	// Verify captures are active
	for _, id := range captureIDs {
		writer := manager.Get(id)
		assert.NotNil(t, writer, "Writer should exist for ID: %s", id)
	}

	// Perform cleanup
	resp, err := server.Cleanup(context.Background(), &emptypb.Empty{})
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Verify all captures are cleaned up
	for _, id := range captureIDs {
		writer := manager.Get(id)
		assert.Nil(t, writer, "Writer should be cleaned up for ID: %s", id)
	}
}

func TestRawCaptureServer_ContextHandling(t *testing.T) {
	manager := NewManager(raw.Target_TARGET_SYSCALLS)
	server := &RawCaptureServer{Manager: manager}

	// Test with canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := &raw.StartRequest{
		Target: raw.Target_TARGET_SYSCALLS,
		Id:     "canceled-context-test",
		Config: &raw.Config{},
	}

	// The service should still work even with canceled context
	// since it doesn't explicitly check context cancellation
	resp, err := server.Start(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Clean up
	if resp != nil && resp.Error == "" {
		writer := manager.Get(resp.Id)
		if writer != nil {
			writer.Destroy()
		}
	}
}

func TestRawCaptureServer_NilRequests(t *testing.T) {
	manager := NewManager(raw.Target_TARGET_SYSCALLS)
	server := &RawCaptureServer{Manager: manager}
	ctx := context.Background()

	// Test Start with nil request - protobuf getters return zero values
	// This will result in target mismatch since GetTarget() returns 0 (TARGET_UNSPECIFIED)
	resp, err := server.Start(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "target mismatch")
	assert.Nil(t, resp)

	// Test Stop with nil request - same target mismatch
	stopResp, err := server.Stop(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "target mismatch")
	assert.Nil(t, stopResp)

	// Test GetStatus with nil request - same target mismatch
	statusResp, err := server.GetStatus(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "target mismatch")
	assert.Nil(t, statusResp)

	// Test Cleanup with nil request (should work since it doesn't check target)
	cleanupResp, err := server.Cleanup(ctx, nil)
	assert.NoError(t, err)
	assert.NotNil(t, cleanupResp)
}

func TestRawCaptureServer_Integration(t *testing.T) {
	manager := NewManager(raw.Target_TARGET_SYSCALLS)
	server := &RawCaptureServer{Manager: manager}
	ctx := context.Background()

	// Full integration test: Start -> GetStatus -> Stop -> Cleanup
	captureID := "integration-test"

	// 1. Start capture
	startReq := &raw.StartRequest{
		Target: raw.Target_TARGET_SYSCALLS,
		Id:     captureID,
		Config: &raw.Config{
			TtlPolicy:   raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST,
			MaxBytes:    1024 * 1024,
			RotateBytes: 64 * 1024,
		},
	}
	startResp, err := server.Start(ctx, startReq)
	require.NoError(t, err)
	require.NotNil(t, startResp)
	require.Equal(t, "", startResp.Error)
	assert.Equal(t, captureID, startResp.Id)

	// 2. Get status (should exist but not active until data is written)
	statusReq := &raw.GetStatusRequest{
		Target: raw.Target_TARGET_SYSCALLS,
		Id:     captureID,
	}
	statusResp, err := server.GetStatus(ctx, statusReq)
	require.NoError(t, err)
	require.NotNil(t, statusResp)
	// Writer exists but no active file yet, so not "active"
	assert.False(t, statusResp.Active)
	assert.Equal(t, captureID, statusResp.Id)

	// 3. Stop capture
	stopReq := &raw.StopRequest{
		Target: raw.Target_TARGET_SYSCALLS,
		Id:     captureID,
	}
	stopResp, err := server.Stop(ctx, stopReq)
	require.NoError(t, err)
	require.NotNil(t, stopResp)
	assert.Equal(t, captureID, stopResp.Id)
	assert.NotNil(t, stopResp.Stats)

	// 4. Get status again (should be inactive)
	statusResp2, err := server.GetStatus(ctx, statusReq)
	require.NoError(t, err)
	require.NotNil(t, statusResp2)
	assert.False(t, statusResp2.Active)

	// 5. Cleanup
	cleanupResp, err := server.Cleanup(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.NotNil(t, cleanupResp)
	assert.Equal(t, "", cleanupResp.Error)
}

// TestRawCaptureServer_ErrorPropagation tests that errors from the underlying functions are properly propagated
func TestRawCaptureServer_ErrorPropagation(t *testing.T) {
	// Create a manager with a target that will cause mismatches
	manager := NewManager(raw.Target_TARGET_PACKETS)
	server := &RawCaptureServer{Manager: manager}
	ctx := context.Background()

	// Test that target mismatches are properly handled for all methods
	syscallTarget := raw.Target_TARGET_SYSCALLS

	// Start with wrong target
	startReq := &raw.StartRequest{
		Target: syscallTarget,
		Id:     "error-test",
		Config: &raw.Config{},
	}
	_, err := server.Start(ctx, startReq)
	assert.Error(t, err)
	assert.Equal(t, "target mismatch", err.Error())

	// Stop with wrong target
	stopReq := &raw.StopRequest{
		Target: syscallTarget,
		Id:     "error-test",
	}
	_, err = server.Stop(ctx, stopReq)
	assert.Error(t, err)
	assert.Equal(t, "target mismatch", err.Error())

	// GetStatus with wrong target
	statusReq := &raw.GetStatusRequest{
		Target: syscallTarget,
		Id:     "error-test",
	}
	_, err = server.GetStatus(ctx, statusReq)
	assert.Error(t, err)
	assert.Equal(t, "target mismatch", err.Error())
}
