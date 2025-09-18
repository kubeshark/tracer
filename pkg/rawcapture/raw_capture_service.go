package rawcapture

import (
	"context"
	"errors"

	raw "github.com/kubeshark/api2/pkg/proto/raw_capture"
	"google.golang.org/protobuf/types/known/emptypb"
)

type RawCaptureServer struct {
	raw.UnimplementedRawCaptureServer
	Manager *Manager
}

func (s *RawCaptureServer) Start(ctx context.Context, req *raw.StartRequest) (*raw.StartResponse, error) {
	if req.GetTarget() != s.Manager.target {
		return nil, errors.New("target mismatch")
	}
	return startCapture(s.Manager, req.GetId(), req.GetConfig())
}

func (s *RawCaptureServer) Stop(ctx context.Context, req *raw.StopRequest) (*raw.StopResponse, error) {
	if req.GetTarget() != s.Manager.target {
		return nil, errors.New("target mismatch")
	}
	return stopCapture(s.Manager, req.GetId())
}

func (s *RawCaptureServer) GetStatus(ctx context.Context, req *raw.GetStatusRequest) (*raw.Status, error) {
	if req.GetTarget() != s.Manager.target {
		return nil, errors.New("target mismatch")
	}
	return getCaptureStatus(s.Manager, req.GetTarget(), req.GetId())
}

func (s *RawCaptureServer) Cleanup(ctx context.Context, _ *emptypb.Empty) (*raw.CleanupResponse, error) {
	return cleanupCaptures(s.Manager)
}
