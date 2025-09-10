package grpcservice

import (
	"context"
	"errors"
	"os"
	"time"

	raw "github.com/kubeshark/api2/pkg/proto/raw_capture"
	"github.com/kubeshark/tracer/pkg/systemstore"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type RawCaptureServer struct {
	*GRPCService
	raw.UnimplementedRawCaptureServer
}

func (s *RawCaptureServer) Start(ctx context.Context, req *raw.StartRequest) (*raw.StartResponse, error) {
	cfg := req.GetConfig()
	if cfg == nil {
		cfg = &raw.Config{}
	}
	policy := toPolicy(cfg.GetTtlPolicy())
	rotateBytes := cfg.GetRotateBytes()
	rotateInterval := cfg.GetRotateInterval().AsDuration()
	maxBytes := cfg.GetMaxBytes()

	switch req.GetTarget() {
	case raw.Target_TARGET_SYSCALLS:
		dir := systemstore.SyscallBaseDir()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		systemstore.GetManager().Ensure("syscall_events", dir, true, rotateBytes, rotateInterval, maxBytes, policy)
		return &raw.StartResponse{
			Target:    req.GetTarget(),
			Dir:       dir,
			Config:    cfg,
			StartedAt: timestamppb.New(time.Now().UTC()),
		}, nil
	case raw.Target_TARGET_PACKETS:
		return nil, errors.New("PACKETS target not enabled in this build")
	default:
		return nil, errors.New("unknown target")
	}
}

func (s *RawCaptureServer) Stop(ctx context.Context, req *raw.StopRequest) (*raw.StopResponse, error) {
	switch req.GetTarget() {
	case raw.Target_TARGET_SYSCALLS:
		w := systemstore.GetManager().Get("syscall_events")
		if w != nil {
			w.Enable(false)
		}
		return &raw.StopResponse{Target: req.GetTarget()}, nil
	case raw.Target_TARGET_PACKETS:
		return nil, errors.New("PACKETS target not enabled in this build")
	default:
		return nil, errors.New("unknown target")
	}
}

func (s *RawCaptureServer) GetStatus(ctx context.Context, req *raw.GetStatusRequest) (*raw.Status, error) {
	switch req.GetTarget() {
	case raw.Target_TARGET_SYSCALLS:
		st := systemstore.GetManager().StatusFor("syscall_events")
		if st == nil {
			return &raw.Status{Target: req.GetTarget(), Active: false}, nil
		}
		return &raw.Status{
			Target:          req.GetTarget(),
			Active:          st.Writing,
			Dir:             st.BaseDir,
			ActiveFile:      st.ActiveFile,
			ActiveFileBytes: st.ActiveFileBytes,
			TotalBytes:      st.TotalBytes,
			FilesCount:      st.FilesCount,
			Config: &raw.Config{
				MaxBytes:       st.MaxBytes,
				RotateBytes:    st.RotateBytes,
				RotateInterval: st.RotateInterval,
				TtlPolicy:      fromPolicy(st.Policy),
			},
			StartedAt: st.StartedAt,
		}, nil
	case raw.Target_TARGET_PACKETS:
		return nil, errors.New("PACKETS target not enabled in this build")
	default:
		return nil, errors.New("unknown target")
	}
}

// Map API policy to writer policy
func toPolicy(p raw.TTLPolicy) systemstore.TTLPolicy {
	switch p {
	case raw.TTLPolicy_TTL_POLICY_STOP:
		return systemstore.TTLPolicyStop
	case raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST:
		return systemstore.TTLPolicyDeleteOldest
	default:
		return systemstore.TTLPolicyDeleteOldest
	}
}

func fromPolicy(p systemstore.TTLPolicy) raw.TTLPolicy {
	switch p {
	case systemstore.TTLPolicyStop:
		return raw.TTLPolicy_TTL_POLICY_STOP
	case systemstore.TTLPolicyDeleteOldest:
		return raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST
	default:
		return raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST
	}
}
