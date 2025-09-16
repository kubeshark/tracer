package grpcservice

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	raw "github.com/kubeshark/api2/pkg/proto/raw_capture"
	"github.com/kubeshark/tracer/pkg/systemstore"
	"google.golang.org/protobuf/types/known/emptypb"
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
		id := strings.TrimSpace(req.GetId())
		if id == "" {
			// generate a sane default id if not provided
			id = time.Now().UTC().Format("20060102T150405.000000000Z07:00")
		}

		dir := systemstore.SyscallBaseDirFor(id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return &raw.StartResponse{
				Target:    req.GetTarget(),
				Id:        id,
				Dir:       dir,
				Config:    cfg,
				StartedAt: timestamppb.New(time.Now().UTC()),
				Error:     err.Error(),
			}, nil
		}

		key := "syscall_events:" + id
		systemstore.GetManager().Ensure(key, dir, true, rotateBytes, rotateInterval, maxBytes, policy)

		return &raw.StartResponse{
			Target:    req.GetTarget(),
			Id:        id,
			Dir:       dir,
			Config:    cfg,
			StartedAt: timestamppb.New(time.Now().UTC()),
			Error:     "",
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
		id := strings.TrimSpace(req.GetId())
		if id == "" {
			id = "default"
		}
		stats := gatherSyscallStats(id)
		key := "syscall_events:" + id
		systemstore.GetManager().Destroy(key)
		return &raw.StopResponse{
			Target: req.GetTarget(),
			Id:     id,
			Stats:  stats,
		}, nil

	case raw.Target_TARGET_PACKETS:
		return nil, errors.New("PACKETS target not enabled in this build")

	default:
		return nil, errors.New("unknown target")
	}
}

func (s *RawCaptureServer) GetStatus(ctx context.Context, req *raw.GetStatusRequest) (*raw.Status, error) {
	switch req.GetTarget() {
	case raw.Target_TARGET_SYSCALLS:
		id := strings.TrimSpace(req.GetId())
		if id == "" {
			id = "default"
		}
		key := "syscall_events:" + id
		st := systemstore.GetManager().StatusFor(key)
		if st == nil {
			return &raw.Status{Target: req.GetTarget(), Id: id, Active: false}, nil
		}
		return &raw.Status{
			Target:          req.GetTarget(),
			Id:              id,
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
			Drops:     st.Drops,
		}, nil

	case raw.Target_TARGET_PACKETS:
		return nil, errors.New("PACKETS target not enabled in this build")

	default:
		return nil, errors.New("unknown target")
	}
}

func (s *RawCaptureServer) Cleanup(ctx context.Context, _ *emptypb.Empty) (*raw.CleanupResponse, error) {
	systemstore.GetManager().Destroy("syscall_events")
	dir := systemstore.SyscallBaseDir()
	if dir != "" {
		if err := os.RemoveAll(dir); err != nil {
			return &raw.CleanupResponse{Error: err.Error()}, nil
		}
	}
	return &raw.CleanupResponse{Error: ""}, nil
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

// gatherSyscallStats scans the syscall dir for basic totals and first/last timestamps.
// File names are RFC3339 nano with zone (e.g. 2006-01-02T15:04:05.000000000Z07:00.bin)
func gatherSyscallStats(id string) *raw.CaptureStats {
	if strings.TrimSpace(id) == "" {
		id = "default"
	}
	key := "syscall_events:" + id
	st := systemstore.GetManager().StatusFor(key)

	dir := systemstore.SyscallBaseDirFor(id)
	drops := uint64(0)
	syscalls := uint64(0)
	if st != nil {
		drops = st.Drops
		syscalls = st.Records
	}

	stats := &raw.CaptureStats{
		FilesCount:       0,
		TotalBytes:       0,
		CapturedPackets:  0,        // not applicable for SYSCALLS
		CapturedSyscalls: syscalls, // from writer counter
		Drops:            drops,
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return stats
	}

	var names []string
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if strings.HasSuffix(name, ".bin") {
			path := filepath.Join(dir, name)
			if info, e := de.Info(); e == nil {
				stats.TotalBytes += uint64(info.Size())
				stats.FilesCount++
				names = append(names, name)
			} else if fi, se := os.Stat(path); se == nil {
				stats.TotalBytes += uint64(fi.Size())
				stats.FilesCount++
				names = append(names, name)
			}
		}
	}

	if len(names) == 0 {
		return stats
	}

	sort.Strings(names)
	first := strings.TrimSuffix(names[0], ".bin")
	last := strings.TrimSuffix(names[len(names)-1], ".bin")

	if t, e := time.Parse(time.RFC3339Nano, first); e == nil {
		stats.FirstTs = timestamppb.New(t.UTC())
	}
	if t, e := time.Parse(time.RFC3339Nano, last); e == nil {
		stats.LastTs = timestamppb.New(t.UTC())
	}
	return stats
}
