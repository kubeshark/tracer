package rawcapture

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	raw "github.com/kubeshark/api2/pkg/proto/raw_capture"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PolicyConversion functions for converting between API and internal types

// toPolicy converts API TTLPolicy to systemstore TTLPolicy
func toPolicy(p raw.TTLPolicy) TTLPolicy {
	switch p {
	case raw.TTLPolicy_TTL_POLICY_STOP:
		return TTLPolicyStop
	case raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST:
		return TTLPolicyDeleteOldest
	default:
		return TTLPolicyDeleteOldest
	}
}

// FromPolicy converts systemstore TTLPolicy to API TTLPolicy
func FromPolicy(p TTLPolicy) raw.TTLPolicy {
	switch p {
	case TTLPolicyStop:
		return raw.TTLPolicy_TTL_POLICY_STOP
	case TTLPolicyDeleteOldest:
		return raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST
	default:
		return raw.TTLPolicy_TTL_POLICY_DELETE_OLDEST
	}
}

// startCapture starts a new syscall capture session
func startCapture(manager *Manager, id string, cfg *raw.Config) (*raw.StartResponse, error) {
	if cfg == nil {
		cfg = &raw.Config{}
	}
	policy := toPolicy(cfg.GetTtlPolicy())
	rotateBytes := cfg.GetRotateBytes()
	rotateInterval := cfg.GetRotateInterval().AsDuration()
	maxBytes := cfg.GetMaxBytes()

	id = strings.TrimSpace(id)
	if id == "" {
		// generate a sane default id if not provided
		id = time.Now().UTC().Format("20060102T150405.000000000Z07:00")
	}

	dir := SyscallBaseDirFor(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return &raw.StartResponse{
			Target: manager.target,
			Id:     id,
			Dir:    dir,
			Config: cfg,
			Error:  err.Error(),
		}, nil
	}

	if err := manager.StartCapturing(dir, id, true, rotateBytes, rotateInterval, maxBytes, policy); err != nil {
		return &raw.StartResponse{
			Target: manager.target,
			Id:     id,
			Dir:    dir,
			Config: cfg,
			Error:  err.Error(),
		}, nil
	}

	return &raw.StartResponse{
		Target:    manager.target,
		Id:        id,
		Dir:       dir,
		Config:    cfg,
		StartedAt: timestamppb.New(time.Now().UTC()),
		Error:     "",
	}, nil
}

// stopCapture stops a syscall capture session
func stopCapture(manager *Manager, id string) (*raw.StopResponse, error) {
	id = strings.TrimSpace(id)
	stats := gatherStats(manager, id)
	manager.Get(id).Destroy()
	return &raw.StopResponse{
		Target: raw.Target_TARGET_SYSCALLS,
		Id:     id,
		Stats:  stats,
	}, nil
}

// getCaptureStatus returns the status of a syscall capture session
func getCaptureStatus(manager *Manager, target raw.Target, id string) (*raw.Status, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		id = "default"
	}
	st := manager.StatusFor(id)
	if st == nil {
		return &raw.Status{Target: target, Id: id, Active: false}, nil
	}
	return &raw.Status{
		Target:          target,
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
			TtlPolicy:      FromPolicy(st.Policy),
		},
		StartedAt: st.StartedAt,
		Drops:     st.Drops,
	}, nil
}

// cleanupCaptures cleans up all syscall capture data
func cleanupCaptures(manager *Manager) (*raw.CleanupResponse, error) {
	manager.Destroy()
	dir := captureBaseDir()
	if dir != "" {
		if err := os.RemoveAll(dir); err != nil {
			return &raw.CleanupResponse{Error: err.Error()}, nil
		}
	}
	return &raw.CleanupResponse{Error: ""}, nil
}

// gatherStats scans the syscall dir for basic totals and first/last timestamps.
// File names are RFC3339 nano with zone (e.g. 2006-01-02T15:04:05.000000000Z07:00)
func gatherStats(manager *Manager, id string) *raw.CaptureStats {
	if strings.TrimSpace(id) == "" {
		id = "default"
	}
	st := manager.StatusFor(id)

	dir := SyscallBaseDirFor(id)
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

	if len(names) == 0 {
		return stats
	}

	sort.Strings(names)
	first := names[0]
	last := names[len(names)-1]

	if t, e := time.Parse(time.RFC3339Nano, first); e == nil {
		stats.FirstTs = timestamppb.New(t.UTC())
	}
	if t, e := time.Parse(time.RFC3339Nano, last); e == nil {
		stats.LastTs = timestamppb.New(t.UTC())
	}
	return stats
}
