package rawcapture

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	raw "github.com/kubeshark/api2/pkg/proto/raw_capture"
	"github.com/rs/zerolog/log"
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

// StartCapture starts a new syscall capture session
func StartCapture(manager *Manager, id string, cfg *raw.Config) (*raw.StartResponse, error) {
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

	var dir string
	if manager.target == raw.Target_TARGET_PACKETS {
		dir = PcapBaseDirFor(manager.baseDir, id)
	} else if manager.target == raw.Target_TARGET_SYSCALLS {
		dir = SyscallBaseDirFor(manager.baseDir, id)
	}
	if dir == "" {
		return &raw.StartResponse{
			Target: manager.target,
			Id:     id,
			Dir:    dir,
			Config: cfg,
			Error:  "invalid target",
		}, nil
	}
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

	log.Info().Str("dir", dir).Str("target", manager.target.String()).Str("id", id).Str("config", cfg.String()).Msg("started capture")
	return &raw.StartResponse{
		Target:    manager.target,
		Id:        id,
		Dir:       dir,
		Config:    cfg,
		StartedAt: timestamppb.New(time.Now().UTC()),
		Error:     "",
	}, nil
}

// StopCapture stops a syscall capture session
func StopCapture(manager *Manager, id string) (*raw.StopResponse, error) {
	id = strings.TrimSpace(id)
	stats := gatherStats(manager, id)
	writer := manager.Get(id)
	if writer != nil {
		writer.Destroy()
	}
	log.Info().Str("target", manager.target.String()).Str("id", id).Stringer("stats", stats).Msg("stopped capture")
	return &raw.StopResponse{
		Target: raw.Target_TARGET_SYSCALLS,
		Id:     id,
		Stats:  stats,
	}, nil
}

// GetCaptureStatus returns the status of a syscall capture session
func GetCaptureStatus(manager *Manager, target raw.Target, id string) (*raw.Status, error) {
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

// CleanupCaptures cleans up all syscall capture data
func CleanupCaptures(manager *Manager) (*raw.CleanupResponse, error) {
	manager.Destroy()
	dir := captureBaseDir(manager.baseDir)
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

	var dir string
	if manager.target == raw.Target_TARGET_PACKETS {
		dir = PcapBaseDirFor(manager.baseDir, id)
	} else if manager.target == raw.Target_TARGET_SYSCALLS {
		dir = SyscallBaseDirFor(manager.baseDir, id)
	}
	if dir == "" {
		return &raw.CaptureStats{
			FilesCount:       0,
			TotalBytes:       0,
			CapturedPackets:  0,
			CapturedSyscalls: 0,
			Drops:            0,
		}
	}
	drops := uint64(0)
	items := uint64(0)
	if st != nil {
		drops = st.Drops
		items = st.Records
	}

	stats := &raw.CaptureStats{
		FilesCount: 0,
		TotalBytes: 0,
		Drops:      drops,
	}
	if manager.target == raw.Target_TARGET_PACKETS {
		stats.CapturedPackets = items
	} else if manager.target == raw.Target_TARGET_SYSCALLS {
		stats.CapturedSyscalls = items
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return stats
	}

	var first, last string
	hasFiles := false

	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		path := filepath.Join(dir, name)
		if info, e := de.Info(); e == nil {
			stats.TotalBytes += uint64(info.Size())
			stats.FilesCount++

			// Track first and last filenames (lexicographically)
			if !hasFiles {
				first = name
				last = name
				hasFiles = true
			} else {
				if name < first {
					first = name
				}
				if name > last {
					last = name
				}
			}
		} else if fi, se := os.Stat(path); se == nil {
			stats.TotalBytes += uint64(fi.Size())
			stats.FilesCount++

			// Track first and last filenames (lexicographically)
			if !hasFiles {
				first = name
				last = name
				hasFiles = true
			} else {
				if name < first {
					first = name
				}
				if name > last {
					last = name
				}
			}
		}
	}

	if !hasFiles {
		return stats
	}

	if t, e := time.Parse(time.RFC3339Nano, first); e == nil {
		stats.FirstTs = timestamppb.New(t.UTC())
	}
	if t, e := time.Parse(time.RFC3339Nano, last); e == nil {
		stats.LastTs = timestamppb.New(t.UTC())
	}
	return stats
}
