package systemstore

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kubeshark/tracer/misc"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type TTLPolicy int

const (
	TTLPolicyUnspecified TTLPolicy = iota
	TTLPolicyStop
	TTLPolicyDeleteOldest
)

const (
	DefaultRotateBytes = 64 * 1024 * 1024       // 64 MiB
	DefaultMaxBytes    = 2 * 1024 * 1024 * 1024 // 2 GiB
)

type Writer struct {
	mu sync.Mutex

	target  string
	baseDir string

	enabled        bool
	rotateBytes    uint64
	rotateInterval time.Duration
	maxBytes       uint64
	policy         TTLPolicy

	activeFile     *os.File
	activePath     string
	activeSize     uint64
	activeOpenedAt time.Time

	ctx    context.Context
	cancel context.CancelFunc
	queue  chan []byte

	dropCount   uint64 // total frames dropped due to backpressure
	recordCount uint64 // successfully written records (frames)
}

type Manager struct {
	mu      sync.RWMutex
	writers map[string]*Writer
}

var defaultManager = &Manager{writers: make(map[string]*Writer)}

func GetManager() *Manager { return defaultManager }

func (m *Manager) Ensure(target, baseDir string, enabled bool, rotateBytes uint64, rotateInterval time.Duration, maxBytes uint64, policy TTLPolicy) *Writer {
	m.mu.Lock()
	defer m.mu.Unlock()

	w := m.writers[target]
	if w == nil {
		ctx, cancel := context.WithCancel(context.Background())
		w = &Writer{
			target:         target,
			baseDir:        baseDir,
			rotateBytes:    DefaultRotateBytes,
			maxBytes:       DefaultMaxBytes,
			policy:         TTLPolicyDeleteOldest,
			ctx:            ctx,
			cancel:         cancel,
			queue:          make(chan []byte, 8192),
			activeOpenedAt: time.Time{},
		}
		_ = os.MkdirAll(baseDir, 0o755)
		go w.loop()
		m.writers[target] = w
	}
	w.applyConfig(enabled, rotateBytes, rotateInterval, maxBytes, policy)
	return w
}

func (m *Manager) Get(target string) *Writer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.writers[target]
}

// Destroy stops and removes the writer (calls cancel()).
func (m *Manager) Destroy(target string) {
	m.mu.Lock()
	w := m.writers[target]
	if w != nil {
		w.mu.Lock()
		w.enabled = false
		w.closeActiveLocked()
		w.cancel() // stop loop
		w.mu.Unlock()
		delete(m.writers, target)
	}
	m.mu.Unlock()
}

func (w *Writer) applyConfig(enabled bool, rotateBytes uint64, rotateInterval time.Duration, maxBytes uint64, policy TTLPolicy) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if rotateBytes == 0 {
		rotateBytes = DefaultRotateBytes
	}
	if maxBytes == 0 {
		maxBytes = DefaultMaxBytes
	}
	if policy == TTLPolicyUnspecified {
		policy = TTLPolicyDeleteOldest
	}
	w.rotateBytes = rotateBytes
	w.rotateInterval = rotateInterval
	w.maxBytes = maxBytes
	w.policy = policy
	w.enabled = enabled
	if !enabled {
		w.closeActiveLocked()
	}
}

func (w *Writer) Enable(v bool) {
	w.applyConfig(v, w.rotateBytes, w.rotateInterval, w.maxBytes, w.policy)
}

func (w *Writer) loop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.mu.Lock()
			if w.enabled && w.activeFile != nil && w.rotateInterval > 0 {
				if time.Since(w.activeOpenedAt) >= w.rotateInterval {
					if err := w.rotateLocked(); err != nil {
						log.Error().Err(err).Msg("systemstore: rotate by interval failed")
					}
				}
			}
			w.mu.Unlock()

		case frame := <-w.queue:
			w.mu.Lock()
			if !w.enabled {
				w.mu.Unlock()
				continue
			}
			if w.activeFile == nil || w.activeSize >= w.rotateBytes {
				if err := w.rotateLocked(); err != nil {
					log.Error().Err(err).Msg("systemstore: rotate by size failed")
					w.mu.Unlock()
					continue
				}
			}
			if err := w.ensureQuotaLocked(uint64(len(frame))); err != nil {
				log.Warn().Err(err).Str("target", w.target).Msg("systemstore: quota handling")
				if errors.Is(err, ErrQuotaStop) {
					w.enabled = false
					w.closeActiveLocked()
				}
				w.mu.Unlock()
				continue
			}
			n, err := w.activeFile.Write(frame)
			if err != nil {
				log.Error().Err(err).Str("file", w.activePath).Msg("systemstore: write failed")
			} else {
				w.recordCount++
				w.activeSize += uint64(n)
			}
			w.mu.Unlock()
		}
	}
}

var ErrQuotaStop = errors.New("quota exceeded and policy=STOP")

func (w *Writer) ensureQuotaLocked(incoming uint64) error {
	// Compute total size and collect file list lexicographically
	var total uint64
	files := []string{}

	entries, err := os.ReadDir(w.baseDir)
	if err != nil {
		return err
	}
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if strings.HasSuffix(name, ".bin") {
			path := filepath.Join(w.baseDir, name)
			if info, e := de.Info(); e == nil {
				total += uint64(info.Size())
				files = append(files, path)
			} else {
				// fall back – try stat and log if still failing
				if fi, se := os.Stat(path); se == nil {
					total += uint64(fi.Size())
					files = append(files, path)
				} else {
					log.Error().Err(se).Str("file", path).Msg("systemstore: unable to stat file during quota scan")
				}
			}
		}
	}

	if total+incoming <= w.maxBytes {
		return nil
	}
	if w.policy == TTLPolicyStop {
		return ErrQuotaStop
	}

	// Sort lexicographically: filenames are timestamps => lexicographic == chronological
	sort.Slice(files, func(i, j int) bool {
		return filepath.Base(files[i]) < filepath.Base(files[j])
	})

	// Prune oldest until we're within the limit (no 90% headroom)
	for total+incoming > w.maxBytes && len(files) > 0 {
		old := files[0]
		files = files[1:]

		fi, statErr := os.Stat(old)
		if statErr != nil {
			log.Error().Err(statErr).Str("file", old).Msg("systemstore: stat failed during prune")
			continue
		}
		size := uint64(fi.Size())
		if rmErr := os.Remove(old); rmErr != nil {
			log.Error().Err(rmErr).Str("file", old).Msg("systemstore: remove failed during prune")
			continue
		}
		total -= size
	}

	return nil
}

func (w *Writer) rotateLocked() error {
	if w.activeFile != nil {
		_ = w.activeFile.Close()
	}
	name := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00") + ".bin"
	full := filepath.Join(w.baseDir, name)
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	w.activeFile = f
	w.activePath = full
	w.activeSize = 0
	w.activeOpenedAt = time.Now().UTC()
	return nil
}

// length-prefixed write
func (w *Writer) WriteProtoLengthPrefixed(b []byte) {
	if b == nil || !w.enabled {
		return
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(b))) // write 4-byte length
	copy(buf[4:], b)

	select {
	case w.queue <- buf:
	default:
		// drop on backpressure
		w.dropCount++
		log.Debug().
			Str("target", w.target).
			Uint64("drops", w.dropCount).
			Msg("systemstore: dropped frame due to backpressure")
	}
}

// Status snapshot for gRPC (internal). NOTE: Drops is exposed here;
// to surface over gRPC responses, the api2 proto needs corresponding fields.
type Status struct {
	BaseDir         string
	ActiveFile      string
	ActiveFileBytes uint64
	TotalBytes      uint64
	FilesCount      uint32
	RotateBytes     uint64
	RotateInterval  *durationpb.Duration
	MaxBytes        uint64
	Policy          TTLPolicy
	Writing         bool
	StartedAt       *timestamppb.Timestamp
	Drops           uint64
	Records         uint64
}

func (m *Manager) StatusFor(target string) *Status {
	m.mu.RLock()
	w := m.writers[target]
	m.mu.RUnlock()
	if w == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	var total uint64
	var count uint32

	entries, err := os.ReadDir(w.baseDir)
	if err == nil {
		for _, de := range entries {
			if de.IsDir() {
				continue
			}
			name := de.Name()
			if strings.HasSuffix(name, ".bin") {
				if info, e := de.Info(); e == nil {
					total += uint64(info.Size())
					count++
				} else if fi, se := os.Stat(filepath.Join(w.baseDir, name)); se == nil {
					total += uint64(fi.Size())
					count++
				} else {
					log.Error().Err(se).Str("file", name).Msg("systemstore: stat failed computing status")
				}
			}
		}
	} else {
		log.Error().Err(err).Str("dir", w.baseDir).Msg("systemstore: readdir failed computing status")
	}

	return &Status{
		BaseDir:         w.baseDir,
		ActiveFile:      w.activePath,
		ActiveFileBytes: w.activeSize,
		TotalBytes:      total,
		FilesCount:      count,
		RotateBytes:     w.rotateBytes,
		RotateInterval:  durationpb.New(w.rotateInterval),
		MaxBytes:        w.maxBytes,
		Policy:          w.policy,
		Writing:         w.enabled && w.activeFile != nil,
		StartedAt:       timestamppb.New(w.activeOpenedAt),
		Drops:           w.dropCount,
		Records:         w.recordCount,
	}
}

// closeActiveLocked closes and clears the current active file.
// Callers must hold w.mu.
func (w *Writer) closeActiveLocked() {
	if w.activeFile != nil {
		_ = w.activeFile.Close()
		w.activeFile = nil
	}
	w.activePath = ""
	w.activeSize = 0
}

// Paths
func SyscallBaseDir() string { return filepath.Join(misc.GetDataDir(), "system", "syscall_events") }
