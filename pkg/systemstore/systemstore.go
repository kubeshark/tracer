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
			target:      target,
			baseDir:     baseDir,
			rotateBytes: DefaultRotateBytes,
			maxBytes:    DefaultMaxBytes,
			policy:      TTLPolicyDeleteOldest,
			ctx:         ctx,
			cancel:      cancel,
			queue:       make(chan []byte, 8192),
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
						log.Error().Err(err).Msg("rotate by interval failed")
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
					log.Error().Err(err).Msg("rotate by size failed")
					w.mu.Unlock()
					continue
				}
			}
			if err := w.ensureQuotaLocked(uint64(len(frame))); err != nil {
				log.Warn().Err(err).Str("target", w.target).Msg("quota handling")
				if errors.Is(err, ErrQuotaStop) {
					w.enabled = false
					w.closeActiveLocked()
				}
				w.mu.Unlock()
				continue
			}
			n, err := w.activeFile.Write(frame)
			if err != nil {
				log.Error().Err(err).Str("file", w.activePath).Msg("write failed")
			}
			w.activeSize += uint64(n)
			w.mu.Unlock()
		}
	}
}

var ErrQuotaStop = errors.New("quota exceeded and policy=STOP")

func (w *Writer) ensureQuotaLocked(incoming uint64) error {
	total := uint64(0)
	files := []string{}
	_ = filepath.WalkDir(w.baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".bin") {
			if fi, e := os.Stat(path); e == nil {
				total += uint64(fi.Size())
				files = append(files, path)
			}
		}
		return nil
	})
	if total+incoming <= w.maxBytes {
		return nil
	}
	if w.policy == TTLPolicyStop {
		return ErrQuotaStop
	}
	sort.Slice(files, func(i, j int) bool {
		fi, _ := os.Stat(files[i])
		fj, _ := os.Stat(files[j])
		return fi.ModTime().Before(fj.ModTime())
	})
	for total+incoming > w.maxBytes*90/100 && len(files) > 0 {
		old := files[0]
		files = files[1:]
		if fi, _ := os.Stat(old); fi != nil {
			total -= uint64(fi.Size())
		}
		_ = os.Remove(old)
	}
	return nil
}

func (w *Writer) rotateLocked() error {
	if w.activeFile != nil {
		_ = w.activeFile.Close()
	}
	name := time.Now().UTC().Format("20060102_150405") + ".bin"
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
	binary.BigEndian.PutUint32(buf[:4], uint32(len(b)))
	copy(buf[4:], b)
	select {
	case w.queue <- buf:
	default:
		// drop on backpressure
	}
}

// Status snapshot for gRPC
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
	_ = filepath.WalkDir(w.baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".bin") {
			if fi, e := os.Stat(path); e == nil {
				total += uint64(fi.Size())
				count++
			}
		}
		return nil
	})
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
	}
}

// closeActiveLocked closes and clears the current active file.
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
