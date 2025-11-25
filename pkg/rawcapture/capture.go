package rawcapture

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	raw "github.com/kubeshark/api2/pkg/proto/raw_capture"
	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/tracer/misc"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/proto"
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

	target  raw.Target
	baseDir string
	id      string

	enabled        bool
	rotateBytes    uint64
	rotateInterval time.Duration
	maxBytes       uint64
	policy         TTLPolicy

	activeFile     *os.File
	activePath     string
	activeSize     uint64
	activeOpenedAt time.Time
	pcapWriter     *pcapgo.Writer // PCAP writer for packet data
	bufWriter      *bufio.Writer
	lastFlush      time.Time

	ctx    context.Context
	cancel context.CancelFunc
	queue  chan []byte

	dropCount   uint64 // total frames dropped due to backpressure
	recordCount uint64 // successfully written records (frames)

	bytesSinceLastQuotaCheck uint64
	needsQuotaCheck          bool
}

type Manager struct {
	mu      sync.RWMutex
	target  raw.Target
	writers map[string]*Writer
	baseDir string
}

func NewManager(target raw.Target) *Manager {
	return &Manager{target: target, writers: make(map[string]*Writer), baseDir: misc.GetDataDir()}
}

// EnqueueSyscall marshals and enqueues a syscall event to the writer.
func (m *Manager) EnqueueSyscall(ev *raw.SyscallEvent) {
	m.mu.RLock()
	if len(m.writers) == 0 {
		m.mu.RUnlock()
		return
	}
	m.mu.RUnlock()
	b, err := proto.Marshal(ev)
	if err != nil {
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, w := range m.writers {
		w.writeProtoLengthPrefixed(b)
	}
}

// EnqueuePacket enqueues a packet to the writer.
func (m *Manager) EnqueuePacket(timestamp uint64, pkt []byte) {
	m.mu.RLock()
	if len(m.writers) == 0 {
		m.mu.RUnlock()
		return
	}
	m.mu.RUnlock()

	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, w := range m.writers {
		w.writePacketToPcapFile(timestamp, pkt)
	}
}

func (m *Manager) StartCapturing(baseDir string, id string, enabled bool, rotateBytes uint64, rotateInterval time.Duration, maxBytes uint64, policy TTLPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	w := m.writers[id]
	if w != nil {
		return fmt.Errorf("capture already started for id: %s", id)
	}
	ctx, cancel := context.WithCancel(context.Background())
	w = &Writer{
		target:         m.target,
		baseDir:        baseDir,
		id:             id,
		rotateBytes:    DefaultRotateBytes,
		maxBytes:       DefaultMaxBytes,
		policy:         TTLPolicyDeleteOldest,
		ctx:            ctx,
		cancel:         cancel,
		queue:          make(chan []byte, 8192),
		activeOpenedAt: time.Time{},
		lastFlush:      time.Now(),
	}
	go w.loop()
	m.writers[id] = w
	w.applyConfig(enabled, rotateBytes, rotateInterval, maxBytes, policy)
	return nil
}

func (m *Manager) Get(id string) *Writer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.writers[id]
}

// Destroy stops and removes the writer (calls cancel()).
func (m *Manager) Destroy() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, w := range m.writers {
		if w != nil {
			w.Destroy()
		}
		delete(m.writers, id)
	}
}

func (m *Manager) UpdateBaseDir() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.baseDir = misc.GetDataDir()
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

func (w *Writer) Destroy() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enabled = false
	w.closeActiveLocked()
	w.cancel()
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
			if w.bufWriter != nil && time.Since(w.lastFlush) >= 10*time.Second {
				if err := w.bufWriter.Flush(); err != nil {
					log.Error().Err(err).Msg("systemstore: periodic flush failed")
				}
				w.lastFlush = time.Now()
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
			w.bytesSinceLastQuotaCheck += uint64(len(frame))
			if w.needsQuotaCheck || w.bytesSinceLastQuotaCheck >= 100*1024*1024 {
				if err := w.ensureQuotaLocked(uint64(len(frame))); err != nil {
					log.Warn().Err(err).Str("target", w.target.String()).Str("id", w.id).Msg("systemstore: quota handling")
					if errors.Is(err, ErrQuotaStop) {
						w.enabled = false
						w.closeActiveLocked()
					}
					w.mu.Unlock()
					continue
				}
				w.bytesSinceLastQuotaCheck = 0
				w.needsQuotaCheck = false
			}

			// Handle packet data
			if w.target == raw.Target_TARGET_PACKETS {
				// Parse packet data from queue format (timestamp + length + data)
				if len(frame) >= 12 {
					timestamp := binary.BigEndian.Uint64(frame[0:8])
					length := binary.BigEndian.Uint32(frame[8:12])
					packetData := frame[12:]

					if len(packetData) == int(length) {
						ci := gopacket.CaptureInfo{
							Timestamp:     time.Unix(0, int64(timestamp)),
							CaptureLength: len(packetData),
							Length:        len(packetData),
						}
						if err := w.pcapWriter.WritePacket(ci, packetData); err != nil {
							log.Error().Err(err).Str("file", w.activePath).Msg("systemstore: pcap write failed")
						} else {
							w.recordCount++
							w.activeSize += uint64(len(frame))
						}
					} else {
						log.Error().Int("expected", int(length)).Int("actual", len(packetData)).Msg("systemstore: packet length mismatch")
					}
				} else {
					log.Error().Int("frame_len", len(frame)).Msg("systemstore: invalid packet frame format")
				}
			} else if w.target == raw.Target_TARGET_SYSCALLS {
				// Regular protobuf data write
				n, err := w.bufWriter.Write(frame)
				if err != nil {
					log.Error().Err(err).Str("file", w.activePath).Msg("systemstore: write failed")
				} else {
					w.recordCount++
					w.activeSize += uint64(n)
				}
			} else {
				log.Fatal().Str("target", w.target.String()).Msg("systemstore: invalid target")
			}
			w.mu.Unlock()
		}
	}
}

var ErrQuotaStop = errors.New("quota exceeded and policy=STOP")

// collectOldestFiles collects up to maxFiles of the oldest files (lexicographically first)
// and returns them along with the total size of all files processed
func (w *Writer) collectOldestFiles(maxFiles int) ([]string, uint64, error) {
	var total uint64
	var oldestFiles []string

	entries, err := os.ReadDir(w.baseDir)
	if err != nil {
		return nil, 0, err
	}

	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		path := filepath.Join(w.baseDir, name)

		var size uint64
		if info, e := de.Info(); e == nil {
			size = uint64(info.Size())
		} else {
			// fall back – try stat and log if still failing
			if fi, se := os.Stat(path); se == nil {
				size = uint64(fi.Size())
			} else {
				log.Error().Err(se).Str("file", path).Msg("systemstore: unable to stat file during quota scan")
				continue
			}
		}

		total += size

		// Insert file into sorted position (maintaining lexicographic order)
		// Create a slice of just the basenames for binary search
		basenames := make([]string, len(oldestFiles))
		for i, file := range oldestFiles {
			basenames[i] = filepath.Base(file)
		}

		// Use binary search to find insertion position
		insertPos, _ := slices.BinarySearch(basenames, name)
		oldestFiles = slices.Insert(oldestFiles, insertPos, path)

		// Keep only the oldest files if we exceed maxFiles
		if len(oldestFiles) > maxFiles {
			oldestFiles = oldestFiles[:maxFiles]
		}
	}

	return oldestFiles, total, nil
}

func (w *Writer) ensureQuotaLocked(incoming uint64) error {
	const maxFilesToCheck = 10

	for {
		// Collect oldest files and total size
		oldestFiles, total, err := w.collectOldestFiles(maxFilesToCheck)
		if err != nil {
			return err
		}

		if total+incoming <= w.maxBytes {
			return nil
		}
		if w.policy == TTLPolicyStop {
			return ErrQuotaStop
		}

		// Try to remove files from the oldest list
		removedAny := false
		for len(oldestFiles) > 0 && total+incoming > w.maxBytes {
			old := oldestFiles[0]
			oldestFiles = oldestFiles[1:]

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
			removedAny = true
		}

		// If we couldn't remove any files or quota is satisfied, we're done
		if !removedAny || total+incoming <= w.maxBytes {
			break
		}

		// If we still need more space and have more files to check, repeat the process
		// This handles cases where we have more than maxFilesToCheck files
	}

	return nil
}

func (w *Writer) rotateLocked() error {
	if w.activeFile != nil {
		if w.bufWriter != nil {
			_ = w.bufWriter.Flush()
		}
		_ = w.activeFile.Close()
	}
	name := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
	full := filepath.Join(w.baseDir, name)
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	w.activeFile = f
	w.activePath = full
	w.activeSize = 0
	w.activeOpenedAt = time.Now().UTC()
	w.needsQuotaCheck = true
	w.lastFlush = time.Now()

	w.bufWriter = bufio.NewWriterSize(f, 8*1024*1024)

	// Initialize PCAP writer for packet data and write header for new file
	if w.target == raw.Target_TARGET_PACKETS {
		w.pcapWriter = pcapgo.NewWriter(w.bufWriter)
		// Write PCAP header with raw link type
		if err := w.pcapWriter.WriteFileHeader(65536, layers.LinkTypeRaw); err != nil {
			return fmt.Errorf("failed to write PCAP header: %v", err)
		}
	}

	return nil
}

// length-prefixed write
func (w *Writer) writeProtoLengthPrefixed(b []byte) {
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
			Str("target", w.target.String()).
			Str("id", w.id).
			Uint64("drops", w.dropCount).
			Msg("systemstore: dropped frame due to backpressure")
	}
}

// writePacketToPcapFile writes a packet to a PCAP file with proper formatting
func (w *Writer) writePacketToPcapFile(timestamp uint64, pkt []byte) {
	if pkt == nil || !w.enabled {
		return
	}

	// Create capture info with timestamp and packet length
	ci := gopacket.CaptureInfo{
		CaptureLength: len(pkt),
		Length:        len(pkt),
	}

	// Convert nanosecond timestamp to time.Time
	if timestamp != 0 {
		ci.Timestamp = time.Unix(0, int64(timestamp))
	} else {
		ci.Timestamp = time.Now()
	}

	select {
	case w.queue <- w.formatPacketForQueue(ci, pkt):
	default:
		// drop on backpressure
		w.dropCount++
		log.Debug().
			Str("target", w.target.String()).
			Str("id", w.id).
			Uint64("drops", w.dropCount).
			Msg("systemstore: dropped packet due to backpressure")
	}
}

// formatPacketForQueue formats packet data with capture info for the queue
func (w *Writer) formatPacketForQueue(ci gopacket.CaptureInfo, pkt []byte) []byte {
	// Create a buffer with timestamp (8 bytes) + length (4 bytes) + packet data
	buf := make([]byte, 12+len(pkt))

	// Write timestamp (nanoseconds)
	binary.BigEndian.PutUint64(buf[0:8], uint64(ci.Timestamp.UnixNano()))

	// Write packet length
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(pkt)))

	// Copy packet data
	copy(buf[12:], pkt)

	return buf
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

func (m *Manager) StatusFor(id string) *Status {
	m.mu.RLock()
	w := m.writers[id]
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
		if w.bufWriter != nil {
			_ = w.bufWriter.Flush()
			w.bufWriter = nil
		}
		_ = w.activeFile.Close()
		w.activeFile = nil
	}
	w.activePath = ""
	w.activeSize = 0
	w.pcapWriter = nil
}

// Paths
func captureBaseDir(baseDir string) string { return filepath.Join(baseDir, "capture") }

// SyscallBaseDir returns the directory for syscall events.
func SyscallBaseDir(baseDir string) string {
	return filepath.Join(captureBaseDir(baseDir), "syscall_events")
}

func SyscallBaseDirFor(baseDir, id string) string {
	return filepath.Join(SyscallBaseDir(baseDir), id)
}

// PcapBaseDir returns the directory for pcap files.
func PcapBaseDir(baseDir string) string {
	return filepath.Join(captureBaseDir(baseDir), "pcap")
}

func PcapBaseDirFor(baseDir, id string) string {
	return filepath.Join(PcapBaseDir(baseDir), id)
}
