package discoverer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/go-errors/errors"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/hooks/ssl"

	"github.com/rs/zerolog/log"
)

type sslHooksKey struct {
	deviceId uint32
	path     string
}

type sslHooksValue struct {
	hooks ssl.SslHooks
	path  string
}

type sslHooksManager struct {
	bpfObjects     *bpf.BpfObjects
	hooksMap       map[sslHooksKey]map[uint64]*sslHooksValue
	unknownDevices map[uint32]struct{}
	hooksMtx       sync.Mutex
}

func newSslHooksManager(bpfObjects *bpf.BpfObjects) *sslHooksManager {
	return &sslHooksManager{
		bpfObjects:     bpfObjects,
		hooksMap:       make(map[sslHooksKey]map[uint64]*sslHooksValue),
		unknownDevices: make(map[uint32]struct{}),
	}
}

func (h *sslHooksManager) attachFile(cgroupId uint64, deviceId uint32, path string) error {
	h.hooksMtx.Lock()
	defer h.hooksMtx.Unlock()
	if _, ok := h.unknownDevices[deviceId]; ok {
		return nil
	}
	k := sslHooksKey{deviceId: deviceId, path: path}
	cgroupMap, ok := h.hooksMap[k]
	if ok {
		if _, ok := cgroupMap[cgroupId]; ok {
			// already installed
			return nil
		}
		log.Debug().Str("path", path).Uint64("Cgroup ID", cgroupId).Uint32("device", deviceId).Msg("Attach new Cgroup ID")
	} else {
		h.hooksMap[k] = make(map[uint64]*sslHooksValue)
	}

	mi, err := parseMountInfo()
	if err != nil {
		return err
	}

	mountEntry, ok := mi[deviceId]
	if !ok {
		log.Debug().Str("path", path).Uint64("Cgroup ID", cgroupId).Uint32("device", deviceId).Msg("Device ID not found")
		h.unknownDevices[deviceId] = struct{}{}
		return nil
	}

	fullPath := filepath.Join(mountEntry, path)

	hooks := ssl.SslHooks{}
	err = hooks.InstallUprobes(h.bpfObjects, fullPath)
	if err == nil {
		val := &sslHooksValue{
			hooks: hooks,
			path:  fullPath,
		}
		h.hooksMap[k][cgroupId] = val
		log.Debug().Str("full path", fullPath).Str("path", path).Uint64("Cgroup ID", cgroupId).Str("device", fmt.Sprintf("%x", deviceId)).Msg("New ssl hook is attached")
	} else if errors.Is(err, os.ErrNotExist) {
		// file can be already removed
		log.Debug().Err(err).Str("path", fullPath).Str("path", path).Uint64("Cgroup ID", cgroupId).Str("device", fmt.Sprintf("%x", deviceId)).Msg("Install uprobe missed")
	} else {
		return err
	}
	return nil
}

func (h *sslHooksManager) detachFile(cgroupId uint64) error {
	h.hooksMtx.Lock()
	defer h.hooksMtx.Unlock()
	for k, v := range h.hooksMap {
		if _, ok := v[cgroupId]; !ok {
			continue
		}
		for cgroup, hooks := range v {
			errs := hooks.hooks.Close()
			for _, err := range errs {
				log.Warn().Uint64("Cgroup ID", cgroup).Uint32("device", k.deviceId).Str("path", k.path).Msg(fmt.Sprintf("Detach ssl hook failed: %v", err))
			}
			log.Debug().Uint64("Cgroup ID", cgroup).Uint32("device", k.deviceId).Str("path", k.path).Msg("Detached ssl hook")
		}
		delete(h.hooksMap, k)
	}
	return nil
}

// parseMountInfo parses /proc/self/mountinfo and extracts overlayfs mounts.
// It returns a map where key = device ID (numerical format) and value = root filesystem path.
func parseMountInfo() (map[uint32]string, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	overlayMounts := make(map[uint32]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue // Skip invalid lines
		}

		fsType := fields[len(fields)-3] // Filesystem type is at position -3 from the end
		if fsType != "overlay" {
			continue // Skip non-overlayfs mounts
		}

		deviceID := fields[2] // Major:Minor device ID
		rootPath := fields[4] // Root path of the mount

		// Convert deviceID to a numerical format (major * 256 + minor)
		devParts := strings.Split(deviceID, ":")
		if len(devParts) != 2 {
			continue
		}
		major, err := strconv.ParseUint(devParts[0], 10, 32)
		if err != nil {
			continue
		}
		minor, err := strconv.ParseUint(devParts[1], 10, 32)
		if err != nil {
			continue
		}
		deviceNum := (major << 20) | minor // Using kernel encoding for dev_t

		overlayMounts[uint32(deviceNum)] = rootPath
		log.Debug().Str("path", rootPath).Uint64("Major", major).Uint64("Minor", minor).Uint32("Device ID", uint32(deviceNum)).Msg("Found new mount entry")
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return overlayMounts, nil
}
