package main

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/types"
)

var numberRegex = regexp.MustCompile("[0-9]+")

type pidInformation struct {
	podId              types.UID
	cgroupPath         string
	containerCgroupIds []uint64
}

type cgroupVersion uint8

type tracerCgroup struct {
	pidsInfo map[uint32]pidInformation
}

// TODO: make as object component:
var cgroupsInfo, _ = lru.New[uint64, string](4096)

func NewTracerCgroup(procfs string, containerIds map[string]types.UID) (*tracerCgroup, error) {

	tc := &tracerCgroup{
		pidsInfo: make(map[uint32]pidInformation),
	}

	isCgroupV2, err := isCgroupV2()
	if err != nil {
		return nil, err
	}

	pids, err := os.ReadDir(procfs)
	if err != nil {
		return nil, err
	}

	if isCgroupV2 {
		if err = tc.scanPidsV2(procfs, pids, containerIds); err != nil {
			return nil, err
		}
	} else {
		if err = tc.scanPidsV1(procfs, pids, containerIds); err != nil {
			return nil, err
		}
	}

	return tc, nil
}

func (t *tracerCgroup) scanPidsV2(procfs string, pids []os.DirEntry, containerIds map[string]types.UID) error {
	cgroupPaths := make(map[string][]uint32)

	for _, pid := range pids {
		if !numberRegex.MatchString(pid.Name()) {
			continue
		}

		fpath := fmt.Sprintf("%s/%s/cgroup", procfs, pid.Name())

		bytes, err := os.ReadFile(fpath)
		if err != nil {
			log.Debug().Err(err).Str("pid", pid.Name()).Msg("Couldn't read cgroup file.")
			continue
		}

		n, err := strconv.ParseUint(pid.Name(), 10, 32)
		if err != nil {
			log.Warn().Err(err).Str("pid", pid.Name()).Msg("Couldn't parse pid number.")
			continue
		}
		pInfo := t.pidsInfo[uint32(n)]

		lines := strings.Split(string(bytes), "\n")
		parts := strings.Split(lines[0], ":")
		cgroupPath := parts[len(parts)-1]

		parts = strings.Split(cgroupPath, "/")
		parts = strings.Split(parts[len(parts)-1], "-")
		parts = strings.Split(parts[len(parts)-1], ".")

		containerId := parts[0]

		// filter by ContainerID:
		podUID, ok := containerIds[containerId]
		if !ok {
			continue
		}

		cgroupPaths[normalyzeCgroupV2Path(cgroupPath)] = append(cgroupPaths[normalyzeCgroupV2Path(cgroupPath)], uint32(n))

		pInfo.podId = podUID

		t.pidsInfo[uint32(n)] = pInfo
	}

	walk := func(s string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			for cgroupPath := range cgroupPaths {
				if !strings.HasSuffix(s, cgroupPath) {
					continue
				}
				containerCgroupId, err := getCgroupId(s)
				if err != nil {
					log.Warn().Err(err).Str("path", s).Msg("Couldn't get container cgroup ID.")
					continue
				}
				cgroupsInfo.Add(containerCgroupId, getContainerIdFromCgroupPath(cgroupPath))

				for _, p := range cgroupPaths[cgroupPath] {
					pInfo := t.pidsInfo[p]

					pInfo.containerCgroupIds = append(pInfo.containerCgroupIds, containerCgroupId)

					if pInfo.cgroupPath == "" {
						pInfo.cgroupPath = filepath.Dir(s)
					}

					t.pidsInfo[p] = pInfo
				}
			}
			return nil
		}
		return nil
	}
	lookupPaths := []string{
		"/sys/fs/cgroup/kubepods.slice",
		"/sys/fs/cgroup/system.slice",
		"/sys/fs/cgroup",
	}
	for _, lookupPath := range lookupPaths {
		_ = filepath.WalkDir(lookupPath, walk)
	}

	return nil
}

func getContainerIdFromCgroupPath(cgroupPath string) (cid string) {
	cgroupParts := strings.Split(cgroupPath, "/")

	for i := len(cgroupParts) - 1; i >= 0; i = i - 1 {
		p := cgroupParts[i]
		if len(p) < 28 {
			continue
		}
		id := strings.TrimSuffix(p, ".scope")
		switch {
		case strings.HasPrefix(id, "docker-"):
			cid = strings.TrimPrefix(id, "docker-")
		case strings.HasPrefix(id, "crio-"):
			cid = strings.TrimPrefix(id, "crio-")
		case strings.HasPrefix(id, "cri-containerd-"):
			cid = strings.TrimPrefix(id, "cri-containerd-")
		case strings.Contains(p, ":cri-containerd:"):
			cid = p[strings.LastIndex(p, ":cri-containerd:")+len(":cri-containerd:"):]
		case strings.HasPrefix(id, "libpod-"):
			cid = strings.TrimPrefix(id, "libpod-")
		}
	}
	return
}

func (t *tracerCgroup) scanPidsV1(procfs string, pids []os.DirEntry, containerIds map[string]types.UID) error {

	for _, pid := range pids {
		if !numberRegex.MatchString(pid.Name()) {
			continue
		}

		fpath := fmt.Sprintf("%s/%s/cgroup", procfs, pid.Name())

		bytes, err := os.ReadFile(fpath)
		if err != nil {
			log.Debug().Err(err).Str("pid", pid.Name()).Msg("Couldn't read cgroup file.")
			continue
		}

		n, err := strconv.ParseUint(pid.Name(), 10, 32)
		if err != nil {
			log.Warn().Err(err).Str("pid", pid.Name()).Msg("Couldn't parse pid number.")
			continue
		}
		pInfo := t.pidsInfo[uint32(n)]

		lines := strings.Split(string(bytes), "\n")

		var cgroupPath string
		if len(lines) == 1 {
			parts := strings.Split(lines[0], ":")
			cgroupPath = parts[len(parts)-1]
		} else {
			for _, line := range lines {
				if strings.Contains(line, ":pids:") {
					parts := strings.Split(line, ":")
					cgroupPath = parts[len(parts)-1]
				}
			}
		}

		if cgroupPath == "" {
			log.Error().Str("pid", pid.Name()).Msg(fmt.Sprintf("Cgroup path not found. Lines: %v", lines))
			continue
		}

		cgroupPath = normalizeCgroup(cgroupPath)

		podUID, ok := containerIds[cgroupPath]
		if !ok {
			continue
		}

		pInfo.podId = podUID

		t.pidsInfo[uint32(n)] = pInfo
	}

	return nil
}

func (t *tracerCgroup) getPodsInfo() map[types.UID]*podInfo {
	podsInfo := make(map[types.UID]*podInfo)
	for pid, info := range t.pidsInfo {
		if podsInfo[info.podId] == nil {
			podsInfo[info.podId] = &podInfo{}
		}
		pod := podsInfo[info.podId]
		pod.pids = append(pod.pids, pid)
		pod.cgroupIDs = append(pod.cgroupIDs, info.containerCgroupIds...)
		pod.cgroupV2Path = info.cgroupPath
	}
	return podsInfo
}

func normalyzeCgroupV2Path(path string) string {
	normalizedPath := strings.ReplaceAll(path, "../", "")
	if normalizedPath[0] == '/' {
		normalizedPath = normalizedPath[1:]
	}
	return normalizedPath
}

func getCgroupId(filepath string) (uint64, error) {
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		return 0, err
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat_t failed")
	}

	return stat.Ino, nil
}

func isCgroupV2() (bool, error) {
	const cgroupV2MagicNumber = unix.CGROUP2_SUPER_MAGIC
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/cgroup/", &stat); err != nil {
		return false, err
	}
	return stat.Type == cgroupV2MagicNumber, nil
}

// cgroup in the /proc/<pid>/cgroup may look something like
//
//	/system.slice/docker-<ID>.scope
//	/system.slice/containerd-<ID>.scope
//	/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3beae8e0_164d_4689_a087_efd902d8c2ab.slice/docker-<ID>.scope
//	/kubepods/besteffort/pod7709c1d5-447c-428f-bed9-8ddec35c93f4/<ID>
//
// This function extract the <ID> out of the cgroup path, the <ID> should match
//
//	the "Container ID:" field when running kubectl describe pod <POD>
func normalizeCgroup(cgrouppath string) string {
	basename := strings.TrimSpace(path.Base(cgrouppath))

	if strings.Contains(basename, "-") {
		basename = basename[strings.LastIndex(basename, "-")+1:]
	}

	if strings.Contains(basename, ".") {
		return strings.TrimSuffix(basename, filepath.Ext(basename))
	} else {
		return basename
	}
}
