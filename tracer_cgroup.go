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

	"github.com/kubeshark/tracer/pkg/discoverer"
	"github.com/kubeshark/tracer/pkg/kubernetes"
	"github.com/kubeshark/tracer/pkg/utils"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/types"
)

var numberRegex = regexp.MustCompile("[0-9]+")

type pidInformation struct {
	podId              types.UID
	cgroupPath         string
	containerCgroupIds []uint64
}

type tracerCgroup struct {
	pidsInfo map[uint32]pidInformation
}

func NewTracerCgroup(procfs string, containerIds map[string]types.UID) (*tracerCgroup, error) {

	tc := &tracerCgroup{
		pidsInfo: make(map[uint32]pidInformation),
	}

	isCgroupV2, err := utils.IsCgroupV2()
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
				containerCgroupId, err := discoverer.GetCgroupIdByPath(s)
				if err != nil {
					log.Warn().Err(err).Str("path", s).Msg("Couldn't get container cgroup ID.")
					continue
				}
				//TODO: removesyscallPoller.CgroupsInfo.Add(containerCgroupId, discoverer.GetContainerIdFromCgroupPath(cgroupPath))

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

func (t *tracerCgroup) getPodsInfo() map[types.UID]*kubernetes.PodInfo {
	podsInfo := make(map[types.UID]*kubernetes.PodInfo)
	for pid, info := range t.pidsInfo {
		if podsInfo[info.podId] == nil {
			podsInfo[info.podId] = &kubernetes.PodInfo{}
		}
		pod := podsInfo[info.podId]
		pod.Pids = append(pod.Pids, pid)
		pod.CgroupIDs = append(pod.CgroupIDs, info.containerCgroupIds...)
		pod.CgroupV2Path = info.cgroupPath
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
