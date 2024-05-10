package main

import (
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/go-errors/errors"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

type podInfo struct {
	pids         []uint32
	cgroupV2Path string
	cgroupIDs    []uint64
}

var numberRegex = regexp.MustCompile("[0-9]+")

func (t *Tracer) updateTargets(addedWatchedPods []v1.Pod, removedWatchedPods []v1.Pod, addedTargetedPods []v1.Pod, removedTargetedPods []v1.Pod) error {
	if t.packetFilter != nil {
		t.packetFilter.update()
	}
	for _, pod := range removedTargetedPods {
		if t.packetFilter != nil {
			if err := t.packetFilter.DetachPod(string(pod.UID)); err == nil {
				log.Info().Str("pod", pod.Name).Msg("Detached pod from cgroup:")
			}
		}
		wInfo, ok := t.watchingPods[pod.UID]
		if !ok {
			continue
		}
		for _, cID := range wInfo.cgroupIDs {
			delete(t.targetedCgroupIDs, cID)
		}

		for _, p := range wInfo.tlsPids {
			if err := p.Untarget(&t.bpfObjects); err != nil {
				return err
			}
			log.Info().Str("pod", pod.Name).Msg("Untarteted pids for pod:")
		}
	}

	for _, pod := range removedWatchedPods {
		wInfo, ok := t.watchingPods[pod.UID]
		if !ok {
			continue
		}
		for _, p := range wInfo.tlsPids {
			if err := p.RemoveProbes(&t.bpfObjects); err != nil {
				return err
			}
		}
		delete(t.watchingPods, pod.UID)
	}

	containerIds := buildContainerIdsMap(append(addedWatchedPods, addedTargetedPods...))

	if len(containerIds) == 0 {
		return nil
	}

	containerPids, err := findContainerPids(t.procfs, containerIds, t.isCgroupV2)
	if err != nil {
		return err
	}

	for _, pod := range addedWatchedPods {
		pInfo, ok := containerPids[pod.UID]
		if !ok {
			continue
		}

		if _, ok = t.watchingPods[pod.UID]; ok {
			log.Error().Str("pod", pod.Name).Msg("pod already watched:")
			continue
		}

		wInfo := &watchingPodsInfo{
			cgroupIDs: pInfo.cgroupIDs,
		}

		for _, containerPid := range pInfo.pids {
			pw, err := NewPodWatcher(t.procfs, &t.bpfObjects, containerPid)
			if err != nil {
				log.Error().Err(err).Str("pod", pod.Name).Uint32("pid", containerPid).Msg("create pod watcher failed:")
				continue
			}
			if pw == nil {
				// nothing to watch in the binary
				continue
			}

			wInfo.tlsPids = append(wInfo.tlsPids, pw)
		}
		t.watchingPods[pod.UID] = wInfo
	}

	for _, pod := range addedTargetedPods {
		pInfo, ok := containerPids[pod.UID]
		if !ok {
			continue
		}

		if t.packetFilter != nil {
			if err := t.packetFilter.AttachPod(string(pod.UID), pInfo.cgroupV2Path); err != nil {
				return err
			}
			log.Info().Str("pod", pod.Name).Msg("Attached pod to cgroup:")
		}

		wInfo, ok := t.watchingPods[pod.UID]
		if !ok {
			continue
		}
		for _, cID := range wInfo.cgroupIDs {
			t.targetedCgroupIDs[cID] = struct{}{}
		}

		for _, p := range wInfo.tlsPids {
			err := p.Target(&t.bpfObjects)
			if err != nil {
				log.Error().Err(err).Str("pod", pod.Name).Msg("target pod failed:")
				continue
			}
		}
		log.Info().Str("pod", pod.Name).Msg("Tarteted pids for pod:")
	}

	return nil
}

func findContainerPids(procfs string, containerIds map[string]v1.Pod, isCgroupV2 bool) (map[types.UID]*podInfo, error) {
	result := make(map[types.UID]*podInfo)

	pids, err := os.ReadDir(procfs)
	if err != nil {
		return result, err
	}

	log.Info().Str("procfs", procfs).Int("pids", len(pids)).Msg("discovering tls started:")

	for _, pid := range pids {
		if !pid.IsDir() {
			continue
		}

		if !numberRegex.MatchString(pid.Name()) {
			continue
		}

		cgroup, cgroupV2Path, cgroupIDs, err := getProcessCgroup(procfs, pid.Name(), containerIds, isCgroupV2)
		if err != nil {
			log.Debug().Err(err).Str("pid", pid.Name()).Msg("Couldn't get the cgroup of process.")
			continue
		}

		pod, ok := containerIds[cgroup]
		if !ok {
			continue
		}

		if isCgroupV2 && cgroupV2Path == "" {
			log.Error().Str("pid", pid.Name()).Msg("cgroup path not found:")
		}

		pidNumber, err := strconv.Atoi(pid.Name())
		if err != nil {
			log.Warn().Str("pid", pid.Name()).Msg("Unable to convert the process id to integer.")
			continue
		}

		if result[pod.UID] == nil {
			result[pod.UID] = &podInfo{}
		}

		pi := result[pod.UID]
		pi.pids = append(pi.pids, uint32(pidNumber))
		pi.cgroupV2Path = cgroupV2Path
		pi.cgroupIDs = cgroupIDs
	}

	log.Info().Str("procfs", procfs).Int("pids", len(pids)).Int("results", len(result)).Msg("discovering tls completed:")

	return result, nil
}

func buildContainerIdsMap(pods []v1.Pod) map[string]v1.Pod {
	result := make(map[string]v1.Pod)

	for _, pod := range pods {
		for _, container := range pod.Status.ContainerStatuses {
			parsedUrl, err := url.Parse(container.ContainerID)
			if err != nil {
				log.Warn().Msg(fmt.Sprintf("Expecting URL like container ID %v", container.ContainerID))
				continue
			}

			result[parsedUrl.Host] = pod
		}
	}

	return result
}

func getProcessCgroup(procfs string, pid string, containerIds map[string]v1.Pod, isCgroupV2 bool) (cgrouppath, cgroupV2Path string, cgroupIDs []uint64, err error) {
	fpath := fmt.Sprintf("%s/%s/cgroup", procfs, pid)

	var bytes []byte
	bytes, err = os.ReadFile(fpath)
	if err != nil {
		err = errors.Errorf("Error reading cgroup file %s - %v", fpath, err)
		return
	}

	lines := strings.Split(string(bytes), "\n")
	cgrouppath, cgroupV2Path, cgroupIDs = extractCgroup(lines, isCgroupV2)

	if strings.Contains(cgrouppath, "-") {
		parts := strings.Split(cgrouppath, "-")
		cgrouppath = parts[len(parts)-1]
	}

	if cgrouppath == "" {
		err = errors.Errorf("Cgroup path not found for %s, %s", pid, lines)
		return
	}

	cgrouppath = normalizeCgroup(cgrouppath)

	return
}

func extractCgroup(lines []string, isCgroupV2 bool) (cgroupPath string, cgroupV2Path string, cgroupIDs []uint64) {
	if isCgroupV2 {
		parts := lines
		parts = strings.Split(parts[0], "/")
		parts = strings.Split(parts[len(parts)-1], "-")
		parts = strings.Split(parts[len(parts)-1], ".")
		cgroupPath = parts[0]

		parts = lines
		parts = strings.Split(parts[0], "/")
		if len(parts) >= 2 {
			podCgroup := parts[len(parts)-1]

			walk := func(s string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() && d.Name() == podCgroup {
					cgroupV2Path = filepath.Dir(s)
					return nil
				}
				return nil
			}
			cgroupPaths := []string{
				"/sys/fs/cgroup/kubepods.slice",
				"/sys/fs/cgroup/system.slice",
				"/sys/fs/cgroup",
			}
			for _, cgroupPath := range cgroupPaths {
				_ = filepath.WalkDir(cgroupPath, walk)
				if cgroupV2Path != "" {
					break
				}
			}
		}
		if cgroupV2Path != "" {
			walkDir := func(path string, f os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if f.IsDir() {
					stat, ok := f.Sys().(*syscall.Stat_t)
					if !ok {
						return fmt.Errorf("unable to get inode for directory %s", path)
					}
					cgroupIDs = append(cgroupIDs, stat.Ino)
					return nil
				}
				return nil
			}
			err := filepath.Walk(cgroupV2Path, walkDir)
			if err != nil {
				log.Error().Err(err).Msg("walk cgroup fs failed:")
			}
		}
		return
	}

	if len(lines) == 1 {
		parts := strings.Split(lines[0], ":")
		cgroupPath = parts[len(parts)-1]
		return
	} else {
		for _, line := range lines {
			if strings.Contains(line, ":pids:") {
				parts := strings.Split(line, ":")
				cgroupPath = parts[len(parts)-1]
				return
			}
		}
	}

	return
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
		basename = basename[strings.Index(basename, "-")+1:]
	}

	if strings.Contains(basename, ".") {
		return strings.TrimSuffix(basename, filepath.Ext(basename))
	} else {
		return basename
	}
}
