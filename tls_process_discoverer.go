package main

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-errors/errors"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

var numberRegex = regexp.MustCompile("[0-9]+")

func (t *Tracer) updateTargets(addedWatchedPods []v1.Pod, removedWatchedPods []v1.Pod, addedTargetedPods []v1.Pod, removedTargetedPods []v1.Pod) error {
	for _, pod := range removedTargetedPods {
		p, ok := t.watchingPods[pod.UID]
		if !ok {
			log.Error().Str("pod", pod.Name).Msg("untarget pod is not watched:")
			continue
		}
		p.Untarget(&t.bpfObjects)
	}

	for _, pod := range removedWatchedPods {
		p, ok := t.watchingPods[pod.UID]
		if !ok {
			continue
		}
		p.RemoveProbes(&t.bpfObjects)
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
		containerPid, ok := containerPids[pod.UID]
		if !ok {
			continue
		}

		if _, ok := t.watchingPods[pod.UID]; ok {
			log.Error().Str("pod", pod.Name).Msg("pod already watched:")
			continue
		}

		pw, err := NewPodWatcher(t.procfs, &t.bpfObjects, containerPid)
		if err != nil {
			log.Error().Err(err).Str("pod", pod.Name).Uint32("pid", containerPid).Msg("create pod watcher failed:")
			continue
		}
		if pw == nil {
			// nothing to watch in the binary
			continue
		}
		t.watchingPods[pod.UID] = pw
	}

	for _, pod := range addedTargetedPods {
		p, ok := t.watchingPods[pod.UID]
		if !ok {
			continue
		}

		err := p.Target(&t.bpfObjects)
		if err != nil {
			log.Error().Err(err).Str("pod", pod.Name).Msg("target pod failed:")
			continue
		}
	}

	return nil
}

func findContainerPids(procfs string, containerIds map[string]v1.Pod, isCgroupV2 bool) (map[types.UID]uint32, error) {
	result := make(map[types.UID]uint32)

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

		cgroup, err := getProcessCgroup(procfs, pid.Name(), isCgroupV2)
		if err != nil {
			log.Debug().Err(err).Str("pid", pid.Name()).Msg("Couldn't get the cgroup of process.")
			continue
		}

		pod, ok := containerIds[cgroup]
		if !ok {
			continue
		}

		pidNumber, err := strconv.Atoi(pid.Name())
		if err != nil {
			log.Warn().Str("pid", pid.Name()).Msg("Unable to convert the process id to integer.")
			continue
		}

		result[pod.UID] = uint32(pidNumber)
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

func getProcessCgroup(procfs string, pid string, isCgroupV2 bool) (string, error) {
	fpath := fmt.Sprintf("%s/%s/cgroup", procfs, pid)

	bytes, err := os.ReadFile(fpath)
	if err != nil {
		return "", errors.Errorf("Error reading cgroup file %s - %v", fpath, err)
	}

	lines := strings.Split(string(bytes), "\n")
	cgrouppath := extractCgroup(lines, isCgroupV2)

	if strings.Contains(cgrouppath, "-") {
		parts := strings.Split(cgrouppath, "-")
		cgrouppath = parts[len(parts)-1]
	}

	if cgrouppath == "" {
		return "", errors.Errorf("Cgroup path not found for %s, %s", pid, lines)
	}

	return normalizeCgroup(cgrouppath), nil
}

func extractCgroup(lines []string, isCgroupV2 bool) string {
	if isCgroupV2 {
		parts := lines
		parts = strings.Split(parts[0], "/")
		parts = strings.Split(parts[len(parts)-1], "-")
		parts = strings.Split(parts[len(parts)-1], ".")
		return parts[0]
	}

	if len(lines) == 1 {
		parts := strings.Split(lines[0], ":")
		return parts[len(parts)-1]
	} else {
		for _, line := range lines {
			if strings.Contains(line, ":pids:") {
				parts := strings.Split(line, ":")
				return parts[len(parts)-1]
			}
		}
	}

	return ""
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
