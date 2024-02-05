package main

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/go-errors/errors"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
)

var numberRegex = regexp.MustCompile("[0-9]+")

func updateTargets(pods []v1.Pod) error {
	containerIds := buildContainerIdsMap(pods)
	log.Debug().Interface("container-ids", containerIds).Send()

	const cgroupV2MagicNumber = 0x63677270
	isCgroupV2 := false
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/cgroup/", &stat); err != nil {
		log.Error().Err(err).Msg("read cgroups information failed:")
	} else if stat.Type == cgroupV2MagicNumber {
		isCgroupV2 = true
	}

	containerPids, err := findContainerPids(tracer.procfs, containerIds, isCgroupV2)

	if err != nil {
		return err
	}

	log.Info().Interface("pids", reflect.ValueOf(containerPids).MapKeys()).Send()

	tracer.clearPids()

	// TODO: CAUSES INITIAL MEMORY SPIKE
	for pid := range containerPids {
		if err := tracer.addSSLLibPid(tracer.procfs, pid); err != nil {
			logError(err)
		}

		if err := tracer.addGoPid(tracer.procfs, pid); err != nil {
			logError(err)
		}
	}

	return nil
}

func findContainerPids(procfs string, containerIds map[string]v1.Pod, isCgroupV2 bool) (map[uint32]v1.Pod, error) {
	result := make(map[uint32]v1.Pod)

	pids, err := os.ReadDir(procfs)
	if err != nil {
		return result, err
	}

	log.Info().Str("procfs", procfs).Int("pids", len(pids)).Msg("Starting TLS auto discoverer:")

	for _, pid := range pids {
		if !pid.IsDir() {
			continue
		}

		if !numberRegex.MatchString(pid.Name()) {
			continue
		}

		cgroup, err := getProcessCgroup(procfs, pid.Name(), isCgroupV2)
		if err != nil {
			log.Warn().Err(err).Str("pid", pid.Name()).Msg("Couldn't get the cgroup of process.")
			continue
		}

		pod, ok := containerIds[cgroup]
		if !ok {
			log.Warn().Str("pid", pid.Name()).Str("cgroup", cgroup).Msg("Couldn't find the pod for the given cgroup of pid.")
			continue
		}

		pidNumber, err := strconv.Atoi(pid.Name())
		if err != nil {
			log.Warn().Str("pid", pid.Name()).Msg("Unable to convert the process id to integer.")
			continue
		}

		result[uint32(pidNumber)] = pod
	}

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
