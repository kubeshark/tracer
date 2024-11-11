package cgroup

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"
)

type RuntimeId int

const (
	runtimeUnknown RuntimeId = iota
	runtimeDocker
	runtimeContainerd
	runtimeCrio
	runtimePodman
	runtimeGarden
)

var (
	containerIdFromCgroupRegex       = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
	gardenContainerIdFromCgroupRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){4}$`)
)

// Borrowed from https://github.com/aquasecurity/tracee/blob/main/pkg/containers/containers.go
func getContainerIdByCgroupPath(cgroupPath string) (id string, runtime RuntimeId) {
	cgroupParts := strings.Split(cgroupPath, "/")

	for i := len(cgroupParts) - 1; i >= 0; i = i - 1 {
		pc := cgroupParts[i]
		if len(pc) < 28 {
			continue
		}

		runtime = runtimeUnknown
		id = strings.TrimSuffix(pc, ".scope")

		switch {
		case strings.HasPrefix(id, "docker-"):
			runtime = runtimeDocker
			id = strings.TrimPrefix(id, "docker-")
		case strings.HasPrefix(id, "crio-"):
			runtime = runtimeCrio
			id = strings.TrimPrefix(id, "crio-")
		case strings.HasPrefix(id, "cri-containerd-"):
			runtime = runtimeContainerd
			id = strings.TrimPrefix(id, "cri-containerd-")
		case strings.Contains(pc, ":cri-containerd:"):
			runtime = runtimeContainerd
			id = pc[strings.LastIndex(pc, ":cri-containerd:")+len(":cri-containerd:"):]
		case strings.HasPrefix(id, "libpod-"):
			runtime = runtimePodman
			id = strings.TrimPrefix(id, "libpod-")
		}

		if runtime != runtimeUnknown {
			return
		}

		if matched := containerIdFromCgroupRegex.MatchString(id); matched && i > 0 {
			prevPart := cgroupParts[i-1]
			if prevPart == "docker" {
				runtime = runtimeDocker
			}
			if prevPart == "actions_job" {
				runtime = runtimeDocker
			}
			if strings.HasPrefix(prevPart, "pod") {
				runtime = runtimeContainerd
			}

			return
		}

		if matched := gardenContainerIdFromCgroupRegex.MatchString(id); matched {
			runtime = runtimeGarden
			return
		}
	}

	id = ""
	return
}

func getCgroupIdByPath(filepath string) (uint64, error) {
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
