package main

import (
	"fmt"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"net/url"
	"os"
)

type podInfo struct {
	pids         []uint32
	cgroupV2Path string
	cgroupIDs    []uint64
}

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

	containerPids, err := findContainerPids(t.procfs, containerIds)
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
		log.Info().Str("pod", pod.Name).Msg("Targeted pids for pod:")
	}

	return nil
}

func findContainerPids(procfs string, containerIds map[string]v1.Pod) (map[types.UID]*podInfo, error) {
	result := make(map[types.UID]*podInfo)

	pids, err := os.ReadDir(procfs)
	if err != nil {
		return result, err
	}

	log.Info().Str("procfs", procfs).Int("pids", len(pids)).Msg("discovering tls started:")

	tracerCgroup, err := NewTracerCgroup(procfs, containerIds)
	if err != nil {
		return result, err
	}
	result = tracerCgroup.getPodsInfo()

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
