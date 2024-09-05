package main

import (
	"os"

	"github.com/cilium/ebpf"
	"github.com/kubeshark/api"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/types"
)

type podInfo struct {
	pids         []uint32
	cgroupV2Path string
	cgroupIDs    []uint64
}

func (t *Tracer) updateTargets(addedWatchedPods []api.TargetPod, removedWatchedPods []api.TargetPod, addedTargetedPods []api.TargetPod, removedTargetedPods []api.TargetPod, settings uint32) error {
	if err := t.bpfObjects.tracerMaps.Settings.Update(uint32(0), settings, ebpf.UpdateAny); err != nil {
		log.Error().Err(err).Msg("Update capture settings failed:")
	}
	for _, pod := range removedTargetedPods {
		if t.packetFilter != nil {
			if err := t.packetFilter.DetachPod(string(pod.UID)); err == nil {
				log.Info().Str("pod", pod.Name).Msg("Detached pod from cgroup:")
			} else {
				log.Error().Err(err).Str("pod", pod.Name).Msg("Detach pod failed from cgroup:")
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

	containerIds := make(map[string]types.UID)
	for _, pod := range addedWatchedPods {
		for _, containerId := range pod.ContainerIDs {
			containerIds[containerId] = pod.UID
		}
	}
	for _, pod := range addedTargetedPods {
		for _, containerId := range pod.ContainerIDs {
			containerIds[containerId] = pod.UID
		}
	}

	if len(containerIds) == 0 {
		return nil
	}

	containerPids, err := findContainerPids(t.procfs, containerIds)
	if err != nil {
		return err
	}

	if t.packetFilter != nil {
		t.packetFilter.update(t.procfs, containerPids)
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
			if err := t.packetFilter.AttachPod(string(pod.UID), pInfo.cgroupV2Path, pInfo.cgroupIDs); err != nil {
				log.Error().Err(err).Str("pod", pod.Name).Msg("Attach pod to cgroup failed:")
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

func findContainerPids(procfs string, containerIds map[string]types.UID) (map[types.UID]*podInfo, error) {
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
