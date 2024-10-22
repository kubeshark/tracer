package main

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-errors/errors"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/discoverer"
	packetHooks "github.com/kubeshark/tracer/pkg/hooks/packet"
	syscallHooks "github.com/kubeshark/tracer/pkg/hooks/syscall"
	"github.com/kubeshark/tracer/pkg/poller"
	"github.com/kubeshark/tracer/pkg/utils"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const GlobalWorkerPid = 0

type containerInfo struct {
	cgroupPath string
	cgroupID   uint64
}

type podInfo struct {
	containers []containerInfo
}

type Tracer struct {
	bpfObjects        *bpf.BpfObjects
	syscallHooks      syscallHooks.SyscalHooks
	eventsDiscoverer  discoverer.InternalEventsDiscoverer
	packetFilter      *packetHooks.PacketFilter
	procfs            string
	targetedCgroupIDs map[uint64]struct{}

	runningPods map[types.UID]podInfo
}

func (t *Tracer) Init(
	chunksBufferSize int,
	logBufferSize int,
	procfs string,
) error {
	log.Info().Msg(fmt.Sprintf("Initializing tracer (chunksSize: %d) (logSize: %d)", chunksBufferSize, logBufferSize))

	var err error
	err = setupRLimit()
	if err != nil {
		return err
	}

	t.bpfObjects, err = bpf.NewBpfObjects(*disableEbpfCapture)
	if err != nil {
		return fmt.Errorf("creating bpf failed: %v", err)
	}
	t.eventsDiscoverer = discoverer.NewInternalEventsDiscoverer(procfs, t.bpfObjects)
	if err := t.eventsDiscoverer.Start(); err != nil {
		log.Error().Msg(fmt.Sprintf("start internal discovery failed: %v", err))
		return err
	}

	t.syscallHooks = syscallHooks.NewSyscallHooks(t.bpfObjects)
	if err = t.syscallHooks.Install(); err != nil {
		return err
	}

	sortedPackets := make(chan *bpf.SortedPacket, misc.PacketChannelBufferSize)

	isCgroupsV2, err := utils.IsCgroupV2()
	if err != nil {
		return err
	}
	allPollers, err := poller.NewBpfPoller(t.bpfObjects, bpf.NewPacketSorter(sortedPackets, isCgroupsV2), t.eventsDiscoverer.CgroupsInfo(), *disableTlsLog)
	if err != nil {
		return err
	}
	allPollers.Start()

	if !*disableEbpfCapture {
		//TODO: for cgroup V2 only
		t.packetFilter, err = packetHooks.NewPacketFilter(procfs, t.bpfObjects.BpfObjs.FilterIngressPackets, t.bpfObjects.BpfObjs.FilterEgressPackets, t.bpfObjects.BpfObjs.TraceCgroupConnect4, t.bpfObjects.BpfObjs.CgroupIds)
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *Tracer) updateTargets(addPods, removePods []*v1.Pod, settings uint32) error {
	log.Info().Int("Add pods", len(addPods)).Int("Remove pods", len(removePods)).Msg("Update targets")
	if err := t.bpfObjects.BpfObjs.Settings.Update(uint32(0), settings, ebpf.UpdateAny); err != nil {
		log.Error().Err(err).Msg("Update capture settings failed:")
	}

	for _, pod := range removePods {
		if t.packetFilter != nil {
			if err := t.packetFilter.DetachPod(string(pod.UID)); err == nil {
				log.Info().Str("pod", pod.Name).Msg("Detached pod from cgroup:")
			} else {
				log.Error().Err(err).Str("pod", pod.Name).Msg("Detach pod failed from cgroup:")
			}
		}

		pInfo, ok := t.runningPods[pod.UID]
		if !ok {
			continue
		}
		for _, cInfo := range pInfo.containers {
			delete(t.targetedCgroupIDs, cInfo.cgroupID)
			t.eventsDiscoverer.UntargetCgroup(cInfo.cgroupID)
			if t.packetFilter == nil {
				if err := t.bpfObjects.BpfObjs.CgroupIds.Delete(cInfo.cgroupID); err != nil {
					log.Error().Err(err).Uint64("Cgroup ID", cInfo.cgroupID).Msg("Cgroup IDs delete failed")
					return err
				}
			}
		}
		log.Info().Str("pod", pod.Name).Msg("Detached pod:")
		delete(t.runningPods, pod.UID)
	}

	for _, pod := range addPods {
		pd := t.runningPods[pod.UID]
		for _, containerId := range getContainerIDs(pod) {
			values, ok := t.eventsDiscoverer.ContainersInfo().Get(discoverer.ContainerID(containerId))
			if !ok {
				// pod can be on a different node
				continue
			}
			for _, value := range values {
				cInfo := containerInfo{
					cgroupPath: value.CgroupPath,
					cgroupID:   uint64(value.CgroupID),
				}
				pd.containers = append(pd.containers, cInfo)

				if t.packetFilter != nil {
					if err := t.packetFilter.AttachPod(string(pod.UID), cInfo.cgroupPath, []uint64{cInfo.cgroupID}); err != nil {
						log.Error().Err(err).Uint64("Cgroup ID", cInfo.cgroupID).Str("Cgroup path", cInfo.cgroupPath).Str("pod", pod.Name).Msg("Attach pod to cgroup failed:")
						return err
					}
					log.Info().Str("pod", pod.Name).Msg("Attached pod to cgroup:")
				} else {
					if err := t.bpfObjects.BpfObjs.CgroupIds.Update(cInfo.cgroupID, uint32(0), ebpf.UpdateNoExist); err != nil {
						log.Error().Err(err).Uint64("Cgroup ID", cInfo.cgroupID).Msg("Cgroup IDs update failed")
						return err
					}
				}
				t.eventsDiscoverer.TargetCgroup(cInfo.cgroupID)
				log.Info().Str("Container ID", containerId).Uint64("Cgroup ID", cInfo.cgroupID).Msg("Cgroup has been targeted")
			}
		}
		t.runningPods[pod.UID] = pd
	}

	return nil
}

func (t *Tracer) Deinit() error {
	if t.packetFilter != nil {
		return t.packetFilter.Close()
	}

	return nil
}

func setupRLimit() error {
	err := rlimit.RemoveMemlock()

	if err != nil {
		return errors.New(fmt.Sprintf("%s: %v", "SYS_RESOURCE is required to change rlimits for eBPF", err))
	}

	return nil
}

func getContainerIDs(pod *v1.Pod) []string {
	extractContainerId := func(cId string) string {
		s := strings.Split(cId, "/")
		return s[len(s)-1]
	}

	var containerIDs []string
	{
		for _, containerStatus := range pod.Status.InitContainerStatuses {
			containerIDs = append(containerIDs, extractContainerId(containerStatus.ContainerID))
		}
		for _, containerStatus := range pod.Status.ContainerStatuses {
			containerIDs = append(containerIDs, extractContainerId(containerStatus.ContainerID))
		}
	}

	return containerIDs
}
