package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-errors/errors"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/cgroup"
	"github.com/kubeshark/tracer/pkg/discoverer"
	packetHooks "github.com/kubeshark/tracer/pkg/hooks/packet"
	syscallHooks "github.com/kubeshark/tracer/pkg/hooks/syscall"
	"github.com/kubeshark/tracer/pkg/poller"
	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"path/filepath"
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

	cgroupsController cgroup.CgroupsController
	tcpMap            map[uint64]bool
}

func (t *Tracer) Init(
	chunksBufferSize int,
	logBufferSize int,
	procfs string,
	isCgroupsV2 bool,
) error {
	var err error

	log.Info().Msg(fmt.Sprintf("Initializing tracer (chunksSize: %d) (logSize: %d)", chunksBufferSize, logBufferSize))

	err = setupRLimit()
	if err != nil {
		return fmt.Errorf("setup rlimit failed: %v", err)
	}

	if t.cgroupsController, err = cgroup.NewCgroupsController(procfs); err != nil {
		return fmt.Errorf("cgroups controller create failed: %v", err)
	}

	var tlsEnabled, plainEnabled bool

	var kernelVersion *kernel.VersionInfo
	kernelVersion, err = kernel.GetKernelVersion()
	if err != nil {
		return fmt.Errorf("kernel version detection failed: %v", err)
	}
	log.Info().Msg(fmt.Sprintf("Detected Linux kernel version: %s cgroups version2: %v", kernelVersion, isCgroupsV2))

	t.bpfObjects, tlsEnabled, plainEnabled, err = bpf.NewBpfObjects(*preferCgroupV1Capture, isCgroupsV2, kernelVersion)
	if err != nil {
		return fmt.Errorf("creating bpf failed: %w", err)
	}

	if t.eventsDiscoverer, err = discoverer.NewInternalEventsDiscoverer(procfs, t.bpfObjects, t.cgroupsController); err != nil {
		return fmt.Errorf("create internal discovery failed: %v", err)
	}
	if err := t.eventsDiscoverer.Start(); err != nil {
		return fmt.Errorf("start internal discovery failed: %v", err)
	}

	t.syscallHooks = syscallHooks.NewSyscallHooks(t.bpfObjects)
	if err = t.syscallHooks.Install(); err != nil {
		return fmt.Errorf("install sycall hooks failed: %v", err)
	}
	for pidFd, isClient := range t.tcpMap {
		var isCli uint8
		if isClient {
			isCli = 1
		}
		err := t.bpfObjects.BpfObjs.ConnectionContext.Update(pidFd, isCli, ebpf.UpdateNoExist)
		if err == ebpf.ErrKeyExist {
			log.Warn().Uint64("pid fd", pidFd).Uint8("client", isCli).Msg("connection context key already exist")
		} else if err != nil {
			return fmt.Errorf("update connection context failed. pid fd: %v client: %v err: %v", pidFd, isCli, err)
		}
	}

	allPollers, err := poller.NewBpfPoller(t.bpfObjects, t.cgroupsController, *disableTlsLog)
	if err != nil {
		return fmt.Errorf("create eBPF poler failed failed: %v", err)
	}

	if t.packetFilter, err = packetHooks.NewPacketFilter(procfs, t.bpfObjects.BpfObjs, t.cgroupsController, plainEnabled, isCgroupsV2); err != nil {
		return fmt.Errorf("create packet filter failed: %v", err)
	}

	if err := markPlain(plainEnabled); err != nil {
		return fmt.Errorf("mark plain failed: %v", err)
	}
	if err := markTls(tlsEnabled); err != nil {
		return fmt.Errorf("mark tls failed: %v", err)
	}

	allPollers.Start()

	log.Info().Msg(fmt.Sprintf("eBPF plain backend: %v, eBPF TLS backend: %v", plainEnabled, tlsEnabled))

	return nil
}

func (t *Tracer) updateTargets(addPods, removePods []*v1.Pod, settings uint32) error {
	log.Info().Int("Add pods", len(addPods)).Int("Remove pods", len(removePods)).Msg("Update targets")
	if err := t.bpfObjects.BpfObjs.Settings.Update(uint32(0), settings, ebpf.UpdateAny); err != nil {
		log.Error().Err(err).Msg("Update capture settings failed:")
	}

	for _, pod := range removePods {
		if t.packetFilter.DetachPod(string(pod.UID)) {
			log.Info().Str("pod", pod.Name).Msg("Detached pod from cgroup:")
		}

		pInfo, ok := t.runningPods[pod.UID]
		if !ok {
			continue
		}
		for _, cInfo := range pInfo.containers {
			delete(t.targetedCgroupIDs, cInfo.cgroupID)
			t.eventsDiscoverer.UntargetCgroup(cInfo.cgroupID)

			if err := t.bpfObjects.BpfObjs.CgroupIds.Delete(cInfo.cgroupID); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
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
			for _, value := range t.cgroupsController.GetCgroupsV2(containerId) {
				cInfo := containerInfo{
					cgroupPath: value.CgroupPath,
					cgroupID:   uint64(value.CgroupID),
				}
				pd.containers = append(pd.containers, cInfo)

				if err := t.bpfObjects.BpfObjs.CgroupIds.Update(cInfo.cgroupID, uint32(0), ebpf.UpdateAny); err != nil {
					log.Error().Err(err).Str("Cgroup Path", cInfo.cgroupPath).Str("Container ID", containerId).Uint64("Cgroup ID", cInfo.cgroupID).Msg("Cgroup IDs update failed")
					return err
				}

				if ok, err := t.packetFilter.AttachPod(string(pod.UID), cInfo.cgroupPath); err != nil {
					log.Warn().Err(err).Uint64("Cgroup ID", cInfo.cgroupID).Str("Cgroup path", cInfo.cgroupPath).Str("pod", pod.Name).Msg("Attach pod to cgroup failed:")
					_ = t.bpfObjects.BpfObjs.CgroupIds.Delete(cInfo.cgroupID)
					continue
				} else if ok {
					log.Info().Str("pod", pod.Name).Msg("Attached pod to cgroup:")
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
	var err error
	if err = t.packetFilter.Close(); err != nil {
		return err
	}

	if t.cgroupsController != nil {
		if err = t.cgroupsController.Close(); err != nil {
			return err
		}
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

func markPlain(enabled bool) error {
	if enabled {
		return createFeatureFile(bpf.PlainBackendSupportedFile)
	}
	return createFeatureFile(bpf.PlainBackendNotSupportedFile)
}

func markTls(enabled bool) error {
	if enabled {
		return createFeatureFile(bpf.TlsBackendSupportedFile)
	}
	return createFeatureFile(bpf.TlsBackendNotSupportedFile)
}

func createFeatureFile(fileName string) error {
	filePath := filepath.Join(misc.GetDataDir(), fileName)
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	file.Close()
	return nil
}
