package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-errors/errors"
	"github.com/kubeshark/tracer/internal/grpcservice"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/cgroup"
	"github.com/kubeshark/tracer/pkg/discoverer"
	packetHooks "github.com/kubeshark/tracer/pkg/hooks/packet"
	syscallHooks "github.com/kubeshark/tracer/pkg/hooks/syscall"
	"github.com/kubeshark/tracer/pkg/poller"
	"github.com/kubeshark/tracer/pkg/rawcapture"
	"github.com/moby/moby/pkg/parsers/kernel"
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

	cgroupsController cgroup.CgroupsController
	tcpMap            map[uint64]bool
	stats             tracerStats
}

func (t *Tracer) Init(
	chunksBufferSize int,
	logBufferSize int,
	procfs string,
	isCgroupsV2 bool,
	grpcService *grpcservice.GRPCService,
	systemStoreManager *rawcapture.Manager,
) error {
	var err error

	log.Info().Msg(fmt.Sprintf("Initializing tracer (chunksSize: %d) (logSize: %d)", chunksBufferSize, logBufferSize))

	err = setupRLimit()
	if err != nil {
		return fmt.Errorf("setup rlimit failed: %v", err)
	}

	if t.cgroupsController, err = cgroup.NewCgroupsController(procfs, grpcService); err != nil {
		return fmt.Errorf("cgroups controller create failed: %v", err)
	}

	var tlsEnabled, plainEnabled bool
	defer func() {
		if err := markPlain(plainEnabled); err != nil {
			log.Warn().Msg(fmt.Sprintf("mark plain failed: %v", err))
			return
		}
		if err := markTls(tlsEnabled); err != nil {
			log.Warn().Msg(fmt.Sprintf("mark tls failed: %v", err))
			return
		}
	}()

	var kernelVersion *kernel.VersionInfo
	kernelVersion, err = kernel.GetKernelVersion()
	if err != nil {
		return fmt.Errorf("kernel version detection failed: %v", err)
	}
	log.Info().Msg(fmt.Sprintf("Detected Linux kernel version: %s cgroups version2: %v", kernelVersion, isCgroupsV2))

	t.bpfObjects, tlsEnabled, plainEnabled, err = bpf.NewBpfObjects(procfs, *preferCgroupV1Capture, isCgroupsV2, kernelVersion)
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
		if errors.Is(err, ebpf.ErrKeyExist) {
			log.Warn().Uint64("pid fd", pidFd).Uint8("client", isCli).Msg("connection context key already exist")
		} else if err != nil {
			return fmt.Errorf("update connection context failed. pid fd: %v client: %v err: %v", pidFd, isCli, err)
		}
	}

	allPollers, err := poller.NewBpfPoller(procfs, t.bpfObjects, t.cgroupsController, systemStoreManager, *disableTlsLog)
	if err != nil {
		return fmt.Errorf("create eBPF poler failed failed: %v", err)
	}

	if t.packetFilter, err = packetHooks.NewPacketFilter(procfs, t.bpfObjects.BpfObjs, t.cgroupsController, plainEnabled, isCgroupsV2); err != nil {
		return fmt.Errorf("create packet filter failed: %v", err)
	}

	allPollers.Start()

	log.Info().Msg(fmt.Sprintf("eBPF plain backend: %v, eBPF TLS backend: %v", plainEnabled, tlsEnabled))

	return nil
}

func (t *Tracer) updateTargets(addPods, removePods, excludedPods []*v1.Pod, settings uint32) error {
	log.Info().Int("Add pods", len(addPods)).Int("Remove pods", len(removePods)).Int("Excluded pods", len(excludedPods)).Msg("Update targets")
	if err := t.bpfObjects.BpfObjs.Settings.Update(uint32(0), settings, ebpf.UpdateAny); err != nil {
		log.Error().Err(err).Msg("Update capture settings failed:")
	}

	// Get existing cgroup IDs before update
	existingIds := make(map[uint64]struct{})
	var key uint64
	var value uint32
	entries := t.bpfObjects.BpfObjs.ExcludedCgroupIds.Iterate()
	for entries.Next(&key, &value) {
		existingIds[key] = struct{}{}
	}
	if err := entries.Err(); err != nil {
		log.Error().Err(err).Msg("Error occurred while iterating ExcludedCgroupIds")
	}

	// Track newly added IDs during update
	newIds := make(map[uint64]struct{})
	for _, pod := range excludedPods {
		for _, containerId := range getContainerIDs(pod) {
			for _, value := range t.cgroupsController.GetCgroupsV2(containerId) {
				cgroupId := uint64(value.CgroupID)
				if err := t.bpfObjects.BpfObjs.ExcludedCgroupIds.Update(cgroupId, uint32(0), ebpf.UpdateAny); err != nil {
					log.Error().Err(err).Uint64("Cgroup ID", cgroupId).Msg("Cgroup IDs update failed")
				}
				newIds[cgroupId] = struct{}{}
			}
		}
	}

	// Remove IDs that weren't part of this update
	for id := range existingIds {
		if _, exists := newIds[id]; !exists {
			if err := t.bpfObjects.BpfObjs.ExcludedCgroupIds.Delete(id); err != nil {
				log.Error().Err(err).Uint64("Cgroup ID", id).Msg("Cgroup IDs delete failed")
			}
		}
	}

	for _, pod := range removePods {
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
			} else {
				t.stats.TargetedCgroups--
				t.stats.TargetedCgroupsDel++
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
				} else {
					t.stats.TargetedCgroups++
					t.stats.TargetedCgroupsAdd++
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

func (t *Tracer) collectStats() {
	if t.bpfObjects.BpfObjs.AllStatsMap == nil {
		// No such map in tracer
		return
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		t.collectStatItem()
	}
}

type tracerStats struct {
	TargetedCgroups    uint64
	TargetedCgroupsAdd uint64
	TargetedCgroupsDel uint64
}

type tracerAllStats struct {
	bpf.TracerAllStats
	TracerStats tracerStats

	Updated time.Time
}

func (t *Tracer) collectStatItem() {
	var cpuStats []bpf.TracerAllStats
	if err := t.bpfObjects.BpfObjs.AllStatsMap.Lookup(uint32(0), &cpuStats); err != nil {
		log.Error().Err(err).Msg("Failed to lookup stats")
		return
	}

	merged := tracerAllStats{
		Updated:     time.Now(),
		TracerStats: t.stats,
	}
	pStMerged := &merged.PktSnifferStats
	pSslMerged := &merged.OpensslStats
	pGoTlsMerged := &merged.GotlsStats
	for _, cpuStat := range cpuStats {
		pSt := &cpuStat.PktSnifferStats

		pStMerged.PacketsTotal += pSt.PacketsTotal
		pStMerged.PacketsProgramEnabled += pSt.PacketsProgramEnabled
		pStMerged.PacketsMatchedCgroup += pSt.PacketsMatchedCgroup
		pStMerged.PacketsIpv4 += pSt.PacketsIpv4
		pStMerged.PacketsIpv6 += pSt.PacketsIpv6
		pStMerged.PacketsParsePassed += pSt.PacketsParsePassed
		pStMerged.PacketsParseFailed += pSt.PacketsParseFailed
		pStMerged.SaveStats.SavePackets += pSt.SaveStats.SavePackets
		pStMerged.SaveStats.SaveFailedLogic += pSt.SaveStats.SaveFailedLogic
		pStMerged.SaveStats.SaveFailedNotOpened += pSt.SaveStats.SaveFailedNotOpened
		pStMerged.SaveStats.SaveFailedFull += pSt.SaveStats.SaveFailedFull
		pStMerged.SaveStats.SaveFailedOther += pSt.SaveStats.SaveFailedOther

		pSsl := &cpuStat.OpensslStats
		pSslMerged.UprobesTotal += pSsl.UprobesTotal
		pSslMerged.UprobesEnabled += pSsl.UprobesEnabled
		pSslMerged.UprobesMatched += pSsl.UprobesMatched
		pSslMerged.UprobesErrUpdate += pSsl.UprobesErrUpdate
		pSslMerged.UretprobesTotal += pSsl.UretprobesTotal
		pSslMerged.UretprobesEnabled += pSsl.UretprobesEnabled
		pSslMerged.UretprobesMatched += pSsl.UretprobesMatched
		pSslMerged.UretprobesErrContext += pSsl.UretprobesErrContext
		pSslMerged.SaveStats.SavePackets += pSsl.SaveStats.SavePackets
		pSslMerged.SaveStats.SaveFailedLogic += pSsl.SaveStats.SaveFailedLogic
		pSslMerged.SaveStats.SaveFailedNotOpened += pSsl.SaveStats.SaveFailedNotOpened
		pSslMerged.SaveStats.SaveFailedFull += pSsl.SaveStats.SaveFailedFull
		pSslMerged.SaveStats.SaveFailedOther += pSsl.SaveStats.SaveFailedOther

		pGoTls := &cpuStat.GotlsStats
		pGoTlsMerged.UprobesTotal += pGoTls.UprobesTotal
		pGoTlsMerged.UprobesEnabled += pGoTls.UprobesEnabled
		pGoTlsMerged.UprobesMatched += pGoTls.UprobesMatched
		pGoTlsMerged.UretprobesTotal += pGoTls.UretprobesTotal
		pGoTlsMerged.UretprobesEnabled += pGoTls.UretprobesEnabled
		pGoTlsMerged.UretprobesMatched += pGoTls.UretprobesMatched
		pGoTlsMerged.SaveStats.SavePackets += pGoTls.SaveStats.SavePackets
		pGoTlsMerged.SaveStats.SaveFailedLogic += pGoTls.SaveStats.SaveFailedLogic
		pGoTlsMerged.SaveStats.SaveFailedNotOpened += pGoTls.SaveStats.SaveFailedNotOpened
		pGoTlsMerged.SaveStats.SaveFailedFull += pGoTls.SaveStats.SaveFailedFull
		pGoTlsMerged.SaveStats.SaveFailedOther += pGoTls.SaveStats.SaveFailedOther
	}

	jsonData, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshall stats")
		return
	}

	if err := os.WriteFile(filepath.Join(misc.GetDataDir(), "stats_tracer.json"), jsonData, 0o644); err != nil {
		log.Error().Err(err).Msg("Failed to write stats")
		return
	}
}
