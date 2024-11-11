package packet

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/cgroup"

	"github.com/rs/zerolog/log"
)

type podLinks struct {
	links map[string][]link.Link
}

type PacketFilter struct {
	enabled      bool
	isCgroupV2   bool
	attachedPods map[string]*podLinks
	tcClient     TcClient
	bpfObjs      bpf.TracerObjects
}

func NewPacketFilter(procfs string, bpfObjs bpf.TracerObjects, cgroupsController cgroup.CgroupsController, enabled, isCgroupV2 bool) (*PacketFilter, error) {
	if !cgroupsController.EbpfCapturePossible() {
		enabled = false
	}

	pf := &PacketFilter{
		enabled:      enabled,
		isCgroupV2:   isCgroupV2,
		attachedPods: make(map[string]*podLinks),
		tcClient:     &TcClientImpl{},
		bpfObjs:      bpfObjs,
	}

	if enabled && !isCgroupV2 {
		if _, err := pf.attachPod("0", cgroupsController.GetCgroupV2MountPoint()); err != nil {
			return nil, err
		}
		log.Info().Msg("Using eBPF packet capture for Cgroup V1")
	} else {
		log.Info().Msg("Using eBPF packet capture for Cgroup V2")
	}

	return pf, nil
}

func (pf *PacketFilter) Close() error {
	for uuid, p := range pf.attachedPods {
		for _, l := range p.links {
			closeLinks(l)
		}
		delete(pf.attachedPods, uuid)
	}

	return pf.tcClient.CleanTC()
}

func (t *PacketFilter) AttachPod(uuid, cgroupV2Path string) (bool, error) {
	if !t.enabled || !t.isCgroupV2 {
		return false, nil
	}
	return t.attachPod(uuid, cgroupV2Path)
}

func (t *PacketFilter) attachPod(uuid, cgroupV2Path string) (bool, error) {
	log.Info().Str("pod", uuid).Str("path", cgroupV2Path).Msg("Attaching pod:")
	var links []link.Link

	addLink := func(attachType ebpf.AttachType, prog *ebpf.Program) error {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupV2Path, Attach: attachType, Program: prog})
		if err != nil {
			closeLinks(links)
			return fmt.Errorf("attach cgroup %v: %v", attachType, err)
		}
		links = append(links, l)
		return nil
	}

	if err := addLink(ebpf.AttachCGroupInetSockCreate, t.bpfObjs.FilterSockCreate); err != nil {
		return false, err
	}

	if err := addLink(ebpf.AttachCgroupInetSockRelease, t.bpfObjs.FilterSockRelease); err != nil {
		return false, err
	}

	if err := addLink(ebpf.AttachCGroupInetIngress, t.bpfObjs.FilterIngressPackets); err != nil {
		return false, err
	}

	if err := addLink(ebpf.AttachCGroupInetEgress, t.bpfObjs.FilterEgressPackets); err != nil {
		return false, err
	}

	if err := addLink(ebpf.AttachCGroupInet4Bind, t.bpfObjs.FilterSockBind); err != nil {
		return false, err
	}

	if t.attachedPods[uuid] == nil {
		t.attachedPods[uuid] = &podLinks{}
	}
	if t.attachedPods[uuid].links == nil {
		t.attachedPods[uuid].links = map[string][]link.Link{}
	}
	t.attachedPods[uuid].links[cgroupV2Path] = links

	return true, nil
}

func (t *PacketFilter) DetachPod(uuid string) bool {
	log.Info().Str("pod", uuid).Msg("Detaching pod:")
	p, ok := t.attachedPods[uuid]
	if !ok {
		// pod can be on a different node
		return false
	}

	for _, l := range p.links {
		closeLinks(l)
	}
	delete(t.attachedPods, uuid)
	return true
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		l.Close()
	}
}
