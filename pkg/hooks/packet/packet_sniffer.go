package packet

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/rs/zerolog/log"
)

type podLinks struct {
	links     map[string][3]link.Link
	cgroupIDs []uint64
}

type PacketFilter struct {
	ingressFilterProgram *ebpf.Program
	egressFilterProgram  *ebpf.Program
	traceCgroupConnect   *ebpf.Program
	cgroupHashMap        *ebpf.Map
	attachedPods         map[string]*podLinks
	tcClient             TcClient
}

func NewPacketFilter(procfs string, ingressFilterProgram, egressFilterProgram, traceCgroupConnect *ebpf.Program, cgroupHash *ebpf.Map) (*PacketFilter, error) {
	pf := &PacketFilter{
		ingressFilterProgram: ingressFilterProgram,
		egressFilterProgram:  egressFilterProgram,
		traceCgroupConnect:   traceCgroupConnect,
		cgroupHashMap:        cgroupHash,
		attachedPods:         make(map[string]*podLinks),
		tcClient:             &TcClientImpl{},
	}
	return pf, nil
}

func (p *PacketFilter) Close() error {
	return p.tcClient.CleanTC()
}

func (t *PacketFilter) AttachPod(uuid, cgroupV2Path string, cgoupIDs []uint64) error {
	log.Info().Str("pod", uuid).Str("path", cgroupV2Path).Msg("Attaching pod:")

	lIngress, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupV2Path, Attach: ebpf.AttachCGroupInetIngress, Program: t.ingressFilterProgram})
	if err != nil {
		return fmt.Errorf("attach cgroup ingress: %v", err)
	}

	lEgress, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupV2Path, Attach: ebpf.AttachCGroupInetEgress, Program: t.egressFilterProgram})
	if err != nil {
		lIngress.Close()
		return fmt.Errorf("attach cgroup egress: %v", err)
	}

	traceConnect, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupV2Path, Attach: ebpf.AttachCGroupInet4Connect, Program: t.traceCgroupConnect})
	if err != nil {
		lIngress.Close()
		lEgress.Close()
		return fmt.Errorf("attach cgroup connect: %v", err)
	}

	if t.attachedPods[uuid] == nil {
		t.attachedPods[uuid] = &podLinks{
			links: make(map[string][3]link.Link),
		}
	}
	t.attachedPods[uuid].links[cgroupV2Path] = [3]link.Link{lIngress, lEgress, traceConnect}

	for _, cgroupID := range cgoupIDs {
		err := t.cgroupHashMap.Update(cgroupID, uint32(0), ebpf.UpdateNoExist)
		if err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
			return fmt.Errorf("adding cgroup %v failed: %v", cgroupID, err)
		} else if err == nil {
			t.attachedPods[uuid].cgroupIDs = append(t.attachedPods[uuid].cgroupIDs, cgroupID)
		}
	}

	return nil
}

func (t *PacketFilter) DetachPod(uuid string) error {
	log.Info().Str("pod", uuid).Msg("Detaching pod:")
	p, ok := t.GetAttachedPod(uuid)
	if !ok {
		return fmt.Errorf("pod not attached")
	}

	for _, cgroupID := range p.cgroupIDs {
		if err := t.cgroupHashMap.Delete(cgroupID); err != nil {
			return fmt.Errorf("deleting cgroup %v failed: %v", cgroupID, err)
		}
	}

	for _, l := range p.links {
		l[0].Close()
		l[1].Close()
		l[2].Close()
	}
	delete(t.attachedPods, uuid)
	return nil
}

func (t *PacketFilter) GetAttachedPod(uuid string) (p *podLinks, ok bool) {
	p, ok = t.attachedPods[uuid]
	return
}
