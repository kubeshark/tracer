package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
)

type packetFilter struct {
	ingressFilterProgram *ebpf.Program
	egressFilterProgram  *ebpf.Program
	attachedPods         map[string][2]link.Link
	tcClient             TcClient
}

func newPacketFilter(ingressFilterProgram, egressFilterProgram, pullIngress, pullEgress *ebpf.Program, pktsRingBuffer *ebpf.Map) (*packetFilter, error) {
	var ifaces []int
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		ifaces = append(ifaces, link.Attrs().Index)
	}

	tcClient := &TcClientImpl{
		TcPackage: &TcPackageImpl{},
	}
	for _, l := range ifaces {
		if err := tcClient.SetupTC(l, pullIngress.FD(), pullEgress.FD()); err != nil {
			return nil, err
		}
	}

	pf := &packetFilter{
		ingressFilterProgram: ingressFilterProgram,
		egressFilterProgram:  egressFilterProgram,
		attachedPods:         make(map[string][2]link.Link),
		tcClient:             tcClient,
	}
	return pf, nil
}

func (p *packetFilter) close() {
	_ = p.tcClient.CleanTC()
	for uuid := range p.attachedPods {
		_ = p.DetachPod(uuid)
	}
}

func (t *packetFilter) AttachPod(uuid, cgroupV2Path string) error {
	lIngress, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupV2Path, Attach: ebpf.AttachCGroupInetIngress, Program: t.ingressFilterProgram})
	if err != nil {
		return err
	}

	lEgress, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupV2Path, Attach: ebpf.AttachCGroupInetEgress, Program: t.egressFilterProgram})
	if err != nil {
		lIngress.Close()
		return err
	}
	t.attachedPods[uuid] = [2]link.Link{lIngress, lEgress}
	log.Info().Str("pod", uuid).Msg("Attaching pod:") //XXX

	return nil
}

func (t *packetFilter) DetachPod(uuid string) error {
	log.Info().Str("pod", uuid).Msg("Detaching pod:") //XXX
	p, ok := t.attachedPods[uuid]
	if !ok {
		return fmt.Errorf("pod not attached")
	}
	p[0].Close()
	p[1].Close()
	delete(t.attachedPods, uuid)
	return nil
}
