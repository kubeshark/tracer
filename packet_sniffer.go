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
	ingressPullProgram   *ebpf.Program
	egressPullProgram    *ebpf.Program
	attachedPods         map[string][2]link.Link
	tcClient             TcClient
}

func newPacketFilter(ingressFilterProgram, egressFilterProgram, pullIngress, pullEgress *ebpf.Program, pktsRingBuffer *ebpf.Map) (*packetFilter, error) {
	tcClient := &TcClientImpl{
		TcPackage: &TcPackageImpl{},
	}

	pf := &packetFilter{
		ingressFilterProgram: ingressFilterProgram,
		egressFilterProgram:  egressFilterProgram,
		ingressPullProgram:   pullIngress,
		egressPullProgram:    pullEgress,
		attachedPods:         make(map[string][2]link.Link),
		tcClient:             tcClient,
	}
	pf.update()
	return pf, nil
}

func (p *packetFilter) update() {
	var ifaces []int
	links, err := netlink.LinkList()
	if err != nil {
		log.Error().Err(err).Msg("Get link list failed:")
		return
	}
	for _, link := range links {
		ifaces = append(ifaces, link.Attrs().Index)
	}

	for _, l := range ifaces {
		if err := p.tcClient.SetupTC(l, p.ingressPullProgram.FD(), p.egressPullProgram.FD()); err != nil {
			log.Error().Int("link", l).Err(err).Msg("Setup TC failed:")
			continue
		}
		log.Info().Int("link", l).Msg("Attached TC programs:")
	}
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
	log.Info().Str("pod", uuid).Msg("Attaching pod:")

	return nil
}

func (t *packetFilter) DetachPod(uuid string) error {
	log.Info().Str("pod", uuid).Msg("Detaching pod:")
	p, ok := t.attachedPods[uuid]
	if !ok {
		return fmt.Errorf("pod not attached")
	}
	p[0].Close()
	p[1].Close()
	delete(t.attachedPods, uuid)
	return nil
}
