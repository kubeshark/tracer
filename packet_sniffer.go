package main

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"k8s.io/apimachinery/pkg/types"
)

type podLinks struct {
	links     map[string][3]link.Link
	cgroupIDs []uint64
}

type packetFilter struct {
	ingressFilterProgram *ebpf.Program
	egressFilterProgram  *ebpf.Program
	ingressPullProgram   *ebpf.Program
	egressPullProgram    *ebpf.Program
	traceCgroupConnect   *ebpf.Program
	cgroupHashMap        *ebpf.Map
	attachedPods         map[string]*podLinks
	tcClient             TcClient
}

func newPacketFilter(ingressFilterProgram, egressFilterProgram, pullIngress, pullEgress, traceCgroupConnect *ebpf.Program, cgroupHash *ebpf.Map) (*packetFilter, error) {
	tcClient := &TcClientImpl{
		TcPackage: &TcPackageImpl{},
	}

	pf := &packetFilter{
		ingressFilterProgram: ingressFilterProgram,
		egressFilterProgram:  egressFilterProgram,
		ingressPullProgram:   pullIngress,
		egressPullProgram:    pullEgress,
		traceCgroupConnect:   traceCgroupConnect,
		cgroupHashMap:        cgroupHash,
		attachedPods:         make(map[string]*podLinks),
		tcClient:             tcClient,
	}
	pf.update("", nil)
	return pf, nil
}

func (p *packetFilter) update(procfs string, pods map[types.UID]*podInfo) {
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

	if pods == nil {
		return
	}

	nsHandles := make(map[netns.NsHandle]struct{})
	for _, podInfo := range pods {
		for _, pid := range podInfo.pids {
			fname := fmt.Sprintf("%v/%v/ns/net", procfs, pid)
			if nsh, err := netns.GetFromPath(fname); err != nil {
				log.Warn().Uint32("pid", pid).Str("file", fname).Err(err).Msg("Get netns failed:")
			} else {
				nsHandles[nsh] = struct{}{}
			}
		}
	}
	for h := range nsHandles {
		done := make(chan bool)
		errors := make(chan error)

		go func(nsh netns.NsHandle, done chan<- bool) {
			// Setting a netns should be done from a dedicated OS thread.
			//
			// goroutines are not really OS threads, we try to mimic the issue by
			//	locking the OS thread to this goroutine
			//
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			oldnetns, err := netns.Get()

			if err != nil {
				errors <- fmt.Errorf("Unable to get netns of current thread %v", err)
				return
			}

			if err := netns.Set(nsh); err != nil {
				errors <- fmt.Errorf("Unable to set netns of handle %v - %v", h, err)
				return
			}

			lo := -1
			links, err := netlink.LinkList()
			if err != nil {
				errors <- fmt.Errorf("Get link list in netns %v failed: %v", h, err)
				return
			}
			for _, link := range links {
				if link.Attrs().Name == "lo" {
					lo = link.Attrs().Index
					break
				}
			}
			if lo == -1 {
				errors <- fmt.Errorf("Can not get lo id for netns %v", h)
				return
			}

			if err := p.tcClient.SetupTC(lo, p.ingressPullProgram.FD(), p.egressPullProgram.FD()); err != nil {
				log.Error().Int("link", lo).Err(err).Msg("Setup TC failed:")
				errors <- fmt.Errorf("Unable to setup tc netns: %v iface: %v error: %v", h, lo, err)
				return
			}
			log.Info().Int("netns", int(h)).Int("link", lo).Msg("Attached netns TC programs:")

			if err := netns.Set(oldnetns); err != nil {
				errors <- fmt.Errorf("Unable to set back netns of current thread %v", err)
				return
			}

			done <- true
		}(h, done)

		select {
		case err := <-errors:
			log.Error().Err(err).Msg("Setup netns program failed:")
		case <-done:
		}
	}
}

func (p *packetFilter) close() {
	_ = p.tcClient.CleanTC()
	for uuid := range p.attachedPods {
		_ = p.DetachPod(uuid)
	}
}

func (t *packetFilter) AttachPod(uuid, cgroupV2Path string, cgoupIDs []uint64) error {
	log.Info().Str("pod", uuid).Str("path", cgroupV2Path).Msg("Attaching pod:")

	lIngress, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupV2Path, Attach: ebpf.AttachCGroupInetIngress, Program: t.ingressFilterProgram})
	if err != nil {
		return err
	}

	lEgress, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupV2Path, Attach: ebpf.AttachCGroupInetEgress, Program: t.egressFilterProgram})
	if err != nil {
		lIngress.Close()
		return err
	}

	traceConnect, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupV2Path, Attach: ebpf.AttachCGroupInet4Connect, Program: t.traceCgroupConnect})
	if err != nil {
		lIngress.Close()
		lEgress.Close()
		return err
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

func (t *packetFilter) DetachPod(uuid string) error {
	log.Info().Str("pod", uuid).Msg("Detaching pod:")
	p, ok := t.attachedPods[uuid]
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
