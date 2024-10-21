package packet

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type TcClient interface {
	SetupTC(link netlink.Link, progFDIngress, progFDEgress *ebpf.Program) error
	CleanTC() error
}

type TcClientImpl struct {
	filters []*netlink.BpfFilter
}

func addFilter(link netlink.Link, prog *ebpf.Program, parent uint32) (filter *netlink.BpfFilter, err error) {
	info, err := prog.Info()
	if err != nil {
		return nil, fmt.Errorf("get program info failed: %v", err)
	}

	infoName := info.Name
	if len(infoName) > 15 {
		infoName = infoName[:15]
	}
	ksFilterName := "ks." + infoName
	prio := uint16(0)
	prios := make(map[uint16]struct{})
	// Find filter to replace
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return nil, fmt.Errorf("get filters failed: %v", err)
	}
	for _, f := range filters {
		bf, ok := f.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		if bf.Name == ksFilterName {
			prio = f.Attrs().Priority
			break
		} else {
			prios[f.Attrs().Priority] = struct{}{}
		}
	}
	if prio == 0 {
		for i := 65535; i > 0; i-- {
			if _, ok := prios[uint16(i)]; !ok {
				prio = uint16(i)
				break
			}
		}
	}

	if prio == 0 {
		return nil, fmt.Errorf("find filter slot failed: %v", err)
	}

	filter = &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  prio,
		},
		Fd:           prog.FD(),
		Name:         ksFilterName,
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("replacing tc filter ingress for interface %v: %w", link.Attrs().Name, err)
	}

	return
}

func (t *TcClientImpl) SetupTC(link netlink.Link, progFDIngress, progFDEgress *ebpf.Program) error {

	filter, err := addFilter(link, progFDIngress, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return err
	}
	t.filters = append(t.filters, filter)

	filter, err = addFilter(link, progFDEgress, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return err
	}
	t.filters = append(t.filters, filter)

	return nil
}

func (t *TcClientImpl) CleanTC() error {
	for _, f := range t.filters {
		if err := netlink.FilterDel(f); err != nil {
			return fmt.Errorf("remove filter failed: %v", err)
		}
	}
	return nil
}
