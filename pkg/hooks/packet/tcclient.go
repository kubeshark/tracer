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
	filterPriority uint16
	filters        []*netlink.BpfFilter
}

func NewTcClient() TcClient {
	return nil //TODO
}

func addFilter(link netlink.Link, prog *ebpf.Program) (filter *netlink.BpfFilter, err error) {
	info, err := prog.Info()
	if err != nil {
		return nil, fmt.Errorf("get program info failed: %v", err)
	}

	filter = &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  65535,
		},
		Fd:           prog.FD(),
		Name:         "ks." + info.Name + "-" + link.Attrs().Name,
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("replacing tc filter ingress for interface %v: %w", link.Attrs().Name, err)
	}

	return
}

func (t *TcClientImpl) SetupTC(link netlink.Link, progFDIngress, progFDEgress *ebpf.Program) error {

	filter, err := addFilter(link, progFDIngress)
	if err != nil {
		return err
	}
	t.filters = append(t.filters, filter)

	filter, err = addFilter(link, progFDEgress)
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
