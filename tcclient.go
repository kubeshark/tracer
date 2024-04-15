package main

import (
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

type TcClient interface {
	SetupTC(ifindex, progFDIngress, progFDEgress int) error
	CleanTC() error
}

type TcClientImpl struct {
	TcPackage TcPackageInterface
	tcClient  TcInterface
	tcObjects []*tc.Object
}

type TcInterface interface {
	Qdisc() QdiscAPI
	Filter() FilterAPI
}

type QdiscAPI interface {
	Add(*tc.Object) error
	Delete(*tc.Object) error
	Close() error
}

type FilterAPI interface {
	Add(*tc.Object) error
}

type TcPackageInterface interface {
	Open(*tc.Config) (TcInterface, error)
}

type TcPackageImpl struct{}

func (r *TcPackageImpl) Open(config *tc.Config) (TcInterface, error) {
	tc, err := tc.Open(config)
	if err != nil {
		return nil, err
	}
	return &TcImpl{tc: tc}, nil
}

type TcImpl struct {
	tc *tc.Tc
}

func (r *TcImpl) Qdisc() QdiscAPI {
	return &QDiscImpl{qdisc: r.tc.Qdisc()}
}

func (r *TcImpl) Filter() FilterAPI {
	return r.tc.Filter()
}

type QDiscImpl struct {
	qdisc *tc.Qdisc
}

func (r *QDiscImpl) Add(obj *tc.Object) error {
	return r.qdisc.Add(obj)
}

func (r *QDiscImpl) Delete(obj *tc.Object) error {
	return r.qdisc.Delete(obj)
}

func (r *QDiscImpl) Close() error {
	return r.qdisc.Close()
}

type FilterImpl struct {
	filter *tc.Filter
}

func (r *FilterImpl) Add(obj *tc.Object) error {
	return r.filter.Add(obj)
}

const (
	qdiscMinor  = 0x0000
	filterFlags = 0x1
	filerInfo   = 0x300
)

func (t *TcClientImpl) SetupTC(ifindex, progFDIngress, progFDEgress int) error {
	var err error
	t.tcClient, err = t.TcPackage.Open(&tc.Config{})
	if err != nil {
		return err
	}

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifindex),
			Handle:  core.BuildHandle(tc.HandleRoot, qdiscMinor),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	_ = t.tcClient.Qdisc().Delete(&qdisc)
	if err := t.tcClient.Qdisc().Add(&qdisc); err != nil {
		return err
	}
	t.tcObjects = append(t.tcObjects, &qdisc)

	fdIngress := uint32(progFDIngress)
	fdEgress := uint32(progFDEgress)
	flags := uint32(filterFlags)

	filterIn := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifindex),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    filerInfo,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fdIngress,
				Flags: &flags,
			},
		},
	}
	if err := t.tcClient.Filter().Add(&filterIn); err != nil {
		return err
	}

	filterEg := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifindex),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
			Info:    filerInfo,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fdEgress,
				Flags: &flags,
			},
		},
	}
	if err := t.tcClient.Filter().Add(&filterEg); err != nil {
		return err
	}

	return nil
}

func (t *TcClientImpl) CleanTC() error {
	for _, tcObj := range t.tcObjects {
		_ = t.tcClient.Qdisc().Delete(tcObj)
	}
	if t.tcClient == nil {
		return nil
	}
	return t.tcClient.Qdisc().Close()
}
