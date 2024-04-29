// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type tracerNoSniffGoidOffsets struct {
	G_addrOffset uint64
	GoidOffset   uint64
}

type tracerNoSniffPkt struct {
	CgroupId uint64
	Id       uint64
	Num      uint16
	Len      uint16
	Last     uint16
	Buf      [4096]uint8
	_        [2]byte
}

type tracerNoSniffTlsChunk struct {
	CgroupId    uint32
	Pid         uint32
	Tgid        uint32
	Len         uint32
	Start       uint32
	Recorded    uint32
	Fd          uint32
	Flags       uint32
	AddressInfo struct {
		Family uint32
		Saddr  uint32
		Daddr  uint32
		Sport  uint16
		Dport  uint16
	}
	Data [4096]uint8
}

// loadTracerNoSniff returns the embedded CollectionSpec for tracerNoSniff.
func loadTracerNoSniff() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TracerNoSniffBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tracerNoSniff: %w", err)
	}

	return spec, err
}

// loadTracerNoSniffObjects loads tracerNoSniff and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tracerNoSniffObjects
//	*tracerNoSniffPrograms
//	*tracerNoSniffMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTracerNoSniffObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTracerNoSniff()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tracerNoSniffSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerNoSniffSpecs struct {
	tracerNoSniffProgramSpecs
	tracerNoSniffMapSpecs
}

// tracerNoSniffSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerNoSniffProgramSpecs struct {
	GoCryptoTlsAbi0Read           *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi0_read"`
	GoCryptoTlsAbi0ReadEx         *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi0_read_ex"`
	GoCryptoTlsAbi0Write          *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi0_write"`
	GoCryptoTlsAbi0WriteEx        *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi0_write_ex"`
	GoCryptoTlsAbiInternalRead    *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi_internal_read"`
	GoCryptoTlsAbiInternalReadEx  *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi_internal_read_ex"`
	GoCryptoTlsAbiInternalWrite   *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi_internal_write"`
	GoCryptoTlsAbiInternalWriteEx *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi_internal_write_ex"`
	SslRead                       *ebpf.ProgramSpec `ebpf:"ssl_read"`
	SslReadEx                     *ebpf.ProgramSpec `ebpf:"ssl_read_ex"`
	SslRetRead                    *ebpf.ProgramSpec `ebpf:"ssl_ret_read"`
	SslRetReadEx                  *ebpf.ProgramSpec `ebpf:"ssl_ret_read_ex"`
	SslRetWrite                   *ebpf.ProgramSpec `ebpf:"ssl_ret_write"`
	SslRetWriteEx                 *ebpf.ProgramSpec `ebpf:"ssl_ret_write_ex"`
	SslWrite                      *ebpf.ProgramSpec `ebpf:"ssl_write"`
	SslWriteEx                    *ebpf.ProgramSpec `ebpf:"ssl_write_ex"`
	SysEnterAccept4               *ebpf.ProgramSpec `ebpf:"sys_enter_accept4"`
	SysEnterConnect               *ebpf.ProgramSpec `ebpf:"sys_enter_connect"`
	SysEnterRead                  *ebpf.ProgramSpec `ebpf:"sys_enter_read"`
	SysEnterWrite                 *ebpf.ProgramSpec `ebpf:"sys_enter_write"`
	SysExitAccept4                *ebpf.ProgramSpec `ebpf:"sys_exit_accept4"`
	SysExitConnect                *ebpf.ProgramSpec `ebpf:"sys_exit_connect"`
	SysExitRead                   *ebpf.ProgramSpec `ebpf:"sys_exit_read"`
	SysExitWrite                  *ebpf.ProgramSpec `ebpf:"sys_exit_write"`
	TcpRecvmsg                    *ebpf.ProgramSpec `ebpf:"tcp_recvmsg"`
	TcpSendmsg                    *ebpf.ProgramSpec `ebpf:"tcp_sendmsg"`
}

// tracerNoSniffMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerNoSniffMapSpecs struct {
	AcceptSyscallContext     *ebpf.MapSpec `ebpf:"accept_syscall_context"`
	ChunksBuffer             *ebpf.MapSpec `ebpf:"chunks_buffer"`
	ConnectSyscallInfo       *ebpf.MapSpec `ebpf:"connect_syscall_info"`
	ConnectionContext        *ebpf.MapSpec `ebpf:"connection_context"`
	GoKernelReadContext      *ebpf.MapSpec `ebpf:"go_kernel_read_context"`
	GoKernelWriteContext     *ebpf.MapSpec `ebpf:"go_kernel_write_context"`
	GoReadContext            *ebpf.MapSpec `ebpf:"go_read_context"`
	GoUserKernelReadContext  *ebpf.MapSpec `ebpf:"go_user_kernel_read_context"`
	GoUserKernelWriteContext *ebpf.MapSpec `ebpf:"go_user_kernel_write_context"`
	GoWriteContext           *ebpf.MapSpec `ebpf:"go_write_context"`
	GoidOffsetsMap           *ebpf.MapSpec `ebpf:"goid_offsets_map"`
	Heap                     *ebpf.MapSpec `ebpf:"heap"`
	LogBuffer                *ebpf.MapSpec `ebpf:"log_buffer"`
	OpensslReadContext       *ebpf.MapSpec `ebpf:"openssl_read_context"`
	OpensslWriteContext      *ebpf.MapSpec `ebpf:"openssl_write_context"`
	PidsInfo                 *ebpf.MapSpec `ebpf:"pids_info"`
	PktContext               *ebpf.MapSpec `ebpf:"pkt_context"`
	PktHeap                  *ebpf.MapSpec `ebpf:"pkt_heap"`
	PktId                    *ebpf.MapSpec `ebpf:"pkt_id"`
	PktsBuffer               *ebpf.MapSpec `ebpf:"pkts_buffer"`
	TargetPidsMap            *ebpf.MapSpec `ebpf:"target_pids_map"`
	WatchPidsMap             *ebpf.MapSpec `ebpf:"watch_pids_map"`
}

// tracerNoSniffObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTracerNoSniffObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerNoSniffObjects struct {
	tracerNoSniffPrograms
	tracerNoSniffMaps
}

func (o *tracerNoSniffObjects) Close() error {
	return _TracerNoSniffClose(
		&o.tracerNoSniffPrograms,
		&o.tracerNoSniffMaps,
	)
}

// tracerNoSniffMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTracerNoSniffObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerNoSniffMaps struct {
	AcceptSyscallContext     *ebpf.Map `ebpf:"accept_syscall_context"`
	ChunksBuffer             *ebpf.Map `ebpf:"chunks_buffer"`
	ConnectSyscallInfo       *ebpf.Map `ebpf:"connect_syscall_info"`
	ConnectionContext        *ebpf.Map `ebpf:"connection_context"`
	GoKernelReadContext      *ebpf.Map `ebpf:"go_kernel_read_context"`
	GoKernelWriteContext     *ebpf.Map `ebpf:"go_kernel_write_context"`
	GoReadContext            *ebpf.Map `ebpf:"go_read_context"`
	GoUserKernelReadContext  *ebpf.Map `ebpf:"go_user_kernel_read_context"`
	GoUserKernelWriteContext *ebpf.Map `ebpf:"go_user_kernel_write_context"`
	GoWriteContext           *ebpf.Map `ebpf:"go_write_context"`
	GoidOffsetsMap           *ebpf.Map `ebpf:"goid_offsets_map"`
	Heap                     *ebpf.Map `ebpf:"heap"`
	LogBuffer                *ebpf.Map `ebpf:"log_buffer"`
	OpensslReadContext       *ebpf.Map `ebpf:"openssl_read_context"`
	OpensslWriteContext      *ebpf.Map `ebpf:"openssl_write_context"`
	PidsInfo                 *ebpf.Map `ebpf:"pids_info"`
	PktContext               *ebpf.Map `ebpf:"pkt_context"`
	PktHeap                  *ebpf.Map `ebpf:"pkt_heap"`
	PktId                    *ebpf.Map `ebpf:"pkt_id"`
	PktsBuffer               *ebpf.Map `ebpf:"pkts_buffer"`
	TargetPidsMap            *ebpf.Map `ebpf:"target_pids_map"`
	WatchPidsMap             *ebpf.Map `ebpf:"watch_pids_map"`
}

func (m *tracerNoSniffMaps) Close() error {
	return _TracerNoSniffClose(
		m.AcceptSyscallContext,
		m.ChunksBuffer,
		m.ConnectSyscallInfo,
		m.ConnectionContext,
		m.GoKernelReadContext,
		m.GoKernelWriteContext,
		m.GoReadContext,
		m.GoUserKernelReadContext,
		m.GoUserKernelWriteContext,
		m.GoWriteContext,
		m.GoidOffsetsMap,
		m.Heap,
		m.LogBuffer,
		m.OpensslReadContext,
		m.OpensslWriteContext,
		m.PidsInfo,
		m.PktContext,
		m.PktHeap,
		m.PktId,
		m.PktsBuffer,
		m.TargetPidsMap,
		m.WatchPidsMap,
	)
}

// tracerNoSniffPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTracerNoSniffObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerNoSniffPrograms struct {
	GoCryptoTlsAbi0Read           *ebpf.Program `ebpf:"go_crypto_tls_abi0_read"`
	GoCryptoTlsAbi0ReadEx         *ebpf.Program `ebpf:"go_crypto_tls_abi0_read_ex"`
	GoCryptoTlsAbi0Write          *ebpf.Program `ebpf:"go_crypto_tls_abi0_write"`
	GoCryptoTlsAbi0WriteEx        *ebpf.Program `ebpf:"go_crypto_tls_abi0_write_ex"`
	GoCryptoTlsAbiInternalRead    *ebpf.Program `ebpf:"go_crypto_tls_abi_internal_read"`
	GoCryptoTlsAbiInternalReadEx  *ebpf.Program `ebpf:"go_crypto_tls_abi_internal_read_ex"`
	GoCryptoTlsAbiInternalWrite   *ebpf.Program `ebpf:"go_crypto_tls_abi_internal_write"`
	GoCryptoTlsAbiInternalWriteEx *ebpf.Program `ebpf:"go_crypto_tls_abi_internal_write_ex"`
	SslRead                       *ebpf.Program `ebpf:"ssl_read"`
	SslReadEx                     *ebpf.Program `ebpf:"ssl_read_ex"`
	SslRetRead                    *ebpf.Program `ebpf:"ssl_ret_read"`
	SslRetReadEx                  *ebpf.Program `ebpf:"ssl_ret_read_ex"`
	SslRetWrite                   *ebpf.Program `ebpf:"ssl_ret_write"`
	SslRetWriteEx                 *ebpf.Program `ebpf:"ssl_ret_write_ex"`
	SslWrite                      *ebpf.Program `ebpf:"ssl_write"`
	SslWriteEx                    *ebpf.Program `ebpf:"ssl_write_ex"`
	SysEnterAccept4               *ebpf.Program `ebpf:"sys_enter_accept4"`
	SysEnterConnect               *ebpf.Program `ebpf:"sys_enter_connect"`
	SysEnterRead                  *ebpf.Program `ebpf:"sys_enter_read"`
	SysEnterWrite                 *ebpf.Program `ebpf:"sys_enter_write"`
	SysExitAccept4                *ebpf.Program `ebpf:"sys_exit_accept4"`
	SysExitConnect                *ebpf.Program `ebpf:"sys_exit_connect"`
	SysExitRead                   *ebpf.Program `ebpf:"sys_exit_read"`
	SysExitWrite                  *ebpf.Program `ebpf:"sys_exit_write"`
	TcpRecvmsg                    *ebpf.Program `ebpf:"tcp_recvmsg"`
	TcpSendmsg                    *ebpf.Program `ebpf:"tcp_sendmsg"`
}

func (p *tracerNoSniffPrograms) Close() error {
	return _TracerNoSniffClose(
		p.GoCryptoTlsAbi0Read,
		p.GoCryptoTlsAbi0ReadEx,
		p.GoCryptoTlsAbi0Write,
		p.GoCryptoTlsAbi0WriteEx,
		p.GoCryptoTlsAbiInternalRead,
		p.GoCryptoTlsAbiInternalReadEx,
		p.GoCryptoTlsAbiInternalWrite,
		p.GoCryptoTlsAbiInternalWriteEx,
		p.SslRead,
		p.SslReadEx,
		p.SslRetRead,
		p.SslRetReadEx,
		p.SslRetWrite,
		p.SslRetWriteEx,
		p.SslWrite,
		p.SslWriteEx,
		p.SysEnterAccept4,
		p.SysEnterConnect,
		p.SysEnterRead,
		p.SysEnterWrite,
		p.SysExitAccept4,
		p.SysExitConnect,
		p.SysExitRead,
		p.SysExitWrite,
		p.TcpRecvmsg,
		p.TcpSendmsg,
	)
}

func _TracerNoSniffClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tracernosniff_bpfel_x86.o
var _TracerNoSniffBytes []byte
