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

type tracer46AcceptData struct{ Sock uint64 }

type tracer46AcceptInfo struct{ Addrlen uint64 }

type tracer46AddressInfo struct {
	Family uint32
	Saddr  uint32
	Daddr  uint32
	Sport  uint16
	Dport  uint16
}

type tracer46Configuration struct{ Flags uint32 }

type tracer46ConnectInfo struct {
	Fd      uint64
	Addrlen uint32
	_       [4]byte
}

type tracer46GoidOffsets struct {
	G_addrOffset uint64
	GoidOffset   uint64
}

type tracer46PidInfo struct {
	SysFdOffset int64
	IsInterface uint64
}

type tracer46PidOffset struct {
	Pid          uint64
	SymbolOffset uint64
}

type tracer46Pkt struct {
	Timestamp uint64
	CgroupId  uint64
	Id        uint64
	Num       uint16
	Len       uint16
	Last      uint16
	Direction uint8
	Buf       [4096]uint8
	_         [1]byte
}

type tracer46PktData struct {
	CgroupId       uint64
	Pad1           uint32
	RewriteSrcPort uint16
	Pad2           uint16
}

type tracer46SslInfo struct {
	Buffer        uint64
	BufferLen     uint32
	Fd            uint32
	CreatedAtNano uint64
	AddressInfo   tracer46AddressInfo
	CountPtr      uint64
}

type tracer46TlsChunk struct {
	Timestamp   uint64
	CgroupId    uint32
	Pid         uint32
	Tgid        uint32
	Len         uint32
	Start       uint32
	Recorded    uint32
	Fd          uint32
	Flags       uint32
	AddressInfo tracer46AddressInfo
	Direction   uint8
	Data        [4096]uint8
	_           [7]byte
}

// loadTracer46 returns the embedded CollectionSpec for tracer46.
func loadTracer46() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Tracer46Bytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tracer46: %w", err)
	}

	return spec, err
}

// loadTracer46Objects loads tracer46 and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tracer46Objects
//	*tracer46Programs
//	*tracer46Maps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTracer46Objects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTracer46()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tracer46Specs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracer46Specs struct {
	tracer46ProgramSpecs
	tracer46MapSpecs
}

// tracer46Specs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracer46ProgramSpecs struct {
	Accept                        *ebpf.ProgramSpec `ebpf:"accept"`
	Accept4                       *ebpf.ProgramSpec `ebpf:"accept4"`
	FilterEgressPackets           *ebpf.ProgramSpec `ebpf:"filter_egress_packets"`
	FilterIngressPackets          *ebpf.ProgramSpec `ebpf:"filter_ingress_packets"`
	GoCryptoTlsAbi0Read           *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi0_read"`
	GoCryptoTlsAbi0ReadEx         *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi0_read_ex"`
	GoCryptoTlsAbi0Write          *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi0_write"`
	GoCryptoTlsAbi0WriteEx        *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi0_write_ex"`
	GoCryptoTlsAbiInternalRead    *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi_internal_read"`
	GoCryptoTlsAbiInternalReadEx  *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi_internal_read_ex"`
	GoCryptoTlsAbiInternalWrite   *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi_internal_write"`
	GoCryptoTlsAbiInternalWriteEx *ebpf.ProgramSpec `ebpf:"go_crypto_tls_abi_internal_write_ex"`
	PacketPullEgress              *ebpf.ProgramSpec `ebpf:"packet_pull_egress"`
	PacketPullIngress             *ebpf.ProgramSpec `ebpf:"packet_pull_ingress"`
	SecuritySocketAccept          *ebpf.ProgramSpec `ebpf:"security_socket_accept"`
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
	SyscallAccept4                *ebpf.ProgramSpec `ebpf:"syscall__accept4"`
	TcpConnect                    *ebpf.ProgramSpec `ebpf:"tcp_connect"`
	TcpRecvmsg                    *ebpf.ProgramSpec `ebpf:"tcp_recvmsg"`
	TcpSendmsg                    *ebpf.ProgramSpec `ebpf:"tcp_sendmsg"`
	TraceCgroupConnect4           *ebpf.ProgramSpec `ebpf:"trace_cgroup_connect4"`
}

// tracer46MapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracer46MapSpecs struct {
	AcceptContext            *ebpf.MapSpec `ebpf:"accept_context"`
	AcceptSyscallContext     *ebpf.MapSpec `ebpf:"accept_syscall_context"`
	CgroupIds                *ebpf.MapSpec `ebpf:"cgroup_ids"`
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
	Settings                 *ebpf.MapSpec `ebpf:"settings"`
	SyscallEvents            *ebpf.MapSpec `ebpf:"syscall_events"`
	TargetPidsMap            *ebpf.MapSpec `ebpf:"target_pids_map"`
	WatchPidsMap             *ebpf.MapSpec `ebpf:"watch_pids_map"`
}

// tracer46Objects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTracer46Objects or ebpf.CollectionSpec.LoadAndAssign.
type tracer46Objects struct {
	tracer46Programs
	tracer46Maps
}

func (o *tracer46Objects) Close() error {
	return _Tracer46Close(
		&o.tracer46Programs,
		&o.tracer46Maps,
	)
}

// tracer46Maps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTracer46Objects or ebpf.CollectionSpec.LoadAndAssign.
type tracer46Maps struct {
	AcceptContext            *ebpf.Map `ebpf:"accept_context"`
	AcceptSyscallContext     *ebpf.Map `ebpf:"accept_syscall_context"`
	CgroupIds                *ebpf.Map `ebpf:"cgroup_ids"`
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
	Settings                 *ebpf.Map `ebpf:"settings"`
	SyscallEvents            *ebpf.Map `ebpf:"syscall_events"`
	TargetPidsMap            *ebpf.Map `ebpf:"target_pids_map"`
	WatchPidsMap             *ebpf.Map `ebpf:"watch_pids_map"`
}

func (m *tracer46Maps) Close() error {
	return _Tracer46Close(
		m.AcceptContext,
		m.AcceptSyscallContext,
		m.CgroupIds,
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
		m.Settings,
		m.SyscallEvents,
		m.TargetPidsMap,
		m.WatchPidsMap,
	)
}

// tracer46Programs contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTracer46Objects or ebpf.CollectionSpec.LoadAndAssign.
type tracer46Programs struct {
	Accept                        *ebpf.Program `ebpf:"accept"`
	Accept4                       *ebpf.Program `ebpf:"accept4"`
	FilterEgressPackets           *ebpf.Program `ebpf:"filter_egress_packets"`
	FilterIngressPackets          *ebpf.Program `ebpf:"filter_ingress_packets"`
	GoCryptoTlsAbi0Read           *ebpf.Program `ebpf:"go_crypto_tls_abi0_read"`
	GoCryptoTlsAbi0ReadEx         *ebpf.Program `ebpf:"go_crypto_tls_abi0_read_ex"`
	GoCryptoTlsAbi0Write          *ebpf.Program `ebpf:"go_crypto_tls_abi0_write"`
	GoCryptoTlsAbi0WriteEx        *ebpf.Program `ebpf:"go_crypto_tls_abi0_write_ex"`
	GoCryptoTlsAbiInternalRead    *ebpf.Program `ebpf:"go_crypto_tls_abi_internal_read"`
	GoCryptoTlsAbiInternalReadEx  *ebpf.Program `ebpf:"go_crypto_tls_abi_internal_read_ex"`
	GoCryptoTlsAbiInternalWrite   *ebpf.Program `ebpf:"go_crypto_tls_abi_internal_write"`
	GoCryptoTlsAbiInternalWriteEx *ebpf.Program `ebpf:"go_crypto_tls_abi_internal_write_ex"`
	PacketPullEgress              *ebpf.Program `ebpf:"packet_pull_egress"`
	PacketPullIngress             *ebpf.Program `ebpf:"packet_pull_ingress"`
	SecuritySocketAccept          *ebpf.Program `ebpf:"security_socket_accept"`
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
	SyscallAccept4                *ebpf.Program `ebpf:"syscall__accept4"`
	TcpConnect                    *ebpf.Program `ebpf:"tcp_connect"`
	TcpRecvmsg                    *ebpf.Program `ebpf:"tcp_recvmsg"`
	TcpSendmsg                    *ebpf.Program `ebpf:"tcp_sendmsg"`
	TraceCgroupConnect4           *ebpf.Program `ebpf:"trace_cgroup_connect4"`
}

func (p *tracer46Programs) Close() error {
	return _Tracer46Close(
		p.Accept,
		p.Accept4,
		p.FilterEgressPackets,
		p.FilterIngressPackets,
		p.GoCryptoTlsAbi0Read,
		p.GoCryptoTlsAbi0ReadEx,
		p.GoCryptoTlsAbi0Write,
		p.GoCryptoTlsAbi0WriteEx,
		p.GoCryptoTlsAbiInternalRead,
		p.GoCryptoTlsAbiInternalReadEx,
		p.GoCryptoTlsAbiInternalWrite,
		p.GoCryptoTlsAbiInternalWriteEx,
		p.PacketPullEgress,
		p.PacketPullIngress,
		p.SecuritySocketAccept,
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
		p.SyscallAccept4,
		p.TcpConnect,
		p.TcpRecvmsg,
		p.TcpSendmsg,
		p.TraceCgroupConnect4,
	)
}

func _Tracer46Close(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tracer46_bpfel_x86.o
var _Tracer46Bytes []byte
