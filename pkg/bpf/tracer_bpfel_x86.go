// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type TracerAcceptData struct{ Sock uint64 }

type TracerAcceptInfo struct{ Addrlen uint64 }

type TracerAddressInfo struct {
	Family uint32
	Saddr4 uint32
	Daddr4 uint32
	Saddr6 [16]uint8
	Daddr6 [16]uint8
	Sport  uint16
	Dport  uint16
}

type TracerAllStats struct {
	PktSnifferStats struct {
		PacketsTotal          uint64
		PacketsProgramEnabled uint64
		PacketsMatchedCgroup  uint64
		PacketsIpv4           uint64
		PacketsIpv6           uint64
		PacketsParsePassed    uint64
		PacketsParseFailed    uint64
		SaveStats             struct {
			SavePackets         uint64
			SaveFailedLogic     uint64
			SaveFailedNotOpened uint64
			SaveFailedFull      uint64
			SaveFailedOther     uint64
		}
	}
	OpensslStats struct {
		UprobesTotal         uint64
		UprobesEnabled       uint64
		UprobesMatched       uint64
		UprobesErrUpdate     uint64
		UretprobesTotal      uint64
		UretprobesEnabled    uint64
		UretprobesMatched    uint64
		UretprobesErrContext uint64
		SaveStats            struct {
			SavePackets         uint64
			SaveFailedLogic     uint64
			SaveFailedNotOpened uint64
			SaveFailedFull      uint64
			SaveFailedOther     uint64
		}
	}
	GotlsStats struct {
		UprobesTotal      uint64
		UprobesEnabled    uint64
		UprobesMatched    uint64
		UretprobesTotal   uint64
		UretprobesEnabled uint64
		UretprobesMatched uint64
		SaveStats         struct {
			SavePackets         uint64
			SaveFailedLogic     uint64
			SaveFailedNotOpened uint64
			SaveFailedFull      uint64
			SaveFailedOther     uint64
		}
	}
}

type TracerBufT struct{ Buf [32768]uint8 }

type TracerCgroupSignal struct {
	Path        [4096]uint8
	CgroupId    uint64
	HierarchyId uint32
	Size        uint16
	Remove      uint8
	_           [1]byte
}

type TracerConfiguration struct{ Flags uint32 }

type TracerConnectInfo struct {
	Fd      uint64
	Addrlen uint32
	_       [4]byte
}

type TracerEntry struct{ Args [6]uint64 }

type TracerFilePath struct {
	Path     [4096]int8
	CgroupId uint64
	Inode    uint64
	DeviceId uint32
	Size     uint16
	Remove   uint8
	_        [1]byte
}

type TracerFlowStatsT struct {
	LastUpdateTime uint64
	Event          struct {
		Comm          [16]int8
		CgroupId      uint64
		InodeId       uint64
		PacketsSent   uint64
		BytesSent     uint64
		PacketsRecv   uint64
		BytesRecv     uint64
		IpSrc         uint32
		IpDst         uint32
		Pid           uint32
		ParentPid     uint32
		HostPid       uint32
		HostParentPid uint32
		EventId       uint16
		PortSrc       uint16
		PortDst       uint16
		Pad           [10]int8
	}
}

type TracerFlowT struct {
	IpLocal struct {
		AddrV4 struct{ S_addr uint32 }
		_      [12]byte
	}
	IpRemote struct {
		AddrV4 struct{ S_addr uint32 }
		_      [12]byte
	}
	PortLocal  uint16
	PortRemote uint16
	Protocol   uint8
	IpVersion  uint8
	_          [2]byte
}

type TracerFoundPid struct {
	Cgroup uint64
	Pid    uint32
	Pad1   uint32
}

type TracerGoidOffsets struct {
	G_addrOffset uint64
	GoidOffset   uint64
}

type TracerIndexerT struct {
	Ts     uint64
	IpCsum uint16
	_      [2]byte
	Src    struct{ In6U struct{ U6Addr8 [16]uint8 } }
	Dst    struct{ In6U struct{ U6Addr8 [16]uint8 } }
	_      [4]byte
}

type TracerPidInfo struct {
	SysFdOffset int64
	IsInterface uint64
}

type TracerPidOffset struct {
	Pid          uint64
	SymbolOffset uint64
}

type TracerPkt struct {
	Timestamp uint64
	CgroupId  uint64
	Id        uint64
	Len       uint32
	TotLen    uint32
	Counter   uint32
	Num       uint16
	Last      uint16
	IpHdrType uint16
	Direction uint8
	Buf       [4096]uint8
	_         [5]byte
}

type TracerPktIdT struct {
	Id   uint64
	Lock struct{ Val uint32 }
	_    [4]byte
}

type TracerSslInfo struct {
	Buffer        uint64
	BufferLen     uint32
	Fd            uint32
	CreatedAtNano uint64
	AddressInfo   TracerAddressInfo
	CountPtr      uint64
}

type TracerTlsChunk struct {
	Timestamp   uint64
	CgroupId    uint32
	Pid         uint32
	Tgid        uint32
	Len         uint32
	Start       uint32
	Recorded    uint32
	Fd          uint32
	Flags       uint32
	AddressInfo TracerAddressInfo
	Direction   uint8
	Data        [4096]uint8
	_           [7]byte
}

// LoadTracer returns the embedded CollectionSpec for Tracer.
func LoadTracer() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TracerBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Tracer: %w", err)
	}

	return spec, err
}

// LoadTracerObjects loads Tracer and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*TracerObjects
//	*TracerPrograms
//	*TracerMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadTracerObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadTracer()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// TracerSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TracerSpecs struct {
	TracerProgramSpecs
	TracerMapSpecs
}

// TracerSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TracerProgramSpecs struct {
	CgroupBpfRunFilterSkb         *ebpf.ProgramSpec `ebpf:"cgroup_bpf_run_filter_skb"`
	CgroupMkdirSignal             *ebpf.ProgramSpec `ebpf:"cgroup_mkdir_signal"`
	CgroupRmdirSignal             *ebpf.ProgramSpec `ebpf:"cgroup_rmdir_signal"`
	DoAccept                      *ebpf.ProgramSpec `ebpf:"do_accept"`
	DoMkdirat                     *ebpf.ProgramSpec `ebpf:"do_mkdirat"`
	DoMkdiratRet                  *ebpf.ProgramSpec `ebpf:"do_mkdirat_ret"`
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
	SchedProcessFork              *ebpf.ProgramSpec `ebpf:"sched_process_fork"`
	SecurityFileOpen              *ebpf.ProgramSpec `ebpf:"security_file_open"`
	SecurityInodeRename           *ebpf.ProgramSpec `ebpf:"security_inode_rename"`
	SecurityInodeUnlink           *ebpf.ProgramSpec `ebpf:"security_inode_unlink"`
	SecurityPathMkdir             *ebpf.ProgramSpec `ebpf:"security_path_mkdir"`
	SecuritySkClone               *ebpf.ProgramSpec `ebpf:"security_sk_clone"`
	SecuritySocketRecvmsg         *ebpf.ProgramSpec `ebpf:"security_socket_recvmsg"`
	SecuritySocketSendmsg         *ebpf.ProgramSpec `ebpf:"security_socket_sendmsg"`
	SockAllocFile                 *ebpf.ProgramSpec `ebpf:"sock_alloc_file"`
	SockAllocFileRet              *ebpf.ProgramSpec `ebpf:"sock_alloc_file_ret"`
	SslPending                    *ebpf.ProgramSpec `ebpf:"ssl_pending"`
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
	SysEnterRecvfrom              *ebpf.ProgramSpec `ebpf:"sys_enter_recvfrom"`
	SysEnterSendto                *ebpf.ProgramSpec `ebpf:"sys_enter_sendto"`
	SysEnterWrite                 *ebpf.ProgramSpec `ebpf:"sys_enter_write"`
	SysExecveExit                 *ebpf.ProgramSpec `ebpf:"sys_execve_exit"`
	SysExitAccept4                *ebpf.ProgramSpec `ebpf:"sys_exit_accept4"`
	SysExitConnect                *ebpf.ProgramSpec `ebpf:"sys_exit_connect"`
	SysExitRead                   *ebpf.ProgramSpec `ebpf:"sys_exit_read"`
	SysExitWrite                  *ebpf.ProgramSpec `ebpf:"sys_exit_write"`
	SyscallAccept4Ret             *ebpf.ProgramSpec `ebpf:"syscall__accept4_ret"`
	TcpClose                      *ebpf.ProgramSpec `ebpf:"tcp_close"`
	TcpConnect                    *ebpf.ProgramSpec `ebpf:"tcp_connect"`
	TcpRecvmsg                    *ebpf.ProgramSpec `ebpf:"tcp_recvmsg"`
	TcpSendmsg                    *ebpf.ProgramSpec `ebpf:"tcp_sendmsg"`
	TraceCgroupConnect4           *ebpf.ProgramSpec `ebpf:"trace_cgroup_connect4"`
	VfsCreate                     *ebpf.ProgramSpec `ebpf:"vfs_create"`
	VfsRmdir                      *ebpf.ProgramSpec `ebpf:"vfs_rmdir"`
}

// TracerMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TracerMapSpecs struct {
	AcceptContext            *ebpf.MapSpec `ebpf:"accept_context"`
	AcceptSyscallContext     *ebpf.MapSpec `ebpf:"accept_syscall_context"`
	AllStatsMap              *ebpf.MapSpec `ebpf:"all_stats_map"`
	Bufs                     *ebpf.MapSpec `ebpf:"bufs"`
	CgroupIds                *ebpf.MapSpec `ebpf:"cgroup_ids"`
	CgroupSignalHeap         *ebpf.MapSpec `ebpf:"cgroup_signal_heap"`
	CgrpctxmapEg             *ebpf.MapSpec `ebpf:"cgrpctxmap_eg"`
	CgrpctxmapIn             *ebpf.MapSpec `ebpf:"cgrpctxmap_in"`
	ChunksBuffer             *ebpf.MapSpec `ebpf:"chunks_buffer"`
	ConnectSyscallInfo       *ebpf.MapSpec `ebpf:"connect_syscall_info"`
	ConnectionContext        *ebpf.MapSpec `ebpf:"connection_context"`
	DoMkdirContext           *ebpf.MapSpec `ebpf:"do_mkdir_context"`
	Entrymap                 *ebpf.MapSpec `ebpf:"entrymap"`
	FileProbeHeap            *ebpf.MapSpec `ebpf:"file_probe_heap"`
	ForkInfo                 *ebpf.MapSpec `ebpf:"fork_info"`
	GoKernelReadContext      *ebpf.MapSpec `ebpf:"go_kernel_read_context"`
	GoKernelWriteContext     *ebpf.MapSpec `ebpf:"go_kernel_write_context"`
	GoReadContext            *ebpf.MapSpec `ebpf:"go_read_context"`
	GoUserKernelReadContext  *ebpf.MapSpec `ebpf:"go_user_kernel_read_context"`
	GoUserKernelWriteContext *ebpf.MapSpec `ebpf:"go_user_kernel_write_context"`
	GoWriteContext           *ebpf.MapSpec `ebpf:"go_write_context"`
	GoidOffsetsMap           *ebpf.MapSpec `ebpf:"goid_offsets_map"`
	Heap                     *ebpf.MapSpec `ebpf:"heap"`
	HeapFlow                 *ebpf.MapSpec `ebpf:"heap_flow"`
	Inodemap                 *ebpf.MapSpec `ebpf:"inodemap"`
	LogBuffer                *ebpf.MapSpec `ebpf:"log_buffer"`
	OpensslReadContext       *ebpf.MapSpec `ebpf:"openssl_read_context"`
	OpensslWriteContext      *ebpf.MapSpec `ebpf:"openssl_write_context"`
	PerfCgroupSignal         *ebpf.MapSpec `ebpf:"perf_cgroup_signal"`
	PerfFoundCgroup          *ebpf.MapSpec `ebpf:"perf_found_cgroup"`
	PerfFoundOpenssl         *ebpf.MapSpec `ebpf:"perf_found_openssl"`
	PerfFoundPid             *ebpf.MapSpec `ebpf:"perf_found_pid"`
	PidsInfo                 *ebpf.MapSpec `ebpf:"pids_info"`
	PktHeap                  *ebpf.MapSpec `ebpf:"pkt_heap"`
	PktId                    *ebpf.MapSpec `ebpf:"pkt_id"`
	PktsBuffer               *ebpf.MapSpec `ebpf:"pkts_buffer"`
	ProgramsConfiguration    *ebpf.MapSpec `ebpf:"programs_configuration"`
	Settings                 *ebpf.MapSpec `ebpf:"settings"`
	SocketCgroups            *ebpf.MapSpec `ebpf:"socket_cgroups"`
	Sockmap                  *ebpf.MapSpec `ebpf:"sockmap"`
	SyscallEvents            *ebpf.MapSpec `ebpf:"syscall_events"`
	TcpAcceptContext         *ebpf.MapSpec `ebpf:"tcp_accept_context"`
	TcpAcceptFlowContext     *ebpf.MapSpec `ebpf:"tcp_accept_flow_context"`
	TcpConnectContext        *ebpf.MapSpec `ebpf:"tcp_connect_context"`
	TcpConnectFlowContext    *ebpf.MapSpec `ebpf:"tcp_connect_flow_context"`
}

// TracerObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type TracerObjects struct {
	TracerPrograms
	TracerMaps
}

func (o *TracerObjects) Close() error {
	return _TracerClose(
		&o.TracerPrograms,
		&o.TracerMaps,
	)
}

// TracerMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type TracerMaps struct {
	AcceptContext            *ebpf.Map `ebpf:"accept_context"`
	AcceptSyscallContext     *ebpf.Map `ebpf:"accept_syscall_context"`
	AllStatsMap              *ebpf.Map `ebpf:"all_stats_map"`
	Bufs                     *ebpf.Map `ebpf:"bufs"`
	CgroupIds                *ebpf.Map `ebpf:"cgroup_ids"`
	CgroupSignalHeap         *ebpf.Map `ebpf:"cgroup_signal_heap"`
	CgrpctxmapEg             *ebpf.Map `ebpf:"cgrpctxmap_eg"`
	CgrpctxmapIn             *ebpf.Map `ebpf:"cgrpctxmap_in"`
	ChunksBuffer             *ebpf.Map `ebpf:"chunks_buffer"`
	ConnectSyscallInfo       *ebpf.Map `ebpf:"connect_syscall_info"`
	ConnectionContext        *ebpf.Map `ebpf:"connection_context"`
	DoMkdirContext           *ebpf.Map `ebpf:"do_mkdir_context"`
	Entrymap                 *ebpf.Map `ebpf:"entrymap"`
	FileProbeHeap            *ebpf.Map `ebpf:"file_probe_heap"`
	ForkInfo                 *ebpf.Map `ebpf:"fork_info"`
	GoKernelReadContext      *ebpf.Map `ebpf:"go_kernel_read_context"`
	GoKernelWriteContext     *ebpf.Map `ebpf:"go_kernel_write_context"`
	GoReadContext            *ebpf.Map `ebpf:"go_read_context"`
	GoUserKernelReadContext  *ebpf.Map `ebpf:"go_user_kernel_read_context"`
	GoUserKernelWriteContext *ebpf.Map `ebpf:"go_user_kernel_write_context"`
	GoWriteContext           *ebpf.Map `ebpf:"go_write_context"`
	GoidOffsetsMap           *ebpf.Map `ebpf:"goid_offsets_map"`
	Heap                     *ebpf.Map `ebpf:"heap"`
	HeapFlow                 *ebpf.Map `ebpf:"heap_flow"`
	Inodemap                 *ebpf.Map `ebpf:"inodemap"`
	LogBuffer                *ebpf.Map `ebpf:"log_buffer"`
	OpensslReadContext       *ebpf.Map `ebpf:"openssl_read_context"`
	OpensslWriteContext      *ebpf.Map `ebpf:"openssl_write_context"`
	PerfCgroupSignal         *ebpf.Map `ebpf:"perf_cgroup_signal"`
	PerfFoundCgroup          *ebpf.Map `ebpf:"perf_found_cgroup"`
	PerfFoundOpenssl         *ebpf.Map `ebpf:"perf_found_openssl"`
	PerfFoundPid             *ebpf.Map `ebpf:"perf_found_pid"`
	PidsInfo                 *ebpf.Map `ebpf:"pids_info"`
	PktHeap                  *ebpf.Map `ebpf:"pkt_heap"`
	PktId                    *ebpf.Map `ebpf:"pkt_id"`
	PktsBuffer               *ebpf.Map `ebpf:"pkts_buffer"`
	ProgramsConfiguration    *ebpf.Map `ebpf:"programs_configuration"`
	Settings                 *ebpf.Map `ebpf:"settings"`
	SocketCgroups            *ebpf.Map `ebpf:"socket_cgroups"`
	Sockmap                  *ebpf.Map `ebpf:"sockmap"`
	SyscallEvents            *ebpf.Map `ebpf:"syscall_events"`
	TcpAcceptContext         *ebpf.Map `ebpf:"tcp_accept_context"`
	TcpAcceptFlowContext     *ebpf.Map `ebpf:"tcp_accept_flow_context"`
	TcpConnectContext        *ebpf.Map `ebpf:"tcp_connect_context"`
	TcpConnectFlowContext    *ebpf.Map `ebpf:"tcp_connect_flow_context"`
}

func (m *TracerMaps) Close() error {
	return _TracerClose(
		m.AcceptContext,
		m.AcceptSyscallContext,
		m.AllStatsMap,
		m.Bufs,
		m.CgroupIds,
		m.CgroupSignalHeap,
		m.CgrpctxmapEg,
		m.CgrpctxmapIn,
		m.ChunksBuffer,
		m.ConnectSyscallInfo,
		m.ConnectionContext,
		m.DoMkdirContext,
		m.Entrymap,
		m.FileProbeHeap,
		m.ForkInfo,
		m.GoKernelReadContext,
		m.GoKernelWriteContext,
		m.GoReadContext,
		m.GoUserKernelReadContext,
		m.GoUserKernelWriteContext,
		m.GoWriteContext,
		m.GoidOffsetsMap,
		m.Heap,
		m.HeapFlow,
		m.Inodemap,
		m.LogBuffer,
		m.OpensslReadContext,
		m.OpensslWriteContext,
		m.PerfCgroupSignal,
		m.PerfFoundCgroup,
		m.PerfFoundOpenssl,
		m.PerfFoundPid,
		m.PidsInfo,
		m.PktHeap,
		m.PktId,
		m.PktsBuffer,
		m.ProgramsConfiguration,
		m.Settings,
		m.SocketCgroups,
		m.Sockmap,
		m.SyscallEvents,
		m.TcpAcceptContext,
		m.TcpAcceptFlowContext,
		m.TcpConnectContext,
		m.TcpConnectFlowContext,
	)
}

// TracerPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type TracerPrograms struct {
	CgroupBpfRunFilterSkb         *ebpf.Program `ebpf:"cgroup_bpf_run_filter_skb"`
	CgroupMkdirSignal             *ebpf.Program `ebpf:"cgroup_mkdir_signal"`
	CgroupRmdirSignal             *ebpf.Program `ebpf:"cgroup_rmdir_signal"`
	DoAccept                      *ebpf.Program `ebpf:"do_accept"`
	DoMkdirat                     *ebpf.Program `ebpf:"do_mkdirat"`
	DoMkdiratRet                  *ebpf.Program `ebpf:"do_mkdirat_ret"`
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
	SchedProcessFork              *ebpf.Program `ebpf:"sched_process_fork"`
	SecurityFileOpen              *ebpf.Program `ebpf:"security_file_open"`
	SecurityInodeRename           *ebpf.Program `ebpf:"security_inode_rename"`
	SecurityInodeUnlink           *ebpf.Program `ebpf:"security_inode_unlink"`
	SecurityPathMkdir             *ebpf.Program `ebpf:"security_path_mkdir"`
	SecuritySkClone               *ebpf.Program `ebpf:"security_sk_clone"`
	SecuritySocketRecvmsg         *ebpf.Program `ebpf:"security_socket_recvmsg"`
	SecuritySocketSendmsg         *ebpf.Program `ebpf:"security_socket_sendmsg"`
	SockAllocFile                 *ebpf.Program `ebpf:"sock_alloc_file"`
	SockAllocFileRet              *ebpf.Program `ebpf:"sock_alloc_file_ret"`
	SslPending                    *ebpf.Program `ebpf:"ssl_pending"`
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
	SysEnterRecvfrom              *ebpf.Program `ebpf:"sys_enter_recvfrom"`
	SysEnterSendto                *ebpf.Program `ebpf:"sys_enter_sendto"`
	SysEnterWrite                 *ebpf.Program `ebpf:"sys_enter_write"`
	SysExecveExit                 *ebpf.Program `ebpf:"sys_execve_exit"`
	SysExitAccept4                *ebpf.Program `ebpf:"sys_exit_accept4"`
	SysExitConnect                *ebpf.Program `ebpf:"sys_exit_connect"`
	SysExitRead                   *ebpf.Program `ebpf:"sys_exit_read"`
	SysExitWrite                  *ebpf.Program `ebpf:"sys_exit_write"`
	SyscallAccept4Ret             *ebpf.Program `ebpf:"syscall__accept4_ret"`
	TcpClose                      *ebpf.Program `ebpf:"tcp_close"`
	TcpConnect                    *ebpf.Program `ebpf:"tcp_connect"`
	TcpRecvmsg                    *ebpf.Program `ebpf:"tcp_recvmsg"`
	TcpSendmsg                    *ebpf.Program `ebpf:"tcp_sendmsg"`
	TraceCgroupConnect4           *ebpf.Program `ebpf:"trace_cgroup_connect4"`
	VfsCreate                     *ebpf.Program `ebpf:"vfs_create"`
	VfsRmdir                      *ebpf.Program `ebpf:"vfs_rmdir"`
}

func (p *TracerPrograms) Close() error {
	return _TracerClose(
		p.CgroupBpfRunFilterSkb,
		p.CgroupMkdirSignal,
		p.CgroupRmdirSignal,
		p.DoAccept,
		p.DoMkdirat,
		p.DoMkdiratRet,
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
		p.SchedProcessFork,
		p.SecurityFileOpen,
		p.SecurityInodeRename,
		p.SecurityInodeUnlink,
		p.SecurityPathMkdir,
		p.SecuritySkClone,
		p.SecuritySocketRecvmsg,
		p.SecuritySocketSendmsg,
		p.SockAllocFile,
		p.SockAllocFileRet,
		p.SslPending,
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
		p.SysEnterRecvfrom,
		p.SysEnterSendto,
		p.SysEnterWrite,
		p.SysExecveExit,
		p.SysExitAccept4,
		p.SysExitConnect,
		p.SysExitRead,
		p.SysExitWrite,
		p.SyscallAccept4Ret,
		p.TcpClose,
		p.TcpConnect,
		p.TcpRecvmsg,
		p.TcpSendmsg,
		p.TraceCgroupConnect4,
		p.VfsCreate,
		p.VfsRmdir,
	)
}

func _TracerClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tracer_bpfel_x86.o
var _TracerBytes []byte
