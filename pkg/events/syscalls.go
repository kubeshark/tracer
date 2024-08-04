package events

type SyscallEventMessage struct {
	Command [16]byte

	CgroupID uint64

	IpSrc         uint32
	IpDst         uint32
	Pid           uint32
	ParentPid     uint32
	HostPid       uint32
	HostParentPid uint32

	EventId uint16
	PortSrc uint16
	PortDst uint16

	Pad [10]byte
}

type SyscallEvent struct {
	SyscallEventMessage
	ContainerID string
}
