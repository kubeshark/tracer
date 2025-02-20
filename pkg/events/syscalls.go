package events

import (
	"bytes"
)


// must match tracer/bpf/include/events.h SYSCALL_EVENT_ID_*
const (
	EventIdConnect      = 0
	EventIdAccept       = 1
	EventIdCloseConnect = 2
	EventIdCloseAccept  = 3
)

type SyscallEventMessage struct {
	Command [16]byte

	CgroupID uint64
	SocketID uint64

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
	ProcessPath string
}

func (ev *SyscallEventMessage) CmdPath() (cmd string) {
	nullIndex := bytes.IndexByte(ev.Command[:], 0)
	if nullIndex == -1 {
		cmd = string(ev.Command[:])
	} else {
		cmd = string(ev.Command[:nullIndex])
	}
	return
}