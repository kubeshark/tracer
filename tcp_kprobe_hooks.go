package main

import (
	"github.com/cilium/ebpf/link"
	"github.com/go-errors/errors"
)

var CompatibleMode = false

type tcpKprobeHooks struct {
	tcpSendmsg  link.Link
	tcpRecvmsg  link.Link
	tcp4Connect link.Link
	accept      link.Link
	accept4     link.Link
}

func (s *tcpKprobeHooks) installTcpKprobeHooks(bpfObjects *tracerObjects) error {
	var err error

	s.tcpSendmsg, err = link.Kprobe("tcp_sendmsg", bpfObjects.TcpSendmsg, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	s.tcpRecvmsg, err = link.Kprobe("tcp_recvmsg", bpfObjects.TcpRecvmsg, nil)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	if !CompatibleMode {
		s.tcp4Connect, err = link.Kprobe("tcp_connect", bpfObjects.TcpConnect, nil)
		if err != nil {
			return errors.Wrap(err, 0)
		}

		s.accept, err = link.Kretprobe("sys_accept4", bpfObjects.SyscallAccept4Ret, nil)
		if err != nil {
			return errors.Wrap(err, 0)
		}

		s.accept4, err = link.Kretprobe("do_accept", bpfObjects.DoAccept, nil)
		if err != nil {
			return errors.Wrap(err, 0)
		}
	}

	return nil
}

func (s *tcpKprobeHooks) close() []error {
	returnValue := make([]error, 0)

	if s.tcpSendmsg != nil {
		if err := s.tcpSendmsg.Close(); err != nil {
			returnValue = append(returnValue, err)
		}
	}

	if s.tcpRecvmsg != nil {
		if err := s.tcpRecvmsg.Close(); err != nil {
			returnValue = append(returnValue, err)
		}
	}

	if s.tcp4Connect != nil {
		if err := s.tcp4Connect.Close(); err != nil {
			returnValue = append(returnValue, err)
		}
	}

	if s.accept != nil {
		if err := s.accept.Close(); err != nil {
			returnValue = append(returnValue, err)
		}
	}

	if s.accept4 != nil {
		if err := s.accept4.Close(); err != nil {
			returnValue = append(returnValue, err)
		}
	}

	return returnValue
}
