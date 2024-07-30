package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/kubeshark/tracer/socket"
	"github.com/rs/zerolog/log"
)

type SyscallEventMessage struct {
	Command       [16]byte
	IpSrc         uint32
	IpDst         uint32
	Pid           uint32
	ParentPid     uint32
	HostPid       uint32
	HostParentPid uint32
	EventId       uint16
	PortSrc       uint16
	PortDst       uint16
}

type syscallEventsTracer struct {
	eventReader *perf.Reader
	eventSocket *socket.SocketEvent
}

func newSyscallEventsTracer(eventsMap *ebpf.Map, eventsSize int, socket *socket.SocketEvent) (*syscallEventsTracer, error) {
	reader, err := perf.NewReader(eventsMap, eventsSize)
	if err != nil {
		return nil, fmt.Errorf("open events perf buffer failed")
	}

	return &syscallEventsTracer{
		eventReader: reader,
		eventSocket: socket,
	}, nil
}

func (t *syscallEventsTracer) start() (err error) {
	go t.pollEvents()

	return nil
}

func (t *syscallEventsTracer) stop() (err error) {
	return t.eventReader.Close()
}

func (t *syscallEventsTracer) pollEvents() {
	log.Info().Msg("Polling syscall events started")
	defer func() {
		log.Info().Msg("Polling syscall events stopped")
	}()

	for {
		record, err := t.eventReader.Read()

		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			log.Error().Err(err).Msg("Reading syscall event failed")
			return
		}

		if record.LostSamples != 0 {
			log.Info().Msg(fmt.Sprintf("Syslog events buffer is full, dropped %d logs", record.LostSamples))
			continue
		}

		buffer := bytes.NewReader(record.RawSample)

		var e SyscallEventMessage

		if err := binary.Read(buffer, binary.LittleEndian, &e); err != nil {
			log.Error().Err(err).Msg("Parse syscall event failed")
			continue
		}

		toIP := func(ip uint32) net.IP {
			ipBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(ipBytes, ip)
			return net.IP(ipBytes)
		}
		toPort := func(port uint16) uint16 {
			return binary.BigEndian.Uint16([]byte{byte(port >> 8), byte(port & 0xff)})
		}

		var evName string
		if e.EventId == 0 {
			evName = "connect"
		}
		if e.EventId == 1 {
			evName = "accept"
		}
		log.Debug().Msg(fmt.Sprintf("Syscall event %v: %v:%v->%v:%v command: %v host pid: %v host ppid: %v pid: %v ppid: %v",
			evName,
			toIP(e.IpSrc),
			toPort(e.PortSrc),
			toIP(e.IpDst),
			toPort(e.PortDst),
			string(e.Command[:]),
			e.HostPid,
			e.HostParentPid,
			e.Pid,
			e.ParentPid,
		))

		if err := t.eventSocket.WriteObject(e); err != nil {
			log.Error().Err(err).Msg("Write syscall event failed")
			continue
		}

	}

}
