package syscall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/cgroup"
	"github.com/kubeshark/tracer/pkg/events"
	"github.com/kubeshark/tracer/pkg/resolver"
	"github.com/kubeshark/tracer/socket"
	"github.com/rs/zerolog/log"
)

type SyscallEventsTracer struct {
	cgroupController cgroup.CgroupsController
	eventReader      *perf.Reader
	eventSocket      *socket.SocketEvent
}

func NewSyscallEventsTracer(bpfObjs *bpf.BpfObjects, cgroupController cgroup.CgroupsController) (*SyscallEventsTracer, error) {
	reader, err := perf.NewReader(bpfObjs.BpfObjs.SyscallEvents, os.Getpagesize())
	if err != nil {
		return nil, fmt.Errorf("open events perf buffer failed")
	}

	return &SyscallEventsTracer{
		cgroupController: cgroupController,
		eventReader:      reader,
		eventSocket:      socket.NewSocketEvent(misc.GetSyscallEventSocketPath()),
	}, nil
}

func (t *SyscallEventsTracer) Start() {
	go t.pollEvents()
}

func (t *SyscallEventsTracer) Stop() (err error) {
	return t.eventReader.Close()
}

func (t *SyscallEventsTracer) pollEvents() {
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
			log.Warn().Msg(fmt.Sprintf("Syslog events buffer is full, dropped %d logs", record.LostSamples))
			continue
		}

		const expectedSize = 108
		if len(record.RawSample) != expectedSize {
			log.Fatal().Int("size", len(record.RawSample)).Int("expected", expectedSize).Msg("wrong syscall event size")
			return
		}
		ev := (*events.SyscallEventMessage)(unsafe.Pointer(&record.RawSample[0]))

		toIP := func(ip uint32) net.IP {
			ipBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(ipBytes, ip)
			return net.IP(ipBytes)
		}
		toPort := func(port uint16) uint16 {
			return binary.BigEndian.Uint16([]byte{byte(port >> 8), byte(port & 0xff)})
		}

		var evName string
		if ev.EventId == 0 {
			evName = "connect"
		} else if ev.EventId == 1 {
			evName = "accept"
		} else if ev.EventId == 2 {
			evName = "close connect"
		} else if ev.EventId == 3 {
			evName = "close accept"
		}

		var e events.SyscallEvent
		e.SyscallEventMessage = *ev

		e.ProcessPath, _ = resolver.ResolveSymlinkWithoutValidation(filepath.Join("/hostproc", fmt.Sprintf("%v", ev.HostPid), "exe"))
		log.Debug().Msg(fmt.Sprintf("Syscall event %v: %v:%v->%v:%v command: %v host pid: %v host ppid: %v pid: %v ppid: %v cgroup id: %v, sent (pkts: %v, bytes: %v), recv (pkts: %v, bytes: %v)",
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
			e.CgroupID,
			e.Stats.PacketsSent,
			e.Stats.BytesSent,
			e.Stats.PacketsReceived,
			e.Stats.BytesReceived,
		))

		t.eventSocket.WriteObject(e)
	}

}
