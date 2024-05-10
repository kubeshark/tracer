package socket

import (
	"bytes"

	"github.com/aquasecurity/tracee/types/trace"

	"github.com/kubeshark/tracerproto/pkg/sysevent"
	"github.com/rs/zerolog/log"
)

type SocketEvent struct {
	*Socket
	buf         bytes.Buffer
	eventWriter sysevent.Writer
}

func NewSocketEvent(unixSocketFileName string) *SocketEvent {
	se := SocketEvent{
		Socket: NewSocket(unixSocketFileName),
	}
	se.eventWriter = sysevent.NewWriter(&se.buf)

	return &se
}

func (s *SocketEvent) WriteObject(ev trace.Event) error {
	if err := s.eventWriter.Write(ev); err != nil {
		log.Error().Err(err).Msg("syscall write failed")
		return err
	}
	buf := s.buf.Bytes()
	s.Lock()
	defer s.Unlock()
	defer func() {
		s.counter++
	}()
	if len(s.connections) == 0 {
		return nil
	}

	for _, conn := range s.connections {
		copyBuf := make([]byte, len(buf))
		copy(copyBuf, buf)

		if conn.writeChannel.Write(copyBuf) {
			conn.packetSent++
		} else {
			conn.packetDropped++
			log.Error().Str("socket", s.name).Uint64("dropped", conn.packetDropped).Msg("dropped syscall packets")
		}
	}
	s.buf.Reset()

	return nil
}
