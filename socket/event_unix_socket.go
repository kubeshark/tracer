package socket

import (
	"encoding/gob"
	"net"
	"os"
	"time"

	"github.com/rs/zerolog/log"
)

type SocketEvent struct {
	unixSocketFileName string
	events             chan any
	lostEvents         uint64
}

func NewSocketEvent(unixSocketFileName string) *SocketEvent {

	se := SocketEvent{
		unixSocketFileName: unixSocketFileName,
		events:             make(chan any, 1024),
	}
	go se.processSocket()

	return &se
}

func (s *SocketEvent) processSocket() {
	for {
		log.Info().Str("Name", s.unixSocketFileName).Msg("Listen event unix socket:")
		_ = os.Remove(s.unixSocketFileName)
		l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: s.unixSocketFileName, Net: "unixpacket"})
		if err != nil {
			log.Warn().Err(err).Str("Name", s.unixSocketFileName).Msg("Listen event unix socket failed:")
			return
		}

		conn, err := l.AcceptUnix()
		if err != nil {
			log.Warn().Err(err).Str("Name", s.unixSocketFileName).Msg("Accept event unix socket failed:")
			time.Sleep(time.Second)
			continue
		}
		log.Info().Str("Name", s.unixSocketFileName).Str("Address", conn.RemoteAddr().String()).Msg("Accepted event unix socket:")

		clearOldEvents := func() {
			for {
				select {
				case <-s.events:
				default:
					return
				}
			}
		}
		clearOldEvents()

		encoder := gob.NewEncoder(conn)

		for ev := range s.events {
			if err := encoder.Encode(ev); err != nil {
				log.Warn().Err(err).Str("Name", s.unixSocketFileName).Msg("Encode to unix socket failed:")
				conn.Close()
				break
			}
		}
	}
}

func (s *SocketEvent) WriteObject(ev any) {
	select {
	case s.events <- ev:
	default:
		s.lostEvents++
	}
}
