package main

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracer/pkg/unixpacket"
	"github.com/rs/zerolog/log"
)

const (
	maxUnixPacketClients = 10
)

type SocketPcapConnection struct {
	packetCounter uint64
	writeChannel  chan []byte
	packetSent    uint64
	packetDropped uint64
}

type SocketPcap struct {
	packetCounter    uint64
	clientsConnected int
	connections      map[*net.UnixConn]*SocketPcapConnection
	sync.Mutex
	maxPktSize int
}

func (s *SocketPcapConnection) Run(conn *net.UnixConn, sock *SocketPcap) {
	for {
		buf := <-s.writeChannel
		_, err := conn.Write(buf)
		if err != nil {
			if errors.Is(err, syscall.EPIPE) {
				log.Info().Str("Address", conn.RemoteAddr().String()).Msg("Unix socket connection closed:")
			} else {
				log.Error().Err(err).Str("Address", conn.RemoteAddr().String()).Msg("Unix socket connection error:")
			}
			sock.Disconnected(conn)
			return
		}
	}
}

func (s *SocketPcap) WritePacket(pkt gopacket.SerializeBuffer) error {
	s.Lock()
	defer s.Unlock()
	defer func() {
		s.packetCounter++
	}()
	if len(s.connections) == 0 {
		return nil
	}

	hdrBytes, err := pkt.PrependBytes(unixpacket.PacketHeaderSize)
	if err != nil {
		return err
	}

	p := unixpacket.PacketUnixSocket(hdrBytes)
	hdr := p.GetHeader()
	hdr.Timestamp = uint64(time.Now().UnixNano())
	// clear buffer at the end as soon as it is prepended with specific data
	defer func() {
		_ = pkt.Clear()
	}()

	buf := pkt.Bytes()
	if len(buf) > s.maxPktSize {
		s.maxPktSize = len(buf)
		// temorary logging
		log.Info().Int("len", s.maxPktSize).Msg("Max packet size:")
	}
	for _, conn := range s.connections {
		copyBuf := make([]byte, len(buf))
		copy(copyBuf, buf)
		p = unixpacket.PacketUnixSocket(copyBuf)
		hdr = p.GetHeader()
		hdr.PacketCounter = conn.packetCounter
		conn.packetCounter++
		select {
		case conn.writeChannel <- copyBuf:
			conn.packetSent++
		default:
			conn.packetDropped++
		}
	}
	return nil
}

func (s *SocketPcap) Connected(conn *net.UnixConn) {
	ch := make(chan []byte, 256)
	s.Lock()
	defer s.Unlock()
	c := &SocketPcapConnection{
		writeChannel: ch,
	}
	s.connections[conn] = c
	go c.Run(conn, s)
}

func (s *SocketPcap) Disconnected(conn *net.UnixConn) {
	s.Lock()
	defer s.Unlock()
	delete(s.connections, conn)
}

func NewSocketPcap(unixSocketFileName string) *SocketPcap {
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: unixSocketFileName, Net: "unixpacket"})
	if err != nil {
		panic(err)
	}

	sock := SocketPcap{
		connections: make(map[*net.UnixConn]*SocketPcapConnection),
	}
	go sock.acceptClients(l)

	return &sock
}

func (c *SocketPcap) acceptClients(l *net.UnixListener) {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			log.Error().Err(err).Msg("Accept unix socket failed:")
			time.Sleep(time.Second)
			continue
		}
		log.Info().Str("Address", conn.RemoteAddr().String()).Msg("Accepted unix socket:")

		c.Lock()
		if c.clientsConnected == maxUnixPacketClients {
			log.Info().Str("Address", conn.RemoteAddr().String()).Msg("Unix socket max connections exceeded, closing:")
			conn.Close()
			c.Unlock()
			continue
		}
		c.Unlock()
		c.Connected(conn)
	}
}
