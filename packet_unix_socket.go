package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/tracerproto/pkg/unixpacket"
	"github.com/rs/zerolog/log"
)

const (
	maxUnixPacketClients = 10
)

type packetsBuffer struct {
	mtx     sync.Mutex
	ch      chan []byte
	maxSize uint32
	size    uint32
}

func newPacketsBuffer(packets, bytes uint32) *packetsBuffer {
	return &packetsBuffer{
		ch:      make(chan []byte, packets),
		maxSize: bytes,
	}
}

func (p *packetsBuffer) Write(buf []byte) bool {
	p.mtx.Lock()
	if p.size+uint32(len(buf)) > p.maxSize {
		p.mtx.Unlock()
		return false
	}
	p.mtx.Unlock()

	select {
	case p.ch <- buf:
		p.mtx.Lock()
		p.size += uint32(len(buf))
		p.mtx.Unlock()
		return true
	default:
	}
	return false
}

func (p *packetsBuffer) Read() []byte {
	buf := <-p.ch
	p.mtx.Lock()
	p.size -= uint32(len(buf))
	p.mtx.Unlock()
	return buf
}

type SocketPcapConnection struct {
	packetCounter uint64
	writeChannel  *packetsBuffer
	packetSent    uint64
	packetDropped uint64
}

type SocketPcap struct {
	name             string
	packetCounter    uint64
	clientsConnected int
	connections      map[*net.UnixConn]*SocketPcapConnection
	sync.Mutex
	maxPktSize int
}

func (s *SocketPcapConnection) Run(conn *net.UnixConn, sock *SocketPcap) {
	for {
		buf := s.writeChannel.Read()
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
		log.Info().Str("Name", s.name).Int("len", s.maxPktSize).Msg("Max packet size:")
	}
	for _, conn := range s.connections {
		copyBuf := make([]byte, len(buf))
		copy(copyBuf, buf)
		p = unixpacket.PacketUnixSocket(copyBuf)
		hdr = p.GetHeader()
		hdr.PacketCounter = conn.packetCounter
		conn.packetCounter++

		if conn.writeChannel.Write(copyBuf) {
			conn.packetSent++
		} else {
			conn.packetDropped++
		}
	}
	return nil
}

func (s *SocketPcap) Connected(conn *net.UnixConn) {
	s.Lock()
	defer s.Unlock()
	c := &SocketPcapConnection{
		writeChannel: newPacketsBuffer(16384, 64*1024*1024),
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
	_ = os.Remove(unixSocketFileName)
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: unixSocketFileName, Net: "unixpacket"})
	if err != nil {
		panic(err)
	}

	sock := SocketPcap{
		name:        filepath.Base(unixSocketFileName),
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
		log.Info().Str("Name", c.name).Str("Address", conn.RemoteAddr().String()).Msg("Accepted unix socket:")

		c.Lock()
		if c.clientsConnected == maxUnixPacketClients {
			log.Info().Str("Name", c.name).Str("Address", conn.RemoteAddr().String()).Msg("Unix socket max connections exceeded, closing:")
			conn.Close()
			c.Unlock()
			continue
		}
		c.Unlock()
		c.Connected(conn)
	}
}
