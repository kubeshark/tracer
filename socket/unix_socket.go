package socket

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	maxClients = 10
)

type sockBuffer struct {
	mtx     sync.Mutex
	ch      chan []byte
	maxSize uint32
	size    uint32
}

func newSockBuffer(packets, bytes uint32) *sockBuffer {
	return &sockBuffer{
		ch:      make(chan []byte, packets),
		maxSize: bytes,
	}
}

func (p *sockBuffer) Write(buf []byte) bool {
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

func (p *sockBuffer) Read() []byte {
	buf := <-p.ch
	p.mtx.Lock()
	p.size -= uint32(len(buf))
	p.mtx.Unlock()
	return buf
}

type Connection struct {
	counter       uint64
	writeChannel  *sockBuffer
	packetSent    uint64
	packetDropped uint64
}

type Socket struct {
	name             string
	counter          uint64
	clientsConnected int
	connections      map[*net.UnixConn]*Connection
	sync.Mutex
}

func (s *Connection) Run(conn *net.UnixConn, sock *Socket) {
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

func (s *Socket) Connected(conn *net.UnixConn) {
	s.Lock()
	defer s.Unlock()
	c := &Connection{
		writeChannel: newSockBuffer(16384, 64*1024*1024),
	}
	s.connections[conn] = c
	go c.Run(conn, s)
}

func (s *Socket) Disconnected(conn *net.UnixConn) {
	s.Lock()
	defer s.Unlock()
	delete(s.connections, conn)
}

func NewSocket(unixSocketFileName string) *Socket {
	_ = os.Remove(unixSocketFileName)
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: unixSocketFileName, Net: "unixpacket"})
	if err != nil {
		panic(err)
	}

	sock := Socket{
		name:        filepath.Base(unixSocketFileName),
		connections: make(map[*net.UnixConn]*Connection),
	}
	go sock.acceptClients(l)

	return &sock
}

func (c *Socket) acceptClients(l *net.UnixListener) {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			log.Error().Err(err).Msg("Accept unix socket failed:")
			time.Sleep(time.Second)
			continue
		}
		log.Info().Str("Name", c.name).Str("Address", conn.RemoteAddr().String()).Msg("Accepted unix socket:")

		c.Lock()
		if c.clientsConnected == maxClients {
			log.Info().Str("Name", c.name).Str("Address", conn.RemoteAddr().String()).Msg("Unix socket max connections exceeded, closing:")
			conn.Close()
			c.Unlock()
			continue
		}
		c.Unlock()
		c.Connected(conn)
	}
}
