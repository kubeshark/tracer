package main

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/kubeshark/gopacket"
	"github.com/rs/zerolog/log"
)

const (
	maxUnixPacketClients = 10
	packetHeaderSize     = int(unsafe.Sizeof(PacketHeader{}))
)

type SocketPcapConnection struct {
	packetCounter uint64
}

type SocketPcap struct {
	packetCounter    uint64
	clientsConnected int
	connections      map[*net.UnixConn]*SocketPcapConnection
	sync.Mutex
}

type PacketHeader struct {
	packetCounter uint64
	timestamp     uint64
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
		} else {
			c.connections[conn] = &SocketPcapConnection{}
			c.clientsConnected++
		}
		c.Unlock()
	}
}

func (c *SocketPcap) WritePacket(buf gopacket.SerializeBuffer) error {
	var err error
	var hdrBytes []byte
	c.Lock()
	defer c.Unlock()
	c.packetCounter++
	if len(c.connections) > 0 {
		hdrBytes, err = buf.PrependBytes(packetHeaderSize)
		if err != nil {
			return err
		}
		// clear buffer at the end as soon as it is prepended with specific data
		defer func() {
			buf.Clear()
		}()
	}
	for sock, conn := range c.connections {
		hdr := (*PacketHeader)(unsafe.Pointer(&hdrBytes))
		hdr.packetCounter = conn.packetCounter

		_, err = sock.Write(buf.Bytes())

		if err != nil {
			if errors.Is(err, syscall.EPIPE) {
				log.Info().Str("Address", sock.RemoteAddr().String()).Msg("Unix socket connection closed:")
			} else {
				log.Error().Err(err).Str("Address", sock.RemoteAddr().String()).Msg("Unix socket connection error:")
			}
			delete(c.connections, sock)
			continue
		}
		conn.packetCounter++
	}

	return nil
}
