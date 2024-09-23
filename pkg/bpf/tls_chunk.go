package bpf

import (
	"encoding/binary"
	"net"
	"unsafe"
)

const FlagsIsClientBit uint32 = 1 << 0
const FlagsIsReadBit uint32 = 1 << 1

type AddressPair struct {
	SrcIp   net.IP
	SrcPort uint16
	DstIp   net.IP
	DstPort uint16
}

func (c *TracerTlsChunk) getSrcAddress() (net.IP, uint16) {
	ip := intToIP(c.AddressInfo.Saddr)
	port := ntohs(c.AddressInfo.Sport)

	return ip, port
}

func (c *TracerTlsChunk) getDstAddress() (net.IP, uint16) {
	ip := intToIP(c.AddressInfo.Daddr)
	port := ntohs(c.AddressInfo.Dport)

	return ip, port
}

func (c *TracerTlsChunk) IsClient() bool {
	return c.Flags&FlagsIsClientBit != 0
}

func (c *TracerTlsChunk) IsServer() bool {
	return !c.IsClient()
}

func (c *TracerTlsChunk) isRead() bool {
	return c.Flags&FlagsIsReadBit != 0
}

func (c *TracerTlsChunk) isWrite() bool {
	return !c.isRead()
}

func (c *TracerTlsChunk) getRecordedData() []byte {
	return c.Data[:c.Recorded]
}

func (c *TracerTlsChunk) IsRequest() bool {
	return (c.IsClient() && c.isWrite()) || (c.IsServer() && c.isRead())
}

func (c *TracerTlsChunk) GetAddressPair() *AddressPair {
	var (
		srcIp, dstIp     net.IP
		srcPort, dstPort uint16
	)

	if c.IsRequest() {
		srcIp, srcPort = c.getSrcAddress()
		dstIp, dstPort = c.getDstAddress()
	} else {
		srcIp, srcPort = c.getDstAddress()
		dstIp, dstPort = c.getSrcAddress()
	}

	return &AddressPair{
		SrcIp:   srcIp,
		SrcPort: srcPort,
		DstIp:   dstIp,
		DstPort: dstPort,
	}
}

func (c *TracerTlsChunk) GetReader(stream *TlsStream) *tlsReader {
	if c.IsRequest() {
		return stream.Client
	} else {
		return stream.Server
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ip32be uint32) net.IP {
	return net.IPv4(uint8(ip32be), uint8(ip32be>>8), uint8(ip32be>>16), uint8(ip32be>>24))
}

// ntohs converts big endian (network byte order) to little endian (assuming that's the host byte order)
func ntohs(i16be uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i16be)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
