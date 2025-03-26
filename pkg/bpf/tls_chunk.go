package bpf

import (
	"encoding/binary"
	"net"
	"unsafe"
)

const (
	FlagsIsClientBit uint32 = 1 << 0
	FlagsIsReadBit   uint32 = 1 << 1
)

const (
	AF_INET  = 2
	AF_INET6 = 10
)

type AddressPair struct {
	SrcIp   net.IP
	SrcPort uint16
	DstIp   net.IP
	DstPort uint16
}

// getSrcAddress retrieves the source IP and port
func (c *TracerTlsChunk) getSrcAddress() (net.IP, uint16) {
	ip := getIPFromAddressInfo(&c.AddressInfo, true)
	port := ntohs(c.AddressInfo.Sport)
	return ip, port
}

// getDstAddress retrieves the destination IP and port
func (c *TracerTlsChunk) getDstAddress() (net.IP, uint16) {
	ip := getIPFromAddressInfo(&c.AddressInfo, false)
	port := ntohs(c.AddressInfo.Dport)
	return ip, port
}

// Function to extract either Src or Dst IP based on offset calculations
func getIPFromAddressInfo(ai *TracerAddressInfo, isSrc bool) net.IP {
	switch ai.Family {
	case AF_INET:
		if isSrc {
			return ipv4ToIP(ai.Saddr4)
		}
		return ipv4ToIP(ai.Daddr4)
	case AF_INET6:
		if isSrc {
			return net.IP(ai.Saddr6[:])
		}
		return net.IP(ai.Daddr6[:])
	default:
		return nil
	}
}

// Converts IPv4 integer representation to net.IP
func ipv4ToIP(ipv4 uint32) net.IP {
	return net.IPv4(
		byte(ipv4), byte(ipv4>>8),
		byte(ipv4>>16), byte(ipv4>>24),
	)
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

// ntohs converts big endian (network byte order) to little endian (assuming that's the host byte order)
func ntohs(i16be uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i16be)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
