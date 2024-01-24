package unixpacket

import (
	"unsafe"
)

const PacketHeaderSize = int(unsafe.Sizeof(PacketUnixSocketHeader{}))

type PacketUnixSocketHeader struct {
	PacketCounter uint64
	Timestamp     uint64
}

type PacketUnixSocket []byte

func (pkt *PacketUnixSocket) GetHeader() *PacketUnixSocketHeader {
	data := []byte(*pkt)
	return (*PacketUnixSocketHeader)(unsafe.Pointer(&data[0]))
}

func (pkt *PacketUnixSocket) GetData() []byte {
	data := []byte(*pkt)
	return data[PacketHeaderSize:]
}
