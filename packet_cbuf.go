package main

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/tracer/misc"
)

type CbufPcap struct {
	writer *cbufWriter
}

func NewCbufPcap(cbufSize int) *CbufPcap {
	p := &CbufPcap{
		writer: newCbufWriter(cbufSize),
	}
	return p
}

func (c *CbufPcap) WritePacket(ci gopacket.CaptureInfo, data []byte) {
	c.writer.writePacket(ci, data)
}

func (c *CbufPcap) DumptoPcapFile(file *os.File, packetsLimit int) (err error) {
	return c.writer.dumpPacketsPcap(file, packetsLimit)
}

type cbufPacket struct {
	ci   gopacket.CaptureInfo
	data []byte
}

type cbufWriter struct {
	counter int
	pos     int
	size    int
	cbuf    map[int]cbufPacket
	sync.Mutex
}

func newCbufWriter(size int) *cbufWriter {
	if size < 1 {
		return nil
	}
	return &cbufWriter{
		size: size,
		cbuf: make(map[int]cbufPacket, size),
	}
}

func (c *cbufWriter) writePacket(ci gopacket.CaptureInfo, data []byte) {
	c.Lock()
	defer c.Unlock()

	c.cbuf[c.pos] = cbufPacket{
		ci:   ci,
		data: data,
	}

	if c.counter < c.size {
		c.counter++
	}

	c.pos++
	if c.pos == c.size {
		c.pos = 0
	}
}

// dumpPacketsPcap dumps max maxCount packets from ringbuf to file writer
func (c *cbufWriter) dumpPacketsPcap(file *os.File, count int) error {
	if count < 0 {
		return errors.New("count less than 0")
	}
	writer := pcapgo.NewWriter(file)
	err := writer.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeEthernet)
	if err != nil {
		return fmt.Errorf("writing the PCAP header failed: %v", err)
	}

	c.Lock()
	defer c.Unlock()

	if c.counter < count {
		count = c.counter
	}

	// c.pos points on the next after last
	pos := c.pos - count
	if pos < 0 {
		pos += c.size
	}

	for count != 0 {
		err = writer.WritePacket(c.cbuf[pos].ci, c.cbuf[pos].data)
		if err != nil {
			return err
		}
		pos++
		if pos == c.size {
			pos = 0
		}
		count--
	}

	return nil
}
