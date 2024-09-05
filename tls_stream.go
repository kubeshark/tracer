package main

import (
	"net"
	"strconv"
	"sync"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/misc/ethernet"
	"github.com/rs/zerolog/log"
)

type tlsLayers struct {
	ethernet *layers.Ethernet
	ipv4     *layers.IPv4
	tcp      *layers.TCP
}

func (l *tlsLayers) swap() {
	l.ethernet.SrcMAC, l.ethernet.DstMAC = l.ethernet.DstMAC, l.ethernet.SrcMAC
	l.ipv4.SrcIP, l.ipv4.DstIP = l.ipv4.DstIP, l.ipv4.SrcIP
	l.tcp.SrcPort, l.tcp.DstPort = l.tcp.DstPort, l.tcp.SrcPort
}

type tlsStream struct {
	poller *tlsPoller
	key    string
	id     int64
	client *tlsReader
	server *tlsReader
	layers *tlsLayers
	sync.Mutex
}

func NewTlsStream(poller *tlsPoller, key string) *tlsStream {
	return &tlsStream{
		poller: poller,
		key:    key,
	}
}

func (t *tlsStream) getId() int64 {
	return t.id
}

func (t *tlsStream) setId(id int64) {
	t.id = id
}

func (t *tlsStream) doTcpHandshake(timestamp uint64, cgroupId uint64, direction uint8) {
	data := []byte{}

	// SYN
	t.layers.tcp.SYN = true
	t.writeLayers(timestamp, cgroupId, direction, data, true, 0)

	// SYN-ACK
	t.layers.swap()
	t.layers.tcp.ACK = true
	t.layers.tcp.Ack++
	t.writeLayers(timestamp, cgroupId, direction, data, false, 0)

	// ACK
	t.layers.swap()
	t.layers.tcp.SYN = false
	t.layers.tcp.ACK = true
	t.layers.tcp.Seq++
	t.writeLayers(timestamp, cgroupId, direction, data, true, 0)

	t.client.seqNumbers.Seq = 1
	t.client.seqNumbers.Ack = 1
	t.server.seqNumbers.Seq = 1
	t.server.seqNumbers.Ack = 1
}

func (t *tlsStream) writeData(timestamp uint64, cgroupId uint64, direction uint8, data []byte, reader *tlsReader) {
	t.setLayers(timestamp, cgroupId, direction, data, reader)
	t.layers.tcp.ACK = true
	if reader.isClient {
		t.layers.tcp.PSH = true
	} else {
		t.layers.tcp.PSH = false
	}
	sentLen := uint32(len(data))
	t.loadSecNumbers(reader.isClient)
	t.writeLayers(timestamp, cgroupId, direction, data, reader.isClient, sentLen)
	t.layers.tcp.PSH = false
	t.layers.swap()
	t.loadSecNumbers(!reader.isClient)
	t.writeLayers(timestamp, cgroupId, direction, []byte{}, !reader.isClient, 0)
}

func (t *tlsStream) writeLayers(timestamp uint64, cgroupId uint64, direction uint8, data []byte, isClient bool, sentLen uint32) {
	t.writePacket(
		timestamp,
		cgroupId,
		direction,
		layers.LayerTypeEthernet,
		t.layers.ethernet,
		t.layers.ipv4,
		t.layers.tcp,
		gopacket.Payload(data),
	)
	t.doTcpSeqAckWalk(isClient, sentLen)
}

func (t *tlsStream) writePacket(timestamp uint64, cgroupId uint64, direction uint8, firstLayerType gopacket.LayerType, l ...gopacket.SerializableLayer) {

	err := t.poller.sorter.WriteTLSPacket(timestamp, cgroupId, direction, firstLayerType, l...)
	if err != nil {
		log.Warn().Err(err).Msg("Error writing PCAP:")
		return
	}
}

func (t *tlsStream) loadSecNumbers(isClient bool) {
	var reader *tlsReader
	if isClient {
		reader = t.client
	} else {
		reader = t.server
	}

	t.layers.tcp.Seq = reader.seqNumbers.Seq
	t.layers.tcp.Ack = reader.seqNumbers.Ack
}

func (t *tlsStream) doTcpSeqAckWalk(isClient bool, sentLen uint32) {
	if isClient {
		t.client.seqNumbers.Seq += sentLen
		t.server.seqNumbers.Ack += sentLen
	} else {
		t.server.seqNumbers.Seq += sentLen
		t.client.seqNumbers.Ack += sentLen
	}
}

func (t *tlsStream) setLayers(timestamp uint64, cgroupId uint64, direction uint8, data []byte, reader *tlsReader) {
	ipv4 := t.newIPv4Layer(reader)
	tcp := t.newTCPLayer(reader)
	err := tcp.SetNetworkLayerForChecksum(ipv4)
	if err != nil {
		log.Warn().Err(err).Send()
	}

	if t.layers == nil {
		t.layers = &tlsLayers{
			ethernet: ethernet.NewEthernetLayer(layers.EthernetTypeIPv4),
			ipv4:     ipv4,
			tcp:      tcp,
		}
		t.doTcpHandshake(timestamp, cgroupId, direction)
	} else {
		t.layers.ipv4.SrcIP = ipv4.SrcIP
		t.layers.ipv4.DstIP = ipv4.DstIP

		t.layers.tcp.SrcPort = tcp.SrcPort
		t.layers.tcp.DstPort = tcp.DstPort
	}
}

func (t *tlsStream) newIPv4Layer(reader *tlsReader) *layers.IPv4 {
	srcIP, _, err := net.ParseCIDR(reader.tcpID.SrcIP + "/24")
	if err != nil {
		panic(err)
	}
	dstIP, _, err := net.ParseCIDR(reader.tcpID.DstIP + "/24")
	if err != nil {
		panic(err)
	}
	res := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	return res
}

func (t *tlsStream) newTCPLayer(reader *tlsReader) *layers.TCP {
	srcPort, err := strconv.ParseUint(reader.tcpID.SrcPort, 10, 64)
	if err != nil {
		panic(err)
	}
	dstPort, err := strconv.ParseUint(reader.tcpID.DstPort, 10, 64)
	if err != nil {
		panic(err)
	}
	return &layers.TCP{
		Window:  uint16(misc.Snaplen - 1),
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     false,
		PSH:     false,
		ACK:     false,
		Seq:     0,
		Ack:     0,
	}
}
