package bpf

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/misc/ethernet"
	"github.com/kubeshark/tracerproto/pkg/unixpacket"
	"github.com/rs/zerolog/log"
)

type tlsLayers struct {
	ethernet *layers.Ethernet
	network  gopacket.SerializableLayer
	tcp      *layers.TCP
}

func (l *tlsLayers) swap() {
	l.ethernet.SrcMAC, l.ethernet.DstMAC = l.ethernet.DstMAC, l.ethernet.SrcMAC
	switch ipLayer := l.network.(type) {
	case *layers.IPv4:
		ipLayer.SrcIP, ipLayer.DstIP = ipLayer.DstIP, ipLayer.SrcIP
	case *layers.IPv6:
		ipLayer.SrcIP, ipLayer.DstIP = ipLayer.DstIP, ipLayer.SrcIP
	}
	l.tcp.SrcPort, l.tcp.DstPort = l.tcp.DstPort, l.tcp.SrcPort
}

type TlsStream struct {
	serializeOptions gopacket.SerializeOptions
	ethernetDecoder  gopacket.Decoder
	poller           *TlsPoller
	key              string
	id               int64
	Client           *tlsReader
	Server           *tlsReader
	layers           *tlsLayers
	stats            tlsStreamStats
	sync.Mutex
}

type tlsStreamStats struct {
	PacketsGot  uint64
	DataWritten uint64
}

var ethernetDecoder = gopacket.DecodersByLayerName["Ethernet"]

func NewTlsStream(poller *TlsPoller, key string) *TlsStream {
	if ethernetDecoder == nil {
		log.Error().Msg("Failed to get Ethernet decoder")
		return nil
	}
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	return &TlsStream{
		serializeOptions: serializeOptions,
		ethernetDecoder:  ethernetDecoder,
		poller:           poller,
		key:              key,
	}
}

func (t *TlsStream) GetId() int64 {
	return t.id
}

func (t *TlsStream) SetId(id int64) {
	t.id = id
}

func (t *TlsStream) doTcpHandshake(timestamp uint64, cgroupId uint64, direction uint8) {
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

	t.Client.seqNumbers.Seq = 1
	t.Client.seqNumbers.Ack = 1
	t.Server.seqNumbers.Seq = 1
	t.Server.seqNumbers.Ack = 1
}

func (t *TlsStream) writeData(timestamp uint64, cgroupId uint64, direction uint8, data []byte, reader *tlsReader) {
	t.setLayers(timestamp, cgroupId, direction, reader)
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
	t.stats.DataWritten++
}

func (t *TlsStream) writeLayers(timestamp uint64, cgroupId uint64, direction uint8, data []byte, isClient bool, sentLen uint32) {
	t.poller.receivedPackets++
	if t.poller.rawWriter != nil {
		err := t.poller.rawWriter(
			timestamp,
			cgroupId,
			direction,
			layers.LayerTypeEthernet,
			t.layers.ethernet,
			t.layers.network,
			t.layers.tcp,
			gopacket.Payload(data),
		)
		if err != nil {
			log.Error().Err(err).Msg("Error writing PCAP:")
			return
		}
	}

	if t.poller.rawPacketWriter != nil {
		t.poller.rawPacketWriter(timestamp, data)
	}

	if t.poller.gopacketWriter != nil {
		buf := gopacket.NewSerializeBuffer()

		err := gopacket.SerializeLayers(buf, t.serializeOptions, t.layers.ethernet, t.layers.network, t.layers.tcp, gopacket.Payload(data))
		if err != nil {
			log.Error().Err(err).Msg("Error serializing packet:")
			return
		}

		bufBytes := buf.Bytes()
		pkt := gopacket.NewPacket(bufBytes, t.ethernetDecoder, gopacket.NoCopy, cgroupId, unixpacket.PacketDirection(direction))
		m := pkt.Metadata()
		ci := &m.CaptureInfo
		if timestamp != 0 {
			ci.Timestamp = time.Unix(0, int64(timestamp)-int64(t.poller.tai.GetTAIOffset()))
		} else {
			ci.Timestamp = time.Now()
		}

		ci.CaptureLength = len(bufBytes)
		ci.Length = len(bufBytes)
		ci.CaptureBackend = gopacket.CaptureBackendEbpfTls

		t.stats.PacketsGot++
		t.poller.gopacketWriter(pkt)
	}

	t.doTcpSeqAckWalk(isClient, sentLen)
}

func (t *TlsStream) loadSecNumbers(isClient bool) {
	var reader *tlsReader
	if isClient {
		reader = t.Client
	} else {
		reader = t.Server
	}

	t.layers.tcp.Seq = reader.seqNumbers.Seq
	t.layers.tcp.Ack = reader.seqNumbers.Ack
}

func (t *TlsStream) doTcpSeqAckWalk(isClient bool, sentLen uint32) {
	if isClient {
		t.Client.seqNumbers.Seq += sentLen
		t.Server.seqNumbers.Ack += sentLen
	} else {
		t.Server.seqNumbers.Seq += sentLen
		t.Client.seqNumbers.Ack += sentLen
	}
}

func (t *TlsStream) setLayers(timestamp uint64, cgroupId uint64, direction uint8, reader *tlsReader) {
	srcIP := net.ParseIP(reader.tcpID.SrcIP)
	var ipLayer gopacket.SerializableLayer
	isIPv4 := srcIP.To4() != nil

	if isIPv4 {
		ipLayer = t.newIPv4Layer(reader)
	} else {
		ipLayer = t.newIPv6Layer(reader)
	}

	tcp := t.newTCPLayer(reader)
	if err := tcp.SetNetworkLayerForChecksum(ipLayer.(gopacket.NetworkLayer)); err != nil {
		log.Error().Err(err).Send()
	}

	if t.layers == nil {
		var ethType layers.EthernetType
		if isIPv4 {
			ethType = layers.EthernetTypeIPv4
		} else {
			ethType = layers.EthernetTypeIPv6
		}
		t.layers = &tlsLayers{
			ethernet: ethernet.NewEthernetLayer(ethType),
			network:  ipLayer,
			tcp:      tcp,
		}
		t.doTcpHandshake(timestamp, cgroupId, direction)
	} else {
		switch layer := t.layers.network.(type) {
		case *layers.IPv4:
			newLayer := ipLayer.(*layers.IPv4)
			layer.SrcIP = newLayer.SrcIP
			layer.DstIP = newLayer.DstIP
		case *layers.IPv6:
			newLayer := ipLayer.(*layers.IPv6)
			layer.SrcIP = newLayer.SrcIP
			layer.DstIP = newLayer.DstIP
		}
		t.layers.tcp.SrcPort = tcp.SrcPort
		t.layers.tcp.DstPort = tcp.DstPort
	}
}

func (t *TlsStream) newIPv4Layer(reader *tlsReader) *layers.IPv4 {
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

func (t *TlsStream) newIPv6Layer(reader *tlsReader) *layers.IPv6 {
	srcIP := net.ParseIP(reader.tcpID.SrcIP)
	dstIP := net.ParseIP(reader.tcpID.DstIP)
	log.Info().Msgf("IPv6 layer created with srcIP: %v, dstIP: %v", srcIP, dstIP)

	return &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		NextHeader: layers.IPProtocolTCP,
	}
}

func (t *TlsStream) newTCPLayer(reader *tlsReader) *layers.TCP {
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
