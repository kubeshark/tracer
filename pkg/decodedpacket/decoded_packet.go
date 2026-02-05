package decodedpacket

import (
	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/tracerproto/pkg/unixpacket"
)

// LayerParser encapsulates the DecodingLayerParser and reusable layer objects
// for zero-copy, zero-allocation packet decoding
type LayerParser struct {
	ipv4Parser    *gopacket.DecodingLayerParser
	ipv6Parser    *gopacket.DecodingLayerParser
	decodedLayers []gopacket.LayerType
	// Reusable layer objects
	ethLayer     layers.Ethernet
	ipv4Layer    layers.IPv4
	ipv6Layer    layers.IPv6
	icmpv4Layer  layers.ICMPv4
	icmpv6Layer  layers.ICMPv6
	tcpLayer     layers.TCP
	udpLayer     layers.UDP
	sctpLayer    layers.SCTP
	dnsLayer     layers.DNS
	radiusLayer  layers.RADIUS
	payloadLayer gopacket.Payload
}

// NewLayerParser creates a new LayerParser with initialized parsers and layer objects
func NewLayerParser() *LayerParser {
	lp := &LayerParser{
		decodedLayers: make([]gopacket.LayerType, 0, 10),
	}

	// Initialize IPv4 DecodingLayerParser starting from IPv4 layer
	lp.ipv4Parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv4,
		&lp.ipv4Layer,
		&lp.icmpv4Layer,
		&lp.tcpLayer,
		&lp.udpLayer,
		&lp.sctpLayer,
		&lp.dnsLayer,
		&lp.radiusLayer,
		&lp.payloadLayer,
	)
	lp.ipv4Parser.IgnoreUnsupported = true

	// Initialize IPv6 DecodingLayerParser starting from IPv6 layer
	lp.ipv6Parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv6,
		&lp.ipv6Layer,
		&lp.icmpv6Layer,
		&lp.tcpLayer,
		&lp.udpLayer,
		&lp.sctpLayer,
		&lp.dnsLayer,
		&lp.radiusLayer,
		&lp.payloadLayer,
	)
	lp.ipv6Parser.IgnoreUnsupported = true

	return lp
}

// detectIPVersion detects the IP version from packet data
// Returns 4 for IPv4, 6 for IPv6, or 0 if unable to determine
func detectIPVersion(data []byte) int {
	if len(data) < 1 {
		return 0
	}

	// IP version is stored in the first 4 bits of the first byte
	// Shift right by 4 bits to get the version
	version := (data[0] >> 4) & 0xF

	if version == 4 {
		return 4
	} else if version == 6 {
		return 6
	}

	return 0
}

// DecodeLayers decodes packet data into the reusable layer objects
// Returns error if decoding fails
func (lp *LayerParser) DecodeLayers(data []byte) error {
	lp.decodedLayers = lp.decodedLayers[:0] // Reset slice but keep capacity

	// Detect IP version and choose appropriate parser
	ipVersion := detectIPVersion(data)

	switch ipVersion {
	case 4:
		return lp.ipv4Parser.DecodeLayers(data, &lp.decodedLayers)
	case 6:
		return lp.ipv6Parser.DecodeLayers(data, &lp.decodedLayers)
	default:
		// If we can't determine IP version, try both parsers
		// Start with IPv4 as it's more common
		if err := lp.ipv4Parser.DecodeLayers(data, &lp.decodedLayers); err == nil {
			return nil
		}
		// If IPv4 fails, try IPv6
		return lp.ipv6Parser.DecodeLayers(data, &lp.decodedLayers)
	}
}

// BuildPacketLayers builds a layers slice from the decoded layers
// This creates references to the reusable layer objects
func (lp *LayerParser) BuildPacketLayers() []gopacket.Layer {
	return BuildLayersFromDecoded(lp.decodedLayers, &lp.ethLayer, &lp.ipv4Layer, &lp.ipv6Layer, &lp.icmpv4Layer, &lp.icmpv6Layer, &lp.tcpLayer, &lp.udpLayer, &lp.sctpLayer, &lp.dnsLayer, &lp.radiusLayer, &lp.payloadLayer)
}

// CreatePacket is a convenience method that decodes data and creates a packet in one call
func (lp *LayerParser) CreatePacket(data []byte, cgroupID uint64, direction unixpacket.PacketDirection, ci gopacket.CaptureInfo, decodeOptions gopacket.DecodeOptions) (gopacket.Packet, error) {
	if err := lp.DecodeLayers(data); err != nil {
		return nil, err
	}

	packetLayers := lp.BuildPacketLayers()
	return NewDecodedPacket(data, packetLayers, cgroupID, direction, ci, decodeOptions), nil
}

// DecodedPacket represents a packet built from pre-decoded layers.
// This is more efficient than gopacket.NewPacket as it reuses already decoded layer data.
type DecodedPacket struct {
	data      []byte
	layers    []gopacket.Layer
	cgroupID  uint64
	direction unixpacket.PacketDirection
	metadata  gopacket.PacketMetadata
	// PacketBuilder specific fields - cached layer references
	linkLayer        gopacket.LinkLayer
	networkLayer     gopacket.NetworkLayer
	transportLayer   gopacket.TransportLayer
	applicationLayer gopacket.ApplicationLayer
	errorLayer       gopacket.ErrorLayer
	decodeOptions    gopacket.DecodeOptions
}

// NewDecodedPacket creates a new packet from pre-decoded layers
func NewDecodedPacket(data []byte, layers []gopacket.Layer, cgroupID uint64, direction unixpacket.PacketDirection, ci gopacket.CaptureInfo, decodeOptions gopacket.DecodeOptions) *DecodedPacket {
	pkt := &DecodedPacket{
		data:          data,
		layers:        layers,
		cgroupID:      cgroupID,
		direction:     direction,
		decodeOptions: decodeOptions,
		metadata: gopacket.PacketMetadata{
			CaptureInfo: ci,
		},
	}

	// Populate layer type fields (linkLayer, networkLayer, etc.)
	for _, layer := range layers {
		if ll, ok := layer.(gopacket.LinkLayer); ok && pkt.linkLayer == nil {
			pkt.linkLayer = ll
		}
		if nl, ok := layer.(gopacket.NetworkLayer); ok && pkt.networkLayer == nil {
			pkt.networkLayer = nl
		}
		if tl, ok := layer.(gopacket.TransportLayer); ok && pkt.transportLayer == nil {
			pkt.transportLayer = tl
		}
		if al, ok := layer.(gopacket.ApplicationLayer); ok && pkt.applicationLayer == nil {
			pkt.applicationLayer = al
		}
		if el, ok := layer.(gopacket.ErrorLayer); ok && pkt.errorLayer == nil {
			pkt.errorLayer = el
		}
	}

	return pkt
}

// BuildLayersFromDecoded builds a layers slice from decoded layer types
func BuildLayersFromDecoded(decodedLayers []gopacket.LayerType, ethLayer *layers.Ethernet, ipv4Layer *layers.IPv4, ipv6Layer *layers.IPv6, icmpv4Layer *layers.ICMPv4, icmpv6Layer *layers.ICMPv6, tcpLayer *layers.TCP, udpLayer *layers.UDP, sctpLayer *layers.SCTP, dnsLayer *layers.DNS, radiusLayer *layers.RADIUS, payloadLayer *gopacket.Payload) []gopacket.Layer {
	var packetLayers []gopacket.Layer

	for _, layerType := range decodedLayers {
		switch layerType {
		case layers.LayerTypeEthernet:
			packetLayers = append(packetLayers, ethLayer)
		case layers.LayerTypeIPv4:
			packetLayers = append(packetLayers, ipv4Layer)
		case layers.LayerTypeIPv6:
			packetLayers = append(packetLayers, ipv6Layer)
		case layers.LayerTypeICMPv4:
			packetLayers = append(packetLayers, icmpv4Layer)
		case layers.LayerTypeICMPv6:
			packetLayers = append(packetLayers, icmpv6Layer)
		case layers.LayerTypeTCP:
			packetLayers = append(packetLayers, tcpLayer)
		case layers.LayerTypeUDP:
			packetLayers = append(packetLayers, udpLayer)
		case layers.LayerTypeSCTP:
			packetLayers = append(packetLayers, sctpLayer)
		case layers.LayerTypeDNS:
			packetLayers = append(packetLayers, dnsLayer)
		case layers.LayerTypeRADIUS:
			packetLayers = append(packetLayers, radiusLayer)
		case gopacket.LayerTypePayload:
			packetLayers = append(packetLayers, payloadLayer)
		}
	}

	return packetLayers
}

func (p *DecodedPacket) String() string {
	var result string
	for i, layer := range p.layers {
		if i > 0 {
			result += "/"
		}
		result += layer.LayerType().String()
	}
	return result
}

func (p *DecodedPacket) Dump() string {
	var result string
	for _, layer := range p.layers {
		result += layer.LayerType().String() + "\n"
	}
	return result
}

// CgroupID returns the cgroup ID for this packet
func (p *DecodedPacket) CgroupID() uint64 {
	return p.cgroupID
}

// Direction returns the packet direction
func (p *DecodedPacket) Direction() unixpacket.PacketDirection {
	return p.direction
}

// GetBackend returns the capture backend
func (p *DecodedPacket) GetBackend() gopacket.CaptureBackend {
	return p.metadata.CaptureInfo.CaptureBackend
}

// GetVlanDot1Q returns whether VLAN dot1q is present
func (p *DecodedPacket) GetVlanDot1Q() bool {
	return false
}

// GetVlanID returns the VLAN ID if present
func (p *DecodedPacket) GetVlanID() uint16 {
	return 0
}

// SetBackend sets the capture backend
func (p *DecodedPacket) SetBackend(backend gopacket.CaptureBackend) {
	p.metadata.CaptureInfo.CaptureBackend = backend
}

// SetVlanDot1Q sets VLAN dot1q information (no-op for our implementation)
func (p *DecodedPacket) SetVlanDot1Q(present bool) {
	// No-op
}

// SetVlanID sets the VLAN ID (no-op for our implementation)
func (p *DecodedPacket) SetVlanID(id uint16) {
	// No-op
}

func (p *DecodedPacket) Layers() []gopacket.Layer {
	return p.layers
}

func (p *DecodedPacket) Layer(t gopacket.LayerType) gopacket.Layer {
	for _, l := range p.layers {
		if l.LayerType() == t {
			return l
		}
	}
	return nil
}

func (p *DecodedPacket) LayerClass(lc gopacket.LayerClass) gopacket.Layer {
	for _, l := range p.layers {
		if lc.Contains(l.LayerType()) {
			return l
		}
	}
	return nil
}

func (p *DecodedPacket) LinkLayer() gopacket.LinkLayer {
	if p.linkLayer != nil {
		return p.linkLayer
	}
	if layer := p.Layer(layers.LayerTypeEthernet); layer != nil {
		linkLayer := layer.(gopacket.LinkLayer)
		p.linkLayer = linkLayer
		return linkLayer
	}
	return nil
}

func (p *DecodedPacket) NetworkLayer() gopacket.NetworkLayer {
	if p.networkLayer != nil {
		return p.networkLayer
	}
	if layer := p.Layer(layers.LayerTypeIPv4); layer != nil {
		networkLayer := layer.(gopacket.NetworkLayer)
		p.networkLayer = networkLayer
		return networkLayer
	}
	if layer := p.Layer(layers.LayerTypeIPv6); layer != nil {
		networkLayer := layer.(gopacket.NetworkLayer)
		p.networkLayer = networkLayer
		return networkLayer
	}
	return nil
}

func (p *DecodedPacket) TransportLayer() gopacket.TransportLayer {
	if p.transportLayer != nil {
		return p.transportLayer
	}
	if layer := p.Layer(layers.LayerTypeTCP); layer != nil {
		transportLayer := layer.(gopacket.TransportLayer)
		p.transportLayer = transportLayer
		return transportLayer
	}
	if layer := p.Layer(layers.LayerTypeUDP); layer != nil {
		transportLayer := layer.(gopacket.TransportLayer)
		p.transportLayer = transportLayer
		return transportLayer
	}
	return nil
}

func (p *DecodedPacket) ApplicationLayer() gopacket.ApplicationLayer {
	if p.applicationLayer != nil {
		return p.applicationLayer
	}
	// Find the last layer that implements ApplicationLayer
	for i := len(p.layers) - 1; i >= 0; i-- {
		if app, ok := p.layers[i].(gopacket.ApplicationLayer); ok {
			p.applicationLayer = app
			return app
		}
	}
	return nil
}

func (p *DecodedPacket) ErrorLayer() gopacket.ErrorLayer {
	if p.errorLayer != nil {
		return p.errorLayer
	}
	for _, l := range p.layers {
		if el, ok := l.(gopacket.ErrorLayer); ok {
			p.errorLayer = el
			return el
		}
	}
	return nil
}

func (p *DecodedPacket) Data() []byte {
	return p.data
}

func (p *DecodedPacket) Metadata() *gopacket.PacketMetadata {
	return &p.metadata
}

// PacketBuilder interface methods

// AddLayer adds a layer to the packet
func (p *DecodedPacket) AddLayer(l gopacket.Layer) {
	p.layers = append(p.layers, l)

	// Update cached layer references based on the layer type
	switch layer := l.(type) {
	case gopacket.LinkLayer:
		if p.linkLayer == nil {
			p.linkLayer = layer
		}
	case gopacket.NetworkLayer:
		if p.networkLayer == nil {
			p.networkLayer = layer
		}
	case gopacket.TransportLayer:
		if p.transportLayer == nil {
			p.transportLayer = layer
		}
	case gopacket.ApplicationLayer:
		if p.applicationLayer == nil {
			p.applicationLayer = layer
		}
	case gopacket.ErrorLayer:
		if p.errorLayer == nil {
			p.errorLayer = layer
		}
	}
}

// SetLinkLayer sets the link layer
func (p *DecodedPacket) SetLinkLayer(l gopacket.LinkLayer) {
	if p.linkLayer == nil {
		p.linkLayer = l
		// Also add to layers if not already present
		found := false
		for _, layer := range p.layers {
			if layer == l {
				found = true
				break
			}
		}
		if !found {
			p.layers = append(p.layers, l)
		}
	}
}

// SetNetworkLayer sets the network layer
func (p *DecodedPacket) SetNetworkLayer(l gopacket.NetworkLayer) {
	if p.networkLayer == nil {
		p.networkLayer = l
		// Also add to layers if not already present
		found := false
		for _, layer := range p.layers {
			if layer == l {
				found = true
				break
			}
		}
		if !found {
			p.layers = append(p.layers, l)
		}
	}
}

// SetTransportLayer sets the transport layer
func (p *DecodedPacket) SetTransportLayer(l gopacket.TransportLayer) {
	if p.transportLayer == nil {
		p.transportLayer = l
		// Also add to layers if not already present
		found := false
		for _, layer := range p.layers {
			if layer == l {
				found = true
				break
			}
		}
		if !found {
			p.layers = append(p.layers, l)
		}
	}
}

// SetApplicationLayer sets the application layer
func (p *DecodedPacket) SetApplicationLayer(l gopacket.ApplicationLayer) {
	if p.applicationLayer == nil {
		p.applicationLayer = l
		// Also add to layers if not already present
		found := false
		for _, layer := range p.layers {
			if layer == l {
				found = true
				break
			}
		}
		if !found {
			p.layers = append(p.layers, l)
		}
	}
}

// SetErrorLayer sets the error layer
func (p *DecodedPacket) SetErrorLayer(l gopacket.ErrorLayer) {
	if p.errorLayer == nil {
		p.errorLayer = l
		// Also add to layers if not already present
		found := false
		for _, layer := range p.layers {
			if layer == l {
				found = true
				break
			}
		}
		if !found {
			p.layers = append(p.layers, l)
		}
	}
}

func DetectIPVersion(data []byte) int { return detectIPVersion(data) }
