package ethernet

import (
	"net"

	"github.com/kubeshark/gopacket/layers"
)

var zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

// NewEthernetLayer creates an Ethernet layer with zero MACs without parsing strings
func NewEthernetLayer(ethernetType layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       zeroMAC,
		DstMAC:       zeroMAC,
		EthernetType: ethernetType,
	}
}
