package ethernet

import (
	"net"

	"github.com/kubeshark/gopacket/layers"
)

func NewEthernetLayer(ethernetType layers.EthernetType) *layers.Ethernet {
	srcMac, _ := net.ParseMAC("00:00:00:00:00:00")
	dstMac, _ := net.ParseMAC("00:00:00:00:00:00")
	res := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: ethernetType,
	}
	return res
}
