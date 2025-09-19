package rawpacket

type RawPacketWriter func(timestamp uint64, pkt []byte)
