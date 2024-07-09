package main

type TcpID struct {
	SrcIP   string
	DstIP   string
	SrcPort string
	DstPort string
}

type seqNumbers struct {
	Seq uint32
	Ack uint32
}

type tlsReader struct {
	seenChunks int
	tcpID      *TcpID
	isClient   bool
	parent     *tlsStream
	seqNumbers *seqNumbers
}

func NewTlsReader(tcpID *TcpID, parent *tlsStream, isClient bool) *tlsReader {
	return &tlsReader{
		tcpID:      tcpID,
		isClient:   isClient,
		parent:     parent,
		seqNumbers: &seqNumbers{},
	}
}

func (r *tlsReader) newChunk(chunk *tracerTlsChunk) {
	r.seenChunks = r.seenChunks + 1

	r.parent.writeData(uint64(chunk.Timestamp), uint64(chunk.CgroupId), chunk.Direction, chunk.getRecordedData(), r)
}
