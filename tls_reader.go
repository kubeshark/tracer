package main

import (
	"time"
)

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
	seenChunks  int
	tcpID       *TcpID
	isClient    bool
	captureTime time.Time
	parent      *tlsStream
	seqNumbers  *seqNumbers
}

func NewTlsReader(tcpID *TcpID, parent *tlsStream, isClient bool) *tlsReader {
	return &tlsReader{
		tcpID:       tcpID,
		isClient:    isClient,
		captureTime: time.Now(),
		parent:      parent,
		seqNumbers:  &seqNumbers{},
	}
}

func (r *tlsReader) newChunk(chunk *tracerTlsChunk) {
	r.captureTime = time.Now()
	r.seenChunks = r.seenChunks + 1

	r.parent.writeData(chunk.getRecordedData(), r)
}

func (r *tlsReader) GetIsClient() bool {
	return r.isClient
}

func (r *tlsReader) GetCaptureTime() time.Time {
	return r.captureTime
}

func (r *tlsReader) GetIsClosed() bool {
	return false
}
