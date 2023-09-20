package main

import (
	"sync"
)

type TcpStreamMap struct {
	streams  *sync.Map
	streamId int64
	done     chan bool
}

func NewTcpStreamMap() *TcpStreamMap {
	streamMap := &TcpStreamMap{
		streams: &sync.Map{},
		done:    make(chan bool),
	}

	return streamMap
}

func (streamMap *TcpStreamMap) Range(f func(key, value interface{}) bool) {
	if streamMap.streams != nil {
		streamMap.streams.Range(f)
	}
}

func (streamMap *TcpStreamMap) Store(key, value interface{}) {
	if streamMap.streams != nil {
		streamMap.streams.Store(key, value)
	}
}

func (streamMap *TcpStreamMap) Delete(key interface{}) {
	if streamMap.streams != nil {
		streamMap.streams.Delete(key)
	}
}

func (streamMap *TcpStreamMap) NextId() int64 {
	streamMap.streamId++
	return streamMap.streamId
}

func (streamMap *TcpStreamMap) Close() {
	streamMap.done <- true
	streamMap.streams = nil
}
