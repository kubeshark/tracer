package grpcservice

import (
	"context"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/kubeshark/api2/pkg/proto/tracer_service"
	v1 "github.com/kubeshark/api2/pkg/proto/tracer_service/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// LRUCacheSize is the size of the LRU cache for container info
	LRUCacheSize = 1024
	// SendChannelSize is the size of the buffered channel for each stream
	SendChannelSize = 1000
)

// StreamInfo represents information about a stream and its send channel
type StreamInfo struct {
	stream     tracer_service.TracerService_StreamContainerInfoServer
	sendChan   chan *tracer_service.ContainerInfo
	cancelFunc context.CancelFunc
	closeOnce  sync.Once // Ensures channel is closed only once
}

// ContainerInfo represents information about a container
type ContainerInfo struct {
	ContainerID string
	CgroupID    uint64
}

// GRPCService implements the TracerService gRPC server
type GRPCService struct {
	tracer_service.UnimplementedTracerServiceServer
	mu        sync.RWMutex
	isRunning bool
	// Channel to notify about service stop
	stopCh chan struct{}
	// Map to store active streams
	streams map[tracer_service.TracerService_StreamContainerInfoServer]*StreamInfo
	// LRU cache for container info
	cache *lru.Cache[string, *tracer_service.ContainerInfo]
}

// NewGRPCService creates a new instance of GRPCServer
func NewGRPCService() *GRPCService {
	cache, err := lru.New[string, *tracer_service.ContainerInfo](LRUCacheSize)
	if err != nil {
		log.Fatal().Msgf("Failed to create LRU cache: %v", err)
	}

	return &GRPCService{
		stopCh:  make(chan struct{}),
		streams: make(map[tracer_service.TracerService_StreamContainerInfoServer]*StreamInfo),
		cache:   cache,
	}
}

// handleStreamSends processes messages for a single stream
func (s *GRPCService) handleStreamSends(streamInfo *StreamInfo) {
	defer func() {
		// Use sync.Once to ensure channel is closed only once
		streamInfo.closeOnce.Do(func() {
			close(streamInfo.sendChan)
		})
		streamInfo.cancelFunc()
	}()

	for {
		select {
		case <-s.stopCh:
			return
		case info, ok := <-streamInfo.sendChan:
			if !ok {
				return
			}
			if err := streamInfo.stream.Send(info); err != nil {
				log.Error().Msgf("Failed to send to stream: %v", err)
				return
			}
		}
	}
}

// StreamContainerInfo implements the gRPC StreamContainerInfo method
func (s *GRPCService) StreamContainerInfo(empty *emptypb.Empty, stream tracer_service.TracerService_StreamContainerInfoServer) error {
	// Get client metadata from the context
	// Log client information
	if clientAddr, ok := peer.FromContext(stream.Context()); ok {
		log.Info().Msgf("Client connected from address: %v", clientAddr.Addr)
	}

	// Create a context that will be canceled when the stream ends
	ctx, cancel := context.WithCancel(stream.Context())

	// Create stream info with buffered channel
	streamInfo := &StreamInfo{
		stream:     stream,
		sendChan:   make(chan *tracer_service.ContainerInfo, SendChannelSize),
		cancelFunc: cancel,
	}

	// Register the stream
	s.mu.Lock()
	s.streams[stream] = streamInfo
	s.mu.Unlock()

	// Start the send handler goroutine
	go s.handleStreamSends(streamInfo)

	// Send cached container info to the new client
	s.mu.RLock()
	for _, key := range s.cache.Keys() {
		if info, ok := s.cache.Get(key); ok {
			select {
			case streamInfo.sendChan <- info:
			default:
				log.Warn().Msgf("Stream send channel full, dropping cached container info")
			}
		}
	}
	s.mu.RUnlock()

	// Cleanup when the stream ends
	defer func() {
		s.mu.Lock()
		if si, exists := s.streams[stream]; exists {
			// Use sync.Once to ensure channel is closed only once
			si.closeOnce.Do(func() {
				close(si.sendChan)
			})
			delete(s.streams, stream)
		}
		s.mu.Unlock()
	}()

	// Wait for context cancellation
	<-ctx.Done()
	return ctx.Err()
}

// Start starts the gRPC server service
func (s *GRPCService) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isRunning {
		return nil
	}

	// Reset channels and state
	s.stopCh = make(chan struct{})
	s.streams = make(map[tracer_service.TracerService_StreamContainerInfoServer]*StreamInfo)

	// Create a new cache
	cache, err := lru.New[string, *tracer_service.ContainerInfo](LRUCacheSize)
	if err != nil {
		return err
	}
	s.cache = cache
	s.isRunning = true

	return nil
}

// Stop stops the gRPC server service
func (s *GRPCService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.isRunning {
		return nil
	}

	// Signal all streams to stop
	close(s.stopCh)
	for _, si := range s.streams {
		si.cancelFunc()
	}
	s.streams = make(map[tracer_service.TracerService_StreamContainerInfoServer]*StreamInfo)
	s.cache.Purge()
	s.isRunning = false

	return nil
}

// AddContainerInfo broadcasts container information to all active streams
func (s *GRPCService) AddContainerInfo(info ContainerInfo) error {
	// Convert internal ContainerInfo to proto ContainerInfo
	protoInfo := &tracer_service.ContainerInfo{
		V: &tracer_service.ContainerInfo_V1{
			V1: &v1.ContainerInfo{
				Created:     timestamppb.New(time.Now()),
				ContainerId: info.ContainerID,
				CgroupId:    info.CgroupID,
			},
		},
	}

	// Add to cache
	s.mu.Lock()
	s.cache.Add(info.ContainerID, protoInfo)
	s.mu.Unlock()

	// Send to all active streams
	s.mu.RLock()
	for _, streamInfo := range s.streams {
		select {
		case streamInfo.sendChan <- protoInfo:
		default:
			log.Warn().Msgf("Stream send channel full, dropping container info")
		}
	}
	s.mu.RUnlock()

	return nil
}
