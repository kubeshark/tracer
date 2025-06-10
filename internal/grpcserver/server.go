package grpcserver

import (
	"context"
	"sync"
	"time"

	"github.com/kubeshark/api2/pkg/proto/tracer_service"
	v1 "github.com/kubeshark/api2/pkg/proto/tracer_service/v1"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ContainerInfo represents information about a container
type ContainerInfo struct {
	ContainerID string
	CgroupID    uint64
}

// GRPCServer implements the TracerService gRPC server
type GRPCServer struct {
	tracer_service.UnimplementedTracerServiceServer
	mu        sync.RWMutex
	isRunning bool
	// Channel to notify about service stop
	stopCh chan struct{}
	// Channel for container updates
	updateCh chan ContainerInfo
}

// NewGRPCServer creates a new instance of GRPCServer
func NewGRPCServer() *GRPCServer {
	return &GRPCServer{
		stopCh:   make(chan struct{}),
		updateCh: make(chan ContainerInfo, 100),
	}
}

// StreamContainerInfo implements the gRPC StreamContainerInfo method
func (s *GRPCServer) StreamContainerInfo(empty *emptypb.Empty, stream tracer_service.TracerService_StreamContainerInfoServer) error {
	// Create a context that will be canceled when the stream ends
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	// Start a goroutine to watch for service stop or stream context cancellation
	go func() {
		select {
		case <-s.stopCh:
			cancel()
		case <-ctx.Done():
			return
		}
	}()

	// Start streaming container info
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case info := <-s.updateCh:
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

			if err := stream.Send(protoInfo); err != nil {
				return err
			}
		}
	}
}

// Start starts the gRPC server service
func (s *GRPCServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reset channels and state
	s.stopCh = make(chan struct{})
	s.updateCh = make(chan ContainerInfo, 100)
	s.isRunning = true

	return nil
}

// Stop stops the gRPC server service
func (s *GRPCServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Signal all streams to stop
	close(s.stopCh)
	close(s.updateCh)
	s.isRunning = false

	return nil
}

// AddContainerInfo broadcasts container information to all active streams
func (s *GRPCServer) AddContainerInfo(info ContainerInfo) error {
	// Send the update to all active streams
	select {
	case s.updateCh <- info:
		// TODO: add stats counters
		// Successfully sent the update
	default:
		// TODO: add stats counters
		// Channel is full or closed, skip this update
	}

	return nil
}
