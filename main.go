package main

import (
	"context"
	"flag"
	"fmt"
	_ "net/http/pprof" // Blank import to pprof
	"os"
	"time"

	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/kubernetes"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

const (
	globCbufMax = 10_000
)

// capture
var procfs = flag.String("procfs", "/proc", "The procfs directory, used when mapping host volumes into a container")

// development
var debug = flag.Bool("debug", false, "Enable debug mode")
var globCbuf = flag.Int("cbuf", 0, fmt.Sprintf("Keep last N packets in circular buffer 0 means disabled, max value is %v", globCbufMax))

var disableEbpfCapture = flag.Bool("disable-ebpf", false, "Disable capture packet via eBPF")

var tracer *Tracer

func main() {
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Caller().Logger()

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	misc.InitDataDir()

	run()
}

func run() {
	log.Info().Msg("Starting tracer...")

	tracer = &Tracer{
		procfs:       *procfs,
		watchingPods: make(map[types.UID][]*pidWatcher),
	}

	_, err := rest.InClusterConfig()
	clusterMode := err == nil
	errOut := make(chan error, 100)
	watcher := kubernetes.NewFromInCluster(errOut, tracer.updateTargets)
	ctx := context.Background()

	if clusterMode {
		nodeName, err := kubernetes.GetThisNodeName(watcher)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		misc.SetDataDir(fmt.Sprintf("/app/data/%s", nodeName))
	}

	streamsMap := NewTcpStreamMap()

	err = createTracer()
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't initialize the tracer:")
	}
	defer tracer.close()

	go tracer.pollForLogging()

	watcher.Start(ctx, clusterMode)

	tracer.poll(streamsMap)
}

func createTracer() (err error) {
	chunksBufferSize := os.Getpagesize() * 10000
	logBufferSize := os.Getpagesize()

	if err = tracer.Init(
		chunksBufferSize,
		logBufferSize,
		*procfs,
	); err != nil {
		return
	}

	// A quick way to instrument libssl.so without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID") != "" {
		if err = tracer.globalSSLLibTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID")); err != nil {
			return
		}
	}

	// A quick way to instrument Go `crypto/tls` without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID") != "" {
		if err = tracer.globalGoTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID")); err != nil {
			return
		}
	}

	return
}
