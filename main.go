package main

import (
	"context"
	"flag"
	"fmt"
	_ "net/http/pprof" // Blank import to pprof
	"os"
	"strings"
	"time"

	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/kubernetes"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"

	"github.com/kubeshark/tracer/pkg/health"
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
var enableSyscallEvents = flag.Bool("enable-syscall", false, "Enable syscall events processing")

type sslListArray []string

func (i *sslListArray) String() string {
	return strings.Join((*i)[:], ",")
}
func (i *sslListArray) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var sslLibsGlobal sslListArray

var tracer *Tracer

func main() {
	flag.Var(&sslLibsGlobal, "ssl-libname", "Custom libssl library name")
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
		procfs:            *procfs,
		watchingPods:      make(map[types.UID]*watchingPodsInfo),
		targetedCgroupIDs: map[uint64]struct{}{},
	}

	_, err := rest.InClusterConfig()
	clusterMode := err == nil
	errOut := make(chan error, 100)
	go func() {
		for err := range errOut {
			log.Error().Err(err).Msg("watch failed:")
		}
	}()
	watcher := kubernetes.NewFromInCluster(errOut, tracer.updateTargets)
	ctx := context.Background()

	nodeName, err := kubernetes.GetThisNodeName(watcher)
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	go health.DumpHealthEvery10Seconds(nodeName)

	if clusterMode {
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
