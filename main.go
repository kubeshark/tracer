package main

import (
	"context"
	"flag"
	"fmt"
	_ "net/http/pprof" // Blank import to pprof
	"os"
	"regexp"
	"time"

	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/kubernetes"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"k8s.io/client-go/rest"
)

// capture
var procfs = flag.String("procfs", "/proc", "The procfs directory, used when mapping host volumes into a container")

var tracer *Tracer

func main() {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" || os.Getenv("KUBERNETES_SERVICE_PORT") == "" {
		mainHost()
	} else {
		mainK8S()
	}
}

func mainK8S() {
	// development
	var debug = flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Caller().Logger()

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	misc.InitDataDir()

	runK8S()
}

func mainHost() {
	var err error
	var cmdLine = flag.String("cmdline", "", "binary command line to handle")
	var pcapFile = flag.String("pcap", "", "pcap file save into")
	// development
	var debug = flag.Bool("debug", false, "Enable debug mode")

	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Caller().Logger()

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	misc.InitDataDir()

	var cmdLineRegex *regexp.Regexp
	if *cmdLine != "" {
		if cmdLineRegex, err = regexp.Compile(fmt.Sprintf(".*%v.*", *cmdLine)); err != nil {
			log.Error().Err(err).Send()
			return
		}
	}
	runHost(cmdLineRegex, *pcapFile)
}

func runK8S() {
	log.Info().Msg("Starting tracer...")

	misc.RunID = time.Now().Unix()

	streamsMap := NewTcpStreamMap()

	createTracer(streamsMap)

	_, err := rest.InClusterConfig()
	clusterMode := err == nil
	errOut := make(chan error, 100)
	watcher := kubernetes.NewFromInCluster(errOut, UpdateTargets)
	ctx := context.Background()
	watcher.Start(ctx, clusterMode)

	go tracer.PollForLogging()
	tracer.Poll(streamsMap)
}

func runHost(cmdLineRegex *regexp.Regexp, pcapFile string) {
	log.Info().Msg("Starting tracer...")

	misc.RunID = time.Now().Unix()

	streamsMap := NewTcpStreamMap()

	NewPacketConsumer(pcapFile)

	createTracerHost(streamsMap, cmdLineRegex)

	go func() {}()
	tracer.Poll(streamsMap)
}

func createTracer(streamsMap *TcpStreamMap) {
	tracer = &Tracer{
		procfs: *procfs,
	}
	chunksBufferSize := os.Getpagesize() * 100
	logBufferSize := os.Getpagesize()

	if err := tracer.Init(
		chunksBufferSize,
		logBufferSize,
		*procfs,
	); err != nil {
		LogError(err)
		return
	}

	podList := kubernetes.GetTargetedPods()
	if err := UpdateTargets(podList); err != nil {
		log.Error().Err(err).Send()
		return
	}

	// A quick way to instrument libssl.so without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID") != "" {
		if err := tracer.GlobalSSLLibTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID")); err != nil {
			LogError(err)
			return
		}
	}

	// A quick way to instrument Go `crypto/tls` without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID") != "" {
		if err := tracer.GlobalGoTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID")); err != nil {
			LogError(err)
			return
		}
	}
}

func createTracerHost(streamsMap *TcpStreamMap, cmdLineRegex *regexp.Regexp) {
	tracer = &Tracer{
		procfs: *procfs,
	}
	chunksBufferSize := os.Getpagesize() * 100
	logBufferSize := os.Getpagesize()

	if err := tracer.Init(
		chunksBufferSize,
		logBufferSize,
		*procfs,
	); err != nil {
		LogError(err)
		return
	}

	if err := UpdateTargetsHost(cmdLineRegex); err != nil {
		log.Error().Err(err).Send()
		return
	}

	// A quick way to instrument libssl.so without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID") != "" {
		if err := tracer.GlobalSSLLibTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID")); err != nil {
			LogError(err)
			return
		}
	}

	// A quick way to instrument Go `crypto/tls` without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID") != "" {
		if err := tracer.GlobalGoTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID")); err != nil {
			LogError(err)
			return
		}
	}
}
