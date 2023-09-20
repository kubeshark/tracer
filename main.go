package main

import (
	"flag"
	_ "net/http/pprof" // Blank import to pprof
	"os"
	"time"

	"github.com/kubeshark/tracer/misc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
)

// capture
var procfs = flag.String("procfs", "/proc", "The procfs directory, used when mapping host volumes into a container")

// development
var debug = flag.Bool("debug", false, "Enable debug mode")

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

	misc.RunID = time.Now().Unix()

	streamsMap := NewTcpStreamMap()

	tracer := createTracer(streamsMap)

	go tracer.PollForLogging()
	tracer.Poll(streamsMap)
}

func createTracer(streamsMap *TcpStreamMap) *Tracer {
	tls := Tracer{}
	chunksBufferSize := os.Getpagesize() * 100
	logBufferSize := os.Getpagesize()

	if err := tls.Init(
		chunksBufferSize,
		logBufferSize,
		*procfs,
	); err != nil {
		LogError(err)
		return nil
	}

	// FIXME: Pod list
	podList := []v1.Pod{}
	if err := UpdateTargets(&tls, &podList, *procfs); err != nil {
		LogError(err)
		return nil
	}

	// A quick way to instrument libssl.so without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID") != "" {
		if err := tls.GlobalSSLLibTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID")); err != nil {
			LogError(err)
			return nil
		}
	}

	// A quick way to instrument Go `crypto/tls` without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID") != "" {
		if err := tls.GlobalGoTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID")); err != nil {
			LogError(err)
			return nil
		}
	}

	return &tls
}
