package main

import (
	"flag"
	_ "net/http/pprof" // Blank import to pprof
	"os"
	"time"

	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/tracer"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

	streamsMap := tracer.NewTcpStreamMap()

	tracer := createTracer(streamsMap)

	go tracer.PollForLogging()
	tracer.Poll(streamsMap)
}
