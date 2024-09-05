package main

import (
	"context"
	"flag"
	"fmt"
	stdlog "log"
	_ "net/http/pprof" // Blank import to pprof
	"os"
	runtimeDebug "runtime/debug"
	"strings"
	"time"

	zlogsentry "github.com/archdx/zerolog-sentry"
	"github.com/getsentry/sentry-go"
	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/kubernetes"
	"github.com/kubeshark/tracer/pkg/version"
	"github.com/kubeshark/tracer/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"

	"github.com/kubeshark/tracer/pkg/health"
)

const (
	globCbufMax = 10_000
)

var port = flag.Int("port", 80, "Port number of the HTTP server")

// capture
var procfs = flag.String("procfs", "/proc", "The procfs directory, used when mapping host volumes into a container")

// development
var debug = flag.Bool("debug", false, "Enable debug mode")
var globCbuf = flag.Int("cbuf", 0, fmt.Sprintf("Keep last N packets in circular buffer 0 means disabled, max value is %v", globCbufMax))

var disableEbpfCapture = flag.Bool("disable-ebpf", false, "Disable capture packet via eBPF")
var enableSyscallEvents = flag.Bool("enable-syscall", false, "Enable syscall events processing")
var disableTlsLog = flag.Bool("disable-tls-log", false, "Disable tls logging")

const sentryDsn = "https://c0b7399e76173c4601a82aab28eb4be8@o4507855877505024.ingest.us.sentry.io/4507886789263360"

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
	// To initialize Sentry's handler, you need to initialize Sentry itself beforehand
	if err := sentry.Init(sentry.ClientOptions{
		Dsn:           sentryDsn,
		EnableTracing: true,
		// Set TracesSampleRate to 1.0 to capture 100%
		// of transactions for tracing.
		// We recommend adjusting this value in production,
		TracesSampleRate: 1.0,
		Release:          version.Ver,
	}); err != nil {
		log.Warn().Err(err).Msg("Sentry initialization failed:")
	} else {
		defer sentry.Flush(2 * time.Second)
	}

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	w, err := zlogsentry.New(
		sentryDsn,
	)
	if err != nil {
		stdlog.Fatal(err)
	}

	defer w.Close()

	multi := zerolog.MultiLevelWriter(w, zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	log.Logger = zerolog.New(multi).With().Timestamp().Caller().Logger()

	flag.Var(&sslLibsGlobal, "ssl-libname", "Custom libssl library name")
	flag.Parse()

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	runtimeDebug.SetPanicOnFault(true)
	defer func() {
		if err := recover(); err != nil {
			log.Fatal().Err(fmt.Errorf("panic: %v", err)).Send()
		}
	}()

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
			log.Warn().Err(err).Msg("watch failed:")
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

	if server.GetProfilingEnabled() {
		go tracer.poll(streamsMap)
		log.Info().Msg("Profiling enabled")
		ginApp := server.Build()
		server.Start(ginApp, *port)
	} else {
		tracer.poll(streamsMap)
	}
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
