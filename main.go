package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	_ "net/http/pprof" // Blank import to pprof
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/kubernetes"
	"github.com/kubeshark/tracer/pkg/resolver"
	"github.com/kubeshark/tracer/pkg/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"

	stdlog "log"
	runtimeDebug "runtime/debug"

	"github.com/getsentry/sentry-go"
	sentryzerolog "github.com/getsentry/sentry-go/zerolog"
	"github.com/kubeshark/tracer/pkg/version"
	"github.com/kubeshark/tracer/server"
	sentrypkg "github.com/kubeshark/utils/sentry"

	"github.com/kubeshark/tracer/pkg/bpf"
)

var port = flag.Int("port", 80, "Port number of the HTTP server")
var procfs = flag.String("procfs", "/proc", "The procfs directory, used when mapping host volumes into a container")
var logLevel = flag.String("loglevel", "warning", "The minimum log level to output. Possible values: debug, info, warning")
var disableTlsLog = flag.Bool("disable-tls-log", false, "Disable tls logging")
var preferCgroupV1Capture = flag.Bool("ebpf1", false, "On systems with Cgroup V2 use Cgroup V1 method for packet capturing")

var initBPFDEPRECATED = flag.Bool("init-bpf", false, "Use to initialize bpf filesystem. Common usage is from init containers. DEPRECATED")
var disableEbpfCaptureDEPRECATED = flag.Bool("disable-ebpf", false, "Disable capture packet via eBPF. DEPRECATED")

var tracer *Tracer

func main() {
	flag.Parse()

	// Set log level
	var level zerolog.Level
	switch strings.ToLower(*logLevel) {
	case "debug":
		level = zerolog.DebugLevel
	case "info":
		level = zerolog.InfoLevel
	case "warning":
		level = zerolog.WarnLevel
	default:
		level = zerolog.WarnLevel
		log.Warn().Msgf("Invalid log level '%s'. Defaulting to 'warning'.", *logLevel)
	}
	zerolog.SetGlobalLevel(level)

	if *initBPFDEPRECATED {
		log.Warn().Msg("-init-bpf option is deprecated")
	}
	if *disableEbpfCaptureDEPRECATED {
		log.Warn().Msg("disable-ebpf option is deprecated")
	}

	if sentrypkg.IsSentryEnabled() {
		sentryDSN, err := sentrypkg.GetDSN(context.Background(), "tracer", version.Ver)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get Sentry DSN")
		}

		// To initialize Sentry's handler, you need to initialize Sentry itself beforehand
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:           sentryDSN,
			EnableTracing: true,
			// Set TracesSampleRate to 1.0 to capture 100%
			// of transactions for tracing.
			// We recommend adjusting this value in production,
			TracesSampleRate: 1.0,
			Release:          version.Ver,
			Environment:      sentrypkg.Environment(),
		}); err != nil {
			log.Error().Err(err).Msg("Sentry initialization failed:")
		} else {
			defer sentry.Flush(2 * time.Second)
		}
	}

	w, err := sentryzerolog.NewWithHub(sentry.CurrentHub(), sentryzerolog.Options{})
	if err != nil {
		stdlog.Fatal(err)
	}
	defer w.Close()

	kubernetes.SentryWriter = sentrypkg.NewWriter(w, zerolog.ErrorLevel)

	multi := zerolog.MultiLevelWriter(kubernetes.SentryWriter,
		zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
	)
	log.Logger = zerolog.New(multi).
		With().
		Timestamp().
		Caller().
		Logger()

	runtimeDebug.SetPanicOnFault(true)
	defer func() {
		if err := recover(); err != nil {
			stackTrace := string(runtimeDebug.Stack())

			for _, line := range strings.Split(stackTrace, "\n") {
				log.Error().Msg(line)
			}
			log.Fatal().Err(fmt.Errorf("panic: %v", err)).Send()
		}
	}()

	run()
}

func run() {
	log.Info().Msg("Starting tracer...")

	isCgroupsV2, err := utils.IsCgroupV2()
	if err != nil {
		log.Error().Err(err).Msg("detect cgroup version failed")
		return
	}

	tcpMap, err := resolver.GatherPidsTCPMap(*procfs, isCgroupsV2)
	if err != nil {
		log.Error().Err(err).Msg("tcp map lookup failed")
		return
	}

	tracer = &Tracer{
		procfs:            *procfs,
		targetedCgroupIDs: map[uint64]struct{}{},
		runningPods:       make(map[types.UID]podInfo),
		tcpMap:            tcpMap,
	}

	_, err = rest.InClusterConfig()
	clusterMode := err == nil
	errOut := make(chan error, 100)
	go func() {
		for err := range errOut {
			if err != nil {
				log.Warn().Err(err).Msg("watch failed:")
			}
		}
	}()
	watcher := kubernetes.NewFromInCluster(errOut, tracer.updateTargets)
	ctx := context.Background()

	nodeName, err := kubernetes.GetThisNodeName(watcher)
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	enrichSentryContext(watcher)

	if clusterMode {
		misc.SetDataDir(fmt.Sprintf("/app/data/%s", nodeName))
	}
	misc.InitDataDir()

	err = createTracer(isCgroupsV2)
	if err != nil {
		log.Error().Err(err).Msg("Couldn't initialize the tracer. To disable tracer permanently, pass 'tap.tls=false' in command line")
		// Stop here to prevent pod respawning
		select {}
	}
	watcher.Start(ctx, clusterMode)

	if server.GetProfilingEnabled() {
		log.Info().Msg("Profiling enabled")
		ginApp := server.Build()
		server.Start(ginApp, *port)
	} else {
		stopChan := make(chan os.Signal, 1)
		signal.Notify(stopChan,
			syscall.SIGHUP,
			syscall.SIGINT,
			syscall.SIGTERM,
			syscall.SIGQUIT)
		go signalHandler(stopChan)
		select {}
	}
}

func stop() {
	if tracer != nil {
		if err := tracer.Deinit(); err != nil {
			log.Error().Err(err).Msg("Tracer stop failed")
		}
	}
}

func createTracer(isCgroupsV2 bool) (err error) {
	chunksBufferSize := os.Getpagesize() * 10000
	logBufferSize := os.Getpagesize()

	if err = tracer.Init(
		chunksBufferSize,
		logBufferSize,
		*procfs,
		isCgroupsV2,
	); err != nil {
		log.Error().Err(err).Msg("Initialize tracer failed.")
		if errors.Is(err, bpf.ErrBpfMountFailed) {
			log.Info().Msg("\n\nBPF filesystem is not mounted on /sys/bs/bpf.\nRun `mount -t bpf bpf /sys/fs/bpf` on the host\nOr pass 'tap.mountBpf=true' parameter in command line to mount bpf filesytem in privileged init container.\n")
		}
		if errors.Is(err, bpf.ErrBpfOperationFailed) {
			log.Info().Msg("In case of permission issue, security profiles can be aligned accordingly.")
		}
		log.Info().Msg("To disable tracer permanently, pass 'tap.tls=false' in command line.")
		// Stop here to prevent pod respawning
		select {}
	}
	go tracer.collectStats()

	return
}

func enrichSentryContext(watcher *kubernetes.Watcher) {
	clusterId, err := kubernetes.GetClusterID(watcher)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get cluster ID for Sentry tag")
	}

	tags := map[string]string{
		"clusterID": clusterId,
	}

	sentrypkg.AddTags(tags)
}

func signalHandler(stopChan chan os.Signal) {
	for {
		s := <-stopChan
		switch s {
		case syscall.SIGHUP:
			fallthrough
		case syscall.SIGINT:
			fallthrough
		case syscall.SIGTERM:
			fallthrough
		case syscall.SIGQUIT:
			stop()
			os.Exit(0)
		default:
		}
	}
}
