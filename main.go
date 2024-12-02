package main

import (
	"context"
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
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"

	stdlog "log"
	runtimeDebug "runtime/debug"

	zlogsentry "github.com/archdx/zerolog-sentry"
	"github.com/getsentry/sentry-go"
	"github.com/kubeshark/tracer/pkg/version"
	"github.com/kubeshark/tracer/server"
	sentrypkg "github.com/kubeshark/utils/sentry"

	"github.com/moby/sys/mount"
	"github.com/moby/sys/mountinfo"
)

var port = flag.Int("port", 80, "Port number of the HTTP server")

// capture
var procfs = flag.String("procfs", "/proc", "The procfs directory, used when mapping host volumes into a container")

// development
var debug = flag.Bool("debug", false, "Enable debug mode")

var disableEbpfCapture = flag.Bool("disable-ebpf", false, "Disable capture packet via eBPF")
var disableTlsLog = flag.Bool("disable-tls-log", false, "Disable tls logging")

var tracer *Tracer

func main() {
	var sentryDSN string
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

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	w, err := zlogsentry.New(
		sentryDSN,
	)
	if err != nil {
		stdlog.Fatal(err)
	}

	defer w.Close()

	multi := zerolog.MultiLevelWriter(w, zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	log.Logger = zerolog.New(multi).With().Timestamp().Caller().Logger()

	flag.Parse()
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Caller().Logger()

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

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

	if err := checkMountedTracerInfo(); err != nil {
		log.Error().Msg("bpffs or debugfs is not available. Tracer is disabled")
		select {}
	}

	tracer = &Tracer{
		procfs:            *procfs,
		targetedCgroupIDs: map[uint64]struct{}{},
		runningPods:       make(map[types.UID]podInfo),
	}

	_, err := rest.InClusterConfig()
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

	err = createTracer()
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't initialize the tracer:")
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

const bpfMountPath = "/sys/fs/bpf"
const debugMountPath = "/sys/kernel/debug"

func checkMountedTracerInfo() error {
	var mounted bool
	var err error
	if mounted, err = mountinfo.Mounted(bpfMountPath); err != nil {
		log.Error().Err(err).Msg("Unable to get mountinfo")
		return err
	}
	if !mounted {
		if err = mount.Mount("bpf", bpfMountPath, "bpf", ""); err != nil {
			log.Error().Err(err).Msg("Unable to mount bpf filesystem")
			return err
		}
		log.Print("bpf filesystem has been mounted")
	}

	if mounted, err = mountinfo.Mounted(debugMountPath); err != nil {
		log.Error().Err(err).Msg("Unable to get mountinfo for debugfs")
		return err
	}
	if !mounted {
		if err = mount.Mount("debugfs", debugMountPath, "debugfs", ""); err != nil {
			log.Error().Err(err).Msg("Unable to mount debugfs filesystem")
			return err
		}
	}

	return nil
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
