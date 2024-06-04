package main

import (
	"bufio"
	"context"
	"fmt"

	"encoding/json"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers" //nolint
	_ "github.com/aquasecurity/tracee"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize" //nolint - depend on generated code
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/ebpf"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"

	"github.com/aquasecurity/tracee/pkg/version"

	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/socket"

	"github.com/go-errors/errors"
	"github.com/rs/zerolog/log"
)

const traceeLogFile = "/app/data/tracee.log"

type systemEventsTracer struct {
	tracee        *ebpf.Tracee
	eventSocket   *socket.SocketEvent
	checkCgroupID func(uint64) bool
}

func processTraceLog() {
	file, err := os.Open(traceeLogFile)
	if err != nil {
		log.Error().Err(err).Msg(fmt.Sprintf("open tracee log file failed: %v", traceeLogFile))
		return
	}
	defer file.Close()
	log.Info().Msg(fmt.Sprintf("opened tracee log file: %v", traceeLogFile))

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		log.Info().Msg(fmt.Sprintf("tracee log: %v", line))
	}
}

func newSystemEventsTracer(checkCgroupID func(uint64) bool) (*systemEventsTracer, error) {
	log.Info().Msg("tracee init started")

	os.Remove(traceeLogFile)
	err := syscall.Mkfifo(traceeLogFile, 0666)
	if err != nil {
		return nil, errors.WrapPrefix(err, "make traceee pipe", 0)
	}
	go processTraceLog()
	logFlags := []string{"info", fmt.Sprintf("file:%v", traceeLogFile)}
	logCfg, err := flags.PrepareLogger(logFlags, true)
	if err != nil {
		return nil, errors.WrapPrefix(err, "tracee logger", 0)
	}
	logger.Init(logCfg)
	initialize.SetLibbpfgoCallbacks()

	regoFlags := []string{"aio"}
	rego, err := flags.PrepareRego(regoFlags)
	if err != nil {
		return nil, errors.WrapPrefix(err, "rego config", 0)
	}

	sigs, dataSources, err := signature.Find(
		rego.RuntimeTarget,
		rego.PartialEval,
		[]string{},
		nil,
		rego.AIO,
	)
	if err != nil {
		return nil, errors.WrapPrefix(err, "rego signature", 0)
	}

	sigNameToEventId := initialize.CreateEventsFromSignatures(events.StartSignatureID, sigs)

	cfg := config.Config{
		PerfBufferSize:     2 * 1024,
		BlobPerfBufferSize: 2 * 1024,
		NoContainersEnrich: true,
	}

	osInfo, err := helpers.GetOSInfo()
	if err != nil {
		return nil, errors.WrapPrefix(err, "osinfo failed", 0)
	} else {
		osInfoSlice := make([]interface{}, 0)
		for k, v := range osInfo.GetOSReleaseAllFieldValues() {
			osInfoSlice = append(osInfoSlice, k.String(), v)
		}
		logger.Debugw("OSInfo", osInfoSlice...)
	}
	cfg.OSInfo = osInfo

	cacheFlags := []string{"none"}
	cache, err := flags.PrepareCache(cacheFlags)
	if err != nil {
		return nil, errors.WrapPrefix(err, "prepare cache", 0)
	}
	cfg.Cache = cache

	procTreeFlags := []string{"none"}
	procTree, err := flags.PrepareProcTree(procTreeFlags)
	if err != nil {
		return nil, errors.WrapPrefix(err, "proc tree", 0)
	}
	cfg.ProcTree = procTree

	dnsCacheFlags := []string{"none"}
	dnsCache, err := flags.PrepareDnsCache(dnsCacheFlags)
	if err != nil {
		return nil, errors.WrapPrefix(err, "dns cache", 0)
	}
	cfg.DNSCacheConfig = dnsCache

	captureFlags := []string{}
	capture, err := flags.PrepareCapture(captureFlags, true)
	if err != nil {
		return nil, errors.WrapPrefix(err, "prepare capture", 0)
	}
	cfg.Capture = &capture

	capFlags := []string{"bypass=true"}
	capsCfg, err := flags.PrepareCapabilities(capFlags)
	if err != nil {
		return nil, errors.WrapPrefix(err, "prepare capabilities", 0)
	}
	cfg.Capabilities = &capsCfg

	scopeFlags := []string{}
	/*
		Here are list of events which are not activated
		but potentially can be used by tracer:
			"security_socket_create",
			"net_tcp_connect",
			"net_flow_tcp_begin",
			"net_flow_tcp_end",
			"security_socket_listen",
			"security_socket_accept",
			"security_socket_bind",
			"security_socket_connect",
			"net_packet_http",
			"net_packet_http_request",
			"net_packet_http_response",
			"bind",
	*/
	// actual events received tracer get subsribed:
	eventFlags := []string{
		"sched_process_exec",
		"sched_process_exit",
		"accept",
		"accept4",
		"connect",
	}

	policyScopeMap, err := flags.PrepareScopeMapFromFlags(scopeFlags)
	if err != nil {
		return nil, errors.WrapPrefix(err, "prepare scope", 0)
	}

	policyEventsMap, err := flags.PrepareEventMapFromFlags(eventFlags)
	if err != nil {
		return nil, errors.WrapPrefix(err, "prepare event map", 0)
	}

	p, err := flags.CreatePolicies(policyScopeMap, policyEventsMap, true)
	if err != nil {
		return nil, errors.WrapPrefix(err, "create policy", 0)
	}
	cfg.Policies = p
	policy.Snapshots().Store(cfg.Policies)

	outputFlags := []string{"table"}
	output, err := flags.PrepareOutput(outputFlags, true)
	if err != nil {
		return nil, errors.WrapPrefix(err, "prepare output flags", 0)
	}
	cfg.Output = output.TraceeConfig

	lockdown, err := helpers.Lockdown()
	if err != nil {
		logger.Debugw("OSInfo", "lockdown", err)
	}
	if err == nil && lockdown == helpers.CONFIDENTIALITY {
		return nil, errors.WrapPrefix(err, "lock down", 0)
	}

	enabled, err := helpers.FtraceEnabled()
	if err != nil {
		return nil, errors.WrapPrefix(err, "ftrace enabling", 0)
	}
	if !enabled {
		logger.Errorw("ftrace_enabled: ftrace is not enabled, kernel events won't be caught, make sure to enable it by executing echo 1 | sudo tee /proc/sys/kernel/ftrace_enabled")
	}

	kernelConfig, err := initialize.KernelConfig()
	if err != nil {
		return nil, errors.WrapPrefix(err, "kernel config", 0)
	}

	traceeInstallPath := "/tmp/tracee"
	err = initialize.BpfObject(&cfg, kernelConfig, osInfo, traceeInstallPath, version.GetVersion())
	if err != nil {
		return nil, errors.WrapPrefix(err, "bpf object", 0)
	}

	cfg.Output.ParseArguments = true
	cfg.EngineConfig = engine.Config{
		Enabled:          true,
		SigNameToEventID: sigNameToEventId,
		Signatures:       sigs,
		// This used to be a flag, we have removed the flag from this binary to test
		// if users do use it or not.
		SignatureBufferSize: 1000,
		DataSources:         dataSources,
	}

	t, err := tracee.New(cfg)
	if err != nil {
		return nil, errors.WrapPrefix(err, "tracee new", 0)
	}

	log.Info().Msg("tracee init completed")

	return &systemEventsTracer{
		tracee:        t,
		eventSocket:   socket.NewSocketEvent(misc.GetEventSocketPath()),
		checkCgroupID: checkCgroupID,
	}, nil
}

func (t *systemEventsTracer) start() (err error) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	err = t.tracee.Init(ctx)
	if err != nil {
		return errors.WrapPrefix(err, "tracee init", 0)
	}

	stream := t.tracee.SubscribeAll()

	go func() {
		log.Info().Msg("event reading started")
		for {
			select {
			case event := <-stream.ReceiveEvents():
				if !t.checkCgroupID(uint64(event.CgroupID)) {
					continue
				}

				var blocked bool

				if event.EventID == 42 { //connect
					for _, arg := range event.Args {
						if arg.Name == "addr" && arg.Type == "struct sockaddr*" {
							value, ok := arg.Value.(map[string]string)
							if ok {
								if value["sa_family"] != "AF_INET" {
									blocked = true
								}
							}
						}
					}
				}

				if event.EventID == 714 || event.EventID == 715 { //connect
					if event.HostProcessID != event.HostThreadID {
						blocked = true
					}
				}

				if blocked {
					continue
				}

				prettyJSON, err := json.MarshalIndent(event, "", "    ")
				if err != nil {
					log.Error().Err(err).Msg("Marshal failed:")
					continue
				}
				log.Debug().Str("event", string(prettyJSON)).Msg("event received")

				if err := t.eventSocket.WriteObject(event); err != nil {
					log.Error().Err(err).Msg("Write object failed")
				}
			case <-ctx.Done():
				log.Info().Msg("event reading stopped")
				return
			}
		}
	}()

	go func() {
		defer stop()
		defer t.tracee.Unsubscribe(stream)
		err = t.tracee.Run(ctx)
		if err != nil {
			log.Error().Err(err).Msg("tracee start failed")
			return
		}
		log.Info().Msg("tracee stopped")
	}()

	return
}
