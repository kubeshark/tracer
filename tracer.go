package main

import (
	"os"

	"github.com/kubeshark/tracer/tracer"
	v1 "k8s.io/api/core/v1"
)

func createTracer(streamsMap *tracer.TcpStreamMap) *tracer.Tracer {
	tls := tracer.Tracer{}
	chunksBufferSize := os.Getpagesize() * 100
	logBufferSize := os.Getpagesize()

	if err := tls.Init(
		chunksBufferSize,
		logBufferSize,
		*procfs,
	); err != nil {
		tracer.LogError(err)
		return nil
	}

	// FIXME: Pod list
	podList := []v1.Pod{}
	if err := tracer.UpdateTargets(&tls, &podList, *procfs); err != nil {
		tracer.LogError(err)
		return nil
	}

	// A quick way to instrument libssl.so without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID") != "" {
		if err := tls.GlobalSSLLibTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID")); err != nil {
			tracer.LogError(err)
			return nil
		}
	}

	// A quick way to instrument Go `crypto/tls` without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID") != "" {
		if err := tls.GlobalGoTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID")); err != nil {
			tracer.LogError(err)
			return nil
		}
	}

	return &tls
}
