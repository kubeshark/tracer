package main

import (
	"fmt"
	"net/url"
	"reflect"
	"regexp"

	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"

	"github.com/kubeshark/tracer/pkg/proc"
)

var numberRegex = regexp.MustCompile("[0-9]+")

func UpdateTargets(pods []v1.Pod) error {
	containerIds := buildContainerIdsMap(pods)
	log.Debug().Interface("container-ids", containerIds).Send()

	containerPids, err := proc.FindContainerPids(containerIds)
	if err != nil {
		return err
	}

	log.Info().Interface("pids", reflect.ValueOf(containerPids).MapKeys()).Send()

	tracer.ClearPids()

	// TODO: CAUSES INITIAL MEMORY SPIKE
	for pid := range containerPids {
		if err := tracer.AddSSLLibPid(tracer.procfs, pid); err != nil {
			LogError(err)
		}

		if err := tracer.AddGoPid(tracer.procfs, pid); err != nil {
			LogError(err)
		}
	}

	return nil
}

func buildContainerIdsMap(pods []v1.Pod) map[string]v1.Pod {
	result := make(map[string]v1.Pod)

	for _, pod := range pods {
		for _, container := range pod.Status.ContainerStatuses {
			parsedUrl, err := url.Parse(container.ContainerID)
			if err != nil {
				log.Warn().Msg(fmt.Sprintf("Expecting URL like container ID %v", container.ContainerID))
				continue
			}

			result[parsedUrl.Host] = pod
		}
	}

	return result
}
