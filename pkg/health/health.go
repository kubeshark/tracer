package health

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/go-errors/errors"
	"github.com/kubeshark/api"
	"github.com/rs/zerolog/log"
	"github.com/struCoder/pidusage"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	utils "github.com/kubeshark/tracer/pkg/kubernetes"
)

const (
	tracerContainerName = "tracer"
)

var tracerHealth *api.HealthWorkerComponent

func DumpHealthEvery30Seconds(nodeName string) {
	log.Debug().Str("nodename", nodeName).Msg("Dumping health data every 10 seconds")

	if tracerHealth == nil {
		initTracerHealth()
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		err := dumpHealth(nodeName)
		if err != nil {
			log.Error().Err(err).Msg("Failed to dump health data")
		}
	}
}

// Tracer health data file is read by sniffer to construct the health object
// for both the sniffer and the tracer.
func dumpHealth(nodeName string) error {
	log.Debug().Str("nodename", nodeName).Msg("Dumping health data")

	memAlloc, memSys := getMemoryUsage()
	memUsage := float64(memAlloc) / float64(memSys) * 100

	cpuUsage := getCPUUsage()

	tracerHealth := &api.HealthWorkerComponent{
		CPUUsage:    cpuUsage,
		MemoryAlloc: memAlloc,
		MemoryUsage: memUsage,
	}

	tracerHealthData, err := json.Marshal(tracerHealth)
	if err != nil {
		return fmt.Errorf("error marshalling health data: %v", err)
	}

	tracerHealthFile := fmt.Sprintf("/app/data/%s/tracer-health.json", nodeName)

	err = os.WriteFile(tracerHealthFile, tracerHealthData, 0644)
	if err != nil {
		return fmt.Errorf("error dumping health data: %v", err)
	}

	return nil
}

func initTracerHealth() {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Warn().Err(err).Send()
	}

	var clientSet *kubernetes.Clientset
	if config != nil {
		clientSet, err = kubernetes.NewForConfig(config)
		if err != nil {
			log.Warn().Err(err).Send()
		}
	}

	if clientSet == nil {
		log.Error().Msg("Failed to create clientSet")
		return
	}

	var tracerResources v1.ResourceRequirements
	var tracerRestarts int
	var tracerLastRestartReason string

	currentPod, err := getCurrentPod(clientSet)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get current pod")
	} else if currentPod != nil {
		for _, container := range currentPod.Spec.Containers {
			if container.Name == tracerContainerName {
				tracerResources = container.Resources
			}
		}
		for _, containerStatus := range currentPod.Status.ContainerStatuses {
			if containerStatus.Name == tracerContainerName {
				tracerRestarts = int(containerStatus.RestartCount)
				if containerStatus.LastTerminationState.Terminated != nil {
					tracerLastRestartReason = containerStatus.LastTerminationState.Terminated.Reason
				}
			}
		}
	}

	tracerHealth = &api.HealthWorkerComponent{
		Resources:         tracerResources,
		Restarts:          tracerRestarts,
		LastRestartReason: tracerLastRestartReason,
	}
}

func getCPUUsage() float64 {
	sysInfo, err := pidusage.GetStat(os.Getpid())
	if err != nil {
		sysInfo = &pidusage.SysInfo{
			CPU:    -1,
			Memory: -1,
		}
	}

	return sysInfo.CPU
}

func getMemoryUsage() (uint64, uint64) {
	var stat runtime.MemStats
	runtime.ReadMemStats(&stat)
	return stat.Alloc, stat.Sys
}

func getCurrentPod(clientSet *kubernetes.Clientset) (*v1.Pod, error) {
	podName := utils.GetSelfPodName()
	namespace := utils.GetSelfNamespace()

	if podName == "" || namespace == "" {
		return nil, errors.New("POD_NAME or POD_NAMESPACE env vars are not set")
	}

	return clientSet.CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
}
