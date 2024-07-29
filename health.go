package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/kubeshark/api"
	"github.com/rs/zerolog/log"
	"github.com/struCoder/pidusage"
)

func dumpHealthEvery10Seconds(nodeName string) {
	log.Debug().Str("nodename", nodeName).Msg("Dumping health data every 10 seconds")
	ticker := time.NewTicker(10 * time.Second)
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
		return fmt.Errorf("Error marshalling health data: %v", err)
	}

	tracerHealthFile := fmt.Sprintf("/app/data/%s/tracer-health.json", nodeName)

	err = os.WriteFile(tracerHealthFile, tracerHealthData, 0644)
	if err != nil {
		return fmt.Errorf("Error dumping health data: %v", err)
	}

	return nil
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
