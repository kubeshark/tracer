package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/kubeshark/api"
	"github.com/struCoder/pidusage"
)

func dumpHealthEvery10Seconds(nodeName string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				err := dumpHealth(nodeName)
				if err != nil {
					fmt.Printf("Error saving health: %v\n", err)
				}
			}
		}
	}()
}

// Tracer health data file is read by sniffer to construct the health object
// for both the sniffer and the tracer.
func dumpHealth(nodeName string) error {

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
