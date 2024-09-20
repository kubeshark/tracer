package discoverer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func getMountPointByDeviceId(deviceId uint32) (string, error) {
	var err error
	var path string
	var ok bool

	path, ok = deviceMap[deviceId]
	if ok {
		if dirExists(path) {
			return path, nil
		}
	}

	if err = parseMountInfo(); err != nil {
		return "", err
	}

	path, ok = deviceMap[deviceId]
	if !ok {
		return "", fmt.Errorf("entry not found: %v", deviceId)
	}

	return path, nil
}

func dirExists(path string) bool {
	info, err := os.Stat(filepath.Join("/hostroot", path))
	return err == nil && info.IsDir()
}

var deviceMap = make(map[uint32]string)

func parseMountInfo() error {
	file, err := os.Open("/hostproc/1/mountinfo")
	if err != nil {
		return fmt.Errorf("failed to open /proc/self/mountinfo: %w", err)
	}
	defer file.Close()

	deviceMap = make(map[uint32]string)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Fields(line)

		if len(fields) < 5 {
			continue
		}

		devNumbers := strings.Split(fields[2], ":")
		if len(devNumbers) != 2 {
			continue
		}

		major, err := strconv.Atoi(devNumbers[0])
		if err != nil {
			continue
		}
		minor, err := strconv.Atoi(devNumbers[1])
		if err != nil {
			continue
		}

		deviceID := uint32((major << 8) | minor)

		mountPoint := fields[4]

		deviceMap[deviceID] = mountPoint
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading /proc/self/mountinfo: %w", err)
	}

	return nil
}
