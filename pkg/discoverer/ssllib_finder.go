package discoverer

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/go-errors/errors"
)

func findLibraryByPid(procfs string, pid uint32, libraryName string) (string, error) {
	file, err := os.Open(fmt.Sprintf("%v/%v/maps", procfs, pid))

	if err != nil {
		return "", err
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())

		if len(parts) < 6 {
			continue
		}

		fpath := parts[5]

		if libraryName != "" {
			found := strings.Contains(fpath, libraryName)

			if !found {
				continue
			}
		}

		fullpath := fmt.Sprintf("%v/%v/root%v", procfs, pid, fpath)

		if _, err := os.Stat(fullpath); os.IsNotExist(err) {
			continue
		}

		return fullpath, nil
	}

	return "", errors.Errorf("%s not found for PID %d", libraryName, pid)
}
