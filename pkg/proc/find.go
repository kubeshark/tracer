package proc

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/go-errors/errors"
	"github.com/rs/zerolog/log"
)

// Finds the fullpath of a library from the /proc/pid/maps
func FindLibraryByPid(pid uint32, libraryName string) (string, error) {
	file, err := os.Open(fmt.Sprintf("%v/%v/maps", Path, pid))

	if err != nil {
		return "", err
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())

		if len(parts) <= 5 {
			continue
		}

		fpath := parts[5]

		if libraryName != "" && !strings.Contains(fpath, libraryName) {
			continue
		}

		fullpath := fmt.Sprintf("%v/%v/root%v", Path, pid, fpath)

		if _, err := os.Stat(fullpath); os.IsNotExist(err) {
			continue
		}

		return fullpath, nil
	}

	return "", errors.Errorf("%s not found for PID %d", libraryName, pid)
}

func FindSSLLib(pid uint32) (string, error) {
	binary, err := os.Readlink(fmt.Sprintf("%s/%d/exe", Path, pid))

	if err != nil {
		return "", errors.Wrap(err, 0)
	}

	log.Debug().Int("pid", int(pid)).Str("binary", binary).Msg("Binary that uses libssl:")

	if strings.HasSuffix(binary, "/node") {
		return FindLibraryByPid(pid, binary)
	}
	return FindLibraryByPid(pid, "libssl.so")
}
