package misc

import (
	"io"
	"os"
	"path/filepath"
)

func GetProcCmdLine(pid string) (string, error) {
	file, err := os.Open(filepath.Join("/proc", pid, "cmdline"))
	if err != nil {
		return "", err
	}
	defer file.Close()

	buf := make([]byte, 128)
	_, err = file.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}

	return string(buf), nil
}
