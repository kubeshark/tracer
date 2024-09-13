package misc

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
)

var dataDir = "data"

func InitDataDir() {
	err := os.MkdirAll(dataDir, os.ModePerm)
	if err != nil {
		log.Error().Err(err).Str("data-dir", dataDir).Msg("Unable to create the new data directory:")
	} else {
		log.Info().Str("data-dir", dataDir).Msg("Set the data directory to:")
	}
}

func GetDataDir() string {
	return dataDir
}

func SetDataDir(v string) {
	dataDir = v
}

func GetTLSSocketPath() string {
	return fmt.Sprintf("%s/tls.unix", GetDataDir())
}

func GetPlainSocketPath() string {
	return fmt.Sprintf("%s/plain.unix", GetDataDir())
}

func GetEventSocketPath() string {
	return fmt.Sprintf("%s/event.unix", GetDataDir())
}

func GetSyscallEventSocketPath() string {
	return fmt.Sprintf("%s/syscall_event.unix", GetDataDir())
}
