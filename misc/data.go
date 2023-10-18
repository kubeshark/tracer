package misc

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
)

var dataDir = "data"
var RunID int64

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

func GetMasterPcapPath() string {
	return fmt.Sprintf("%s/tls.pcap", GetDataDir())
}
