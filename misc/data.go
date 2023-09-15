package misc

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const NameResolutionHistoryFilename string = "name_resolution_history.json"
const DefaultContext string = "master"
const PcapTTL time.Duration = 10 * time.Second
const MasterPcapSizeCheckPeriod time.Duration = 5 * time.Second
const NameResolutionDumpPeriod time.Duration = 3 * time.Second
const ClientHelloBasicPacket string = "48d343aac4b8f018982a38be0800450002390000400040063dddc0a8b20d58c62f66fa5401bb22afc03a4f66c79a80180814af8900000101080a571eb2fab5d8c2d71603010200010001fc03030c4c5a78621a9d1f687fda02e40b01897bc32fefdd8f66612360cb40f186e29f2075aae50aca7bd3d7db205ce25ddc409a902578c8b5b6b1eb1f1cbe19cc02a45a0034130113021303c02cc02bc024c023c00ac009cca9c030c02fc028c027c014c013cca8009d009c003d003c0035002fc008c012000a0100017fff010001000000001a00180000156463382e733234302e6d656574726963732e6e657400170000000d0018001604030804040105030203080508050501080606010201000500050100000000001200000010000e000c02683208687474702f312e31000b00020100003300260024001d00200bd78e1307f42e2e1ce25309a2191a31f8436c270476f7808171d787c7d2b25f002d00020101002b0009080304030303020301000a000a0008001d001700180019001500c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

var dataDir = "data"
var RunID int64

func InitDataDir() {
	body, err := os.ReadFile("/etc/machine-id")
	newDataDir := dataDir
	if err == nil {
		machineId := strings.TrimSpace(string(body))
		log.Info().Str("id", machineId).Msg("Machine ID is:")
		newDataDir = fmt.Sprintf("%s/%s", dataDir, machineId)
	}

	err = os.MkdirAll(newDataDir, os.ModePerm)
	if err != nil {
		log.Error().Err(err).Str("data-dir", newDataDir).Msg("Unable to create the new data directory:")
	} else {
		dataDir = newDataDir
		log.Info().Str("data-dir", dataDir).Msg("Set the data directory to:")
	}

	pcapsDir := GetPcapsDir()
	err = os.MkdirAll(pcapsDir, os.ModePerm)
	if err != nil {
		log.Error().Err(err).Str("pcaps-dir", pcapsDir).Msg("Unable to create the new pcaps directory:")
	}
}

func GetDataDir() string {
	return dataDir
}

func GetDataPath(path string) string {
	return fmt.Sprintf("%s/%s", GetDataDir(), path)
}

func RemoveDataDir(path string) string {
	return strings.TrimLeft(path, fmt.Sprintf("%s/", GetDataDir()))
}

func GetPcapsDir() string {
	return GetDataPath("pcaps")
}

func GetContextPath(context string) string {
	if context == "" {
		return GetPcapsDir()
	}
	return fmt.Sprintf("%s/%s", GetPcapsDir(), context)
}

func GetContextDataPath(context string) string {
	return fmt.Sprintf("%s/data", GetContextPath(context))
}

func GetPcapPath(filename string, context string) string {
	return fmt.Sprintf("%s/%s/%s", GetPcapsDir(), context, filename)
}

func GetMasterPcapPath() string {
	return fmt.Sprintf("%s/master.pcap", GetDataDir())
}

func BuildPcapFilename(id int64) string {
	return fmt.Sprintf("%012d.pcap", id)
}
