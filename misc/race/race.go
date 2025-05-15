package race

import (
	"fmt"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/nxadm/tail"
	"github.com/rs/zerolog/log"
)

const logSeparator string = "=================="

func WatchRaceLogs() {
	if !isRaceFlagEnabled() {
		return
	}

	t, err := tail.TailFile(
		findRaceLogFile(),
		tail.Config{
			Follow: true,
			ReOpen: true,
		},
	)
	if err != nil {
		log.Error().Err(err).Send()
	}

	var buffer []string

	for line := range t.Lines {
		if line.Text == logSeparator {
			msg := strings.Join(buffer, "\n")
			buffer = make([]string, 0)

			msg = strings.TrimPrefix(msg, logSeparator)
			msg = strings.TrimSuffix(msg, logSeparator)
			msg = strings.TrimSpace(msg)
			if msg != "" {
				log.Error().Str("type", "race").Msg(msg)
			}
		}

		buffer = append(buffer, line.Text)
	}
}

func findRaceLogFile() string {
	for {
		time.Sleep(1 * time.Second)

		matches, err := filepath.Glob("/tmp/kubeshark-race.log.*")
		if err != nil {
			log.Error().Err(err).Send()
			continue
		}

		if len(matches) > 0 {
			return matches[0]
		}
	}
}

func isRaceFlagEnabled() bool {
	b, ok := debug.ReadBuildInfo()
	if !ok {
		log.Error().Err(fmt.Errorf("could not read build info")).Send()
		return false
	}

	for _, s := range b.Settings {
		if s.Key == "-race" && s.Value == "true" {
			return true
		}
	}
	return false
}
