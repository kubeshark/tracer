package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/go-errors/errors"
	"github.com/kubeshark/ebpf/perf"
	"github.com/rs/zerolog/log"
)

const logPrefix = "[bpf] "

// The same consts defined in log.h
const (
	logLevelError = 0
	logLevelInfo  = 1
	logLevelDebug = 2
)

type logMessage struct {
	Level       uint32
	MessageCode uint32
	Arg1        uint64
	Arg2        uint64
	Arg3        uint64
}

type bpfLogger struct {
	logReader *perf.Reader
}

func newBpfLogger(bpfObjects *tracerObjects, bufferSize int) (p *bpfLogger, err error) {
	p = &bpfLogger{}

	p.logReader, err = perf.NewReader(bpfObjects.LogBuffer, bufferSize)

	if err != nil {
		err = errors.Wrap(err, 0)
		return
	}

	return
}

func (p *bpfLogger) close() error {
	return p.logReader.Close()
}

func (p *bpfLogger) poll() {
	log.Info().Msg("Start polling for bpf logs")

	for {
		record, err := p.logReader.Read()

		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			logError(errors.Errorf("Error reading from bpf logger perf buffer, aboring logger! %w", err))
			return
		}

		if record.LostSamples != 0 {
			log.Info().Msg(fmt.Sprintf("Log buffer is full, dropped %d logs", record.LostSamples))
			continue
		}

		buffer := bytes.NewReader(record.RawSample)

		var log logMessage

		if err := binary.Read(buffer, binary.LittleEndian, &log); err != nil {
			logError(errors.Errorf("Error parsing log %v", err))
			continue
		}

		p.log(&log)
	}
}

func (p *bpfLogger) log(msg *logMessage) {
	if int(msg.MessageCode) >= len(bpfLogMessages) {
		log.Info().Msg(fmt.Sprintf("Unknown message code from bpf logger %d", msg.MessageCode))
		return
	}

	format := bpfLogMessages[msg.MessageCode]
	tokensCount := strings.Count(format, "%")

	if tokensCount == 0 {
		p.logLevel(msg.Level, format)
	} else if tokensCount == 1 {
		p.logLevel(msg.Level, format, msg.Arg1)
	} else if tokensCount == 2 {
		p.logLevel(msg.Level, format, msg.Arg1, msg.Arg2)
	} else if tokensCount == 3 {
		p.logLevel(msg.Level, format, msg.Arg1, msg.Arg2, msg.Arg3)
	}
}

func (p *bpfLogger) logLevel(level uint32, format string, args ...interface{}) {
	if level == logLevelError {
		log.Error().Msg(fmt.Sprintf(logPrefix+format, args...))
	} else if level == logLevelInfo {
		log.Info().Msg(fmt.Sprintf(logPrefix+format, args...))
	} else if level == logLevelDebug {
		log.Debug().Msg(fmt.Sprintf(logPrefix+format, args...))
	}
}
