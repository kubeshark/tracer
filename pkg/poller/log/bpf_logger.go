package log

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/perf"
	"github.com/go-errors/errors"
	"github.com/kubeshark/tracer/pkg/bpf"
	"github.com/kubeshark/tracer/pkg/utils"
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

type BpfLogger struct {
	logDisabled bool
	logReader   *perf.Reader
}

func NewBpfLogger(bpfObjects *bpf.TracerObjects, logDisabled bool) (p *BpfLogger, err error) {
	p = &BpfLogger{
		logDisabled: logDisabled,
	}

	p.logReader, err = perf.NewReader(bpfObjects.LogBuffer, os.Getpagesize())
	if err != nil {
		err = errors.Wrap(err, 0)
		return p, err
	}

	return p, err
}

func (p *BpfLogger) Stop() error {
	return p.logReader.Close()
}

func (p *BpfLogger) Start() {
	go p.poll()
}

func (p *BpfLogger) poll() {
	log.Info().Msg("Start polling for bpf logs")

	for {
		record, err := p.logReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			utils.LogError(errors.Errorf("Error reading from bpf logger perf buffer, aboring logger! %w", err))
			return
		}

		if p.logDisabled {
			continue
		}

		if record.LostSamples != 0 {
			log.Warn().Msg(fmt.Sprintf("Log buffer is full, dropped %d logs", record.LostSamples))
			continue
		}

		buffer := bytes.NewReader(record.RawSample)

		var log logMessage

		if err := binary.Read(buffer, binary.LittleEndian, &log); err != nil {
			utils.LogError(errors.Errorf("Error parsing log %v", err))
			continue
		}

		p.log(&log)
	}
}

func (p *BpfLogger) log(msg *logMessage) {
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

func (p *BpfLogger) logLevel(level uint32, format string, args ...interface{}) {
	if level == logLevelError {
		log.Warn().Msg(fmt.Sprintf(logPrefix+format, args...))
	} else if level == logLevelInfo {
		log.Info().Msg(fmt.Sprintf(logPrefix+format, args...))
	} else if level == logLevelDebug {
		log.Debug().Msg(fmt.Sprintf(logPrefix+format, args...))
	}
}
