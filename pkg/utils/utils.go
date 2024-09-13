package utils

import (
	"github.com/go-errors/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
	"syscall"
)

func LogError(err error) {
	var e *errors.Error
	if errors.As(err, &e) {
		log.Error().Str("stack", e.ErrorStack()).Send()
	} else {
		log.Error().Err(err).Send()
	}
}

func IsCgroupV2() (bool, error) {
	const cgroupV2MagicNumber = unix.CGROUP2_SUPER_MAGIC
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/cgroup/", &stat); err != nil {
		return false, err
	}
	return stat.Type == cgroupV2MagicNumber, nil
}
