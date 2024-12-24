package tai

import (
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
	"sync"
	"time"
)

type TaiInfo interface {
	GetTAIOffset() uint64
}

type taiInfoImpl struct {
	tai    int32
	taiMtx sync.RWMutex
}

func (s *taiInfoImpl) GetTAIOffset() uint64 {
	s.taiMtx.RLock()
	defer s.taiMtx.RUnlock()
	return uint64(s.tai) * 1e9
}

func NewTaiInfo() TaiInfo {
	taiInfo := taiInfoImpl{}

	taiInfo.assignTAI()
	go taiInfo.updateTAI()

	return &taiInfo
}

func (s *taiInfoImpl) updateTAI() {
	ticker := time.NewTicker(30 * time.Second)
	for {
		<-ticker.C
		s.assignTAI()
	}
}

func (s *taiInfoImpl) assignTAI() {
	tai, err := getTAIOffset()
	if err != nil {
		log.Error().Err(err).Msg("Get TAI failed:")
		return
	}
	s.taiMtx.Lock()
	s.tai = tai
	s.taiMtx.Unlock()
}

// getTAIOffset retrieves the current TAI offset from the system.
func getTAIOffset() (int32, error) {
	var timex unix.Timex

	if _, err := unix.Adjtimex(&timex); err != nil {
		return 0, err
	}

	return timex.Tai, nil
}
