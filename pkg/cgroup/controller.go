package cgroup

import (
	"fmt"
	"os"

	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/kubeshark/tracer/pkg/utils"
	"github.com/rs/zerolog/log"
)

type CgroupInfo struct {
	CgroupPath string
	CgroupID   uint64
}

type CgroupsController interface {
	EbpfCapturePossible() bool
	AddCgroupPath(cgroupPath string) (cgroupID uint64, containerID string, ok bool)
	DelCgroupID(cgroupID uint64)
	GetContainerID(cgroupID uint64) (containerID string)
	GetCgroupsV2(containerId string) []CgroupInfo
	GetExistingCgroupsByCgroupPath(cgroupPath string) []CgroupInfo
	GetCgroupV2MountPoint() string
	Close() error
}

type CgroupsControllerImpl struct {
	cgroupToContainer *lru.Cache[uint64, string]

	containerToCgroup *lru.Cache[string, []CgroupInfo]
	containerMtx      sync.Mutex

	cgroup *CgroupV2

	actualCgroupVersion CgroupVersion
	cgroupV2Supported   bool
}

func (e *CgroupsControllerImpl) EbpfCapturePossible() bool {
	return e.cgroupV2Supported
}

func (e *CgroupsControllerImpl) AddCgroupPath(cgroupPath string) (cgroupID uint64, containerID string, ok bool) {
	var err error

	containerID, _ = getContainerIdByCgroupPath(cgroupPath)
	if containerID == "" {
		log.Debug().Str("path", cgroupPath).Msg("Can not get container id")
		return
	}

	cgroupID, err = getCgroupIdByPath(cgroupPath)
	if err != nil {
		log.Warn().Str("path", cgroupPath).Msg(fmt.Sprintf("Can not get container Cgroup ID: %v", err))
		return
	}

	e.cgroupToContainer.Add(cgroupID, containerID)

	item := CgroupInfo{
		CgroupPath: cgroupPath,
		CgroupID:   cgroupID,
	}

	e.containerMtx.Lock()
	defer e.containerMtx.Unlock()
	//TODO: check same already exists
	if !e.containerToCgroup.Contains(containerID) {
		e.containerToCgroup.Add(containerID, []CgroupInfo{item})
	} else {
		v, _ := e.containerToCgroup.Get(containerID)
		v = append(v, item)
		e.containerToCgroup.Add(containerID, v)
	}

	ok = true
	return
}

func (e *CgroupsControllerImpl) DelCgroupID(cgroup uint64) {
	e.cgroupToContainer.Remove(cgroup)
}

func (e *CgroupsControllerImpl) GetContainerID(cgroup uint64) string {
	if contId, ok := e.cgroupToContainer.Get(cgroup); !ok {
		return ""
	} else {
		return contId
	}
}

func (e *CgroupsControllerImpl) GetCgroupsV2(containerID string) (info []CgroupInfo) {
	info, _ = e.containerToCgroup.Get(containerID)
	if e.actualCgroupVersion == CgroupVersion2 {
		return
	}
	return

	//TODO: check if cgroup has unified inside and it already has existing cgroup V2
}

func (e *CgroupsControllerImpl) GetExistingCgroupsByCgroupPath(cgroupPath string) (info []CgroupInfo) {
	containerID, _ := getContainerIdByCgroupPath(cgroupPath)
	if containerID == "" {
		return
	}

	info, _ = e.containerToCgroup.Get(containerID)
	return info
}

func (e *CgroupsControllerImpl) GetCgroupV2MountPoint() string {
	return e.cgroup.mountpoint
}

func (e *CgroupsControllerImpl) Close() error {
	return nil
}

func NewCgroupsController() CgroupsController {
	var err error
	cgroupToContainer, err := lru.New[uint64, string](16384)
	if err != nil {
		log.Error().Err(err).Msg("create cgroup to container failed")
		return nil
	}

	containerToCgroup, err := lru.New[string, []CgroupInfo](16384)
	if err != nil {
		log.Error().Err(err).Msg("create container to cgroup failed")
		return nil
	}

	actualCgroupVersion := CgroupVersion1
	ok, err := utils.IsCgroupV2()
	if err != nil {
		log.Error().Err(err).Msg("check cgroup version failed")
		return nil
	}
	if ok {
		actualCgroupVersion = CgroupVersion2
	}
	cgroupV2Supported := true
	cgroupV2, err := NewCgroup(CgroupVersion2)
	if err != nil {
		if _, ok := err.(*VersionNotSupported); !ok {
			log.Error().Err(err).Msg("new cgroup2 create failed")
			return nil
		} else {
			cgroupV2Supported = false
		}
	}

	// add write permissions to user:
	info, err := os.Stat(cgroupV2.GetMountPoint())
	if err != nil {
		log.Error().Err(err).Msg("get stat cgroup2 failed")
		return nil
	}

	mode := info.Mode()
	newMode := mode | 0200

	if err := os.Chmod(cgroupV2.GetMountPoint(), newMode); err != nil {
		log.Error().Err(err).Msg("chmod cgroup2 failed")
		return nil
	}

	return &CgroupsControllerImpl{
		cgroupToContainer:   cgroupToContainer,
		containerToCgroup:   containerToCgroup,
		cgroup:              cgroupV2.(*CgroupV2),
		actualCgroupVersion: actualCgroupVersion,
		cgroupV2Supported:   cgroupV2Supported,
	}
}
