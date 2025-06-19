package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/kubeshark/tracer/internal/grpcservice"
	"github.com/kubeshark/tracer/pkg/utils"
	"github.com/rs/zerolog/log"
)

var socketRegex = regexp.MustCompile(`socket:\[(\d+)\]`)

type CgroupInfo struct {
	CgroupPath string
	CgroupID   uint64
}

type CgroupsController interface {
	EbpfCapturePossible() bool
	AddCgroupPath(cgroupPath string) (cgroupID uint64, containerID string, ok bool)
	PopulateSocketsInodes(isCgroupV2 bool, inodeMap *ebpf.Map) error
	DelCgroupID(cgroupID uint64)
	GetContainerID(cgroupID uint64) (containerID string)
	GetCgroupsV2(containerId string) []CgroupInfo
	GetExistingCgroupsByCgroupPath(cgroupPath string) []CgroupInfo
	GetCgroupV2MountPoint() string
	Close() error
}

type CgroupsControllerImpl struct {
	procfs            string
	cgroupToContainer *lru.Cache[uint64, string]

	containerToCgroup *lru.Cache[string, []CgroupInfo]
	containerMtx      sync.Mutex

	cgroup *CgroupV2

	actualCgroupVersion CgroupVersion
	cgroupSupported     bool

	grpcServer *grpcservice.GRPCService
}

func (e *CgroupsControllerImpl) EbpfCapturePossible() bool {
	return e.cgroupSupported
}

func (e *CgroupsControllerImpl) AddCgroupPath(cgroupPath string) (cgroupID uint64, containerID string, ok bool) {
	var err error

	containerID, _ = GetContainerIdByCgroupPath(cgroupPath)
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
	if !e.containerToCgroup.Contains(containerID) {
		e.containerToCgroup.Add(containerID, []CgroupInfo{item})
	} else {
		v, _ := e.containerToCgroup.Get(containerID)
		found := false
		for _, it := range v {
			if it.CgroupID == item.CgroupID && it.CgroupPath == item.CgroupPath {
				found = true
				break
			}
		}
		if !found {
			v = append(v, item)
			e.containerToCgroup.Add(containerID, v)
		}
	}

	// Notify gRPC server about new container info
	if e.grpcServer != nil {
		if err := e.grpcServer.AddContainerInfo(grpcservice.ContainerInfo{
			ContainerID: containerID,
			CgroupID:    cgroupID,
		}); err != nil {
			log.Error().Err(err).Msg("Failed to notify gRPC server about new container")
		}
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
	containerID, _ := GetContainerIdByCgroupPath(cgroupPath)
	if containerID == "" {
		return
	}

	info, _ = e.containerToCgroup.Get(containerID)
	return info
}

func (e *CgroupsControllerImpl) GetCgroupV2MountPoint() string {
	return e.cgroup.mountpoint
}

func (e *CgroupsControllerImpl) PopulateSocketsInodes(isCgroupV2 bool, inodeMap *ebpf.Map) error {
	if inodeMap == nil {
		return nil
	}
	getContId := func(pid string) string {
		path := filepath.Join(e.procfs, pid, "cgroup")
		file, err := os.Open(path)
		if err != nil {
			return ""
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if !isCgroupV2 && !strings.Contains(line, ":cpuset:") {
				continue
			}
			items := strings.Split(line, ":")
			cgroupPath := items[len(items)-1]
			containerID, _ := GetContainerIdByCgroupPath(cgroupPath)
			return containerID
		}

		return ""
	}

	extractInode := func(isCgroupsV2 bool, socketId string, cgroups []CgroupInfo) {
		if inode, err := strconv.ParseUint(socketId, 10, 64); err == nil {
			for _, cgroup := range cgroups {
				if !isCgroupsV2 && !strings.Contains(cgroup.CgroupPath, "/sys/fs/cgroup/cpuset") {
					continue
				}
				if err := inodeMap.Update(inode, cgroup.CgroupID, ebpf.UpdateNoExist); err != nil {
					if errors.Is(err, ebpf.ErrKeyExist) {
						// two processes in the same cgroup can share one socket
						var cgroupExist uint64
						if err := inodeMap.Lookup(inode, &cgroupExist); err != nil {
							log.Error().Err(err).Str("Cgroup Path", cgroup.CgroupPath).Uint64("Cgroup ID", cgroup.CgroupID).Uint64("inode", inode).Msg("Lookup inodemap failed")
						}
						if cgroup.CgroupID != cgroupExist {
							// having one of IDs in inodemap must be enough
							log.Debug().Err(err).Str("Cgroup Path", cgroup.CgroupPath).Uint64("Cgroup ID", cgroup.CgroupID).Uint64("inode", inode).Uint64("Cgroup ID exists", cgroupExist).Msg("Update inodemap failed")
						}
					}
				} else {
					log.Debug().Str("Cgroup Path", cgroup.CgroupPath).Uint64("Cgroup ID", cgroup.CgroupID).Uint64("inode", inode).Msg("Found socket inode")
				}
			}
		}
	}

	findProcessSockets := func(isCgroupsV2 bool, prefix string, files []os.DirEntry, cgroups []CgroupInfo) {
		for _, file := range files {
			link, err := os.Readlink(filepath.Join(prefix, file.Name()))
			if err != nil {
				// some files can be unaccessable
				continue
			}
			match := socketRegex.FindStringSubmatch(link)
			if match != nil {
				extractInode(isCgroupsV2, match[1], cgroups)
			}
		}

	}

	procDir, err := os.Open(e.procfs)
	if err != nil {
		return err
	}
	defer procDir.Close()

	for {
		entries, err := procDir.Readdirnames(100) // to prevent consuming memory
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		for _, entry := range entries {
			if _, err := strconv.Atoi(entry); err != nil {
				continue
			}
			containerID := getContId(entry)
			if containerID == "" {
				continue
			}
			if cgroups, ok := e.containerToCgroup.Get(containerID); ok {
				fdPath := filepath.Join(e.procfs, entry, "fd")
				files, err := os.ReadDir(fdPath)
				if err != nil {
					// process can be already terminated
					continue
				}

				findProcessSockets(isCgroupV2, fdPath, files, cgroups)
			}
		}
	}
}

func (e *CgroupsControllerImpl) Close() error {
	return nil
}

func NewCgroupsController(procfs string, grpcServer *grpcservice.GRPCService) (CgroupsController, error) {
	var err error
	cgroupToContainer, err := lru.New[uint64, string](16384)
	if err != nil {
		return nil, fmt.Errorf("create cgroup to container failed")
	}

	containerToCgroup, err := lru.New[string, []CgroupInfo](16384)
	if err != nil {
		return nil, fmt.Errorf("create container to cgroup failed")
	}

	actualCgroupVersion := CgroupVersion1
	ok, err := utils.IsCgroupV2()
	if err != nil {
		return nil, fmt.Errorf("check cgroup version failed")
	}
	if ok {
		actualCgroupVersion = CgroupVersion2
	}
	cgroupSupported := true
	cgroupV2, err := NewCgroup(CgroupVersion2)
	if err != nil {
		if _, ok := err.(*VersionNotSupported); !ok {
			return nil, fmt.Errorf("new cgroup2 create failed")
		} else {
			cgroupSupported = false
		}
	}

	// add write permissions to user:
	info, err := os.Stat(cgroupV2.GetMountPoint())
	if err != nil {
		return nil, fmt.Errorf("get stat cgroup2 failed")
	}

	mode := info.Mode()
	newMode := mode | 0200

	if err := os.Chmod(cgroupV2.GetMountPoint(), newMode); err != nil {
		return nil, fmt.Errorf("chmod cgroup2 failed")
	}

	return &CgroupsControllerImpl{
		procfs:              procfs,
		cgroupToContainer:   cgroupToContainer,
		containerToCgroup:   containerToCgroup,
		cgroup:              cgroupV2.(*CgroupV2),
		actualCgroupVersion: actualCgroupVersion,
		cgroupSupported:     cgroupSupported,
		grpcServer:          grpcServer,
	}, nil
}
