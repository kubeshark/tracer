package resolver

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"path/filepath"
	"strconv"
	"strings"

	"github.com/kubeshark/api"
	"github.com/rs/zerolog/log"

	"github.com/kubeshark/tracer/pkg/cgroup"
	"github.com/kubeshark/tracer/pkg/utils"
)

type Resolver interface {
	ResolveSourceTCP(cInfo *api.ConnectionInfo) *api.Resolution
	ResolveDestTCP(cInfo *api.ConnectionInfo) *api.Resolution
	ResolveSourceUDP(cInfo *api.ConnectionInfo) *api.Resolution
	ResolveDestUDP(cInfo *api.ConnectionInfo) *api.Resolution
}

type ResolverImpl struct {
	procfs     string
	isCgroupV2 bool
	tcpMap     connectionsMap
	udpMap     connectionsMap
}

func NewResolver(procfs string) Resolver {
	isCgroupV2, err := utils.IsCgroupV2()
	if err != nil {
		log.Error().Err(err).Msg("get cgroupv2 failed")
		return nil
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	return &ResolverImpl{
		procfs:     procfs,
		isCgroupV2: isCgroupV2,
		tcpMap:     getAllFlows(procfs, isCgroupV2, "tcp"),
		udpMap:     getAllFlows(procfs, isCgroupV2, "udp"),
	}
}

func getIpPortKey(localIP, localPort, remoteIP, remotePort string) string {
	return fmt.Sprintf("%s%s%s%s", localIP, localPort, remoteIP, remotePort)
}

func getIpPortKeyLocal(localIP, localPort string) string {
	return fmt.Sprintf("l%s%s", localIP, localPort)
}

type connectionResolution struct {
	CgroupID            uint64
	SocketID            uint64
	ProcessID           uint32
	ParentProcessID     uint32
	HostProcessID       uint32
	HostParentProcessID uint32
	ProcessName         string
	ProcessPath         string
}

type pidInfo struct {
	pid           uint32
	parentPid     uint32
	hostPid       uint32
	hostParentPid uint32
	name          string
	path          string
	socketInodes  map[uint64]struct{}
}

type connectionsMap map[string]*connectionResolution

func resolvePair(connMap connectionsMap, localIP, localPort, remoteIP, remotePort string) *api.Resolution {
	log.Debug().Str("local IP", localIP).Str("local Port", localPort).Str("remote IP", remoteIP).Str("remote Port", remotePort).Msg("looking resolution")
	key := getIpPortKey(localIP, localPort, remoteIP, remotePort)
	res, ok := connMap[key]
	if !ok {
		key = getIpPortKeyLocal(localIP, localPort)
		res, ok = connMap[key]
	}
	if !ok {
		return nil
	}
	r := api.Resolution{
		CgroupID:            uint(res.CgroupID),
		SocketID:            uint(res.SocketID),
		ProcessID:           int(res.ProcessID),
		ParentProcessID:     int(res.ParentProcessID),
		HostProcessID:       int(res.HostProcessID),
		HostParentProcessID: int(res.HostParentProcessID),
		ProcessName:         res.ProcessName,
	}
	log.Debug().Str("local IP", localIP).Str("local Port", localPort).Str("remote IP", remoteIP).Str("remote Port", remotePort).Interface("resolution", r).Msg("found resolution")
	return &r
}

func (r *ResolverImpl) resolveTCP(localIP, localPort, remoteIP, remotePort string) *api.Resolution {
	return resolvePair(r.tcpMap, localIP, localPort, remoteIP, remotePort)
}

func (r *ResolverImpl) resolveUDP(localIP, localPort, remoteIP, remotePort string) *api.Resolution {
	return resolvePair(r.udpMap, localIP, localPort, remoteIP, remotePort)
}

func (r *ResolverImpl) ResolveSourceTCP(cInfo *api.ConnectionInfo) *api.Resolution {
	return r.resolveTCP(cInfo.ClientIP, cInfo.ClientPort, cInfo.ServerIP, cInfo.ServerPort)
}

func (r *ResolverImpl) ResolveDestTCP(cInfo *api.ConnectionInfo) *api.Resolution {
	return r.resolveTCP(cInfo.ServerIP, cInfo.ServerPort, cInfo.ClientIP, cInfo.ClientPort)
}

func (r *ResolverImpl) ResolveSourceUDP(cInfo *api.ConnectionInfo) *api.Resolution {
	return r.resolveUDP(cInfo.ClientIP, cInfo.ClientPort, cInfo.ServerIP, cInfo.ServerPort)
}

func (r *ResolverImpl) ResolveDestUDP(cInfo *api.ConnectionInfo) *api.Resolution {
	return r.resolveUDP(cInfo.ServerIP, cInfo.ServerPort, cInfo.ClientIP, cInfo.ClientPort)
}

func getAllFlows(procfs string, isCgroupV2 bool, proto string) connectionsMap {
	res := make(connectionsMap)
	cgroups, err := getAllCgroups(procfs, isCgroupV2)
	if err != nil {
		log.Error().Err(err).Msg("get all cgroups failed")
		return nil
	}
	log.Info().Int("cgroups", len(cgroups)).Str("proto", proto).Msg("got cgroups")
	for cgroup, cgroupID := range cgroups {
		pids, err := findPIDsInCgroup(procfs, isCgroupV2, cgroup)
		if err != nil {
			log.Debug().Msg(fmt.Sprintf("get pids for cgroup %q failed: %v", cgroup, err))
			continue
		}

		log.Debug().Int("connections", len(pids)).Str("Cgroup", cgroup).Str("proto", proto).Msg("got pids")

		var conns []IpSocketLine
		for i := range pids {
			if proto == "tcp" {
				conns, err = getTCPConnections(fmt.Sprintf("%v", pids[i].hostPid))
			} else {
				conns, err = getUDPConnections(fmt.Sprintf("%v", pids[i].hostPid))
			}
			if err != nil {
				// process can be short-living
				continue
			}
			break
		}
		if err != nil {
			log.Error().Err(err).Str("Cgroup", cgroup).Str("proto", proto).Msg("get connections failed")
			continue
		}

		log.Debug().Int("connections", len(conns)).Str("Cgroup", cgroup).Str("proto", proto).Msg("got connections")

		for _, conn := range conns {
			if conn.Inode == 0 {
				continue
			}
			// find out process socket entry belongs to:
			var pidFound *pidInfo
			for _, pid := range pids {
				if _, ok := pid.socketInodes[conn.Inode]; ok {
					pidFound = &pid
					break
				}
			}

			if pidFound == nil {
				// no pid for socket inode
				continue
			}

			resolution := &connectionResolution{
				CgroupID:            cgroupID,
				SocketID:            conn.Inode,
				ProcessID:           pidFound.pid,
				ParentProcessID:     pidFound.parentPid,
				HostProcessID:       pidFound.hostPid,
				HostParentProcessID: pidFound.hostParentPid,
				ProcessName:         pidFound.name,
				ProcessPath:         pidFound.path,
			}

			key := getIpPortKey(conn.LocalAddr.String(), fmt.Sprintf("%v", conn.LocalPort), conn.RemAddr.String(), fmt.Sprintf("%v", conn.RemPort))
			res[key] = resolution
			log.Debug().Str("Cgroup", cgroup).Str("proto", proto).Str("local IP", conn.LocalAddr.String()).Uint64("local Port", conn.LocalPort).Str("remote IP", conn.RemAddr.String()).Uint64("remote Port", conn.RemPort).Interface("resolution", resolution).Msg("saved resolution")

			if conn.LocalAddr[0] != 127 { // save non-loopback locals
				keyLocal := getIpPortKeyLocal(conn.LocalAddr.String(), fmt.Sprintf("%v", conn.LocalPort))
				res[keyLocal] = resolution
			}
		}
	}
	return res
}

func getAllCgroups(procfs string, isCgroupV2 bool) (ret map[string]uint64, err error) {
	ret = make(map[string]uint64)
	procDir, err := os.Open(procfs)
	if err != nil {
		return
	}
	defer procDir.Close()

	pidPaths := make(map[string]struct{})
	for {
		entries, err := procDir.Readdirnames(100) // to prevent consuming memory
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return ret, err
		}

		for _, entry := range entries {
			hostPid, err := strconv.Atoi(entry)
			if err != nil {
				continue
			}
			err = findPidPaths(pidPaths, procfs, isCgroupV2, entry)
			if err != nil {
				log.Debug().Int("pid", hostPid).Msg(fmt.Sprintf("find pid paths failed: %v", err))
				continue
			}
		}
	}

	return findCgroupsEndWith(isCgroupV2, pidPaths)
}

func findPIDsInCgroup(procfs string, isCgroupV2 bool, cgroupEntry string) ([]pidInfo, error) {
	procDir, err := os.Open(procfs)
	if err != nil {
		return nil, err
	}
	defer procDir.Close()

	var pinfos []pidInfo
	for {
		entries, err := procDir.Readdirnames(100) // to prevent consuming memory
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		for _, entry := range entries {
			hostPid, err := strconv.Atoi(entry)
			if err != nil {
				continue
			}
			ok, err := pidInCgroup(procfs, isCgroupV2, entry, cgroupEntry)
			if err != nil {
				return nil, err
			}
			if ok {
				pi, err := getPidInfo(procfs, uint32(hostPid), isCgroupV2)
				if err != nil {
					//TODO: handle case when pid was terminated
					log.Debug().Err(err).Int("pid", hostPid).Msg("get pid info failed")
					continue
				}
				pinfos = append(pinfos, pi)
			}
		}
	}

	return pinfos, nil
}

func getPidInfo(proc string, hostPid uint32, isCgroupV2 bool) (pi pidInfo, err error) {
	status, err := getPidStatus(proc, hostPid)
	if err != nil {
		return
	}
	cgroup, err := getPidCgroup(proc, hostPid, isCgroupV2)
	if err != nil {
		return
	}

	name := status["Name:"]

	hostParentPid, err := strconv.Atoi(status["PPid:"])
	if err != nil {
		return
	}

	nspid, err := strconv.Atoi(status["NSpid:"])
	if err != nil {
		return
	}

	cgroupPpid, err := getPidCgroup(proc, uint32(hostParentPid), isCgroupV2)
	if err != nil {
		return
	}

	var parentNspid int

	// if not root pid, get parent
	if cgroup == cgroupPpid {
		statusPpid, err := getPidStatus(proc, uint32(hostParentPid))
		if err != nil {
			return pi, err
		}

		parentNspid, err = strconv.Atoi(statusPpid["NSpid:"])
		if err != nil {
			return pi, err
		}
	}

	inodes, err := getPidSocketInodes(proc, hostPid)
	if err != nil {
		return
	}

	if pi.path, err = resolveSymlinkWithoutValidation(filepath.Join(proc, fmt.Sprintf("%v", hostPid), "exe")); err != nil {
		return
	}

	pi.hostPid = hostPid
	pi.hostParentPid = uint32(hostParentPid)
	pi.pid = uint32(nspid)
	pi.parentPid = uint32(parentNspid)
	pi.name = name
	pi.socketInodes = inodes

	return
}

func pidInCgroup(procfs string, isCgroupV2 bool, pid, cgroupEntry string) (bool, error) {
	path := filepath.Join(procfs, pid, "cgroup")
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Error().Msg(fmt.Sprintf("Closing file error: %v", err))
		}
	}()

	scanner := bufio.NewScanner(file)

	if isCgroupV2 {
		for scanner.Scan() {
			line := strings.Split(scanner.Text(), ":")
			if len(line) < 3 {
				continue
			}
			path = line[2]
			for strings.HasPrefix(path, "/..") {
				path = path[3:]
			}
			if strings.HasSuffix(cgroupEntry, path) {
				return true, nil
			}
			break // only one entry
		}
	} else {
		for scanner.Scan() {
			line := strings.Split(scanner.Text(), ":")
			if len(line) < 3 {
				continue
			}
			if !strings.Contains(line[1], "cpuset") {
				continue
			}
			path = line[2]
			if strings.HasSuffix(cgroupEntry, path) {
				return true, nil
			}
		}
	}

	return false, nil
}

func findPidPaths(pidPaths map[string]struct{}, procfs string, isCgroupV2 bool, pid string) error {
	path := filepath.Join(procfs, pid, "cgroup")
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Error().Msg(fmt.Sprintf("Closing file error: %v", err))
		}
	}()

	scanner := bufio.NewScanner(file)

	if isCgroupV2 {
		for scanner.Scan() {
			line := strings.Split(scanner.Text(), ":")
			if len(line) < 3 {
				continue
			}
			path = line[2]
			for strings.HasPrefix(path, "/..") {
				path = path[3:]
			}
			if contId, _ := cgroup.GetContainerIdByCgroupPath(path); contId != "" {
				pidPaths[path] = struct{}{}
			}
		}
	} else {
		for scanner.Scan() {
			line := strings.Split(scanner.Text(), ":")
			if len(line) < 3 {
				continue
			}
			if !strings.Contains(line[1], "cpuset") {
				continue
			}
			path = line[2]
			pidPaths[path] = struct{}{}
		}
	}

	return nil
}

func findCgroupsEndWith(isCgroupsV2 bool, pidPaths map[string]struct{}) (paths map[string]uint64, err error) {
	paths = make(map[string]uint64)

	basePath := "/sys/fs/cgroup/"
	err = filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if !isCgroupsV2 && !strings.HasPrefix(path, "/sys/fs/cgroup/cpuset") {
			return nil
		}
		for pidPath := range pidPaths {
			if strings.HasSuffix(path, pidPath) {
				inode, err := utils.GetInode(path)
				if err != nil {
					return err
				}
				paths[path] = inode
			}
		}
		return nil
	})

	return
}

func getTCPConnections(pid string) (lines []IpSocketLine, err error) {
	return getSocketLines("tcp", pid)
}

func getUDPConnections(pid string) (lines []IpSocketLine, err error) {
	return getSocketLines("udp", pid)
}
