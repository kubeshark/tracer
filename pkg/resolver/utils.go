package resolver

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kubeshark/procfs"
	"github.com/rs/zerolog/log"
)

type IpSocketLine struct {
	Sl        uint64
	LocalAddr net.IP
	LocalPort uint64
	RemAddr   net.IP
	RemPort   uint64
	St        uint64
	TxQueue   uint64
	RxQueue   uint64
	UID       uint64
	Inode     uint64
}

func getSocketLines(procpath, proto, pid string) (lines []IpSocketLine, err error) {
	var tcpConns procfs.NetTCP
	var tcpConns6 procfs.NetTCP
	getTcpConns := func(procpath, _pid string) error {
		tcpConns, err = procfs.NewNetTCP(fmt.Sprintf("%v/%v/net/tcp", procpath, _pid))
		if err != nil {
			return err
		}

		tcpConns6, err = procfs.NewNetTCP(fmt.Sprintf("%v/%v/net/tcp6", procpath, _pid))
		if errors.Is(err, os.ErrNotExist) {
			// ipv6 is disabled
			return nil
		} else if err != nil {
			return err
		}

		return nil
	}

	var udpConns procfs.NetUDP
	var udpConns6 procfs.NetUDP
	getUdpConns := func(procpath, _pid string) error {
		udpConns, err = procfs.NewNetUDP(fmt.Sprintf("%v/%v/net/udp", procpath, _pid))
		if err != nil {
			return err
		}

		udpConns6, err = procfs.NewNetUDP(fmt.Sprintf("%v/%v/net/udp6", procpath, _pid))
		if errors.Is(err, os.ErrNotExist) {
			// ipv6 is disabled
			return nil
		} else if err != nil {
			return err
		}

		return nil
	}

	if proto == "tcp" {
		if err = getTcpConns(procpath, pid); err != nil {
			err = fmt.Errorf("execute tcp in ns failed for pid: %v error: %v", pid, err)
			return lines, err
		}
		for _, c := range tcpConns {
			d := IpSocketLine{
				Sl:        c.Sl,
				LocalAddr: c.LocalAddr,
				LocalPort: c.LocalPort,
				RemAddr:   c.RemAddr,
				RemPort:   c.RemPort,
				St:        c.St,
				TxQueue:   c.TxQueue,
				RxQueue:   c.RxQueue,
				UID:       c.UID,
				Inode:     c.Inode,
			}
			lines = append(lines, d)
		}
		for _, c := range tcpConns6 {
			if !isIPv4Mapped(c.LocalAddr) || !isIPv4Mapped(c.RemAddr) {
				continue
			}
			d := IpSocketLine{
				Sl:        c.Sl,
				LocalAddr: c.LocalAddr.To4(),
				LocalPort: c.LocalPort,
				RemAddr:   c.RemAddr.To4(),
				RemPort:   c.RemPort,
				St:        c.St,
				TxQueue:   c.TxQueue,
				RxQueue:   c.RxQueue,
				UID:       c.UID,
				Inode:     c.Inode,
			}
			lines = append(lines, d)
		}

	} else if proto == "udp" {
		if err = getUdpConns(procpath, pid); err != nil {
			err = fmt.Errorf("execute udp in ns failed for pid: %v error: %v", pid, err)
			return lines, err
		}
		for _, c := range udpConns {
			d := IpSocketLine{
				Sl:        c.Sl,
				LocalAddr: c.LocalAddr,
				LocalPort: c.LocalPort,
				RemAddr:   c.RemAddr,
				RemPort:   c.RemPort,
				St:        c.St,
				TxQueue:   c.TxQueue,
				RxQueue:   c.RxQueue,
				UID:       c.UID,
				Inode:     c.Inode,
			}
			lines = append(lines, d)
		}
		for _, c := range udpConns6 {
			if !isIPv4Mapped(c.LocalAddr) || !isIPv4Mapped(c.RemAddr) {
				continue
			}
			d := IpSocketLine{
				Sl:        c.Sl,
				LocalAddr: c.LocalAddr.To4(),
				LocalPort: c.LocalPort,
				RemAddr:   c.RemAddr.To4(),
				RemPort:   c.RemPort,
				St:        c.St,
				TxQueue:   c.TxQueue,
				RxQueue:   c.RxQueue,
				UID:       c.UID,
				Inode:     c.Inode,
			}
			// pass only established connections
			if c.St != 1 {
				continue
			}
			lines = append(lines, d)
		}
	}

	return lines, err
}

func getPidStatus(proc string, hostPid uint32) (status map[string]string, err error) {
	status = make(map[string]string)
	path := filepath.Join(proc, fmt.Sprintf("%v", hostPid), "status")
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return status, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Error().Msg(fmt.Sprintf("Closing file error: %v", err))
		}
	}()

	scanner := bufio.NewScanner(file)
	checkFields := map[string]struct{}{
		"Name:":  {},
		"PPid:":  {},
		"NSpid:": {},
	}

	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) < 2 {
			continue
		}
		if _, ok := checkFields[line[0]]; ok {
			status[line[0]] = line[len(line)-1]
		}
	}
	for f := range checkFields {
		if _, ok := status[f]; !ok {
			err = fmt.Errorf("process status field %q not found, pid: %v", f, hostPid)
			return status, err
		}
	}

	return status, err
}

func getPidCgroup(proc string, hostPid uint32, isCgroupV2 bool) (cgroup string, err error) {
	path := filepath.Join(proc, fmt.Sprintf("%v", hostPid), "cgroup")
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return cgroup, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Error().Msg(fmt.Sprintf("Closing file error: %v", err))
		}
	}()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.Split(scanner.Text(), ":")
		if len(line) < 3 {
			continue
		}
		if isCgroupV2 || strings.Contains(line[1], "cpuset") {
			cgroup = line[2]
			return cgroup, err
		}
	}

	return cgroup, err
}

func getPidSocketInodes(proc string, pid uint32) (map[uint64]uint32, error) {
	fdPath := filepath.Join(proc, fmt.Sprintf("%v", pid), "fd")

	fdDir, err := os.Open(fdPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open fd directory: %v", err)
	}
	defer fdDir.Close()

	fds, err := fdDir.Readdirnames(0)
	if err != nil {
		return nil, fmt.Errorf("failed to read fd directory: %v", err)
	}

	socketInodes := make(map[uint64]uint32)

	for _, fd := range fds {
		fdLink := filepath.Join(fdPath, fd)
		linkTarget, err := os.Readlink(fdLink)
		if err != nil {
			// Ignore errors for invalid file descriptors
			continue
		}

		if strings.HasPrefix(linkTarget, "socket:[") {
			inode := strings.TrimSuffix(strings.TrimPrefix(linkTarget, "socket:["), "]")
			inodeNum, err := strconv.ParseUint(inode, 10, 64)
			if err != nil {
				continue
			}
			fdVal, err := strconv.ParseUint(fd, 10, 32)
			if err != nil {
				log.Error().Err(err).Str("fd", fd).Msg("parse process file descriptor failed")
				continue
			}
			socketInodes[inodeNum] = uint32(fdVal)
		}
	}

	return socketInodes, nil
}

func ResolveSymlinkWithoutValidation(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}

	if info.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("path is not a symlink")
	}

	target, err := os.Readlink(path)
	if err != nil {
		return "", err
	}

	return target, nil
}

func isIPv4Mapped(ip net.IP) bool {
	return ip.To4() != nil && len(ip) == net.IPv6len && ip[0] == 0 && ip[1] == 0 &&
		ip[2] == 0 && ip[3] == 0 && ip[4] == 0 && ip[5] == 0 &&
		ip[6] == 0 && ip[7] == 0 && ip[8] == 0 && ip[9] == 0 &&
		ip[10] == 0xff && ip[11] == 0xff
}
