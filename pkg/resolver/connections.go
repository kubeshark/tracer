package resolver

import (
	"encoding/binary"
	"fmt"

	"github.com/rs/zerolog/log"
)

type ip4Port struct {
	ip   uint32
	port uint16
}

type ConnectionCb func(pidFd uint64, isClient bool) error

func GatherPidsTCPMap(procfs string, isCgroupV2 bool) (tcpMap map[uint64]bool, err error) {
	tcpMap = make(map[uint64]bool) // (pid<<32)|fd -> client flag

	cgroups, err := getAllCgroups(procfs, isCgroupV2)
	if err != nil {
		log.Error().Err(err).Msg("get all cgroups failed")
		return tcpMap, err
	}
	log.Info().Int("cgroups", len(cgroups)).Msg("got cgroups")
	for cgroup := range cgroups {
		pids, err := findPIDsInCgroup(procfs, isCgroupV2, cgroup)
		if err != nil {
			log.Debug().Msg(fmt.Sprintf("get pids for cgroup %q failed: %v", cgroup, err))
			continue
		}

		log.Debug().Int("connections", len(pids)).Str("Cgroup", cgroup).Msg("got pids")

		var conns []IpSocketLine
		for i := range pids {
			conns, err = getTCPConnections(fmt.Sprintf("%v", pids[i].hostPid))
			if err != nil {
				// process can be short-living
				continue
			}
			break
		}

		log.Debug().Int("connections", len(conns)).Str("Cgroup", cgroup).Msg("got connections")

		// ip:port -> inode:
		listenConnections := make(map[uint16]uint32)

		// (pid<<32) | fd -> local ip:port
		// for established connections
		pidConnections := make(map[uint64]ip4Port)

		for _, conn := range conns {
			if conn.Inode == 0 {
				continue
			}
			if conn.St == 0xA { // listen sockets
				ipPort := ip4Port{
					ip:   binary.BigEndian.Uint32(conn.LocalAddr.To4()),
					port: uint16(conn.LocalPort),
				}
				listenConnections[ipPort.port] = ipPort.ip
			} else if conn.St == 0x1 { // established sockets
				for _, pid := range pids {
					if fd, ok := pid.socketInodes[conn.Inode]; ok {
						pidFd := uint64(pid.hostPid)
						pidFd = (pidFd << 32) | uint64(fd)
						ipPort := ip4Port{
							ip:   binary.BigEndian.Uint32(conn.LocalAddr.To4()),
							port: uint16(conn.LocalPort),
						}
						pidConnections[pidFd] = ipPort
					}
				}
			}

			for pidFd, ipPort := range pidConnections {
				isClient := true
				if listenIp, ok := listenConnections[ipPort.port]; ok {
					// socket can be bound on 0.0.0.0 or interface address
					if listenIp == 0 || listenIp == ipPort.ip {
						isClient = false
					}
				}
				tcpMap[pidFd] = isClient
			}
		}
	}
	return tcpMap, err
}
