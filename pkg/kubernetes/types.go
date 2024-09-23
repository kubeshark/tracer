package kubernetes

type PodInfo struct {
	Pids         []uint32
	CgroupV2Path string
	CgroupIDs    []uint64
}
