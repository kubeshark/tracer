package main

import (
	"fmt"
	"github.com/cilium/ebpf/link"

	"github.com/kubeshark/tracer/pkg/mysql"
	"github.com/kubeshark/tracer/pkg/proc"
)

type MysqlHooks struct {
	DispatchCommandName  string
	Pid                  uint32
	SSLLibPath           string
	BinaryPath           string
	DispatchCommandProbe link.Link
}

func NewMysqlHooks(procfs string, pid uint32) (*MysqlHooks, error) {
	sym, err := mysql.FindDispatchCommandSymbol(procfs, pid)
	if err != nil {
		return nil, err
	}
	sslLibPath, err := proc.FindSSLLib(pid)
	if err != nil {
		return nil, err
	}
	return &MysqlHooks{
		DispatchCommandName: sym,
		Pid:                 pid,
		SSLLibPath:          sslLibPath,
		BinaryPath:          fmt.Sprintf("%s/%d/exe", procfs, pid),
	}, nil
}

func (hooks *MysqlHooks) AttachUprobesToFile(bpfObjects *tracerObjects) error {
	mysqlBinary, err := link.OpenExecutable(hooks.BinaryPath)
	if err != nil {
		return err
	}
	return hooks.AttachUprobesToExecutable(bpfObjects, mysqlBinary)
}

func (hooks *MysqlHooks) AttachUprobesToExecutable(bpfObjects *tracerObjects, executable *link.Executable) error {
	var err error
	hooks.DispatchCommandProbe, err = executable.Uprobe(hooks.DispatchCommandName, bpfObjects.MysqlDispatchCommandProbe, nil)
	if err != nil {
		return err
	}
	return nil
}
