package mysql

import (
	"debug/elf"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/perf"

	kself "github.com/kubeshark/tracer/pkg/elf"
)

const (
	symbolName = "dispatch_command"
)

func FindDispatchCommandSymbol(procfs string, pid uint32) (string, error) {
	// Get the mysql executable from /proc/pid/exe
	executable, err := elf.Open(fmt.Sprintf("%s/%d/exe", procfs, pid))
	if err != nil {
		return "", err
	}
	// Find dispatch_command mangled name in binary
	found := make([]elf.Symbol, 0)
	kself.FilterELFSymbols(executable, func(sym elf.Symbol) bool {
		if strings.Contains(sym.Name, symbolName) {
			found = append(found, sym)
		}
		return false
	})
	executable.Close()
	if len(found) == 0 {
		return "", fmt.Errorf("Cannot find dispatch_command in binary")
	}
	if len(found) > 1 {
		return "", fmt.Errorf("Multiple dispatch_command symbols in binary")
	}

	return found[0].Name, nil
}

type MapPoller struct {
	reader *perf.Reader
}

// func NewMapPoller(mp *ebpf.Map) (*MapPoller, error) {
// 	return perf.NewReader(mp, 4096)
// }

// func (p *Poller) Start() (cancel func()) {
// 	ctx, cn := context.WithCancel(context.Background())
// 	go func() {
// 		defer cn()
// 		for {
// 			rec, err := p.reader.Read()
// 			if err != nil {
// 				fmt.Println("Perf reader failed", err)
// 				return
// 			}
// 			p.Target <- rec
// 		}
// 	}()
// }
