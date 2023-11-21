package main

import (
	"bytes"
	"debug/elf"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const (
	executable = "/usr/sbin/mysqld"
	symbolName = "dispatch_command"
)

func main() {
	// Find the dispatch_command symbol in executable. This is necessary
	// to figure out the mangled name

	f, err := elf.Open(executable)
	if err != nil {
		panic(err)
	}
	found := make([]elf.Symbol, 0)
	SearchELFSymbols(f, func(sym elf.Symbol) bool {
		if strings.Contains(sym.Name, symbolName) {
			found = append(found, sym)
		}
		return false
	})
	f.Close()
	if len(found) != 1 {
		panic("Cannot find symbol")
	}
	fmt.Println(found[0].Name)

	// found[0].Name contains the name of the symbol to uprobe

	// Load the epbf program
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(_TracerBytes))
	if err != nil {
		panic(err)
	}

	type TObj struct {
		Prog *ebpf.Program `ebpf:"server_command_probe"`
		Map  *ebpf.Map     `ebpf:"mysql_queries"`
	}

	var obj TObj

	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		panic(err)
	}

	executable, err := link.OpenExecutable(executable)
	if err != nil {
		panic(err)
	}
	fmt.Println("Executable opened")
	_ = executable
	link, err := executable.Uprobe(found[0].Name, obj.Prog, nil)
	if err != nil {
		panic(err)
	}
	defer link.Close()
	fmt.Println("link", link)
	reader, err := perf.NewReader(obj.Map, 4096)
	if err != nil {
		panic(err)
	}
	fmt.Println("Got perf reader", reader)
	for {
		rec, err := reader.Read()
		if err != nil {
			fmt.Println(err)
			break
		}
		fmt.Println(string(rec.RawSample))
	}

}

// Scan the elf symbols, and call filter for each. If filter returns true, returns the symbol
func SearchELFSymbols(exe *elf.File, filter func(elf.Symbol) bool) (*elf.Symbol, error) {
	var symbols []elf.Symbol
	var err1, err2 error

	symbols, err1 = exe.Symbols()
	if err1 == nil {
		for i, s := range symbols {
			if filter(s) {
				return &symbols[i], nil
			}
		}
	}

	var dynSymbols []elf.Symbol
	dynSymbols, err2 = exe.DynamicSymbols()
	if err2 == nil {
		for i, dyn := range dynSymbols {
			if filter(dyn) {
				return &dynSymbols[i], nil
			}
		}
	}

	if len(symbols) == 0 {
		if !errors.Is(err1, elf.ErrNoSymbols) {
			return nil, err1
		}

		if !errors.Is(err2, elf.ErrNoSymbols) {
			return nil, err2
		}
	}

	return nil, nil
}

// Do not access this directly.
//
//go:embed tracer_bpfel_x86.o
var _TracerBytes []byte
