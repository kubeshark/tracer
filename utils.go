package main

import (
	"debug/elf"
	"fmt"

	"github.com/go-errors/errors"
)

func getSymbol(exe *elf.File, name string) (*elf.Symbol, error) {
	var symbols []elf.Symbol
	var err1, err2 error

	symbols, err1 = exe.Symbols()
	if err1 != nil {
		symbols = []elf.Symbol{}
	}

	var dynSymbols []elf.Symbol
	dynSymbols, err2 = exe.DynamicSymbols()
	if err2 == nil {
		symbols = append(symbols, dynSymbols...)
	}

	if len(symbols) == 0 {
		if !errors.Is(err1, elf.ErrNoSymbols) {
			return nil, err1
		}

		if !errors.Is(err2, elf.ErrNoSymbols) {
			return nil, err2
		}
	}

	for _, symbol := range symbols {
		if symbol.Name == name {
			return &symbol, nil
		}
	}

	return nil, fmt.Errorf("Symbol '%s' not found", name)
}
