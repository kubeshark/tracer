package elf

import (
	"debug/elf"
	"fmt"

	"github.com/go-errors/errors"
)

func GetELFSymbol(exe *elf.File, symbol string) (*elf.Symbol, error) {
	sym, err := FilterELFSymbols(exe, func(sym elf.Symbol) bool {
		return sym.Name == symbol
	})
	if err != nil {
		return nil, err
	}
	if sym == nil {
		return nil, fmt.Errorf("Symbol '%s' not found", symbol)
	}
	return sym, nil
}

// Scan the elf symbols, and call filter for each. If filter returns true, returns the symbol
func FilterELFSymbols(exe *elf.File, filter func(elf.Symbol) bool) (*elf.Symbol, error) {
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
