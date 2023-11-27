package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type ElfFile struct {
	*elf.File
}

func NewElfFile(r io.ReaderAt) (*ElfFile, error) {
	f, err := elf.NewFile(r)
	ret := &ElfFile{
		File: f,
	}
	return ret, err
}

func (f *ElfFile) SymbolsChan() (chan elf.Symbol, error) {
	sym, err := f.getSymbolsChan(elf.SHT_SYMTAB)
	return sym, err
}

func (f *ElfFile) getSymbolsChan(typ elf.SectionType) (chan elf.Symbol, error) {
	switch f.Class {
	case elf.ELFCLASS64:
		return f.getSymbols64Chan(typ)

	case elf.ELFCLASS32:
		return f.getSymbols32Chan(typ)
	}

	return nil, errors.New("not implemented")
}

func (f *ElfFile) getSymbols32Chan(typ elf.SectionType) (chan elf.Symbol, error) {
	symtabSection := f.SectionByType(typ)
	if symtabSection == nil {
		return nil, elf.ErrNoSymbols
	}

	data, err := symtabSection.Data()
	if err != nil {
		return nil, fmt.Errorf("cannot load symbol section: %w", err)
	}
	symtab := bytes.NewReader(data)
	if symtab.Len()%elf.Sym32Size != 0 {
		return nil, errors.New("length of symbol section is not a multiple of SymSize")
	}

	strdata, err := f.stringTable(symtabSection.Link)
	if err != nil {
		return nil, fmt.Errorf("cannot load string table section: %w", err)
	}

	// The first entry is all zeros.
	var skip [elf.Sym32Size]byte
	symtab.Read(skip[:])

	ch := make(chan elf.Symbol, 1)

	var sym elf.Sym32
	for symtab.Len() > 0 {
		defer close(ch)
		binary.Read(symtab, f.ByteOrder, &sym)
		str, _ := getString(strdata, int(sym.Name))
		var symbol elf.Symbol
		symbol.Name = str
		symbol.Info = sym.Info
		symbol.Other = sym.Other
		symbol.Section = elf.SectionIndex(sym.Shndx)
		symbol.Value = uint64(sym.Value)
		symbol.Size = uint64(sym.Size)
		ch <- symbol
	}

	return ch, nil
}

func (f *ElfFile) getSymbols64Chan(typ elf.SectionType) (chan elf.Symbol, error) {
	symtabSection := f.SectionByType(typ)
	if symtabSection == nil {
		return nil, elf.ErrNoSymbols
	}

	data, err := symtabSection.Data()
	if err != nil {
		return nil, fmt.Errorf("cannot load symbol section: %w", err)
	}
	symtab := bytes.NewReader(data)
	if symtab.Len()%elf.Sym64Size != 0 {
		return nil, errors.New("length of symbol section is not a multiple of Sym64Size")
	}

	strdata, err := f.stringTable(symtabSection.Link)
	if err != nil {
		return nil, fmt.Errorf("cannot load string table section: %w", err)
	}

	// The first entry is all zeros.
	var skip [elf.Sym64Size]byte
	symtab.Read(skip[:])

	ch := make(chan elf.Symbol, 1)
	go func() {
		defer close(ch)
		var sym elf.Sym64
		for symtab.Len() > 0 {
			binary.Read(symtab, f.ByteOrder, &sym)
			str, _ := getString(strdata, int(sym.Name))
			var symbol elf.Symbol
			symbol.Name = str
			symbol.Info = sym.Info
			symbol.Other = sym.Other
			symbol.Section = elf.SectionIndex(sym.Shndx)
			symbol.Value = sym.Value
			symbol.Size = sym.Size
			ch <- symbol
		}
	}()

	return ch, nil
}

func getString(section []byte, start int) (string, bool) {
	if start < 0 || start >= len(section) {
		return "", false
	}

	for end := start; end < len(section); end++ {
		if section[end] == 0 {
			return string(section[start:end]), true
		}
	}
	return "", false
}

func stringTable(f *elf.File, link uint32) ([]byte, error) {
	if link <= 0 || link >= uint32(len(f.Sections)) {
		return nil, errors.New("section has invalid string table link")
	}
	return f.Sections[link].Data()
}

func (f *ElfFile) stringTable(link uint32) ([]byte, error) {
	if link <= 0 || link >= uint32(len(f.Sections)) {
		return nil, errors.New("section has invalid string table link")
	}
	return f.Sections[link].Data()
}
