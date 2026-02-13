// Package elfx provides ELF loading helpers for Dart AOT libapp.so files.
package elfx

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	ErrNotELF       = errors.New("elfx: not an ELF file")
	ErrNotARM64     = errors.New("elfx: not ARM64 (EM_AARCH64)")
	ErrNotShared    = errors.New("elfx: not a shared object")
	ErrNot64Bit     = errors.New("elfx: not 64-bit ELF")
	ErrNoSymbol     = errors.New("elfx: symbol not found")
	ErrNoSegment    = errors.New("elfx: no PT_LOAD segment covers address")
	ErrSymbolNoSize = errors.New("elfx: symbol has zero size")
)

// File wraps a debug/elf.File with convenience methods for Dart AOT analysis.
type File struct {
	ELF  *elf.File
	raw  io.ReaderAt
	size int64
}

// Open opens an ELF file and validates it is an ARM64 shared object.
func Open(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("elfx: open: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("elfx: stat: %w", err)
	}

	ef, err := elf.NewFile(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %v", ErrNotELF, err)
	}

	if ef.Class != elf.ELFCLASS64 {
		ef.Close()
		return nil, ErrNot64Bit
	}
	if ef.Machine != elf.EM_AARCH64 {
		ef.Close()
		return nil, ErrNotARM64
	}
	if ef.Type != elf.ET_DYN {
		ef.Close()
		return nil, ErrNotShared
	}

	return &File{ELF: ef, raw: f, size: info.Size()}, nil
}

// Close releases resources.
func (f *File) Close() error {
	return f.ELF.Close()
}

// FileSize returns the size of the underlying file.
func (f *File) FileSize() int64 { return f.size }

// Symbol looks up a dynamic symbol by exact name.
// Returns the symbol's virtual address and size.
func (f *File) Symbol(name string) (addr, size uint64, err error) {
	syms, err := f.ELF.DynamicSymbols()
	if err != nil {
		return 0, 0, fmt.Errorf("elfx: dynsym: %w", err)
	}
	for _, s := range syms {
		if s.Name == name {
			return s.Value, s.Size, nil
		}
	}
	return 0, 0, fmt.Errorf("%w: %s", ErrNoSymbol, name)
}

// VAToFileOffset converts a virtual address to a file offset using PT_LOAD segments.
func (f *File) VAToFileOffset(va uint64) (uint64, error) {
	for _, p := range f.ELF.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if va >= p.Vaddr && va < p.Vaddr+p.Memsz {
			offset := va - p.Vaddr + p.Off
			if offset >= uint64(f.size) {
				return 0, fmt.Errorf("elfx: VA 0x%x maps to offset 0x%x beyond file size 0x%x", va, offset, f.size)
			}
			return offset, nil
		}
	}
	return 0, fmt.Errorf("%w: VA 0x%x", ErrNoSegment, va)
}

// ReadAt reads bytes from the underlying file at the given file offset.
func (f *File) ReadAt(buf []byte, off int64) (int, error) {
	return f.raw.ReadAt(buf, off)
}

// ReadBytesAtVA reads n bytes starting at the given virtual address.
func (f *File) ReadBytesAtVA(va uint64, n int) ([]byte, error) {
	off, err := f.VAToFileOffset(va)
	if err != nil {
		return nil, err
	}
	// Clamp to file size.
	avail := f.size - int64(off)
	if avail <= 0 {
		return nil, fmt.Errorf("elfx: offset 0x%x at or past end of file", off)
	}
	if int64(n) > avail {
		n = int(avail)
	}
	buf := make([]byte, n)
	_, err = f.raw.ReadAt(buf, int64(off))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("elfx: read at 0x%x: %w", off, err)
	}
	return buf, nil
}

// SegmentInfo describes a PT_LOAD segment.
type SegmentInfo struct {
	Vaddr  uint64
	Memsz  uint64
	Filesz uint64
	Offset uint64
	Flags  elf.ProgFlag
}

// LoadSegments returns all PT_LOAD segments.
func (f *File) LoadSegments() []SegmentInfo {
	var segs []SegmentInfo
	for _, p := range f.ELF.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		segs = append(segs, SegmentInfo{
			Vaddr:  p.Vaddr,
			Memsz:  p.Memsz,
			Filesz: p.Filesz,
			Offset: p.Off,
			Flags:  p.Flags,
		})
	}
	return segs
}

// ByteOrder returns the ELF byte order.
func (f *File) ByteOrder() binary.ByteOrder {
	return f.ELF.ByteOrder
}
