package main

import (
	"flag"
	"fmt"
	"os"

	"unflutter/internal/dartfmt"
	"unflutter/internal/disasm"
	"unflutter/internal/elfx"
	"unflutter/internal/output"
	"unflutter/internal/snapshot"
)

func cmdDump(args []string) error {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	outDir := fs.String("out", "", "output directory")
	_ = fs.String("profile", "", "override version profile")
	strict := fs.Bool("strict", false, "fail on first structural error")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *libapp == "" || *outDir == "" {
		return fmt.Errorf("--lib and --out are required")
	}

	opts := dartfmt.Options{
		Mode:     dartfmt.ModeBestEffort,
		MaxSteps: *maxSteps,
	}
	if *strict {
		opts.Mode = dartfmt.ModeStrict
	}

	// Create output directory.
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Open ELF.
	ef, err := elfx.Open(*libapp)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer ef.Close()

	// Extract snapshots.
	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	// Write snapshot.json.
	if err := output.WriteSnapshotJSON(*outDir, info); err != nil {
		return fmt.Errorf("write snapshot.json: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s/snapshot.json\n", *outDir)

	// Generate placeholder symbols from instruction region.
	symbols := make(map[uint64]string)
	var symList []output.SymbolEntry

	// For now, generate sub_<addr> entries at the start of each region.
	if info.IsolateInstructions.VA != 0 {
		name := fmt.Sprintf("sub_%x", info.IsolateInstructions.VA)
		symbols[info.IsolateInstructions.VA] = name
		symList = append(symList, output.SymbolEntry{
			Address: info.IsolateInstructions.VA,
			Name:    name,
			Size:    info.IsolateInstructions.DataSize,
		})
	}
	if info.VmInstructions.VA != 0 {
		name := fmt.Sprintf("sub_%x", info.VmInstructions.VA)
		symbols[info.VmInstructions.VA] = name
		symList = append(symList, output.SymbolEntry{
			Address: info.VmInstructions.VA,
			Name:    name,
			Size:    info.VmInstructions.DataSize,
		})
	}

	// Write symbols.json.
	if err := output.WriteSymbolsJSON(*outDir, symList); err != nil {
		return fmt.Errorf("write symbols.json: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s/symbols.json (%d entries)\n", *outDir, len(symList))

	lookup := disasm.PlaceholderLookup(symbols)

	// Extract actual code region from isolate instructions (skip Image + InstructionsSection headers).
	if len(info.IsolateInstructions.Data) > 0 {
		code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not parse isolate instructions image header: %v\n", err)
			// Fall back to raw disassembly.
			code = info.IsolateInstructions.Data
			codeOff = 0
			payloadLen = uint64(len(code))
		}
		codeVA := info.IsolateInstructions.VA + codeOff
		fmt.Fprintf(os.Stderr, "disassembling isolate code (%d bytes, VA=0x%x, payload=%d)...\n",
			len(code), codeVA, payloadLen)
		insts := disasm.Disassemble(code, disasm.Options{
			BaseAddr: codeVA,
			MaxSteps: opts.EffectiveMaxSteps(),
			Symbols:  lookup,
		})
		if err := output.WriteASMSingle(*outDir, insts, lookup); err != nil {
			return fmt.Errorf("write asm.txt: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s/asm.txt (%d instructions)\n", *outDir, len(insts))
	}

	// Extract code from VM instructions.
	if len(info.VmInstructions.Data) > 0 {
		code, codeOff, _, err := snapshot.CodeRegion(info.VmInstructions.Data)
		if err != nil {
			code = info.VmInstructions.Data
			codeOff = 0
		}
		codeVA := info.VmInstructions.VA + codeOff
		insts := disasm.Disassemble(code, disasm.Options{
			BaseAddr: codeVA,
			MaxSteps: opts.EffectiveMaxSteps(),
		})
		if err := output.WriteASM(*outDir, "vm_stubs", insts, lookup); err != nil {
			return fmt.Errorf("write asm/vm_stubs.txt: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s/asm/vm_stubs.txt (%d instructions)\n", *outDir, len(insts))
	}

	if len(info.Diags) > 0 {
		fmt.Fprintf(os.Stderr, "\ndiagnostics: %d issues\n", len(info.Diags))
		for _, d := range info.Diags {
			fmt.Fprintf(os.Stderr, "  %s\n", d)
		}
	}

	return nil
}
