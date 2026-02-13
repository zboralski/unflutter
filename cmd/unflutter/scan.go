package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"unflutter/internal/dartfmt"
	"unflutter/internal/elfx"
	"unflutter/internal/snapshot"
)

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	profile := fs.String("profile", "", "override version profile")
	strict := fs.Bool("strict", false, "fail on first structural error")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	jsonOut := fs.Bool("json", false, "output as JSON")
	_ = profile // used later

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}

	opts := dartfmt.Options{
		Mode:     dartfmt.ModeBestEffort,
		MaxSteps: *maxSteps,
	}
	if *strict {
		opts.Mode = dartfmt.ModeStrict
	}

	// Open and validate ELF.
	ef, err := elfx.Open(*libapp)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer ef.Close()

	fmt.Fprintf(os.Stderr, "ELF: ARM64 shared object, %d bytes\n", ef.FileSize())

	// Print load segments.
	segs := ef.LoadSegments()
	fmt.Fprintf(os.Stderr, "PT_LOAD segments: %d\n", len(segs))
	for _, s := range segs {
		perm := ""
		if s.Flags&0x4 != 0 {
			perm += "R"
		}
		if s.Flags&0x2 != 0 {
			perm += "W"
		}
		if s.Flags&0x1 != 0 {
			perm += "X"
		}
		fmt.Fprintf(os.Stderr, "  VA=0x%08x Filesz=0x%08x Memsz=0x%08x %s\n",
			s.Vaddr, s.Filesz, s.Memsz, perm)
	}

	// Extract snapshots.
	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	// Text output.
	printRegion := func(r snapshot.Region) {
		fmt.Printf("  %-40s VA=0x%08x  FileOff=0x%08x  SymSize=0x%x\n",
			r.Name, r.VA, r.FileOffset, r.SymSize)
		if r.SHA256 != "" {
			fmt.Printf("    SHA256=%s  DataSize=%d\n", r.SHA256[:16]+"...", r.DataSize)
		}
	}

	fmt.Println("\nSnapshot Regions:")
	printRegion(info.VmData)
	printRegion(info.VmInstructions)
	printRegion(info.IsolateData)
	printRegion(info.IsolateInstructions)

	if info.VmHeader != nil {
		fmt.Printf("\nVM Snapshot Header:\n")
		fmt.Printf("  Kind:     %s\n", info.VmHeader.Kind)
		fmt.Printf("  Size:     %d (0x%x)\n", info.VmHeader.TotalSize, info.VmHeader.TotalSize)
		fmt.Printf("  Hash:     %s\n", info.VmHeader.SnapshotHash)
		fmt.Printf("  Features: %s\n", info.VmHeader.Features)

		prof := snapshot.DetectProfile(info.VmHeader)
		if *profile != "" {
			fmt.Printf("  Profile:  %s (overridden to %s)\n", prof.ID, *profile)
		} else {
			fmt.Printf("  Profile:  %s\n", prof.ID)
		}
		fmt.Printf("    CompressedPointers=%v NullSafety=%v\n",
			prof.CompressedPointers, prof.NullSafety)
	}

	if info.IsolateHeader != nil {
		fmt.Printf("\nIsolate Snapshot Header:\n")
		fmt.Printf("  Kind:     %s\n", info.IsolateHeader.Kind)
		fmt.Printf("  Size:     %d (0x%x)\n", info.IsolateHeader.TotalSize, info.IsolateHeader.TotalSize)
		fmt.Printf("  Hash:     %s\n", info.IsolateHeader.SnapshotHash)
		fmt.Printf("  Features: %s\n", info.IsolateHeader.Features)
	}

	// Parse instruction image headers for code region info.
	for _, r := range []struct {
		name string
		data []byte
		va   uint64
	}{
		{"VM Instructions", info.VmInstructions.Data, info.VmInstructions.VA},
		{"Isolate Instructions", info.IsolateInstructions.Data, info.IsolateInstructions.VA},
	} {
		if len(r.data) < 16 {
			continue
		}
		imgHdr, err := snapshot.ParseImageHeader(r.data)
		if err != nil {
			continue
		}
		sect, err := snapshot.ParseInstructionsSection(r.data, imgHdr.InstructionsSectionOffset)
		if err != nil {
			continue
		}
		fmt.Printf("\n%s Image:\n", r.name)
		fmt.Printf("  ImageSize=0x%x  InstrSectionOffset=0x%x\n",
			imgHdr.ImageSize, imgHdr.InstructionsSectionOffset)
		fmt.Printf("  PayloadLength=0x%x (%d bytes)\n", sect.PayloadLength, sect.PayloadLength)
		fmt.Printf("  RelocatedAddr=0x%x  CodeStart=VA 0x%x\n",
			sect.InstructionsRelocatedAddress, r.va+sect.CodeOffset)
	}

	if len(info.Diags) > 0 {
		fmt.Printf("\nDiagnostics (%d):\n", len(info.Diags))
		for _, d := range info.Diags {
			fmt.Printf("  %s\n", d)
		}
	}

	return nil
}
