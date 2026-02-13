package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"unflutter/internal/cluster"
	"unflutter/internal/dartfmt"
	"unflutter/internal/disasm"
	"unflutter/internal/elfx"
	"unflutter/internal/snapshot"
)

func cmdTHRAudit(args []string) error {
	fs := flag.NewFlagSet("thr-audit", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	outPath := fs.String("out", "", "output JSONL path")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	limit := fs.Int("limit", 0, "max functions to scan (0 = all)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" || *outPath == "" {
		return fmt.Errorf("--lib and --out are required")
	}

	opts := dartfmt.Options{
		Mode:     dartfmt.ModeBestEffort,
		MaxSteps: *maxSteps,
	}

	ef, err := elfx.Open(*libapp)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer ef.Close()

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	dartVersion := ""
	if info.Version != nil {
		dartVersion = info.Version.DartVersion
	}
	fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", dartVersion)
	if info.Version != nil && !info.Version.Supported {
		return fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)", info.Version.DartVersion, info.VmHeader.SnapshotHash)
	}

	// Parse isolate snapshot clusters + fill.
	data := info.IsolateData.Data
	if len(data) < 64 {
		return fmt.Errorf("isolate data too short (%d bytes)", len(data))
	}

	clusterStart, err := cluster.FindClusterDataStart(data)
	if err != nil {
		return fmt.Errorf("cluster start: %w", err)
	}

	result, err := cluster.ScanClusters(data, clusterStart, info.Version, false, opts)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	if err := cluster.ReadFill(data, result, info.Version, false, info.IsolateHeader.TotalSize); err != nil {
		return fmt.Errorf("fill: %w", err)
	}

	// Parse instructions table.
	table, err := cluster.ParseInstructionsTable(data, &result.Header, info.Version, info.IsolateHeader)
	if err != nil {
		return fmt.Errorf("instrtable: %w", err)
	}

	ranges, err := cluster.ResolveCodeRanges(result.Codes, table)
	if err != nil {
		return fmt.Errorf("code ranges: %w", err)
	}

	code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data)
	if err != nil {
		return fmt.Errorf("code region: %w", err)
	}
	codeEndOffset := uint32(codeOff) + uint32(payloadLen)
	cluster.SetLastRangeSize(ranges, codeEndOffset)

	codeVA := info.IsolateInstructions.VA + codeOff

	// Build name lookup.
	refToStr := make(map[int]string)
	for _, ps := range result.Strings {
		refToStr[ps.RefID] = ps.Value
	}

	refToNamed := make(map[int]*cluster.NamedObject)
	for i := range result.Named {
		no := &result.Named[i]
		refToNamed[no.RefID] = no
	}

	resolveName := func(no *cluster.NamedObject) string {
		if no.NameRefID >= 0 {
			if s, ok := refToStr[no.NameRefID]; ok {
				return s
			}
		}
		return ""
	}

	resolveOwnerName := func(no *cluster.NamedObject) string {
		if no.OwnerRefID < 0 {
			return ""
		}
		if owner, ok := refToNamed[no.OwnerRefID]; ok {
			return resolveName(owner)
		}
		return ""
	}

	type codeInfo struct {
		funcName  string
		ownerName string
	}
	codeNames := make(map[int]codeInfo)
	for _, ce := range result.Codes {
		if ce.OwnerRef <= 0 {
			continue
		}
		owner, ok := refToNamed[ce.OwnerRef]
		if !ok {
			continue
		}
		codeNames[ce.RefID] = codeInfo{
			funcName:  resolveName(owner),
			ownerName: resolveOwnerName(owner),
		}
	}

	// Build symbol map.
	symbols := make(map[uint64]string)
	for _, r := range ranges {
		va := codeVA + uint64(r.PCOffset) - codeOff
		ci := codeNames[r.RefID]
		name := qualifiedName(ci.ownerName, ci.funcName, r.PCOffset)
		symbols[va] = name
	}
	lookup := disasm.PlaceholderLookup(symbols)

	// THR fields for resolved marking.
	thrFields := disasm.THRFields(dartVersion)

	// Open output.
	outFile, err := os.Create(*outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer outFile.Close()
	enc := json.NewEncoder(outFile)
	enc.SetEscapeHTML(false)

	// Derive sample name from libapp path.
	sample := *libapp

	n := len(ranges)
	if *limit > 0 && *limit < n {
		n = *limit
	}

	var totalAccesses, resolvedCount, unresolvedCount int

	for i := 0; i < n; i++ {
		r := &ranges[i]
		if r.Size == 0 {
			continue
		}

		funcStart := uint64(r.PCOffset) - codeOff
		funcEnd := funcStart + uint64(r.Size)
		if funcEnd > uint64(len(code)) {
			funcEnd = uint64(len(code))
		}
		if funcStart >= funcEnd {
			continue
		}
		funcCode := code[funcStart:funcEnd]
		funcVA := codeVA + funcStart

		ci := codeNames[r.RefID]
		funcName := qualifiedName(ci.ownerName, ci.funcName, r.PCOffset)

		insts := disasm.Disassemble(funcCode, disasm.Options{
			BaseAddr: funcVA,
			Symbols:  lookup,
		})

		accesses := disasm.ExtractTHRAccesses(insts, thrFields)
		if len(accesses) == 0 {
			continue
		}

		records := disasm.BuildAuditRecords(accesses, insts, sample, dartVersion, funcName)
		for _, rec := range records {
			if err := enc.Encode(rec); err != nil {
				return fmt.Errorf("write record: %w", err)
			}
			totalAccesses++
			if rec.Resolved {
				resolvedCount++
			} else {
				unresolvedCount++
			}
		}
	}

	fmt.Fprintf(os.Stderr, "THR accesses: %d total, %d resolved, %d unresolved\n",
		totalAccesses, resolvedCount, unresolvedCount)
	fmt.Fprintf(os.Stderr, "wrote %s\n", *outPath)

	return nil
}
