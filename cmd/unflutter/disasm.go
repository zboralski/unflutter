package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/zboralski/lattice"
	"github.com/zboralski/lattice/render"
	"unflutter/internal/callgraph"
	"unflutter/internal/cluster"
	"unflutter/internal/dartfmt"
	"unflutter/internal/disasm"
	"unflutter/internal/elfx"
	"unflutter/internal/output"
	"unflutter/internal/snapshot"
)

type disasmIndexEntry struct {
	Name      string `json:"name"`
	OwnerName string `json:"owner_name,omitempty"`
	RefID     int    `json:"ref_id"`
	OwnerRef  int    `json:"owner_ref,omitempty"`
	PCOffset  uint32 `json:"pc_offset"`
	Size      uint32 `json:"size"`
	File      string `json:"file"`
}

func cmdDisasm(args []string) error {
	fs := flag.NewFlagSet("disasm", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	outDir := fs.String("out", "", "output directory")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	limit := fs.Int("limit", 0, "max functions to disassemble (0 = all)")
	graph := fs.Bool("graph", false, "build lattice call graph and CFG (writes DOT files)")

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

	ef, err := elfx.Open(*libapp)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer ef.Close()

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	if info.Version != nil && info.Version.DartVersion != "" {
		fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", info.Version.DartVersion)
	}
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

	// Parse instructions table from data image.
	table, err := cluster.ParseInstructionsTable(data, &result.Header, info.Version, info.IsolateHeader)
	if err != nil {
		return fmt.Errorf("instrtable: %w", err)
	}

	// Resolve code ranges (snapshot Code objects).
	codeRanges, err := cluster.ResolveCodeRanges(result.Codes, table)
	if err != nil {
		return fmt.Errorf("code ranges: %w", err)
	}

	// Resolve stub ranges (entries before FirstEntryWithCode).
	stubRanges := cluster.ResolveStubRanges(table)

	// Merge stubs + code into a single sorted range list.
	ranges := cluster.MergeRanges(stubRanges, codeRanges)

	// Set last range size from code region end.
	code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data)
	if err != nil {
		return fmt.Errorf("code region: %w", err)
	}
	codeEndOffset := uint32(codeOff) + uint32(payloadLen)
	cluster.SetLastRangeSize(ranges, codeEndOffset)

	codeVA := info.IsolateInstructions.VA + codeOff

	fmt.Fprintf(os.Stderr, "code region: %d bytes at VA 0x%x (offset 0x%x in image)\n",
		payloadLen, codeVA, codeOff)
	fmt.Fprintf(os.Stderr, "instructions table: %d entries, %d stubs + %d code\n",
		table.Length, table.FirstEntryWithCode, int(table.Length)-int(table.FirstEntryWithCode))
	fmt.Fprintf(os.Stderr, "resolved %d ranges (%d stubs + %d code)\n",
		len(ranges), len(stubRanges), len(codeRanges))

	// Create output directory (must exist before any file creation).
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("mkdir output: %w", err)
	}

	// Build name lookups and pool display map.
	pl := buildPoolLookups(result, info.Version.CIDs, nil)
	poolDisplay := resolvePoolDisplay(result.Pool, pl)

	// Build and write class layouts.
	classLayouts := buildClassLayouts(result, pl, info.Version.CompressedPointers)
	if len(classLayouts) > 0 {
		classesPath := filepath.Join(*outDir, "classes.jsonl")
		classesFile, err := os.Create(classesPath)
		if err != nil {
			return fmt.Errorf("create classes.jsonl: %w", err)
		}
		classesEnc := json.NewEncoder(classesFile)
		classesEnc.SetEscapeHTML(false)
		for i := range classLayouts {
			if err := classesEnc.Encode(&classLayouts[i]); err != nil {
				classesFile.Close()
				return fmt.Errorf("write classes.jsonl: %w", err)
			}
		}
		classesFile.Close()
		fmt.Fprintf(os.Stderr, "classes: %d layouts written\n", len(classLayouts))
	}

	// Write dart_meta.json — snapshot metadata for downstream tools (ghidra-meta, etc.).
	thrFields := disasm.THRFields(info.Version.DartVersion)
	ptrSize := 8
	if info.Version.CompressedPointers {
		ptrSize = 4
	}
	if err := writeDartMeta(*outDir, info.Version.DartVersion, info.Version.CompressedPointers, ptrSize, thrFields); err != nil {
		return fmt.Errorf("write dart_meta.json: %w", err)
	}

	// Build symbol map for cross-references during disassembly.
	symbols := make(map[uint64]string)
	for _, r := range ranges {
		va := codeVA + uint64(r.PCOffset) - codeOff
		if r.RefID >= 0 {
			symbols[va] = qualifiedCodeName(r.RefID, pl, r.PCOffset)
		} else {
			symbols[va] = fmt.Sprintf("stub_%x", r.PCOffset)
		}
	}
	lookup := disasm.PlaceholderLookup(symbols)

	ppAnn := disasm.PPAnnotator(poolDisplay)
	peephole := disasm.NewPeepholeState(poolDisplay)

	fmt.Fprintf(os.Stderr, "pool: %d entries (%d resolved)\n", len(result.Pool), len(poolDisplay))

	// Create output directories.
	asmDir := filepath.Join(*outDir, "asm")
	if err := os.MkdirAll(asmDir, 0755); err != nil {
		return fmt.Errorf("mkdir asm: %w", err)
	}
	cfgDir := filepath.Join(*outDir, "cfg")
	if *graph {
		if err := os.MkdirAll(cfgDir, 0755); err != nil {
			return fmt.Errorf("mkdir cfg: %w", err)
		}
	}

	// Disassemble each function and write to files.
	n := len(ranges)
	if *limit > 0 && *limit < n {
		n = *limit
	}

	// Open all output files.
	indexPath := filepath.Join(*outDir, "index.jsonl")
	indexFile, err := os.Create(indexPath)
	if err != nil {
		return fmt.Errorf("create index: %w", err)
	}
	defer indexFile.Close()
	enc := json.NewEncoder(indexFile)
	enc.SetEscapeHTML(false)

	funcsPath := filepath.Join(*outDir, "functions.jsonl")
	funcsFile, err := os.Create(funcsPath)
	if err != nil {
		return fmt.Errorf("create functions.jsonl: %w", err)
	}
	defer funcsFile.Close()
	funcsEnc := json.NewEncoder(funcsFile)
	funcsEnc.SetEscapeHTML(false)

	edgesPath := filepath.Join(*outDir, "call_edges.jsonl")
	edgesFile, err := os.Create(edgesPath)
	if err != nil {
		return fmt.Errorf("create call_edges.jsonl: %w", err)
	}
	defer edgesFile.Close()
	edgesEnc := json.NewEncoder(edgesFile)
	edgesEnc.SetEscapeHTML(false)

	unresTHRPath := filepath.Join(*outDir, "unresolved_thr.jsonl")
	unresTHRFile, err := os.Create(unresTHRPath)
	if err != nil {
		return fmt.Errorf("create unresolved_thr.jsonl: %w", err)
	}
	defer unresTHRFile.Close()
	unresTHREnc := json.NewEncoder(unresTHRFile)
	unresTHREnc.SetEscapeHTML(false)

	stringRefsPath := filepath.Join(*outDir, "string_refs.jsonl")
	stringRefsFile, err := os.Create(stringRefsPath)
	if err != nil {
		return fmt.Errorf("create string_refs.jsonl: %w", err)
	}
	defer stringRefsFile.Close()
	stringRefsEnc := json.NewEncoder(stringRefsFile)
	stringRefsEnc.SetEscapeHTML(false)

	var written int
	var totalEdges, totalBLR, blrAnnotated, blrUnannotated int
	var totalUnresTHR int
	var totalStringRefs int
	var cfgCount int
	var funcInfos []callgraph.FuncInfo // lightweight: Name + CallEdges only (no Insts)
	for i := 0; i < n; i++ {
		r := &ranges[i]
		if r.Size == 0 {
			continue
		}

		// Slice code bytes for this function.
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

		// Resolve name.
		var funcName, ownerName, name string
		if r.RefID >= 0 {
			ci := pl.codeNames[r.RefID]
			funcName = ci.funcName
			ownerName = ci.ownerName
			name = qualifiedName(ownerName, funcName, r.PCOffset)
		} else {
			funcName = fmt.Sprintf("stub_%x", r.PCOffset)
			name = funcName
		}

		// Disassemble.
		peephole.Reset()
		insts := disasm.Disassemble(funcCode, disasm.Options{
			BaseAddr: funcVA,
			Symbols:  lookup,
		})

		// Build per-function annotators (THR context needs full instruction stream).
		thrCtxAnn := disasm.THRContextAnnotator(insts, thrFields)
		annotators := []disasm.Annotator{ppAnn, thrCtxAnn, peephole.Annotate}

		// Write asm file.
		filename := funcRelPath(ownerName, funcName, r.PCOffset)
		if err := output.WriteASM(*outDir, filename, insts, lookup, annotators...); err != nil {
			return fmt.Errorf("write asm %s: %w", filename, err)
		}

		// Write raw bytes for CFG construction.
		if err := output.WriteBin(*outDir, filename, funcCode); err != nil {
			return fmt.Errorf("write bin %s: %w", filename, err)
		}

		// Write index entry.
		entry := disasmIndexEntry{
			Name:      funcName,
			OwnerName: ownerName,
			RefID:     r.RefID,
			OwnerRef:  r.OwnerRef,
			PCOffset:  r.PCOffset,
			Size:      r.Size,
			File:      filepath.ToSlash(filepath.Join("asm", filename+".txt")),
		}
		if err := enc.Encode(entry); err != nil {
			return fmt.Errorf("write index: %w", err)
		}

		// Emit functions.jsonl entry.
		var paramCount int
		if r.RefID >= 0 {
			paramCount = pl.codeNames[r.RefID].paramCount
		}
		funcRec := disasm.FuncRecord{
			PC:         fmt.Sprintf("0x%x", funcVA),
			Size:       int(r.Size),
			Name:       name,
			Owner:      ownerName,
			ParamCount: paramCount,
		}
		if err := funcsEnc.Encode(funcRec); err != nil {
			return fmt.Errorf("write functions.jsonl: %w", err)
		}

		// Extract call edges with W=8 register tracking.
		edges := disasm.ExtractCallEdges(insts, lookup, annotators, 8)
		for _, e := range edges {
			rec := disasm.CallEdgeRecord{
				FromFunc: name,
				FromPC:   fmt.Sprintf("0x%x", e.FromPC),
				Kind:     e.Kind,
				Reg:      e.Reg,
				Via:      e.Via,
			}
			if e.Kind == "bl" {
				if e.TargetName != "" {
					rec.Target = e.TargetName
				} else {
					rec.Target = fmt.Sprintf("0x%x", e.TargetPC)
				}
			}
			if err := edgesEnc.Encode(rec); err != nil {
				return fmt.Errorf("write call_edges.jsonl: %w", err)
			}
			totalEdges++
			if e.Kind == "blr" {
				totalBLR++
				if e.Via != "" {
					blrAnnotated++
				} else {
					blrUnannotated++
				}
			}
		}

		// Build per-function CFG DOT and accumulate for call graph.
		if *graph {
			// Per-function CFG: build, convert, render, write.
			lcfg, nblocks := callgraph.BuildFuncCFG(name, insts, edges)
			if nblocks > 1 {
				g := &lattice.CFGGraph{Funcs: []*lattice.FuncCFG{lcfg}}
				dot := render.DOTCFG(g, name)
				dotPath := filepath.Join(cfgDir, filename+".dot")
				if err := os.MkdirAll(filepath.Dir(dotPath), 0755); err != nil {
					return fmt.Errorf("mkdir cfg: %w", err)
				}
				if err := os.WriteFile(dotPath, []byte(dot), 0644); err != nil {
					return fmt.Errorf("write cfg dot %s: %w", filename, err)
				}
				cfgCount++
			}
			// Lightweight accumulation for call graph (no Insts).
			funcInfos = append(funcInfos, callgraph.FuncInfo{
				Name:      name,
				CallEdges: edges,
			})
		}

		// Extract string references from PP loads.
		stringRefs := extractStringRefs(insts, poolDisplay, name)
		for _, sr := range stringRefs {
			if err := stringRefsEnc.Encode(sr); err != nil {
				return fmt.Errorf("write string_refs.jsonl: %w", err)
			}
			totalStringRefs++
		}

		// Extract unresolved THR accesses.
		thrAccesses := disasm.ExtractTHRAccesses(insts, thrFields)
		for _, a := range thrAccesses {
			if a.Resolved {
				continue
			}
			// Classify using instruction context.
			rec := disasm.UnresolvedTHRRecord{
				FuncName:  name,
				PC:        fmt.Sprintf("0x%x", a.PC),
				THROffset: fmt.Sprintf("0x%x", a.THROffset),
				Width:     a.Width,
				IsStore:   a.IsStore,
				Class:     "UNKNOWN",
			}
			// Use THR context annotator result for classification.
			if ann := thrCtxAnn(disasm.Inst{Addr: a.PC, Raw: 0}); ann != "" {
				// Parse classification from the annotation.
				switch {
				case strings.Contains(ann, "RUNTIME_ENTRY"):
					rec.Class = "RUNTIME_ENTRY"
				case strings.Contains(ann, "OBJSTORE"):
					rec.Class = "OBJSTORE"
				case strings.Contains(ann, "ISO_GROUP"):
					rec.Class = "ISO_GROUP"
				case strings.HasPrefix(ann, "THR."):
					// Already resolved by name — shouldn't be here.
					continue
				}
			}
			if err := unresTHREnc.Encode(rec); err != nil {
				return fmt.Errorf("write unresolved_thr.jsonl: %w", err)
			}
			totalUnresTHR++
		}

		written++
	}

	fmt.Fprintf(os.Stderr, "wrote %d function disassemblies to %s\n", written, asmDir)
	fmt.Fprintf(os.Stderr, "wrote %s (%d entries)\n", indexPath, written)
	fmt.Fprintf(os.Stderr, "wrote %s (%d functions)\n", funcsPath, written)
	fmt.Fprintf(os.Stderr, "wrote %s (%d edges, %d BLR: %d annotated, %d unannotated)\n",
		edgesPath, totalEdges, totalBLR, blrAnnotated, blrUnannotated)
	fmt.Fprintf(os.Stderr, "wrote %s (%d unresolved THR accesses)\n", unresTHRPath, totalUnresTHR)
	fmt.Fprintf(os.Stderr, "wrote %s (%d string references)\n", stringRefsPath, totalStringRefs)
	if totalBLR > 0 {
		pct := float64(blrAnnotated) / float64(totalBLR) * 100
		fmt.Fprintf(os.Stderr, "BLR annotation rate: %.1f%%\n", pct)
	}

	// Build call graph and write DOT output.
	if *graph && len(funcInfos) > 0 {
		cg := callgraph.BuildCallGraph(funcInfos)
		cgDOT := render.DOT(cg, "callgraph")
		cgPath := filepath.Join(*outDir, "callgraph.dot")
		if err := os.WriteFile(cgPath, []byte(cgDOT), 0644); err != nil {
			return fmt.Errorf("write callgraph.dot: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d nodes, %d edges)\n",
			cgPath, len(cg.Nodes), len(cg.Edges))
		fmt.Fprintf(os.Stderr, "wrote %d per-function CFG DOTs to %s\n", cfgCount, cfgDir)
	}

	return nil
}

// extractStringRefs scans instructions for PP loads that resolve to string values.
// poolDisplay maps pool index → display string (strings are Go-quoted with %q).
func extractStringRefs(insts []disasm.Inst, poolDisplay map[int]string, funcName string) []disasm.StringRefRecord {
	var refs []disasm.StringRefRecord
	peep := disasm.NewPeepholeState(poolDisplay)

	for _, inst := range insts {
		// Check single-instruction PP load: LDR Xt, [X27, #imm]
		if baseReg, byteOff, ok := disasm.IsLDR64UnsignedOffsetExported(inst.Raw); ok && baseReg == 27 {
			idx := byteOff / 8
			if s, found := poolDisplay[idx]; found && len(s) > 0 && s[0] == '"' {
				val, err := strconv.Unquote(s)
				if err == nil {
					refs = append(refs, disasm.StringRefRecord{
						Func:    funcName,
						PC:      fmt.Sprintf("0x%x", inst.Addr),
						Kind:    "PP",
						PoolIdx: idx,
						Value:   val,
					})
				}
			}
		}

		// Check two-instruction peephole: ADD Xd, X27, #upper + LDR Xt, [Xd, #lower]
		ann := peep.Annotate(inst)
		if ann != "" && strings.HasPrefix(ann, "PP[") {
			// Parse "PP[N] "string""
			// Find the index and check if value is quoted.
			closeBracket := strings.IndexByte(ann, ']')
			if closeBracket > 3 {
				idxStr := ann[3:closeBracket]
				idx, err := strconv.Atoi(idxStr)
				if err == nil {
					rest := strings.TrimSpace(ann[closeBracket+1:])
					if len(rest) > 0 && rest[0] == '"' {
						val, err := strconv.Unquote(rest)
						if err == nil {
							refs = append(refs, disasm.StringRefRecord{
								Func:    funcName,
								PC:      fmt.Sprintf("0x%x", inst.Addr),
								Kind:    "PP_peep",
								PoolIdx: idx,
								Value:   val,
							})
						}
					}
				}
			}
		}
	}
	return refs
}

// qualifiedName builds "Owner.FuncName_hexaddr" like blutter.
// The hex suffix eliminates all filename collisions.
func qualifiedName(ownerName, funcName string, pcOffset uint32) string {
	suffix := fmt.Sprintf("_%x", pcOffset)
	if funcName == "" {
		return "sub" + suffix
	}
	if ownerName != "" {
		return ownerName + "." + funcName + suffix
	}
	return funcName + suffix
}

// dartMetaJSON is the structure written to dart_meta.json.
type dartMetaJSON struct {
	DartVersion        string             `json:"dart_version"`
	CompressedPointers bool               `json:"compressed_pointers"`
	PointerSize        int                `json:"pointer_size"`
	THRFields          []dartMetaTHRField `json:"thr_fields"`
}

type dartMetaTHRField struct {
	Offset int    `json:"offset"`
	Name   string `json:"name"`
}

// writeDartMeta writes dart_meta.json with snapshot metadata for downstream tools.
func writeDartMeta(outDir, dartVersion string, compressed bool, ptrSize int, thrFields map[int]string) error {
	// Convert THR fields map to sorted slice.
	fields := make([]dartMetaTHRField, 0, len(thrFields))
	for off, name := range thrFields {
		fields = append(fields, dartMetaTHRField{Offset: off, Name: name})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Offset < fields[j].Offset })

	meta := dartMetaJSON{
		DartVersion:        dartVersion,
		CompressedPointers: compressed,
		PointerSize:        ptrSize,
		THRFields:          fields,
	}

	f, err := os.Create(filepath.Join(outDir, "dart_meta.json"))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(meta); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// sanitizeFilename makes a string safe for use as a filename.
func sanitizeFilename(name string) string {
	r := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)
	s := r.Replace(name)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// funcRelPath returns a relative path like "OwnerClass/funcName_hex" for functions
// with an owner, or "funcName_hex" for ownerless functions. This creates a
// directory structure in asm/, cfg/, and decompiled/ grouped by class.
func funcRelPath(ownerName, funcName string, pcOffset uint32) string {
	suffix := fmt.Sprintf("_%x", pcOffset)
	var fpart string
	if funcName == "" {
		fpart = "sub" + suffix
	} else {
		fpart = sanitizeFilename(funcName + suffix)
	}
	if ownerName != "" {
		return sanitizeFilename(ownerName) + "/" + fpart
	}
	return fpart
}

// funcRelPathFromQualified reconstructs the relative path from a qualified name
// (e.g., "OwnerClass.funcName_hex") and its owner. Used by post-disasm commands
// (signal, decompile) that read functions.jsonl.
func funcRelPathFromQualified(qualifiedName, owner string) string {
	if owner != "" {
		prefix := owner + "."
		funcPart := qualifiedName
		if strings.HasPrefix(qualifiedName, prefix) {
			funcPart = qualifiedName[len(prefix):]
		}
		return sanitizeFilename(owner) + "/" + sanitizeFilename(funcPart)
	}
	return sanitizeFilename(qualifiedName)
}
