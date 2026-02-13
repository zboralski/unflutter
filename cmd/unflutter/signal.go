package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"unflutter/internal/disasm"
	"unflutter/internal/render"
	"unflutter/internal/signal"
)

func cmdSignal(args []string) error {
	fs := flag.NewFlagSet("signal", flag.ExitOnError)
	inDir := fs.String("in", "", "input directory (disasm output)")
	k := fs.Int("k", 2, "context hops from signal functions")
	outPath := fs.String("out", "", "output HTML file (default: <in>/signal.html)")
	noAsm := fs.Bool("no-asm", false, "skip loading asm snippets")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inDir == "" {
		return fmt.Errorf("--in is required")
	}
	if *outPath == "" {
		*outPath = filepath.Join(*inDir, "signal.html")
	}

	// Read functions.jsonl.
	funcs, err := readJSONL[disasm.FuncRecord](filepath.Join(*inDir, "functions.jsonl"))
	if err != nil {
		return fmt.Errorf("read functions.jsonl: %w", err)
	}
	fmt.Fprintf(os.Stderr, "read %d functions\n", len(funcs))

	// Read call_edges.jsonl.
	edges, err := readJSONL[disasm.CallEdgeRecord](filepath.Join(*inDir, "call_edges.jsonl"))
	if err != nil {
		return fmt.Errorf("read call_edges.jsonl: %w", err)
	}
	fmt.Fprintf(os.Stderr, "read %d call edges\n", len(edges))

	// Read string_refs.jsonl.
	stringRefsPath := filepath.Join(*inDir, "string_refs.jsonl")
	stringRefs, err := readJSONL[disasm.StringRefRecord](stringRefsPath)
	if err != nil {
		return fmt.Errorf("read string_refs.jsonl: %w", err)
	}
	fmt.Fprintf(os.Stderr, "read %d string refs\n", len(stringRefs))

	// Compute entry points.
	entryList := render.FindEntryPoints(funcs, edges)
	entrySet := make(map[string]bool, len(entryList))
	for _, ep := range entryList {
		entrySet[ep] = true
	}
	fmt.Fprintf(os.Stderr, "found %d entry points\n", len(entryList))

	// Build signal graph.
	g := signal.BuildSignalGraph(funcs, edges, stringRefs, *k, entrySet)
	fmt.Fprintf(os.Stderr, "signal graph: %d signal + %d context = %d functions, %d edges\n",
		g.Stats.SignalFuncs, g.Stats.ContextFuncs,
		g.Stats.SignalFuncs+g.Stats.ContextFuncs, g.Stats.TotalEdges)
	for cat, count := range g.Stats.Categories {
		fmt.Fprintf(os.Stderr, "  %s: %d\n", cat, count)
	}

	// Load asm snippets: full for signal, truncated for context, none for other.
	const contextAsmLines = 30
	asmSnippets := make(map[string]string)
	if !*noAsm {
		asmDir := filepath.Join(*inDir, "asm")
		for _, sf := range g.Funcs {
			if sf.Role == "" {
				continue // skip "other" (no role) functions
			}
			relPath := funcRelPathFromQualified(sf.Name, sf.Owner)
			path := filepath.Join(asmDir, relPath+".txt")
			data, err := os.ReadFile(path)
			if err != nil {
				// Fallback: flat layout (pre-subdirectory disasm output).
				flatPath := filepath.Join(asmDir, sanitizeFilename(sf.Name)+".txt")
				data, err = os.ReadFile(flatPath)
				if err != nil {
					continue
				}
			}
			s := strings.TrimRight(string(data), "\n")
			if sf.Role == "context" {
				// Truncate context functions to first N lines.
				lines := strings.SplitN(s, "\n", contextAsmLines+1)
				if len(lines) > contextAsmLines {
					s = strings.Join(lines[:contextAsmLines], "\n") + "\n[... truncated]"
				}
			}
			asmSnippets[sf.Name] = s
		}
		fmt.Fprintf(os.Stderr, "loaded %d asm snippets\n", len(asmSnippets))
	}

	// Write signal_graph.json.
	jsonPath := filepath.Join(filepath.Dir(*outPath), "signal_graph.json")
	jsonFile, err := os.Create(jsonPath)
	if err != nil {
		return fmt.Errorf("create signal_graph.json: %w", err)
	}
	enc := json.NewEncoder(jsonFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(g); err != nil {
		jsonFile.Close()
		return fmt.Errorf("write signal_graph.json: %w", err)
	}
	jsonFile.Close()
	fi, _ := os.Stat(jsonPath)
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", jsonPath, fi.Size())

	// Write signal.html.
	htmlFile, err := os.Create(*outPath)
	if err != nil {
		return fmt.Errorf("create signal.html: %w", err)
	}
	title := "unflutter"
	// Try to get digest from parent dir name (typically the hash).
	digest := filepath.Base(filepath.Dir(*inDir))
	// Use relative in-dir as filename.
	filename := *inDir
	// Try meta.json for source path.
	if metaBytes, err := os.ReadFile(filepath.Join(filepath.Dir(*inDir), "meta.json")); err == nil {
		var meta struct {
			Hash   string `json:"hash"`
			Source string `json:"source"`
		}
		if json.Unmarshal(metaBytes, &meta) == nil {
			if meta.Hash != "" {
				digest = meta.Hash
			}
			if meta.Source != "" {
				filename = filepath.Base(meta.Source)
			}
		}
	}
	render.WriteSignalHTML(htmlFile, g, title, filename, digest, asmSnippets)
	if err := htmlFile.Close(); err != nil {
		return fmt.Errorf("close signal.html: %w", err)
	}
	fi, _ = os.Stat(*outPath)
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", *outPath, fi.Size())

	// Write signal.dot.
	dotPath := filepath.Join(filepath.Dir(*outPath), "signal.dot")
	dotContent := render.SignalDOT(g, title, render.NASA)
	if err := os.WriteFile(dotPath, []byte(dotContent), 0644); err != nil {
		return fmt.Errorf("write signal.dot: %w", err)
	}
	fi, _ = os.Stat(dotPath)
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", dotPath, fi.Size())

	// Build connected signal CFG (re-disassemble from bin files for call/string content).
	if !*noAsm {
		content := buildSignalContent(g, *inDir, funcs, edges)
		if len(content) > 0 {
			cfgTitle := "signal CFG"
			if title != "" {
				cfgTitle = title + " — signal CFG"
			}
			cfgDOT := render.SignalCFGDOT(g, content, cfgTitle, render.NASA)
			cfgPath := filepath.Join(filepath.Dir(*outPath), "signal_cfg.dot")
			if err := os.WriteFile(cfgPath, []byte(cfgDOT), 0644); err != nil {
				return fmt.Errorf("write signal_cfg.dot: %w", err)
			}
			fi, _ = os.Stat(cfgPath)
			fmt.Fprintf(os.Stderr, "wrote %s (%d functions, %d bytes)\n", cfgPath, len(content), fi.Size())
		}
	}

	// Render SVG via dot if available.
	dotBin, err := exec.LookPath("dot")
	if err != nil {
		outDir := filepath.Dir(*outPath)
		fmt.Fprintf(os.Stderr, "\ndot not found in PATH; SVG not generated.\n")
		fmt.Fprintf(os.Stderr, "Install Graphviz to auto-render SVG:\n")
		fmt.Fprintf(os.Stderr, "  brew install graphviz        # macOS\n")
		fmt.Fprintf(os.Stderr, "  apt install graphviz         # Debian/Ubuntu\n")
		fmt.Fprintf(os.Stderr, "Or render manually:\n")
		fmt.Fprintf(os.Stderr, "  dot -Tsvg -o %s/signal.svg %s\n", outDir, dotPath)
		cfgDotPath := filepath.Join(outDir, "signal_cfg.dot")
		if _, statErr := os.Stat(cfgDotPath); statErr == nil {
			fmt.Fprintf(os.Stderr, "  dot -Tsvg -o %s/signal_cfg.svg %s\n", outDir, cfgDotPath)
		}
	} else {
		dotFiles := []string{dotPath}
		cfgDotPath := filepath.Join(filepath.Dir(*outPath), "signal_cfg.dot")
		if _, statErr := os.Stat(cfgDotPath); statErr == nil {
			dotFiles = append(dotFiles, cfgDotPath)
		}
		for _, df := range dotFiles {
			svgPath := strings.TrimSuffix(df, ".dot") + ".svg"
			cmd := exec.Command(dotBin, "-Tsvg", "-o", svgPath, df)
			if out, err := cmd.CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "dot render failed for %s: %v\n%s\n", filepath.Base(df), err, out)
			} else {
				fi, _ = os.Stat(svgPath)
				fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", svgPath, fi.Size())
			}
		}
	}

	return nil
}

// buildSignalContent re-disassembles signal functions from bin files and extracts
// interesting calls and string refs for each function.
func buildSignalContent(
	g *signal.SignalGraph,
	inDir string,
	funcs []disasm.FuncRecord,
	edgeRecords []disasm.CallEdgeRecord,
) map[string]*render.SignalFuncContent {
	// Index call edges by function name → []CallEdge.
	edgesByFunc := make(map[string][]disasm.CallEdge)
	for _, er := range edgeRecords {
		pc := parseHexAddr(er.FromPC)
		ce := disasm.CallEdge{
			FromPC:     pc,
			Kind:       er.Kind,
			TargetName: er.Target,
			TargetPC:   parseHexAddr(er.Target),
			Via:        er.Via,
		}
		edgesByFunc[er.FromFunc] = append(edgesByFunc[er.FromFunc], ce)
	}

	// Index functions by name for base address lookup.
	funcByName := make(map[string]disasm.FuncRecord, len(funcs))
	for _, f := range funcs {
		funcByName[f.Name] = f
	}

	asmDir := filepath.Join(inDir, "asm")
	result := make(map[string]*render.SignalFuncContent)

	for _, sf := range g.Funcs {
		if sf.Role != "signal" {
			continue
		}
		fr, ok := funcByName[sf.Name]
		if !ok {
			continue
		}

		// Read bin file (raw ARM64 bytes).
		relPath := funcRelPathFromQualified(sf.Name, sf.Owner)
		binPath := filepath.Join(asmDir, relPath+".bin")
		data, err := os.ReadFile(binPath)
		if err != nil {
			// Fallback: flat layout.
			binPath = filepath.Join(asmDir, sanitizeFilename(sf.Name)+".bin")
			data, err = os.ReadFile(binPath)
		}
		if err != nil || len(data) < 4 {
			continue
		}

		baseAddr := parseHexAddr(fr.PC)
		if baseAddr == 0 {
			continue
		}

		// Re-disassemble.
		insts := disasm.Disassemble(data, disasm.Options{BaseAddr: baseAddr})
		if len(insts) == 0 {
			continue
		}

		// Build PC→edge map for O(1) lookup.
		funcEdges := edgesByFunc[sf.Name]
		edgeByPC := make(map[uint64]disasm.CallEdge, len(funcEdges))
		for _, e := range funcEdges {
			edgeByPC[e.FromPC] = e
		}
		// Collect interesting calls from re-disassembly.
		seenCalls := make(map[string]bool)
		var calls []string
		for _, inst := range insts {
			if e, ok := edgeByPC[inst.Addr]; ok {
				callee := e.TargetName
				if callee == "" {
					callee = e.Via
				}
				if isInterestingCallee(callee) && !seenCalls[callee] {
					seenCalls[callee] = true
					calls = append(calls, callee)
				}
			}
		}

		// Use classified string refs from signal graph (already categorized).
		seenStrs := make(map[string]bool)
		var strs []render.ClassifiedString
		for _, sr := range sf.StringRefs {
			if seenStrs[sr.Value] {
				continue
			}
			seenStrs[sr.Value] = true
			cat := ""
			if len(sr.Categories) > 0 {
				cat = sr.Categories[0]
			}
			strs = append(strs, render.ClassifiedString{Value: sr.Value, Category: cat})
		}

		if len(calls) > 0 || len(strs) > 0 {
			result[sf.Name] = &render.SignalFuncContent{
				Calls:   calls,
				Strings: strs,
			}
		}
	}

	return result
}

// isInterestingCallee returns true if the callee name represents a real named
// function rather than VM internals, stubs, or dispatch noise.
func isInterestingCallee(name string) bool {
	if name == "" {
		return false
	}
	switch {
	case len(name) > 4 && name[:4] == "sub_":
		return false
	case len(name) > 2 && name[0] == '0' && name[1] == 'x':
		return false
	case name == "dispatch_table" || name == "object_field":
		return false
	case len(name) > 4 && name[:4] == "THR.":
		return false
	case len(name) > 3 && name[:3] == "PP[":
		return false
	}
	return true
}

// parseHexAddr parses "0x..." hex address strings. Returns 0 on failure.
func parseHexAddr(s string) uint64 {
	s = strings.TrimPrefix(s, "0x")
	v, _ := strconv.ParseUint(s, 16, 64)
	return v
}
