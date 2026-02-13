package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"unflutter/internal/disasm"
	"unflutter/internal/signal"
)

// ghidraMetaFunc is a function entry in ghidra_meta.json.
type ghidraMetaFunc struct {
	Addr       string `json:"addr"`
	Name       string `json:"name"`
	Size       int    `json:"size"`
	Owner      string `json:"owner,omitempty"`
	ParamCount int    `json:"param_count,omitempty"`
}

// ghidraMetaComment is a comment entry in ghidra_meta.json.
type ghidraMetaComment struct {
	Addr string `json:"addr"`
	Text string `json:"text"`
}

// ghidraMetaTHRField is a THR (thread) struct field.
type ghidraMetaTHRField struct {
	Offset int    `json:"offset"`
	Name   string `json:"name"`
}

// ghidraMetaJSON is the top-level ghidra_meta.json structure.
type ghidraMetaJSON struct {
	Version        string               `json:"version"`
	DartVersion    string               `json:"dart_version,omitempty"`
	PointerSize    int                  `json:"pointer_size,omitempty"`
	Functions      []ghidraMetaFunc     `json:"functions"`
	Comments       []ghidraMetaComment  `json:"comments"`
	FocusFunctions []string             `json:"focus_functions,omitempty"`
	Classes        []DartClassLayout    `json:"classes,omitempty"`
	THRFields      []ghidraMetaTHRField `json:"thr_fields,omitempty"`
}

// asmCommentRe matches annotated asm lines: address + instruction + "; comment"
var asmCommentRe = regexp.MustCompile(`^(0x[0-9a-fA-F]+)\s+.*;\s+(.+)$`)

func cmdGhidraMeta(args []string) error {
	fs := flag.NewFlagSet("ghidra-meta", flag.ExitOnError)
	inDir := fs.String("in", "", "input directory (disasm output)")
	outPath := fs.String("out", "", "output JSON file (default: <in>/ghidra_meta.json)")
	decompAll := fs.Bool("decompile-all", false, "decompile ALL functions (default: signal functions only)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inDir == "" {
		return fmt.Errorf("--in is required")
	}
	if *outPath == "" {
		*outPath = filepath.Join(*inDir, "ghidra_meta.json")
	}

	// 1. Read functions.jsonl.
	funcs, err := readJSONL[disasm.FuncRecord](filepath.Join(*inDir, "functions.jsonl"))
	if err != nil {
		return fmt.Errorf("read functions.jsonl: %w", err)
	}
	fmt.Fprintf(os.Stderr, "read %d functions\n", len(funcs))

	metaFuncs := make([]ghidraMetaFunc, len(funcs))
	for i, f := range funcs {
		metaFuncs[i] = ghidraMetaFunc{
			Addr:       f.PC,
			Name:       f.Name,
			Size:       f.Size,
			Owner:      f.Owner,
			ParamCount: f.ParamCount,
		}
	}

	// 2. Determine which functions to decompile.
	var focusFuncs []string
	if *decompAll {
		// Decompile ALL functions.
		for _, f := range funcs {
			focusFuncs = append(focusFuncs, f.PC)
		}
		fmt.Fprintf(os.Stderr, "decompile: ALL %d functions\n", len(focusFuncs))
	} else {
		// Default: signal functions only (from signal_graph.json).
		sgPath := filepath.Join(*inDir, "signal_graph.json")
		if data, err := os.ReadFile(sgPath); err == nil {
			var sg signal.SignalGraph
			if err := json.Unmarshal(data, &sg); err == nil {
				for _, sf := range sg.Funcs {
					if sf.Role == "signal" {
						focusFuncs = append(focusFuncs, sf.PC)
					}
				}
			}
		}
		fmt.Fprintf(os.Stderr, "decompile: %d signal functions (use --all to decompile everything)\n", len(focusFuncs))
	}

	// 2b. Read dart_meta.json for pointer size and THR fields (best-effort).
	var pointerSize int
	var dartVersion string
	var thrFields []ghidraMetaTHRField
	dmPath := filepath.Join(*inDir, "dart_meta.json")
	if dmData, err := os.ReadFile(dmPath); err == nil {
		var dm struct {
			DartVersion string `json:"dart_version"`
			PointerSize int    `json:"pointer_size"`
			THRFields   []struct {
				Offset int    `json:"offset"`
				Name   string `json:"name"`
			} `json:"thr_fields"`
		}
		if err := json.Unmarshal(dmData, &dm); err == nil {
			dartVersion = dm.DartVersion
			pointerSize = dm.PointerSize
			for _, f := range dm.THRFields {
				thrFields = append(thrFields, ghidraMetaTHRField{Offset: f.Offset, Name: f.Name})
			}
			fmt.Fprintf(os.Stderr, "read dart_meta.json: dart=%s ptr_size=%d thr_fields=%d\n",
				dartVersion, pointerSize, len(thrFields))
		}
	} else {
		fmt.Fprintf(os.Stderr, "warning: dart_meta.json: %v (pointer size defaults to 8)\n", err)
		pointerSize = 8
	}

	// 2c. Read class layouts (best-effort).
	classLayouts, err := readJSONL[DartClassLayout](filepath.Join(*inDir, "classes.jsonl"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: classes.jsonl: %v (skipping struct export)\n", err)
		classLayouts = nil
	} else {
		fmt.Fprintf(os.Stderr, "read %d class layouts\n", len(classLayouts))
	}

	// 3. Extract comments from asm/*.txt files.
	asmDir := filepath.Join(*inDir, "asm")
	comments, err := extractAsmComments(asmDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: asm comment extraction: %v\n", err)
		comments = nil
	}
	fmt.Fprintf(os.Stderr, "extracted %d comments from asm files\n", len(comments))

	// 3b. Merge string references as comments.
	// String refs from PP loads get inline comments like: str: "hello world"
	stringRefs, err := readJSONL[disasm.StringRefRecord](filepath.Join(*inDir, "string_refs.jsonl"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: string_refs.jsonl: %v (skipping string comments)\n", err)
	} else {
		// Build set of existing comment addresses to avoid duplicates.
		seen := make(map[string]bool, len(comments))
		for _, c := range comments {
			seen[c.Addr] = true
		}
		strAdded := 0
		for _, sr := range stringRefs {
			addr := normalizeHexAddr(sr.PC)
			if seen[addr] {
				continue
			}
			seen[addr] = true
			// Truncate long strings for readability.
			val := sr.Value
			if len(val) > 80 {
				val = val[:77] + "..."
			}
			comments = append(comments, ghidraMetaComment{
				Addr: addr,
				Text: fmt.Sprintf("str: %q", val),
			})
			strAdded++
		}
		fmt.Fprintf(os.Stderr, "added %d string reference comments\n", strAdded)
	}

	// 4. Write ghidra_meta.json.
	meta := ghidraMetaJSON{
		Version:        "1",
		DartVersion:    dartVersion,
		PointerSize:    pointerSize,
		Functions:      metaFuncs,
		Comments:       comments,
		FocusFunctions: focusFuncs,
		Classes:        classLayouts,
		THRFields:      thrFields,
	}

	f, err := os.Create(*outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(meta); err != nil {
		f.Close()
		return fmt.Errorf("write json: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}

	fi, _ := os.Stat(*outPath)
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", *outPath, fi.Size())
	fmt.Fprintf(os.Stderr, "  functions:  %d\n", len(metaFuncs))
	fmt.Fprintf(os.Stderr, "  comments:   %d\n", len(comments))
	fmt.Fprintf(os.Stderr, "  focus:      %d\n", len(focusFuncs))
	fmt.Fprintf(os.Stderr, "  classes:    %d\n", len(classLayouts))
	fmt.Fprintf(os.Stderr, "  ptr_size:   %d\n", pointerSize)
	fmt.Fprintf(os.Stderr, "  thr_fields: %d\n", len(thrFields))

	return nil
}

// extractAsmComments parses all .txt files in asmDir for instruction-level
// annotations ("; THR.xxx", "; PP[N] xxx", etc.) and returns comment records.
func extractAsmComments(asmDir string) ([]ghidraMetaComment, error) {
	entries, err := os.ReadDir(asmDir)
	if err != nil {
		return nil, err
	}

	var comments []ghidraMetaComment
	seen := make(map[string]bool) // deduplicate by address

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		path := filepath.Join(asmDir, entry.Name())
		fc, err := extractFileComments(path, seen)
		if err != nil {
			continue // skip unreadable files
		}
		comments = append(comments, fc...)
	}

	return comments, nil
}

// extractFileComments parses a single asm file for annotation comments.
func extractFileComments(path string, seen map[string]bool) ([]ghidraMetaComment, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var comments []ghidraMetaComment
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		m := asmCommentRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		addr := normalizeHexAddr(m[1])
		text := strings.TrimSpace(m[2])

		// Skip function entry labels like "<FuncName>"
		if strings.HasPrefix(text, "<") && strings.HasSuffix(text, ">") {
			continue
		}

		// Deduplicate: same address can appear in multiple asm files (unlikely but safe).
		if seen[addr] {
			continue
		}
		seen[addr] = true

		comments = append(comments, ghidraMetaComment{
			Addr: addr,
			Text: text,
		})
	}

	return comments, scanner.Err()
}

// normalizeHexAddr strips leading zeros: "0x000652e4" → "0x652e4".
func normalizeHexAddr(s string) string {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return s
	}
	v, err := strconv.ParseUint(s[2:], 16, 64)
	if err != nil {
		return s
	}
	return fmt.Sprintf("0x%x", v)
}
