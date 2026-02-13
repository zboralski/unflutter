package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(os.Args[2:])
	case "dump":
		err = cmdDump(os.Args[2:])
	case "objects":
		err = cmdObjects(os.Args[2:])
	case "clusters":
		err = cmdClusters(os.Args[2:])
	case "strings":
		err = cmdStrings(os.Args[2:])
	case "graph":
		err = cmdGraph(os.Args[2:])
	case "disasm":
		err = cmdDisasm(os.Args[2:])
	case "render":
		err = cmdRender(os.Args[2:])
	case "signal":
		err = cmdSignal(os.Args[2:])
	case "ghidra-meta":
		err = cmdGhidraMeta(os.Args[2:])
	case "thr-audit":
		err = cmdTHRAudit(os.Args[2:])
	case "thr-cluster":
		err = cmdTHRCluster(os.Args[2:])
	case "thr-classify":
		err = cmdTHRClassify(os.Args[2:])
	case "inventory":
		err = cmdInventory(os.Args[2:])
	case "find-libapp":
		err = cmdFindLibapp(os.Args[2:])
	case "find-libapp-batch":
		err = cmdFindLibappBatch(os.Args[2:])
	case "dart2-buckets":
		err = cmdDart2Buckets(os.Args[2:])
	case "parity":
		err = cmdParity(os.Args[2:])
	case "decompile":
		err = cmdDecompile(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `unflutter — Dart AOT snapshot analyzer

Usage:
  unflutter scan    --lib <path>               Scan ELF and print snapshot info
  unflutter dump    --lib <path> --out <dir>    Disassemble and dump symbols
  unflutter objects --lib <path> [--json]        Dump object pool
  unflutter strings --lib <path>               Extract strings from snapshot
  unflutter graph   --lib <path> --out <dir>    Extract named object graph
  unflutter disasm  --lib <path> --out <dir>    Per-function named disassembly
  unflutter render  --in <dir>                     Render callgraph and HTML from JSONL
  unflutter signal  --in <dir>                     Signal graph: interesting functions + context
  unflutter ghidra-meta --in <dir>                 Export metadata for Ghidra headless
  unflutter thr-audit --lib <path> --out <file>  Audit THR-relative memory accesses
  unflutter thr-cluster --in <jsonl> --out <dir>    Cluster unresolved THR offsets
  unflutter thr-classify --in <jsonl> --out <dir>   Classify unresolved THR offsets
  unflutter inventory --dir <dir> --out <file>     Inventory Flutter sample corpus
  unflutter find-libapp --apk <path> --out <dir>   Find Dart AOT library in APK
  unflutter find-libapp-batch --dir <dir> --out <dir> Batch find-libapp + report
  unflutter parity --samples <dir> --out <dir>       Run pipeline on all samples, produce parity report
  unflutter decompile --in <dir> [--lib <path>] [--all]  Decompile via Ghidra (signal only by default)

Flags:
  --lib <path>       Path to libapp.so
  --out <dir>           Output directory
  --profile <id>        Override version profile
  --strict              Fail on first structural error
  --best-effort         Continue with placeholders (default)
  --max-steps <n>       Global loop cap
  --max-bytes <n>       Output size cap
`)
}
