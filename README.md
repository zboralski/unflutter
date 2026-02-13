# unflutter

Static analyzer for Flutter/Dart AOT snapshots. Recovers function names, class hierarchies, call graphs, and behavioral signals from `libapp.so` — without embedding or executing the Dart VM.

## Why Not Blutter

[Blutter](https://github.com/aspect-sec/blutter) solves Flutter reverse engineering by embedding the Dart VM itself. It calls `Dart_Initialize`, creates an isolate group from the snapshot, and walks the deserialized heap with internal VM APIs. No Dart code from the snapshot is executed — the VM is used purely for introspection. But this still means Blutter must compile a matching Dart SDK for every target version and link against VM internals.

unflutter takes a different path. No VM. No SDK compilation. The snapshot is a byte stream with a known grammar. We parse it directly.

The tradeoff: Blutter gets perfect fidelity because it deserializes through the VM's own code paths. unflutter gets portability, speed, and the ability to analyze snapshots from any Dart version without building anything version-specific. The cost is that every format change across Dart versions must be handled explicitly in our parser — there is no runtime to fall back on.

## Design

Constraint elimination. We treat the snapshot as a deterministic binary grammar.

```
Omega = all possible interpretations of the byte stream

C = {
  ELF invariants,
  snapshot magic (0xf5f5dcdc),
  version hash (32-byte ASCII),
  CID table (class ID -> cluster handler),
  cluster grammar (alloc counts, fill encoding),
  instruction layout (stubs + code regions)
}

R = Omega reduced by C
```

Each constraint narrows the space. ELF validation eliminates non-ARM64 binaries. The snapshot magic eliminates non-Dart data. The version hash selects exactly one CID table and tag encoding. Cluster alloc counts fix the object population. Fill parsing recovers field values within that fixed population. What survives all constraints is the analysis result.

```
if |R| == 0  → HALT: overconstrained (bug in our model)
if |R| > 1   → HALT: underdetermined (missing constraint)
if |R| == 1  → COMMIT: the answer
```

No heuristics. No runtime fallback. No inference outside constraints.

## How It Works

### Snapshot reconstruction

Dart AOT snapshot = two-phase serialization: **alloc** then **fill**.

**Alloc** walks clusters in CID order. Each cluster declares how many objects of that class exist. This assigns sequential reference IDs to every object. No data is read yet — just counts.

**Fill** walks the same clusters again. This time it reads the actual field values: string bytes, reference IDs pointing to other objects, integer scalars. The fill encoding varies by object type and Dart version.

We replay both phases from raw bytes. The alloc phase gives us the object census. The fill phase gives us names, strings, and cross-references. Combined with the instructions table (which maps code objects to their machine code offsets), we recover the full function-name-to-address mapping that Blutter gets from the VM API.

### Code recovery

The isolate instructions image contains two regions:

**Stubs** (indices 0 through `FirstEntryWithCode-1`): runtime trampolines — type-check handlers, allocation stubs, dispatch helpers — that Dart AOT places before user code.

**Code** (indices `FirstEntryWithCode` onward): user functions and framework code. Each Code object maps to a PC offset via the instructions table.

We resolve both regions, producing a complete function map that covers the entire executable range.

### ARM64 disassembly and call edges

Each function's code bytes are decoded instruction-by-instruction using `arm64asm.Decode`. Branch detection handles B, B.cond, CBZ, CBNZ, TBZ, TBNZ, RET — all from raw 32-bit encodings.

**CFG construction** follows a 3-phase algorithm:
1. Collect block leaders: instruction 0, branch targets, instructions after terminators
2. Sort and partition into basic blocks
3. Walk blocks, compute successor edges from terminal instructions

**Call edge extraction** distinguishes two kinds:

- **BL (direct call)**: decode target address from imm26 field, resolve to function name via symbol map
- **BLR (indirect call)**: resolve target register provenance via `RegTracker` (sliding window W=8)

The register tracker traces how BLR target registers get their values:

| Provenance | Pattern | Description |
|------------|---------|-------------|
| PP (object pool) | `LDR Xt, [X27, #imm]` | X27 is the pool pointer. Pool index = byte_offset / 8 |
| THR (thread) | `LDR Xt, [X26, #imm]` | X26 is the thread pointer. Resolved via version-specific offset maps |
| Peephole PP | `ADD Xd, X27, #hi; LDR Xt, [Xd, #lo]` | Two-instruction PP for large pool indices |
| Dispatch table | `LDR Xn, [X21, Xm, LSL #3]` | X21 is the dispatch table register |

Each BLR gets annotated with its provenance (e.g., `PP[42] Widget.build`, `THR.AllocateArray_ep`, `dispatch_table`).

### Graph construction

Call edges and CFGs are converted to [lattice](https://github.com/zboralski/lattice) types — an architecture-neutral graph IR shared with SpiderMonkey-dumper (for JS bytecode analysis). The lattice library provides DOT rendering.

Per-function CFG DOT files are written with the Japanese minimalist style from lattice. The call graph is rendered with NASA/Bauhaus style.

### Ghidra integration

The `decompile` command runs a full Ghidra headless pipeline:

1. Generates `ghidra_meta.json` with function names, class struct layouts, THR fields, string references, and pointer size metadata
2. Runs `analyzeHeadless` with a pre-script (disables problematic analyzers) and post-script that:
   - Disassembles at all known function addresses
   - Creates/renames functions
   - Creates Dart class struct types with correct field sizes (4-byte for compressed pointers, 8-byte otherwise)
   - Creates a `DartThread` struct for THR (X26) accesses
   - Applies typed function signatures (`this` pointer, parameter count, return type)
   - Sets EOL comments for THR fields, PP pool references, and string literals
   - Decompiles and exports selected functions as `.c` files

### Version handling

| Dart | Tag Style | Pointers | Key change |
|------|-----------|----------|------------|
| 2.10.0 | CID-Int32 | Uncompressed | 4 header fields, pre-canonical-split |
| 2.13.0 | CID-Int32 | Uncompressed | 5 header fields, split canonical |
| 2.14.0 | CID-Shift1 | Uncompressed | CID shifted into uint64 tag |
| 2.15.0 | CID-Shift1 | Uncompressed | NativePointer CID inserted |
| 2.16.0 | CID-Shift1 | Uncompressed | ConstMap/ConstSet added |
| 2.17.6 | CID-Shift1 | Uncompressed | Last unsigned-ref version |
| 2.18.0 | CID-Shift1 | Compressed | Signed refs, compressed pointers |
| 2.19.0 | CID-Shift1 | Compressed | 64-byte alignment |
| 3.0.5–3.3.0 | CID-Shift1 | Compressed | Progressive CID table changes |
| 3.4.3–3.10.7 | ObjectHeader | Compressed | New tag encoding, record types |

No version-conditional architecture. The version hash selects a constraint set. Same pipeline runs.

## Build and Install

Requires Go 1.24+. One external dependency: `golang.org/x/arch` (ARM64 instruction decoding).

```bash
make build          # build ./unflutter binary
make install        # install binary to /usr/local/bin, scripts to ~/.unflutter/
make test           # run tests
```

Ghidra integration requires Ghidra 11.x with Jython support. Auto-detected from `GHIDRA_HOME`, `PATH`, or common brew locations.

## Usage

### Quick scan

```bash
unflutter scan --lib libapp.so           # print snapshot info
unflutter strings --lib libapp.so        # extract strings
```

### Disassembly

```bash
# Basic disassembly — functions, call edges, string refs, class layouts
unflutter disasm --lib libapp.so --out out/target

# With call graph + per-function CFG DOT files
unflutter disasm --lib libapp.so --out out/target --graph
```

Output lands in `out/target/`:

- `functions.jsonl` — every recovered function with name, address, size
- `call_edges.jsonl` — BL/BLR edges with resolved targets
- `string_refs.jsonl` — string references from object pool loads
- `asm/` — annotated ARM64 disassembly per function (with THR/PP annotations)
- `callgraph.dot`, `cfg/*.dot` — graph output (when `--graph` is set)

### Signal analysis

Signal finds functions with behavioral relevance — networking, crypto, cloaking, auth, etc. — and builds a context graph around them.

```bash
# Run signal on disasm output
unflutter signal --in out/target

# Custom context depth (default: 2 hops from signal functions)
unflutter signal --in out/target -k 3

# Skip asm loading (faster, no asm in HTML)
unflutter signal --in out/target --no-asm

# Custom output path
unflutter signal --in out/target --out /tmp/report.html
```

Produces:

- `signal.html` — self-contained interactive report with function cards, asm, string refs, category badges
- `signal_graph.json` — machine-readable signal graph
- `signal.dot` / `signal.svg` — call graph of signal + context functions
- `signal_cfg.dot` / `signal_cfg.svg` — CFG with calls and classified strings per signal function

If [Graphviz](https://graphviz.org/) is installed, SVGs are auto-rendered. Otherwise the command prints manual render instructions.

### Ghidra decompilation

> **Note:** Ghidra decompilation works but output quality is still being improved. ARM64 Dart AOT code uses unconventional calling conventions (X26=thread, X27=pool, compressed pointers) that Ghidra's default analysis doesn't handle well. The pre/post scripts partially address this, but expect noisy output for complex functions.

```bash
# Decompile signal functions (crypto, networking, cloaking, etc.)
unflutter decompile --in out/target --lib libapp.so

# Decompile ALL functions
unflutter decompile --in out/target --lib libapp.so --all
```

Or via make:

```bash
make disasm SAMPLE=path/to/libapp.so
make ghidra SAMPLE=path/to/libapp.so
```

### Output artifacts

| File | Description |
|------|-------------|
| `functions.jsonl` | Function records: name, address, size, owner, param count |
| `call_edges.jsonl` | Call edges: BL/BLR with resolved targets and provenance |
| `classes.jsonl` | Class layouts: fields, offsets, instance sizes |
| `string_refs.jsonl` | String references from PP loads |
| `dart_meta.json` | Snapshot metadata: Dart version, pointer size, THR fields |
| `ghidra_meta.json` | Ghidra-ready metadata: all of the above merged |
| `asm/*.txt` | Annotated ARM64 disassembly per function |
| `cfg/*.dot` | Per-function control flow graphs (with `--graph`) |
| `callgraph.dot` | Full call graph (with `--graph`) |
| `signal.html` | Behavioral signal report |
| `decompiled/*.c` | Ghidra decompiled C output |

## Architecture

```
internal/
  elfx/       ELF validation, ARM64 symbol extraction
  snapshot/   Region extraction, header parsing, version profiles
  dartfmt/    Dart VM stream encoding (variable-length integers)
  cluster/    Two-phase snapshot deserialization (alloc + fill)
  disasm/     ARM64 decode, CFG, call edge provenance, register tracking
  callgraph/  Lattice graph builders (call graph + CFG)
  signal/     Behavioral string classification
  render/     HTML/DOT visualization
  output/     JSONL serialization
```

### Pipeline

```
libapp.so
  → ELF parse (elfx)
  → snapshot region extraction (snapshot)
  → header + version detection (snapshot)
  → cluster alloc scan (cluster)
  → cluster fill parse (cluster)
  → instructions table: stubs + code (cluster)
  → ARM64 disassembly + CFG (disasm)
  → call edge extraction with register tracking (disasm)
  → lattice graph construction (callgraph)
  → signal classification (signal)
  → Ghidra metadata + decompilation (ghidra-meta / decompile)
  → JSON / DOT / HTML artifacts
```

Each stage is a pure function from bytes to structured data. No mutable global state. No VM runtime. Same input, same output.

## Known Limitations

- **AOT only.** No JIT mode support.
- **ARM64 only.** No x86 or RISC-V.
- **No source reconstruction.** Output is function names, call edges, structs, strings — not Dart source.
- **BLR tracking window.** Register provenance uses a sliding window (W=8). Complex register chains outside the window are unresolved.
- **Dart 2.12.x not validated.** No samples available.
- **Every format change must be modeled.** There is no runtime to handle it automatically.
