package disasm

import "fmt"

const regDT = 21 // X21 = dispatch table register

// CallEdge represents a call site extracted from disassembly.
type CallEdge struct {
	FromPC     uint64 `json:"from_pc"`
	Kind       string `json:"kind"`                // "bl" or "blr"
	TargetPC   uint64 `json:"target_pc,omitempty"` // resolved VA for bl
	TargetName string `json:"target_name,omitempty"`
	Reg        string `json:"reg,omitempty"` // register for blr (e.g. "X16")
	Via        string `json:"via,omitempty"` // provenance: "THR.AllocateArray_ep", "PP[36] foo", ""
}

// RegDef records the last definition of a register within the W=8 window.
type RegDef struct {
	Annotation string // e.g. "THR.AllocateArray_ep" or "PP[36] foo"
	Age        int    // instructions since definition
}

// RegTracker tracks last-def provenance for GP registers X0-X30.
// Window size W=8: definitions older than W instructions are expired.
type RegTracker struct {
	defs [31]RegDef // X0..X30
	w    int
}

// NewRegTracker creates a tracker with the given window size.
func NewRegTracker(w int) *RegTracker {
	return &RegTracker{w: w}
}

// Reset clears all tracked definitions. Call between functions.
func (rt *RegTracker) Reset() {
	for i := range rt.defs {
		rt.defs[i] = RegDef{}
	}
}

// Tick ages all definitions by 1 and expires those beyond the window.
func (rt *RegTracker) Tick() {
	for i := range rt.defs {
		if rt.defs[i].Annotation != "" {
			rt.defs[i].Age++
			if rt.defs[i].Age > rt.w {
				rt.defs[i] = RegDef{}
			}
		}
	}
}

// Define records that register rd was defined with the given annotation.
func (rt *RegTracker) Define(rd int, annotation string) {
	if rd < 0 || rd > 30 {
		return
	}
	rt.defs[rd] = RegDef{Annotation: annotation, Age: 0}
}

// Lookup returns the annotation for register rd, or "" if expired/unknown.
func (rt *RegTracker) Lookup(rd int) string {
	if rd < 0 || rd > 30 {
		return ""
	}
	return rt.defs[rd].Annotation
}

// Kill clears the definition for a register (e.g. when overwritten by a
// non-annotated instruction).
func (rt *RegTracker) Kill(rd int) {
	if rd < 0 || rd > 30 {
		return
	}
	rt.defs[rd] = RegDef{}
}

// isBL detects ARM64 BL (branch with link) instructions.
// Encoding: 1 | 00101 | imm26
// Mask: 0xFC000000, Value: 0x94000000
// Returns the target address (sign-extended imm26 * 4 + PC).
func isBL(raw uint32, pc uint64) (target uint64, ok bool) {
	if raw&0xFC000000 != 0x94000000 {
		return 0, false
	}
	imm26 := int32(raw & 0x03FFFFFF)
	// Sign extend from 26 bits.
	if imm26&(1<<25) != 0 {
		imm26 |= ^int32(0x03FFFFFF)
	}
	target = uint64(int64(pc) + int64(imm26)*4)
	return target, true
}

// isBLR detects ARM64 BLR (branch with link to register) instructions.
// Encoding: 1101011 | 0 | 0 | 01 | 11111 | 0000 | 0 | 0 | Rn | 00000
// Mask: 0xFFFFFC1F, Value: 0xD63F0000
// Returns the register number.
func isBLR(raw uint32) (rn int, ok bool) {
	if raw&0xFFFFFC1F != 0xD63F0000 {
		return 0, false
	}
	rn = int((raw >> 5) & 0x1F)
	return rn, true
}

// dstRegOfInst returns the destination register of a data-processing or load
// instruction, or -1 if not detected. Used by the register tracker to know
// which register an annotated instruction defines.
func dstRegOfInst(raw uint32) int {
	// LDR X64 unsigned offset
	if raw&0xFFC00000 == 0xF9400000 {
		return int(raw & 0x1F)
	}
	// LDR W32 unsigned offset
	if raw&0xFFC00000 == 0xB9400000 {
		return int(raw & 0x1F)
	}
	// LDUR X64 (unscaled offset): size=11|111|V=0|00|opc=01|imm9|00|Rn|Rt
	// Mask: 0xFFE00C00, Value: 0xF8400000
	if raw&0xFFE00C00 == 0xF8400000 {
		return int(raw & 0x1F)
	}
	// LDUR W32 (unscaled offset): size=10|111|V=0|00|opc=01|imm9|00|Rn|Rt
	if raw&0xFFE00C00 == 0xB8400000 {
		return int(raw & 0x1F)
	}
	// LDR X64 register offset: size=11|111|V=0|01|opc=01|1|Rm|option|S|10|Rn|Rt
	// Mask: 0xFFE00C00, Value: 0xF8600800
	if raw&0xFFE00C00 == 0xF8600800 {
		return int(raw & 0x1F)
	}
	// ADD X64 immediate
	if raw&0xFF000000 == 0x91000000 {
		return int(raw & 0x1F)
	}
	// SUB X64 immediate
	if raw&0xFF000000 == 0xD1000000 {
		return int(raw & 0x1F)
	}
	// MOV (alias of ORR Rd, XZR, Rm) - wide: MOVZ/MOVK/MOVN
	if raw&0xFF800000 == 0xD2800000 || // MOVZ X
		raw&0xFF800000 == 0xF2800000 || // MOVK X
		raw&0xFF800000 == 0x92800000 { // MOVN X
		return int(raw & 0x1F)
	}
	// UBFX/UBFM (bit field extract): sf=1|opc=10|100110|N=1|...
	if raw&0xFF800000 == 0xD3000000 {
		return int(raw & 0x1F)
	}
	return -1
}

// isLDRRegExtended detects LDR Xt, [Xn, Xm, LSL #3] (64-bit register offset).
// Returns base, index register, and destination register.
func isLDRRegExtended(raw uint32) (base, rm, rt int, ok bool) {
	// Encoding: 11|111|V=0|01|opc=01|1|Rm|option|S|10|Rn|Rt
	// We match: 0xFFE00C00 == 0xF8600800
	if raw&0xFFE00C00 != 0xF8600800 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	rm = int((raw >> 16) & 0x1F)
	return base, rm, rt, true
}

// isLDUR64 detects LDUR Xt, [Xn, #imm9] (64-bit unscaled immediate).
func isLDUR64(raw uint32) (base, rt int, ok bool) {
	if raw&0xFFE00C00 != 0xF8400000 {
		return 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	return base, rt, true
}

// ExtractCallEdges scans instructions for BL and BLR call sites.
// Uses register tracking with window W to resolve BLR targets.
// annotators are run per-instruction to populate the register tracker.
// symbols resolves BL target addresses to names.
func ExtractCallEdges(insts []Inst, symbols SymbolLookup, annotators []Annotator, w int) []CallEdge {
	rt := NewRegTracker(w)
	var edges []CallEdge

	for _, inst := range insts {
		// Check for BL first.
		if target, ok := isBL(inst.Raw, inst.Addr); ok {
			e := CallEdge{
				FromPC:   inst.Addr,
				Kind:     "bl",
				TargetPC: target,
			}
			if symbols != nil {
				if name, found := symbols(target); found {
					e.TargetName = name
				}
			}
			edges = append(edges, e)
			rt.Tick()
			continue
		}

		// Check for BLR.
		if rn, ok := isBLR(inst.Raw); ok {
			via := rt.Lookup(rn)
			e := CallEdge{
				FromPC: inst.Addr,
				Kind:   "blr",
				Reg:    fmt.Sprintf("X%d", rn),
				Via:    via,
			}
			edges = append(edges, e)
			rt.Tick()
			continue
		}

		// Check for dispatch table load: LDR Xn, [X21, Xm, LSL #3].
		if base, _, dstR, ok := isLDRRegExtended(inst.Raw); ok && base == regDT {
			rt.Tick()
			rt.Define(dstR, "dispatch_table")
			continue
		}

		// Check for object field load via LDUR: LDUR Xn, [Xm, #imm].
		// These are compressed pointer dereferences (vtable/closure calls).
		if _, dstR, ok := isLDUR64(inst.Raw); ok {
			rt.Tick()
			rt.Define(dstR, "object_field")
			continue
		}

		// Run annotators to check if this instruction defines a register
		// with a known provenance (PP load, THR load).
		var annotation string
		for _, ann := range annotators {
			if s := ann(inst); s != "" {
				annotation = s
				break
			}
		}

		if annotation != "" {
			rd := dstRegOfInst(inst.Raw)
			if rd >= 0 {
				rt.Tick()
				rt.Define(rd, annotation)
				continue
			}
		}

		// Non-annotated instruction: kill the destination register if it's
		// a load or data-processing instruction.
		rd := dstRegOfInst(inst.Raw)
		if rd >= 0 {
			rt.Kill(rd)
		}
		rt.Tick()
	}

	return edges
}
