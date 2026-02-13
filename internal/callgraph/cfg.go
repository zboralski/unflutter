package callgraph

import (
	"fmt"
	"sort"

	"github.com/zboralski/lattice"
	"unflutter/internal/disasm"
)

// BuildCFG constructs a lattice.CFGGraph from disassembled functions.
// Each FuncInfo is converted to a lattice.FuncCFG via the existing
// disasm.BuildCFG (3-phase algorithm) then mapped to lattice types.
func BuildCFG(funcs []FuncInfo) *lattice.CFGGraph {
	cg := &lattice.CFGGraph{}
	for _, f := range funcs {
		dcfg := disasm.BuildCFG(f.Name, f.Insts)
		lcfg := convertFuncCFG(&dcfg, f.CallEdges)
		cg.Funcs = append(cg.Funcs, lcfg)
	}
	return cg
}

// BuildFuncCFG builds a single-function lattice.FuncCFG from instructions and call edges.
// Returns the FuncCFG and the number of basic blocks (for filtering trivial functions).
func BuildFuncCFG(name string, insts []disasm.Inst, edges []disasm.CallEdge) (*lattice.FuncCFG, int) {
	dcfg := disasm.BuildCFG(name, insts)
	lcfg := convertFuncCFG(&dcfg, edges)
	return lcfg, len(dcfg.Blocks)
}

// BuildSignalFuncCFG builds a FuncCFG for signal analysis. Only interesting calls
// (named functions, not sub_*/hex stubs) and string references are included.
// Blocks with no interesting content are pruned by the renderer.
func BuildSignalFuncCFG(name string, insts []disasm.Inst, edges []disasm.CallEdge, strRefs map[uint64]string) (*lattice.FuncCFG, int) {
	dcfg := disasm.BuildCFG(name, insts)
	lcfg := convertSignalFuncCFG(&dcfg, edges, strRefs)
	return lcfg, len(dcfg.Blocks)
}

// injectStringRefs adds string reference CallSite entries into the appropriate blocks.
func injectStringRefs(lcfg *lattice.FuncCFG, dcfg *disasm.FuncCFG, strRefs map[uint64]string) {
	if len(strRefs) == 0 {
		return
	}
	for bi, db := range dcfg.Blocks {
		added := false
		for idx := db.Start; idx < db.End && idx < len(dcfg.Insts); idx++ {
			pc := dcfg.Insts[idx].Addr
			if val, ok := strRefs[pc]; ok {
				if len(val) > 50 {
					val = val[:47] + "..."
				}
				lcfg.Blocks[bi].Calls = append(lcfg.Blocks[bi].Calls, lattice.CallSite{
					Offset: idx,
					Callee: fmt.Sprintf("%q", val),
				})
				added = true
			}
		}
		if added {
			sort.Slice(lcfg.Blocks[bi].Calls, func(i, j int) bool {
				return lcfg.Blocks[bi].Calls[i].Offset < lcfg.Blocks[bi].Calls[j].Offset
			})
		}
	}
}

// isInterestingCallee returns true if the callee name represents a real named
// function rather than VM internals, stubs, or dispatch noise.
func isInterestingCallee(name string) bool {
	if name == "" {
		return false
	}
	switch {
	case len(name) > 4 && name[:4] == "sub_": // unresolved address stubs
		return false
	case len(name) > 2 && name[0] == '0' && name[1] == 'x': // raw hex fallback
		return false
	case name == "dispatch_table" || name == "object_field": // VM dispatch noise
		return false
	case len(name) > 4 && name[:4] == "THR.": // thread-local runtime entries
		return false
	case len(name) > 3 && name[:3] == "PP[": // pool pointer stubs
		return false
	}
	return true
}

// convertSignalFuncCFG builds a single-block lattice.FuncCFG containing all
// interesting calls (named functions) and string references from the function.
// Each function becomes one node in the CFG showing its call/string summary.
func convertSignalFuncCFG(dcfg *disasm.FuncCFG, edges []disasm.CallEdge, strRefs map[uint64]string) *lattice.FuncCFG {
	edgeByPC := make(map[uint64]disasm.CallEdge, len(edges))
	for _, e := range edges {
		edgeByPC[e.FromPC] = e
	}

	// Collect all interesting calls and string refs across all blocks into one.
	seen := make(map[string]bool)
	var calls []lattice.CallSite
	seq := 0
	for _, db := range dcfg.Blocks {
		for idx := db.Start; idx < db.End && idx < len(dcfg.Insts); idx++ {
			pc := dcfg.Insts[idx].Addr

			if e, ok := edgeByPC[pc]; ok {
				callee := e.TargetName
				if callee == "" {
					callee = e.Via
				}
				if isInterestingCallee(callee) && !seen[callee] {
					seen[callee] = true
					calls = append(calls, lattice.CallSite{Offset: seq, Callee: callee})
					seq++
				}
			}

			if val, ok := strRefs[pc]; ok {
				if len(val) > 50 {
					val = val[:47] + "..."
				}
				label := fmt.Sprintf("%q", val)
				if !seen[label] {
					seen[label] = true
					calls = append(calls, lattice.CallSite{Offset: seq, Callee: label})
					seq++
				}
			}
		}
	}

	lcfg := &lattice.FuncCFG{Name: dcfg.Name}
	if len(calls) > 0 {
		lcfg.Blocks = append(lcfg.Blocks, &lattice.BasicBlock{
			ID:    0,
			Start: 0,
			End:   1,
			Term:  true,
			Calls: calls,
		})
	}
	return lcfg
}

// convertFuncCFG maps a disasm.FuncCFG to a lattice.FuncCFG.
// Call edges are mapped into blocks by matching instruction PCs.
func convertFuncCFG(dcfg *disasm.FuncCFG, edges []disasm.CallEdge) *lattice.FuncCFG {
	// Build PC → CallEdge map for O(1) lookup.
	edgeByPC := make(map[uint64]disasm.CallEdge, len(edges))
	for _, e := range edges {
		edgeByPC[e.FromPC] = e
	}

	lcfg := &lattice.FuncCFG{Name: dcfg.Name}
	for _, db := range dcfg.Blocks {
		lb := &lattice.BasicBlock{
			ID:    db.ID,
			Start: db.Start,
			End:   db.End,
			Term:  db.IsTerm,
		}

		// Convert successors.
		for _, ds := range db.Succs {
			lb.Succs = append(lb.Succs, lattice.Successor{
				BlockID: ds.BlockID,
				Cond:    ds.Cond,
			})
		}

		// Populate calls from edges that fall within this block's instruction range.
		for idx := db.Start; idx < db.End && idx < len(dcfg.Insts); idx++ {
			if e, ok := edgeByPC[dcfg.Insts[idx].Addr]; ok {
				callee := e.TargetName
				if callee == "" {
					callee = e.Via
				}
				if callee == "" {
					callee = fmt.Sprintf("0x%x", e.TargetPC)
				}
				lb.Calls = append(lb.Calls, lattice.CallSite{
					Offset: idx,
					Callee: callee,
				})
			}
		}

		lcfg.Blocks = append(lcfg.Blocks, lb)
	}
	return lcfg
}
