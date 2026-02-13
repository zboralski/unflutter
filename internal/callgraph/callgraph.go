package callgraph

import (
	"github.com/zboralski/lattice"
	"unflutter/internal/disasm"
)

// FuncInfo holds the data needed to build call graph and CFG for one function.
type FuncInfo struct {
	Name      string
	Insts     []disasm.Inst
	CallEdges []disasm.CallEdge
}

// BuildCallGraph constructs a lattice.Graph from disassembled functions.
// Each function becomes a node. Each resolved call edge becomes an edge.
// Unresolved BLR targets (no TargetName or Via) are skipped.
func BuildCallGraph(funcs []FuncInfo) *lattice.Graph {
	g := &lattice.Graph{}
	for _, f := range funcs {
		g.Nodes = append(g.Nodes, f.Name)
		for _, e := range f.CallEdges {
			callee := e.TargetName
			if callee == "" {
				callee = e.Via
			}
			if callee == "" {
				continue
			}
			g.Edges = append(g.Edges, lattice.Edge{
				Caller: f.Name,
				Callee: callee,
			})
		}
	}
	g.Dedup()
	return g
}
