package main

import (
	"fmt"
	"sort"

	"unflutter/internal/cluster"
	"unflutter/internal/snapshot"
)

// codeNameInfo holds resolved function and owner names for a code ref.
type codeNameInfo struct {
	funcName   string
	ownerName  string
	paramCount int // total visible parameters (fixed + optional, excluding implicit 'this')
}

// poolLookups holds the lookup maps needed for pool entry resolution.
type poolLookups struct {
	refToStr       map[int]string
	refToNamed     map[int]*cluster.NamedObject
	refCID         map[int]int
	codeRefDisplay map[int]string
	codeNames      map[int]codeNameInfo
	vmRefToStr     map[int]string // VM snapshot strings by ref ID
	vmRefCID       map[int]int    // VM snapshot CID by ref ID
	vmRefToNamed   map[int]*cluster.NamedObject
	ct             *snapshot.CIDTable
	baseObjLimit   int
}

// buildPoolLookups builds the lookup maps from a fill result.
// vmResult is optional — if non-nil, VM snapshot strings/names are used to resolve base object refs.
func buildPoolLookups(result *cluster.Result, ct *snapshot.CIDTable, vmResult *cluster.Result) *poolLookups {
	l := &poolLookups{
		refToStr:       make(map[int]string),
		refToNamed:     make(map[int]*cluster.NamedObject),
		refCID:         make(map[int]int),
		codeRefDisplay: make(map[int]string),
		vmRefToStr:     make(map[int]string),
		vmRefCID:       make(map[int]int),
		vmRefToNamed:   make(map[int]*cluster.NamedObject),
		ct:             ct,
		baseObjLimit:   int(result.Header.NumBaseObjects) + 1,
	}

	for _, ps := range result.Strings {
		l.refToStr[ps.RefID] = ps.Value
	}
	for i := range result.Named {
		no := &result.Named[i]
		l.refToNamed[no.RefID] = no
	}
	for _, cm := range result.Clusters {
		for ref := cm.StartRef; ref < cm.StopRef; ref++ {
			l.refCID[ref] = cm.CID
		}
	}

	// Populate VM lookups from VM snapshot result.
	if vmResult != nil {
		for _, ps := range vmResult.Strings {
			l.vmRefToStr[ps.RefID] = ps.Value
		}
		for i := range vmResult.Named {
			no := &vmResult.Named[i]
			l.vmRefToNamed[no.RefID] = no
		}
		for _, cm := range vmResult.Clusters {
			for ref := cm.StartRef; ref < cm.StopRef; ref++ {
				l.vmRefCID[ref] = cm.CID
			}
		}
	}

	// Build FunctionType ref→info lookup for parameter count resolution.
	funcTypeByRef := make(map[int]*cluster.FuncTypeInfo, len(result.FuncTypes))
	for i := range result.FuncTypes {
		ft := &result.FuncTypes[i]
		funcTypeByRef[ft.RefID] = ft
	}

	// Build code ref→name.
	l.codeNames = make(map[int]codeNameInfo)
	for _, ce := range result.Codes {
		if ce.OwnerRef <= 0 {
			continue
		}
		owner, ok := l.refToNamed[ce.OwnerRef]
		if !ok {
			continue
		}
		ci := codeNameInfo{
			funcName:  l.resolveName(owner),
			ownerName: l.resolveOwnerName(owner),
		}
		// Follow Function→FunctionType chain for parameter count.
		if owner.SignatureRefID > 0 {
			if ft, ok := funcTypeByRef[owner.SignatureRefID]; ok {
				ci.paramCount = ft.NumFixed + ft.NumOptional
			}
		}
		l.codeNames[ce.RefID] = ci
	}
	for _, ce := range result.Codes {
		ci := l.codeNames[ce.RefID]
		if ci.funcName != "" {
			if ci.ownerName != "" {
				l.codeRefDisplay[ce.RefID] = ci.ownerName + "." + ci.funcName
			} else {
				l.codeRefDisplay[ce.RefID] = ci.funcName
			}
		}
	}

	return l
}

func (l *poolLookups) resolveName(no *cluster.NamedObject) string {
	if no.NameRefID >= 0 {
		if s, ok := l.refToStr[no.NameRefID]; ok {
			return s
		}
	}
	return ""
}

func (l *poolLookups) resolveVMName(no *cluster.NamedObject) string {
	if no.NameRefID >= 0 {
		if s, ok := l.vmRefToStr[no.NameRefID]; ok {
			return s
		}
	}
	return ""
}

func (l *poolLookups) resolveOwnerName(no *cluster.NamedObject) string {
	if no.OwnerRefID < 0 {
		return ""
	}
	if owner, ok := l.refToNamed[no.OwnerRefID]; ok {
		return l.resolveName(owner)
	}
	return ""
}

// qualifiedCodeName returns "Owner.Func_hexaddr" for a code refID using poolLookups.
func qualifiedCodeName(refID int, pl *poolLookups, pcOffset uint32) string {
	ci := pl.codeNames[refID]
	return qualifiedName(ci.ownerName, ci.funcName, pcOffset)
}

// resolvePoolDisplay builds a map from pool entry index to display string.
func resolvePoolDisplay(pool []cluster.PoolEntry, l *poolLookups) map[int]string {
	display := make(map[int]string, len(pool))
	for _, pe := range pool {
		switch pe.Kind {
		case cluster.PoolTagged:
			if s, ok := l.refToStr[pe.RefID]; ok {
				display[pe.Index] = fmt.Sprintf("%q", s)
			} else if no, ok := l.refToNamed[pe.RefID]; ok {
				name := l.resolveName(no)
				if name != "" {
					display[pe.Index] = name
				} else {
					display[pe.Index] = fmt.Sprintf("<%s>", cluster.CidNameV(no.CID, l.ct))
				}
			} else if fn, ok := l.codeRefDisplay[pe.RefID]; ok {
				display[pe.Index] = fn
			} else if cidNum, ok := l.refCID[pe.RefID]; ok {
				cidName := cluster.CidNameV(cidNum, l.ct)
				if cidName != "" {
					display[pe.Index] = fmt.Sprintf("<%s>", cidName)
				} else {
					display[pe.Index] = fmt.Sprintf("<Instance_%d>", cidNum)
				}
			} else if pe.RefID == 1 {
				display[pe.Index] = "null"
			} else if pe.RefID > 0 && pe.RefID < l.baseObjLimit {
				// Try resolving from VM snapshot lookups.
				if s, ok := l.vmRefToStr[pe.RefID]; ok {
					display[pe.Index] = fmt.Sprintf("%q", s)
				} else if no, ok := l.vmRefToNamed[pe.RefID]; ok {
					name := l.resolveVMName(no)
					if name != "" {
						display[pe.Index] = name
					} else {
						display[pe.Index] = fmt.Sprintf("<vm:%s>", cluster.CidNameV(no.CID, l.ct))
					}
				} else if cidNum, ok := l.vmRefCID[pe.RefID]; ok {
					cidName := cluster.CidNameV(cidNum, l.ct)
					if cidName != "" {
						display[pe.Index] = fmt.Sprintf("<vm:%s>", cidName)
					} else {
						display[pe.Index] = fmt.Sprintf("<vm:%d>", pe.RefID)
					}
				} else {
					display[pe.Index] = fmt.Sprintf("<vm:%d>", pe.RefID)
				}
			} else {
				display[pe.Index] = fmt.Sprintf("<ref:%d>", pe.RefID)
			}
		case cluster.PoolImmediate:
			display[pe.Index] = fmt.Sprintf("0x%x", pe.Imm)
		}
	}
	return display
}

// DartClassLayout is a resolved class definition ready for export.
type DartClassLayout struct {
	ClassName    string            `json:"class_name"`
	ClassID      int32             `json:"class_id"`
	InstanceSize int32             `json:"instance_size"`
	Fields       []DartFieldLayout `json:"fields"`
}

// DartFieldLayout is one field in a DartClassLayout.
type DartFieldLayout struct {
	Name       string `json:"name"`
	ByteOffset int32  `json:"byte_offset"`
}

// buildClassLayouts joins ClassInfo + FieldInfo + string lookups into class layouts.
// compressedPtrs indicates whether the snapshot uses compressed pointers (4-byte words vs 8-byte).
// Both instance_size and field offsets are stored in compressed words; we convert to bytes here.
func buildClassLayouts(result *cluster.Result, pl *poolLookups, compressedPtrs bool) []DartClassLayout {
	// Compressed word size: 4 bytes for compressed-pointer builds, 8 for 64-bit uncompressed.
	var wordSize int32 = 8
	if compressedPtrs {
		wordSize = 4
	}

	// Build ClassInfo ref→ClassInfo lookup.
	classByRef := make(map[int]*cluster.ClassInfo, len(result.Classes))
	for i := range result.Classes {
		ci := &result.Classes[i]
		classByRef[ci.RefID] = ci
	}

	// Resolve field offset ref IDs against Mint values and group by owner.
	// FieldInfo.HostOffset stores a ref ID pointing to a Smi in the Mint cluster.
	// We resolve it to get the actual word offset, then convert to bytes.
	type resolvedField struct {
		nameRefID  int
		byteOffset int32
	}
	fieldsByOwner := make(map[int][]resolvedField)
	for _, fi := range result.Fields {
		if fi.OwnerRefID <= 0 || fi.HostOffset < 0 {
			continue // skip static fields
		}
		offsetRef := int(fi.HostOffset)
		wordOff, ok := result.MintValues[offsetRef]
		if !ok {
			continue // can't resolve ref → skip
		}
		fieldsByOwner[fi.OwnerRefID] = append(fieldsByOwner[fi.OwnerRefID], resolvedField{
			nameRefID:  fi.NameRefID,
			byteOffset: int32(wordOff) * wordSize,
		})
	}

	// Assemble layouts.
	var layouts []DartClassLayout
	for _, ci := range result.Classes {
		if ci.InstanceSize <= 0 {
			continue
		}
		className := ""
		if ci.NameRefID >= 0 {
			if s, ok := pl.refToStr[ci.NameRefID]; ok {
				className = s
			}
		}
		if className == "" {
			continue
		}

		layout := DartClassLayout{
			ClassName:    className,
			ClassID:      ci.ClassID,
			InstanceSize: ci.InstanceSize * wordSize,
		}

		if rfs, ok := fieldsByOwner[ci.RefID]; ok {
			// Named fields from snapshot Field objects.
			for _, rf := range rfs {
				fieldName := ""
				if rf.nameRefID >= 0 {
					if s, ok := pl.refToStr[rf.nameRefID]; ok {
						fieldName = s
					}
				}
				if fieldName == "" {
					fieldName = fmt.Sprintf("field_0x%x", rf.byteOffset)
				}
				layout.Fields = append(layout.Fields, DartFieldLayout{
					Name:       fieldName,
					ByteOffset: rf.byteOffset,
				})
			}
		} else {
			// No Field objects for this class — generate synthetic slots.
			// Dart object header is 1 word (tag+hash). Fields start after that.
			// Every slot is wordSize bytes (4 compressed, 8 uncompressed).
			byteSize := ci.InstanceSize * wordSize
			for off := wordSize; off+wordSize <= byteSize; off += wordSize {
				layout.Fields = append(layout.Fields, DartFieldLayout{
					Name:       fmt.Sprintf("f_0x%x", off),
					ByteOffset: off,
				})
			}
		}

		sort.Slice(layout.Fields, func(i, j int) bool {
			return layout.Fields[i].ByteOffset < layout.Fields[j].ByteOffset
		})

		layouts = append(layouts, layout)
	}
	return layouts
}
