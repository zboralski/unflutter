package cluster

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"unflutter/internal/dartfmt"
	"unflutter/internal/snapshot"
)

var debugFill = os.Getenv("DEFLUTTER_DEBUG_FILL") != ""

// NamedObject holds a named object extracted from the fill section.
type NamedObject struct {
	CID            int
	RefID          int
	NameRefID      int // ref ID pointing to name string (-1 if none)
	OwnerRefID     int // ref ID pointing to owner (-1 if none)
	SignatureRefID int // ref ID pointing to FunctionType signature (-1 if none)
}

// FuncTypeInfo holds parameter count data extracted from a FunctionType object.
type FuncTypeInfo struct {
	RefID       int
	NumFixed    int  // fixed parameters (excludes implicit 'this')
	NumOptional int  // optional parameters
	HasImplicit bool // true if instance method (has implicit 'this' parameter)
}

// ClassInfo holds class layout data extracted from a Class object's fill.
type ClassInfo struct {
	RefID        int
	NameRefID    int
	ClassID      int32
	InstanceSize int32
	NextFieldOff int32 // next_field_offset in bytes
	TypeArgsOff  int32 // type_arguments field offset in bytes
}

// FieldInfo holds field layout data extracted from a Field object's fill.
type FieldInfo struct {
	RefID      int
	NameRefID  int
	OwnerRefID int
	KindBits   int32
	HostOffset int32 // byte offset within instance; -1 for static fields
}

// readRef reads a fill-phase ref using the correct encoding for the version.
// ≤2.17 (fillRefUnsigned=true): ReadRef() → ReadUnsigned() (marker 128, little-endian).
// ≥2.18 (fillRefUnsigned=false): ReadRef() → ReadRefId() (big-endian, signed-byte).
func readRef(s *dartfmt.Stream, fillRefUnsigned bool) (int64, error) {
	if fillRefUnsigned {
		return s.ReadUnsigned()
	}
	return s.ReadRefId()
}

// DebugFillPositions iterates the fill section and prints the stream position
// before/after each cluster's fill to w. Used to diagnose fill drift.
func DebugFillPositions(data []byte, result *Result, profile *snapshot.VersionProfile, isVM bool, w io.Writer) error {
	if result.FillStart <= 0 || result.FillStart >= len(data) {
		return fmt.Errorf("fill: invalid start offset %d", result.FillStart)
	}
	s := dartfmt.NewStreamAt(data, result.FillStart)
	fillRefUnsigned := profile.FillRefUnsigned
	instrIdx := 0
	for i := range result.Clusters {
		cm := &result.Clusters[i]
		spec := GetFillSpec(cm.CID, cm, profile)
		startPos := s.Position()
		name := CidNameV(cm.CID, profile.CIDs)
		if name == "" {
			name = fmt.Sprintf("CID_%d", cm.CID)
		}
		err := fillOneCluster(s, cm, &spec, fillRefUnsigned, profile, &instrIdx, nil)
		endPos := s.Position()
		delta := endPos - startPos
		status := "OK"
		if err != nil {
			status = fmt.Sprintf("ERR: %v", err)
		}
		nfoStr := ""
		if cm.NextFieldOffsetInWords != 0 {
			nfoStr = fmt.Sprintf(" nfo=%d", cm.NextFieldOffsetInWords)
		}
		fmt.Fprintf(w, "FILL[%3d] CID=%-3d %-24s kind=%-2d count=%-5d start=0x%06x end=0x%06x delta=%-6d%s %s\n",
			i, cm.CID, name, spec.Kind, cm.Count, startPos, endPos, delta, nfoStr, status)
		if err != nil {
			return err
		}
	}
	return nil
}

// FillOneClusterExported is an exported wrapper around fillOneCluster for debug tools.
func FillOneClusterExported(s *dartfmt.Stream, cm *ClusterMeta, spec *FillSpec, fillRefUnsigned bool, profile *snapshot.VersionProfile, instrIdx *int) error {
	return fillOneCluster(s, cm, spec, fillRefUnsigned, profile, instrIdx, nil)
}

// dataImageObjStart computes the byte offset within data[] where ROData objects begin.
// snapshotSize is the TotalSize from the snapshot header.
// Returns 0 if ROData string extraction is not applicable.
func dataImageObjStart(dataLen int, snapshotSize int64, profile *snapshot.VersionProfile) int64 {
	if snapshotSize <= 0 || profile.CompressedPointers {
		return 0
	}
	var align int64
	if profile.TopLevelCid16 {
		align = 16
	} else {
		align = 64
	}
	diStart := (snapshotSize + align - 1) &^ (align - 1)
	objStart := diStart + align // skip image header
	if objStart >= int64(dataLen) {
		return 0
	}
	return objStart
}

// ReadFill parses the fill section of the snapshot, extracting strings
// and named objects. It processes ALL clusters in alloc order.
// snapshotSize is the TotalSize from the snapshot header (needed for ROData string extraction).
func ReadFill(data []byte, result *Result, profile *snapshot.VersionProfile, isVM bool, snapshotSize int64) error {
	if result.FillStart <= 0 || result.FillStart >= len(data) {
		return fmt.Errorf("fill: invalid start offset %d", result.FillStart)
	}

	s := dartfmt.NewStreamAt(data, result.FillStart)
	ct := profile.CIDs
	fillRefUnsigned := profile.FillRefUnsigned
	instrIdx := 0 // running instructions_index_ across Code clusters

	if debugFill {
		fmt.Fprintf(os.Stderr, "fill: %d clusters, fillStart=0x%x, dataLen=0x%x\n", len(result.Clusters), result.FillStart, len(data))
		for ci := range result.Clusters {
			cc := &result.Clusters[ci]
			name := CidNameV(cc.CID, ct)
			if name == "" {
				name = fmt.Sprintf("CID_%d", cc.CID)
			}
			fmt.Fprintf(os.Stderr, "  cluster[%d] CID=%d (%s) count=%d canonical=%v refs=%d..%d\n",
				ci, cc.CID, name, cc.Count, cc.IsCanonical, cc.StartRef, cc.StopRef)
		}
	}

	for i := range result.Clusters {
		cm := &result.Clusters[i]
		spec := GetFillSpec(cm.CID, cm, profile)
		fillPos := s.Position()
		if debugFill {
			fmt.Fprintf(os.Stderr, "fill[%d] CID=%d kind=%d count=%d pos=0x%x\n", i, cm.CID, spec.Kind, cm.Count, s.Position())
		}

		switch spec.Kind {
		case FillString:
			strings, err := readFillStrings(s, cm, profile.OldStringFormat, profile.CIDs)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (String CID %d): %w", i, cm.CID, err)
			}
			result.Strings = append(result.Strings, strings...)

		case FillNone, FillSentinel, FillInstructionsTable:
			// No fill data to read.

		case FillROData:
			// No fill data in the stream, but for string ROData clusters,
			// extract string data from the data image region.
			// In non-compressed-pointers mode, the abstract String cluster (ct.String)
			// holds deltas for ALL string objects (OneByteString + TwoByteString).
			// OneByteString/TwoByteString clusters are empty (count=0) or have wrong deltas.
			objStart := dataImageObjStart(len(data), snapshotSize, profile)
			if objStart > 0 && len(cm.Lengths) > 0 {
				// Only extract from the abstract String cluster, not from subclass clusters.
				if cm.CID == ct.String {
					strs := extractRODataStrings(data, cm, ct, objStart)
					result.Strings = append(result.Strings, strs...)
				}
			}

		case FillInlineBytes:
			if err := skipFillInlineBytes(s, cm); err != nil {
				return fmt.Errorf("fill: cluster %d (CID %d) pos=0x%x: %w", i, cm.CID, fillPos, err)
			}

		case FillRefs:
			named, funcTypes, fieldInfos, err := readFillRefs(s, cm, &spec, fillRefUnsigned)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (CID %d): %w", i, cm.CID, err)
			}
			result.Named = append(result.Named, named...)
			result.FuncTypes = append(result.FuncTypes, funcTypes...)
			result.Fields = append(result.Fields, fieldInfos...)

		case FillDouble:
			if err := skipFillDouble(s, cm, profile.PreCanonicalSplit); err != nil {
				return fmt.Errorf("fill: cluster %d (Double): %w", i, err)
			}

		case FillCode:
			codes, err := readFillCode(s, cm, profile.CIDs, fillRefUnsigned, instrIdx, profile.CodeNumRefs, profile.CodeTextOffsetDelta, profile.CodeStateBitsAfterRef, profile.CodeStateBitsAtEnd)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Code): %w", i, err)
			}
			result.Codes = append(result.Codes, codes...)
			// Advance instrIdx by the number of main (non-deferred) codes.
			instrIdx += int(cm.MainCount)

		case FillObjectPool:
			pool, err := readFillObjectPool(s, cm, profile.OldPoolFormat, profile.PoolTypeSwapped, fillRefUnsigned)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (ObjectPool): %w", i, err)
			}
			result.Pool = append(result.Pool, pool...)

		case FillArray:
			if err := skipFillArray(s, cm, fillRefUnsigned, profile); err != nil {
				return fmt.Errorf("fill: cluster %d (Array): %w", i, err)
			}

		case FillWeakArray:
			if err := skipFillWeakArray(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (WeakArray): %w", i, err)
			}

		case FillTypedData:
			if err := skipFillTypedData(s, cm, profile.CIDs, profile.PreCanonicalSplit); err != nil {
				return fmt.Errorf("fill: cluster %d (TypedData CID %d): %w", i, cm.CID, err)
			}

		case FillExceptionHandlers:
			if err := skipFillExceptionHandlers(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (ExceptionHandlers) pos=0x%x: %w", i, fillPos, err)
			}

		case FillContext:
			if err := skipFillContext(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (Context): %w", i, err)
			}

		case FillTypeArguments:
			if err := skipFillTypeArguments(s, cm, fillRefUnsigned, profile); err != nil {
				return fmt.Errorf("fill: cluster %d (TypeArguments): %w", i, err)
			}

		case FillClass:
			named, classInfos, err := readFillClass(s, cm, &spec, fillRefUnsigned, profile.TopLevelCid16, profile.ClassHasTokenPos)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Class): %w", i, err)
			}
			result.Named = append(result.Named, named...)
			result.Classes = append(result.Classes, classInfos...)

		case FillField:
			named, fieldInfos, err := readFillField(s, cm, &spec, fillRefUnsigned)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Field): %w", i, err)
			}
			result.Named = append(result.Named, named...)
			result.Fields = append(result.Fields, fieldInfos...)

		case FillInstance:
			if err := skipFillInstance(s, cm, fillRefUnsigned, profile.CompressedPointers, profile.PreCanonicalSplit); err != nil {
				return fmt.Errorf("fill: cluster %d (Instance CID %d): %w", i, cm.CID, err)
			}

		case FillRecord:
			if err := skipFillRecord(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (Record): %w", i, err)
			}

		case FillContextScope:
			if err := skipFillContextScope(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (ContextScope): %w", i, err)
			}

		default:
			return fmt.Errorf("fill: cluster %d (CID %d): unknown fill kind %d", i, cm.CID, spec.Kind)
		}
	}

	return nil
}

// fillOneCluster advances the stream past one cluster's fill data.
// Used by DebugFillPositions to track stream positions without collecting results.
// instrIdx is updated for Code clusters.
func fillOneCluster(s *dartfmt.Stream, cm *ClusterMeta, spec *FillSpec, fillRefUnsigned bool, profile *snapshot.VersionProfile, instrIdx *int, result *Result) error {
	switch spec.Kind {
	case FillString:
		strings, err := readFillStrings(s, cm, profile.OldStringFormat, profile.CIDs)
		if err != nil {
			return err
		}
		if result != nil {
			result.Strings = append(result.Strings, strings...)
		}
	case FillNone, FillSentinel, FillROData, FillInstructionsTable:
		// No fill data.
	case FillInlineBytes:
		return skipFillInlineBytes(s, cm)
	case FillRefs:
		_, _, _, err := readFillRefs(s, cm, spec, fillRefUnsigned)
		return err
	case FillDouble:
		return skipFillDouble(s, cm, profile.PreCanonicalSplit)
	case FillCode:
		_, err := readFillCode(s, cm, profile.CIDs, fillRefUnsigned, *instrIdx, profile.CodeNumRefs, profile.CodeTextOffsetDelta, profile.CodeStateBitsAfterRef, profile.CodeStateBitsAtEnd)
		*instrIdx += int(cm.MainCount)
		return err
	case FillObjectPool:
		_, err := readFillObjectPool(s, cm, profile.OldPoolFormat, profile.PoolTypeSwapped, fillRefUnsigned)
		return err
	case FillArray:
		return skipFillArray(s, cm, fillRefUnsigned, profile)
	case FillWeakArray:
		return skipFillWeakArray(s, cm, fillRefUnsigned)
	case FillTypedData:
		return skipFillTypedData(s, cm, profile.CIDs, profile.PreCanonicalSplit)
	case FillExceptionHandlers:
		return skipFillExceptionHandlers(s, cm, fillRefUnsigned)
	case FillContext:
		return skipFillContext(s, cm, fillRefUnsigned)
	case FillTypeArguments:
		return skipFillTypeArguments(s, cm, fillRefUnsigned, profile)
	case FillClass:
		_, _, err := readFillClass(s, cm, spec, fillRefUnsigned, profile.TopLevelCid16, profile.ClassHasTokenPos)
		return err
	case FillField:
		_, _, err := readFillField(s, cm, spec, fillRefUnsigned)
		return err
	case FillInstance:
		return skipFillInstance(s, cm, fillRefUnsigned, profile.CompressedPointers, profile.PreCanonicalSplit)
	case FillRecord:
		return skipFillRecord(s, cm, fillRefUnsigned)
	case FillContextScope:
		return skipFillContextScope(s, cm, fillRefUnsigned)
	default:
		return fmt.Errorf("unknown fill kind %d", spec.Kind)
	}
	return nil
}

// ReadFillStrings parses the Fill section of the snapshot to extract string
// values. It processes clusters in order, extracting strings from String
// clusters and skipping non-string clusters. Extracted strings are stored
// in result.Strings with their ref IDs for later correlation.
//
// Deprecated: Use ReadFill for full fill parsing including name extraction.
func ReadFillStrings(data []byte, result *Result, profile *snapshot.VersionProfile, isVM bool, snapshotSize int64) error {
	if result.FillStart <= 0 || result.FillStart >= len(data) {
		return fmt.Errorf("fill: invalid start offset %d", result.FillStart)
	}

	s := dartfmt.NewStreamAt(data, result.FillStart)
	ct := profile.CIDs

	for i := range result.Clusters {
		cm := &result.Clusters[i]
		kind := ClassifyAlloc(cm.CID, ct)

		if kind == AllocString {
			// ROData strings (non-compressed-pointers or SplitCanonical) have no fill data.
			// Extract string bytes from the data image region instead.
			if profile.SplitCanonical || !profile.CompressedPointers {
				objStart := dataImageObjStart(len(data), snapshotSize, profile)
				// Only extract from the abstract String cluster (ct.String), not subclass clusters.
				if objStart > 0 && len(cm.Lengths) > 0 && cm.CID == ct.String {
					strs := extractRODataStrings(data, cm, ct, objStart)
					result.Strings = append(result.Strings, strs...)
				}
				continue
			}
			strings, err := readFillStrings(s, cm, profile.OldStringFormat, profile.CIDs)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (String): %w", i, err)
			}
			result.Strings = append(result.Strings, strings...)
		} else {
			break
		}
	}

	return nil
}

// readFillStrings reads the fill data for a String cluster.
// When oldFormat is true (≤2.14), length is plain ReadUnsigned and
// isTwoByte is determined by the cluster CID (ct.TwoByteString).
// When oldFormat is false (≥2.16), length is encoded as (length<<1)|flag.
func readFillStrings(s *dartfmt.Stream, cm *ClusterMeta, oldFormat bool, ct *snapshot.CIDTable) ([]ParsedString, error) {
	count := int(cm.Count)
	if count <= 0 {
		return nil, nil
	}

	// In old format, the CID determines one-byte vs two-byte for the entire cluster.
	cidIsTwoByte := oldFormat && ct != nil && cm.CID == ct.TwoByteString

	strings := make([]ParsedString, 0, count)
	ref := cm.StartRef

	for i := 0; i < count; i++ {
		encoded, err := s.ReadUnsigned()
		if err != nil {
			return strings, fmt.Errorf("string %d/%d encoded: %w", i, count, err)
		}

		var length int
		var isTwoByte bool
		if oldFormat {
			length = int(encoded)
			isTwoByte = cidIsTwoByte
		} else {
			length = int(encoded >> 1)
			isTwoByte = (encoded & 1) != 0
		}

		var value string
		if isTwoByte {
			nbytes := length * 2
			raw, err := s.ReadBytes(nbytes)
			if err != nil {
				return strings, fmt.Errorf("string %d/%d data (%d bytes): %w", i, count, nbytes, err)
			}
			runes := make([]rune, length)
			for j := 0; j < length; j++ {
				runes[j] = rune(uint16(raw[j*2]) | uint16(raw[j*2+1])<<8)
			}
			value = string(runes)
		} else {
			raw, err := s.ReadBytes(length)
			if err != nil {
				return strings, fmt.Errorf("string %d/%d data (%d bytes): %w", i, count, length, err)
			}
			value = string(raw)
		}

		strings = append(strings, ParsedString{
			RefID:     ref,
			Value:     value,
			IsOneByte: !isTwoByte,
		})
		ref++
	}

	return strings, nil
}

// extractRODataStrings reads string data from the data image for ROData string clusters.
// When strings use ROData format (non-compressed-pointers), the string bytes live
// in the data image region of the snapshot, not in the fill stream.
// The alloc phase recorded offset deltas in cm.Lengths.
// dataImageObjStart is the byte offset within data[] where ROData objects begin.
func extractRODataStrings(data []byte, cm *ClusterMeta, ct *snapshot.CIDTable, dataImageObjStart int64) []ParsedString {
	if len(cm.Lengths) == 0 || dataImageObjStart <= 0 {
		return nil
	}

	runningOffset := int64(0)
	ref := cm.StartRef
	var strings []ParsedString

	for i := 0; i < len(cm.Lengths); i++ {
		// First object is at offset 0, then we add deltas cumulatively.
		objPos := dataImageObjStart + runningOffset

		// Need at least 16 bytes for header (tags + length).
		if objPos+16 > int64(len(data)) {
			ref++
			continue
		}

		tags := binary.LittleEndian.Uint64(data[objPos : objPos+8])
		cid := int((tags >> 16) & 0xFFFF)

		// Check if this is a string object.
		isOneByte := cid == ct.OneByteString
		isTwoByte := ct.TwoByteString != 0 && cid == ct.TwoByteString

		if !isOneByte && !isTwoByte {
			// Non-string ROData object (TypeArguments, Array, etc.). Skip it.
			ref++
			// Still advance runningOffset to stay aligned.
			if i < len(cm.Lengths)-1 {
				runningOffset += cm.Lengths[i] << 5
			}
			continue
		}

		lenSmi := int64(binary.LittleEndian.Uint64(data[objPos+8 : objPos+16]))
		strLen := lenSmi >> 1 // Smi decode (kSmiTagShift=1 on arm64)

		if strLen < 0 || strLen > 1<<20 {
			// Implausible length — skip.
			strings = append(strings, ParsedString{RefID: ref, Value: "", IsOneByte: isOneByte})
			ref++
			continue
		}

		dataStart := objPos + 16 // oneByteStringHeaderSize
		var value string
		if isTwoByte {
			nbytes := strLen * 2
			if dataStart+nbytes > int64(len(data)) {
				strings = append(strings, ParsedString{RefID: ref, Value: "", IsOneByte: false})
				ref++
				continue
			}
			runes := make([]rune, strLen)
			for j := int64(0); j < strLen; j++ {
				off := dataStart + j*2
				runes[j] = rune(uint16(data[off]) | uint16(data[off+1])<<8)
			}
			value = string(runes)
		} else {
			if dataStart+strLen > int64(len(data)) {
				strings = append(strings, ParsedString{RefID: ref, Value: "", IsOneByte: true})
				ref++
				continue
			}
			value = string(data[dataStart : dataStart+strLen])
		}

		strings = append(strings, ParsedString{
			RefID:     ref,
			Value:     value,
			IsOneByte: isOneByte,
		})
		ref++
		// ROData object alignment is 32 bytes (2^5) in non-compressed-pointers mode.
		runningOffset += cm.Lengths[i] << 5
	}

	return strings
}

// readFillRefs reads fill data for a FillRefs cluster, extracting name/owner/signature refs.
// When spec.IsFuncType is true, also extracts packed_parameter_counts from scalars.
// When spec.IsField is true, also extracts kind_bits and host_offset from scalars.
func readFillRefs(s *dartfmt.Stream, cm *ClusterMeta, spec *FillSpec, fillRefUnsigned bool) ([]NamedObject, []FuncTypeInfo, []FieldInfo, error) {
	count := int(cm.Count)
	if count <= 0 {
		return nil, nil, nil, nil
	}

	hasName := spec.NameIdx >= 0
	var named []NamedObject
	if hasName {
		named = make([]NamedObject, 0, count)
	}

	var funcTypes []FuncTypeInfo
	if spec.IsFuncType {
		funcTypes = make([]FuncTypeInfo, 0, count)
	}

	var fields []FieldInfo
	if spec.IsField {
		fields = make([]FieldInfo, 0, count)
	}

	ref := cm.StartRef
	for i := 0; i < count; i++ {
		// v2.10: Read<bool>(is_canonical) — 1 raw byte before refs.
		if spec.LeadingBool {
			if _, err := s.ReadByte(); err != nil {
				return named, funcTypes, fields, fmt.Errorf("obj %d/%d is_canonical: %w", i, count, err)
			}
		}

		var nameRef, ownerRef, sigRef int
		nameRef = -1
		ownerRef = -1
		sigRef = -1

		// Read refs using version-appropriate encoding.
		for j := 0; j < spec.NumRefs; j++ {
			r, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return named, funcTypes, fields, fmt.Errorf("obj %d/%d ref %d: %w", i, count, j, err)
			}
			if j == spec.NameIdx {
				nameRef = int(r)
			}
			if j == spec.OwnerIdx {
				ownerRef = int(r)
			}
			if spec.SignatureIdx > 0 && j == spec.SignatureIdx {
				sigRef = int(r)
			}
		}

		// Read scalars; extract type-specific data for FunctionType and Field clusters.
		var fieldKindBits int32
		for si, op := range spec.Scalars {
			if spec.IsFuncType && si == 1 {
				// packed_parameter_counts is OpTagged32 at scalar index 1.
				packed, err := s.ReadTagged32()
				if err != nil {
					return named, funcTypes, fields, fmt.Errorf("obj %d/%d packed_param_counts: %w", i, count, err)
				}
				hasImplicit := (packed & 1) != 0
				numFixed := int((packed >> 2) & 0x3FFF)
				numOptional := int((packed >> 16) & 0x3FFF)
				if hasImplicit && numFixed > 0 {
					numFixed-- // subtract implicit 'this'
				}
				funcTypes = append(funcTypes, FuncTypeInfo{
					RefID:       ref,
					NumFixed:    numFixed,
					NumOptional: numOptional,
					HasImplicit: hasImplicit,
				})
			} else if spec.IsField && si == 0 {
				// kind_bits is OpTagged32 at scalar index 0.
				kb, err := s.ReadTagged32()
				if err != nil {
					return named, funcTypes, fields, fmt.Errorf("obj %d/%d kind_bits: %w", i, count, err)
				}
				fieldKindBits = int32(kb)
			} else if spec.IsField && si == 1 {
				// host_offset_or_field_id is OpRefId at scalar index 1.
				hostOff, err := s.ReadRefId()
				if err != nil {
					return named, funcTypes, fields, fmt.Errorf("obj %d/%d host_offset: %w", i, count, err)
				}
				isStatic := (fieldKindBits>>1)&1 != 0
				offset := int32(hostOff)
				if isStatic {
					offset = -1
				}
				fields = append(fields, FieldInfo{
					RefID:      ref,
					NameRefID:  nameRef,
					OwnerRefID: ownerRef,
					KindBits:   fieldKindBits,
					HostOffset: offset,
				})
			} else {
				if err := skipScalar(s, op); err != nil {
					return named, funcTypes, fields, fmt.Errorf("obj %d/%d scalar: %w", i, count, err)
				}
			}
		}

		if hasName {
			named = append(named, NamedObject{
				CID:            cm.CID,
				RefID:          ref,
				NameRefID:      nameRef,
				OwnerRefID:     ownerRef,
				SignatureRefID: sigRef,
			})
		}
		ref++
	}

	return named, funcTypes, fields, nil
}

// skipScalar reads and discards one scalar value.
func skipScalar(s *dartfmt.Stream, op ScalarOp) error {
	switch op {
	case OpTagged32, OpUint16, OpInt16:
		// Read<int32_t/uint32_t/uint16_t/int16_t>: variable-length, marker 192.
		_, err := s.ReadTagged32()
		return err
	case OpTagged64:
		// Read<int64_t/double/uword>: variable-length, marker 192.
		_, err := s.ReadTagged64()
		return err
	case OpUnsigned:
		// ReadUnsigned: variable-length, marker 128.
		_, err := s.ReadUnsigned()
		return err
	case OpBool, OpUint8, OpInt8:
		// Read<uint8_t/int8_t/bool>: Raw<1,T> = 1 raw byte.
		_, err := s.ReadByte()
		return err
	case OpRefId:
		// ReadRef: big-endian signed-byte accumulation (trailing ref after scalars).
		_, err := s.ReadRefId()
		return err
	default:
		return fmt.Errorf("unknown scalar op %d", op)
	}
}

// readFillClass parses Class fill data with conditional bitmap read.
// Predefined classes (i < mainCount): bitmap always read.
// New classes (i >= mainCount): bitmap only if !IsTopLevelCid(class_id).
// ≤2.18: kTopLevelCidOffset = 1<<16. ≥2.19: kTopLevelCidOffset = 1<<20.
func readFillClass(s *dartfmt.Stream, cm *ClusterMeta, spec *FillSpec, fillRefUnsigned, topLevelCid16, classHasTokenPos bool) ([]NamedObject, []ClassInfo, error) {
	count := int(cm.Count)
	if count <= 0 {
		return nil, nil, nil
	}

	topLevelOffset := int64(1 << 20)
	if topLevelCid16 {
		topLevelOffset = 1 << 16
	}

	named := make([]NamedObject, 0, count)
	classes := make([]ClassInfo, 0, count)
	ref := cm.StartRef

	for i := 0; i < count; i++ {
		var nameRef int = -1

		// ReadFromTo: 13 refs.
		for j := 0; j < spec.NumRefs; j++ {
			r, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return named, classes, fmt.Errorf("obj %d/%d ref %d/%d: %w", i, count, j, spec.NumRefs, err)
			}
			if j == spec.NameIdx {
				nameRef = int(r)
			}
		}

		// ReadCid (class_id) — Read<int32_t> = ReadTagged32.
		classID, err := s.ReadTagged32()
		if err != nil {
			return named, classes, fmt.Errorf("obj %d/%d class_id: %w", i, count, err)
		}

		// Read<int32_t>(instance_size) + Read<int32_t>(next_field_offset).
		instanceSize, err := s.ReadTagged32()
		if err != nil {
			return named, classes, fmt.Errorf("obj %d/%d instance_size: %w", i, count, err)
		}
		nextFieldOff, err := s.ReadTagged32()
		if err != nil {
			return named, classes, fmt.Errorf("obj %d/%d next_field_offset: %w", i, count, err)
		}
		// Read<int32_t>(type_args_offset).
		typeArgsOff, err := s.ReadTagged32()
		if err != nil {
			return named, classes, fmt.Errorf("obj %d/%d type_args_offset: %w", i, count, err)
		}
		// Read<int16_t>(num_type_arguments) — Read16 marker 192.
		if _, err := s.ReadTagged32(); err != nil {
			return named, classes, fmt.Errorf("obj %d/%d num_type_args: %w", i, count, err)
		}
		// Read<uint16_t>(num_native_fields) — Read16 marker 192.
		if _, err := s.ReadTagged32(); err != nil {
			return named, classes, fmt.Errorf("obj %d/%d num_native_fields: %w", i, count, err)
		}
		// v2.10/v2.13: ReadTokenPosition(token_pos) + ReadTokenPosition(end_token_pos).
		// These are Read<int32_t> each; not present in v2.14+ AOT.
		if classHasTokenPos {
			if _, err := s.ReadTagged32(); err != nil {
				return named, classes, fmt.Errorf("obj %d/%d token_pos: %w", i, count, err)
			}
			if _, err := s.ReadTagged32(); err != nil {
				return named, classes, fmt.Errorf("obj %d/%d end_token_pos: %w", i, count, err)
			}
		}
		// Read<uint32_t>(state_bits) — Read32 marker 192.
		if _, err := s.ReadTagged32(); err != nil {
			return named, classes, fmt.Errorf("obj %d/%d state_bits: %w", i, count, err)
		}

		// ReadUnsigned64 (bitmap) — conditional for new classes.
		isPredefined := int64(i) < cm.MainCount
		isTopLevel := int64(int32(classID)) >= topLevelOffset
		if isPredefined || !isTopLevel {
			if _, err := s.ReadUnsigned(); err != nil {
				return named, classes, fmt.Errorf("obj %d/%d bitmap: %w", i, count, err)
			}
		}

		named = append(named, NamedObject{
			CID:        cm.CID,
			RefID:      ref,
			NameRefID:  nameRef,
			OwnerRefID: -1,
		})
		classes = append(classes, ClassInfo{
			RefID:        ref,
			NameRefID:    nameRef,
			ClassID:      int32(classID),
			InstanceSize: int32(instanceSize),
			NextFieldOff: int32(nextFieldOff),
			TypeArgsOff:  int32(typeArgsOff),
		})
		ref++
	}
	return named, classes, nil
}

// readFillField parses v2.17.6 Field fill with conditional ReadUnsigned for static fields.
// v2.17.6 AOT: ReadFromTo(4 refs) + Read<uint16_t>(kind_bits) + ReadRef(value_or_offset) +
// [if static: ReadUnsigned(field_id)].
// kStaticBit = 1 in v2.17.6 kind_bits.
func readFillField(s *dartfmt.Stream, cm *ClusterMeta, spec *FillSpec, fillRefUnsigned bool) ([]NamedObject, []FieldInfo, error) {
	count := int(cm.Count)
	if count <= 0 {
		return nil, nil, nil
	}

	named := make([]NamedObject, 0, count)
	fields := make([]FieldInfo, 0, count)
	ref := cm.StartRef

	for i := 0; i < count; i++ {
		var nameRef, ownerRef int
		nameRef = -1
		ownerRef = -1

		// ReadFromTo: 4 refs (name, owner, type, initializer_function).
		for j := 0; j < spec.NumRefs; j++ {
			r, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return named, fields, fmt.Errorf("field %d/%d ref %d: %w", i, count, j, err)
			}
			if j == spec.NameIdx {
				nameRef = int(r)
			}
			if j == spec.OwnerIdx {
				ownerRef = int(r)
			}
		}

		// Read<uint16_t>(kind_bits) — Read16(marker 192).
		kindBits, err := s.ReadTagged32()
		if err != nil {
			return named, fields, fmt.Errorf("field %d/%d kind_bits: %w", i, count, err)
		}

		// ReadRef(value_or_offset).
		valOrOff, err := readRef(s, fillRefUnsigned)
		if err != nil {
			return named, fields, fmt.Errorf("field %d/%d value_or_offset: %w", i, count, err)
		}

		// Conditional: if static field, read field_id.
		isStatic := (kindBits>>1)&1 != 0
		if isStatic {
			if _, err := s.ReadUnsigned(); err != nil {
				return named, fields, fmt.Errorf("field %d/%d field_id: %w", i, count, err)
			}
		}

		offset := int32(valOrOff)
		if isStatic {
			offset = -1
		}
		fields = append(fields, FieldInfo{
			RefID:      ref,
			NameRefID:  nameRef,
			OwnerRefID: ownerRef,
			KindBits:   int32(kindBits),
			HostOffset: offset,
		})

		named = append(named, NamedObject{
			CID:        cm.CID,
			RefID:      ref,
			NameRefID:  nameRef,
			OwnerRefID: ownerRef,
		})
		ref++
	}
	return named, fields, nil
}

// skipFillDouble skips Double fill.
// Read<double>() → Raw<8,double>::Read() → Read64(kEndByteMarker=192) = variable-length.
// v2.10: Read<bool>(is_canonical) before the double.
func skipFillDouble(s *dartfmt.Stream, cm *ClusterMeta, preCanonicalSplit bool) error {
	for i := int64(0); i < cm.Count; i++ {
		if preCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("double %d/%d is_canonical: %w", i, cm.Count, err)
			}
		}
		if _, err := s.ReadTagged64(); err != nil {
			return fmt.Errorf("double %d/%d: %w", i, cm.Count, err)
		}
	}
	return nil
}

// readFillCode reads Code fill data, extracting owner refs and instruction metadata.
// AOT PRODUCT: ReadInstructions + N ReadRef per code.
// v2.16+: ReadInstructions = 1 ReadUnsigned (payload_info). 6 refs.
// v2.10-v2.15: ReadInstructions = 2 ReadUnsigned (text_offset_delta + payload_info). 7 refs.
// Deferred codes skip ReadInstructions (no stream read).
// Ref 0 = owner (Function/Closure/FfiTrampolineData).
// instrIdxBase is the running instructions_index_ counter from previous Code clusters.
//
// stateBitsAfterRef: 0 = no state_bits in fill (v2.10, v2.14+).
// N>0 = state_bits is read after first N refs (v2.13: N=1). DiscardedBit (bit 3)
// of state_bits determines whether remaining refs are skipped.
func readFillCode(s *dartfmt.Stream, cm *ClusterMeta, ct *snapshot.CIDTable, fillRefUnsigned bool, instrIdxBase int, codeNumRefs int, textOffsetDelta bool, stateBitsAfterRef int, stateBitsAtEnd bool) ([]CodeEntry, error) {
	numRefs := codeNumRefs
	if numRefs == 0 {
		numRefs = 6 // default: owner, exception_handlers, pc_descriptors, catch_entry, inlined_id_to_function, code_source_map
	}
	codes := make([]CodeEntry, 0, cm.Count)
	ref := cm.StartRef
	instrIdx := instrIdxBase
	discardedCount := 0
	for i := int64(0); i < cm.Count; i++ {
		var payloadInfo int64
		clusterIndex := -1
		traceCode := debugFill && i < 5

		// v2.14+: discarded status from alloc phase. v2.13: determined from state_bits below.
		discarded := cm.DiscardedCodes[i]

		posStart := s.Position()

		// Dump raw bytes for first 3, last 3, and codes near known failure points.
		if debugFill && (i < 3 || i >= cm.Count-3 || (i >= 21600 && i <= 21610)) {
			saved := s.Position()
			hexBytes, _ := s.ReadBytes(30)
			s.SetPosition(saved)
			fmt.Fprintf(os.Stderr, "  code[%d] RAW@0x%x: %x\n", i, posStart, hexBytes)
		}

		// Main (non-deferred) codes: ReadInstructions reads payload data.
		// v2.10-v2.15: ReadUnsigned(text_offset_delta) + ReadUnsigned(payload_info).
		//   v2.14+: discarded codes also read compressed_stackmaps(ReadRef) in ReadInstructions.
		// v2.16+: ReadUnsigned(payload_info) only.
		// Deferred codes: ReadInstructions does nothing (early return).
		if i < cm.MainCount {
			if textOffsetDelta {
				if _, err := s.ReadUnsigned(); err != nil {
					return codes, fmt.Errorf("code %d/%d text_offset_delta: %w", i, cm.Count, err)
				}
			}
			pi, err := s.ReadUnsigned()
			if err != nil {
				return codes, fmt.Errorf("code %d/%d payload_info: %w", i, cm.Count, err)
			}
			payloadInfo = pi
			clusterIndex = instrIdx
			instrIdx++

			// v2.14+: discarded codes read compressed_stackmaps ref inside ReadInstructions,
			// then return without reading any other refs or state_bits.
			if discarded && stateBitsAfterRef == 0 {
				if _, err := readRef(s, fillRefUnsigned); err != nil {
					return codes, fmt.Errorf("code %d/%d discarded compressed_stackmaps: %w", i, cm.Count, err)
				}
			}
		}

		// v2.13 (stateBitsAfterRef > 0): compressed_stackmaps → state_bits → [if discarded: stop] → 6 refs.
		// All codes read compressed_stackmaps and state_bits. DiscardedBit (bit 3) of state_bits
		// determines whether remaining refs are read. This is different from v2.14+ where
		// discarded status comes from the alloc phase.
		var ownerRef int
		if stateBitsAfterRef > 0 {
			// Read first N refs (before state_bits) — all codes, including discarded.
			for j := 0; j < stateBitsAfterRef; j++ {
				if _, err := readRef(s, fillRefUnsigned); err != nil {
					return codes, fmt.Errorf("code %d/%d ref %d: %w", i, cm.Count, j, err)
				}
			}
			// Read state_bits (Read<int32_t> VLE).
			sbPos := s.Position()
			sb, err := s.ReadTagged32()
			if err != nil {
				// Dump context for diagnosis.
				if debugFill {
					fmt.Fprintf(os.Stderr, "  code[%d] state_bits ERR at pos=0x%x (code start=0x%x)\n", i, sbPos, posStart)
					// Dump raw bytes from code start.
					saved := s.Position()
					s.SetPosition(posStart)
					hexBytes, _ := s.ReadBytes(40)
					s.SetPosition(saved)
					fmt.Fprintf(os.Stderr, "  hex@0x%x=%x\n", posStart, hexBytes)
				}
				return codes, fmt.Errorf("code %d/%d state_bits: %w", i, cm.Count, err)
			}
			if debugFill && (i%1000 == 0 || (i >= 21595 && i <= 21610)) {
				fmt.Fprintf(os.Stderr, "  code[%d] pos=0x%x sb=0x%x discarded=%v cumDisc=%d\n",
					i, posStart, sb, (sb>>3)&1 != 0, discardedCount)
			}
			// DiscardedBit = bit 3 of state_bits.
			discarded = (sb>>3)&1 != 0
			if discarded {
				discardedCount++
				if traceCode {
					fmt.Fprintf(os.Stderr, "  code[%d] pos=0x%x state_bits=0x%x DISCARDED\n", i, posStart, sb)
				}
				goto done
			}
			// Read remaining refs after state_bits.
			for j := stateBitsAfterRef; j < numRefs; j++ {
				r, err := readRef(s, fillRefUnsigned)
				if err != nil {
					return codes, fmt.Errorf("code %d/%d ref %d: %w", i, cm.Count, j, err)
				}
				// Owner is the first ref after state_bits (e.g., ref[1] for v2.13).
				if j == stateBitsAfterRef {
					ownerRef = int(r)
				}
			}
		} else if !discarded {
			// v2.10, v2.14+: read all refs in order (no interleaved state_bits).
			for j := 0; j < numRefs; j++ {
				r, err := readRef(s, fillRefUnsigned)
				if err != nil {
					return codes, fmt.Errorf("code %d/%d ref %d: %w", i, cm.Count, j, err)
				}
				if j == 0 {
					ownerRef = int(r)
				}
			}
		}

		// v2.10: state_bits_ = Read<int32_t>() after ALL refs, unconditionally (no discarded check).
		if stateBitsAtEnd {
			if _, err := s.ReadTagged32(); err != nil {
				return codes, fmt.Errorf("code %d/%d state_bits_at_end: %w", i, cm.Count, err)
			}
		}

	done:
		if traceCode {
			fmt.Fprintf(os.Stderr, "  code[%d] pos=0x%x total=%d discarded=%v\n",
				i, posStart, s.Position()-posStart, discarded)
		}
		if debugFill && (i < 5 || i >= cm.Count-3 || i == cm.MainCount-1 || i == cm.MainCount || i%5000 == 0) {
			fmt.Fprintf(os.Stderr, "  code[%d/%d] main=%d owner=%d discarded=%v endPos=0x%x\n", i, cm.Count, cm.MainCount, ownerRef, discarded, s.Position())
		}
		codes = append(codes, CodeEntry{
			RefID:        ref,
			OwnerRef:     ownerRef,
			ClusterIndex: clusterIndex,
			PayloadInfo:  payloadInfo,
		})
		ref++
	}
	if debugFill && discardedCount > 0 {
		fmt.Fprintf(os.Stderr, "  code: %d/%d discarded (from state_bits)\n", discardedCount, cm.Count)
	}
	return codes, nil
}

// readFillObjectPool reads ObjectPool fill data and captures entries.
// Per pool: ReadUnsigned(length) + length × (ReadByte(entry_bits) + type-dependent data).
//
// v2.17.6: TypeBits[0:7] (7 bits), PatchableBit[7].
//
//	0=kTaggedObject→ReadRef, 1=kImmediate→Read<intptr_t>, 2+=nothing.
//
// v3.x: TypeBits[0:4], PatchableBit[4], SnapshotBehaviorBits[5:8].
//
//	behavior 0: 0=kImmediate→Read<intptr_t>, 1=kTaggedObject→ReadRef, 2=kNativeFunction→nothing.
//	behavior 1,2,3: nothing.
func readFillObjectPool(s *dartfmt.Stream, cm *ClusterMeta, oldPoolFormat, poolTypeSwapped, fillRefUnsigned bool) ([]PoolEntry, error) {
	if debugFill {
		saved := s.Position()
		rawBytes, _ := s.ReadBytes(40)
		s.SetPosition(saved)
		fmt.Fprintf(os.Stderr, "  ObjectPool fill start @0x%x raw=%x\n", saved, rawBytes)
	}
	var entries []PoolEntry
	idx := 0
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return nil, fmt.Errorf("pool %d/%d length: %w", i, cm.Count, err)
		}
		for j := int64(0); j < length; j++ {
			entryBits, err := s.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("pool %d entry %d bits: %w", i, j, err)
			}

			pe := PoolEntry{Index: idx}
			idx++

			if oldPoolFormat {
				// ≤3.2: TypeBits = entryBits & 0x7F (7 bits).
				typeBits := entryBits & 0x7F
				// v3.2 swapped kImmediate(0) and kTaggedObject(1). Normalize to pre-3.2 ordering.
				if poolTypeSwapped && typeBits <= 1 {
					typeBits ^= 1
				}
				switch typeBits {
				case 0: // kTaggedObject → ReadRef
					ref, err := readRef(s, fillRefUnsigned)
					if err != nil {
						return nil, fmt.Errorf("pool %d entry %d ref (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
					}
					pe.Kind = PoolTagged
					pe.RefID = int(ref)
				case 1: // kImmediate → Read<intptr_t> = Read64
					imm, err := s.ReadTagged64()
					if err != nil {
						return nil, fmt.Errorf("pool %d entry %d imm (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
					}
					pe.Kind = PoolImmediate
					pe.Imm = imm
				case 2, 3: // kNativeFunction, kNativeFunctionWrapper → nothing
					pe.Kind = PoolNative
				case 4: // kNativeEntryData → ReadRef (same as kTaggedObject)
					ref, err := readRef(s, fillRefUnsigned)
					if err != nil {
						return nil, fmt.Errorf("pool %d entry %d native_entry_data ref (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
					}
					pe.Kind = PoolTagged
					pe.RefID = int(ref)
				default:
					return nil, fmt.Errorf("pool %d entry %d: unknown type %d (bits=0x%02x pos=0x%x)", i, j, typeBits, entryBits, s.Position())
				}
			} else {
				// v3.x: SnapshotBehaviorBits = entryBits >> 5 (3 bits).
				behaviorBits := entryBits >> 5
				typeBits := entryBits & 0x0F
				switch behaviorBits {
				case 0: // kSnapshotable
					switch typeBits {
					case 0: // kImmediate → Read<intptr_t>
						imm, err := s.ReadTagged64()
						if err != nil {
							return nil, fmt.Errorf("pool %d entry %d imm: %w", i, j, err)
						}
						pe.Kind = PoolImmediate
						pe.Imm = imm
					case 1: // kTaggedObject → ReadRef
						ref, err := readRef(s, fillRefUnsigned)
						if err != nil {
							return nil, fmt.Errorf("pool %d entry %d ref: %w", i, j, err)
						}
						pe.Kind = PoolTagged
						pe.RefID = int(ref)
					case 2: // kNativeFunction → nothing
						pe.Kind = PoolNative
					default:
						return nil, fmt.Errorf("pool %d entry %d: unknown type %d", i, j, typeBits)
					}
				case 1, 2, 3, 4: // kResetToBootstrapNative, kResetToSwitchableCallMissEntryPoint, kSetToZero, kResetToMegamorphicCallEntryPoint
					pe.Kind = PoolEmpty
				default:
					return nil, fmt.Errorf("pool %d entry %d: unknown snapshot behavior %d", i, j, behaviorBits)
				}
			}
			entries = append(entries, pe)
		}
	}
	return entries, nil
}

// skipFillInlineBytes skips clusters that store inline byte data.
// Per object: ReadUnsigned(length) + ReadBytes(length).
// Used for PcDescriptors, CodeSourceMap, CompressedStackMaps with compressed pointers.
func skipFillInlineBytes(s *dartfmt.Stream, cm *ClusterMeta) error {
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("inline_bytes %d/%d length: %w", i, cm.Count, err)
		}
		if err := s.Skip(int(length)); err != nil {
			return fmt.Errorf("inline_bytes %d/%d data (%d bytes): %w", i, cm.Count, length, err)
		}
	}
	return nil
}

// skipFillArray skips Array/ImmutableArray fill.
//
// New format (v2.16+):
//
//	Per object: ReadUnsigned(length) + ReadRef(type_args) + length × ReadRef(element).
//
// Old format (v2.13, v2.15 — OldArrayFill):
//
//	Per object: ReadRef(type_args) + N × ReadRef(element) where N = cm.Lengths[i] from alloc.
func skipFillArray(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool, profile *snapshot.VersionProfile) error {
	if profile.OldArrayFill {
		return skipFillArrayOld(s, cm, fillRefUnsigned)
	}
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("array %d/%d length: %w", i, cm.Count, err)
		}
		// v2.10: Read<bool>(is_canonical) after length.
		if profile.PreCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("array %d is_canonical: %w", i, err)
			}
		}
		// ReadRef(type_arguments).
		if _, err := readRef(s, fillRefUnsigned); err != nil {
			return fmt.Errorf("array %d type_args: %w", i, err)
		}
		for j := int64(0); j < length; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("array %d elem %d/%d: %w", i, j, length, err)
			}
		}
	}
	return nil
}

// skipFillArrayOld handles the pre-v2.16 Array fill format.
// Per object: ReadRef(type_args) + N × ReadRef(element) where N = cm.Lengths[i] from alloc.
func skipFillArrayOld(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	for i := int64(0); i < cm.Count; i++ {
		allocLen := int64(0)
		if int(i) < len(cm.Lengths) {
			allocLen = cm.Lengths[i]
		}
		// ReadRef(type_arguments).
		if _, err := readRef(s, fillRefUnsigned); err != nil {
			return fmt.Errorf("array_old %d/%d type_args: %w", i, cm.Count, err)
		}
		for j := int64(0); j < allocLen; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("array_old %d elem %d/%d: %w", i, j, allocLen, err)
			}
		}
	}
	return nil
}

// skipFillWeakArray skips WeakArray fill.
// Per object: ReadUnsigned(length) + length × ReadRef(element).
func skipFillWeakArray(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("weak_array %d/%d length: %w", i, cm.Count, err)
		}
		for j := int64(0); j < length; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("weak_array %d elem %d/%d: %w", i, j, length, err)
			}
		}
	}
	return nil
}

// skipFillTypedData skips TypedData fill.
// Per object: ReadUnsigned(length) + length × element_size raw bytes.
// v2.10: Read<bool>(is_canonical) after length.
func skipFillTypedData(s *dartfmt.Stream, cm *ClusterMeta, ct *snapshot.CIDTable, preCanonicalSplit bool) error {
	elemSize := typedDataElementSize(cm.CID, ct)
	for i := int64(0); i < cm.Count; i++ {
		// Fill reads: ReadUnsigned(length), then length * element_size raw bytes.
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("typed_data %d/%d length: %w", i, cm.Count, err)
		}
		if preCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("typed_data %d is_canonical: %w", i, err)
			}
		}
		nbytes := int(length) * elemSize
		if err := s.Skip(nbytes); err != nil {
			return fmt.Errorf("typed_data %d/%d data (%d bytes): %w", i, cm.Count, nbytes, err)
		}
	}
	return nil
}

// skipFillExceptionHandlers skips ExceptionHandlers fill.
// v2.17.6: ReadUnsigned(length) directly.
// v3.x: ReadUnsigned(packed_fields), length = packed_fields >> 1 (AsyncHandlerBit at bit 0).
// Then: ReadRef(handled_types_data) + per-handler: Read<uint32_t>(pc_offset) +
// Read<int16_t>(outer_try_index) + Read<int8_t>(needs_stacktrace) +
// Read<int8_t>(has_catch_all) + Read<int8_t>(is_generated).
func skipFillExceptionHandlers(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	for i := int64(0); i < cm.Count; i++ {
		raw, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("exc_handlers %d length/packed: %w", i, err)
		}
		// v2.17.6: value IS the length. v3.x: length = packed_fields >> 1.
		length := raw
		if !fillRefUnsigned {
			length = raw >> 1
		}
		// ReadRef(handled_types_data).
		if _, err := readRef(s, fillRefUnsigned); err != nil {
			return fmt.Errorf("exc_handlers %d handled_types: %w", i, err)
		}
		for j := int64(0); j < length; j++ {
			// Read<uint32_t>(handler_pc_offset) — marker 192.
			if _, err := s.ReadTagged32(); err != nil {
				return fmt.Errorf("exc_handlers %d handler %d pc: %w", i, j, err)
			}
			// Read<int16_t>(outer_try_index) — marker 192 (Read16).
			if _, err := s.ReadTagged32(); err != nil {
				return fmt.Errorf("exc_handlers %d handler %d try_idx: %w", i, j, err)
			}
			// Read<int8_t>(needs_stacktrace) — Raw<1,T> = ReadByte.
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("exc_handlers %d handler %d stacktrace: %w", i, j, err)
			}
			// Read<int8_t>(has_catch_all) — Raw<1,T> = ReadByte.
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("exc_handlers %d handler %d catch_all: %w", i, j, err)
			}
			// Read<int8_t>(is_generated) — Raw<1,T> = ReadByte.
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("exc_handlers %d handler %d generated: %w", i, j, err)
			}
		}
	}
	return nil
}

// skipFillContext skips Context fill.
// Per object: ReadRef(parent) + num_variables × ReadRef(variable).
// skipFillContext skips Context fill.
// Per object: ReadUnsigned(length) + ReadRef(parent) + length × ReadRef(variable).
func skipFillContext(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("context %d/%d length: %w", i, cm.Count, err)
		}
		// ReadRef(parent).
		if _, err := readRef(s, fillRefUnsigned); err != nil {
			return fmt.Errorf("context %d parent: %w", i, err)
		}
		for j := int64(0); j < length; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("context %d var %d/%d: %w", i, j, length, err)
			}
		}
	}
	return nil
}

// skipFillTypeArguments skips TypeArguments fill.
//
// New format (v2.14, v2.16+):
//
//	Per object: ReadUnsigned(length) + Read<int32_t>(hash) + ReadUnsigned(nullability) +
//	  ReadRef(instantiations) + length × ReadRef(type).
//
// Old format (v2.13, v2.15 — OldTypeArgsFill):
//
//	Per object: ReadRef(instantiations) + N × ReadRef(type) + Read<int32_t>(hash)
//	  where N = cm.Lengths[i] from alloc phase (no length/nullability in stream).
func skipFillTypeArguments(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool, profile *snapshot.VersionProfile) error {
	if profile.OldTypeArgsFill {
		return skipFillTypeArgumentsOld(s, cm, fillRefUnsigned)
	}
	if debugFill {
		pos := s.Position()
		peek, _ := s.ReadBytes(32)
		s.SetPosition(pos)
		fmt.Fprintf(os.Stderr, "  TypeArgs fill start pos=0x%x raw=%x\n", pos, peek)
		if len(cm.Lengths) > 0 {
			n := 5
			if len(cm.Lengths) < n {
				n = len(cm.Lengths)
			}
			fmt.Fprintf(os.Stderr, "  TypeArgs alloc lengths[0:%d]=%v\n", n, cm.Lengths[:n])
		}
	}
	for i := int64(0); i < cm.Count; i++ {
		itemPos := s.Position()
		// Fill reads length from stream (not from alloc).
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("type_args %d/%d length: %w", i, cm.Count, err)
		}
		if debugFill && (i < 3 || i >= 45 && i <= 50) {
			fmt.Fprintf(os.Stderr, "  typeargs[%d] pos=0x%x length=%d\n", i, itemPos, length)
		}
		// v2.10: Read<bool>(is_canonical) — 1 raw byte.
		if profile.PreCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("type_args %d is_canonical: %w", i, err)
			}
		}
		// Read<int32_t>(hash) — marker 192.
		hash, err := s.ReadTagged32()
		if err != nil {
			return fmt.Errorf("type_args %d hash: %w", i, err)
		}
		// ReadUnsigned(nullability) — marker 128.
		nullab, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("type_args %d nullability: %w", i, err)
		}
		// ReadRef(instantiations).
		inst, err := readRef(s, fillRefUnsigned)
		if err != nil {
			return fmt.Errorf("type_args %d instantiations: %w", i, err)
		}
		if debugFill && i < 3 {
			fmt.Fprintf(os.Stderr, "    hash=%d nullab=%d inst=%d\n", hash, nullab, inst)
		}
		for j := int64(0); j < length; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("type_args %d type %d/%d: %w", i, j, length, err)
			}
		}
	}
	return nil
}

// skipFillTypeArgumentsOld handles the pre-v2.14 TypeArguments fill format.
// Per object: ReadRef(instantiations) + N × ReadRef(type) + Read<int32_t>(hash)
// where N = cm.Lengths[i] from the alloc phase.
func skipFillTypeArgumentsOld(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	for i := int64(0); i < cm.Count; i++ {
		allocLen := int64(1)
		if int(i) < len(cm.Lengths) {
			allocLen = cm.Lengths[i]
		}
		// ReadRef(instantiations).
		if _, err := readRef(s, fillRefUnsigned); err != nil {
			return fmt.Errorf("type_args_old %d/%d instantiations: %w", i, cm.Count, err)
		}
		// N × ReadRef(type) where N = alloc length.
		for j := int64(0); j < allocLen; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("type_args_old %d type %d/%d: %w", i, j, allocLen, err)
			}
		}
		// Read<int32_t>(hash).
		if _, err := s.ReadTagged32(); err != nil {
			return fmt.Errorf("type_args_old %d hash: %w", i, err)
		}
	}
	return nil
}

// skipFillInstance skips Instance fill.
// Format: ReadUnsigned64(unboxed_bitmap) ONCE, then per object:
//
//	for each field offset from header to next_field_offset:
//	  if unboxed: ReadWordWith32BitReads (2 × ReadTagged32)
//	  else: ReadRef (ReadRefId)
//
// header_words: 2 for compressed pointers (tags + hash = 2 × 4 bytes = 2 compressed words).
// header_words: 1 for uncompressed (tags = 1 × 8 bytes = 1 word).
func skipFillInstance(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned, compressedPointers, preCanonicalSplit bool) error {
	// v2.13+: ReadUnsigned64(unboxed_fields_bitmap) read once before all objects.
	// v2.10 (PreCanonicalSplit): bitmap from class table (not in stream); assume 0.
	var bitmap int64
	if !preCanonicalSplit {
		var err error
		bitmap, err = s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("instance(%d) bitmap: %w", cm.CID, err)
		}
	}

	nfo := int(cm.NextFieldOffsetInWords)
	if nfo <= 0 {
		return nil
	}
	// Compressed pointers: header = 2 compressed words (tags 4B + hash 4B).
	// Uncompressed: header = 1 word (tags 8B).
	headerWords := 1
	if compressedPointers {
		headerWords = 2
	}
	numFields := nfo - headerWords
	if numFields < 0 {
		numFields = 0
	}

	for i := int64(0); i < cm.Count; i++ {
		// v2.10: Read<bool>(is_canonical) per object — 1 raw byte.
		if preCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("instance(%d) %d/%d is_canonical: %w", cm.CID, i, cm.Count, err)
			}
		}
		for j := 0; j < numFields; j++ {
			fieldWordIdx := headerWords + j
			isUnboxed := (bitmap>>uint(fieldWordIdx))&1 != 0
			if isUnboxed {
				// ReadWordWith32BitReads: 2 × Read<uint32_t> (marker 192).
				if _, err := s.ReadTagged32(); err != nil {
					return fmt.Errorf("instance(%d) %d/%d unboxed field %d lo: %w", cm.CID, i, cm.Count, j, err)
				}
				if _, err := s.ReadTagged32(); err != nil {
					return fmt.Errorf("instance(%d) %d/%d unboxed field %d hi: %w", cm.CID, i, cm.Count, j, err)
				}
			} else {
				if _, err := readRef(s, fillRefUnsigned); err != nil {
					return fmt.Errorf("instance(%d) %d/%d ref %d: %w", cm.CID, i, cm.Count, j, err)
				}
			}
		}
	}
	return nil
}

// skipFillRecord skips Record fill.
// Per object: ReadRef(shape) + num_fields × ReadRef(field).
// skipFillRecord skips Record fill.
// Per object: ReadUnsigned(shape) + num_fields × ReadRef(field).
// num_fields = RecordShape.NumFieldsBitField (lower 16 bits of shape).
func skipFillRecord(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	for i := int64(0); i < cm.Count; i++ {
		// Fill reads shape from stream; num_fields decoded from lower 16 bits.
		shape, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("record %d/%d shape: %w", i, cm.Count, err)
		}
		numFields := shape & 0xFFFF
		for j := int64(0); j < numFields; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("record %d field %d/%d: %w", i, j, numFields, err)
			}
		}
	}
	return nil
}

// skipFillContextScope skips ContextScope fill.
// Per scope: num_variables entries, each with multiple refs and scalars.
// ContextScope is non-AOT only (context_scope_ = null in AOT ClosureData).
// In practice this cluster type should not appear in AOT snapshots,
// but we handle it for completeness.
// skipFillContextScope skips ContextScope fill.
// ContextScope is non-AOT only. Should not appear in AOT PRODUCT snapshots.
// Per object: ReadUnsigned(length) + ReadByte(is_implicit) + ReadFromTo(scope, length).
// ReadFromTo reads all pointer fields per variable entry as ReadRef.
func skipFillContextScope(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	// ContextScope shouldn't appear in AOT. If it does, we'll attempt to skip
	// using the known structure: ReadUnsigned(length) + ReadByte(is_implicit) +
	// then ReadFromTo which reads pointer fields per variable.
	// Each variable in ContextScope has ~7 pointer fields.
	const refsPerVariable = 7
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("context_scope %d/%d length: %w", i, cm.Count, err)
		}
		// Read<bool>(is_implicit) = ReadByte.
		if _, err := s.ReadByte(); err != nil {
			return fmt.Errorf("context_scope %d is_implicit: %w", i, err)
		}
		// ReadFromTo reads all pointer fields for this scope.
		// Each variable entry has ~7 pointer fields.
		totalRefs := int64(refsPerVariable) * length
		for j := int64(0); j < totalRefs; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("context_scope %d ref %d/%d: %w", i, j, totalRefs, err)
			}
		}
	}
	return nil
}

// typedDataElementSize returns the element size in bytes for a TypedData CID.
func typedDataElementSize(cid int, ct *snapshot.CIDTable) int {
	// DeltaEncodedTypedData (NativePointer) uses element size 1.
	if ct.NativePointerCid != 0 && cid == ct.NativePointerCid {
		return 1
	}

	// Generic TypedData CID (the base class) — element size 1.
	if cid == ct.TypedData {
		return 1
	}

	// Internal TypedData CIDs: stride-based lookup.
	if ct.TypedDataInt8ArrayCid == 0 || ct.TypedDataCidStride == 0 {
		return 1
	}
	idx := (cid - ct.TypedDataInt8ArrayCid) / ct.TypedDataCidStride
	// Element sizes by TypedData type index:
	// 0=Int8(1), 1=Uint8(1), 2=Uint8Clamped(1),
	// 3=Int16(2), 4=Uint16(2), 5=Int32(4), 6=Uint32(4),
	// 7=Int64(8), 8=Uint64(8), 9=Float32(4), 10=Float64(8),
	// 11=Float32x4(16), 12=Int32x4(16), 13=Float64x2(16)
	sizes := [14]int{1, 1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 16, 16, 16}
	if idx >= 0 && idx < 14 {
		return sizes[idx]
	}
	return 1
}
