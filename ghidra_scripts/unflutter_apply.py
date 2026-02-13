# -*- coding: utf-8 -*-
# unflutter_apply.py - Ghidra headless postScript
#
# Reads ghidra_meta.json produced by `unflutter ghidra-meta`, applies:
#   1. Function creation + renaming
#   2. Struct types for Dart classes + typed function signatures
#   3. EOL comments (THR fields, PP pool references)
#   4. Selective decompilation export for signal (focus) functions
#
# Usage (headless):
#   analyzeHeadless <project_dir> <project_name> \
#       -import <libapp.so> -overwrite \
#       -scriptPath <path_to_this_dir> \
#       -preScript unflutter_prescript.py \
#       -postScript unflutter_apply.py <ghidra_meta.json> [<output_dir>]
#
# Script args:
#   arg[0]: path to ghidra_meta.json (required)
#   arg[1]: output directory for decompiled .c files (optional)

import json
import os

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    Pointer64DataType, Pointer32DataType, PointerDataType,
    StructureDataType, CategoryPath,
)
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing import Function as GhidraFunction
from ghidra.app.decompiler import DecompInterface

try:
    from ghidra.program.model.data import DataTypeConflictHandler
    REPLACE_HANDLER = DataTypeConflictHandler.REPLACE_HANDLER
except:
    REPLACE_HANDLER = None


def main():
    args = getScriptArgs()
    if len(args) < 1:
        println("ERROR: missing ghidra_meta.json path argument")
        return

    meta_path = args[0]
    out_dir = args[1] if len(args) > 1 else None

    println("unflutter_apply: loading %s" % meta_path)

    with open(meta_path, "r") as f:
        meta = json.load(f)

    stats = {
        "functions": len(meta.get("functions", [])),
        "renamed": 0,
        "created": 0,
        "create_failed": 0,
        "labels": 0,
        "comments": 0,
        "comment_failed": 0,
        "decompiled": 0,
        "decompile_failed": 0,
    }

    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    symtab = currentProgram.getSymbolTable()

    # Detect image base: Ghidra rebases shared objects (typically +0x100000).
    mem = currentProgram.getMemory()
    image_base = currentProgram.getImageBase().getOffset()
    println("  image base: 0x%x" % image_base)

    # Determine pointer size from metadata (compressed pointers = 4 bytes).
    pointer_size = meta.get("pointer_size", 8)
    println("  pointer_size: %d" % pointer_size)

    # ptr_type = full 64-bit pointer (for return types, params — always 8 bytes in AArch64).
    ptr_type = Pointer64DataType.dataType

    # field_type = type used for Dart object fields inside structs.
    # With compressed pointers (4 bytes), fields are 32-bit pointers.
    # Without compression (8 bytes), fields are 64-bit pointers.
    if pointer_size == 4:
        field_type = Pointer32DataType.dataType
    else:
        field_type = Pointer64DataType.dataType

    # Phase 1a: Force disassembly at all function addresses.
    # Ghidra's auto-analysis skips Dart AOT code (no standard prologues).
    println("Phase 1a: disassembling at %d addresses..." % stats["functions"])
    disasm_ok = 0
    disasm_fail = 0
    for entry in meta.get("functions", []):
        addr_int = int(entry["addr"], 16) + image_base
        addr = toAddr(addr_int)
        if listing.getInstructionAt(addr) is not None:
            disasm_ok += 1
            continue
        try:
            clearListing(addr)
            disassemble(addr)
            if listing.getInstructionAt(addr) is not None:
                disasm_ok += 1
            else:
                disasm_fail += 1
        except:
            disasm_fail += 1
    println("  disassembled=%d failed=%d" % (disasm_ok, disasm_fail))

    # Phase 1b: Create/rename functions.
    println("Phase 1b: creating/renaming %d functions..." % stats["functions"])
    for entry in meta.get("functions", []):
        addr_int = int(entry["addr"], 16) + image_base
        addr = toAddr(addr_int)
        name = entry["name"]

        fn = fm.getFunctionAt(addr)
        if fn is not None:
            try:
                fn.setName(name, SourceType.USER_DEFINED)
                stats["renamed"] += 1
            except:
                pass
            continue

        # Try to create function.
        try:
            fn = createFunction(addr, name)
            if fn is not None:
                stats["created"] += 1
                continue
        except:
            pass

        # Fallback: disassemble at the address, then try again.
        try:
            disassemble(addr)
            fn = createFunction(addr, name)
            if fn is not None:
                stats["created"] += 1
                continue
        except:
            pass

        # Last resort: create a label so the name appears.
        try:
            symtab.createLabel(addr, name, SourceType.USER_DEFINED)
            stats["labels"] += 1
        except:
            stats["create_failed"] += 1

    println("  created=%d renamed=%d labels=%d failed=%d" % (
        stats["created"], stats["renamed"], stats["labels"], stats["create_failed"]))

    # Verify: count how many functions exist now at our addresses.
    verify_count = 0
    for entry in meta.get("functions", []):
        addr = toAddr(int(entry["addr"], 16) + image_base)
        if fm.getFunctionAt(addr) is not None:
            verify_count += 1
    println("  verified: %d/%d addresses have functions" % (verify_count, stats["functions"]))

    # Phase 1c: Create struct types for Dart classes.
    # Must run BEFORE param application so typed 'this' pointers can reference structs.
    classes = meta.get("classes", [])
    struct_by_owner = {}  # class_name -> Ghidra DataType
    if classes:
        println("Phase 1c: creating %d class struct types..." % len(classes))
        dtm = currentProgram.getDataTypeManager()
        cat = CategoryPath("/DartClasses")
        struct_created = 0
        struct_failed = 0

        for cls in classes:
            try:
                cname = cls["class_name"]
                sname = "Dart_" + sanitize(cname)
                size = cls["instance_size"]
                if size <= 0:
                    continue
                fields = cls.get("fields", [])

                struct_dt = StructureDataType(cat, sname, size)
                for field in fields:
                    offset = field["byte_offset"]
                    fname = field["name"]
                    if offset >= 0 and offset + pointer_size <= size:
                        struct_dt.replaceAtOffset(offset, field_type, pointer_size, fname, "")

                resolved = dtm.addDataType(struct_dt, REPLACE_HANDLER)
                struct_by_owner[cname] = resolved
                struct_created += 1
            except Exception as e:
                struct_failed += 1
                if struct_failed <= 5:
                    println("  WARN: struct %s: %s" % (cls.get("class_name", "?"), str(e)[:80]))

        println("  structs created=%d failed=%d (lookup=%d)" % (struct_created, struct_failed, len(struct_by_owner)))
    else:
        println("Phase 1c: skipped (no class layouts)")

    # Phase 1c2: Create DartThread struct from THR fields.
    thr_fields = meta.get("thr_fields", [])
    if thr_fields:
        println("Phase 1c2: creating DartThread struct (%d fields)..." % len(thr_fields))
        dtm = currentProgram.getDataTypeManager()
        cat = CategoryPath("/DartClasses")
        try:
            # Find max offset to determine struct size.
            max_off = max(f["offset"] for f in thr_fields)
            thr_size = max_off + 8  # last field is a pointer
            thr_dt = StructureDataType(cat, "DartThread", thr_size)
            thr_placed = 0
            for tf in thr_fields:
                off = tf["offset"]
                tname = tf["name"]
                if off >= 0 and off + 8 <= thr_size:
                    thr_dt.replaceAtOffset(off, ptr_type, 8, tname, "")
                    thr_placed += 1
            dtm.addDataType(thr_dt, REPLACE_HANDLER)
            println("  DartThread: %d/%d fields placed (size=%d)" % (thr_placed, len(thr_fields), thr_size))
        except Exception as e:
            println("  WARN: DartThread creation failed: %s" % str(e)[:120])
    else:
        println("Phase 1c2: skipped (no THR fields)")

    # Phase 1d: Apply function signatures (typed parameters + return type).
    # For methods (functions with an owner class):
    #   - First param = this: Dart_OwnerClass* (typed pointer to owner struct)
    #   - Remaining params = generic pointers
    # For all functions:
    #   - Return type = pointer (Dart functions return objects, not undefined)
    println("Phase 1d: applying function signatures...")
    sig_applied = 0
    sig_failed = 0
    ret_applied = 0
    this_typed = 0
    for entry in meta.get("functions", []):
        addr = toAddr(int(entry["addr"], 16) + image_base)
        fn = fm.getFunctionAt(addr)
        if fn is None:
            continue

        owner = entry.get("owner", "")
        pc = entry.get("param_count", 0)

        # Set return type to pointer (Dart returns objects, not undefined).
        try:
            fn.setReturnType(ptr_type, SourceType.USER_DEFINED)
            ret_applied += 1
        except:
            pass

        # Build parameter list.
        params = []

        # Methods get typed 'this' as first parameter.
        # param_count excludes implicit 'this', so we add it separately.
        if owner:
            if owner in struct_by_owner:
                this_dt = PointerDataType(struct_by_owner[owner])
                this_typed += 1
            else:
                this_dt = ptr_type
            params.append(ParameterImpl("this", this_dt, currentProgram))

        # Explicit parameters.
        for i in range(pc):
            params.append(ParameterImpl("p%d" % i, ptr_type, currentProgram))

        if not params:
            continue

        try:
            fn.replaceParameters(params,
                GhidraFunction.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                True, SourceType.USER_DEFINED)
            sig_applied += 1
        except:
            sig_failed += 1

    println("  signatures applied=%d failed=%d return_types=%d this_typed=%d" % (
        sig_applied, sig_failed, ret_applied, this_typed))

    # Phase 2: Set EOL comments.
    comment_entries = meta.get("comments", [])
    println("Phase 2: setting %d comments..." % len(comment_entries))
    for entry in comment_entries:
        addr_int = int(entry["addr"], 16) + image_base
        addr = toAddr(addr_int)
        text = entry["text"]
        try:
            setEOLComment(addr, text)
            stats["comments"] += 1
        except:
            stats["comment_failed"] += 1

    println("  set=%d failed=%d" % (stats["comments"], stats["comment_failed"]))

    # Phase 3: Selective decompilation.
    # Build addr → owner lookup for directory grouping.
    owner_by_addr = {}
    for entry in meta.get("functions", []):
        owner = entry.get("owner", "")
        if owner:
            owner_by_addr[entry["addr"]] = owner

    focus = meta.get("focus_functions", [])
    if out_dir and focus:
        println("Phase 3: decompiling %d focus functions..." % len(focus))
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        ifc = DecompInterface()
        ifc.openProgram(currentProgram)

        index = []
        not_found = 0
        for addr_str in focus:
            addr_int = int(addr_str, 16) + image_base
            addr = toAddr(addr_int)

            # Try exact match first, then containing.
            fn = fm.getFunctionAt(addr)
            if fn is None:
                fn = fm.getFunctionContaining(addr)

            if fn is None:
                not_found += 1
                if not_found <= 5:
                    println("  WARN: no function at %s" % addr_str)
                index.append({
                    "addr": addr_str,
                    "name": "unknown",
                    "file": None,
                    "decompile_ok": False,
                    "reason": "no_function",
                })
                stats["decompile_failed"] += 1
                continue

            fn_name = fn.getName()
            try:
                result = ifc.decompileFunction(fn, 60, monitor)
            except Exception as e:
                index.append({
                    "addr": addr_str,
                    "name": fn_name,
                    "file": None,
                    "decompile_ok": False,
                    "reason": str(e)[:100],
                })
                stats["decompile_failed"] += 1
                continue

            if result and result.decompileCompleted():
                decomp = result.getDecompiledFunction()
                if decomp:
                    c_code = decomp.getC()
                    safe_name = addr_str.replace("0x", "") + "_" + sanitize(fn_name)
                    # Use owner-based subdirectory if available.
                    owner = owner_by_addr.get(addr_str, "")
                    if owner:
                        sub_dir = os.path.join(out_dir, sanitize(owner))
                        if not os.path.exists(sub_dir):
                            os.makedirs(sub_dir)
                        out_file = os.path.join(sanitize(owner), safe_name + ".c")
                    else:
                        out_file = safe_name + ".c"
                    out_path = os.path.join(out_dir, out_file)
                    with open(out_path, "w") as cf:
                        cf.write(c_code)
                    index.append({
                        "addr": addr_str,
                        "name": fn_name,
                        "file": out_file,
                        "decompile_ok": True,
                    })
                    stats["decompiled"] += 1
                    continue

            reason = "decompile_incomplete"
            if result:
                err_msg = result.getErrorMessage()
                if err_msg:
                    reason = err_msg[:100]

            index.append({
                "addr": addr_str,
                "name": fn_name,
                "file": None,
                "decompile_ok": False,
                "reason": reason,
            })
            stats["decompile_failed"] += 1

        if not_found > 0:
            println("  %d focus functions not found" % not_found)

        ifc.dispose()

        # Write index.json.
        index_path = os.path.join(out_dir, "index.json")
        with open(index_path, "w") as idx:
            json.dump(index, idx, indent=2)
        println("  decompiled=%d failed=%d" % (stats["decompiled"], stats["decompile_failed"]))
    elif focus:
        println("Phase 3: skipped (no output directory specified)")
    else:
        println("Phase 3: skipped (no focus functions)")

    # Summary.
    println("UNFLUTTER_APPLY: functions=%d renamed=%d created=%d labels=%d comments=%d decompiled=%d failed=%d" % (
        stats["functions"],
        stats["renamed"],
        stats["created"],
        stats["labels"],
        stats["comments"],
        stats["decompiled"],
        stats["decompile_failed"],
    ))


def sanitize(name):
    """Sanitize a function name for use as a filename."""
    out = []
    for ch in name:
        if ch.isalnum() or ch in ("_", "-", "."):
            out.append(ch)
        else:
            out.append("_")
    s = "".join(out)
    if len(s) > 120:
        s = s[:120]
    return s


main()
