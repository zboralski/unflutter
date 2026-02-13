# -*- coding: utf-8 -*-
# unflutter_prescript.py - Ghidra headless preScript
#
# Configures analysis options before Ghidra auto-analysis runs.
# Dart AOT binaries have patterns that confuse standard analyzers:
#   - No standard ARM64 function prologues (Dart uses unchecked entry +0x18)
#   - BLR X21 dispatch table calls (not switch tables)
#   - Dense data sections interleaved with code
#
# Usage:
#   analyzeHeadless ... -preScript unflutter_prescript.py -postScript unflutter_apply.py ...

def main():
    println("unflutter_prescript: configuring analysis for Dart AOT binary")

    # Dart AOT doesn't use standard ARM64 prologues, so the aggressive
    # instruction finder creates false function starts in data regions.
    try:
        setAnalysisOption(currentProgram, "Aggressive Instruction Finder", "false")
        println("  disabled: Aggressive Instruction Finder")
    except Exception as e:
        println("  WARN: could not disable Aggressive Instruction Finder: %s" % str(e)[:60])

    # Dart functions don't follow standard non-return conventions.
    # The discovered non-returning analysis propagates incorrect assumptions.
    try:
        setAnalysisOption(currentProgram, "Non-Returning Functions - Discovered", "false")
        println("  disabled: Non-Returning Functions - Discovered")
    except Exception as e:
        println("  WARN: could not disable Non-Returning Functions - Discovered: %s" % str(e)[:60])

    println("unflutter_prescript: done")


main()
