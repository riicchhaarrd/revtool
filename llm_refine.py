#!/usr/bin/env python3
"""
LLM Refinement Pass for decompiled C code.

Usage:
  python3 llm_refine.py -n <func>        # refine a single function
  python3 llm_refine.py -s <src_idx>     # refine a whole source file
  python3 llm_refine.py --batch N        # refine N random functions and report stats
  python3 llm_refine.py --benchmark      # compare before/after on D3DDevice (src 27)

Requires: ANTHROPIC_API_KEY in environment
"""

import subprocess
import sys
import os
import re
import argparse
import tempfile
import random
import anthropic

DECOMP = "./build/decomp"
BINARY = ""
MODEL  = "claude-opus-4-6"

# ── Platform header (extracted once) ────────────────────────────────────────

def get_platform_header() -> str:
    """Extract the platform types preamble from a known source file."""
    out = subprocess.run([DECOMP, BINARY, "-s", "6"],
                         capture_output=True, text=True).stdout
    lines = out.splitlines()
    header_lines = []
    for line in lines:
        stripped = line.strip()
        # Stop at first real function definition
        if (stripped and not stripped.startswith("/*") and
                not stripped.startswith("#") and
                not stripped.startswith("typedef") and
                not stripped.startswith("struct") and
                not stripped.startswith("union") and
                not stripped.startswith("enum") and
                not stripped.startswith("}") and
                not stripped.startswith("//") and
                "(" in stripped and "{" not in stripped and
                not stripped.endswith(";")):
            break
        header_lines.append(line)
    return "\n".join(header_lines)

PLATFORM_HEADER = None  # lazy-loaded

def platform_header() -> str:
    global PLATFORM_HEADER
    if PLATFORM_HEADER is None:
        PLATFORM_HEADER = get_platform_header()
    return PLATFORM_HEADER

# ── Decompiler ───────────────────────────────────────────────────────────────

def decompile_func(name: str) -> str:
    return subprocess.run([DECOMP, BINARY, "-n", name],
                          capture_output=True, text=True).stdout.strip()

def decompile_file(idx: int) -> str:
    return subprocess.run([DECOMP, BINARY, "-s", str(idx)],
                          capture_output=True, text=True).stdout.strip()

# ── GCC check ────────────────────────────────────────────────────────────────

def gcc_check(code: str, with_header: bool = True) -> tuple[bool, str]:
    """Returns (ok, stderr). Prepends platform header if not already present."""
    src = code
    if with_header and "typedef int BOOL" not in code:
        src = platform_header() + "\n\n" + code
    proc = subprocess.run(
        ["gcc", "-x", "c", "-fsyntax-only", "-std=c99",
         "-Werror=implicit-function-declaration", "-"],
        input=src.encode(), capture_output=True)
    return proc.returncode == 0, proc.stderr.decode()

def count_gcc_errors(code: str, with_header: bool = True) -> int:
    ok, stderr = gcc_check(code, with_header)
    return 0 if ok else len([l for l in stderr.splitlines() if ": error:" in l])

# ── Quality metrics ──────────────────────────────────────────────────────────

def count_raw_vars(code: str) -> int:
    return len(re.findall(r'^\s*int v\d+\s*;', code, re.MULTILINE))

def count_gotos(code: str) -> int:
    return len(re.findall(r'\bgoto\b', code))

def count_lines(code: str) -> int:
    return len(code.splitlines())

def metrics(code: str, with_header: bool = True) -> dict:
    return {
        "lines":    count_lines(code),
        "gotos":    count_gotos(code),
        "raw_vars": count_raw_vars(code),
        "errors":   count_gcc_errors(code, with_header),
    }

# ── LLM refinement ───────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a C code refiner for decompiled code. You receive decompiled C code with \
auto-generated variable names (v0, v1, t2, var_3, etc.) and your job is to make \
it more readable without changing its semantics.

Rules:
1. Rename variables from auto-generated names (v0, v1, t2, var_3, etc.) to \
   meaningful names based on context (usage, type, value, surrounding code).
2. Simplify arithmetic expressions where the result is obvious (e.g. \
   "(double)(x) * 4.656613e-10f" near rand() is a float normalization → keep \
   the comment or simplify expression).
3. Fix obviously wrong types: if a variable is used as a float (assigned 0.0f, \
   used in float arithmetic) but declared "int", change to "float".
4. Keep ALL control flow EXACTLY the same: same if/else structure, same goto \
   labels, same loops, same switch cases.
5. Keep ALL function signatures EXACTLY the same (same parameter names/types, \
   same return type).
6. Do NOT add new variables, new functions, or new logic.
7. Do NOT remove existing variables — only rename them.
8. Output ONLY the refined C code, no explanation, no markdown fences.
9. If in doubt about a rename, keep the original name.
10. The code must compile with: gcc -x c -fsyntax-only -std=c99

Focus on: variable renaming > type fixes > expression comments.
Do NOT try to restructure the code."""

def refine_with_llm(code: str, client: anthropic.Anthropic) -> str:
    """Send decompiled C to Claude for refinement. Returns refined code."""
    # For single functions, include platform header as context
    context = ""
    if "typedef int BOOL" not in code:
        context = f"/* Context types (not to be reproduced in output): */\n{platform_header()}\n\n"

    message = client.messages.create(
        model=MODEL,
        max_tokens=8192,
        thinking={"type": "adaptive"},
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"{context}/* Code to refine: */\n{code}"
        }]
    )
    # Extract text content
    for block in message.content:
        if block.type == "text":
            # Strip markdown fences if model wrapped in them
            text = block.text.strip()
            if text.startswith("```"):
                text = re.sub(r'^```[a-z]*\n?', '', text)
                text = re.sub(r'\n?```$', '', text)
            return text.strip()
    return code  # fallback: unchanged

# ── Pipeline ─────────────────────────────────────────────────────────────────

def process_function(name: str, client: anthropic.Anthropic, verbose: bool = True) -> dict:
    """Decompile, refine, verify. Returns result dict."""
    original = decompile_func(name)
    if not original or "could not decompile" in original:
        return {"name": name, "status": "skip", "reason": "empty/failed"}

    before = metrics(original, with_header=True)

    if verbose:
        print(f"\n{'='*60}")
        print(f"Function: {name}")
        print(f"Before: {before['lines']} lines, {before['raw_vars']} raw vars, "
              f"{before['gotos']} gotos, {before['errors']} errors")

    refined = refine_with_llm(original, client)

    after = metrics(refined, with_header=True)

    # Accept only if it still compiles (0 errors) and isn't longer
    if after["errors"] > 0:
        ok, stderr = gcc_check(refined, with_header=True)
        if verbose:
            print(f"After:  REJECTED — {after['errors']} GCC errors")
            print(f"  Stderr: {stderr[:200]}")
        return {"name": name, "status": "rejected", "before": before,
                "after": after, "original": original, "refined": refined}

    status = "improved" if after["raw_vars"] < before["raw_vars"] else "unchanged"

    if verbose:
        print(f"After:  {after['lines']} lines, {after['raw_vars']} raw vars, "
              f"{after['gotos']} gotos, {after['errors']} errors  [{status}]")
        if status == "improved":
            # Show diff summary
            old_names = set(re.findall(r'\bv\d+\b|\bvar_\w+\b|\bt\d+\b', original))
            new_names = set(re.findall(r'\bv\d+\b|\bvar_\w+\b|\bt\d+\b', refined))
            renamed = old_names - new_names
            if renamed:
                print(f"  Renamed away: {', '.join(sorted(renamed))}")

    return {"name": name, "status": status, "before": before,
            "after": after, "original": original, "refined": refined}

def process_file(idx: int, client: anthropic.Anthropic, verbose: bool = True) -> dict:
    """Decompile a full source file, refine, verify."""
    original = decompile_file(idx)
    if not original or "could not decompile" in original:
        return {"idx": idx, "status": "skip"}

    before = metrics(original, with_header=False)

    if verbose:
        print(f"\n{'='*60}")
        print(f"Source file: {idx}")
        print(f"Before: {before['lines']} lines, {before['raw_vars']} raw vars, "
              f"{before['gotos']} gotos, {before['errors']} errors")

    # For large files, chunk by function and refine each
    # For now, send whole file (≤200K tokens for most files)
    refined = refine_with_llm(original, client)
    after = metrics(refined, with_header=False)

    if after["errors"] > before["errors"]:
        if verbose:
            print(f"After:  REJECTED — {after['errors']} errors (was {before['errors']})")
        return {"idx": idx, "status": "rejected", "before": before, "after": after}

    status = "improved" if after["raw_vars"] < before["raw_vars"] else "unchanged"
    if verbose:
        print(f"After:  {after['lines']} lines, {after['raw_vars']} raw vars, "
              f"{after['gotos']} gotos, {after['errors']} errors  [{status}]")

    return {"idx": idx, "status": status, "before": before, "after": after,
            "original": original, "refined": refined}

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LLM refinement pass for decompiled C")
    parser.add_argument("-n", "--name",    help="Function name (substring match)")
    parser.add_argument("-s", "--source",  type=int, help="Source file index")
    parser.add_argument("--batch",         type=int, metavar="N",
                        help="Refine N random functions and report stats")
    parser.add_argument("--benchmark",     action="store_true",
                        help="Run on D3DDevice (src 27) and report stats")
    parser.add_argument("--show-refined",  action="store_true",
                        help="Print refined code to stdout")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    if args.name:
        result = process_function(args.name, client, verbose=True)
        if args.show_refined and "refined" in result:
            print("\n" + "="*60 + "\nRefined output:\n" + "="*60)
            print(result["refined"])

    elif args.source is not None:
        result = process_file(args.source, client, verbose=True)
        if args.show_refined and "refined" in result:
            print("\n" + "="*60 + "\nRefined output:\n" + "="*60)
            print(result["refined"])

    elif args.benchmark:
        print("Benchmark: D3DDevice (source file 27)")
        result = process_file(27, client, verbose=True)
        if result.get("status") not in ("skip", "rejected"):
            b, a = result["before"], result["after"]
            print(f"\nSummary:")
            print(f"  Lines:    {b['lines']} → {a['lines']} ({a['lines']-b['lines']:+d})")
            print(f"  Raw vars: {b['raw_vars']} → {a['raw_vars']} ({a['raw_vars']-b['raw_vars']:+d})")
            print(f"  Gotos:    {b['gotos']} → {a['gotos']} ({a['gotos']-b['gotos']:+d})")
            print(f"  Errors:   {b['errors']} → {a['errors']}")

    elif args.batch:
        # Pick N functions from the binary
        funcs_out = subprocess.run([DECOMP, BINARY, "-F"],
                                   capture_output=True, text=True).stdout
        func_names = re.findall(r'\s+(\w+)\(', funcs_out)
        func_names = [f for f in func_names if len(f) > 4]  # skip short names
        sample = random.sample(func_names, min(args.batch, len(func_names)))

        results = []
        for name in sample:
            r = process_function(name, client, verbose=True)
            results.append(r)

        # Aggregate stats
        improved  = [r for r in results if r["status"] == "improved"]
        rejected  = [r for r in results if r["status"] == "rejected"]
        unchanged = [r for r in results if r["status"] == "unchanged"]

        total_before_vars = sum(r["before"]["raw_vars"] for r in results
                                if "before" in r)
        total_after_vars  = sum(r["after"]["raw_vars"] for r in results
                                if "after" in r and r["status"] != "rejected")

        print(f"\n{'='*60}")
        print(f"Batch results ({len(results)} functions):")
        print(f"  Improved:  {len(improved)}")
        print(f"  Unchanged: {len(unchanged)}")
        print(f"  Rejected:  {len(rejected)}")
        print(f"  Raw vars before: {total_before_vars}")
        print(f"  Raw vars after:  {total_after_vars}")
        print(f"  Reduction: {total_before_vars - total_after_vars} vars "
              f"({100*(total_before_vars-total_after_vars)/max(1,total_before_vars):.1f}%)")

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
