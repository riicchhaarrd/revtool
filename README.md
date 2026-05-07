# Revtool

[![Build and Publish Web UI](https://github.com/riicchhaarrd/revtool/actions/workflows/pages.yml/badge.svg)](https://github.com/riicchhaarrd/revtool/actions/workflows/pages.yml)

Revtool is a reverse engineering workbench for 32-bit x86 binaries. It combines a native Qt desktop UI, a scriptable CLI, and a WebAssembly browser interface for inspecting binaries, navigating recovered symbols, and generating readable C-like decompiler output.

Try the hosted web UI: [riicchhaarrd.github.io/revtool](https://riicchhaarrd.github.io/revtool/)

## What It Does

Revtool loads supported x86 executables, analyzes their code and metadata, and presents the result as an interactive reverse engineering workspace. It is designed for fast inspection of function structure, source-level debug information where available, strings, cross-references, and decompiled pseudocode.

The browser version runs the same decompiler core through WebAssembly. Files are opened locally in the page and processed in the browser; the GitHub Pages deployment is just static HTML, JavaScript, and Wasm.

## Highlights

- Native Qt interface for desktop binary exploration.
- Browser UI built from the same C++ decompiler core through Emscripten.
- CLI entry point for scripts, tests, and automation.
- 32-bit x86 Mach-O, PE32, and ELF parsing.
- Capstone-backed x86 disassembly.
- Function, source file, string, and string cross-reference views.
- STABS-aware symbol, type, local, parameter, and line metadata recovery.
- DWARF source file, function, parameter name, and line metadata recovery for ELF.
- Function-level and source-file-level C-like decompilation.
- Optional SSA-based simplification and cosmetic output mode.
- JSON output modes for machine-readable automation.

## Web UI

The public web build is deployed by GitHub Actions:

[https://riicchhaarrd.github.io/revtool/](https://riicchhaarrd.github.io/revtool/)

On every push to `master`, the workflow installs Emscripten, builds `web/dis.js` and `web/dis.wasm`, and publishes the generated web bundle to the `gh-pages` branch.

## Native Build

Dependencies:

- CMake 3.16 or newer
- C++17 compiler
- Qt 6 Widgets
- Capstone
- pkg-config

Ubuntu example:

```bash
sudo apt-get install build-essential cmake pkg-config qt6-base-dev libcapstone-dev
cmake -S . -B build
cmake --build build -j"$(nproc)"
```

The native build produces:

- `build/dis`: Qt desktop application
- `build/decomp`: command-line decompiler

## CLI Usage

```bash
./build/decomp <binary> [options]
```

Useful options:

```text
-l                 List source files
-F                 List functions
--strings          List discovered strings
--xref-string <q>  Find code references to strings containing <q>
-f <addr>          Decompile function at a hex address
-n <name>          Decompile function by name substring
-s <idx>           Decompile source file by index
-a                 Decompile all source files
--json             Emit machine-readable JSON for the selected action
--gcc              Pipe decompiled output through gcc -fsyntax-only
```

Examples:

```bash
./build/decomp sample.bin -F
./build/decomp sample.bin --strings --json
./build/decomp sample.bin -f 0x000027B6
./build/decomp sample.bin -n main --gcc
```

## WebAssembly Build

For local web builds, install or symlink an Emscripten SDK at `./emsdk`, or set `EMSDK_DIR`:

```bash
./build_wasm.sh
```

Outputs:

```text
web/dis.js
web/dis.wasm
```

Open `web/index.html` through a local static server, or use the hosted GitHub Pages build.

## Supported Inputs

Revtool currently targets 32-bit x86 binaries:

- Mach-O i386
- PE32 i386
- ELF32 i386

Decompiler output is intended as an analysis aid. It is not a guarantee of buildable source reconstruction, especially for stripped, optimized, obfuscated, or metadata-poor binaries.
