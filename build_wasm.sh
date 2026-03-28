#!/usr/bin/env bash
# Build the decompiler as a WebAssembly module.
# Outputs: web/dis.js  web/dis.wasm
#
# Usage:  ./build_wasm.sh [--clean]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EMSDK_DIR="${EMSDK_DIR:-$SCRIPT_DIR/emsdk}"   # symlink in project root
CAPSTONE_VERSION="5.0.7"
DEPS_DIR="$SCRIPT_DIR/wasm_deps"
BUILD_DIR="$SCRIPT_DIR/build_wasm"

# ── Activate emsdk ────────────────────────────────────────────────────
if [[ ! -f "$EMSDK_DIR/emsdk_env.sh" ]]; then
    echo "ERROR: emsdk not found at $EMSDK_DIR"
    echo "       Set EMSDK_DIR or ensure the emsdk symlink/directory exists."
    exit 1
fi
# shellcheck source=/dev/null
source "$EMSDK_DIR/emsdk_env.sh"

# ── Optional clean ────────────────────────────────────────────────────
if [[ "${1:-}" == "--clean" ]]; then
    rm -rf "$BUILD_DIR" "$DEPS_DIR"
fi

# ── Build Capstone for WASM (once) ───────────────────────────────────
if [[ ! -f "$DEPS_DIR/lib/libcapstone.a" ]]; then
    echo "==> Building Capstone $CAPSTONE_VERSION for WASM..."
    CS_SRC="$SCRIPT_DIR/wasm_deps/capstone_src"
    if [[ ! -d "$CS_SRC" ]]; then
        mkdir -p "$(dirname "$CS_SRC")"
        git clone --depth 1 --branch "$CAPSTONE_VERSION" \
            https://github.com/capstone-engine/capstone.git "$CS_SRC"
    fi
    CS_BUILD="$SCRIPT_DIR/wasm_deps/capstone_build"
    mkdir -p "$CS_BUILD"
    emcmake cmake -S "$CS_SRC" -B "$CS_BUILD" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCAPSTONE_BUILD_STATIC=ON \
        -DCAPSTONE_BUILD_SHARED=OFF \
        -DCAPSTONE_BUILD_TESTS=OFF \
        -DCAPSTONE_BUILD_CSTOOL=OFF \
        -DCAPSTONE_X86_SUPPORT=ON \
        -DCAPSTONE_ARM_SUPPORT=OFF \
        -DCAPSTONE_ARM64_SUPPORT=OFF \
        -DCAPSTONE_MIPS_SUPPORT=OFF \
        -DCAPSTONE_PPC_SUPPORT=OFF \
        -DCAPSTONE_SPARC_SUPPORT=OFF \
        -DCAPSTONE_SYSZ_SUPPORT=OFF \
        -DCAPSTONE_XCORE_SUPPORT=OFF \
        -DCAPSTONE_M68K_SUPPORT=OFF \
        -DCAPSTONE_TMS320C64X_SUPPORT=OFF \
        -DCAPSTONE_M680X_SUPPORT=OFF \
        -DCAPSTONE_EVM_SUPPORT=OFF \
        -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"
    emmake make -C "$CS_BUILD" -j"$(nproc)"
    emmake make -C "$CS_BUILD" install
    echo "==> Capstone WASM build complete."
fi

# ── Build dis_wasm ────────────────────────────────────────────────────
mkdir -p "$BUILD_DIR"
mkdir -p "$SCRIPT_DIR/web"

echo "==> Configuring dis_wasm..."
emcmake cmake -S "$SCRIPT_DIR/wasm" -B "$BUILD_DIR" \
    -DCAPSTONE_WASM_LIB="$DEPS_DIR/lib/libcapstone.a" \
    -DCAPSTONE_WASM_INC="$DEPS_DIR/include" \
    -DCMAKE_BUILD_TYPE=Release

echo "==> Building dis_wasm..."
emmake make -C "$BUILD_DIR" -j"$(nproc)"

echo ""
echo "Done!  Output:"
ls -lh "$SCRIPT_DIR/web/dis.js" "$SCRIPT_DIR/web/dis.wasm" 2>/dev/null || true
