// WASM entry point — exposes the decompiler to JavaScript via Emscripten Embind.
// File data is passed as a JS Uint8Array (converted to std::string by Embind).
//
// JS usage:
//   const mod = await loadWasmModule();
//   mod.loadBinary(data);          // data: Uint8Array
//   mod.listSourceFiles();         // returns string
//   mod.listFunctions();           // returns string
//   mod.decompileFunction(0x1234); // returns string
//   mod.decompileSourceFile(0);    // returns string

#include "decompiler.h"
#include "macho.h"
#include <emscripten/bind.h>
#include <cstdio>
#include <string>

static MachOFile g_mf;
static bool      g_loaded = false;

// Accept raw bytes from JS via pointer+length.
// JS side: allocate with mod._malloc, copy with mod.HEAPU8.set, then free.
// This avoids UTF-8 corruption that occurs when binary data passes through
// Embind's std::string interface.
std::string loadBinaryPtr(uintptr_t ptr, size_t len) {
    const uint8_t *data = reinterpret_cast<const uint8_t *>(ptr);

    FILE *f = fopen("/tmp/input.bin", "wb");
    if (!f) return "error: cannot create /tmp/input.bin";
    fwrite(data, 1, len, f);
    fclose(f);

    g_mf     = MachOFile();
    g_loaded = g_mf.load("/tmp/input.bin");
    if (!g_loaded) return "error: not a supported Mach-O binary";

    return "ok: " + std::to_string(len) + " bytes, " +
           std::to_string(g_mf.stabsFunctions().size()) + " functions, " +
           std::to_string(g_mf.stabsSourceFiles().size()) + " source files";
}

// Convenience wrapper kept for completeness (not used for binary data)
std::string loadBinary(const std::string &data) {
    // Re-route through the pointer path so the logic stays in one place
    return loadBinaryPtr(reinterpret_cast<uintptr_t>(data.data()), data.size());
}

std::string listSourceFiles() {
    if (!g_loaded) return "error: no binary loaded";
    std::string out;
    const auto &srcs = g_mf.stabsSourceFiles();
    for (size_t i = 0; i < srcs.size(); ++i) {
        const auto &sf = srcs[i];
        out += "[" + std::to_string(i) + "] " +
               sf.directory + sf.filename +
               "  (" + std::to_string(sf.functionIndices.size()) + " functions)\n";
    }
    return out.empty() ? "(no STABS source info)" : out;
}

std::string listFunctions() {
    if (!g_loaded) return "error: no binary loaded";
    std::string out;
    const auto &funcs = g_mf.stabsFunctions();
    const auto &types = g_mf.typeTable();
    for (const auto &fn : funcs) {
        if (fn.address == 0) continue;
        std::string ret = fn.returnType != NullType ? types.formatType(fn.returnType) : "int";
        char addr[16];
        snprintf(addr, sizeof(addr), "0x%08X", fn.address);
        out += std::string(addr) + "  " + ret + " " + fn.name + "(";
        for (size_t p = 0; p < fn.params.size(); ++p) {
            if (p) out += ", ";
            const auto &par = fn.params[p];
            out += par.typeRef != NullType ? types.formatType(par.typeRef) : "int";
        }
        out += ")\n";
    }
    return out.empty() ? "(no functions found)" : out;
}

std::string decompileFunction(unsigned int addr) {
    if (!g_loaded) return "error: no binary loaded";
    return Decompiler::decompile(g_mf, addr).toStdString();
}

std::string decompileSourceFile(int idx) {
    if (!g_loaded) return "error: no binary loaded";
    return Decompiler::decompileFile(g_mf, idx).toStdString();
}

void setUseSSA(bool enabled) {
    Decompiler::s_useSSA = enabled;
}

void setFlatMode(bool enabled) {
    Decompiler::s_flatMode = enabled;
}

EMSCRIPTEN_BINDINGS(dis) {
    emscripten::function("loadBinaryPtr",     &loadBinaryPtr,
                         emscripten::allow_raw_pointers());
    emscripten::function("listSourceFiles",   &listSourceFiles);
    emscripten::function("listFunctions",     &listFunctions);
    emscripten::function("decompileFunction", &decompileFunction);
    emscripten::function("decompileSourceFile", &decompileSourceFile);
    emscripten::function("setUseSSA",           &setUseSSA);
    emscripten::function("setFlatMode",         &setFlatMode);
}
