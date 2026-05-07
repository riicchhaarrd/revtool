// WASM entry point for the browser UI.

bool g_cosmeticMode = false;

#include "decompiler.h"
#include "macho.h"
#include <emscripten/bind.h>
#include <algorithm>
#include <capstone/capstone.h>
#include <cctype>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

struct FunctionInfo {
    uint32_t address = 0;
    uint32_t size = 0;
    std::string name;
    std::string sourcePath;
    int sourceFileIdx = -1;
    bool fromDebug = false;
    const StabsFunction *stabsFn = nullptr;
};

struct StringInfo {
    uint32_t address = 0;
    std::string section;
    std::string value;
};

struct StringXrefInfo {
    uint32_t functionAddr = 0;
    std::string functionName;
    uint32_t xrefAddr = 0;
    uint32_t stringAddr = 0;
    std::string stringSection;
    std::string stringValue;
    std::string mnemonic;
    std::string operands;
};

static MachOFile g_mf;
static bool g_loaded = false;

static std::string hex32(uint32_t v) {
    char buf[16];
    snprintf(buf, sizeof(buf), "0x%08X", v);
    return buf;
}

static std::string jsonEscape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char ch : s) {
        switch (ch) {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04X", ch);
                out += buf;
            } else {
                out += (char)ch;
            }
            break;
        }
    }
    return out;
}

static std::string lowerAscii(std::string s) {
    for (char &ch : s)
        ch = (char)std::tolower((unsigned char)ch);
    return s;
}

static int fuzzyScore(const std::string &text, const std::string &query) {
    if (query.empty()) return 1;

    std::string hay = lowerAscii(text);
    std::string needle = lowerAscii(query);

    size_t pos = hay.find(needle);
    if (pos != std::string::npos)
        return 100000 - (int)(pos * 16) - (int)(hay.size() - needle.size());

    size_t qi = 0;
    int score = 0;
    int streak = 0;
    for (size_t i = 0; i < hay.size() && qi < needle.size(); ++i) {
        if (hay[i] != needle[qi]) {
            streak = 0;
            continue;
        }
        score += 10;
        if (i == 0 || !std::isalnum((unsigned char)hay[i - 1]))
            score += 8;
        if (streak > 0)
            score += 6;
        ++qi;
        ++streak;
    }

    if (qi != needle.size()) return -1;
    return score - (int)hay.size();
}

static std::string sourcePathFor(const MachOFile &mf, int srcIdx) {
    auto &sources = mf.stabsSourceFiles();
    if (srcIdx < 0 || srcIdx >= (int)sources.size()) return "";
    const auto &sf = sources[srcIdx];
    return sf.filename.rfind(sf.directory, 0) == 0 ? sf.filename : sf.directory + sf.filename;
}

static std::string autoName(uint32_t addr) {
    char buf[32];
    snprintf(buf, sizeof(buf), "sub_%08X", addr);
    return buf;
}

static std::vector<FunctionInfo> collectFunctions(const MachOFile &mf) {
    std::map<uint32_t, FunctionInfo> byAddr;

    for (const auto &fn : mf.stabsFunctions()) {
        if (fn.address == 0) continue;
        FunctionInfo fi;
        fi.address = fn.address;
        fi.size = fn.size;
        fi.name = fn.name.empty() ? autoName(fn.address) : fn.name;
        fi.sourceFileIdx = fn.sourceFileIdx;
        fi.sourcePath = sourcePathFor(mf, fn.sourceFileIdx);
        fi.fromDebug = true;
        fi.stabsFn = &fn;
        byAddr[fi.address] = fi;
    }

    for (const auto &[addr, name] : mf.functionMap()) {
        const Section *sec = mf.sectionForAddress(addr);
        if (!sec || !mf.isCodeSection(*sec)) continue;
        auto &fi = byAddr[addr];
        if (fi.address == 0) fi.address = addr;
        if (fi.name.empty())
            fi.name = name.empty() ? autoName(addr) : name;
    }

    std::vector<FunctionInfo> out;
    out.reserve(byAddr.size());
    for (auto &[addr, fi] : byAddr) {
        if (fi.name.empty()) fi.name = autoName(addr);
        out.push_back(fi);
    }
    return out;
}

static std::vector<StringInfo> collectStrings(const MachOFile &mf, size_t minLen = 4) {
    std::vector<StringInfo> out;
    std::set<uint32_t> seen;

    for (const Section *sec : mf.allSections()) {
        if (!sec || !mf.isCStringSection(*sec) || sec->size == 0) continue;
        const uint8_t *data = mf.bytesAt(sec->offset, sec->size);
        if (!data) continue;

        for (uint32_t i = 0; i < sec->size; ) {
            if (data[i] < 0x20 || data[i] >= 0x7F) {
                ++i;
                continue;
            }

            uint32_t j = i;
            while (j < sec->size && data[j] >= 0x20 && data[j] < 0x7F)
                ++j;

            if (j < sec->size && data[j] == 0 && j > i && (j - i) >= minLen) {
                uint32_t addr = sec->addr + i;
                if (!seen.count(addr)) {
                    StringInfo si;
                    si.address = addr;
                    si.section = sec->sectname;
                    si.value.assign(reinterpret_cast<const char *>(data + i), j - i);
                    out.push_back(std::move(si));
                    seen.insert(addr);
                }
                i = j + 1;
            } else {
                ++i;
            }
        }
    }

    std::sort(out.begin(), out.end(), [](const auto &a, const auto &b) {
        return a.address < b.address;
    });
    return out;
}

static bool isPaddingByte(uint8_t b) {
    return b == 0x90 || b == 0xCC || b == 0x00;
}

static bool isTerminatorByte(uint8_t b) {
    switch (b) {
    case 0xC2:
    case 0xC3:
    case 0xCA:
    case 0xCB:
    case 0xE9:
    case 0xEB:
        return true;
    default:
        return false;
    }
}

static uint32_t sectionSpan(const MachOFile &mf, const Section &sec) {
    if (((mf.isPE() && sec.segname == "IMAGE") || mf.isELF()) && sec.align)
        return sec.align;
    return sec.size;
}

static uint32_t functionEndAddress(const MachOFile &mf,
                                   const std::vector<FunctionInfo> &funcs,
                                   size_t idx) {
    const auto &fn = funcs[idx];
    const Section *sec = mf.sectionForAddress(fn.address);
    if (!sec) return fn.address;

    uint32_t end = sec->addr + sectionSpan(mf, *sec);
    if (fn.size > 0 && fn.address + fn.size > fn.address)
        end = std::min(end, fn.address + fn.size);

    for (size_t i = idx + 1; i < funcs.size(); ++i) {
        if (funcs[i].address <= fn.address) continue;
        const Section *nextSec = mf.sectionForAddress(funcs[i].address);
        if (nextSec == sec) {
            end = std::min(end, funcs[i].address);
            break;
        }
    }

    if (fn.size == 0 && end > fn.address + 0x4000)
        end = fn.address + 0x4000;
    return end > fn.address ? end : fn.address;
}

static uint32_t guessFunctionStartFromPadding(const MachOFile &mf, uint32_t addr) {
    if (!mf.isPE() && !mf.isELF()) return 0;
    const Section *sec = mf.sectionForAddress(addr);
    if (!sec || !mf.isCodeSection(*sec) || sec->size == 0) return 0;
    if (addr < sec->addr || addr >= sec->addr + sec->size) return 0;

    const uint8_t *code = mf.bytesAt(sec->offset, sec->size);
    if (!code) return 0;

    uint32_t rel = addr - sec->addr;
    for (uint32_t i = rel; i > 0; --i) {
        if (isPaddingByte(code[i])) continue;
        uint32_t padStart = i;
        while (padStart > 0 && isPaddingByte(code[padStart - 1]))
            --padStart;
        uint32_t padLen = i - padStart;
        if (padLen < 4) continue;
        if (padStart > 0 && !isTerminatorByte(code[padStart - 1]))
            continue;
        return sec->addr + i;
    }

    return 0;
}

static FunctionInfo resolveOwningFunction(const MachOFile &mf,
                                          const std::vector<FunctionInfo> &funcs,
                                          uint32_t addr) {
    const Section *addrSec = mf.sectionForAddress(addr);
    if (!addrSec) {
        FunctionInfo fi;
        fi.address = addr;
        fi.name = autoName(addr);
        return fi;
    }

    FunctionInfo best;
    for (size_t i = 0; i < funcs.size(); ++i) {
        const auto &fn = funcs[i];
        if (fn.address > addr) break;
        const Section *fnSec = mf.sectionForAddress(fn.address);
        if (fnSec != addrSec) continue;
        if (fn.size > 0 && addr >= fn.address && addr < fn.address + fn.size)
            return fn;
        best = fn;
    }

    if (best.address != 0 && addr >= best.address && addr - best.address <= 0x4000)
        return best;

    uint32_t guessed = guessFunctionStartFromPadding(mf, addr);
    if (guessed != 0 && guessed <= addr) {
        FunctionInfo fi;
        fi.address = guessed;
        auto it = mf.functionMap().find(guessed);
        fi.name = it != mf.functionMap().end() ? it->second : autoName(guessed);
        return fi;
    }

    FunctionInfo fi;
    fi.address = addr;
    fi.name = autoName(addr);
    return fi;
}

static bool detectPicBase(const MachOFile &mf, const cs_insn *insn, size_t count,
                          uint32_t &picBase) {
    picBase = 0;
    auto &funcMap = mf.functionMap();
    for (size_t i = 0; i + 1 < count; ++i) {
        if (std::string(insn[i].mnemonic) != "call") continue;
        if (!insn[i].detail || insn[i].detail->x86.op_count == 0) continue;
        if (insn[i].detail->x86.operands[0].type != X86_OP_IMM) continue;
        uint32_t tgt = (uint32_t)insn[i].detail->x86.operands[0].imm;
        auto it = funcMap.find(tgt);
        if (it == funcMap.end()) continue;
        if (it->second.find("get_pc_thunk") == std::string::npos &&
            it->second.find("__i686") == std::string::npos)
            continue;
        if (std::string(insn[i + 1].mnemonic) != "add") continue;
        auto *d2 = insn[i + 1].detail;
        if (!d2 || d2->x86.op_count != 2 ||
            d2->x86.operands[1].type != X86_OP_IMM)
            continue;
        picBase = insn[i].address + insn[i].size + (uint32_t)d2->x86.operands[1].imm;
        return true;
    }
    return false;
}

static bool instructionReferencesAddress(const cs_insn &insn, uint32_t addr) {
    if (!insn.detail) return false;
    for (uint8_t oi = 0; oi < insn.detail->x86.op_count; ++oi) {
        const auto &op = insn.detail->x86.operands[oi];
        if (op.type == X86_OP_IMM && (uint32_t)op.imm == addr)
            return true;
        if (op.type == X86_OP_MEM &&
            op.mem.base == X86_REG_INVALID &&
            op.mem.index == X86_REG_INVALID &&
            (uint32_t)op.mem.disp == addr)
            return true;
    }
    return false;
}

struct DecodedHit {
    uint32_t xrefAddr = 0;
    std::string mnemonic;
    std::string operands;
};

static DecodedHit decodePEHit(const Section &sec, const uint8_t *code,
                              uint32_t hitOff, uint32_t addr, csh cs) {
    DecodedHit hit;
    if (!code || hitOff + 4 > sec.size) return hit;

    uint32_t startOff = hitOff > 12 ? hitOff - 12 : 0;
    for (uint32_t off = startOff; off <= hitOff; ++off) {
        size_t len = std::min<uint32_t>(32, sec.size - off);
        cs_insn *insn = nullptr;
        size_t count = cs_disasm(cs, code + off, len, sec.addr + off, 0, &insn);
        if (count == 0) continue;

        for (size_t i = 0; i < count; ++i) {
            uint32_t instOff = (uint32_t)(insn[i].address - sec.addr);
            uint32_t instEnd = instOff + insn[i].size;
            if (hitOff < instOff || hitOff + 4 > instEnd) continue;
            if (!instructionReferencesAddress(insn[i], addr)) continue;
            hit.xrefAddr = (uint32_t)insn[i].address;
            hit.mnemonic = insn[i].mnemonic;
            hit.operands = insn[i].op_str;
            cs_free(insn, count);
            return hit;
        }

        cs_free(insn, count);
    }

    return hit;
}

static std::vector<StringXrefInfo> findStringXrefsByAddress(const MachOFile &mf,
                                                            const std::vector<FunctionInfo> &funcs,
                                                            uint32_t stringAddr) {
    std::vector<StringXrefInfo> out;
    std::string stringValue = mf.cStringAtAddress(stringAddr, 4, 256);
    if (stringValue.empty()) return out;

    csh cs = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs) != CS_ERR_OK) return out;
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

    std::set<std::tuple<uint32_t, uint32_t, uint32_t>> seen;
    auto recordHit = [&](uint32_t ownerAddr, const std::string &ownerName,
                         uint32_t xrefAddr, const char *mnemonic,
                         const char *operands) {
        auto key = std::make_tuple(ownerAddr, xrefAddr, stringAddr);
        if (seen.count(key)) return;
        seen.insert(key);

        const Section *strSec = mf.sectionForAddress(stringAddr);
        StringXrefInfo hit;
        hit.functionAddr = ownerAddr;
        hit.functionName = ownerName;
        hit.xrefAddr = xrefAddr;
        hit.stringAddr = stringAddr;
        hit.stringSection = strSec ? strSec->sectname : "";
        hit.stringValue = stringValue;
        hit.mnemonic = mnemonic ? mnemonic : "";
        hit.operands = operands ? operands : "";
        out.push_back(std::move(hit));
    };

    if (mf.isPE() || mf.isELF()) {
        for (const Section *sec : mf.allSections()) {
            if (!sec || !mf.isCodeSection(*sec) || sec->size < 4) continue;
            const uint8_t *code = mf.bytesAt(sec->offset, sec->size);
            if (!code) continue;

            for (uint32_t i = 0; i + 4 <= sec->size; ++i) {
                uint32_t addr = (uint32_t)code[i] |
                                ((uint32_t)code[i + 1] << 8) |
                                ((uint32_t)code[i + 2] << 16) |
                                ((uint32_t)code[i + 3] << 24);
                if (addr != stringAddr) continue;

                DecodedHit decoded = decodePEHit(*sec, code, i, addr, cs);
                if (decoded.xrefAddr == 0) continue;

                FunctionInfo owner = resolveOwningFunction(mf, funcs, decoded.xrefAddr);
                std::string ownerName = owner.name.empty() ? autoName(owner.address) : owner.name;
                recordHit(owner.address, ownerName, decoded.xrefAddr,
                          decoded.mnemonic.c_str(), decoded.operands.c_str());
            }
        }
    } else {
        for (size_t fi = 0; fi < funcs.size(); ++fi) {
            const auto &fn = funcs[fi];
            const Section *sec = mf.sectionForAddress(fn.address);
            if (!sec || !mf.isCodeSection(*sec) || sec->size == 0) continue;

            uint32_t codeOff = fn.address - sec->addr;
            if (codeOff >= sec->size) continue;
            uint32_t endAddr = functionEndAddress(mf, funcs, fi);
            if (endAddr <= fn.address) continue;
            uint32_t codeLen = std::min<uint32_t>(endAddr - fn.address, sec->size - codeOff);
            const uint8_t *code = mf.bytesAt(sec->offset + codeOff, codeLen);
            if (!code || codeLen == 0) continue;

            cs_insn *insn = nullptr;
            size_t count = cs_disasm(cs, code, codeLen, fn.address, 0, &insn);
            if (count == 0) continue;

            uint32_t picBase = 0;
            bool hasPIC = detectPicBase(mf, insn, count, picBase);

            for (size_t i = 0; i < count; ++i) {
                if (!insn[i].detail) continue;
                bool matched = false;
                for (uint8_t oi = 0; oi < insn[i].detail->x86.op_count && !matched; ++oi) {
                    const auto &op = insn[i].detail->x86.operands[oi];
                    if (op.type == X86_OP_IMM && (uint32_t)op.imm == stringAddr) {
                        matched = true;
                    } else if (op.type == X86_OP_MEM) {
                        if (op.mem.base == X86_REG_INVALID &&
                            op.mem.index == X86_REG_INVALID &&
                            (uint32_t)op.mem.disp == stringAddr) {
                            matched = true;
                        } else if (hasPIC &&
                                   op.mem.base == X86_REG_EBX &&
                                   op.mem.index == X86_REG_INVALID &&
                                   picBase + (uint32_t)(int32_t)op.mem.disp == stringAddr) {
                            matched = true;
                        }
                    }
                }

                if (matched)
                    recordHit(fn.address, fn.name, (uint32_t)insn[i].address,
                              insn[i].mnemonic, insn[i].op_str);
            }

            cs_free(insn, count);
        }
    }

    cs_close(&cs);
    std::sort(out.begin(), out.end(), [](const auto &a, const auto &b) {
        if (a.functionAddr != b.functionAddr) return a.functionAddr < b.functionAddr;
        if (a.stringAddr != b.stringAddr) return a.stringAddr < b.stringAddr;
        return a.xrefAddr < b.xrefAddr;
    });
    return out;
}

std::string loadBinaryPtr(uintptr_t ptr, size_t len) {
    const uint8_t *data = reinterpret_cast<const uint8_t *>(ptr);

    FILE *f = fopen("/tmp/input.bin", "wb");
    if (!f) return "error: cannot create /tmp/input.bin";
    fwrite(data, 1, len, f);
    fclose(f);

    g_mf = MachOFile();
    g_loaded = g_mf.load("/tmp/input.bin");
    if (!g_loaded) return "error: not a supported Mach-O, PE32, or ELF32 binary";

    return "ok: " + std::to_string(len) + " bytes, " +
           std::to_string(collectFunctions(g_mf).size()) + " functions, " +
           std::to_string(g_mf.stabsSourceFiles().size()) + " source files";
}

std::string loadBinary(const std::string &data) {
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

std::string listSourceFilesJson() {
    if (!g_loaded) return "{\"error\":\"no binary loaded\"}";
    std::string out = "{\"format\":\"" + jsonEscape(g_mf.formatName()) + "\",\"source_files\":[";
    bool first = true;
    const auto &srcs = g_mf.stabsSourceFiles();
    for (size_t i = 0; i < srcs.size(); ++i) {
        const auto &sf = srcs[i];
        if (!first) out += ",";
        first = false;
        out += "{";
        out += "\"index\":" + std::to_string(i) + ",";
        out += "\"path\":\"" + jsonEscape(sf.directory + sf.filename) + "\",";
        out += "\"function_count\":" + std::to_string(sf.functionIndices.size());
        out += "}";
    }
    out += "]}";
    return out;
}

std::string listFunctions() {
    if (!g_loaded) return "error: no binary loaded";
    std::string out;
    const auto funcs = collectFunctions(g_mf);
    const auto &types = g_mf.typeTable();
    for (const auto &fn : funcs) {
        char addr[16];
        snprintf(addr, sizeof(addr), "0x%08X", fn.address);
        if (fn.stabsFn) {
            std::string ret = fn.stabsFn->returnType != NullType ?
                types.formatType(fn.stabsFn->returnType) : "int";
            out += std::string(addr) + "  " + ret + " " + fn.name + "(";
            for (size_t p = 0; p < fn.stabsFn->params.size(); ++p) {
                if (p) out += ", ";
                const auto &par = fn.stabsFn->params[p];
                out += par.typeRef != NullType ? types.formatType(par.typeRef) : "int";
            }
            out += ")\n";
        } else {
            out += std::string(addr) + "  int " + fn.name + "()\n";
        }
    }
    return out.empty() ? "(no functions found)" : out;
}

std::string listFunctionsJson() {
    if (!g_loaded) return "{\"error\":\"no binary loaded\"}";
    std::string out = "{\"format\":\"" + jsonEscape(g_mf.formatName()) + "\",\"functions\":[";
    bool first = true;
    for (const auto &fn : collectFunctions(g_mf)) {
        if (!first) out += ",";
        first = false;
        out += "{";
        out += "\"address\":" + std::to_string(fn.address) + ",";
        out += "\"address_hex\":\"" + hex32(fn.address) + "\",";
        out += "\"name\":\"" + jsonEscape(fn.name) + "\",";
        out += "\"size\":" + std::to_string(fn.size) + ",";
        out += "\"source_file_idx\":" + std::to_string(fn.sourceFileIdx) + ",";
        out += "\"source_path\":\"" + jsonEscape(fn.sourcePath) + "\",";
        out += "\"has_debug_info\":" + std::string(fn.fromDebug ? "true" : "false");
        out += "}";
    }
    out += "]}";
    return out;
}

std::string listStringsJson() {
    if (!g_loaded) return "{\"error\":\"no binary loaded\"}";
    std::string out = "{\"format\":\"" + jsonEscape(g_mf.formatName()) + "\",\"strings\":[";
    bool first = true;
    for (const auto &s : collectStrings(g_mf)) {
        if (!first) out += ",";
        first = false;
        out += "{";
        out += "\"address\":" + std::to_string(s.address) + ",";
        out += "\"address_hex\":\"" + hex32(s.address) + "\",";
        out += "\"section\":\"" + jsonEscape(s.section) + "\",";
        out += "\"value\":\"" + jsonEscape(s.value) + "\"";
        out += "}";
    }
    out += "]}";
    return out;
}

std::string findStringXrefsByAddressJson(unsigned int addr) {
    if (!g_loaded) return "{\"error\":\"no binary loaded\"}";
    std::string out = "{\"format\":\"" + jsonEscape(g_mf.formatName()) +
                      "\",\"string_address\":" + std::to_string(addr) +
                      ",\"string_address_hex\":\"" + hex32(addr) + "\",\"matches\":[";
    bool first = true;
    for (const auto &hit : findStringXrefsByAddress(g_mf, collectFunctions(g_mf), addr)) {
        if (!first) out += ",";
        first = false;
        out += "{";
        out += "\"function_address\":" + std::to_string(hit.functionAddr) + ",";
        out += "\"function_address_hex\":\"" + hex32(hit.functionAddr) + "\",";
        out += "\"function_name\":\"" + jsonEscape(hit.functionName) + "\",";
        out += "\"xref_address\":" + std::to_string(hit.xrefAddr) + ",";
        out += "\"xref_address_hex\":\"" + hex32(hit.xrefAddr) + "\",";
        out += "\"string_address\":" + std::to_string(hit.stringAddr) + ",";
        out += "\"string_address_hex\":\"" + hex32(hit.stringAddr) + "\",";
        out += "\"string_section\":\"" + jsonEscape(hit.stringSection) + "\",";
        out += "\"string_value\":\"" + jsonEscape(hit.stringValue) + "\",";
        out += "\"mnemonic\":\"" + jsonEscape(hit.mnemonic) + "\",";
        out += "\"operands\":\"" + jsonEscape(hit.operands) + "\"";
        out += "}";
    }
    out += "]}";
    return out;
}

static bool isValidCIdentifier(const std::string &name) {
    if (name.empty()) return false;
    unsigned char first = (unsigned char)name[0];
    if (!(std::isalpha(first) || first == '_')) return false;
    for (unsigned char ch : name) {
        if (!(std::isalnum(ch) || ch == '_'))
            return false;
    }
    return true;
}

std::string renameFunction(unsigned int addr, const std::string &name) {
    if (!g_loaded) return "error: no binary loaded";
    if (!isValidCIdentifier(name))
        return "error: function name must be a C identifier";
    const Section *sec = g_mf.sectionForAddress(addr);
    if (!sec || !g_mf.isCodeSection(*sec))
        return "error: address is not in executable code";
    if (!g_mf.setFunctionName(addr, name))
        return "error: function rename failed";
    return "ok: renamed " + hex32(addr) + " to " + name;
}

std::string decompileFunction(unsigned int addr) {
    if (!g_loaded) return "error: no binary loaded";
    return Decompiler::decompile(g_mf, addr).toStdString();
}

static uint32_t functionSizeForDisassembly(const MachOFile &mf,
                                           const std::vector<FunctionInfo> &funcs,
                                           const Section *sec,
                                           uint32_t addr) {
    if (!sec || addr < sec->addr || addr >= sec->addr + sec->size)
        return 0;

    uint32_t maxSize = sec->size - (addr - sec->addr);
    uint32_t size = 0;
    for (const auto &fn : funcs) {
        if (fn.address == addr && fn.size > 0) {
            size = fn.size;
            break;
        }
    }
    if (size == 0) {
        uint32_t next = 0;
        for (const auto &fn : funcs) {
            if (fn.address > addr && mf.sectionForAddress(fn.address) == sec &&
                (!next || fn.address < next))
                next = fn.address;
        }
        if (next > addr)
            size = next - addr;
    }
    if (size == 0 || size > maxSize)
        size = maxSize;
    if (size > 0x4000)
        size = 0x4000;
    return size;
}

std::string disassembleFunction(unsigned int addr) {
    if (!g_loaded) return "error: no binary loaded";
    const Section *sec = g_mf.sectionForAddress(addr);
    if (!sec || !g_mf.isCodeSection(*sec))
        return "error: address is not in executable code";
    if (addr < sec->addr)
        return "error: invalid function address";

    uint32_t codeOff = addr - sec->addr;
    if (codeOff >= sec->size)
        return "error: function bytes unavailable";
    uint32_t size = functionSizeForDisassembly(g_mf, collectFunctions(g_mf), sec, addr);
    if (size == 0)
        return "error: empty function";
    const uint8_t *code = g_mf.bytesAt(sec->offset + codeOff, size);
    if (!code)
        return "error: function bytes unavailable";

    csh cs;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs) != CS_ERR_OK)
        return "error: capstone unavailable";
    cs_option(cs, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    cs_insn *insn = nullptr;
    size_t count = cs_disasm(cs, code, size, addr, 0, &insn);
    std::string out;
    for (size_t i = 0; i < count; ++i) {
        char line[192];
        char bytes[64] = {0};
        size_t bytePos = 0;
        for (size_t b = 0; b < insn[i].size && b < 10; ++b) {
            int n = snprintf(bytes + bytePos, sizeof(bytes) - bytePos,
                             b ? " %02X" : "%02X", insn[i].bytes[b]);
            if (n <= 0 || (size_t)n >= sizeof(bytes) - bytePos)
                break;
            bytePos += (size_t)n;
        }
        snprintf(line, sizeof(line), "%08llX  %-30s  %-8s %s\n",
                 (unsigned long long)insn[i].address, bytes,
                 insn[i].mnemonic, insn[i].op_str);
        out += line;
    }
    cs_free(insn, count);
    cs_close(&cs);
    return out.empty() ? "error: no instructions decoded" : out;
}

static std::string sanitizeIdentifier(std::string s, const std::string &fallback) {
    for (char &ch : s) {
        unsigned char c = (unsigned char)ch;
        if (!(std::isalnum(c) || ch == '_'))
            ch = '_';
    }
    while (!s.empty() && s.front() == '_')
        s.erase(s.begin());
    if (s.empty() || !(std::isalpha((unsigned char)s[0]) || s[0] == '_'))
        s = fallback;
    if (!isValidCIdentifier(s))
        s = fallback;
    return s;
}

static std::string typeForAccessSize(int size) {
    switch (size) {
    case 1: return "unsigned char";
    case 2: return "unsigned short";
    case 8: return "unsigned long long";
    default: return "unsigned int";
    }
}

struct StructFieldCandidate {
    int offset = 0;
    int size = 0;
    int refs = 0;
};

struct StructCandidate {
    uint32_t functionAddr = 0;
    std::string functionName;
    std::string baseReg;
    std::map<int, StructFieldCandidate> fields;
    int refs = 0;
};

static std::string formatStructCandidateDecl(const StructCandidate &cand,
                                             const std::string &name) {
    std::string out = "struct " + name + " {\n";
    int cursor = 0;
    for (const auto &[off, field] : cand.fields) {
        if (off > cursor) {
            char pad[96];
            snprintf(pad, sizeof(pad), "    unsigned char pad_0x%X[%d];\n", cursor, off - cursor);
            out += pad;
            cursor = off;
        }

        char line[160];
        snprintf(line, sizeof(line), "    %s field_0x%X; /* %d refs */\n",
                 typeForAccessSize(field.size).c_str(), off, field.refs);
        out += line;
        cursor = std::max(cursor, off + std::max(1, field.size));
    }
    out += "};";
    return out;
}

std::string inferStructCandidatesJson() {
    if (!g_loaded) return "{\"error\":\"no binary loaded\"}";

    const auto funcs = collectFunctions(g_mf);
    csh cs = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs) != CS_ERR_OK)
        return "{\"error\":\"capstone unavailable\"}";
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

    std::vector<StructCandidate> candidates;
    for (const auto &fn : funcs) {
        const Section *sec = g_mf.sectionForAddress(fn.address);
        if (!sec || !g_mf.isCodeSection(*sec) || sec->size == 0)
            continue;
        uint32_t codeOff = fn.address - sec->addr;
        if (codeOff >= sec->size)
            continue;
        uint32_t size = functionSizeForDisassembly(g_mf, funcs, sec, fn.address);
        if (size == 0)
            continue;
        const uint8_t *code = g_mf.bytesAt(sec->offset + codeOff, size);
        if (!code)
            continue;

        cs_insn *insn = nullptr;
        size_t count = cs_disasm(cs, code, size, fn.address, 0, &insn);
        if (count == 0)
            continue;

        std::map<std::string, StructCandidate> byBase;
        for (size_t i = 0; i < count; ++i) {
            auto *detail = insn[i].detail;
            if (!detail)
                continue;
            for (uint8_t oi = 0; oi < detail->x86.op_count; ++oi) {
                const auto &op = detail->x86.operands[oi];
                if (op.type != X86_OP_MEM)
                    continue;
                if (op.mem.base == X86_REG_INVALID ||
                    op.mem.base == X86_REG_ESP ||
                    op.mem.base == X86_REG_EBP)
                    continue;
                if (op.mem.disp < 0 || op.mem.disp > 0xFFFF)
                    continue;

                const char *reg = cs_reg_name(cs, op.mem.base);
                if (!reg || !*reg)
                    continue;
                auto &cand = byBase[reg];
                cand.functionAddr = fn.address;
                cand.functionName = fn.name;
                cand.baseReg = reg;
                auto &field = cand.fields[(int)op.mem.disp];
                field.offset = (int)op.mem.disp;
                field.size = std::max<int>(field.size, op.size > 0 ? op.size : 4);
                field.refs++;
                cand.refs++;
            }
        }
        cs_free(insn, count);

        for (auto &[base, cand] : byBase) {
            if (cand.fields.size() < 2 || cand.refs < 2)
                continue;
            candidates.push_back(std::move(cand));
        }
    }
    cs_close(&cs);

    std::sort(candidates.begin(), candidates.end(), [](const auto &a, const auto &b) {
        if (a.fields.size() != b.fields.size()) return a.fields.size() > b.fields.size();
        if (a.refs != b.refs) return a.refs > b.refs;
        return a.functionAddr < b.functionAddr;
    });
    if (candidates.size() > 128)
        candidates.resize(128);

    std::string out = "{\"format\":\"" + jsonEscape(g_mf.formatName()) + "\",\"candidates\":[";
    bool firstCand = true;
    for (const auto &cand : candidates) {
        if (!firstCand) out += ",";
        firstCand = false;

        char fallback[64];
        snprintf(fallback, sizeof(fallback), "sub_%08X_%s", cand.functionAddr, cand.baseReg.c_str());
        std::string baseName = sanitizeIdentifier(cand.functionName, fallback);
        std::string name = "inferred_" + baseName + "_" + cand.baseReg + "_t";
        std::string decl = formatStructCandidateDecl(cand, name);

        out += "{";
        out += "\"name\":\"" + jsonEscape(name) + "\",";
        out += "\"function_address\":" + std::to_string(cand.functionAddr) + ",";
        out += "\"function_address_hex\":\"" + hex32(cand.functionAddr) + "\",";
        out += "\"function_name\":\"" + jsonEscape(cand.functionName) + "\",";
        out += "\"base_register\":\"" + jsonEscape(cand.baseReg) + "\",";
        out += "\"field_count\":" + std::to_string(cand.fields.size()) + ",";
        out += "\"ref_count\":" + std::to_string(cand.refs) + ",";
        out += "\"c_decl\":\"" + jsonEscape(decl) + "\",";
        out += "\"fields\":[";
        bool firstField = true;
        for (const auto &[off, field] : cand.fields) {
            if (!firstField) out += ",";
            firstField = false;
            out += "{";
            out += "\"offset\":" + std::to_string(off) + ",";
            out += "\"offset_hex\":\"0x";
            char hex[16];
            snprintf(hex, sizeof(hex), "%X", off);
            out += hex;
            out += "\",";
            out += "\"size\":" + std::to_string(field.size) + ",";
            out += "\"refs\":" + std::to_string(field.refs);
            out += "}";
        }
        out += "]}";
    }
    out += "]}";
    return out;
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

void setCosmeticMode(bool enabled) {
    Decompiler::s_cosmeticMode = enabled;
    g_cosmeticMode = enabled;
}

EMSCRIPTEN_BINDINGS(dis) {
    emscripten::function("loadBinaryPtr", &loadBinaryPtr,
                         emscripten::allow_raw_pointers());
    emscripten::function("loadBinary", &loadBinary);
    emscripten::function("listSourceFiles", &listSourceFiles);
    emscripten::function("listSourceFilesJson", &listSourceFilesJson);
    emscripten::function("listFunctions", &listFunctions);
    emscripten::function("listFunctionsJson", &listFunctionsJson);
    emscripten::function("listStringsJson", &listStringsJson);
    emscripten::function("findStringXrefsByAddressJson", &findStringXrefsByAddressJson);
    emscripten::function("renameFunction", &renameFunction);
    emscripten::function("decompileFunction", &decompileFunction);
    emscripten::function("disassembleFunction", &disassembleFunction);
    emscripten::function("inferStructCandidatesJson", &inferStructCandidatesJson);
    emscripten::function("decompileSourceFile", &decompileSourceFile);
    emscripten::function("setUseSSA", &setUseSSA);
    emscripten::function("setFlatMode", &setFlatMode);
    emscripten::function("setCosmeticMode", &setCosmeticMode);
}
