// CLI tool for testing the decompiler and driving it from scripts/LLMs.
// Usage:
//   decomp <binary> [options]
//
//   -l                 List source files
//   -F                 List functions
//   --strings          List discovered strings
//   --xref-string <q>  Find code references to strings containing <q>
//   --disasm <addr>    Disassemble function at hex address
//   --infer-structs    Infer struct candidates from memory access patterns
//   -f <addr>          Decompile function at hex address
//   -n <name>          Decompile function by name (substring match)
//   -s <idx>           Decompile source file by index
//   -a                 Decompile all source files
//   --project <file>   Apply exported web Project DB edits
//   --json             Emit machine-readable JSON for the selected action
//   --gcc              Pipe decompiled output through gcc -fsyntax-only

#include "decompiler.h"
#include "macho.h"
#include "project_types.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QString>
#include <capstone/capstone.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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

static QString hex32q(uint32_t v) {
    return QString("0x%1").arg(v, 8, 16, QChar('0')).toUpper();
}

static std::string autoName(uint32_t addr) {
    char buf[32];
    snprintf(buf, sizeof(buf), "sub_%08X", addr);
    return buf;
}

static QString sourcePathFor(const MachOFile &mf, int srcIdx) {
    auto &sources = mf.stabsSourceFiles();
    if (srcIdx < 0 || srcIdx >= (int)sources.size()) return "";
    const auto &sf = sources[srcIdx];
    QString dir = QString::fromStdString(sf.directory);
    QString fname = QString::fromStdString(sf.filename);
    return fname.startsWith(dir) ? fname : dir + fname;
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
        fi.sourcePath = sourcePathFor(mf, fn.sourceFileIdx).toStdString();
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
        if (fi.name.empty())
            fi.name = autoName(addr);
    }

    std::vector<FunctionInfo> out;
    out.reserve(byAddr.size());
    for (auto &[addr, fi] : byAddr) {
        if (fi.name.empty()) fi.name = autoName(addr);
        out.push_back(fi);
    }
    return out;
}

static QJsonObject functionToJson(const FunctionInfo &fn) {
    QJsonObject obj;
    obj["address"] = (int)fn.address;
    obj["address_hex"] = hex32q(fn.address);
    obj["name"] = QString::fromStdString(fn.name);
    obj["size"] = (int)fn.size;
    obj["source_file_idx"] = fn.sourceFileIdx;
    obj["source_path"] = QString::fromStdString(fn.sourcePath);
    obj["has_debug_info"] = fn.fromDebug;
    return obj;
}

static void listSourceFilesText(const MachOFile &mf) {
    auto &sources = mf.stabsSourceFiles();
    for (size_t i = 0; i < sources.size(); ++i) {
        auto &sf = sources[i];
        printf("[%3zu] %s%s  (%zu functions)\n",
               i, sf.directory.c_str(), sf.filename.c_str(),
               sf.functionIndices.size());
    }
}

static void listFunctionsText(const std::vector<FunctionInfo> &funcs,
                              const StabsTypeTable &types) {
    for (const auto &fn : funcs) {
        if (fn.stabsFn) {
            std::string retStr = fn.stabsFn->returnType != NullType ?
                types.formatType(fn.stabsFn->returnType) : "int";
            printf("  %08X  %s %s(", fn.address, retStr.c_str(), fn.name.c_str());
            for (size_t p = 0; p < fn.stabsFn->params.size(); ++p) {
                if (p) printf(", ");
                auto &par = fn.stabsFn->params[p];
                if (par.typeRef != NullType)
                    printf("%s", types.formatDecl(par.typeRef, par.name).c_str());
                else
                    printf("int %s", par.name.c_str());
            }
            if (fn.stabsFn->isVariadic) {
                if (!fn.stabsFn->params.empty()) printf(", ");
                printf("...");
            }
            printf(")\n");
        } else {
            printf("  %08X  int %s()\n", fn.address, fn.name.c_str());
        }
    }
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

static QJsonObject stringToJson(const StringInfo &s) {
    QJsonObject obj;
    obj["address"] = (int)s.address;
    obj["address_hex"] = hex32q(s.address);
    obj["section"] = QString::fromStdString(s.section);
    obj["value"] = QString::fromStdString(s.value);
    return obj;
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

static bool matchesQuery(const std::string &text, const std::string &query) {
    return query.empty() || fuzzyScore(text, query) >= 0;
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
        if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP &&
            (uint32_t)(insn.address + insn.size + op.mem.disp) == addr)
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

static std::vector<StringXrefInfo> findStringXrefs(const MachOFile &mf,
                                                   const std::vector<FunctionInfo> &funcs,
                                                   const QString &query) {
    std::vector<StringXrefInfo> out;
    csh cs = 0;
    if (cs_open(CS_ARCH_X86, mf.capstoneMode(), &cs) != CS_ERR_OK) return out;
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);
    const std::string queryStd = query.toStdString();

    std::set<std::tuple<uint32_t, uint32_t, uint32_t>> seen;
    auto recordHit = [&](uint32_t ownerAddr, const std::string &ownerName,
                         uint32_t xrefAddr, uint32_t stringAddr,
                         const char *mnemonic, const char *operands) {
        std::string s = mf.cStringAtAddress(stringAddr, 4, 256);
        if (s.empty()) return;
        if (!matchesQuery(s, queryStd))
            return;

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
        hit.stringValue = std::move(s);
        hit.mnemonic = mnemonic ? mnemonic : "";
        hit.operands = operands ? operands : "";
        out.push_back(std::move(hit));
    };

    if ((mf.isPE() || mf.isELF()) && !mf.is64Bit()) {
        std::unordered_map<uint32_t, StringInfo> targets;
        for (const auto &s : collectStrings(mf)) {
            if (matchesQuery(s.value, queryStd))
                targets[s.address] = s;
        }

        for (const Section *sec : mf.allSections()) {
            if (!sec || !mf.isCodeSection(*sec) || sec->size < 4) continue;
            const uint8_t *code = mf.bytesAt(sec->offset, sec->size);
            if (!code) continue;

            for (uint32_t i = 0; i + 4 <= sec->size; ++i) {
                uint32_t addr = (uint32_t)code[i] |
                                ((uint32_t)code[i + 1] << 8) |
                                ((uint32_t)code[i + 2] << 16) |
                                ((uint32_t)code[i + 3] << 24);
                if (targets.find(addr) == targets.end()) continue;

                DecodedHit decoded = decodePEHit(*sec, code, i, addr, cs);
                if (decoded.xrefAddr == 0) continue;

                FunctionInfo owner = resolveOwningFunction(mf, funcs, decoded.xrefAddr);
                std::string ownerName = owner.name.empty() ? autoName(owner.address) : owner.name;
                recordHit(owner.address, ownerName, decoded.xrefAddr, addr,
                          decoded.mnemonic.c_str(), decoded.operands.c_str());
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
        bool hasPIC = !mf.is64Bit() && detectPicBase(mf, insn, count, picBase);

        for (size_t i = 0; i < count; ++i) {
            if (!insn[i].detail) continue;
            std::set<uint32_t> candidates;

            for (uint8_t oi = 0; oi < insn[i].detail->x86.op_count; ++oi) {
                const auto &op = insn[i].detail->x86.operands[oi];
                if (op.type == X86_OP_IMM) {
                    candidates.insert((uint32_t)op.imm);
                } else if (op.type == X86_OP_MEM) {
                    if (op.mem.base == X86_REG_INVALID &&
                        op.mem.index == X86_REG_INVALID &&
                        op.mem.disp != 0) {
                        candidates.insert((uint32_t)op.mem.disp);
                    } else if (hasPIC &&
                               op.mem.base == X86_REG_EBX &&
                               op.mem.index == X86_REG_INVALID) {
                        candidates.insert(picBase + (uint32_t)(int32_t)op.mem.disp);
                    }
                }
            }

            for (uint32_t addr : candidates) {
                recordHit(fn.address, fn.name, (uint32_t)insn[i].address, addr,
                          insn[i].mnemonic, insn[i].op_str);
            }
        }

        cs_free(insn, count);
    }

    cs_close(&cs);
    std::sort(out.begin(), out.end(), [](const auto &a, const auto &b) {
        if (a.functionAddr != b.functionAddr) return a.functionAddr < b.functionAddr;
        if (a.stringAddr != b.stringAddr) return a.stringAddr < b.stringAddr;
        return a.xrefAddr < b.xrefAddr;
    });
    return out;
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

static QString disassembleFunctionText(const MachOFile &mf,
                                       const std::vector<FunctionInfo> &funcs,
                                       uint32_t addr) {
    const Section *sec = mf.sectionForAddress(addr);
    if (!sec || !mf.isCodeSection(*sec))
        return "error: address is not in executable code\n";

    uint32_t codeOff = addr - sec->addr;
    if (codeOff >= sec->size)
        return "error: function bytes unavailable\n";
    uint32_t size = functionSizeForDisassembly(mf, funcs, sec, addr);
    if (size == 0)
        return "error: empty function\n";
    const uint8_t *code = mf.bytesAt(sec->offset + codeOff, size);
    if (!code)
        return "error: function bytes unavailable\n";

    csh cs = 0;
    if (cs_open(CS_ARCH_X86, mf.capstoneMode(), &cs) != CS_ERR_OK)
        return "error: capstone unavailable\n";
    cs_option(cs, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    cs_insn *insn = nullptr;
    size_t count = cs_disasm(cs, code, size, addr, 0, &insn);
    QString out;
    for (size_t i = 0; i < count; ++i) {
        char bytes[64] = {0};
        size_t bytePos = 0;
        for (size_t b = 0; b < insn[i].size && b < 10; ++b) {
            int n = snprintf(bytes + bytePos, sizeof(bytes) - bytePos,
                             b ? " %02X" : "%02X", insn[i].bytes[b]);
            if (n <= 0 || (size_t)n >= sizeof(bytes) - bytePos)
                break;
            bytePos += (size_t)n;
        }
        char line[192];
        snprintf(line, sizeof(line), "%08llX  %-30s  %-8s %s\n",
                 (unsigned long long)insn[i].address, bytes,
                 insn[i].mnemonic, insn[i].op_str);
        out += QString::fromUtf8(line);
    }
    cs_free(insn, count);
    cs_close(&cs);
    return out.isEmpty() ? QString("error: no instructions decoded\n") : out;
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
    bool isGlobal = false;
    uint32_t globalAddr = 0;
    std::string globalName;
    std::map<int, StructFieldCandidate> fields;
    int refs = 0;
};

static QString typeForAccessSize(int size) {
    switch (size) {
    case 1: return "unsigned char";
    case 2: return "unsigned short";
    case 8: return "unsigned long long";
    default: return "unsigned int";
    }
}

static std::string sanitizeStructIdentifier(std::string s, const std::string &fallback) {
    for (char &ch : s) {
        unsigned char c = (unsigned char)ch;
        if (!(std::isalnum(c) || ch == '_'))
            ch = '_';
    }
    while (!s.empty() && s.front() == '_')
        s.erase(s.begin());
    if (s.empty() || !(std::isalpha((unsigned char)s[0]) || s[0] == '_'))
        s = fallback;
    for (char ch : s) {
        unsigned char c = (unsigned char)ch;
        if (!(std::isalnum(c) || ch == '_'))
            return fallback;
    }
    return s;
}

struct GlobalDataSymbol {
    uint32_t addr = 0;
    uint32_t end = 0;
    std::string name;
};

static std::string dataSymbolDisplayName(const MachOFile &mf, const NList &sym) {
    std::string name = mf.symbolNameAtAddress(sym.n_value);
    if (name.empty()) {
        name = sym.name;
        if (!mf.isELF() && !name.empty() && name[0] == '_')
            name = name.substr(1);
    }
    return name.empty() ? "data" : name;
}

static std::vector<GlobalDataSymbol> collectGlobalDataSymbols(const MachOFile &mf) {
    std::map<uint32_t, GlobalDataSymbol> byAddr;
    for (const auto &sym : mf.symbols()) {
        if (sym.n_value == 0 || sym.name.empty()) continue;
        if (sym.n_type & N_STAB) continue;
        if ((sym.n_type & N_TYPE) != N_SECT) continue;
        const Section *sec = mf.sectionForAddress(sym.n_value);
        if (!sec || !mf.isDataSection(*sec)) continue;

        auto &gs = byAddr[sym.n_value];
        gs.addr = sym.n_value;
        if (sym.n_size > 0 && sym.n_value + sym.n_size > sym.n_value)
            gs.end = sym.n_value + sym.n_size;
        gs.name = dataSymbolDisplayName(mf, sym);
    }

    std::vector<GlobalDataSymbol> out;
    out.reserve(byAddr.size());
    for (auto &[addr, gs] : byAddr)
        out.push_back(std::move(gs));

    for (size_t i = 0; i < out.size(); ++i) {
        const Section *sec = mf.sectionForAddress(out[i].addr);
        uint32_t secEnd = sec ? sec->addr + sectionSpan(mf, *sec) : out[i].addr;
        uint32_t next = secEnd;
        for (size_t j = i + 1; j < out.size(); ++j) {
            const Section *nextSec = mf.sectionForAddress(out[j].addr);
            if (nextSec == sec) {
                next = out[j].addr;
                break;
            }
        }
        if (out[i].end == 0 || out[i].end > next)
            out[i].end = next;
        if (out[i].end <= out[i].addr)
            out[i].end = secEnd;
    }
    return out;
}

static const GlobalDataSymbol *globalSymbolForAddress(
    const std::vector<GlobalDataSymbol> &globals, uint32_t addr) {
    auto it = std::upper_bound(globals.begin(), globals.end(), addr,
        [](uint32_t value, const GlobalDataSymbol &sym) {
            return value < sym.addr;
        });
    if (it == globals.begin()) return nullptr;
    --it;
    if (addr < it->addr || addr >= it->end) return nullptr;
    return &*it;
}

static bool absoluteMemoryTarget(const cs_insn &insn, const cs_x86_op &op,
                                 bool hasPIC, uint32_t picBase,
                                 uint32_t &target) {
    if (op.mem.base == X86_REG_RIP) {
        target = (uint32_t)(insn.address + insn.size + op.mem.disp);
        return true;
    }
    if (op.mem.base == X86_REG_INVALID && op.mem.disp != 0) {
        target = (uint32_t)op.mem.disp;
        return true;
    }
    if (hasPIC && op.mem.base == X86_REG_EBX) {
        target = picBase + (uint32_t)(int32_t)op.mem.disp;
        return true;
    }
    return false;
}

static void recordStructAccess(std::map<std::string, StructCandidate> &byBase,
                               const FunctionInfo &fn,
                               const std::string &key,
                               const std::string &baseLabel,
                               int offset, int size,
                               bool isGlobal = false,
                               uint32_t globalAddr = 0,
                               const std::string &globalName = "") {
    if (offset < 0 || offset > 0xFFFF) return;
    auto &cand = byBase[key];
    cand.functionAddr = fn.address;
    cand.functionName = fn.name;
    cand.baseReg = baseLabel;
    cand.isGlobal = isGlobal;
    cand.globalAddr = globalAddr;
    cand.globalName = globalName;
    auto &field = cand.fields[offset];
    field.offset = offset;
    field.size = std::max<int>(field.size, size > 0 ? size : 4);
    field.refs++;
    cand.refs++;
}

static QString structCandidateName(const StructCandidate &cand) {
    char fallback[64];
    snprintf(fallback, sizeof(fallback), "sub_%08X_%s",
             cand.functionAddr, cand.baseReg.c_str());
    std::string baseName = sanitizeStructIdentifier(cand.functionName, fallback);
    std::string baseReg = sanitizeStructIdentifier(cand.baseReg, "base");
    return QString::fromStdString("inferred_" + baseName + "_" + baseReg + "_t");
}

static QString formatStructCandidateDecl(const StructCandidate &cand) {
    QString name = structCandidateName(cand);
    QString out = "struct " + name + " {\n";
    int cursor = 0;
    for (const auto &[off, field] : cand.fields) {
        if (off > cursor) {
            QString cursorHex = QString::number(cursor, 16).toUpper();
            out += QString("    unsigned char pad_0x%1[%2];\n")
                .arg(cursorHex)
                .arg(off - cursor);
            cursor = off;
        }
        QString offHex = QString::number(off, 16).toUpper();
        if (off < cursor) {
            out += QString("    /* overlapping access at 0x%1: size %2, %3 refs */\n")
                .arg(offHex)
                .arg(std::max(1, field.size))
                .arg(field.refs);
            continue;
        }
        if (field.size == 1 || field.size == 2 || field.size == 4 || field.size == 8) {
            out += QString("    %1 field_0x%2; /* %3 refs */\n")
                .arg(typeForAccessSize(field.size))
                .arg(offHex)
                .arg(field.refs);
        } else {
            out += QString("    unsigned char field_0x%1[%2]; /* %3 refs */\n")
                .arg(offHex)
                .arg(std::max(1, field.size))
                .arg(field.refs);
        }
        cursor = std::max(cursor, off + std::max(1, field.size));
    }
    out += "};";
    return out;
}

static std::vector<StructCandidate> inferStructCandidates(const MachOFile &mf,
                                                          const std::vector<FunctionInfo> &funcs) {
    csh cs = 0;
    if (cs_open(CS_ARCH_X86, mf.capstoneMode(), &cs) != CS_ERR_OK)
        return {};
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

    const std::vector<GlobalDataSymbol> globals = collectGlobalDataSymbols(mf);
    std::vector<StructCandidate> candidates;
    for (const auto &fn : funcs) {
        const Section *sec = mf.sectionForAddress(fn.address);
        if (!sec || !mf.isCodeSection(*sec) || sec->size == 0)
            continue;
        uint32_t codeOff = fn.address - sec->addr;
        if (codeOff >= sec->size)
            continue;
        uint32_t size = functionSizeForDisassembly(mf, funcs, sec, fn.address);
        if (size == 0)
            continue;
        const uint8_t *code = mf.bytesAt(sec->offset + codeOff, size);
        if (!code)
            continue;

        cs_insn *insn = nullptr;
        size_t count = cs_disasm(cs, code, size, fn.address, 0, &insn);
        if (count == 0)
            continue;

        std::map<std::string, StructCandidate> byBase;
        uint32_t picBase = 0;
        bool hasPIC = !mf.is64Bit() && detectPicBase(mf, insn, count, picBase);
        for (size_t i = 0; i < count; ++i) {
            auto *detail = insn[i].detail;
            if (!detail)
                continue;
            for (uint8_t oi = 0; oi < detail->x86.op_count; ++oi) {
                const auto &op = detail->x86.operands[oi];
                if (op.type != X86_OP_MEM)
                    continue;
                uint32_t target = 0;
                if (absoluteMemoryTarget(insn[i], op, hasPIC, picBase, target)) {
                    const GlobalDataSymbol *global = globalSymbolForAddress(globals, target);
                    if (global) {
                        char globalFallback[32];
                        snprintf(globalFallback, sizeof(globalFallback), "data_%08X", global->addr);
                        std::string label = "global_" +
                            sanitizeStructIdentifier(global->name, globalFallback);
                        char key[64];
                        snprintf(key, sizeof(key), "global:%08X", global->addr);
                        recordStructAccess(byBase, fn, key, label,
                                           (int)(target - global->addr),
                                           op.size > 0 ? op.size : 4,
                                           true, global->addr, global->name);
                        continue;
                    }
                }
                if (op.mem.base == X86_REG_INVALID ||
                    op.mem.base == X86_REG_ESP ||
                    op.mem.base == X86_REG_EBP ||
                    op.mem.base == X86_REG_RSP ||
                    op.mem.base == X86_REG_RBP ||
                    op.mem.base == X86_REG_RIP)
                    continue;
                if (op.mem.disp < 0 || op.mem.disp > 0xFFFF)
                    continue;

                const char *reg = cs_reg_name(cs, op.mem.base);
                if (!reg || !*reg)
                    continue;
                recordStructAccess(byBase, fn, reg, reg, (int)op.mem.disp,
                                   op.size > 0 ? op.size : 4);
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
    return candidates;
}

static QJsonObject structCandidateToJson(const StructCandidate &cand) {
    QJsonObject obj;
    obj["name"] = structCandidateName(cand);
    obj["function_address"] = (int)cand.functionAddr;
    obj["function_address_hex"] = hex32q(cand.functionAddr);
    obj["function_name"] = QString::fromStdString(cand.functionName);
    obj["base_register"] = QString::fromStdString(cand.baseReg);
    obj["is_global"] = cand.isGlobal;
    if (cand.isGlobal) {
        obj["global_symbol"] = QString::fromStdString(cand.globalName);
        obj["global_address"] = (int)cand.globalAddr;
        obj["global_address_hex"] = hex32q(cand.globalAddr);
    }
    obj["field_count"] = (int)cand.fields.size();
    obj["ref_count"] = cand.refs;
    obj["c_decl"] = formatStructCandidateDecl(cand);
    QJsonArray fields;
    for (const auto &[off, field] : cand.fields) {
        QJsonObject f;
        f["offset"] = off;
        f["offset_hex"] = QString("0x%1").arg(off, 0, 16).toUpper();
        f["size"] = field.size;
        f["refs"] = field.refs;
        fields.append(f);
    }
    obj["fields"] = fields;
    return obj;
}

static QJsonObject xrefToJson(const StringXrefInfo &hit) {
    QJsonObject obj;
    obj["function_address"] = (int)hit.functionAddr;
    obj["function_address_hex"] = hex32q(hit.functionAddr);
    obj["function_name"] = QString::fromStdString(hit.functionName);
    obj["xref_address"] = (int)hit.xrefAddr;
    obj["xref_address_hex"] = hex32q(hit.xrefAddr);
    obj["string_address"] = (int)hit.stringAddr;
    obj["string_address_hex"] = hex32q(hit.stringAddr);
    obj["string_section"] = QString::fromStdString(hit.stringSection);
    obj["string_value"] = QString::fromStdString(hit.stringValue);
    obj["mnemonic"] = QString::fromStdString(hit.mnemonic);
    obj["operands"] = QString::fromStdString(hit.operands);
    return obj;
}

static int gccCheck(const QString &code) {
    QProcess proc;
    proc.start("gcc", QStringList()
        << "-x" << "c" << "-fsyntax-only" << "-std=c99"
        << "-Werror=implicit-function-declaration"
        << "-");
    if (!proc.waitForStarted(3000)) {
        fprintf(stderr, "Failed to start gcc\n");
        return -1;
    }
    proc.write(code.toUtf8());
    proc.closeWriteChannel();
    if (!proc.waitForFinished(30000)) {
        fprintf(stderr, "gcc timed out\n");
        return -1;
    }

    QByteArray err = proc.readAllStandardError();
    if (!err.isEmpty())
        fprintf(stderr, "%s", err.constData());

    int errors = 0;
    for (auto &line : err.split('\n')) {
        if (line.contains(": error:"))
            errors++;
    }
    if (proc.exitCode() == 0) {
        printf("gcc: OK (no errors)\n");
    } else {
        printf("gcc: %d errors\n", errors);
    }
    return errors;
}

bool g_cosmeticMode = false;

static void printJson(const QJsonObject &obj) {
    QByteArray out = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    printf("%s\n", out.constData());
}

static bool isValidCIdentifier(const QString &name) {
    if (name.isEmpty()) return false;
    const QChar first = name[0];
    if (!(first == '_' || first.isLetter())) return false;
    for (QChar ch : name) {
        if (!(ch == '_' || ch.isLetterOrNumber()))
            return false;
    }
    return true;
}

static uint32_t parseProjectAddr(const QString &key) {
    QByteArray bytes = key.trimmed().toUtf8();
    if (bytes.isEmpty()) return 0;
    char *end = nullptr;
    unsigned long v = strtoul(bytes.constData(), &end, 0);
    if (!end || *end != '\0' || v > UINT32_MAX)
        return 0;
    return (uint32_t)v;
}

static int applyProjectDb(MachOFile &mf, const char *path,
                          QString &customTypes,
                          QString &globalTypeBindings,
                          std::map<uint32_t, QString> &functionNotes,
                          QString &error) {
    QFile file(QString::fromUtf8(path));
    if (!file.open(QIODevice::ReadOnly)) {
        error = QString("Cannot open project DB: %1").arg(QString::fromUtf8(path));
        return -1;
    }
    QJsonParseError parseErr{};
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &parseErr);
    if (parseErr.error != QJsonParseError::NoError || !doc.isObject()) {
        error = QString("Invalid project DB JSON: %1").arg(parseErr.errorString());
        return -1;
    }

    QJsonObject root = doc.object();
    customTypes = root.value("customTypes").toString();
    globalTypeBindings.clear();
    functionNotes.clear();

    int applied = 0;
    QJsonObject names = root.value("functionNames").toObject();
    for (auto it = names.begin(); it != names.end(); ++it) {
        uint32_t addr = parseProjectAddr(it.key());
        QString name = it.value().toString().trimmed();
        if (!addr || !isValidCIdentifier(name))
            continue;
        if (mf.setFunctionName(addr, name.toStdString()))
            applied++;
    }

    QJsonObject notes = root.value("functionNotes").toObject();
    for (auto it = notes.begin(); it != notes.end(); ++it) {
        uint32_t addr = parseProjectAddr(it.key());
        QString note = it.value().toString().trimmed();
        if (addr && !note.isEmpty())
            functionNotes[addr] = note;
    }

    QJsonObject globalTypes = root.value("globalTypes").toObject();
    for (auto it = globalTypes.begin(); it != globalTypes.end(); ++it) {
        uint32_t addr = parseProjectAddr(it.key());
        if (!addr) continue;
        QString typeName;
        QString symbol;
        if (it.value().isObject()) {
            QJsonObject obj = it.value().toObject();
            typeName = obj.value("type").toString().trimmed();
            symbol = obj.value("symbol").toString().trimmed();
        } else {
            typeName = it.value().toString().trimmed();
        }
        if (!isValidCIdentifier(typeName))
            continue;
        globalTypeBindings += QString("0x%1 %2 %3\n")
            .arg(addr, 8, 16, QChar('0'))
            .arg(typeName)
            .arg(symbol);
    }

    if (!customTypes.trimmed().isEmpty() || !globalTypeBindings.trimmed().isEmpty())
        applyProjectTypes(mf, customTypes.toStdString(), globalTypeBindings.toStdString());
    return applied;
}

static QString formatProjectNote(const QString &note) {
    QString clean = note.trimmed();
    if (clean.isEmpty())
        return "";
    QString out;
    for (const auto &line : clean.split('\n'))
        out += "// NOTE: " + line + "\n";
    return out.trimmed();
}

static QString withProjectEdits(const QString &code, const QString &customTypes,
                                const QString &functionNote = "") {
    if (code.startsWith("error:"))
        return code;
    QString out = code;
    QString note = formatProjectNote(functionNote);
    if (!note.isEmpty())
        out = note + "\n\n" + out;

    QString prelude = customTypes.trimmed();
    if (!prelude.isEmpty())
        out = prelude + "\n\n" + out;
    return out;
}

static QString withProjectTypes(const QString &code, const QString &customTypes) {
    return withProjectEdits(code, customTypes);
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    if (argc < 2) {
        fprintf(stderr,
            "Usage: decomp <binary> [options]\n"
            "  -l                 List source files\n"
            "  -F                 List functions\n"
            "  --strings          List discovered strings\n"
            "  --xref-string <q>  Find functions/xrefs by string usage\n"
            "  --disasm <addr>    Disassemble function at hex address\n"
            "  --infer-structs    Infer struct candidates from memory access patterns\n"
            "  -f <addr>          Decompile function at hex address\n"
            "  -n <name>          Decompile function by name (substring match)\n"
            "  -s <idx>           Decompile source file by index\n"
            "  -a                 Decompile all source files\n"
            "  -o <dir>           Write -a output to individual .c files\n"
            "  --only <file>      Limit -a to basenames listed in file\n"
            "  --project <file>   Apply exported web Project DB edits\n"
            "  --json             Emit machine-readable JSON\n"
            "  --gcc              Pipe output through gcc to count errors\n"
            "  --ssa              Enable full SSA pass (experimental)\n"
            "  --cosmetic         Prefer readable output over byte-matching\n"
            "  --types            Dump all STABS types as C header\n"
            "  --srcof <addr>     Find source file index for function at address\n"
            "  -q                 Quiet: suppress decompiled output (use with --gcc)\n"
        );
        return 1;
    }

    const char *binPath = argv[1];
    bool doList = false, doFuncs = false, doAll = false, doStrings = false;
    bool doInferStructs = false;
    bool doGcc = false, quiet = false, doTypes = false, jsonMode = false;
    uint32_t srcOfAddr = 0;
    uint32_t disasmAddr = 0;
    uint32_t funcAddr = 0;
    int srcIdx = -1;
    const char *funcName = nullptr;
    const char *xrefString = nullptr;
    const char *outDir = nullptr;
    const char *onlyList = nullptr;
    const char *projectPath = nullptr;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "-l") == 0) doList = true;
        else if (strcmp(argv[i], "-F") == 0) doFuncs = true;
        else if (strcmp(argv[i], "-a") == 0) doAll = true;
        else if (strcmp(argv[i], "--strings") == 0) doStrings = true;
        else if (strcmp(argv[i], "--infer-structs") == 0) doInferStructs = true;
        else if (strcmp(argv[i], "--xref-string") == 0 && i + 1 < argc)
            xrefString = argv[++i];
        else if (strcmp(argv[i], "--json") == 0) jsonMode = true;
        else if (strcmp(argv[i], "--gcc") == 0) doGcc = true;
        else if (strcmp(argv[i], "--ssa") == 0) Decompiler::s_useSSA = true;
        else if (strcmp(argv[i], "--flat") == 0) Decompiler::s_flatMode = true;
        else if (strcmp(argv[i], "--cosmetic") == 0) { Decompiler::s_cosmeticMode = true; g_cosmeticMode = true; }
        else if (strcmp(argv[i], "--port") == 0) { Decompiler::s_portMode = true; }
        else if (strcmp(argv[i], "--types") == 0) doTypes = true;
        else if (strcmp(argv[i], "--srcof") == 0 && i + 1 < argc)
            srcOfAddr = strtoul(argv[++i], nullptr, 16);
        else if (strcmp(argv[i], "--disasm") == 0 && i + 1 < argc)
            disasmAddr = strtoul(argv[++i], nullptr, 16);
        else if (strcmp(argv[i], "-q") == 0) quiet = true;
        else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc)
            funcAddr = strtoul(argv[++i], nullptr, 16);
        else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc)
            srcIdx = atoi(argv[++i]);
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            funcName = argv[++i];
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
            outDir = argv[++i];
        else if (strcmp(argv[i], "--only") == 0 && i + 1 < argc)
            onlyList = argv[++i];
        else if (strcmp(argv[i], "--project") == 0 && i + 1 < argc)
            projectPath = argv[++i];
    }

    auto fail = [&](int code, const QString &msg) {
        if (jsonMode) {
            QJsonObject obj;
            obj["status"] = QString("error");
            obj["binary"] = QString::fromUtf8(binPath);
            obj["error"] = msg;
            printJson(obj);
        } else {
            fprintf(stderr, "%s\n", msg.toUtf8().constData());
        }
        return code;
    };

    MachOFile mf;
    if (!mf.load(binPath)) {
        return fail(1, QString("Failed to load %1 (supported: Mach-O i386, PE32 i386, ELF32 i386, ELF64 x86-64)")
                          .arg(QString::fromUtf8(binPath)));
    }

    QString projectCustomTypes;
    QString projectGlobalTypeBindings;
    std::map<uint32_t, QString> projectFunctionNotes;
    int projectAppliedNames = 0;
    if (projectPath) {
        QString err;
        projectAppliedNames = applyProjectDb(mf, projectPath, projectCustomTypes,
                                             projectGlobalTypeBindings,
                                             projectFunctionNotes, err);
        if (projectAppliedNames < 0)
            return fail(1, err);
    }

    auto makeMeta = [&](const char *action) {
        QJsonObject obj;
        obj["status"] = QString("ok");
        obj["action"] = QString::fromUtf8(action);
        obj["binary"] = QString::fromUtf8(binPath);
        obj["format"] = QString::fromUtf8(mf.formatName());
        obj["size"] = (int)mf.size();
        obj["debug_function_count"] = (int)mf.stabsFunctions().size();
        obj["source_file_count"] = (int)mf.stabsSourceFiles().size();
        if (projectPath) {
            obj["project_db"] = QString::fromUtf8(projectPath);
            obj["project_function_names"] = projectAppliedNames;
            obj["project_function_notes"] = (int)projectFunctionNotes.size();
            obj["project_custom_type_bytes"] = projectCustomTypes.toUtf8().size();
            obj["project_global_type_bindings"] =
                projectGlobalTypeBindings.trimmed().isEmpty()
                    ? 0
                    : projectGlobalTypeBindings.trimmed().count('\n') + 1;
        }
        return obj;
    };

    if (!jsonMode) {
        fprintf(stderr, "Loaded %s [%s]: %zu bytes, %zu functions, %zu source files\n",
                binPath, mf.formatName(), mf.size(), mf.stabsFunctions().size(),
                mf.stabsSourceFiles().size());
        if (projectPath)
            fprintf(stderr, "Applied project DB: %d function names, %zu notes, %d custom type bytes\n",
                    projectAppliedNames, projectFunctionNotes.size(),
                    projectCustomTypes.toUtf8().size());
    }

    std::vector<FunctionInfo> funcs = collectFunctions(mf);

    if (doList) {
        if (jsonMode) {
            QJsonObject obj = makeMeta("list_sources");
            QJsonArray arr;
            for (size_t i = 0; i < mf.stabsSourceFiles().size(); ++i) {
                const auto &sf = mf.stabsSourceFiles()[i];
                QJsonObject item;
                item["index"] = (int)i;
                item["path"] = sourcePathFor(mf, (int)i);
                item["address"] = (int)sf.address;
                item["address_hex"] = hex32q(sf.address);
                item["function_count"] = (int)sf.functionIndices.size();
                arr.append(item);
            }
            obj["sources"] = arr;
            printJson(obj);
        } else {
            listSourceFilesText(mf);
        }
        return 0;
    }

    if (doFuncs) {
        if (jsonMode) {
            QJsonObject obj = makeMeta("list_functions");
            QJsonArray arr;
            for (const auto &fn : funcs)
                arr.append(functionToJson(fn));
            obj["functions"] = arr;
            printJson(obj);
        } else {
            listFunctionsText(funcs, mf.typeTable());
        }
        return 0;
    }

    if (doStrings) {
        std::vector<StringInfo> strings = collectStrings(mf);
        if (jsonMode) {
            QJsonObject obj = makeMeta("list_strings");
            QJsonArray arr;
            for (const auto &s : strings)
                arr.append(stringToJson(s));
            obj["strings"] = arr;
            printJson(obj);
        } else {
            for (const auto &s : strings) {
                printf("%08X  %-12s  \"%s\"\n",
                       s.address, s.section.c_str(), s.value.c_str());
            }
        }
        return 0;
    }

    if (xrefString) {
        QString query = QString::fromUtf8(xrefString);
        std::vector<StringXrefInfo> hits = findStringXrefs(mf, funcs, query);
        if (jsonMode) {
            QJsonObject obj = makeMeta("xref_string");
            obj["query"] = query;
            QJsonArray arr;
            for (const auto &hit : hits)
                arr.append(xrefToJson(hit));
            obj["matches"] = arr;
            printJson(obj);
        } else {
            for (const auto &hit : hits) {
                printf("%08X  %-32s  %08X  %08X  \"%s\"  %s %s\n",
                       hit.functionAddr, hit.functionName.c_str(),
                       hit.xrefAddr, hit.stringAddr, hit.stringValue.c_str(),
                       hit.mnemonic.c_str(), hit.operands.c_str());
            }
        }
        return 0;
    }

    if (disasmAddr) {
        QString asmText = disassembleFunctionText(mf, funcs, disasmAddr);
        if (asmText.startsWith("error:"))
            return fail(1, asmText.trimmed());
        if (jsonMode) {
            QJsonObject obj = makeMeta("disassemble_function");
            obj["function_address"] = (int)disasmAddr;
            obj["function_address_hex"] = hex32q(disasmAddr);
            obj["assembly"] = asmText;
            printJson(obj);
        } else {
            printf("%s", asmText.toUtf8().constData());
        }
        return 0;
    }

    if (doInferStructs) {
        std::vector<StructCandidate> candidates = inferStructCandidates(mf, funcs);
        if (jsonMode) {
            QJsonObject obj = makeMeta("infer_structs");
            QJsonArray arr;
            for (const auto &cand : candidates)
                arr.append(structCandidateToJson(cand));
            obj["candidates"] = arr;
            printJson(obj);
        } else {
            for (const auto &cand : candidates) {
                printf("/* inferred: %s / %s */\n",
                       cand.functionName.c_str(), cand.baseReg.c_str());
                printf("%s\n\n", formatStructCandidateDecl(cand).toUtf8().constData());
            }
        }
        return 0;
    }

    if (doTypes) {
        QString hdr = withProjectTypes(Decompiler::dumpTypes(mf), projectCustomTypes);
        if (jsonMode) {
            QJsonObject obj = makeMeta("dump_types");
            obj["code"] = hdr;
            printJson(obj);
        } else {
            printf("%s", hdr.toUtf8().constData());
        }
        return 0;
    }

    if (srcOfAddr) {
        auto &sources = mf.stabsSourceFiles();
        for (size_t si = 0; si < sources.size(); ++si) {
            for (size_t fi : sources[si].functionIndices) {
                if (mf.stabsFunctions()[fi].address == srcOfAddr) {
                    if (jsonMode) {
                        QJsonObject obj = makeMeta("source_of_function");
                        obj["function_address"] = (int)srcOfAddr;
                        obj["function_address_hex"] = hex32q(srcOfAddr);
                        obj["source_index"] = (int)si;
                        obj["source_path"] = sourcePathFor(mf, (int)si);
                        printJson(obj);
                    } else {
                        printf("%zu\n", si);
                    }
                    return 0;
                }
            }
        }
        return fail(1, QString("Function at %1 not found in any source file")
                          .arg(hex32q(srcOfAddr)));
    }

    QString output;

    if (funcAddr != 0) {
        QString note;
        auto noteIt = projectFunctionNotes.find(funcAddr);
        if (noteIt != projectFunctionNotes.end())
            note = noteIt->second;
        output = withProjectEdits(Decompiler::decompile(mf, funcAddr), projectCustomTypes, note);
        if (jsonMode) {
            QJsonObject obj = makeMeta("decompile_function");
            obj["function_address"] = (int)funcAddr;
            obj["function_address_hex"] = hex32q(funcAddr);
            obj["code"] = output;
            printJson(obj);
            return 0;
        }
    } else if (funcName) {
        bool found = false;
        QJsonArray matches;
        for (const auto &fn : funcs) {
            if (fn.name.find(funcName) == std::string::npos) continue;
            found = true;
            if (!jsonMode)
                fprintf(stderr, "Decompiling: %s @ 0x%08X\n", fn.name.c_str(), fn.address);
            QString code = Decompiler::decompile(mf, fn.address);
            QString note;
            auto noteIt = projectFunctionNotes.find(fn.address);
            if (noteIt != projectFunctionNotes.end())
                note = noteIt->second;
            code = withProjectEdits(code, projectCustomTypes, note);
            if (jsonMode) {
                QJsonObject match = functionToJson(fn);
                match["code"] = code;
                matches.append(match);
            } else {
                output += code;
                output += "\n";
            }
        }
        if (!found)
            return fail(1, QString("No function matching '%1'").arg(funcName));
        if (jsonMode) {
            QJsonObject obj = makeMeta("decompile_function_by_name");
            obj["query"] = QString::fromUtf8(funcName);
            obj["matches"] = matches;
            printJson(obj);
            return 0;
        }
    } else if (srcIdx >= 0) {
        output = withProjectTypes(Decompiler::decompileFile(mf, srcIdx), projectCustomTypes);
        if (jsonMode) {
            QJsonObject obj = makeMeta("decompile_source");
            obj["source_index"] = srcIdx;
            obj["source_path"] = sourcePathFor(mf, srcIdx);
            obj["code"] = output;
            printJson(obj);
            return 0;
        }
    } else if (doAll) {
        // Optional allow-list: one basename (without .c) per line.
        std::set<std::string> onlySet;
        if (onlyList) {
            FILE *fp = fopen(onlyList, "r");
            if (!fp) {
                fprintf(stderr, "Cannot open --only list: %s\n", onlyList);
                return 1;
            }
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                std::string s(line);
                while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
                    s.pop_back();
                if (!s.empty()) onlySet.insert(s);
            }
            fclose(fp);
        }

        auto &sources = mf.stabsSourceFiles();
        int totalErrors = 0, written = 0, skipped = 0;
        QJsonArray files;
        for (size_t i = 0; i < sources.size(); ++i) {
            auto &sf = sources[i];
            if (sf.functionIndices.empty()) continue;

            // Derive basename: strip directory prefix and extension
            std::string base = sf.filename;
            size_t slash = base.find_last_of('/');
            if (slash != std::string::npos) base.erase(0, slash + 1);
            size_t dot = base.find_last_of('.');
            if (dot != std::string::npos) base.erase(dot);
            if (!onlySet.empty() && !onlySet.count(base)) {
                skipped++;
                continue;
            }

            if (!jsonMode)
                fprintf(stderr, "Decompiling [%zu] %s%s...\n",
                        i, sf.directory.c_str(), sf.filename.c_str());
            QString fileOut = withProjectTypes(Decompiler::decompileFile(mf, (int)i),
                                               projectCustomTypes);
            int errs = 0;
            if (doGcc) {
                errs = gccCheck(fileOut);
                if (errs > 0) totalErrors += errs;
            }
            if (jsonMode) {
                QJsonObject item;
                item["source_index"] = (int)i;
                item["source_path"] = sourcePathFor(mf, (int)i);
                item["code"] = fileOut;
                if (doGcc) item["gcc_errors"] = errs;
                if (outDir) item["output_path"] = QString::fromStdString(std::string(outDir) + "/" + base + ".c");
                files.append(item);
            }
            if (outDir) {
                std::string outPath = std::string(outDir) + "/" + base + ".c";
                FILE *fp = fopen(outPath.c_str(), "w");
                if (!fp) {
                    fprintf(stderr, "Cannot write %s\n", outPath.c_str());
                    continue;
                }
                QByteArray ba = fileOut.toUtf8();
                fwrite(ba.data(), 1, ba.size(), fp);
                fclose(fp);
                written++;
            } else if (!quiet) {
                printf("// ═══ [%zu] %s%s ═══\n",
                       i, sf.directory.c_str(), sf.filename.c_str());
                printf("%s\n", fileOut.toUtf8().constData());
            }
        }
        if (jsonMode) {
            QJsonObject obj = makeMeta("decompile_all_sources");
            obj["files"] = files;
            if (doGcc) obj["gcc_total_errors"] = totalErrors;
            if (outDir) {
                obj["output_dir"] = QString::fromUtf8(outDir);
                obj["written"] = written;
                obj["skipped"] = skipped;
            }
            printJson(obj);
        } else {
            if (outDir)
                fprintf(stderr, "Wrote %d files to %s (%d skipped)\n", written, outDir, skipped);
            if (doGcc)
                printf("\n=== Total: %d gcc errors across %zu files ===\n",
                       totalErrors, sources.size());
        }
        return 0;
    } else {
        return fail(1, "No action specified. Use -l, -F, --strings, --xref-string, --disasm, --infer-structs, -f, -n, -s, or -a");
    }

    if (!quiet)
        printf("%s", output.toUtf8().constData());
    if (doGcc)
        gccCheck(output);

    return 0;
}
