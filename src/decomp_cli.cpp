// CLI tool for testing the decompiler and driving it from scripts/LLMs.
// Usage:
//   decomp <binary> [options]
//
//   -l                 List source files
//   -F                 List functions
//   --strings          List discovered strings
//   --xref-string <q>  Find code references to strings containing <q>
//   -f <addr>          Decompile function at hex address
//   -n <name>          Decompile function by name (substring match)
//   -s <idx>           Decompile source file by index
//   -a                 Decompile all source files
//   --json             Emit machine-readable JSON for the selected action
//   --gcc              Pipe decompiled output through gcc -fsyntax-only

#include "decompiler.h"
#include "macho.h"
#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QString>
#include <capstone/capstone.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
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

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    if (argc < 2) {
        fprintf(stderr,
            "Usage: decomp <binary> [options]\n"
            "  -l                 List source files\n"
            "  -F                 List functions\n"
            "  --strings          List discovered strings\n"
            "  --xref-string <q>  Find functions/xrefs by string usage\n"
            "  -f <addr>          Decompile function at hex address\n"
            "  -n <name>          Decompile function by name (substring match)\n"
            "  -s <idx>           Decompile source file by index\n"
            "  -a                 Decompile all source files\n"
            "  -o <dir>           Write -a output to individual .c files\n"
            "  --only <file>      Limit -a to basenames listed in file\n"
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
    bool doGcc = false, quiet = false, doTypes = false, jsonMode = false;
    uint32_t srcOfAddr = 0;
    uint32_t funcAddr = 0;
    int srcIdx = -1;
    const char *funcName = nullptr;
    const char *xrefString = nullptr;
    const char *outDir = nullptr;
    const char *onlyList = nullptr;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "-l") == 0) doList = true;
        else if (strcmp(argv[i], "-F") == 0) doFuncs = true;
        else if (strcmp(argv[i], "-a") == 0) doAll = true;
        else if (strcmp(argv[i], "--strings") == 0) doStrings = true;
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

    auto makeMeta = [&](const char *action) {
        QJsonObject obj;
        obj["status"] = QString("ok");
        obj["action"] = QString::fromUtf8(action);
        obj["binary"] = QString::fromUtf8(binPath);
        obj["format"] = QString::fromUtf8(mf.formatName());
        obj["size"] = (int)mf.size();
        obj["debug_function_count"] = (int)mf.stabsFunctions().size();
        obj["source_file_count"] = (int)mf.stabsSourceFiles().size();
        return obj;
    };

    if (!jsonMode) {
        fprintf(stderr, "Loaded %s [%s]: %zu bytes, %zu functions, %zu source files\n",
                binPath, mf.formatName(), mf.size(), mf.stabsFunctions().size(),
                mf.stabsSourceFiles().size());
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

    if (doTypes) {
        QString hdr = Decompiler::dumpTypes(mf);
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
        output = Decompiler::decompile(mf, funcAddr);
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
        output = Decompiler::decompileFile(mf, srcIdx);
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
            QString fileOut = Decompiler::decompileFile(mf, (int)i);
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
        return fail(1, "No action specified. Use -l, -F, --strings, --xref-string, -f, -n, -s, or -a");
    }

    if (!quiet)
        printf("%s", output.toUtf8().constData());
    if (doGcc)
        gccCheck(output);

    return 0;
}
