#pragma once
#include "macho.h"
#include "demangle.h"
#include <QString>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <cstdint>
#include <cstdio>
#include <capstone/capstone.h>

// ── Type-aware C decompiler for i386 Mach-O ─────────────────────────
// Produces compilable C using STABS debug info for types, struct fields,
// enum values, globals, and proper variable declarations.

class Decompiler {
    struct Expr {
        std::string text;
        TypeRef     typeRef  = NullType;
        bool        isParam  = false;
        bool        isCallRet= false;
        bool        isAddr   = false;
    };

    struct Ctx {
        const MachOFile        &mf;
        const StabsTypeTable   &types;
        const StabsFunction    *sfn;
        csh                     cs;
        cs_insn                *insn;
        size_t                  funcEnd;
        uint32_t                funcAddr;
        bool                    hasFrame  = false;
        int                     frameSize = 0;
        uint32_t                picBase   = 0;
        bool                    hasPIC    = false;

        std::map<int, StabsTypedVar>  paramByOffset;  // ebp+off -> typed param
        std::map<int, StabsTypedVar>  localByOffset;  // ebp-off -> typed local
        std::map<x86_reg, Expr>       regs;
        std::map<int, std::string>    espArgs;
        std::map<int, TypeRef>        espArgTypes;
        std::vector<std::string>      pushArgs;
        std::vector<TypeRef>          pushArgTypes;
        std::set<uint32_t>            jumpTargets;
        std::map<uint32_t, size_t>    addrToIdx;
        int callCounter = 0;

        // Track which types are referenced so we can emit forward decls
        mutable std::set<TypeRef> referencedTypes;

        // ── String resolution ───────────────────────────────────────
        std::string tryString(uint32_t addr) const {
            int64_t off = mf.fileOffsetForAddress(addr);
            if (off < 0) return "";
            const Section *sec = mf.sectionForAddress(addr);
            if (!sec || (sec->sectname != "__cstring" && sec->sectname != "__const"))
                return "";
            const uint8_t *p = mf.bytesAt(off, std::min((uint32_t)80, (uint32_t)(mf.size() - off)));
            if (!p) return "";
            std::string s;
            for (int i = 0; i < 72 && p[i]; ++i) {
                if (p[i] >= 0x20 && p[i] < 0x7F) {
                    if (p[i] == '"') s += "\\\"";
                    else if (p[i] == '\\') s += "\\\\";
                    else s += (char)p[i];
                } else {
                    char b[8]; snprintf(b, 8, "\\x%02X", p[i]); s += b;
                }
            }
            if (s.empty()) return "";
            return "\"" + s + "\"";
        }

        // ── Resolve an immediate as an enum value if we have context ─
        std::string tryEnumValue(uint32_t v, TypeRef expectedType) const {
            if (expectedType != NullType) {
                std::string name = types.findEnumName(expectedType, (int64_t)(int32_t)v);
                if (!name.empty()) return name;
            }
            return "";
        }

        // ── Global/static variable resolution ───────────────────────
        std::string tryGlobal(uint32_t addr) const {
            auto *g = types.globalAtAddress(addr);
            if (g) return g->name;
            return "";
        }

        // ── Format a capstone operand as C expression ───────────────
        std::string fmtOp(cs_x86_op &op, TypeRef hint = NullType) {
            if (op.type == X86_OP_REG) {
                auto it = regs.find(op.reg);
                if (it != regs.end() && !it->second.text.empty())
                    return it->second.text;
                return cs_reg_name(cs, op.reg);
            }
            if (op.type == X86_OP_IMM) {
                uint32_t v = (uint32_t)op.imm;
                // Try enum value with hint
                auto en = tryEnumValue(v, hint);
                if (!en.empty()) return en;
                // Check for string literal
                auto s = tryString(v);
                if (!s.empty()) return s;
                // Check for known function
                auto fit = mf.functionMap().find(v);
                if (fit != mf.functionMap().end()) return fit->second;
                // Check for global variable
                auto gn = tryGlobal(v);
                if (!gn.empty()) return "&" + gn;
                if (op.imm >= -256 && op.imm <= 256) return std::to_string(op.imm);
                char buf[32]; snprintf(buf, sizeof(buf), "0x%X", v);
                return buf;
            }
            if (op.type == X86_OP_MEM) return fmtMem(op.mem);
            return "?";
        }

        // Get type of an operand
        TypeRef opType(cs_x86_op &op) const {
            if (op.type == X86_OP_REG) {
                auto it = regs.find(op.reg);
                if (it != regs.end()) return it->second.typeRef;
            }
            if (op.type == X86_OP_MEM) return memType(op.mem);
            return NullType;
        }

        // Get type from a memory operand
        TypeRef memType(x86_op_mem &m) const {
            if (m.base == X86_REG_EBP && m.index == X86_REG_INVALID) {
                int d = (int)m.disp;
                if (d > 0) {
                    auto it = paramByOffset.find(d);
                    if (it != paramByOffset.end()) return it->second.typeRef;
                }
                if (d < 0) {
                    auto it = localByOffset.find(d);
                    if (it != localByOffset.end()) return it->second.typeRef;
                }
            }
            // Struct member access — return the field type
            if (m.index == X86_REG_INVALID && m.base != X86_REG_INVALID) {
                auto rit = regs.find(m.base);
                if (rit != regs.end() && rit->second.typeRef != NullType) {
                    TypeRef ptrType = rit->second.typeRef;
                    TypeRef structRef = types.getPointedStruct(ptrType);
                    if (structRef != NullType) {
                        auto *field = types.findFieldAtOffset(structRef, (int)m.disp);
                        if (field) return field->typeRef;
                    }
                }
            }
            return NullType;
        }

        std::string fmtMem(x86_op_mem &m) {
            // ebp-relative: params and locals with real names and types
            if (m.base == X86_REG_EBP && m.index == X86_REG_INVALID) {
                int d = (int)m.disp;
                if (d > 0) {
                    auto it = paramByOffset.find(d);
                    if (it != paramByOffset.end()) return it->second.name;
                    char buf[32]; snprintf(buf, sizeof(buf), "arg_%x", (d - 8) / 4);
                    return buf;
                }
                if (d < 0) {
                    auto it = localByOffset.find(d);
                    if (it != localByOffset.end()) return it->second.name;
                    char buf[32]; snprintf(buf, sizeof(buf), "var_%x", (-d) / 4);
                    return buf;
                }
                return "saved_ebp";
            }
            // PIC-relative: ebx + offset
            if (hasPIC && m.base == X86_REG_EBX && m.index == X86_REG_INVALID && picBase) {
                uint32_t addr = picBase + (int)m.disp;
                // Global variable?
                auto gn = tryGlobal(addr);
                if (!gn.empty()) return gn;
                auto s = tryString(addr);
                if (!s.empty()) return s;
                auto fit = mf.functionMap().find(addr);
                if (fit != mf.functionMap().end()) return "&" + fit->second;
                const Section *sec = mf.sectionForAddress(addr);
                if (sec) {
                    char buf[64];
                    snprintf(buf, sizeof(buf), "*(0x%X)  /* %s+0x%X */", addr,
                             sec->sectname.c_str(), addr - sec->addr);
                    return buf;
                }
                char buf[32]; snprintf(buf, sizeof(buf), "*(0x%X)", addr);
                return buf;
            }
            // esp-relative: suppress (captured as call args)
            if (m.base == X86_REG_ESP && m.index == X86_REG_INVALID)
                return "";

            // Struct member access: [base + disp] where base is a struct pointer
            if (m.index == X86_REG_INVALID && m.base != X86_REG_INVALID) {
                auto rit = regs.find(m.base);
                if (rit != regs.end() && rit->second.typeRef != NullType) {
                    TypeRef ptrType = rit->second.typeRef;
                    TypeRef structRef = types.getPointedStruct(ptrType);
                    if (structRef != NullType) {
                        auto *field = types.findFieldAtOffset(structRef, (int)m.disp);
                        if (field && !field->name.empty()) {
                            referencedTypes.insert(structRef);
                            return rit->second.text + "->" + field->name;
                        }
                    }
                    // Even without struct info, use the tracked expression
                    if (!rit->second.text.empty() && m.disp != 0) {
                        char buf[64]; snprintf(buf, sizeof(buf), "%s->field_%X",
                                               rit->second.text.c_str(), (unsigned)(int)m.disp);
                        return buf;
                    }
                }
                // Fallback with register name
                if (m.base && m.disp != 0) {
                    std::string base = cs_reg_name(cs, m.base);
                    char buf[64]; snprintf(buf, sizeof(buf), "%s->field_%X",
                                           base.c_str(), (unsigned)(int)m.disp);
                    return buf;
                }
            }

            // Direct memory access: [disp] (no base, no index)
            if (m.base == X86_REG_INVALID && m.index == X86_REG_INVALID && m.disp) {
                uint32_t addr = (uint32_t)m.disp;
                auto gn = tryGlobal(addr);
                if (!gn.empty()) return gn;
                auto s = tryString(addr);
                if (!s.empty()) return s;
                char buf[32]; snprintf(buf, sizeof(buf), "*(0x%X)", addr);
                return buf;
            }

            // General
            std::string s = "*(";
            bool needPlus = false;
            if (m.base) {
                auto rit = regs.find(m.base);
                if (rit != regs.end() && !rit->second.text.empty())
                    s += rit->second.text;
                else
                    s += cs_reg_name(cs, m.base);
                needPlus = true;
            }
            if (m.index != X86_REG_INVALID) {
                if (needPlus) s += " + ";
                auto rit = regs.find(m.index);
                if (rit != regs.end() && !rit->second.text.empty())
                    s += rit->second.text;
                else
                    s += cs_reg_name(cs, m.index);
                if (m.scale > 1) s += " * " + std::to_string(m.scale);
                needPlus = true;
            }
            if (m.disp) {
                if (m.disp < 0) {
                    char buf[32]; snprintf(buf, sizeof(buf), " - 0x%X", -(int)m.disp);
                    s += buf;
                } else {
                    char buf[32]; snprintf(buf, sizeof(buf), "%s0x%X", needPlus ? " + " : "", (int)m.disp);
                    s += buf;
                }
            }
            s += ")";
            return s;
        }

        std::string callTargetName(cs_x86_op &op) {
            if (op.type == X86_OP_IMM) {
                uint32_t addr = (uint32_t)op.imm;
                auto it = mf.functionMap().find(addr);
                if (it != mf.functionMap().end()) return it->second;
                char buf[32]; snprintf(buf, sizeof(buf), "sub_%X", addr);
                return buf;
            }
            return fmtOp(op);
        }

        // Get the return type of a call target
        TypeRef callReturnType(cs_x86_op &op) const {
            if (op.type == X86_OP_IMM) {
                uint32_t addr = (uint32_t)op.imm;
                auto *fn = mf.stabsFunctionAt(addr);
                if (fn && fn->returnType != NullType) return fn->returnType;
            }
            return NullType;
        }
    };

public:
    static QString decompile(const MachOFile &mf, uint32_t funcAddr) {
        const StabsFunction *sfn = mf.stabsFunctionAt(funcAddr);
        uint32_t endAddr = sfn && sfn->size > 0 ? funcAddr + sfn->size : funcAddr + 0x400;
        const auto &types = mf.typeTable();

        const Section *sec = mf.sectionForAddress(funcAddr);
        if (!sec) return "// Could not find section\n";

        csh cs;
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs) != CS_ERR_OK)
            return "// Capstone init failed\n";
        cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

        uint32_t codeOff = funcAddr - sec->addr;
        uint32_t codeLen = std::min(endAddr - funcAddr, sec->size - codeOff);
        const uint8_t *code = mf.bytesAt(sec->offset + codeOff, codeLen);
        if (!code) { cs_close(&cs); return "// Could not read code\n"; }

        cs_insn *insn;
        size_t count = cs_disasm(cs, code, codeLen, funcAddr, 0, &insn);
        if (count == 0) { cs_close(&cs); return "// Disassembly failed\n"; }

        // Trim at final ret
        size_t funcEnd = count;
        for (size_t i = 0; i < count; ++i)
            if (insn[i].detail)
                for (uint8_t g = 0; g < insn[i].detail->groups_count; ++g)
                    if (insn[i].detail->groups[g] == CS_GRP_RET)
                        { funcEnd = i + 1; goto found_ret; }
        found_ret:

        Ctx ctx{mf, types, sfn, cs, insn, funcEnd, funcAddr};
        auto &funcMap = mf.functionMap();

        for (size_t i = 0; i < funcEnd; ++i)
            ctx.addrToIdx[insn[i].address] = i;

        // ── Detect prologue ─────────────────────────────────────────
        if (funcEnd >= 2) {
            if (std::string(insn[0].mnemonic) == "push" && std::string(insn[0].op_str) == "ebp" &&
                std::string(insn[1].mnemonic) == "mov" && std::string(insn[1].op_str) == "ebp, esp") {
                ctx.hasFrame = true;
                if (funcEnd > 2 && std::string(insn[2].mnemonic) == "sub") {
                    auto *d = insn[2].detail;
                    if (d && d->x86.op_count == 2 && d->x86.operands[1].type == X86_OP_IMM)
                        ctx.frameSize = (int)d->x86.operands[1].imm;
                }
            }
        }

        // ── Detect PIC thunk ────────────────────────────────────────
        for (size_t i = 0; i + 1 < funcEnd; ++i) {
            if (std::string(insn[i].mnemonic) == "call" && i + 1 < funcEnd) {
                uint32_t tgt = 0;
                if (insn[i].detail && insn[i].detail->x86.op_count > 0 &&
                    insn[i].detail->x86.operands[0].type == X86_OP_IMM)
                    tgt = (uint32_t)insn[i].detail->x86.operands[0].imm;
                auto it = funcMap.find(tgt);
                bool isThunk = (it != funcMap.end() &&
                    (it->second.find("get_pc_thunk") != std::string::npos ||
                     it->second.find("__i686") != std::string::npos));
                if (isThunk && std::string(insn[i+1].mnemonic) == "add") {
                    auto *d2 = insn[i+1].detail;
                    if (d2 && d2->x86.op_count == 2 && d2->x86.operands[1].type == X86_OP_IMM) {
                        ctx.picBase = insn[i].address + insn[i].size + (uint32_t)d2->x86.operands[1].imm;
                        ctx.hasPIC = true;
                    }
                }
            }
        }

        // ── Build typed param/local maps ────────────────────────────
        if (sfn) {
            for (size_t i = 0; i < sfn->params.size(); ++i) {
                auto &p = sfn->params[i];
                int off = p.stackOffset ? p.stackOffset : (int)(8 + i * 4);
                ctx.paramByOffset[off] = p;
            }
            for (auto &l : sfn->locals) {
                if (l.stackOffset != 0)
                    ctx.localByOffset[l.stackOffset] = l;
            }
        }

        // Initialize register state for params
        if (sfn && !sfn->params.empty()) {
            ctx.regs[X86_REG_ECX] = {sfn->params[0].name, sfn->params[0].typeRef, true};
        }

        // ── Collect jump targets ────────────────────────────────────
        for (size_t i = 0; i < funcEnd; ++i) {
            if (!insn[i].detail) continue;
            for (uint8_t g = 0; g < insn[i].detail->groups_count; ++g)
                if (insn[i].detail->groups[g] == CS_GRP_JUMP) {
                    auto &op = insn[i].detail->x86.operands[0];
                    if (op.type == X86_OP_IMM)
                        ctx.jumpTargets.insert((uint32_t)op.imm);
                }
        }

        // ── Identify if/else structures ─────────────────────────────
        struct IfInfo {
            uint32_t elseAddr;
            uint32_t endAddr;
            bool     hasElse;
        };
        std::map<uint32_t, IfInfo> ifStructs;
        for (size_t i = 0; i < funcEnd; ++i) {
            if (!insn[i].detail) continue;
            bool isJcc = false;
            for (uint8_t g = 0; g < insn[i].detail->groups_count; ++g)
                if (insn[i].detail->groups[g] == CS_GRP_JUMP) isJcc = true;
            if (!isJcc) continue;
            std::string mn = insn[i].mnemonic;
            if (mn == "jmp") continue;
            auto &op = insn[i].detail->x86.operands[0];
            if (op.type != X86_OP_IMM) continue;
            uint32_t target = (uint32_t)op.imm;
            if (target <= insn[i].address) continue;

            auto tit = ctx.addrToIdx.find(target);
            if (tit == ctx.addrToIdx.end()) continue;
            size_t tgtIdx = tit->second;
            if (tgtIdx > 0 && std::string(insn[tgtIdx-1].mnemonic) == "jmp") {
                auto &jop = insn[tgtIdx-1].detail->x86.operands[0];
                if (jop.type == X86_OP_IMM && (uint32_t)jop.imm > target) {
                    ifStructs[insn[i].address] = {target, (uint32_t)jop.imm, true};
                    continue;
                }
            }
            ifStructs[insn[i].address] = {target, target, false};
        }

        // ── Generate output ─────────────────────────────────────────
        QString out;

        // Source file comment
        if (sfn && sfn->sourceFileIdx >= 0 && sfn->sourceFileIdx < (int)mf.stabsSourceFiles().size()) {
            auto &sf = mf.stabsSourceFiles()[sfn->sourceFileIdx];
            std::string fullPath = sf.directory + sf.filename;
            out += QString("/* %1 */\n").arg(QString::fromStdString(fullPath));
            if (!sfn->lineMap.empty())
                out += QString("/* lines %1-%2 */\n").arg(sfn->lineMap.front().second)
                           .arg(sfn->lineMap.back().second);
        }

        // Include directives from STABS
        auto &includes = types.includes();
        std::set<std::string> emittedIncludes;
        if (sfn && sfn->sourceFileIdx >= 0) {
            for (auto &inc : includes) {
                // Only emit relevant includes (heuristic: system vs local)
                if (emittedIncludes.count(inc)) continue;
                emittedIncludes.insert(inc);
                // Extract just the filename for the include
                std::string incName = inc;
                size_t lastSlash = inc.rfind('/');
                if (lastSlash != std::string::npos) incName = inc.substr(lastSlash + 1);
                if (incName.find('.') != std::string::npos) {
                    if (inc.find("/usr/") != std::string::npos || inc.find("/System/") != std::string::npos)
                        out += QString("#include <%1>\n").arg(QString::fromStdString(incName));
                    else
                        out += QString("#include \"%1\"\n").arg(QString::fromStdString(incName));
                }
            }
            if (!emittedIncludes.empty()) out += "\n";
        }

        // Function signature with real types
        auto fit = funcMap.find(funcAddr);
        std::string funcName = fit != funcMap.end() ? fit->second : "sub_" + ([&]{
            char b[16]; snprintf(b, sizeof(b), "%08X", funcAddr); return std::string(b); })();

        // Return type
        std::string retType = "int";
        if (sfn && sfn->returnType != NullType)
            retType = types.formatType(sfn->returnType);
        if (retType.empty()) retType = "int";

        // Static qualifier
        std::string qualifier;
        if (sfn && !sfn->isGlobal) qualifier = "static ";

        out += QString::fromStdString(qualifier + retType) + " " +
               QString::fromStdString(funcName) + "(";
        if (sfn && !sfn->params.empty()) {
            for (size_t i = 0; i < sfn->params.size(); ++i) {
                if (i) out += ", ";
                auto &p = sfn->params[i];
                if (p.typeRef != NullType) {
                    out += QString::fromStdString(types.formatDecl(p.typeRef, p.name));
                } else {
                    out += "int " + QString::fromStdString(p.name);
                }
            }
        } else if (!sfn) {
            out += "void";
        }
        out += ")\n{\n";

        // Declare locals with real types (filter empty and duplicates)
        if (sfn && !sfn->locals.empty()) {
            std::set<std::string> seen;
            for (auto &l : sfn->locals) {
                if (l.name.empty() || seen.count(l.name)) continue;
                seen.insert(l.name);
                if (l.typeRef != NullType) {
                    out += "    " + QString::fromStdString(types.formatDecl(l.typeRef, l.name)) + ";\n";
                } else {
                    out += "    int " + QString::fromStdString(l.name) + ";\n";
                }
            }
            if (!seen.empty()) out += "\n";
        }

        // ── Emit body ───────────────────────────────────────────────
        int indent = 1;
        auto pad = [&]() -> QString { return QString(indent * 4, ' '); };
        std::set<size_t> skip;

        for (size_t i = 0; i < funcEnd; ++i) {
            if (skip.count(i)) continue;
            auto &in = insn[i];
            std::string mn = in.mnemonic;
            cs_detail *d = in.detail;

            // Skip prologue
            if (i < 4 && ctx.hasFrame) {
                if (mn == "push" && std::string(in.op_str) == "ebp") continue;
                if (mn == "mov" && std::string(in.op_str) == "ebp, esp") continue;
                if (mn == "sub" && d && d->x86.op_count == 2 && d->x86.operands[0].reg == X86_REG_ESP) continue;
                if (mn == "push" && d && d->x86.op_count == 1 && d->x86.operands[0].type == X86_OP_REG) {
                    x86_reg r = d->x86.operands[0].reg;
                    if (r == X86_REG_EBX || r == X86_REG_ESI || r == X86_REG_EDI) continue;
                }
            }
            // Skip epilogue
            if (mn == "leave" || (mn == "pop" && d && d->x86.operands[0].type == X86_OP_REG &&
                (d->x86.operands[0].reg == X86_REG_EBX || d->x86.operands[0].reg == X86_REG_ESI ||
                 d->x86.operands[0].reg == X86_REG_EDI || d->x86.operands[0].reg == X86_REG_EBP)))
                continue;
            if (mn == "ret") {
                auto rit = ctx.regs.find(X86_REG_EAX);
                if (rit != ctx.regs.end() && !rit->second.text.empty())
                    out += pad() + "return " + QString::fromStdString(rit->second.text) + ";\n";
                else
                    out += pad() + "return;\n";
                continue;
            }
            if (mn == "nop" || mn == "fnop") continue;

            // ── PIC thunk call + add: skip ──────────────────────────
            if (mn == "call" && d && d->x86.op_count > 0 && d->x86.operands[0].type == X86_OP_IMM) {
                uint32_t tgt = (uint32_t)d->x86.operands[0].imm;
                auto tit = funcMap.find(tgt);
                if (tit != funcMap.end() && (tit->second.find("get_pc_thunk") != std::string::npos ||
                    tit->second.find("__i686") != std::string::npos)) {
                    if (i + 1 < funcEnd && std::string(insn[i+1].mnemonic) == "add")
                        skip.insert(i + 1);
                    continue;
                }
            }

            // ── Block labels ────────────────────────────────────────
            if (ctx.jumpTargets.count(in.address)) {
                bool isElse = false;
                for (auto &[jAddr, info] : ifStructs)
                    if (info.hasElse && info.elseAddr == in.address) isElse = true;
                bool isEnd = false;
                for (auto &[jAddr, info] : ifStructs)
                    if (info.endAddr == in.address) isEnd = true;

                if (isElse) {
                    indent--;
                    out += pad() + "} else {\n";
                    indent++;
                } else if (isEnd) {
                    indent--;
                    out += pad() + "}\n\n";
                } else {
                    out += "\n" + pad() + QString("loc_%1:\n").arg(in.address, 0, 16);
                }
            }

            // ── mov to [esp+N]: collect as call argument ────────────
            if (mn == "mov" && d && d->x86.op_count == 2 &&
                d->x86.operands[0].type == X86_OP_MEM &&
                d->x86.operands[0].mem.base == X86_REG_ESP &&
                d->x86.operands[0].mem.index == X86_REG_INVALID) {
                int off = (int)d->x86.operands[0].mem.disp;
                ctx.espArgs[off] = ctx.fmtOp(d->x86.operands[1]);
                ctx.espArgTypes[off] = ctx.opType(d->x86.operands[1]);
                if (d->x86.operands[1].type == X86_OP_REG)
                    ctx.regs.erase(d->x86.operands[1].reg);
                continue;
            }

            // ── push: collect as call argument ──────────────────────
            if (mn == "push" && d && d->x86.op_count == 1) {
                ctx.pushArgs.push_back(ctx.fmtOp(d->x86.operands[0]));
                ctx.pushArgTypes.push_back(ctx.opType(d->x86.operands[0]));
                continue;
            }

            // ── call: emit with collected arguments ─────────────────
            if (mn == "call" && d && d->x86.op_count > 0) {
                std::string target = ctx.callTargetName(d->x86.operands[0]);
                TypeRef retTypeRef = ctx.callReturnType(d->x86.operands[0]);

                std::vector<std::string> args;
                if (!ctx.espArgs.empty()) {
                    std::map<int, std::string> sorted(ctx.espArgs.begin(), ctx.espArgs.end());
                    for (auto &[off, val] : sorted) args.push_back(val);
                } else if (!ctx.pushArgs.empty()) {
                    for (int a = (int)ctx.pushArgs.size() - 1; a >= 0; --a)
                        args.push_back(ctx.pushArgs[a]);
                }

                std::string retName = "r" + std::to_string(ctx.callCounter++);
                ctx.regs[X86_REG_EAX] = {retName, retTypeRef, false, true};

                bool resultUsed = false;
                if (i + 1 < funcEnd) {
                    std::string nm = insn[i+1].mnemonic;
                    if (nm == "mov" || nm == "test" || nm == "cmp" || nm == "movzx" || nm == "movsx")
                        resultUsed = true;
                }

                // Determine return type string
                std::string retTypeStr = "int";
                if (retTypeRef != NullType) {
                    retTypeStr = types.formatType(retTypeRef);
                    auto *resolved = types.resolveType(retTypeRef);
                    if (resolved && resolved->kind == StabsTypeKind::Void)
                        resultUsed = false; // void functions have no return value
                }

                if (resultUsed) {
                    out += pad() + QString::fromStdString(retTypeStr) + " " +
                           QString::fromStdString(retName) + " = " +
                           QString::fromStdString(target) + "(";
                } else {
                    out += pad() + QString::fromStdString(target) + "(";
                }
                for (size_t a = 0; a < args.size(); ++a) {
                    if (a) out += ", ";
                    out += QString::fromStdString(args[a]);
                }
                out += ");\n";
                ctx.espArgs.clear();
                ctx.espArgTypes.clear();
                ctx.pushArgs.clear();
                ctx.pushArgTypes.clear();
                continue;
            }

            if (!d || d->x86.op_count == 0) {
                if (mn != "cdq")
                    out += pad() + "/* " + QString::fromStdString(mn) + " " + QString(in.op_str) + " */\n";
                continue;
            }

            // ── cmp/test + jcc: emit if/else ────────────────────────
            if ((mn == "test" || mn == "cmp") && d->x86.op_count == 2 && i + 1 < funcEnd) {
                auto &next = insn[i + 1];
                bool isJcc = false;
                if (next.detail)
                    for (uint8_t g = 0; g < next.detail->groups_count; ++g)
                        if (next.detail->groups[g] == CS_GRP_JUMP) isJcc = true;

                if (isJcc && next.detail && next.detail->x86.op_count > 0 &&
                    next.detail->x86.operands[0].type == X86_OP_IMM) {

                    // Get type context for enum resolution
                    TypeRef lhsType = ctx.opType(d->x86.operands[0]);

                    std::string lhs = ctx.fmtOp(d->x86.operands[0]);
                    std::string rhs = ctx.fmtOp(d->x86.operands[1], lhsType);
                    std::string jmn = next.mnemonic;

                    std::string cond;
                    if (mn == "test" && lhs == rhs) {
                        if (jmn == "je" || jmn == "jz")        cond = lhs + " != 0";
                        else if (jmn == "jne" || jmn == "jnz") cond = lhs + " == 0";
                        else if (jmn == "js")                   cond = lhs + " >= 0";
                        else if (jmn == "jns")                  cond = lhs + " < 0";
                        else cond = "!(" + lhs + " & " + rhs + ")";
                    } else {
                        std::string cop;
                        if (jmn == "je" || jmn == "jz")        cop = "!=";
                        else if (jmn == "jne" || jmn == "jnz") cop = "==";
                        else if (jmn == "jl" || jmn == "jnge") cop = ">=";
                        else if (jmn == "jle" || jmn == "jng") cop = ">";
                        else if (jmn == "jg" || jmn == "jnle") cop = "<=";
                        else if (jmn == "jge" || jmn == "jnl") cop = "<";
                        else if (jmn == "jb" || jmn == "jnae") cop = ">=";
                        else if (jmn == "jbe" || jmn == "jna") cop = ">";
                        else if (jmn == "ja" || jmn == "jnbe") cop = "<=";
                        else if (jmn == "jae" || jmn == "jnb") cop = "<";
                        else cop = "/* " + jmn + " */";
                        cond = lhs + " " + cop + " " + rhs;
                    }

                    auto ifit = ifStructs.find(next.address);
                    if (ifit != ifStructs.end()) {
                        out += pad() + "if (" + QString::fromStdString(cond) + ") {\n";
                        indent++;
                        skip.insert(i + 1);
                        if (ifit->second.hasElse) {
                            auto jmpIt = ctx.addrToIdx.find(ifit->second.elseAddr);
                            if (jmpIt != ctx.addrToIdx.end() && jmpIt->second > 0)
                                skip.insert(jmpIt->second - 1);
                        }
                        ++i;
                        continue;
                    }

                    uint32_t tgt = (uint32_t)next.detail->x86.operands[0].imm;
                    out += pad() + QString("if (!(%1)) goto loc_%2;\n")
                               .arg(QString::fromStdString(cond)).arg(tgt, 0, 16);
                    ++i;
                    continue;
                }
            }

            // ── mov ─────────────────────────────────────────────────
            if (mn == "mov" && d->x86.op_count == 2) {
                TypeRef srcType = ctx.opType(d->x86.operands[1]);
                std::string src = ctx.fmtOp(d->x86.operands[1]);
                if (src.empty()) continue;

                if (d->x86.operands[0].type == X86_OP_REG) {
                    // Track in register with type
                    if (srcType == NullType) srcType = ctx.memType(d->x86.operands[1].mem);
                    ctx.regs[d->x86.operands[0].reg] = {src, srcType};
                    continue;
                }
                std::string dst = ctx.fmtOp(d->x86.operands[0]);
                if (dst.empty() || dst == src) continue;
                out += pad() + QString::fromStdString(dst) + " = " + QString::fromStdString(src) + ";\n";
                continue;
            }
            if (mn == "lea" && d->x86.op_count == 2) {
                std::string src = ctx.fmtMem(d->x86.operands[1].mem);
                TypeRef srcType = ctx.memType(d->x86.operands[1].mem);
                if (d->x86.operands[0].type == X86_OP_REG) {
                    // LEA loads the address — make it a pointer
                    ctx.regs[d->x86.operands[0].reg] = {src.empty() ? "?" : "&" + src, srcType, false, false, true};
                    continue;
                }
                std::string dst = ctx.fmtOp(d->x86.operands[0]);
                if (src.empty()) continue;
                out += pad() + QString::fromStdString(dst) + " = &" + QString::fromStdString(src) + ";\n";
                continue;
            }
            if (mn == "movzx" || mn == "movsx") {
                std::string src = ctx.fmtOp(d->x86.operands[1]);
                TypeRef srcType = ctx.opType(d->x86.operands[1]);
                std::string cast = (mn == "movzx") ? "(unsigned char)" : "(signed char)";
                // Check if source has a known type that's already a char
                if (srcType != NullType) {
                    auto *resolved = types.resolveType(srcType);
                    if (resolved) {
                        if (resolved->kind == StabsTypeKind::Char || resolved->kind == StabsTypeKind::UChar ||
                            resolved->kind == StabsTypeKind::Bool)
                            cast = ""; // no cast needed, already the right type
                    }
                }
                if (d->x86.operands[0].type == X86_OP_REG) {
                    ctx.regs[d->x86.operands[0].reg] = {cast + src, srcType};
                    continue;
                }
                std::string dst = ctx.fmtOp(d->x86.operands[0]);
                out += pad() + QString::fromStdString(dst) + " = " + QString::fromStdString(cast + src) + ";\n";
                continue;
            }

            // ── xor reg, reg → zero ─────────────────────────────────
            if (mn == "xor" && d->x86.op_count == 2 &&
                d->x86.operands[0].type == X86_OP_REG && d->x86.operands[1].type == X86_OP_REG &&
                d->x86.operands[0].reg == d->x86.operands[1].reg) {
                ctx.regs[d->x86.operands[0].reg] = {"0"};
                continue;
            }

            // ── ALU ops ─────────────────────────────────────────────
            if ((mn == "add" || mn == "sub" || mn == "or" || mn == "and" ||
                 mn == "shl" || mn == "shr" || mn == "sar" || mn == "xor" || mn == "imul") &&
                d->x86.op_count == 2) {
                if (d->x86.operands[0].type == X86_OP_REG && d->x86.operands[0].reg == X86_REG_ESP)
                    continue;
                std::string dst = ctx.fmtOp(d->x86.operands[0]);
                std::string src = ctx.fmtOp(d->x86.operands[1]);
                std::string op;
                if (mn == "add") op = "+="; else if (mn == "sub") op = "-=";
                else if (mn == "or") op = "|="; else if (mn == "and") op = "&=";
                else if (mn == "shl") op = "<<="; else if (mn == "shr" || mn == "sar") op = ">>=";
                else if (mn == "xor") op = "^="; else if (mn == "imul") op = "*=";
                out += pad() + QString::fromStdString(dst) + " " + QString::fromStdString(op) +
                       " " + QString::fromStdString(src) + ";\n";
                if (d->x86.operands[0].type == X86_OP_REG)
                    ctx.regs.erase(d->x86.operands[0].reg);
                continue;
            }
            if ((mn == "inc" || mn == "dec") && d->x86.op_count == 1) {
                out += pad() + QString::fromStdString(ctx.fmtOp(d->x86.operands[0])) +
                       (mn == "inc" ? "++" : "--") + ";\n";
                continue;
            }
            if (mn == "not" && d->x86.op_count == 1) {
                std::string v = ctx.fmtOp(d->x86.operands[0]);
                out += pad() + QString::fromStdString(v) + " = ~" + QString::fromStdString(v) + ";\n";
                continue;
            }
            if (mn == "neg" && d->x86.op_count == 1) {
                std::string v = ctx.fmtOp(d->x86.operands[0]);
                out += pad() + QString::fromStdString(v) + " = -" + QString::fromStdString(v) + ";\n";
                continue;
            }

            // ── Unconditional jump ──────────────────────────────────
            {
                bool isJmp = false;
                if (d) for (uint8_t g = 0; g < d->groups_count; ++g)
                    if (d->groups[g] == CS_GRP_JUMP) isJmp = true;
                if (isJmp && d->x86.op_count > 0 && d->x86.operands[0].type == X86_OP_IMM) {
                    uint32_t tgt = (uint32_t)d->x86.operands[0].imm;
                    bool isStructured = false;
                    for (auto &[jAddr, info] : ifStructs)
                        if (info.hasElse && info.elseAddr == insn[i+1 < funcEnd ? i+1 : i].address)
                            isStructured = true;
                    if (!isStructured)
                        out += pad() + QString("goto loc_%1;\n").arg(tgt, 0, 16);
                    continue;
                }
            }

            // ── Fallback ────────────────────────────────────────────
            out += pad() + "/* " + QString::fromStdString(mn) + " " + QString(in.op_str) + " */\n";
        }

        // Close any open braces
        while (indent > 1) { indent--; out += pad() + "}\n"; }
        out += "}\n";

        cs_free(insn, count);
        cs_close(&cs);
        return out;
    }
};
