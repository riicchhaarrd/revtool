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
#include <sstream>
#include <capstone/capstone.h>

// Lightweight pseudo-C decompiler for i386 Mach-O.
// Not a real decompiler — produces annotated pseudo-code from
// instruction patterns, STABS debug info, and heuristics.

class PseudoDecompiler {
public:
    struct FuncRange {
        uint32_t start = 0;
        uint32_t end = 0;       // exclusive
    };

    static QString decompile(const MachOFile &mf, uint32_t funcAddr) {
        // Find the STABS function
        const StabsFunction *sfn = mf.stabsFunctionAt(funcAddr);

        // Determine range
        FuncRange range;
        range.start = funcAddr;
        if (sfn && sfn->size > 0)
            range.end = sfn->address + sfn->size;
        else
            range.end = funcAddr + 0x400; // default cap

        // Get the section containing this address
        const Section *sec = mf.sectionForAddress(funcAddr);
        if (!sec) return "// Could not find section for address\n";

        // Disassemble the function
        csh cs;
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs) != CS_ERR_OK)
            return "// Capstone init failed\n";
        cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

        uint32_t codeOff = funcAddr - sec->addr;
        uint32_t codeLen = std::min(range.end - funcAddr, sec->size - codeOff);
        const uint8_t *code = mf.bytesAt(sec->offset + codeOff, codeLen);
        if (!code) { cs_close(&cs); return "// Could not read code\n"; }

        cs_insn *insn;
        size_t count = cs_disasm(cs, code, codeLen, funcAddr, 0, &insn);
        if (count == 0) { cs_close(&cs); return "// Disassembly failed\n"; }

        // Trim at first ret (unless it's a conditional pattern)
        size_t funcEnd = count;
        for (size_t i = 0; i < count; ++i) {
            if (insn[i].detail) {
                for (uint8_t g = 0; g < insn[i].detail->groups_count; ++g) {
                    if (insn[i].detail->groups[g] == CS_GRP_RET) {
                        funcEnd = i + 1;
                        goto found_ret;
                    }
                }
            }
        }
        found_ret:

        auto &funcMap = mf.functionMap();

        // ── Collect info from prologue ──────────────────────────────
        int frameSize = 0;
        bool hasFrame = false;

        // Detect push ebp / mov ebp, esp / sub esp, N
        if (funcEnd >= 3) {
            std::string m0 = insn[0].mnemonic, m1 = insn[1].mnemonic;
            if (m0 == "push" && std::string(insn[0].op_str) == "ebp" &&
                m1 == "mov" && std::string(insn[1].op_str) == "ebp, esp") {
                hasFrame = true;
                if (funcEnd > 2 && std::string(insn[2].mnemonic) == "sub") {
                    auto *d = insn[2].detail;
                    if (d && d->x86.op_count == 2 && d->x86.operands[1].type == X86_OP_IMM)
                        frameSize = (int)d->x86.operands[1].imm;
                }
            }
        }

        // ── Collect jump targets for block labels ───────────────────
        std::set<uint32_t> jumpTargets;
        for (size_t i = 0; i < funcEnd; ++i) {
            if (!insn[i].detail) continue;
            for (uint8_t g = 0; g < insn[i].detail->groups_count; ++g) {
                if (insn[i].detail->groups[g] == CS_GRP_JUMP) {
                    auto &op = insn[i].detail->x86.operands[0];
                    if (op.type == X86_OP_IMM) jumpTargets.insert((uint32_t)op.imm);
                }
            }
        }

        // ── Build param/local name maps ─────────────────────────────
        // ebp+8 = arg0, ebp+12 = arg1, etc.
        // ebp-N = local
        std::map<int, std::string> paramNames;  // offset from ebp -> name
        std::map<int, std::string> localNames;

        if (sfn) {
            for (size_t i = 0; i < sfn->params.size(); ++i)
                paramNames[8 + (int)i * 4] = sfn->params[i];
            for (size_t i = 0; i < sfn->locals.size(); ++i)
                localNames[-(int)(i + 1) * 4] = sfn->locals[i];
        }

        // ── Helper: format operand as C-like expression ─────────────
        auto fmtOp = [&](cs_x86_op &op) -> std::string {
            if (op.type == X86_OP_IMM) {
                int64_t v = op.imm;
                if (v >= -256 && v <= 256) return std::to_string(v);
                char buf[32]; snprintf(buf, sizeof(buf), "0x%X", (uint32_t)v);
                return buf;
            }
            if (op.type == X86_OP_REG)
                return cs_reg_name(cs, op.reg);
            if (op.type == X86_OP_MEM) {
                auto &m = op.mem;
                // ebp-relative addressing
                if (m.base == X86_REG_EBP && m.index == X86_REG_INVALID) {
                    int disp = (int)m.disp;
                    if (disp > 0) {
                        auto it = paramNames.find(disp);
                        if (it != paramNames.end()) return it->second;
                        char buf[32]; snprintf(buf, sizeof(buf), "arg_%X", disp - 8);
                        return buf;
                    } else if (disp < 0) {
                        auto it = localNames.find(disp);
                        if (it != localNames.end()) return it->second;
                        char buf[32]; snprintf(buf, sizeof(buf), "var_%X", -disp);
                        return buf;
                    }
                }
                // esp-relative (common before calls)
                if (m.base == X86_REG_ESP && m.index == X86_REG_INVALID) {
                    char buf[32]; snprintf(buf, sizeof(buf), "*(esp + 0x%X)", (int)m.disp);
                    return buf;
                }
                // General: *(base + index*scale + disp)
                std::string s = "*(";
                if (m.base) s += cs_reg_name(cs, m.base);
                if (m.index) {
                    s += " + ";
                    s += cs_reg_name(cs, m.index);
                    if (m.scale > 1) s += "*" + std::to_string(m.scale);
                }
                if (m.disp) {
                    char buf[32]; snprintf(buf, sizeof(buf), " + 0x%X", (int)m.disp);
                    s += buf;
                }
                s += ")";
                return s;
            }
            return "?";
        };

        // ── Generate output ─────────────────────────────────────────
        QString out;
        out += "// ──────────────────────────────────────────────\n";
        out += "// Pseudo-C decompilation (heuristic)\n";
        if (sfn && sfn->sourceFileIdx >= 0 && sfn->sourceFileIdx < (int)mf.stabsSourceFiles().size()) {
            auto &sf = mf.stabsSourceFiles()[sfn->sourceFileIdx];
            out += QString("// Source: %1\n").arg(QString::fromStdString(sf.filename));
            if (!sfn->lineMap.empty())
                out += QString("// Lines: %1–%2\n").arg(sfn->lineMap.front().second).arg(sfn->lineMap.back().second);
        }
        out += "// ──────────────────────────────────────────────\n\n";

        // Function name
        auto fit = funcMap.find(funcAddr);
        std::string funcName = fit != funcMap.end() ? fit->second : "sub_" + ([&]{
            char b[16]; snprintf(b, sizeof(b), "%08X", funcAddr); return std::string(b);
        })();

        // Signature
        out += QString("int %1(").arg(QString::fromStdString(funcName));
        if (sfn && !sfn->params.empty()) {
            for (size_t i = 0; i < sfn->params.size(); ++i) {
                if (i) out += ", ";
                out += QString("int %1").arg(QString::fromStdString(sfn->params[i]));
            }
        } else {
            out += "...";
        }
        out += ")\n{\n";

        // Locals
        if (frameSize > 0)
            out += QString("    // stack frame: %1 bytes\n").arg(frameSize);
        if (sfn && !sfn->locals.empty()) {
            for (auto &l : sfn->locals)
                out += QString("    int %1;\n").arg(QString::fromStdString(l));
            out += "\n";
        }

        // ── Walk instructions and emit pseudo-C ─────────────────────
        int indent = 1;
        auto pad = [&]() { return QString(indent * 4, ' '); };

        // Track pending call args (pushes before call)
        std::vector<std::string> callArgs;

        for (size_t i = 0; i < funcEnd; ++i) {
            auto &in = insn[i];
            std::string mn = in.mnemonic;
            cs_detail *d = in.detail;

            // Skip prologue
            if (i < 3 && hasFrame &&
                (mn == "push" || (mn == "mov" && std::string(in.op_str) == "ebp, esp") ||
                 (mn == "sub" && d && d->x86.op_count == 2 && d->x86.operands[0].reg == X86_REG_ESP)))
                continue;

            // Skip epilogue
            if (mn == "leave" || mn == "pop" || mn == "ret") {
                if (mn == "ret") out += pad() + "return eax;\n";
                continue;
            }

            // Block label
            if (jumpTargets.count(in.address)) {
                out += QString("\nloc_%1:\n").arg(in.address, 0, 16);
            }

            // ── Translate instructions ───────────────────────────────
            if (mn == "nop" || mn == "fnop") continue;

            if (mn == "push" && d && d->x86.op_count == 1) {
                callArgs.push_back(fmtOp(d->x86.operands[0]));
                continue;
            }

            if (mn == "call") {
                std::string target;
                if (d && d->x86.op_count > 0 && d->x86.operands[0].type == X86_OP_IMM) {
                    uint32_t taddr = (uint32_t)d->x86.operands[0].imm;
                    auto tit = funcMap.find(taddr);
                    target = tit != funcMap.end() ? tit->second : ([&]{
                        char b[16]; snprintf(b, sizeof(b), "sub_%X", taddr); return std::string(b);
                    })();
                } else {
                    target = fmtOp(d->x86.operands[0]);
                }
                out += pad() + "eax = " + QString::fromStdString(target) + "(";
                // Reverse the push order for args
                for (int a = (int)callArgs.size() - 1; a >= 0; --a) {
                    if (a < (int)callArgs.size() - 1) out += ", ";
                    out += QString::fromStdString(callArgs[a]);
                }
                out += ");\n";
                callArgs.clear();
                continue;
            }

            if (!d || d->x86.op_count == 0) {
                out += pad() + "// " + QString::fromStdString(mn) + " " + QString(in.op_str) + "\n";
                continue;
            }

            if (mn == "mov" && d->x86.op_count == 2) {
                out += pad() + QString::fromStdString(fmtOp(d->x86.operands[0])) +
                       " = " + QString::fromStdString(fmtOp(d->x86.operands[1])) + ";\n";
                continue;
            }
            if (mn == "lea" && d->x86.op_count == 2) {
                out += pad() + QString::fromStdString(fmtOp(d->x86.operands[0])) +
                       " = &" + QString::fromStdString(fmtOp(d->x86.operands[1])) + ";\n";
                continue;
            }
            if (mn == "xor" && d->x86.op_count == 2 &&
                d->x86.operands[0].type == X86_OP_REG && d->x86.operands[1].type == X86_OP_REG &&
                d->x86.operands[0].reg == d->x86.operands[1].reg) {
                out += pad() + QString::fromStdString(fmtOp(d->x86.operands[0])) + " = 0;\n";
                continue;
            }
            if ((mn == "add" || mn == "sub" || mn == "or" || mn == "and" || mn == "shl" || mn == "shr" || mn == "sar" || mn == "xor" || mn == "imul") && d->x86.op_count == 2) {
                std::string op;
                if (mn == "add") op = "+="; else if (mn == "sub") op = "-=";
                else if (mn == "or") op = "|="; else if (mn == "and") op = "&=";
                else if (mn == "shl") op = "<<="; else if (mn == "shr" || mn == "sar") op = ">>=";
                else if (mn == "xor") op = "^="; else if (mn == "imul") op = "*=";
                out += pad() + QString::fromStdString(fmtOp(d->x86.operands[0])) + " " +
                       QString::fromStdString(op) + " " +
                       QString::fromStdString(fmtOp(d->x86.operands[1])) + ";\n";
                continue;
            }
            if ((mn == "inc" || mn == "dec") && d->x86.op_count == 1) {
                out += pad() + QString::fromStdString(fmtOp(d->x86.operands[0])) +
                       (mn == "inc" ? "++" : "--") + ";\n";
                continue;
            }
            if ((mn == "test" || mn == "cmp") && d->x86.op_count == 2) {
                std::string lhs = fmtOp(d->x86.operands[0]);
                std::string rhs = fmtOp(d->x86.operands[1]);
                // Look ahead for conditional jump
                if (i + 1 < funcEnd) {
                    auto &next = insn[i + 1];
                    bool isJcc = false;
                    if (next.detail)
                        for (uint8_t g = 0; g < next.detail->groups_count; ++g)
                            if (next.detail->groups[g] == CS_GRP_JUMP) isJcc = true;

                    if (isJcc && next.detail && next.detail->x86.op_count > 0 &&
                        next.detail->x86.operands[0].type == X86_OP_IMM) {
                        uint32_t tgt = (uint32_t)next.detail->x86.operands[0].imm;
                        std::string jmn = next.mnemonic;
                        std::string cond;
                        if (mn == "test" && lhs == rhs) {
                            // test x, x is a zero check
                            if (jmn == "je" || jmn == "jz") cond = lhs + " == 0";
                            else if (jmn == "jne" || jmn == "jnz") cond = lhs + " != 0";
                            else if (jmn == "js") cond = lhs + " < 0";
                            else if (jmn == "jns") cond = lhs + " >= 0";
                            else cond = lhs + " (flag: " + jmn + ")";
                        } else {
                            std::string cop;
                            if (jmn == "je" || jmn == "jz") cop = "==";
                            else if (jmn == "jne" || jmn == "jnz") cop = "!=";
                            else if (jmn == "jl" || jmn == "jnge") cop = "<";
                            else if (jmn == "jle" || jmn == "jng") cop = "<=";
                            else if (jmn == "jg" || jmn == "jnle") cop = ">";
                            else if (jmn == "jge" || jmn == "jnl") cop = ">=";
                            else if (jmn == "jb" || jmn == "jnae") cop = "<";  // unsigned
                            else if (jmn == "jbe" || jmn == "jna") cop = "<="; // unsigned
                            else if (jmn == "ja" || jmn == "jnbe") cop = ">";  // unsigned
                            else if (jmn == "jae" || jmn == "jnb") cop = ">="; // unsigned
                            else cop = jmn;
                            cond = lhs + " " + cop + " " + rhs;
                        }
                        out += pad() + QString("if (%1) goto loc_%2;\n")
                                   .arg(QString::fromStdString(cond))
                                   .arg(tgt, 0, 16);
                        ++i; // skip the jcc
                        continue;
                    }
                }
                out += pad() + "// " + QString::fromStdString(mn) + " " + QString(in.op_str) + "\n";
                continue;
            }

            // Unconditional jump
            bool isJmp = false;
            if (d) for (uint8_t g = 0; g < d->groups_count; ++g) if (d->groups[g] == CS_GRP_JUMP) isJmp = true;
            if (isJmp && d->x86.op_count > 0 && d->x86.operands[0].type == X86_OP_IMM) {
                uint32_t tgt = (uint32_t)d->x86.operands[0].imm;
                out += pad() + QString("goto loc_%1;\n").arg(tgt, 0, 16);
                continue;
            }

            if (mn == "movzx" || mn == "movsx") {
                out += pad() + QString::fromStdString(fmtOp(d->x86.operands[0])) +
                       " = (" + QString(mn == "movzx" ? "unsigned" : "signed") + ")" +
                       QString::fromStdString(fmtOp(d->x86.operands[1])) + ";\n";
                continue;
            }
            if (mn == "cdq") { out += pad() + "edx = (eax < 0) ? -1 : 0;  // sign-extend\n"; continue; }
            if (mn == "not" && d->x86.op_count == 1) {
                out += pad() + QString::fromStdString(fmtOp(d->x86.operands[0])) + " = ~" +
                       QString::fromStdString(fmtOp(d->x86.operands[0])) + ";\n";
                continue;
            }
            if (mn == "neg" && d->x86.op_count == 1) {
                out += pad() + QString::fromStdString(fmtOp(d->x86.operands[0])) + " = -" +
                       QString::fromStdString(fmtOp(d->x86.operands[0])) + ";\n";
                continue;
            }

            // Fallback: emit as asm comment
            out += pad() + "// " + QString::fromStdString(mn) + " " + QString(in.op_str) + "\n";
        }

        out += "}\n";

        cs_free(insn, count);
        cs_close(&cs);
        return out;
    }
};
