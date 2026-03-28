#pragma once
#include "ir.h"
#include "macho.h"
#include <capstone/capstone.h>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>

// ── x86 → IR Lifter ─────────────────────────────────────────────────
// Converts every x86-32 instruction into IR statements.  Tracks register
// contents as IR temps so later passes can build expression trees.

class Lifter {
public:
    Lifter(const MachOFile &mf) : m_mf(mf), m_types(mf.typeTable()) {}

    // Lift one function into an IRFunc.  Returns empty blocks on failure.
    IRFunc liftFunction(uint32_t funcAddr) {
        IRFunc func;
        const StabsFunction *sfn = m_mf.stabsFunctionAt(funcAddr);
        uint32_t endAddr;
        if (sfn && sfn->size > 0) {
            endAddr = funcAddr + sfn->size;
        } else {
            // Find the next function's address as an upper bound
            endAddr = funcAddr + 0x2000;
            auto &funcMap = m_mf.functionMap();
            for (auto &[addr, name] : funcMap) {
                if (addr > funcAddr && addr < endAddr)
                    endAddr = addr;
            }
        }
        auto &funcMap = m_mf.functionMap();

        // Function metadata from STABS
        auto fit = funcMap.find(funcAddr);
        func.name = fit != funcMap.end() ? fit->second :
            "sub_" + ([&]{ char b[16]; snprintf(b,16,"%08X",funcAddr); return std::string(b); })();
        func.address = funcAddr;
        if (sfn) {
            func.returnType = sfn->returnType;
            func.isStatic = !sfn->isGlobal;
            func.params = sfn->params;
            func.locals = sfn->locals;
            func.sourceFileIdx = sfn->sourceFileIdx;
        }

        // Disassemble
        const Section *sec = m_mf.sectionForAddress(funcAddr);
        if (!sec) return func;

        csh cs;
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs) != CS_ERR_OK) return func;
        cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

        uint32_t codeOff = funcAddr - sec->addr;
        uint32_t codeLen = std::min(endAddr - funcAddr, sec->size - codeOff);
        const uint8_t *code = m_mf.bytesAt(sec->offset + codeOff, codeLen);
        if (!code) { cs_close(&cs); return func; }

        cs_insn *insn;
        size_t count = cs_disasm(cs, code, codeLen, funcAddr, 0, &insn);
        if (count == 0) { cs_close(&cs); return func; }

        // Find actual end — use STABS size if available, else find the right ret
        size_t funcEndIdx = count;
        if (sfn && sfn->size > 0) {
            // Use the known function size from STABS
            uint32_t funcEnd = funcAddr + sfn->size;
            for (size_t i = 0; i < count; ++i) {
                if (insn[i].address >= funcEnd) {
                    funcEndIdx = i;
                    break;
                }
            }
        } else {
            // If we detect jump tables, use last ret; otherwise use first ret
            bool hasJumpTable = false;
            size_t firstRet = count, lastRet = 0;
            for (size_t i = 0; i < count; ++i) {
                if (insn[i].detail) {
                    for (uint8_t g = 0; g < insn[i].detail->groups_count; ++g) {
                        if (insn[i].detail->groups[g] == CS_GRP_RET) {
                            if (firstRet == count) firstRet = i + 1;
                            lastRet = i + 1;
                        }
                    }
                    // Quick check for indirect jmp with scale=4 (potential jump table)
                    if (std::string(insn[i].mnemonic) == "jmp" &&
                        insn[i].detail->x86.op_count > 0 &&
                        insn[i].detail->x86.operands[0].type == X86_OP_MEM &&
                        insn[i].detail->x86.operands[0].mem.scale == 4)
                        hasJumpTable = true;
                }
            }
            funcEndIdx = hasJumpTable ? lastRet : firstRet;
            if (funcEndIdx == 0) funcEndIdx = count;
        }

        // ── Pass 1: find all branch targets → basic block boundaries ─
        std::set<uint32_t> blockStarts;
        blockStarts.insert(funcAddr);
        for (size_t i = 0; i < funcEndIdx; ++i) {
            auto &in = insn[i];
            if (!in.detail) continue;
            bool isBranch = false, isJump = false, isRet = false;
            for (uint8_t g = 0; g < in.detail->groups_count; ++g) {
                if (in.detail->groups[g] == CS_GRP_JUMP) isJump = true;
                if (in.detail->groups[g] == CS_GRP_RET)  isRet = true;
            }
            if (isJump && in.detail->x86.op_count > 0 &&
                in.detail->x86.operands[0].type == X86_OP_IMM) {
                uint32_t target = (uint32_t)in.detail->x86.operands[0].imm;
                if (target >= funcAddr && target < funcAddr + codeLen)
                    blockStarts.insert(target);
                // Instruction after a branch is also a block start
                if (i + 1 < funcEndIdx)
                    blockStarts.insert(insn[i + 1].address);
            }
            if (isRet && i + 1 < funcEndIdx)
                blockStarts.insert(insn[i + 1].address);

            // ── Jump table detection: jmp [index*4 + table] ──────────
            if (isJump && in.detail->x86.op_count > 0 &&
                in.detail->x86.operands[0].type == X86_OP_MEM) {
                auto &mem = in.detail->x86.operands[0].mem;
                // Pattern: jmp [reg*4 + addr] or jmp [ebx + reg*4 + disp] (PIC)
                if (mem.scale == 4 && mem.index != X86_REG_INVALID) {
                    uint32_t tableAddr = 0;
                    if (mem.base == X86_REG_INVALID && mem.disp)
                        tableAddr = (uint32_t)mem.disp;
                    else if (m_hasPIC && mem.base == X86_REG_EBX && m_picBase)
                        tableAddr = m_picBase + (int)mem.disp;

                    if (tableAddr) {
                        // Find the bounds check (cmp + ja/jbe) preceding this jmp
                        int numCases = 0;
                        int switchBase = 0;
                        uint32_t defaultAddr = 0;
                        for (int back = (int)i - 1; back >= 0 && back >= (int)i - 20; --back) {
                            std::string bmn = insn[back].mnemonic;
                            // ja default_label (unsigned above = out of range)
                            if ((bmn == "ja" || bmn == "jnbe") && insn[back].detail &&
                                insn[back].detail->x86.op_count > 0 &&
                                insn[back].detail->x86.operands[0].type == X86_OP_IMM) {
                                defaultAddr = (uint32_t)insn[back].detail->x86.operands[0].imm;
                            }
                            // jbe in_range → jbe jumps to switch body; NOT-taken is default
                            if ((bmn == "jbe" || bmn == "jna") && !defaultAddr && insn[back].detail &&
                                insn[back].detail->x86.op_count > 0 &&
                                insn[back].detail->x86.operands[0].type == X86_OP_IMM) {
                                // Default = instruction after jbe (fall-through when NOT taken)
                                if (back + 1 < (int)funcEndIdx)
                                    defaultAddr = insn[back + 1].address;
                            }
                            if (bmn == "cmp" && insn[back].detail &&
                                insn[back].detail->x86.op_count >= 2 &&
                                insn[back].detail->x86.operands[insn[back].detail->x86.op_count-1].type == X86_OP_IMM) {
                                numCases = (int)insn[back].detail->x86.operands[insn[back].detail->x86.op_count-1].imm + 1;
                            }
                            if (bmn == "sub" && insn[back].detail &&
                                insn[back].detail->x86.op_count == 2 &&
                                insn[back].detail->x86.operands[1].type == X86_OP_IMM) {
                                switchBase = (int)insn[back].detail->x86.operands[1].imm;
                            }
                        }
                        if (numCases > 0 && numCases <= 1024) {
                            // Read jump table and add targets as block starts
                            SwitchInfo si;
                            si.instrAddr = in.address;
                            si.tableAddr = tableAddr;
                            si.numCases = numCases;
                            si.switchBase = switchBase;
                            si.defaultAddr = defaultAddr;
                            for (int c = 0; c < numCases; ++c) {
                                int64_t off = m_mf.fileOffsetForAddress(tableAddr + c * 4);
                                if (off < 0) break;
                                const uint8_t *p = m_mf.bytesAt((uint32_t)off, 4);
                                if (!p) break;
                                uint32_t target;
                                memcpy(&target, p, 4);
                                si.targets.push_back(target);
                                if (target >= funcAddr && target < funcAddr + codeLen)
                                    blockStarts.insert(target);
                            }
                            if (defaultAddr >= funcAddr && defaultAddr < funcAddr + codeLen)
                                blockStarts.insert(defaultAddr);
                            m_switchTables[in.address] = std::move(si);
                            if (i + 1 < funcEndIdx)
                                blockStarts.insert(insn[i + 1].address);
                        }
                    }
                }
            }
        }

        // ── Pass 2: create basic blocks ──────────────────────────────
        std::map<uint32_t, int> addrToBlock;
        for (uint32_t addr : blockStarts) {
            int id = (int)func.blocks.size();
            func.blocks.push_back({});
            func.blocks.back().id = id;
            func.blocks.back().startAddr = addr;
            addrToBlock[addr] = id;
        }

        // ── Pass 3: detect prologue & PIC thunk ─────────────────────
        m_hasFrame = false; m_frameSize = 0;
        m_hasPIC = false; m_picBase = 0;
        m_prologueEnd = 0;

        if (funcEndIdx >= 2 &&
            std::string(insn[0].mnemonic) == "push" && std::string(insn[0].op_str) == "ebp" &&
            std::string(insn[1].mnemonic) == "mov" && std::string(insn[1].op_str) == "ebp, esp") {
            m_hasFrame = true;
            m_prologueEnd = 2;
            if (funcEndIdx > 2 && std::string(insn[2].mnemonic) == "sub") {
                auto *d = insn[2].detail;
                if (d && d->x86.op_count == 2 && d->x86.operands[1].type == X86_OP_IMM) {
                    m_frameSize = (int)d->x86.operands[1].imm;
                    m_prologueEnd = 3;
                }
            }
            // Callee-saved pushes
            for (size_t i = m_prologueEnd; i < std::min(funcEndIdx, m_prologueEnd + 3); ++i) {
                if (std::string(insn[i].mnemonic) == "push" && insn[i].detail &&
                    insn[i].detail->x86.op_count == 1 && insn[i].detail->x86.operands[0].type == X86_OP_REG) {
                    auto r = insn[i].detail->x86.operands[0].reg;
                    if (r == X86_REG_EBX || r == X86_REG_ESI || r == X86_REG_EDI)
                        m_prologueEnd = i + 1;
                }
            }
        }

        // PIC thunk detection
        for (size_t i = 0; i + 1 < funcEndIdx; ++i) {
            if (std::string(insn[i].mnemonic) != "call") continue;
            if (!insn[i].detail || insn[i].detail->x86.op_count == 0) continue;
            if (insn[i].detail->x86.operands[0].type != X86_OP_IMM) continue;
            uint32_t tgt = (uint32_t)insn[i].detail->x86.operands[0].imm;
            auto it = funcMap.find(tgt);
            if (it == funcMap.end()) continue;
            if (it->second.find("get_pc_thunk") == std::string::npos &&
                it->second.find("__i686") == std::string::npos) continue;
            if (std::string(insn[i+1].mnemonic) == "add") {
                auto *d2 = insn[i+1].detail;
                if (d2 && d2->x86.op_count == 2 && d2->x86.operands[1].type == X86_OP_IMM) {
                    m_picBase = insn[i].address + insn[i].size + (uint32_t)d2->x86.operands[1].imm;
                    m_hasPIC = true;
                    m_picThunkAddr = insn[i].address;
                }
            }
        }

        // ── Pass 3b: detect float-returning calls by post-call FPU usage ─
        // If the instruction after a call reads ST(0) (fstp, fst, fadd, etc.),
        // the call returns float/double via the x87 FPU stack.
        m_floatReturnAddrs.clear();
        for (size_t i = 0; i + 1 < funcEndIdx; ++i) {
            if (std::string(insn[i].mnemonic) != "call") continue;
            std::string nextMn = insn[i+1].mnemonic;
            // Any FPU instruction that reads ST(0) implies float return
            if (nextMn == "fstp" || nextMn == "fst" || nextMn == "fmul" ||
                nextMn == "fmulp" || nextMn == "fadd" || nextMn == "faddp" ||
                nextMn == "fsub" || nextMn == "fsubp" || nextMn == "fdiv" ||
                nextMn == "fdivp" || nextMn == "fxch" || nextMn == "fchs" ||
                nextMn == "fcomp" || nextMn == "fcompp" || nextMn == "fucomip" ||
                nextMn == "fucomp" || nextMn == "fucompp" || nextMn == "fild" ||
                nextMn == "fabs") {
                // Mark the call target address as float-returning
                if (insn[i].detail && insn[i].detail->x86.op_count >= 1 &&
                    insn[i].detail->x86.operands[0].type == X86_OP_IMM) {
                    m_floatReturnAddrs.insert((uint32_t)insn[i].detail->x86.operands[0].imm);
                }
                // Also mark by instruction address for indirect calls
                m_floatRetCallSites.insert(insn[i].address);
            }
        }

        // ── Pass 4: build param/local offset maps ───────────────────
        m_paramByOffset.clear();
        m_localByOffset.clear();
        if (sfn) {
            for (size_t i = 0; i < sfn->params.size(); ++i) {
                int off = sfn->params[i].stackOffset ? sfn->params[i].stackOffset : (int)(8 + i * 4);
                m_paramByOffset[off] = &sfn->params[i];
            }
            for (auto &l : sfn->locals) {
                if (l.stackOffset != 0)
                    m_localByOffset[l.stackOffset] = &l;
            }
        }

        // ── Pass 4b: inject register parameter assignments ────────
        // When STABS says a param is in a register (regNum >= 0, stackOffset == 0),
        // inject a VarSet at the start of block 0 capturing the register value.
        // STABS register numbers: 0=eax, 1=ecx, 2=edx, 3=ebx, 4=esp, 5=ebp,
        // 6=esi, 7=edi, 12-19=xmm0-7, 21-28=st0-7
        m_regParamRegs.clear();
        if (sfn) {
            for (auto &p : sfn->params) {
                if (p.regNum >= 0 && p.stackOffset == 0) {
                    x86_reg xr = stabsRegToX86(p.regNum);
                    if (xr != X86_REG_INVALID)
                        m_regParamRegs[xr] = &p;
                }
            }
        }

        // ── Pass 5: lift instructions into basic blocks ─────────────
        m_func = &func;
        m_cs = cs;
        m_regTemps.clear();
        m_espArgs.clear();
        m_pushArgs.clear();
        m_fpuStack.clear();
        m_lastFpuTop = -1;
        m_regParamInjected.clear();
        m_flags = {-1, IROp::Eq, nullptr, nullptr};

        // Inject register parameter initializations.
        // Scan the first few instructions for "mov REGPARAM_DEST, SRC" patterns
        // where DEST is a regparam register. Pre-bind the SRC register to the
        // parameter name since the calling convention delivers the value there.
        if (!func.blocks.empty() && !m_regParamRegs.empty()) {
            auto &bb0 = func.blocks[0];
            // First, scan prologue instructions to find source registers
            std::set<x86_reg> sourcesHandled;
            for (size_t pi = 0; pi < std::min(funcEndIdx, (size_t)20); ++pi) {
                auto &pin = insn[pi];
                std::string pmn = pin.mnemonic;
                if (pmn != "mov" && pmn != "movaps") continue;
                if (pin.detail->x86.op_count != 2) continue;
                auto &dst = pin.detail->x86.operands[0];
                auto &src = pin.detail->x86.operands[1];
                if (dst.type != X86_OP_REG || src.type != X86_OP_REG) continue;
                x86_reg dstR = canonReg(dst.reg);
                x86_reg srcR = canonReg(src.reg);
                auto pit = m_regParamRegs.find(dstR);
                if (pit == m_regParamRegs.end()) continue;
                if (sourcesHandled.count(srcR)) continue;
                sourcesHandled.insert(srcR);
                // Pre-bind the source register to the parameter
                auto *param = pit->second;
                int t = func.newTemp(param->typeRef);
                bb0.stmts.push_back(IRStmt::mkAssign(t,
                    IRExpr::mkVar(param->name, param->typeRef), param->typeRef));
                m_regTemps[srcR] = t;
            }
            // Also bind the regparam registers themselves (for direct use)
            for (auto &[xr, param] : m_regParamRegs) {
                if (m_regTemps.count(xr)) continue; // already bound via source
                int t = func.newTemp(param->typeRef);
                bb0.stmts.push_back(IRStmt::mkAssign(t,
                    IRExpr::mkVar(param->name, param->typeRef), param->typeRef));
                m_regTemps[xr] = t;
            }
        }

        int curBlock = 0;
        for (size_t i = 0; i < funcEndIdx; ++i) {
            auto &in = insn[i];
            // Check if this starts a new block
            auto bit = addrToBlock.find(in.address);
            if (bit != addrToBlock.end()) curBlock = bit->second;

            // Skip prologue instructions
            if (i < m_prologueEnd) continue;

            // Skip PIC thunk call + add
            if (m_hasPIC && in.address == m_picThunkAddr) { continue; }
            if (m_hasPIC && i > 0 && insn[i-1].address == m_picThunkAddr &&
                std::string(in.mnemonic) == "add") continue;

            // Skip epilogue
            std::string mn = in.mnemonic;
            if (mn == "leave") continue;
            if (mn == "pop" && in.detail && in.detail->x86.op_count == 1 &&
                in.detail->x86.operands[0].type == X86_OP_REG) {
                auto r = in.detail->x86.operands[0].reg;
                if (r == X86_REG_EBP || r == X86_REG_EBX ||
                    r == X86_REG_ESI || r == X86_REG_EDI) continue;
            }
            if (mn == "nop" || mn == "fnop") continue;

            {
                bool isRet = false;
                if (in.detail) {
                    for (uint8_t g = 0; g < in.detail->groups_count; ++g)
                        if (in.detail->groups[g] == CS_GRP_RET) isRet = true;
                }
                if (isRet) fprintf(stderr, "RET_INSN: mn='%s' addr=0x%llx\n",
                                   in.mnemonic, (unsigned long long)in.address);
            }
            liftInsn(in, func.blocks[curBlock], func, addrToBlock);
        }

        // ── Pass 5b: ensure float functions have proper return ───────
        // The ret instruction may fall outside STABS-reported function size.
        // If the last block has no Return and the function returns float/double,
        // synthesize one from the last FPU stack value.
        if (sfn && sfn->returnType != NullType && !func.blocks.empty()) {
            auto *rt = m_types.resolveType(sfn->returnType);
            fprintf(stderr, "PASS5B: rt=%p kind=%d fpuStack=%d lastFpuTop=%d\n",
                    (void*)rt, rt ? (int)rt->kind : -1, (int)m_fpuStack.size(), m_lastFpuTop);
            if (rt && (rt->kind == StabsTypeKind::Float ||
                       rt->kind == StabsTypeKind::Double ||
                       rt->kind == StabsTypeKind::LongDouble)) {
                // Check if any block has a Return statement
                bool hasReturn = false;
                for (auto &bb : func.blocks)
                    for (auto &s : bb.stmts)
                        if (s.kind == IRStmtKind::Return) { hasReturn = true; break; }
                fprintf(stderr, "PASS5B_FLOAT: hasReturn=%d\n", hasReturn);
                if (!hasReturn) {
                    auto &lastBB = func.blocks.back();
                    if (!m_fpuStack.empty()) {
                        lastBB.stmts.push_back(IRStmt::mkReturn(fpuRead(0)));
                    } else if (m_lastFpuTop >= 0) {
                        lastBB.stmts.push_back(IRStmt::mkReturn(
                            IRExpr::mkTemp(m_lastFpuTop, m_func->tempType(m_lastFpuTop))));
                    }
                }
            }
        }

        // ── Pass 6: merge duplicate SSE branches ─────────────────────
        // SSE float compares (ucomisd) emit jp + jne to same target.
        // Only merge when the second block has EXACTLY one Branch statement
        // AND no preceding comparison instruction changed the flags.
        // Disabled for now — the merge was incorrectly eating early-exit checks.
        // TODO: re-enable with proper SSE pattern detection (check for ucomis* flag source)


        // ── Pass 6b: CSE — eliminate duplicate Loads within each block ──
        // When the same memory address is loaded twice in the same block,
        // replace the second Load with a reference to the first temp.
        // This is critical for matching: the compiler uses the register
        // holding the first load, not a reload from memory.
        for (auto &bb : func.blocks) {
            // Map: (base_reg, offset) → temp that holds the loaded value
            std::map<std::pair<int,int>, int> loadedTemps;
            for (auto &stmt : bb.stmts) {
                if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0 && stmt.expr) {
                    auto *e = stmt.expr.get();
                    // Detect Load(Add(Temp(base), Const(off))) or Load(Field(Temp(base), off))
                    if (e->op == IROp::Load && !e->kids.empty()) {
                        auto *addr = e->kids[0].get();
                        int baseTemp = -1, offset = 0;
                        if (addr->op == IROp::Temp) {
                            baseTemp = addr->tempId();
                            offset = 0;
                        } else if (addr->op == IROp::Add && addr->kids.size() == 2 &&
                                   addr->kids[0]->op == IROp::Temp && addr->kids[1]->isConst()) {
                            baseTemp = addr->kids[0]->tempId();
                            offset = (int)addr->kids[1]->value;
                        }
                        if (baseTemp >= 0) {
                            auto key = std::make_pair(baseTemp, offset);
                            auto it = loadedTemps.find(key);
                            if (it != loadedTemps.end()) {
                                // Replace this Load with a reference to the existing temp
                                stmt.expr = IRExpr::mkTemp(it->second, func.tempType(it->second));
                            } else {
                                loadedTemps[key] = stmt.destTemp;
                            }
                        }
                    }
                }
                // Stores invalidate the CSE cache for the stored address
                if (stmt.kind == IRStmtKind::Store) {
                    loadedTemps.clear(); // conservative: clear all on any store
                }
            }
        }

        // ── Pass 7: wire up block edges ─────────────────────────────
        for (auto &bb : func.blocks) {
            if (bb.stmts.empty()) {
                // Empty block falls through to next
                if (bb.id + 1 < (int)func.blocks.size()) {
                    bb.succs.push_back(bb.id + 1);
                    func.blocks[bb.id + 1].preds.push_back(bb.id);
                }
                continue;
            }
            auto &last = bb.stmts.back();
            if (last.kind == IRStmtKind::Jump) {
                if (last.jumpTarget >= 0 && last.jumpTarget < (int)func.blocks.size()) {
                    bb.succs.push_back(last.jumpTarget);
                    func.blocks[last.jumpTarget].preds.push_back(bb.id);
                }
            } else if (last.kind == IRStmtKind::Branch) {
                if (last.trueTarget >= 0 && last.trueTarget < (int)func.blocks.size()) {
                    bb.succs.push_back(last.trueTarget);
                    func.blocks[last.trueTarget].preds.push_back(bb.id);
                }
                if (last.falseTarget >= 0 && last.falseTarget < (int)func.blocks.size()) {
                    bb.succs.push_back(last.falseTarget);
                    func.blocks[last.falseTarget].preds.push_back(bb.id);
                }
            } else if (last.kind == IRStmtKind::Switch) {
                // Add edges for all case targets and default
                std::set<int> added;
                for (auto &[caseVal, target] : last.switchCases) {
                    if (target >= 0 && target < (int)func.blocks.size() && !added.count(target)) {
                        bb.succs.push_back(target);
                        func.blocks[target].preds.push_back(bb.id);
                        added.insert(target);
                    }
                }
                if (last.switchDefault >= 0 && last.switchDefault < (int)func.blocks.size() &&
                    !added.count(last.switchDefault)) {
                    bb.succs.push_back(last.switchDefault);
                    func.blocks[last.switchDefault].preds.push_back(bb.id);
                }
            } else if (last.kind == IRStmtKind::Return) {
                // no successors
            } else {
                // falls through to next block
                if (bb.id + 1 < (int)func.blocks.size()) {
                    bb.succs.push_back(bb.id + 1);
                    func.blocks[bb.id + 1].preds.push_back(bb.id);
                }
            }
        }

        cs_free(insn, count);
        cs_close(&cs);
        return func;
    }

private:
    const MachOFile      &m_mf;
    const StabsTypeTable &m_types;
    IRFunc               *m_func = nullptr;
    csh                   m_cs;

    // Prologue/PIC state
    bool     m_hasFrame = false;
    int      m_frameSize = 0;
    size_t   m_prologueEnd = 0;
    bool     m_hasPIC = false;
    uint32_t m_picBase = 0;
    uint32_t m_picThunkAddr = 0;

    // Param/local lookup
    std::map<int, const StabsTypedVar*> m_paramByOffset;
    std::map<int, const StabsTypedVar*> m_localByOffset;
    std::map<x86_reg, const StabsTypedVar*> m_regParamRegs;  // register params (regparm)
    std::set<x86_reg> m_regParamInjected;  // which reg params we've already injected
    std::set<uint32_t> m_floatReturnAddrs;   // call target addresses known to return float
    std::set<uint32_t> m_floatRetCallSites;  // instruction addresses of float-returning calls

    // Register → temp mapping (current state)
    std::map<x86_reg, int> m_regTemps;

    // Flags state: which temp holds the flag result and what comparison produced it
    struct FlagsState {
        int   temp = -1;
        IROp  op   = IROp::Eq;
        std::unique_ptr<IRExpr> lhs, rhs;
    } m_flags;

    // Call argument collection
    std::map<int, std::unique_ptr<IRExpr>> m_espArgs;
    std::vector<std::unique_ptr<IRExpr>>   m_pushArgs;

    // FPU stack: tracks temp IDs for ST0..STn (index 0 = top of stack)
    std::vector<int> m_fpuStack;
    int m_lastFpuTop = -1;  // Last temp that was at ST0 before a pop (for float return heuristic)

    // Switch table info collected in Pass 1
    struct SwitchInfo {
        uint32_t instrAddr = 0;       // address of the jmp instruction
        uint32_t tableAddr = 0;       // address of the jump table
        int numCases = 0;             // number of entries
        int switchBase = 0;           // value subtracted before indexing
        uint32_t defaultAddr = 0;     // default case target
        std::vector<uint32_t> targets; // resolved target addresses
    };
    std::map<uint32_t, SwitchInfo> m_switchTables;

    // ── Register helpers ────────────────────────────────────────────
    int regTemp(x86_reg reg) {
        auto it = m_regTemps.find(canonReg(reg));
        if (it != m_regTemps.end()) return it->second;
        return -1;
    }

    std::unique_ptr<IRExpr> readReg(x86_reg reg) {
        // Route ST registers through FPU stack
        if (reg >= X86_REG_ST0 && reg <= X86_REG_ST7) {
            int idx = (int)(reg - X86_REG_ST0);
            if (idx < (int)m_fpuStack.size()) {
                int t = m_fpuStack[idx];
                return IRExpr::mkTemp(t, m_func->tempType(t));
            }
        }
        x86_reg canon = canonReg(reg);
        int t = regTemp(reg);
        if (t >= 0) return IRExpr::mkTemp(t, m_func->tempType(t));
        // No temp for this register — create one initialized to 0
        // This avoids raw register names leaking into decompiled C
        int newT = m_func->newTemp();
        m_regTemps[canon] = newT;
        return IRExpr::mkTemp(newT);
    }

    void writeReg(x86_reg reg, int temp, BasicBlock &bb) {
        m_regTemps[canonReg(reg)] = temp;
    }

    void assignReg(x86_reg reg, std::unique_ptr<IRExpr> val, BasicBlock &bb, TypeRef t = NullType) {
        int temp = m_func->newTemp(t);
        bb.stmts.push_back(IRStmt::mkAssign(temp, std::move(val), t));
        writeReg(reg, temp, bb);
    }

    // ── FPU stack helpers ──────────────────────────────────────────────
    // Sync m_regTemps for ST0..ST7 from the FPU stack state
    void fpuSyncRegs() {
        for (int i = 0; i < 8; ++i) {
            x86_reg sr = (x86_reg)(X86_REG_ST0 + i);
            if (i < (int)m_fpuStack.size())
                m_regTemps[sr] = m_fpuStack[i];
            else
                m_regTemps.erase(sr);
        }
    }

    // Push a new temp onto the FPU stack
    void fpuPush(std::unique_ptr<IRExpr> val, BasicBlock &bb) {
        int temp = m_func->newTemp();
        bb.stmts.push_back(IRStmt::mkAssign(temp, std::move(val)));
        m_fpuStack.insert(m_fpuStack.begin(), temp);
        if (m_fpuStack.size() > 8) m_fpuStack.resize(8);
        fpuSyncRegs();
    }

    // Pop the FPU stack top, return temp ID (-1 if empty)
    int fpuPop() {
        if (m_fpuStack.empty()) return regTemp(X86_REG_ST0);
        int t = m_fpuStack[0];
        m_lastFpuTop = t;  // Remember last ST0 for float return heuristic
        m_fpuStack.erase(m_fpuStack.begin());
        fpuSyncRegs();
        return t;
    }

    // Read FPU stack at position (0 = ST0, 1 = ST1, ...)
    std::unique_ptr<IRExpr> fpuRead(int pos) {
        if (pos >= 0 && pos < (int)m_fpuStack.size()) {
            int t = m_fpuStack[pos];
            return IRExpr::mkTemp(t, m_func->tempType(t));
        }
        // Fall back to register-based read for empty stack positions
        x86_reg sr = (x86_reg)(X86_REG_ST0 + pos);
        return readReg(sr);
    }

    // Write result to FPU stack position
    void fpuWrite(int pos, std::unique_ptr<IRExpr> val, BasicBlock &bb) {
        int temp = m_func->newTemp();
        bb.stmts.push_back(IRStmt::mkAssign(temp, std::move(val)));
        if (pos < (int)m_fpuStack.size()) {
            m_fpuStack[pos] = temp;
        } else {
            // Stack not deep enough — extend
            while ((int)m_fpuStack.size() <= pos)
                m_fpuStack.push_back(m_func->newTemp());
            m_fpuStack[pos] = temp;
        }
        fpuSyncRegs();
    }

    // Map capstone ST register to stack index
    int stRegIndex(x86_reg r) {
        if (r >= X86_REG_ST0 && r <= X86_REG_ST7) return (int)(r - X86_REG_ST0);
        return 0;
    }

    // Convert STABS register number to Capstone x86_reg
    // STABS: 0=eax, 1=ecx, 2=edx, 3=ebx, 4=esp, 5=ebp, 6=esi, 7=edi
    //        12-19=st0-st7, 21-28=xmm0-xmm7
    static x86_reg stabsRegToX86(int stabsReg) {
        switch (stabsReg) {
        case 0: return X86_REG_EAX;
        case 1: return X86_REG_ECX;
        case 2: return X86_REG_EDX;
        case 3: return X86_REG_EBX;
        case 4: return X86_REG_ESP;
        case 5: return X86_REG_EBP;
        case 6: return X86_REG_ESI;
        case 7: return X86_REG_EDI;
        case 21: return X86_REG_XMM0;
        case 22: return X86_REG_XMM1;
        case 23: return X86_REG_XMM2;
        case 24: return X86_REG_XMM3;
        case 25: return X86_REG_XMM4;
        case 26: return X86_REG_XMM5;
        case 27: return X86_REG_XMM6;
        case 28: return X86_REG_XMM7;
        default: return X86_REG_INVALID;
        }
    }

    // Normalize sub-registers to their 32-bit parent
    static x86_reg canonReg(x86_reg r) {
        switch (r) {
        case X86_REG_AL: case X86_REG_AH: case X86_REG_AX: return X86_REG_EAX;
        case X86_REG_BL: case X86_REG_BH: case X86_REG_BX: return X86_REG_EBX;
        case X86_REG_CL: case X86_REG_CH: case X86_REG_CX: return X86_REG_ECX;
        case X86_REG_DL: case X86_REG_DH: case X86_REG_DX: return X86_REG_EDX;
        case X86_REG_SI: return X86_REG_ESI;
        case X86_REG_DI: return X86_REG_EDI;
        case X86_REG_SP: return X86_REG_ESP;
        case X86_REG_BP: return X86_REG_EBP;
        default: return r;
        }
    }

    // ── Operand reading ─────────────────────────────────────────────

    std::unique_ptr<IRExpr> readOp(cs_x86_op &op) {
        switch (op.type) {
        case X86_OP_REG: return readReg(op.reg);
        case X86_OP_IMM: return readImm(op.imm);
        case X86_OP_MEM: return readMem(op.mem);
        default: return IRExpr::mkConst(0);
        }
    }

    std::unique_ptr<IRExpr> readImm(int64_t imm) {
        uint32_t v = (uint32_t)imm;
        // String literal?
        std::string s = tryString(v);
        if (!s.empty()) return IRExpr::mkString(s);
        // Global variable (from STABS)?
        auto *g = m_types.globalAtAddress(v);
        if (g) return IRExpr::mkVar(g->name, g->typeRef);
        // Don't resolve function addresses here — they'd be misidentified as data.
        // Function refs are handled in the 'call' and 'lea' instruction handlers.
        return IRExpr::mkConst(imm);
    }

    std::unique_ptr<IRExpr> readMem(x86_op_mem &m) {
        // EBP-relative: param or local
        if (m.base == X86_REG_EBP && m.index == X86_REG_INVALID) {
            int d = (int)m.disp;
            if (d > 0) {
                auto it = m_paramByOffset.find(d);
                if (it != m_paramByOffset.end())
                    return IRExpr::mkVar(it->second->name, it->second->typeRef);
            }
            if (d < 0) {
                auto it = m_localByOffset.find(d);
                if (it != m_localByOffset.end())
                    return IRExpr::mkVar(it->second->name, it->second->typeRef);
                // Check if offset falls within an array local
                for (auto &[off, loc] : m_localByOffset) {
                    if (off > d) continue;
                    auto *lt = m_types.resolveType(loc->typeRef);
                    if (lt && lt->kind == StabsTypeKind::Array) {
                        int arrSz = lt->sizeBytes;
                        if (arrSz <= 0 && lt->arrayHigh >= lt->arrayLow) {
                            auto *et = m_types.resolveType(lt->targetType);
                            arrSz = (lt->arrayHigh - lt->arrayLow + 1) * (et && et->sizeBytes > 0 ? et->sizeBytes : 4);
                        }
                        if (arrSz <= 0) arrSz = 64;
                        int elemSz = 4;
                        { auto *et = m_types.resolveType(lt->targetType); if (et && et->sizeBytes > 0) elemSz = et->sizeBytes; }
                        int arrayEnd = off + arrSz;
                        if (d >= off && d < arrayEnd) {
                            int idx = (d - off) / elemSz;
                            char idxBuf[64];
                            snprintf(idxBuf, sizeof(idxBuf), "%s[%d]", loc->name.c_str(), idx);
                            return IRExpr::mkVar(idxBuf, lt->targetType);
                        }
                    }
                }
            }
            // Unnamed stack slot
            char buf[32];
            if (d > 0) snprintf(buf, sizeof(buf), "arg_%x", (d - 8) / 4);
            else snprintf(buf, sizeof(buf), "var_%x", (-d) / 4);
            return IRExpr::mkVar(buf);
        }

        // PIC-relative (EBX + disp)
        if (m_hasPIC && m.base == X86_REG_EBX && m.index == X86_REG_INVALID && m_picBase) {
            uint32_t addr = m_picBase + (int)m.disp;
            auto *g = m_types.globalAtAddress(addr);
            if (g) return IRExpr::mkVar(g->name, g->typeRef);
            std::string s = tryString(addr);
            if (!s.empty()) return IRExpr::mkString(s);
            auto fit = m_mf.functionMap().find(addr);
            if (fit != m_mf.functionMap().end())
                return IRExpr::mkAddrOf(IRExpr::mkFunc(fit->second));
            { std::string sn = m_mf.symbolNameAtAddress(addr);
              if (!sn.empty()) return IRExpr::mkVar(sn); }
            const Section *dSec = m_mf.sectionForAddress(addr);
            if (dSec && (dSec->segname == "__DATA" || dSec->segname == "__IMPORT")) {
                char gn[32]; snprintf(gn, sizeof(gn), "g_%X", addr);
                return IRExpr::mkVar(gn);
            }
            return IRExpr::mkLoad(IRExpr::mkConst(addr));
        }

        // ESP-relative: suppress (call arg collection handles these)
        if (m.base == X86_REG_ESP && m.index == X86_REG_INVALID)
            return nullptr;

        // Struct field access: [base + disp] where base holds a struct pointer
        if (m.base != X86_REG_INVALID && m.index == X86_REG_INVALID) {
            auto base = readReg(m.base);
            TypeRef baseType = NullType;
            int bt = regTemp(m.base);
            if (bt >= 0) baseType = m_func->tempType(bt);

            // Try struct field resolution with array subscript support
            if (baseType != NullType && m_types.isStructPointer(baseType)) {
                TypeRef structRef = m_types.getPointedStruct(baseType);
                if (structRef != NullType) {
                    std::string access = m_types.formatFieldAccess(structRef, (int)m.disp);
                    if (!access.empty()) {
                        auto *field = m_types.findFieldAtOffset(structRef, (int)m.disp);
                        TypeRef ft = field ? field->typeRef : NullType;
                        // Annotate the base with the struct pointer type for type inference
                        base->typeRef = baseType;
                        return IRExpr::mkField(std::move(base), access, (int)m.disp, ft);
                    }
                }
            }
            // If we have a displacement but no struct type, use pointer arithmetic
            if (m.disp != 0) {
                // Only use ->field notation for positive offsets on pointer types
                if ((int)m.disp > 0 && baseType != NullType) {
                    auto *resolved = m_types.resolveType(baseType);
                    if (resolved && resolved->kind == StabsTypeKind::Pointer) {
                        // Annotate base with pointer type
                        base->typeRef = baseType;
                        char fname[32]; snprintf(fname, sizeof(fname), "field_%X", (unsigned)(int)m.disp);
                        return IRExpr::mkField(std::move(base), fname, (int)m.disp);
                    }
                }
                return IRExpr::mkLoad(IRExpr::mkBinary(IROp::Add, std::move(base), IRExpr::mkConst(m.disp)));
            }
            return IRExpr::mkLoad(std::move(base));
        }

        // Direct address: [disp]
        if (m.base == X86_REG_INVALID && m.index == X86_REG_INVALID && m.disp) {
            uint32_t addr = (uint32_t)m.disp;
            auto *g = m_types.globalAtAddress(addr);
            if (g) return IRExpr::mkVar(g->name, g->typeRef);
            // Check function map for import pointers
            auto fit = m_mf.functionMap().find(addr);
            if (fit != m_mf.functionMap().end())
                return IRExpr::mkVar(fit->second);
            std::string s = tryString(addr);
            if (!s.empty()) return IRExpr::mkString(s);
            // Try nlist symbol table for named globals
            std::string symName = m_mf.symbolNameAtAddress(addr);
            if (!symName.empty()) return IRExpr::mkVar(symName);
            // For addresses in data sections, use a synthetic global name
            const Section *dataSec = m_mf.sectionForAddress(addr);
            if (dataSec && (dataSec->segname == "__DATA" || dataSec->segname == "__IMPORT")) {
                char gname[32]; snprintf(gname, sizeof(gname), "g_%X", addr);
                return IRExpr::mkVar(gname);
            }
            return IRExpr::mkLoad(IRExpr::mkConst(addr));
        }

        // General: base + index*scale + disp
        std::unique_ptr<IRExpr> addr;
        if (m.base != X86_REG_INVALID) addr = readReg(m.base);
        if (m.index != X86_REG_INVALID) {
            auto idx = readReg(m.index);
            if (m.scale > 1)
                idx = IRExpr::mkBinary(IROp::Mul, std::move(idx), IRExpr::mkConst(m.scale));
            addr = addr ? IRExpr::mkBinary(IROp::Add, std::move(addr), std::move(idx)) : std::move(idx);
        }
        if (m.disp) {
            auto d = IRExpr::mkConst(m.disp);
            addr = addr ? IRExpr::mkBinary(IROp::Add, std::move(addr), std::move(d)) : std::move(d);
        }
        if (!addr) addr = IRExpr::mkConst(0);
        return IRExpr::mkLoad(std::move(addr));
    }

    // Write to a memory destination
    void writeMem(x86_op_mem &m, std::unique_ptr<IRExpr> val, BasicBlock &bb) {
        // EBP-relative
        if (m.base == X86_REG_EBP && m.index == X86_REG_INVALID) {
            int d = (int)m.disp;
            if (d > 0) {
                auto it = m_paramByOffset.find(d);
                if (it != m_paramByOffset.end()) {
                    bb.stmts.push_back(IRStmt::mkVarSet(it->second->name, std::move(val), it->second->typeRef));
                    return;
                }
            }
            if (d < 0) {
                auto it = m_localByOffset.find(d);
                if (it != m_localByOffset.end()) {
                    bb.stmts.push_back(IRStmt::mkVarSet(it->second->name, std::move(val), it->second->typeRef));
                    return;
                }
                // Check if offset falls within an array local
                for (auto &[off, loc] : m_localByOffset) {
                    if (off > d) continue;
                    auto *lt = m_types.resolveType(loc->typeRef);
                    if (lt && lt->kind == StabsTypeKind::Array) {
                        int arrSz = lt->sizeBytes;
                        if (arrSz <= 0 && lt->arrayHigh >= lt->arrayLow) {
                            auto *et = m_types.resolveType(lt->targetType);
                            arrSz = (lt->arrayHigh - lt->arrayLow + 1) * (et && et->sizeBytes > 0 ? et->sizeBytes : 4);
                        }
                        if (arrSz <= 0) arrSz = 64;
                        int elemSz = 4;
                        { auto *et = m_types.resolveType(lt->targetType); if (et && et->sizeBytes > 0) elemSz = et->sizeBytes; }
                        int arrayEnd = off + arrSz;
                        if (d >= off && d < arrayEnd) {
                            int idx = (d - off) / elemSz;
                            char idxBuf[64];
                            snprintf(idxBuf, sizeof(idxBuf), "%s[%d]", loc->name.c_str(), idx);
                            bb.stmts.push_back(IRStmt::mkVarSet(idxBuf, std::move(val), lt->targetType));
                            return;
                        }
                    }
                }
            }
            char buf[32];
            if (d > 0) snprintf(buf, sizeof(buf), "arg_%x", (d - 8) / 4);
            else snprintf(buf, sizeof(buf), "var_%x", (-d) / 4);
            bb.stmts.push_back(IRStmt::mkVarSet(buf, std::move(val)));
            return;
        }
        // Struct field write (including offset 0)
        if (m.base != X86_REG_INVALID && m.index == X86_REG_INVALID) {
            auto base = readReg(m.base);
            TypeRef baseType = NullType;
            int bt = regTemp(m.base);
            if (bt >= 0) baseType = m_func->tempType(bt);
            if (baseType != NullType && m_types.isStructPointer(baseType)) {
                TypeRef structRef = m_types.getPointedStruct(baseType);
                if (structRef != NullType) {
                    std::string access = m_types.formatFieldAccess(structRef, (int)m.disp);
                    if (!access.empty()) {
                        auto *field = m_types.findFieldAtOffset(structRef, (int)m.disp);
                        TypeRef ft = field ? field->typeRef : NullType;
                        auto fld = IRExpr::mkField(std::move(base), access, (int)m.disp, ft);
                        bb.stmts.push_back(IRStmt::mkStore(std::move(fld), std::move(val)));
                        return;
                    }
                }
            }
        }
        // Direct address store: [disp] with no base/index
        if (m.base == X86_REG_INVALID && m.index == X86_REG_INVALID && m.disp) {
            uint32_t addr = (uint32_t)m.disp;
            auto *g = m_types.globalAtAddress(addr);
            if (g) {
                bb.stmts.push_back(IRStmt::mkVarSet(g->name, std::move(val), g->typeRef));
                return;
            }
            // Try nlist symbol table
            std::string symName = m_mf.symbolNameAtAddress(addr);
            if (!symName.empty()) {
                bb.stmts.push_back(IRStmt::mkVarSet(symName, std::move(val)));
                return;
            }
            // Synthetic global name for data section addresses
            const Section *dSec = m_mf.sectionForAddress(addr);
            if (dSec && (dSec->segname == "__DATA" || dSec->segname == "__IMPORT")) {
                char gn[32]; snprintf(gn, sizeof(gn), "g_%X", addr);
                bb.stmts.push_back(IRStmt::mkVarSet(gn, std::move(val)));
                return;
            }
        }
        // General store
        auto addr = readMem_addr(m);
        if (addr)
            bb.stmts.push_back(IRStmt::mkStore(std::move(addr), std::move(val)));
    }

    // Get the address expression for a memory operand (without loading)
    std::unique_ptr<IRExpr> readMem_addr(x86_op_mem &m) {
        std::unique_ptr<IRExpr> addr;
        if (m.base != X86_REG_INVALID) addr = readReg(m.base);
        if (m.index != X86_REG_INVALID) {
            auto idx = readReg(m.index);
            if (m.scale > 1)
                idx = IRExpr::mkBinary(IROp::Mul, std::move(idx), IRExpr::mkConst(m.scale));
            addr = addr ? IRExpr::mkBinary(IROp::Add, std::move(addr), std::move(idx)) : std::move(idx);
        }
        if (m.disp) {
            auto d = IRExpr::mkConst(m.disp);
            addr = addr ? IRExpr::mkBinary(IROp::Add, std::move(addr), std::move(d)) : std::move(d);
        }
        return addr;
    }

    // ── Write to an operand destination ─────────────────────────────
    void writeOp(cs_x86_op &op, std::unique_ptr<IRExpr> val, BasicBlock &bb, TypeRef t = NullType) {
        if (op.type == X86_OP_REG) {
            assignReg(op.reg, std::move(val), bb, t);
        } else if (op.type == X86_OP_MEM) {
            // Preserve byte-width stores for matching
            if (op.size == 1)
                val = IRExpr::mkCast(CastKind::Trunc8, std::move(val));
            else if (op.size == 2)
                val = IRExpr::mkCast(CastKind::Trunc16, std::move(val));
            writeMem(op.mem, std::move(val), bb);
        }
    }

    // ── String resolution ───────────────────────────────────────────
    std::string tryString(uint32_t addr) const {
        int64_t off = m_mf.fileOffsetForAddress(addr);
        if (off < 0) return "";
        const Section *sec = m_mf.sectionForAddress(addr);
        if (!sec || (sec->sectname != "__cstring" && sec->sectname != "__const")) return "";
        const uint8_t *p = m_mf.bytesAt(off, std::min((uint32_t)80, (uint32_t)(m_mf.size() - off)));
        if (!p) return "";
        std::string s;
        for (int i = 0; i < 72 && p[i]; ++i) {
            if (p[i] >= 0x20 && p[i] < 0x7F) {
                if (p[i] == '"') s += "\\\"";
                else if (p[i] == '\\') s += "\\\\";
                else s += (char)p[i];
            } else { char b[8]; snprintf(b, 8, "\\x%02X", p[i]); s += b; }
        }
        return s.empty() ? "" : "\"" + s + "\"";
    }

    // ── Build a comparison expression from flags state ───────────────
    std::unique_ptr<IRExpr> buildCondition(const std::string &jmn) {
        if (!m_flags.lhs) return IRExpr::mkConst(1);
        auto lhs = m_flags.lhs->clone();
        auto rhs = m_flags.rhs ? m_flags.rhs->clone() : IRExpr::mkConst(0);

        // test X, X → compare X with 0
        bool isTest = (m_flags.op == IROp::And);

        IROp cmpOp;
        if (isTest && lhs->op == rhs->op && lhs->op == IROp::Temp &&
            lhs->value == rhs->value) {
            // test reg, reg → flags based on reg value
            rhs = IRExpr::mkConst(0);
            if      (jmn == "je"  || jmn == "jz")  cmpOp = IROp::Eq;
            else if (jmn == "jne" || jmn == "jnz") cmpOp = IROp::Ne;
            else if (jmn == "js")                   cmpOp = IROp::Slt;
            else if (jmn == "jns")                  cmpOp = IROp::Sge;
            else cmpOp = IROp::Ne;
        } else if (isTest) {
            // test with different operands: condition is (lhs & rhs) vs 0
            auto andExpr = IRExpr::mkBinary(IROp::And, std::move(lhs), std::move(rhs));
            lhs = std::move(andExpr);
            rhs = IRExpr::mkConst(0);
            if      (jmn == "je"  || jmn == "jz")  cmpOp = IROp::Eq;
            else if (jmn == "jne" || jmn == "jnz") cmpOp = IROp::Ne;
            else if (jmn == "js")                   cmpOp = IROp::Slt;
            else if (jmn == "jns")                  cmpOp = IROp::Sge;
            else cmpOp = IROp::Ne;
        } else {
            // cmp or sub-based flags
            if      (jmn == "je"  || jmn == "jz")  cmpOp = IROp::Eq;
            else if (jmn == "jne" || jmn == "jnz") cmpOp = IROp::Ne;
            else if (jmn == "jl"  || jmn == "jnge") cmpOp = IROp::Slt;
            else if (jmn == "jle" || jmn == "jng")  cmpOp = IROp::Sle;
            else if (jmn == "jg"  || jmn == "jnle") cmpOp = IROp::Sgt;
            else if (jmn == "jge" || jmn == "jnl")  cmpOp = IROp::Sge;
            else if (jmn == "jb"  || jmn == "jnae") cmpOp = IROp::Ult;
            else if (jmn == "jbe" || jmn == "jna")  cmpOp = IROp::Ule;
            else if (jmn == "ja"  || jmn == "jnbe") cmpOp = IROp::Ugt;
            else if (jmn == "jae" || jmn == "jnb")  cmpOp = IROp::Uge;
            else if (jmn == "js")                    cmpOp = IROp::Slt;
            else if (jmn == "jns")                   cmpOp = IROp::Sge;
            else cmpOp = IROp::Ne;
        }
        return IRExpr::mkBinary(cmpOp, std::move(lhs), std::move(rhs));
    }

    // ── Main instruction lifter ─────────────────────────────────────
    void liftInsn(cs_insn &in, BasicBlock &bb, IRFunc &func,
                  const std::map<uint32_t, int> &addrToBlock) {
        std::string mn = in.mnemonic;
        cs_detail *d = in.detail;
        if (!d) return;
        auto &ops = d->x86;
        auto *o = ops.operands;
        int n = ops.op_count;

        // ── Data movement ───────────────────────────────────────────
        if (mn == "mov" && n == 2) {
            if (o[0].type == X86_OP_MEM && o[0].mem.base == X86_REG_ESP &&
                o[0].mem.index == X86_REG_INVALID) {
                // mov [esp+N], src → collect as call arg
                auto val = readOp(o[1]);
                if (val) m_espArgs[(int)o[0].mem.disp] = std::move(val);
                return;
            }
            auto src = readOp(o[1]);
            if (!src) return;
            TypeRef t = src->typeRef;
            writeOp(o[0], std::move(src), bb, t);
            return;
        }
        if (mn == "lea" && n == 2) {
            // LEA: compute address, don't load
            auto addr = readMem_addr(o[1].mem);
            if (!addr) addr = IRExpr::mkConst(0);

            // Check if this is just loading address of a stack var
            if (o[1].mem.base == X86_REG_EBP && o[1].mem.index == X86_REG_INVALID) {
                int disp = (int)o[1].mem.disp;
                if (disp > 0) {
                    auto it = m_paramByOffset.find(disp);
                    if (it != m_paramByOffset.end())
                        addr = IRExpr::mkAddrOf(IRExpr::mkVar(it->second->name, it->second->typeRef));
                    else {
                        char buf[32]; snprintf(buf, sizeof(buf), "arg_%x", (disp - 8) / 4);
                        addr = IRExpr::mkAddrOf(IRExpr::mkVar(buf));
                    }
                }
                if (disp < 0) {
                    auto it = m_localByOffset.find(disp);
                    if (it != m_localByOffset.end())
                        addr = IRExpr::mkAddrOf(IRExpr::mkVar(it->second->name, it->second->typeRef));
                    else {
                        char buf[32]; snprintf(buf, sizeof(buf), "var_%x", (-disp) / 4);
                        addr = IRExpr::mkAddrOf(IRExpr::mkVar(buf));
                    }
                }
            }
            // PIC-relative LEA
            if (m_hasPIC && o[1].mem.base == X86_REG_EBX &&
                o[1].mem.index == X86_REG_INVALID && m_picBase) {
                uint32_t target = m_picBase + (int)o[1].mem.disp;
                auto *g = m_types.globalAtAddress(target);
                if (g) addr = IRExpr::mkAddrOf(IRExpr::mkVar(g->name, g->typeRef));
                else {
                    std::string s = tryString(target);
                    if (!s.empty()) addr = IRExpr::mkString(s);
                    else {
                        auto fit = m_mf.functionMap().find(target);
                        if (fit != m_mf.functionMap().end())
                            addr = IRExpr::mkFunc(fit->second);
                        else
                            addr = IRExpr::mkConst(target);
                    }
                }
            }
            writeOp(o[0], std::move(addr), bb);
            return;
        }
        if (mn == "movzx" && n == 2) {
            auto src = readOp(o[1]);
            if (!src) return;
            CastKind ck = (o[1].size == 1) ? CastKind::ZeroExt8 : CastKind::ZeroExt16;
            writeOp(o[0], IRExpr::mkCast(ck, std::move(src)), bb);
            return;
        }
        if (mn == "movsx" && n == 2) {
            auto src = readOp(o[1]);
            if (!src) return;
            CastKind ck = (o[1].size == 1) ? CastKind::SignExt8 : CastKind::SignExt16;
            writeOp(o[0], IRExpr::mkCast(ck, std::move(src)), bb);
            return;
        }
        if (mn == "xchg" && n == 2) {
            auto a = readOp(o[0]);
            auto b = readOp(o[1]);
            if (a && b) {
                writeOp(o[0], std::move(b), bb);
                writeOp(o[1], std::move(a), bb);
            }
            return;
        }
        if (mn == "bswap" && n == 1) {
            auto v = readOp(o[0]);
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(v->clone());
            writeOp(o[0], IRExpr::mkCall("__builtin_bswap32", std::move(args)), bb);
            return;
        }
        if (mn == "cdq") {
            // sign-extend EAX into EDX:EAX — we model EDX = (EAX >> 31)
            auto eax = readReg(X86_REG_EAX);
            assignReg(X86_REG_EDX,
                IRExpr::mkBinary(IROp::Sar, std::move(eax), IRExpr::mkConst(31)), bb);
            return;
        }
        if (mn == "cwde") {
            auto ax = readReg(X86_REG_EAX);
            assignReg(X86_REG_EAX, IRExpr::mkCast(CastKind::SignExt16, std::move(ax)), bb);
            return;
        }
        if (mn == "cbw") {
            auto al = readReg(X86_REG_EAX);
            assignReg(X86_REG_EAX, IRExpr::mkCast(CastKind::SignExt8, std::move(al)), bb);
            return;
        }

        // ── Conditional moves ───────────────────────────────────────
        if (mn.substr(0, 4) == "cmov" && n == 2) {
            std::string cc = mn.substr(4);
            auto cond = buildCondition("j" + cc);
            auto src = readOp(o[1]);
            auto dst = readOp(o[0]);
            if (src && dst)
                writeOp(o[0], IRExpr::mkTernary(std::move(cond), std::move(src), std::move(dst)), bb);
            return;
        }

        // ── Conditional set ─────────────────────────────────────────
        if (mn.substr(0, 3) == "set" && n == 1) {
            std::string cc = mn.substr(3);
            auto cond = buildCondition("j" + cc);
            writeOp(o[0], std::move(cond), bb);
            return;
        }

        // ── Push: collect as call arg ───────────────────────────────
        if (mn == "push" && n == 1) {
            auto val = readOp(o[0]);
            if (val) m_pushArgs.push_back(std::move(val));
            return;
        }
        // Pop (non-epilogue) — rare, just model as a var read
        if (mn == "pop" && n == 1) {
            writeOp(o[0], IRExpr::mkVar("__stack_pop"), bb);
            return;
        }

        // ── Arithmetic ──────────────────────────────────────────────
        if ((mn == "add" || mn == "sub" || mn == "or" || mn == "and" ||
             mn == "xor" || mn == "shl" || mn == "shr" || mn == "sar") && n == 2) {
            // Skip ESP adjustments
            if (o[0].type == X86_OP_REG && canonReg(o[0].reg) == X86_REG_ESP) return;
            // xor reg, reg → zero
            if (mn == "xor" && o[0].type == X86_OP_REG && o[1].type == X86_OP_REG &&
                canonReg(o[0].reg) == canonReg(o[1].reg)) {
                writeOp(o[0], IRExpr::mkConst(0), bb);
                return;
            }
            IROp irop;
            if      (mn == "add") irop = IROp::Add;
            else if (mn == "sub") irop = IROp::Sub;
            else if (mn == "or")  irop = IROp::Or;
            else if (mn == "and") irop = IROp::And;
            else if (mn == "xor") irop = IROp::Xor;
            else if (mn == "shl") irop = IROp::Shl;
            else if (mn == "shr") irop = IROp::Shr;
            else                  irop = IROp::Sar;

            auto lhs = readOp(o[0]);
            auto rhs = readOp(o[1]);
            if (lhs && rhs) {
                auto res = IRExpr::mkBinary(irop, std::move(lhs), std::move(rhs));
                writeOp(o[0], std::move(res), bb);
            }
            return;
        }
        if (mn == "inc" && n == 1) {
            auto v = readOp(o[0]);
            if (v) writeOp(o[0], IRExpr::mkBinary(IROp::Add, std::move(v), IRExpr::mkConst(1)), bb);
            return;
        }
        if (mn == "dec" && n == 1) {
            auto v = readOp(o[0]);
            if (v) writeOp(o[0], IRExpr::mkBinary(IROp::Sub, std::move(v), IRExpr::mkConst(1)), bb);
            return;
        }
        if (mn == "neg" && n == 1) {
            auto v = readOp(o[0]);
            if (v) writeOp(o[0], IRExpr::mkUnary(IROp::Neg, std::move(v)), bb);
            return;
        }
        if (mn == "not" && n == 1) {
            auto v = readOp(o[0]);
            if (v) writeOp(o[0], IRExpr::mkUnary(IROp::Not, std::move(v)), bb);
            return;
        }
        if (mn == "imul") {
            if (n == 1) {
                // imul r/m32 → EDX:EAX = EAX * r/m32
                auto src = readOp(o[0]);
                auto eax = readReg(X86_REG_EAX);
                assignReg(X86_REG_EAX, IRExpr::mkBinary(IROp::Mul, std::move(eax), std::move(src)), bb);
                return;
            }
            if (n == 2) {
                auto a = readOp(o[0]); auto b = readOp(o[1]);
                if (a && b) writeOp(o[0], IRExpr::mkBinary(IROp::Mul, std::move(a), std::move(b)), bb);
                return;
            }
            if (n == 3) {
                auto a = readOp(o[1]); auto b = readOp(o[2]);
                if (a && b) writeOp(o[0], IRExpr::mkBinary(IROp::Mul, std::move(a), std::move(b)), bb);
                return;
            }
            return;
        }
        if (mn == "mul" && n == 1) {
            auto src = readOp(o[0]);
            auto eax = readReg(X86_REG_EAX);
            assignReg(X86_REG_EAX, IRExpr::mkBinary(IROp::Mul, std::move(eax), std::move(src)), bb);
            return;
        }
        if ((mn == "div" || mn == "idiv") && n == 1) {
            auto src = readOp(o[0]);
            auto eax = readReg(X86_REG_EAX);
            IROp divOp = (mn == "div") ? IROp::UDiv : IROp::SDiv;
            IROp modOp = (mn == "div") ? IROp::UMod : IROp::SMod;
            assignReg(X86_REG_EDX, IRExpr::mkBinary(modOp, eax->clone(), src->clone()), bb);
            assignReg(X86_REG_EAX, IRExpr::mkBinary(divOp, std::move(eax), std::move(src)), bb);
            return;
        }

        // ── SBB / ADC idioms ─────────────────────────────────────────
        // sbb reg, reg → reg = -(CF) → reg = (prev_cmp < 0 unsigned) ? -1 : 0
        if (mn == "sbb" && n == 2 && o[0].type == X86_OP_REG && o[1].type == X86_OP_REG &&
            canonReg(o[0].reg) == canonReg(o[1].reg)) {
            if (m_flags.lhs) {
                // CF=1 when lhs < rhs (unsigned) → sbb reg,reg = -(lhs < rhs) = (lhs < rhs) ? -1 : 0
                auto cond = IRExpr::mkBinary(IROp::Ult, m_flags.lhs->clone(),
                    m_flags.rhs ? m_flags.rhs->clone() : IRExpr::mkConst(0));
                writeOp(o[0], IRExpr::mkUnary(IROp::Neg, std::move(cond)), bb);
            } else {
                writeOp(o[0], IRExpr::mkConst(0), bb);
            }
            return;
        }
        // General sbb: 64-bit subtract high word.
        // sub lo, X; sbb hi, Y produces hi:lo = (hi:lo) - (Y:X).
        // Emit as a simple subtract — the full 64-bit result is consumed
        // by later patterns (push hi; push lo; fild qword [esp]).
        if (mn == "sbb" && n == 2) {
            auto dst = readOp(o[0]);
            auto src = readOp(o[1]);
            if (dst && src)
                writeOp(o[0], IRExpr::mkBinary(IROp::Sub, std::move(dst), std::move(src)), bb);
            return;
        }
        // adc reg, 0 → reg = reg + CF → reg = reg + (prev_cmp < 0 unsigned)
        if (mn == "adc" && n == 2 && o[1].type == X86_OP_IMM && o[1].imm == 0) {
            if (m_flags.lhs) {
                auto carry = IRExpr::mkBinary(IROp::Ult, m_flags.lhs->clone(),
                    m_flags.rhs ? m_flags.rhs->clone() : IRExpr::mkConst(0));
                auto reg = readOp(o[0]);
                if (reg)
                    writeOp(o[0], IRExpr::mkBinary(IROp::Add, std::move(reg), std::move(carry)), bb);
            }
            return;
        }

        // ── Comparison / test (set flags) ───────────────────────────
        if (mn == "cmp" && n == 2) {
            m_flags.lhs = readOp(o[0]);
            m_flags.rhs = readOp(o[1]);
            // Preserve byte-width for correct comparison codegen (memory operands only)
            if (o[0].type == X86_OP_MEM && o[0].size == 1 && m_flags.lhs)
                m_flags.lhs = IRExpr::mkCast(CastKind::Trunc8, std::move(m_flags.lhs));
            m_flags.op = IROp::Sub;
            return;
        }
        if (mn == "test" && n == 2) {
            m_flags.lhs = readOp(o[0]);
            m_flags.rhs = readOp(o[1]);
            // Note: register-width truncation for test/cmp disabled for now
            // because it causes re-emission of inlined call expressions
            m_flags.op = IROp::And;
            return;
        }

        // ── Branches ────────────────────────────────────────────────
        if (mn == "jmp" && n == 1 && o[0].type == X86_OP_IMM) {
            uint32_t tgt = (uint32_t)o[0].imm;
            auto bit = addrToBlock.find(tgt);
            if (bit != addrToBlock.end()) {
                bb.stmts.push_back(IRStmt::mkJump(bit->second));
            } else {
                // Tail call: jmp to a function outside this one
                auto fit = m_mf.functionMap().find(tgt);
                std::string target = fit != m_mf.functionMap().end() ? fit->second :
                    ([&]{ char b[16]; snprintf(b,16,"sub_%X",tgt); return std::string(b); })();
                TypeRef retType = NullType;
                auto *callee = m_mf.stabsFunctionAt(tgt);
                if (!callee) callee = m_mf.stabsFunctionByName(target);
                if (callee) retType = callee->returnType;
                // Build tail call: return target(args) — reuse current function's params
                std::vector<std::unique_ptr<IRExpr>> args;
                for (auto &p : func.params)
                    args.push_back(IRExpr::mkVar(p.name, p.typeRef));
                auto callExpr = IRExpr::mkCall(target, std::move(args), retType);
                bb.stmts.push_back(IRStmt::mkReturn(std::move(callExpr)));
            }
            return;
        }
        // Conditional jumps
        {
            bool isJcc = false;
            for (uint8_t g = 0; g < d->groups_count; ++g)
                if (d->groups[g] == CS_GRP_JUMP) isJcc = true;
            if (isJcc && mn != "jmp" && n == 1 && o[0].type == X86_OP_IMM) {
                uint32_t tgt = (uint32_t)o[0].imm;
                auto bit = addrToBlock.find(tgt);
                int trueBlock = bit != addrToBlock.end() ? bit->second : -1;
                // False target = next instruction's block
                uint32_t fallAddr = in.address + in.size;
                auto fbit = addrToBlock.find(fallAddr);
                int falseBlock = fbit != addrToBlock.end() ? fbit->second : -1;

                auto cond = buildCondition(mn);
                bb.stmts.push_back(IRStmt::mkBranch(std::move(cond), trueBlock, falseBlock));
                return;
            }
        }

        // ── Return ──────────────────────────────────────────────────
        if (mn == "ret") {
            fprintf(stderr, "RET_LIFTER: retType=%d fpuStack=%d lastFpuTop=%d\n",
                    m_func->returnType, (int)m_fpuStack.size(), m_lastFpuTop);
            // Check if return type is void (including through typedef chains)
            if (m_func->returnType != NullType) {
                auto *rt = m_types.resolveType(m_func->returnType);
                fprintf(stderr, "RET_LIFTER2: rt=%p kind=%d\n", (void*)rt, rt ? (int)rt->kind : -1);
                if (rt && rt->kind == StabsTypeKind::Void) {
                    bb.stmts.push_back(IRStmt::mkReturn());
                    return;
                }
                // Also check if formatType would produce "void"
                std::string retStr = m_types.formatType(m_func->returnType);
                if (retStr == "void") {
                    bb.stmts.push_back(IRStmt::mkReturn());
                    return;
                }
                // Float/double return → use ST0 from FPU stack, or last popped value
                if (rt && (rt->kind == StabsTypeKind::Float ||
                           rt->kind == StabsTypeKind::Double ||
                           rt->kind == StabsTypeKind::LongDouble)) {
                    // If FPU stack has a value, use ST0 directly
                    if (!m_fpuStack.empty()) {
                        bb.stmts.push_back(IRStmt::mkReturn(fpuRead(0)));
                        return;
                    }
                    // Use the last value that was on the FPU stack top before pop
                    // (common pattern: fstp stores result then ret returns it)
                    if (m_lastFpuTop >= 0) {
                        bb.stmts.push_back(IRStmt::mkReturn(
                            IRExpr::mkTemp(m_lastFpuTop, m_func->tempType(m_lastFpuTop))));
                        return;
                    }
                    // Fallback: find last VarSet to a float local across all blocks
                    for (int bi = (int)m_func->blocks.size() - 1; bi >= 0; --bi)
                    for (int si = (int)m_func->blocks[bi].stmts.size() - 1; si >= 0; --si) {
                        auto &s = m_func->blocks[bi].stmts[si];
                        if (s.kind == IRStmtKind::VarSet && !s.destVar.empty()) {
                            for (auto &loc : m_func->locals) {
                                if (loc.name == s.destVar && loc.typeRef != NullType) {
                                    auto *lt = m_types.resolveType(loc.typeRef);
                                    if (lt && (lt->kind == StabsTypeKind::Float ||
                                               lt->kind == StabsTypeKind::Double)) {
                                        bb.stmts.push_back(IRStmt::mkReturn(
                                            IRExpr::mkVar(s.destVar, loc.typeRef)));
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    // Fallback: just return ST0 temp (may be uninitialized)
                    bb.stmts.push_back(IRStmt::mkReturn(readReg(X86_REG_ST0)));
                    return;
                }
            }
            // Heuristic: detect void functions with STABS "int" return type
            {
                std::string retStr = m_types.formatType(m_func->returnType);
                bool isDefaultInt = (retStr == "int" || retStr == "Bool" || retStr == "BOOL");
                if (isDefaultInt) {
                    // If the block has NO statements, the function is an empty stub → void
                    if (bb.stmts.empty()) {
                        bb.stmts.push_back(IRStmt::mkReturn());
                        return;
                    }
                    // If the last statement is a Store/VarSet, EAX is leftover → void
                    auto &lastStmt = bb.stmts.back();
                    if (lastStmt.kind == IRStmtKind::Store ||
                        lastStmt.kind == IRStmtKind::VarSet) {
                        bb.stmts.push_back(IRStmt::mkReturn());
                        return;
                    }
                    // If the last statement is a Call (void call), the function is void
                    if (lastStmt.kind == IRStmtKind::Call) {
                        bb.stmts.push_back(IRStmt::mkReturn());
                        return;
                    }
                }
            }
            auto eax = readReg(X86_REG_EAX);
            bb.stmts.push_back(IRStmt::mkReturn(std::move(eax)));
            return;
        }

        // ── Call ────────────────────────────────────────────────────
        if (mn == "call" && n == 1) {
            std::string target;
            TypeRef retType = NullType;
            if (o[0].type == X86_OP_IMM) {
                uint32_t addr = (uint32_t)o[0].imm;
                auto fit = m_mf.functionMap().find(addr);
                target = fit != m_mf.functionMap().end() ? fit->second :
                    ([&]{ char b[16]; snprintf(b,16,"sub_%X",addr); return std::string(b); })();
                auto *callee = m_mf.stabsFunctionAt(addr);
                // Fallback: look up by name (handles import stubs → real function)
                if (!callee && !target.empty())
                    callee = m_mf.stabsFunctionByName(target);
                if (callee) {
                    retType = callee->returnType;
                }
            } else {
                // Indirect call through function pointer
                auto tgt = readOp(o[0]);
                if (tgt) {
                    // Assign the function pointer to a temp, then call through it
                    int fpTemp = func.newTemp();
                    bb.stmts.push_back(IRStmt::mkAssign(fpTemp, std::move(tgt)));
                    target = "t" + std::to_string(fpTemp);
                } else {
                    target = "???";
                }
            }

            // Gather args
            std::vector<std::unique_ptr<IRExpr>> args;
            if (!m_espArgs.empty()) {
                std::map<int, std::unique_ptr<IRExpr>> sorted;
                for (auto &[off, val] : m_espArgs) sorted[off] = std::move(val);
                for (auto &[off, val] : sorted) args.push_back(std::move(val));
            } else if (!m_pushArgs.empty()) {
                for (int a = (int)m_pushArgs.size() - 1; a >= 0; --a)
                    args.push_back(std::move(m_pushArgs[a]));
            }
            m_espArgs.clear();
            m_pushArgs.clear();

            auto callExpr = IRExpr::mkCall(target, std::move(args), retType);

            // Check if void return
            bool isVoid = false;
            bool isFloatRet = false;
            if (retType != NullType) {
                auto *rt = m_types.resolveType(retType);
                if (rt && rt->kind == StabsTypeKind::Void) isVoid = true;
                if (rt && (rt->kind == StabsTypeKind::Float ||
                           rt->kind == StabsTypeKind::Double ||
                           rt->kind == StabsTypeKind::LongDouble))
                    isFloatRet = true;
                // Fallback: check formatted type string for float/double
                // (handles cases where type table conflicts cause wrong kind)
                if (!isFloatRet && !isVoid) {
                    std::string fmtRet = m_types.formatType(retType);
                    if (fmtRet.find("float") != std::string::npos ||
                        fmtRet.find("double") != std::string::npos ||
                        fmtRet == "vec_t" || fmtRet == "const vec_t")
                        isFloatRet = true;
                    if (fmtRet == "void") isVoid = true;
                }
            }
            // Detect float return from pre-scan: if the instruction after this
            // call reads ST(0) (fstp, fst, etc.), the call returns float.
            if (!isFloatRet && !isVoid) {
                if (m_floatRetCallSites.count(in.address))
                    isFloatRet = true;
                // Also check by target address (covers all call sites to this func)
                if (o[0].type == X86_OP_IMM &&
                    m_floatReturnAddrs.count((uint32_t)o[0].imm))
                    isFloatRet = true;
            }

            if (isVoid) {
                bb.stmts.push_back(IRStmt::mkCall(std::move(callExpr)));
            } else {
                int t = func.newTemp(retType);
                bb.stmts.push_back(IRStmt::mkAssign(t, std::move(callExpr), retType));
                if (isFloatRet) {
                    // Float returns come back in ST0 — push onto FPU stack
                    m_fpuStack.insert(m_fpuStack.begin(), t);
                    if (m_fpuStack.size() > 8) m_fpuStack.resize(8);
                    fpuSyncRegs();
                } else {
                    writeReg(X86_REG_EAX, t, bb);
                }
            }
            // Caller-saved registers invalidated
            m_regTemps.erase(X86_REG_ECX);
            m_regTemps.erase(X86_REG_EDX);
            return;
        }

        // ── String operations ───────────────────────────────────────
        if (mn == "rep movsb" || mn == "rep movsd" || mn == "repe movsb" || mn == "repe movsd") {
            int sz = (mn.find("movsd") != std::string::npos) ? 4 : 1;
            auto dst = readReg(X86_REG_EDI);
            auto src = readReg(X86_REG_ESI);
            auto cnt = readReg(X86_REG_ECX);
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(std::move(dst));
            args.push_back(std::move(src));
            if (sz > 1) args.push_back(IRExpr::mkBinary(IROp::Mul, std::move(cnt), IRExpr::mkConst(sz)));
            else args.push_back(std::move(cnt));
            bb.stmts.push_back(IRStmt::mkCall(IRExpr::mkCall("memcpy", std::move(args))));
            return;
        }
        if (mn == "rep stosb" || mn == "rep stosd") {
            int sz = (mn.find("stosd") != std::string::npos) ? 4 : 1;
            auto dst = readReg(X86_REG_EDI);
            auto val = readReg(X86_REG_EAX);
            auto cnt = readReg(X86_REG_ECX);
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(std::move(dst));
            args.push_back(std::move(val));
            if (sz > 1) args.push_back(IRExpr::mkBinary(IROp::Mul, std::move(cnt), IRExpr::mkConst(sz)));
            else args.push_back(std::move(cnt));
            bb.stmts.push_back(IRStmt::mkCall(IRExpr::mkCall("memset", std::move(args))));
            return;
        }
        if (mn == "repe cmpsb" || mn == "repe cmpsd" || mn == "repne cmpsb" || mn == "repne cmpsd") {
            int sz = (mn.find("cmpsd") != std::string::npos) ? 4 : 1;
            bool equal = (mn.find("repe") != std::string::npos);
            auto dst = readReg(X86_REG_EDI);
            auto src = readReg(X86_REG_ESI);
            auto cnt = readReg(X86_REG_ECX);
            // Build proper Call expression for memcmp
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(std::move(src));
            args.push_back(std::move(dst));
            if (sz > 1) {
                args.push_back(IRExpr::mkBinary(IROp::Mul, std::move(cnt), IRExpr::mkConst(sz)));
            } else {
                args.push_back(std::move(cnt));
            }
            auto callExpr = IRExpr::mkCall("memcmp", std::move(args));
            int t = func.newTemp();
            bb.stmts.push_back(IRStmt::mkAssign(t, std::move(callExpr)));
            m_flags.lhs = IRExpr::mkTemp(t);
            m_flags.rhs = IRExpr::mkConst(0);
            m_flags.op = IROp::Sub;
            return;
        }
        if (mn == "repne scasb" || mn == "repe scasb" || mn == "repne scasd" || mn == "repe scasd") {
            auto dst = readReg(X86_REG_EDI);
            auto cnt = readReg(X86_REG_ECX);
            auto val = readReg(X86_REG_EAX);
            bool repne = (mn.find("repne") != std::string::npos);
            std::vector<std::unique_ptr<IRExpr>> args;
            std::string fname;
            if (repne && mn.find("scasb") != std::string::npos) {
                fname = "strlen";
                args.push_back(std::move(dst));
            } else {
                fname = "memchr";
                args.push_back(std::move(dst));
                args.push_back(std::move(val));
                args.push_back(std::move(cnt));
            }
            int t = func.newTemp();
            bb.stmts.push_back(IRStmt::mkAssign(t, IRExpr::mkCall(fname, std::move(args))));
            // Assign strlen result directly to ECX.
            // Note: repne scasb produces ~(len+1) in ECX, but we abstract to strlen().
            // The subsequent xor edi,-1 pattern will produce (strlen ^ -1) in the output.
            // For correct C: the original pattern is strlen(s)+1 (including null terminator).
            assignReg(X86_REG_ECX, IRExpr::mkTemp(t), bb);
            return;
        }
        if (mn == "movsb" || (mn == "movsd" && n == 0) || mn == "movsw") {
            auto dst = readReg(X86_REG_EDI);
            auto src = readReg(X86_REG_ESI);
            // *(dst) = *(src) — single element copy
            bb.stmts.push_back(IRStmt::mkStore(std::move(dst),
                IRExpr::mkLoad(std::move(src))));
            return;
        }
        if (mn == "stosb" || mn == "stosd" || mn == "stosw") {
            auto dst = readReg(X86_REG_EDI);
            auto val = readReg(X86_REG_EAX);
            // *(dst) = val — single element store
            bb.stmts.push_back(IRStmt::mkStore(std::move(dst), std::move(val)));
            return;
        }
        if (mn == "cmpsb" || mn == "cmpsd" || mn == "cmpsw") {
            auto dst = readReg(X86_REG_EDI);
            auto src = readReg(X86_REG_ESI);
            m_flags.lhs = IRExpr::mkLoad(std::move(src));
            m_flags.rhs = IRExpr::mkLoad(std::move(dst));
            m_flags.op = IROp::Sub;
            return;
        }
        if (mn == "scasb" || mn == "scasd" || mn == "scasw") {
            auto dst = readReg(X86_REG_EDI);
            auto val = readReg(X86_REG_EAX);
            m_flags.lhs = std::move(val);
            m_flags.rhs = IRExpr::mkLoad(std::move(dst));
            m_flags.op = IROp::Sub;
            return;
        }
        if (mn == "lodsb" || mn == "lodsd" || mn == "lodsw") {
            auto src = readReg(X86_REG_ESI);
            assignReg(X86_REG_EAX, IRExpr::mkLoad(std::move(src)), bb);
            return;
        }

        // ── Bit operations ──────────────────────────────────────────
        if ((mn == "bt" || mn == "bts" || mn == "btr" || mn == "btc") && n == 2) {
            auto base = readOp(o[0]);
            auto bit = readOp(o[1]);
            auto mask = IRExpr::mkBinary(IROp::Shl, IRExpr::mkConst(1), std::move(bit));
            m_flags.lhs = IRExpr::mkBinary(IROp::And, base->clone(), mask->clone());
            m_flags.rhs = IRExpr::mkConst(0);
            m_flags.op = IROp::Sub;
            if (mn == "bts")
                writeOp(o[0], IRExpr::mkBinary(IROp::Or, std::move(base), std::move(mask)), bb);
            else if (mn == "btr")
                writeOp(o[0], IRExpr::mkBinary(IROp::And, std::move(base),
                    IRExpr::mkUnary(IROp::Not, std::move(mask))), bb);
            else if (mn == "btc")
                writeOp(o[0], IRExpr::mkBinary(IROp::Xor, std::move(base), std::move(mask)), bb);
            return;
        }
        if (mn == "bsf" || mn == "bsr") {
            auto src = readOp(o[1]);
            std::string fn = (mn == "bsf") ? "__builtin_ctz" : "__builtin_clz";
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(std::move(src));
            auto callExpr = IRExpr::mkCall(fn, std::move(args));
            if (o[0].type == X86_OP_REG)
                assignReg(canonReg(o[0].reg), std::move(callExpr), bb);
            return;
        }

        // ── Rotate ──────────────────────────────────────────────────
        if ((mn == "rol" || mn == "ror") && n == 2) {
            auto v = readOp(o[0]);
            auto amt = readOp(o[1]);
            std::string fn = (mn == "rol") ? "__builtin_rotl" : "__builtin_rotr";
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(v->clone());
            args.push_back(std::move(amt));
            writeOp(o[0], IRExpr::mkCall(fn, std::move(args)), bb);
            return;
        }

        // ── FPU ─────────────────────────────────────────────────────
        if (mn == "fld" || mn == "fild" || mn == "flds" || mn == "fldl" ||
            mn == "fst" || mn == "fstp" || mn == "fist" || mn == "fistp" ||
            mn == "fistl" || mn == "fistpl" ||
            mn == "fadd" || mn == "faddp" || mn == "fiadd" ||
            mn == "fsub" || mn == "fsubp" || mn == "fisub" || mn == "fsubr" || mn == "fsubrp" ||
            mn == "fmul" || mn == "fmulp" || mn == "fimul" ||
            mn == "fdiv" || mn == "fdivp" || mn == "fidiv" || mn == "fdivr" || mn == "fdivrp" ||
            mn == "fchs" || mn == "fabs" || mn == "fsqrt" || mn == "fsin" || mn == "fcos" ||
            mn == "fpatan" || mn == "fyl2x" || mn == "f2xm1" ||
            mn == "fxch" || mn == "fcom" || mn == "fcomp" || mn == "fcompp" ||
            mn == "fucom" || mn == "fucomp" || mn == "fucompp" || mn == "fcomi" || mn == "fcomip" ||
            mn == "fucomi" || mn == "fucomip" ||
            mn == "fld1" || mn == "fldz" || mn == "fldpi" || mn == "fldl2e" || mn == "fldln2" ||
            mn == "fnstcw" || mn == "fldcw" || mn == "fnstsw" || mn == "fstsw" ||
            mn == "frndint" || mn == "fscale" || mn == "fdecstp" || mn == "fincstp" ||
            mn == "ffree" || mn == "finit" || mn == "fninit" || mn == "fwait" || mn == "wait") {
            liftFPU(mn, o, n, bb);
            return;
        }

        // ── Misc ────────────────────────────────────────────────────
        if (mn == "cld" || mn == "std" || mn == "clc" || mn == "stc" || mn == "cmc" ||
            mn == "sahf" || mn == "lahf" || mn == "int3" || mn == "hlt" || mn == "ud2") {
            // Direction/carry flag ops and traps — no C equivalent needed usually
            return;
        }
        if (mn == "cpuid") {
            bb.stmts.push_back(IRStmt::mkIntrinsic("cpuid", "__cpuid()"));
            return;
        }
        if (mn == "rdtsc") {
            bb.stmts.push_back(IRStmt::mkIntrinsic("rdtsc", "__rdtsc()"));
            return;
        }

        // ── Indirect jump (switch/vtable) ───────────────────────────
        if (mn == "jmp" && n == 1 && o[0].type != X86_OP_IMM) {
            // Check if this is a known switch table
            auto sit = m_switchTables.find(in.address);
            if (sit != m_switchTables.end()) {
                auto &si = sit->second;
                // Find the switch expression — look back for the sub/cmp pattern
                // The index register holds (original_value - base)
                // We want to switch on original_value
                auto &mem = o[0].mem;
                auto switchExpr = (mem.index != X86_REG_INVALID) ?
                    readReg(mem.index) : IRExpr::mkConst(0);

                // Build case list: (case_value, block_id)
                std::vector<std::pair<int, int>> cases;
                int defaultBlock = -1;
                if (si.defaultAddr) {
                    auto dit = addrToBlock.find(si.defaultAddr);
                    if (dit != addrToBlock.end()) defaultBlock = dit->second;
                }
                for (int c = 0; c < (int)si.targets.size(); ++c) {
                    uint32_t tgt = si.targets[c];
                    if (tgt == si.defaultAddr) continue; // skip default entries
                    auto tit = addrToBlock.find(tgt);
                    if (tit == addrToBlock.end()) continue;
                    int caseVal = c + si.switchBase;
                    cases.push_back({caseVal, tit->second});
                }
                bb.stmts.push_back(IRStmt::mkSwitch(
                    std::move(switchExpr), std::move(cases), defaultBlock, si.switchBase));
                return;
            }
            auto target = readOp(o[0]);
            bb.stmts.push_back(IRStmt::mkIntrinsic("indirect_jmp",
                "goto *" + varText(std::move(target))));
            return;
        }

        // ── SSE / SSE2 ─────────────────────────────────────────────
        if (liftSSE(mn, o, n, bb, in)) return;

        // ── Fallback: emit as intrinsic with original asm ───────────
        std::string asmText = mn + " " + std::string(in.op_str);
        bb.stmts.push_back(IRStmt::mkIntrinsic("asm", "__asm__(\"" + asmText + "\")"));
    }

    // ── FPU instruction lifter (with stack model) ────────────────────
    void liftFPU(const std::string &mn, cs_x86_op *o, int n, BasicBlock &bb) {
        bool isPop = (mn.size() >= 4 && mn.back() == 'p' &&
                      mn != "fnstcw" && mn != "fcomp" && mn != "fcompp" &&
                      mn != "fucomp" && mn != "fucompp" && mn != "fcomip" && mn != "fucomip");

        // ── Loads: push onto FPU stack ────────────────────────────────
        if (mn == "fld" || mn == "flds" || mn == "fldl") {
            if (n == 1) {
                // fld st(i) — duplicate a stack entry
                if (o[0].type == X86_OP_REG && o[0].reg >= X86_REG_ST0 && o[0].reg <= X86_REG_ST7) {
                    int idx = stRegIndex(o[0].reg);
                    auto val = fpuRead(idx);
                    fpuPush(std::move(val), bb);
                } else {
                    // fld loads a float from memory — no int-to-float cast needed
                    auto src = readOp(o[0]);
                    fpuPush(std::move(src), bb);
                }
            }
            return;
        }
        if (mn == "fild") {
            if (n == 1) {
                auto src = readOp(o[0]);
                fpuPush(IRExpr::mkCast(CastKind::IntToFloat, std::move(src)), bb);
            }
            return;
        }
        // ── Stores ───────────────────────────────────────────────────
        if (mn == "fst" || mn == "fstp") {
            if (n == 1) {
                auto st0 = fpuRead(0);
                // fstp st(i) — store into stack register and pop
                if (mn == "fstp" && o[0].type == X86_OP_REG &&
                    o[0].reg >= X86_REG_ST0 && o[0].reg <= X86_REG_ST7) {
                    int idx = stRegIndex(o[0].reg);
                    // After pop, what was at idx+1 moves to idx, so write to idx-1 post-pop
                    // But the value comes from ST0 before pop
                    fpuPop();
                    if (idx > 0 && idx - 1 < (int)m_fpuStack.size())
                        fpuWrite(idx - 1, std::move(st0), bb);
                } else if (o[0].type == X86_OP_MEM &&
                           o[0].mem.base == X86_REG_ESP &&
                           o[0].mem.index == X86_REG_INVALID) {
                    // fstp [esp+N] → collect as call argument (float pushed to stack)
                    m_espArgs[(int)o[0].mem.disp] = std::move(st0);
                    if (mn == "fstp") fpuPop();
                } else {
                    writeOp(o[0], std::move(st0), bb);
                    if (mn == "fstp") fpuPop();
                }
            }
            return;
        }
        if (mn == "fist" || mn == "fistp" || mn == "fistl" || mn == "fistpl") {
            if (n == 1) {
                auto st0 = fpuRead(0);
                writeOp(o[0], IRExpr::mkCast(CastKind::FloatToInt, std::move(st0)), bb);
                if (mn == "fistp" || mn == "fistpl") fpuPop();
            }
            return;
        }
        // ── Arithmetic (binary) ──────────────────────────────────────
        auto fpuBinOp = [&](IROp irop, bool reverse = false) {
            if (n == 0) {
                // No operands: fadd = ST1 + ST0, faddp = ST1 + ST0 then pop
                auto a = fpuRead(0);
                auto b = fpuRead(1);
                if (reverse) std::swap(a, b);
                if (isPop) {
                    // faddp: result goes to ST1, then pop ST0 (result ends in new ST0)
                    fpuWrite(1, IRExpr::mkBinary(irop, std::move(a), std::move(b)), bb);
                } else {
                    fpuWrite(0, IRExpr::mkBinary(irop, std::move(a), std::move(b)), bb);
                }
            } else if (n >= 2 && o[0].type == X86_OP_REG && o[1].type == X86_OP_REG) {
                // fadd st(i), st(j) — result in st(i)
                int di = stRegIndex(o[0].reg);
                int si = stRegIndex(o[1].reg);
                auto a = fpuRead(di);
                auto b = fpuRead(si);
                if (reverse) std::swap(a, b);
                fpuWrite(di, IRExpr::mkBinary(irop, std::move(a), std::move(b)), bb);
            } else if (n >= 1) {
                // fadd [mem] or fadd st(i)
                auto st0 = fpuRead(0);
                std::unique_ptr<IRExpr> src;
                if (o[0].type == X86_OP_REG && o[0].reg >= X86_REG_ST0 && o[0].reg <= X86_REG_ST7)
                    src = fpuRead(stRegIndex(o[0].reg));
                else
                    src = readOp(o[0]);
                if (reverse) std::swap(st0, src);
                fpuWrite(0, IRExpr::mkBinary(irop, std::move(st0), std::move(src)), bb);
            }
            if (isPop && !m_fpuStack.empty()) fpuPop();
        };

        if (mn == "fadd" || mn == "faddp" || mn == "fiadd") { fpuBinOp(IROp::Add); return; }
        if (mn == "fsub" || mn == "fsubp" || mn == "fisub") { fpuBinOp(IROp::Sub); return; }
        if (mn == "fsubr" || mn == "fsubrp") { fpuBinOp(IROp::Sub, true); return; }
        if (mn == "fmul" || mn == "fmulp" || mn == "fimul") { fpuBinOp(IROp::Mul); return; }
        if (mn == "fdiv" || mn == "fdivp" || mn == "fidiv") { fpuBinOp(IROp::SDiv); return; }
        if (mn == "fdivr" || mn == "fdivrp") { fpuBinOp(IROp::SDiv, true); return; }

        // ── Unary on ST0 ─────────────────────────────────────────────
        if (mn == "fchs") {
            auto st0 = fpuRead(0);
            fpuWrite(0, IRExpr::mkUnary(IROp::Neg, std::move(st0)), bb);
            return;
        }
        if (mn == "fabs") {
            auto st0 = fpuRead(0);
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(std::move(st0));
            fpuWrite(0, IRExpr::mkCall("fabs", std::move(args)), bb);
            return;
        }
        if (mn == "fsqrt") {
            auto st0 = fpuRead(0);
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(std::move(st0));
            fpuWrite(0, IRExpr::mkCall("sqrt", std::move(args)), bb);
            return;
        }
        if (mn == "fsin") {
            auto st0 = fpuRead(0);
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(std::move(st0));
            fpuWrite(0, IRExpr::mkCall("sinf", std::move(args)), bb);
            return;
        }
        if (mn == "fcos") {
            auto st0 = fpuRead(0);
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(std::move(st0));
            fpuWrite(0, IRExpr::mkCall("cosf", std::move(args)), bb);
            return;
        }
        // ── Constants: push onto stack ────────────────────────────────
        if (mn == "fld1")  { fpuPush(IRExpr::mkConst(1), bb); return; }
        if (mn == "fldz")  { fpuPush(IRExpr::mkConst(0), bb); return; }
        if (mn == "fldpi") { fpuPush(IRExpr::mkVar("M_PI"), bb); return; }

        // ── Comparisons ──────────────────────────────────────────────
        if (mn == "fcom" || mn == "fcomp" || mn == "fcompp" ||
            mn == "fucom" || mn == "fucomp" || mn == "fucompp" ||
            mn == "fcomi" || mn == "fcomip" || mn == "fucomi" || mn == "fucomip") {
            auto st0 = fpuRead(0);
            auto cmp = (n >= 1) ? readOp(o[0]) : fpuRead(1);
            m_flags.lhs = std::move(st0);
            m_flags.rhs = std::move(cmp);
            m_flags.op = IROp::Sub;
            // Pop for fcomp/fucomp/fcomip/fucomip
            if (mn == "fcomp" || mn == "fucomp" || mn == "fcomip" || mn == "fucomip")
                fpuPop();
            // Pop twice for fcompp/fucompp
            if (mn == "fcompp" || mn == "fucompp") { fpuPop(); fpuPop(); }
            return;
        }
        if (mn == "fnstsw" || mn == "fstsw") {
            assignReg(X86_REG_EAX, IRExpr::mkVar("__fpu_status"), bb);
            return;
        }
        // ── Exchange ─────────────────────────────────────────────────
        if (mn == "fxch") {
            int idx = (n >= 1 && o[0].type == X86_OP_REG) ? stRegIndex(o[0].reg) : 1;
            if (idx > 0 && idx < (int)m_fpuStack.size()) {
                std::swap(m_fpuStack[0], m_fpuStack[idx]);
                fpuSyncRegs();
            }
            return;
        }
        // ── Transcendental functions that modify the stack ──────────
        if (mn == "fpatan") {
            // fpatan: ST1 = atan2(ST1, ST0), then pop (result in new ST0)
            auto st0 = fpuRead(0);
            auto st1 = fpuRead(1);
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(std::move(st1));
            args.push_back(std::move(st0));
            fpuWrite(1, IRExpr::mkCall("atan2f", std::move(args)), bb);
            fpuPop();
            return;
        }
        if (mn == "fyl2x") {
            // fyl2x: ST1 = ST1 * log2(ST0), then pop
            auto st0 = fpuRead(0);
            auto st1 = fpuRead(1);
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(std::move(st0));
            auto logExpr = IRExpr::mkCall("log2f", std::move(args));
            fpuWrite(1, IRExpr::mkBinary(IROp::Mul, std::move(st1), std::move(logExpr)), bb);
            fpuPop();
            return;
        }
        if (mn == "f2xm1") {
            // f2xm1: ST0 = 2^ST0 - 1
            auto st0 = fpuRead(0);
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(IRExpr::mkConst(2));
            args.push_back(std::move(st0));
            auto powExpr = IRExpr::mkCall("powf", std::move(args));
            fpuWrite(0, IRExpr::mkBinary(IROp::Sub, std::move(powExpr), IRExpr::mkConst(1)), bb);
            return;
        }
        if (mn == "fscale") {
            // fscale: ST0 = ST0 * 2^(trunc(ST1))  (ST1 unchanged)
            auto st0 = fpuRead(0);
            auto st1 = fpuRead(1);
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(IRExpr::mkConst(2));
            args.push_back(std::move(st1));
            auto powExpr = IRExpr::mkCall("powf", std::move(args));
            fpuWrite(0, IRExpr::mkBinary(IROp::Mul, std::move(st0), std::move(powExpr)), bb);
            return;
        }
        if (mn == "frndint") {
            // frndint: ST0 = round(ST0)
            auto st0 = fpuRead(0);
            std::vector<std::unique_ptr<IRExpr>> args;
            args.push_back(std::move(st0));
            fpuWrite(0, IRExpr::mkCall("roundf", std::move(args)), bb);
            return;
        }
        if (mn == "fldl2e") {
            // Push log2(e)
            fpuPush(IRExpr::mkVar("M_LOG2E"), bb);
            return;
        }
        if (mn == "fldln2") {
            // Push ln(2)
            fpuPush(IRExpr::mkVar("M_LN2"), bb);
            return;
        }
        if (mn == "fdecstp") {
            // Rotate stack pointer down — approximate as no-op
            return;
        }
        if (mn == "fincstp") {
            // Rotate stack pointer up — approximate as no-op
            return;
        }
        if (mn == "ffree") {
            // Free a stack register
            if (n >= 1 && o[0].type == X86_OP_REG && o[0].reg == X86_REG_ST0 && !m_fpuStack.empty())
                fpuPop();
            return;
        }
        // ── Control — suppress ──────────────────────────────────────────
        if (mn == "fnstcw" || mn == "fldcw" ||
            mn == "finit" || mn == "fninit" || mn == "fwait" || mn == "wait") {
            return;
        }
    }

    // ── SSE / SSE2 instruction lifter ──────────────────────────────
    bool liftSSE(const std::string &mn, cs_x86_op *o, int n, BasicBlock &bb, cs_insn &in) {
        // ── Scalar moves: movss, movsd ──────────────────────────────
        if ((mn == "movss" || mn == "movsd") && n == 2) {
            // movss/movsd [esp+N], xmm → collect as call argument
            if (o[0].type == X86_OP_MEM && o[0].mem.base == X86_REG_ESP &&
                o[0].mem.index == X86_REG_INVALID) {
                auto src = readSSEOp(o[1], mn == "movsd");
                if (src) m_espArgs[(int)o[0].mem.disp] = std::move(src);
                return true;
            }
            auto src = readSSEOp(o[1], mn == "movsd");
            if (src) writeOp(o[0], std::move(src), bb);
            return true;
        }
        // ── Packed moves (treat as scalar for decompilation) ────────
        if ((mn == "movaps" || mn == "movups" || mn == "movapd" || mn == "movupd" ||
             mn == "movdqa" || mn == "movdqu" || mn == "movlps" || mn == "movhps" ||
             mn == "movlpd" || mn == "movhpd" || mn == "movq") && n == 2) {
            auto src = readSSEOp(o[1], mn.find('d') != std::string::npos);
            if (src) writeOp(o[0], std::move(src), bb);
            return true;
        }

        // ── Scalar arithmetic: addss/sd, subss/sd, mulss/sd, divss/sd
        if ((mn == "addss" || mn == "addsd" || mn == "subss" || mn == "subsd" ||
             mn == "mulss" || mn == "mulsd" || mn == "divss" || mn == "divsd") && n == 2) {
            bool dbl = (mn.back() == 'd');
            IROp irop;
            if (mn.find("add") == 0) irop = IROp::Add;
            else if (mn.find("sub") == 0) irop = IROp::Sub;
            else if (mn.find("mul") == 0) irop = IROp::Mul;
            else irop = IROp::SDiv;
            auto lhs = readSSEOp(o[0], dbl);
            auto rhs = readSSEOp(o[1], dbl);
            if (lhs && rhs) writeOp(o[0], IRExpr::mkBinary(irop, std::move(lhs), std::move(rhs)), bb);
            return true;
        }

        // ── Packed arithmetic (treat as scalar) ─────────────────────
        if ((mn == "addps" || mn == "addpd" || mn == "subps" || mn == "subpd" ||
             mn == "mulps" || mn == "mulpd" || mn == "divps" || mn == "divpd") && n == 2) {
            bool dbl = (mn.back() == 'd');
            IROp irop;
            if (mn.find("add") == 0) irop = IROp::Add;
            else if (mn.find("sub") == 0) irop = IROp::Sub;
            else if (mn.find("mul") == 0) irop = IROp::Mul;
            else irop = IROp::SDiv;
            auto lhs = readSSEOp(o[0], dbl);
            auto rhs = readSSEOp(o[1], dbl);
            if (lhs && rhs) writeOp(o[0], IRExpr::mkBinary(irop, std::move(lhs), std::move(rhs)), bb);
            return true;
        }

        // ── Conversions ─────────────────────────────────────────────
        if ((mn == "cvtsi2ss" || mn == "cvtsi2sd") && n == 2) {
            auto src = readOp(o[1]);
            if (src) writeOp(o[0], IRExpr::mkCast(CastKind::IntToFloat, std::move(src)), bb);
            return true;
        }
        if ((mn == "cvttss2si" || mn == "cvttsd2si" || mn == "cvtss2si" || mn == "cvtsd2si") && n == 2) {
            auto src = readSSEOp(o[1], mn.find("sd") != std::string::npos);
            if (src) writeOp(o[0], IRExpr::mkCast(CastKind::FloatToInt, std::move(src)), bb);
            return true;
        }
        if ((mn == "cvtss2sd" || mn == "cvtsd2ss") && n == 2) {
            auto src = readSSEOp(o[1], mn == "cvtsd2ss");
            if (src) writeOp(o[0], std::move(src), bb); // just propagate, C handles float<->double
            return true;
        }
        if ((mn == "cvtps2pd" || mn == "cvtpd2ps" || mn == "cvtdq2ps" || mn == "cvtps2dq" ||
             mn == "cvttps2dq" || mn == "cvtdq2pd" || mn == "cvtpd2dq" || mn == "cvttpd2dq") && n == 2) {
            auto src = readSSEOp(o[1], false);
            if (src) writeOp(o[0], std::move(src), bb);
            return true;
        }

        // ── Comparisons: ucomiss, ucomisd, comiss, comisd ───────────
        if ((mn == "ucomiss" || mn == "ucomisd" || mn == "comiss" || mn == "comisd") && n == 2) {
            bool dbl = (mn.find("sd") != std::string::npos);
            m_flags.lhs = readSSEOp(o[0], dbl);
            m_flags.rhs = readSSEOp(o[1], dbl);
            m_flags.op = IROp::Sub;
            return true;
        }
        // ── cmpss/cmpsd and all SSE comparison variants ──────────────
        // Capstone emits: cmpss, cmpeqss, cmpltss, cmpless, cmpunordss,
        // cmpneqss, cmpnltss, cmpnless, cmpordss (and *sd, *ps, *pd variants)
        if ((mn.find("cmp") == 0 && (mn.find("ss") != std::string::npos ||
             mn.find("sd") != std::string::npos || mn.find("ps") != std::string::npos ||
             mn.find("pd") != std::string::npos) &&
             mn != "cmpsb" && mn != "cmpsd" && mn != "cmpsw" && // not string ops
             mn.find("cmpxchg") == std::string::npos) && n >= 2) {
            bool dbl = (mn.find("sd") != std::string::npos || mn.find("pd") != std::string::npos);
            auto lhs = readSSEOp(o[0], dbl);
            auto rhs = readSSEOp(o[1], dbl);

            // Determine comparison op from mnemonic
            IROp cmpOp = IROp::Ne; // default
            if (mn.find("cmpnlt") != std::string::npos) cmpOp = IROp::Sge;
            else if (mn.find("cmpnle") != std::string::npos) cmpOp = IROp::Sgt;
            else if (mn.find("cmpneq") != std::string::npos) cmpOp = IROp::Ne;
            else if (mn.find("cmpeq") != std::string::npos) cmpOp = IROp::Eq;
            else if (mn.find("cmplt") != std::string::npos) cmpOp = IROp::Slt;
            else if (mn.find("cmple") != std::string::npos) cmpOp = IROp::Sle;
            else if (mn.find("cmpord") != std::string::npos) cmpOp = IROp::Eq; // ordered = !NaN
            else if (mn.find("cmpunord") != std::string::npos) cmpOp = IROp::Ne;

            if (lhs && rhs) {
                auto cmpExpr = IRExpr::mkBinary(cmpOp, std::move(lhs), std::move(rhs));
                writeOp(o[0], std::move(cmpExpr), bb);
            }
            return true;
        }

        // ── Bitwise: xorps/xorpd, andps/andpd, orps/orpd ──────────
        if ((mn == "xorps" || mn == "xorpd" || mn == "pxor") && n == 2) {
            // xorps xmm0, xmm0 → zero
            if (o[0].type == X86_OP_REG && o[1].type == X86_OP_REG && o[0].reg == o[1].reg) {
                writeOp(o[0], IRExpr::mkVar("0.0f"), bb);
                return true;
            }
            // Detect negation pattern: xorps xmm, [0x80000000 mask]
            if (o[1].type == X86_OP_MEM) {
                uint32_t caddr = resolveMemAddr(o[1].mem);
                if (caddr) {
                    int64_t foff = m_mf.fileOffsetForAddress(caddr);
                    if (foff >= 0) {
                        const uint8_t *cp = m_mf.bytesAt((uint32_t)foff, 4);
                        if (cp) {
                            uint32_t mask; memcpy(&mask, cp, 4);
                            if (mask == 0x80000000) {
                                // xorps with 0x80000000 = float negation
                                auto src = readSSEOp(o[0], false);
                                if (src) writeOp(o[0], IRExpr::mkUnary(IROp::Neg, std::move(src)), bb);
                                return true;
                            }
                        }
                    }
                }
            }
            auto lhs = readSSEOp(o[0], false);
            auto rhs = readSSEOp(o[1], false);
            if (lhs && rhs) writeOp(o[0], IRExpr::mkBinary(IROp::Xor, std::move(lhs), std::move(rhs)), bb);
            return true;
        }
        if ((mn == "andps" || mn == "andpd" || mn == "pand" ||
             mn == "andnps" || mn == "andnpd" || mn == "pandn") && n == 2) {
            // Detect fabsf pattern: andps xmm, [0x7FFFFFFF mask]
            if (o[1].type == X86_OP_MEM) {
                uint32_t caddr = resolveMemAddr(o[1].mem);
                if (caddr) {
                    int64_t foff = m_mf.fileOffsetForAddress(caddr);
                    if (foff >= 0) {
                        const uint8_t *cp = m_mf.bytesAt((uint32_t)foff, 4);
                        if (cp) {
                            uint32_t mask; memcpy(&mask, cp, 4);
                            if (mask == 0x7FFFFFFF) {
                                // andps with 0x7FFFFFFF = fabsf
                                auto src = readSSEOp(o[0], false);
                                if (src) {
                                    std::vector<std::unique_ptr<IRExpr>> args;
                                    args.push_back(std::move(src));
                                    writeOp(o[0], IRExpr::mkCall("fabsf", std::move(args)), bb);
                                }
                                return true;
                            }
                        }
                    }
                }
            }
            auto lhs = readSSEOp(o[0], false);
            auto rhs = readSSEOp(o[1], false);
            if (lhs && rhs) writeOp(o[0], IRExpr::mkBinary(IROp::And, std::move(lhs), std::move(rhs)), bb);
            return true;
        }
        if ((mn == "orps" || mn == "orpd" || mn == "por") && n == 2) {
            auto lhs = readSSEOp(o[0], false);
            auto rhs = readSSEOp(o[1], false);
            if (lhs && rhs) writeOp(o[0], IRExpr::mkBinary(IROp::Or, std::move(lhs), std::move(rhs)), bb);
            return true;
        }

        // ── Min/Max/Sqrt/Rsqrt/Rcp ─────────────────────────────────
        if ((mn == "minss" || mn == "minsd" || mn == "minps" || mn == "minpd") && n == 2) {
            auto a = readSSEOp(o[0], mn.find('d') != std::string::npos);
            auto b = readSSEOp(o[1], mn.find('d') != std::string::npos);
            if (a && b) writeOp(o[0], IRExpr::mkVar("fminf(" + varText(std::move(a)) + ", " + varText(std::move(b)) + ")"), bb);
            return true;
        }
        if ((mn == "maxss" || mn == "maxsd" || mn == "maxps" || mn == "maxpd") && n == 2) {
            auto a = readSSEOp(o[0], mn.find('d') != std::string::npos);
            auto b = readSSEOp(o[1], mn.find('d') != std::string::npos);
            if (a && b) writeOp(o[0], IRExpr::mkVar("fmaxf(" + varText(std::move(a)) + ", " + varText(std::move(b)) + ")"), bb);
            return true;
        }
        if ((mn == "sqrtss" || mn == "sqrtsd" || mn == "sqrtps" || mn == "sqrtpd") && n == 2) {
            auto src = readSSEOp(o[1], mn.find('d') != std::string::npos);
            if (src) writeOp(o[0], IRExpr::mkVar("sqrtf(" + varText(std::move(src)) + ")"), bb);
            return true;
        }
        if ((mn == "rsqrtss" || mn == "rsqrtps") && n == 2) {
            auto src = readSSEOp(o[1], false);
            if (src) writeOp(o[0], IRExpr::mkVar("(1.0f / sqrtf(" + varText(std::move(src)) + "))"), bb);
            return true;
        }
        if ((mn == "rcpss" || mn == "rcpps") && n == 2) {
            auto src = readSSEOp(o[1], false);
            if (src) writeOp(o[0], IRExpr::mkVar("(1.0f / " + varText(std::move(src)) + ")"), bb);
            return true;
        }

        // ── Shuffles / unpacks (pass through, hard to decompile) ────
        if (mn == "shufps" || mn == "shufpd" || mn == "pshufd" || mn == "pshufw" ||
            mn == "pshufb" || mn == "pshuflw" || mn == "pshufhw" ||
            mn == "unpcklps" || mn == "unpckhps" || mn == "unpcklpd" || mn == "unpckhpd" ||
            mn == "punpcklbw" || mn == "punpckhbw" || mn == "punpcklwd" || mn == "punpckhwd" ||
            mn == "punpckldq" || mn == "punpckhdq" || mn == "punpcklqdq" || mn == "punpckhqdq") {
            if (n >= 2) {
                auto src = readSSEOp(o[1], false);
                if (src) writeOp(o[0], std::move(src), bb);
            }
            return true;
        }

        // ── Integer SIMD packed ops (just propagate values) ─────────
        if ((mn.substr(0, 4) == "padd" || mn.substr(0, 4) == "psub" ||
             mn.substr(0, 4) == "pmul" || mn.substr(0, 4) == "pmin" ||
             mn.substr(0, 4) == "pmax" || mn.substr(0, 4) == "pcmp" ||
             mn.substr(0, 4) == "pack" || mn.substr(0, 4) == "psll" ||
             mn.substr(0, 4) == "psrl" || mn.substr(0, 4) == "psra" ||
             mn.substr(0, 5) == "pmovs" || mn.substr(0, 5) == "pmovz") && n == 2) {
            IROp irop = IROp::Add;
            if (mn.find("sub") != std::string::npos) irop = IROp::Sub;
            else if (mn.find("mull") != std::string::npos || mn.find("mulh") != std::string::npos) irop = IROp::Mul;
            else if (mn.find("sll") != std::string::npos) irop = IROp::Shl;
            else if (mn.find("srl") != std::string::npos) irop = IROp::Shr;
            else if (mn.find("sra") != std::string::npos) irop = IROp::Sar;
            auto lhs = readSSEOp(o[0], false);
            auto rhs = readSSEOp(o[1], false);
            if (lhs && rhs) writeOp(o[0], IRExpr::mkBinary(irop, std::move(lhs), std::move(rhs)), bb);
            return true;
        }

        // ── movd/movq between GP and XMM ────────────────────────────
        if ((mn == "movd" || mn == "movq") && n == 2) {
            auto src = readOp(o[1]);
            if (src) writeOp(o[0], std::move(src), bb);
            return true;
        }

        // ── Prefetch, fence, etc — no-ops for decompilation ─────────
        if (mn == "prefetchnta" || mn == "prefetcht0" || mn == "prefetcht1" || mn == "prefetcht2" ||
            mn == "lfence" || mn == "mfence" || mn == "sfence" || mn == "emms" ||
            mn == "ldmxcsr" || mn == "stmxcsr") {
            return true;
        }

        return false; // not an SSE instruction
    }

    // Read an SSE operand, resolving memory as float/double constants
    std::unique_ptr<IRExpr> readSSEOp(cs_x86_op &op, bool isDouble) {
        if (op.type == X86_OP_REG) return readReg(op.reg);
        if (op.type == X86_OP_IMM) return IRExpr::mkConst(op.imm);
        if (op.type == X86_OP_MEM) {
            // Try to resolve the memory address to an actual float constant
            auto resolved = resolveFloatConst(op.mem, isDouble);
            if (resolved) return resolved;
            // Fall back to regular memory read
            return readMem(op.mem);
        }
        return IRExpr::mkConst(0);
    }

    // Try to read a float/double constant from a known memory address
    // Resolve a memory operand to a virtual address (for constant pool lookups)
    uint32_t resolveMemAddr(x86_op_mem &m) {
        if (m.base == X86_REG_INVALID && m.index == X86_REG_INVALID && m.disp)
            return (uint32_t)m.disp;
        if (m_hasPIC && m.base == X86_REG_EBX && m.index == X86_REG_INVALID && m_picBase)
            return m_picBase + (int)m.disp;
        return 0;
    }

    std::unique_ptr<IRExpr> resolveFloatConst(x86_op_mem &m, bool isDouble) {
        uint32_t addr = 0;

        // Direct address: [disp]
        if (m.base == X86_REG_INVALID && m.index == X86_REG_INVALID && m.disp)
            addr = (uint32_t)m.disp;
        // PIC-relative: [ebx + disp]
        else if (m_hasPIC && m.base == X86_REG_EBX && m.index == X86_REG_INVALID && m_picBase)
            addr = m_picBase + (int)m.disp;
        else
            return nullptr;

        // Check if it's in a const data section
        const Section *sec = m_mf.sectionForAddress(addr);
        if (!sec) return nullptr;
        if (sec->sectname != "__const" && sec->sectname != "__literal4" &&
            sec->sectname != "__literal8" && sec->sectname != "__data")
            return nullptr;

        int64_t off = m_mf.fileOffsetForAddress(addr);
        if (off < 0) return nullptr;

        // Check for global variable first
        auto *g = m_types.globalAtAddress(addr);
        if (g) return IRExpr::mkVar(g->name, g->typeRef);

        if (isDouble) {
            const uint8_t *p = m_mf.bytesAt((uint32_t)off, 8);
            if (!p) return nullptr;
            double val;
            memcpy(&val, p, 8);
            char buf[64]; snprintf(buf, sizeof(buf), "%.10g", val);
            // Ensure decimal point for valid C
            if (strchr(buf, '.') == nullptr && strchr(buf, 'e') == nullptr)
                strcat(buf, ".0");
            return IRExpr::mkVar(buf);
        } else {
            const uint8_t *p = m_mf.bytesAt((uint32_t)off, 4);
            if (!p) return nullptr;
            uint32_t bits;
            memcpy(&bits, p, 4);
            // Special IEEE754 bit patterns used as SSE masks
            if (bits == 0x7FFFFFFF) return nullptr;  // fabsf mask — handle at andps level
            if (bits == 0x80000000) return nullptr;  // sign bit mask — handle at xorps level
            uint32_t exp = (bits >> 23) & 0xFF;
            if (exp == 0xFF) return nullptr;  // inf/nan — not a valid float constant
            float val;
            memcpy(&val, &bits, 4);
            char buf[64]; snprintf(buf, sizeof(buf), "%.7g", val);
            // Ensure decimal point for valid C float suffix
            if (strchr(buf, '.') == nullptr && strchr(buf, 'e') == nullptr)
                strcat(buf, ".0");
            strcat(buf, "f");
            return IRExpr::mkVar(buf);
        }
    }

    // Helper: extract a readable string from an IR expr (for intrinsic text)
    static std::string varText(std::unique_ptr<IRExpr> e) {
        return varTextExpr(e.get());
    }

    // Recursive expression-to-string for generating readable C-like text
    static std::string varTextExpr(const IRExpr *e) {
        if (!e) return "0";
        switch (e->op) {
        case IROp::Var:     return e->name;
        case IROp::String:  return e->name;
        case IROp::FuncRef: return e->name;
        case IROp::Const: {
            if (e->value >= -256 && e->value <= 256) return std::to_string(e->value);
            char buf[32]; snprintf(buf, sizeof(buf), "0x%X", (unsigned)(uint32_t)e->value);
            return buf;
        }
        case IROp::Temp: return "t" + std::to_string(e->value);
        case IROp::Field: {
            std::string base = e->kids.empty() ? "0" : varTextExpr(e->kids[0].get());
            return base + "->" + e->name;
        }
        case IROp::Load:
            if (!e->kids.empty())
                return "*(" + varTextExpr(e->kids[0].get()) + ")";
            return "*0";
        case IROp::Add: case IROp::Sub: case IROp::Mul: {
            if (e->kids.size() < 2) return "0";
            std::string l = varTextExpr(e->kids[0].get());
            std::string r = varTextExpr(e->kids[1].get());
            const char *op = e->op == IROp::Add ? " + " :
                             e->op == IROp::Sub ? " - " : " * ";
            return "(" + l + op + r + ")";
        }
        case IROp::Cast:
            if (!e->kids.empty()) return varTextExpr(e->kids[0].get());
            return "0";
        default: return "0";
        }
    }
};
