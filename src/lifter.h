#pragma once
#include "ir.h"
#include "macho.h"
#include <capstone/capstone.h>
#include <list>
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
            m_curSourceFileIdx = sfn->sourceFileIdx;
        } else {
            m_curSourceFileIdx = -1;
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
        std::set<uint32_t> loopHeaderAddrs; // targets of unconditional forward jumps
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
                // Detect loop headers: unconditional forward jumps that skip
                // an increment block (jmp header pattern in while/for loops)
                {
                    std::string jmn = in.mnemonic;
                    if (jmn == "jmp" && target > in.address)
                        loopHeaderAddrs.insert(target);
                }
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

        // ── Pass 2b: pre-compute predecessors for CFG-aware lifting ──
        int nBlocks = (int)func.blocks.size();
        std::vector<std::set<int>> prePreds(nBlocks);
        {
            int prevBlk = 0;
            for (size_t i = 0; i < funcEndIdx; ++i) {
                auto bit2 = addrToBlock.find(insn[i].address);
                if (bit2 != addrToBlock.end()) prevBlk = bit2->second;
                bool isJmp = false, isRet = false, isCond = false;
                if (insn[i].detail) {
                    for (uint8_t g = 0; g < insn[i].detail->groups_count; ++g) {
                        if (insn[i].detail->groups[g] == CS_GRP_JUMP) isJmp = true;
                        if (insn[i].detail->groups[g] == CS_GRP_RET) isRet = true;
                    }
                }
                if (isJmp && std::string(insn[i].mnemonic) != "jmp") isCond = true;
                if (isJmp && insn[i].detail && insn[i].detail->x86.op_count > 0 &&
                    insn[i].detail->x86.operands[0].type == X86_OP_IMM) {
                    uint32_t tgt = (uint32_t)insn[i].detail->x86.operands[0].imm;
                    auto tit = addrToBlock.find(tgt);
                    if (tit != addrToBlock.end() && tit->second < nBlocks)
                        prePreds[tit->second].insert(prevBlk);
                    if (isCond && i + 1 < funcEndIdx) {
                        auto fit = addrToBlock.find(insn[i+1].address);
                        if (fit != addrToBlock.end() && fit->second < nBlocks)
                            prePreds[fit->second].insert(prevBlk);
                    }
                } else if (!isJmp && !isRet && i + 1 < funcEndIdx) {
                    auto nbit = addrToBlock.find(insn[i+1].address);
                    if (nbit != addrToBlock.end() && nbit->second != prevBlk && nbit->second < nBlocks)
                        prePreds[nbit->second].insert(prevBlk);
                }
            }
        }

        // ── Pass 2c: dominator-based loop header detection ──────────
        // Compute immediate dominators from prePreds to identify true loop
        // headers (blocks where a back-edge enters). This is needed before
        // lifting to create phi temps at loop headers.
        std::set<int> domLoopHeaders;
        std::map<int, std::set<x86_reg>> loopWrittenRegs;
        if (nBlocks >= 3) {
            // Compute idom using Cooper-Harvey-Kennedy algorithm
            std::vector<int> idom(nBlocks, -1);
            idom[0] = 0;
            // Build RPO from prePreds (successors implied by who has us as pred)
            std::vector<std::set<int>> succsFromPreds(nBlocks);
            for (int b = 0; b < nBlocks; ++b)
                for (int p : prePreds[b])
                    if (p >= 0 && p < nBlocks) succsFromPreds[p].insert(b);
            std::vector<int> rpo;
            std::vector<int> rpoNum(nBlocks, -1);
            {
                std::vector<bool> vis(nBlocks, false);
                std::vector<int> po;
                std::vector<std::pair<int,int>> stk = {{0, 0}};
                vis[0] = true;
                while (!stk.empty()) {
                    auto &[nd, ci] = stk.back();
                    std::vector<int> sc(succsFromPreds[nd].begin(), succsFromPreds[nd].end());
                    if (ci < (int)sc.size()) {
                        int s = sc[ci++];
                        if (s >= 0 && s < nBlocks && !vis[s]) { vis[s] = true; stk.push_back({s, 0}); }
                    } else { po.push_back(nd); stk.pop_back(); }
                }
                rpo.resize(po.size());
                for (int i = 0; i < (int)po.size(); ++i) {
                    rpo[po.size()-1-i] = po[i];
                    rpoNum[po[i]] = (int)po.size()-1-i;
                }
            }
            auto intersect = [&](int b1, int b2) -> int {
                int limit = nBlocks;
                while (b1 != b2 && limit-- > 0) {
                    while (rpoNum[b1] > rpoNum[b2] && limit-- > 0) b1 = idom[b1];
                    while (rpoNum[b2] > rpoNum[b1] && limit-- > 0) b2 = idom[b2];
                }
                return b1;
            };
            bool changed = true;
            for (int iter = 0; iter < nBlocks && changed; ++iter) {
                changed = false;
                for (int idx = 1; idx < (int)rpo.size(); ++idx) {
                    int b = rpo[idx];
                    int newIdom = -1;
                    for (int p : prePreds[b]) {
                        if (p < 0 || p >= nBlocks || idom[p] == -1) continue;
                        newIdom = (newIdom == -1) ? p : intersect(newIdom, p);
                    }
                    if (newIdom == -1) newIdom = 0;
                    if (idom[b] != newIdom) { idom[b] = newIdom; changed = true; }
                }
            }
            // Find back edges: B→H where H dominates B → H is a loop header
            for (int b = 0; b < nBlocks; ++b) {
                for (int succ : succsFromPreds[b]) {
                    if (succ < 0 || succ >= nBlocks) continue;
                    int runner = b;
                    bool dominates = false;
                    int limit = nBlocks;
                    while (runner >= 0 && limit-- > 0) {
                        if (runner == succ) { dominates = true; break; }
                        if (runner == idom[runner]) break;
                        runner = idom[runner];
                    }
                    if (dominates)
                        domLoopHeaders.insert(succ);
                }
            }
            // For each loop header, scan the loop body to find which GP regs are written
            // Only these regs need phi temps (avoids breaking unmodified param regs)
            // Build back-edge map: header → set of back-edge sources
            std::map<int, std::set<int>> backEdgeSources;
            for (int b = 0; b < nBlocks; ++b)
                for (int succ : succsFromPreds[b]) {
                    if (succ < 0 || succ >= nBlocks) continue;
                    int runner = b; bool dom = false; int lim = nBlocks;
                    while (runner >= 0 && lim-- > 0) {
                        if (runner == succ) { dom = true; break; }
                        if (runner == idom[runner]) break;
                        runner = idom[runner];
                    }
                    if (dom) backEdgeSources[succ].insert(b);
                }
            for (int hdr : domLoopHeaders) {
                // Find loop body blocks: only blocks between header and
                // back-edge sources (not post-loop blocks that happen to be dominated)
                int maxBackSrc = hdr;
                auto beit = backEdgeSources.find(hdr);
                if (beit != backEdgeSources.end())
                    for (int s : beit->second)
                        if (s > maxBackSrc) maxBackSrc = s;
                std::set<int> loopBlocks;
                for (int b = hdr; b <= maxBackSrc; ++b)
                    loopBlocks.insert(b);
                // Scan instructions in loop blocks for written GP registers
                auto &written = loopWrittenRegs[hdr];
                for (size_t ii = 0; ii < funcEndIdx; ++ii) {
                    auto bit2 = addrToBlock.find(insn[ii].address);
                    int blk = (bit2 != addrToBlock.end()) ? bit2->second : -1;
                    if (blk < 0) {
                        // Find containing block
                        for (auto it = addrToBlock.rbegin(); it != addrToBlock.rend(); ++it)
                            if (it->first <= insn[ii].address) { blk = it->second; break; }
                    }
                    if (blk < 0 || !loopBlocks.count(blk)) continue;
                    if (blk == hdr && !backEdgeSources[hdr].count(hdr))
                        continue; // header only counts for self-loop bodies
                    auto *det = insn[ii].detail;
                    if (!det) continue;
                    for (uint8_t oi = 0; oi < det->x86.op_count; ++oi) {
                        auto &op = det->x86.operands[oi];
                        if (op.type == X86_OP_REG &&
                            (op.access & CS_AC_WRITE)) {
                            x86_reg cr = canonReg(op.reg);
                            if (cr == X86_REG_EAX || cr == X86_REG_EBX || cr == X86_REG_ECX ||
                                cr == X86_REG_EDX || cr == X86_REG_ESI || cr == X86_REG_EDI)
                                written.insert(cr);
                        }
                    }
                }
            }
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
        m_insn = insn;
        m_insnCount = funcEndIdx;
        m_regTemps.clear();
        m_regGlobalSource.clear();
        m_regFuncPtrName.clear();
        m_blockExitState.clear();
        m_espArgs.clear();
        m_pushArgs.clear();
        m_tailStackArgs.clear();
        m_fpuStack.clear();
        m_lastFpuTop = -1;
        m_regParamInjected.clear();
        m_flags = {-1, IROp::Eq, nullptr, nullptr};

        // Inject register parameter initializations.
        // Regparm args arrive in EAX, EDX, ECX. Detection:
        // 1. STABS N_RSYM with descriptor 'P' (explicit register param)
        // 2. Prologue pattern: mov [ebp-N], eax/edx/ecx where a STABS param exists
        //    at that stack offset (param saved to stack in prologue)
        m_regParamLocals.clear();

        // Detect additional regparm params from prologue save patterns.
        // If we see "mov [ebp-N], eax/edx/ecx" and STABS has a param at offset N,
        // the param is regparm (arrived in register, saved to stack).
        if (sfn && !func.blocks.empty()) {
            static const x86_reg regparmRegs[] = {X86_REG_EAX, X86_REG_EDX, X86_REG_ECX};
            for (size_t pi = 0; pi < std::min(funcEndIdx, (size_t)15); ++pi) {
                auto &pin = insn[pi];
                std::string pmn = pin.mnemonic;
                if (pmn != "mov") continue;
                if (pin.detail->x86.op_count != 2) continue;
                auto &dst = pin.detail->x86.operands[0];
                auto &src = pin.detail->x86.operands[1];
                if (src.type != X86_OP_REG) continue;
                x86_reg srcR = canonReg(src.reg);
                bool isRegparm = false;
                for (auto rr : regparmRegs) if (srcR == rr) { isRegparm = true; break; }
                if (!isRegparm) continue;
                if (m_regParamRegs.count(srcR)) continue;  // already detected

                if (dst.type == X86_OP_MEM &&
                    dst.mem.base == X86_REG_EBP && dst.mem.index == X86_REG_INVALID &&
                    (int)dst.mem.disp < 0) {
                    // Pattern 1: mov [ebp-N], eax/edx/ecx — save to stack
                    int off = (int)dst.mem.disp;
                    for (auto &p : sfn->params) {
                        if (p.stackOffset == off && p.regNum < 0) {
                            m_regParamRegs[srcR] = &p;
                            break;
                        }
                    }
                } else if (dst.type == X86_OP_REG) {
                    // Pattern 2: mov REG_DEST, eax/edx/ecx — save to callee-saved reg
                    // Check if STABS has a param with regNum matching DEST
                    x86_reg dstR = canonReg(dst.reg);
                    int stabsReg = -1;
                    switch (dstR) {
                        case X86_REG_EAX: stabsReg = 0; break;
                        case X86_REG_ECX: stabsReg = 1; break;
                        case X86_REG_EDX: stabsReg = 2; break;
                        case X86_REG_EBX: stabsReg = 3; break;
                        case X86_REG_ESI: stabsReg = 6; break;
                        case X86_REG_EDI: stabsReg = 7; break;
                        default: break;
                    }
                    if (stabsReg >= 0) {
                        for (auto &p : sfn->params) {
                            if (p.regNum == stabsReg) {
                                m_regParamRegs[srcR] = &p;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (!func.blocks.empty() && !m_regParamRegs.empty()) {
            // Mark this function as using regparm calling convention
            if (sfn) const_cast<StabsFunction*>(sfn)->isRegparm = true;
            auto &bb0 = func.blocks[0];

            // Bind the regparam registers to parameter names
            for (auto &[xr, param] : m_regParamRegs) {
                int t = func.newTemp(param->typeRef);
                bb0.stmts.push_back(IRStmt::mkAssign(t,
                    IRExpr::mkVar(param->name, param->typeRef), param->typeRef));
                m_regTemps[xr] = t;
            }

            // Scan prologue for instructions that SAVE regparam values.
            for (size_t pi = 0; pi < std::min(funcEndIdx, (size_t)20); ++pi) {
                auto &pin = insn[pi];
                std::string pmn = pin.mnemonic;
                if (pmn != "mov" && pmn != "movaps") continue;
                if (pin.detail->x86.op_count != 2) continue;
                auto &dst = pin.detail->x86.operands[0];
                auto &src = pin.detail->x86.operands[1];
                if (src.type != X86_OP_REG) continue;
                x86_reg srcR = canonReg(src.reg);
                auto pit = m_regParamRegs.find(srcR);
                if (pit == m_regParamRegs.end()) continue;

                auto *param = pit->second;
                if (dst.type == X86_OP_REG) {
                    x86_reg dstR = canonReg(dst.reg);
                    if (dstR == srcR) continue;
                    if (m_regTemps.count(dstR)) continue;
                    m_regTemps[dstR] = m_regTemps[srcR];
                } else if (dst.type == X86_OP_MEM &&
                           dst.mem.base == X86_REG_EBP &&
                           dst.mem.index == X86_REG_INVALID &&
                           (int)dst.mem.disp < 0) {
                    int off = (int)dst.mem.disp;
                    if (m_localByOffset.find(off) == m_localByOffset.end()) {
                        m_regParamLocals.push_back({param->name, param->typeRef, off, -1});
                        m_localByOffset[off] = &m_regParamLocals.back();
                    }
                }
            }
        }

        // Save register→temp mapping at each block end for join-point analysis
        std::map<int, std::map<x86_reg, int>> blockEndRegs;
        int curBlock = 0;
        for (size_t i = 0; i < funcEndIdx; ++i) {
            auto &in = insn[i];
            // Check if this starts a new block
            auto bit = addrToBlock.find(in.address);
            if (bit != addrToBlock.end()) {
                // Save previous block's register state
                blockEndRegs[curBlock] = m_regTemps;
                saveBlockState(curBlock);
                int prevBlock = curBlock;
                curBlock = bit->second;
                // Restore register state from the block's real CFG
                // predecessors. Address order often places an unrelated block
                // between a conditional branch and its taken target; carrying
                // registers linearly through that unrelated block leaks stale
                // call-clobbered values into the target.
                if (curBlock > 0 && curBlock < nBlocks &&
                    prevBlock >= 0 && prevBlock != curBlock) {
                    bool allPredsProcessed = !prePreds[curBlock].empty();
                    for (int p : prePreds[curBlock]) {
                        if (!m_blockExitState.count(p)) {
                            allPredsProcessed = false;
                            break;
                        }
                    }
                    bool isLoopHeader =
                        domLoopHeaders.count(curBlock) ||
                        loopHeaderAddrs.count(in.address);
                    bool linearPredecessor = prePreds[curBlock].count(prevBlock) != 0;
                    if (!isLoopHeader && !linearPredecessor && allPredsProcessed &&
                        prePreds[curBlock].size() == 1) {
                        mergeBlockState(curBlock, prePreds, func);
                    } else if (nBlocks >= 50 && !linearPredecessor) {
                        m_regTemps.clear();
                        m_regGlobalSource.clear();
                        m_regFuncPtrName.clear();
                        m_flags = {-1, IROp::Eq, nullptr, nullptr};
                    }
                }
                // At dominator-confirmed loop headers (not already handled by
                // heuristic), create phi temps ONLY for registers written in
                // the loop body. This avoids breaking unmodified param registers.
                if (curBlock > 0 && domLoopHeaders.count(curBlock) &&
                    !loopHeaderAddrs.count(in.address)) {
                    auto &hdr = func.blocks[curBlock];
                    auto wit = loopWrittenRegs.find(curBlock);
                    if (wit != loopWrittenRegs.end()) {
                        for (x86_reg reg : wit->second) {
                            auto it = m_regTemps.find(reg);
                            if (it != m_regTemps.end()) {
                                int oldTemp = it->second;
                                TypeRef tt = func.tempType(oldTemp);
                                int newTemp = func.newTemp(tt);
                                func.phiTemps.insert(newTemp);
                                hdr.stmts.push_back(IRStmt::mkAssign(newTemp,
                                    IRExpr::mkTemp(oldTemp, tt), tt));
                                m_regTemps[reg] = newTemp;
                                // Propagate variable mapping so phi temp gets a name
                                auto vit = func.tempToVar.find(oldTemp);
                                if (vit != func.tempToVar.end())
                                    func.tempToVar[newTemp] = vit->second;
                            }
                        }
                    }
                    m_regGlobalSource.clear();
                    m_regFuncPtrName.clear();
                }
                // At heuristic loop headers (jmp-forward targets), create phi temps
                if (curBlock > 0 && loopHeaderAddrs.count(in.address)) {
                    auto &hdr = func.blocks[curBlock];
                    static const x86_reg gpRegs[] = {
                        X86_REG_EAX, X86_REG_EBX, X86_REG_ECX,
                        X86_REG_EDX, X86_REG_ESI, X86_REG_EDI
                    };
                    for (x86_reg reg : gpRegs) {
                        auto it = m_regTemps.find(reg);
                        if (it != m_regTemps.end()) {
                            int oldTemp = it->second;
                            // Skip phi creation for struct pointer temps — changing
                            // their identity breaks field access and type coalescing.
                            // Just clear the global source info instead.
                            TypeRef tt = func.tempType(oldTemp);
                            if (tt != NullType && m_types.isStructPointer(tt)) {
                                m_regGlobalSource.erase(reg);
                                m_regFuncPtrName.erase(reg);
                                continue;
                            }
                            int newTemp = func.newTemp(tt);
                            func.phiTemps.insert(newTemp);
                            hdr.stmts.push_back(IRStmt::mkAssign(newTemp,
                                IRExpr::mkTemp(oldTemp, tt), tt));
                            m_regTemps[reg] = newTemp;
                            m_regGlobalSource.erase(reg);
                            m_regFuncPtrName.erase(reg);
                        }
                    }
                }
            }

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

            }
            liftInsn(in, func.blocks[curBlock], func, addrToBlock);
        }
        blockEndRegs[curBlock] = m_regTemps; // save final block's state
        saveBlockState(curBlock);

        // ── Pass 5b: ensure float functions have proper return ───────
        // The ret instruction may fall outside STABS-reported function size.
        // If the last block has no Return and the function returns float/double,
        // synthesize one from the last FPU stack value.
        if (sfn && sfn->returnType != NullType && !func.blocks.empty()) {
            auto *rt = m_types.resolveType(sfn->returnType);

            if (rt && (rt->kind == StabsTypeKind::Float ||
                       rt->kind == StabsTypeKind::Double ||
                       rt->kind == StabsTypeKind::LongDouble)) {
                // Check if any block has a Return statement
                bool hasReturn = false;
                for (auto &bb : func.blocks)
                    for (auto &s : bb.stmts)
                        if (s.kind == IRStmtKind::Return) { hasReturn = true; break; }

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

        // ── Pass 6: merge SSE float compare branches ─────────────────
        // Pattern: BB_A ends with jp(NaN check) → BB_C; fallthrough → BB_B
        //          BB_B has only one Branch: jb/jbe/ja/jae → BB_D
        // This is ucomiss + jp + jcc. The jp handles NaN, jcc is the real compare.
        // Merge: remove BB_A's jp branch, keep BB_B's comparison.
        // The jp target (BB_C) must be BB_B's fallthrough (NaN skips the error check).
        for (int bi = 0; bi < (int)func.blocks.size(); ++bi) {
            auto &bbA = func.blocks[bi];
            if (bbA.stmts.empty()) continue;
            auto &brA = bbA.stmts.back();
            if (brA.kind != IRStmtKind::Branch || !brA.expr) continue;
            // Check if this is a jp(x != x) = NaN check
            if (brA.expr->op != IROp::Ne) continue;
            if (!brA.expr->kids[0] || !brA.expr->kids[1]) continue;
            // x != x pattern (both sides are the same expression)
            bool isNanCheck = false;
            if (brA.expr->kids[0]->op == IROp::Temp && brA.expr->kids[1]->op == IROp::Temp &&
                brA.expr->kids[0]->tempId() == brA.expr->kids[1]->tempId())
                isNanCheck = true;
            if (!isNanCheck) continue;

            int jpTarget = brA.trueTarget;   // where NaN goes
            int fallBB = brA.falseTarget;     // the real comparison BB
            if (fallBB < 0 || fallBB >= (int)func.blocks.size()) continue;

            auto &bbB = func.blocks[fallBB];
            if (bbB.stmts.empty()) continue;
            // Case 1: BB_B has exactly one statement (a Branch) — merge jp with the real comparison
            if (bbB.stmts.size() == 1 && bbB.stmts[0].kind == IRStmtKind::Branch) {
                auto &brB = bbB.stmts[0];
                // BB_B's fallthrough should be the jp target (NaN skips to same place)
                if (brB.falseTarget != jpTarget && brB.trueTarget != jpTarget) continue;
                // Merge: replace BB_A's branch with BB_B's branch
                brA.expr = brB.expr->clone();
                brA.trueTarget = brB.trueTarget;
                brA.falseTarget = brB.falseTarget;
                // Clear BB_B (now dead)
                bbB.stmts.clear();
                bbB.succs.clear();
                continue;
            }
            // Case 2: BB_B has multiple statements — jp not safe to eliminate here
        }


        // ── Pass 6a: bypass empty blocks ──────────────────────────────
        // After pass 6 clears jp blocks, some empty blocks remain as
        // intermediaries. Redirect branches that target empty blocks to
        // the empty block's sole successor.
        {
            // Build successor map for empty blocks
            std::map<int, int> emptySucc;
            for (int bi = 0; bi < (int)func.blocks.size(); ++bi) {
                auto &bb = func.blocks[bi];
                if (!bb.stmts.empty()) continue;
                if (bb.succs.size() == 1)
                    emptySucc[bi] = bb.succs[0];
                else if (bb.succs.empty() && bi + 1 < (int)func.blocks.size())
                    emptySucc[bi] = bi + 1; // fallthrough to next block
            }
            // Follow chains: if an empty block points to another empty block
            for (auto &[src, dst] : emptySucc) {
                int d = dst;
                for (int i = 0; i < 5 && emptySucc.count(d); ++i) d = emptySucc[d];
                emptySucc[src] = d;
            }
            // Redirect all branches targeting empty blocks
            if (!emptySucc.empty()) {
                for (auto &bb : func.blocks) {
                    for (auto &stmt : bb.stmts) {
                        if (stmt.kind == IRStmtKind::Branch) {
                            auto it = emptySucc.find(stmt.trueTarget);
                            if (it != emptySucc.end()) stmt.trueTarget = it->second;
                            it = emptySucc.find(stmt.falseTarget);
                            if (it != emptySucc.end()) stmt.falseTarget = it->second;
                        }
                    }
                }
            }
        }

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

        // ── Pass 7b: fix XMM register conflicts at join points ─────
        // When a block has 2+ predecessors that write DIFFERENT temps to the
        // same XMM register, and the join block reads that register, the linear
        // processing order causes only one predecessor's temp to be visible.
        // Fix: for each such conflict, convert the Assign to a VarSet to a shared
        // local in ALL predecessors, and rewrite the join block's use.
        {
            for (auto &bb : func.blocks) {
                if (bb.preds.size() < 2) continue;
                // For each XMM register (XMM0-XMM7), check if predecessors
                // have different temps at block end
                for (int xr = X86_REG_XMM0; xr <= X86_REG_XMM7; ++xr) {
                    x86_reg reg = (x86_reg)xr;
                    std::map<int, int> predTempForReg; // predId → temp for this reg
                    bool hasConflict = false;
                    int firstTemp = -1;
                    for (int pid : bb.preds) {
                        auto bit = blockEndRegs.find(pid);
                        if (bit == blockEndRegs.end()) continue;
                        auto rit = bit->second.find(reg);
                        if (rit == bit->second.end()) continue;
                        predTempForReg[pid] = rit->second;
                        if (firstTemp < 0) firstTemp = rit->second;
                        else if (rit->second != firstTemp) hasConflict = true;
                    }
                    if (!hasConflict || predTempForReg.size() < 2) continue;
                    // Only fix conflicts where the predecessor that defines the
                    // temp used in the join block assigns a float CONSTANT.
                    // This targets the pattern where different predecessors
                    // load different float constants for a return value.
                    // Skip general register reuse (computation results).
                    {
                        int constPreds = 0;
                        for (auto &[pid, tid] : predTempForReg) {
                            if (pid < 0 || pid >= (int)func.blocks.size()) continue;
                            for (auto &s : func.blocks[pid].stmts) {
                                if (s.kind == IRStmtKind::Assign && s.destTemp == tid && s.expr) {
                                    if (s.expr->op == IROp::Var) {
                                        auto &nm = s.expr->name;
                                        if (!nm.empty() && (nm.back() == 'f' || nm.find('.') != std::string::npos))
                                            constPreds++;
                                    }
                                    if (s.expr->isConst()) constPreds++;
                                }
                            }
                        }
                        if (constPreds < 2) continue;  // Need at least 2 constant-assigning preds
                    }
                    // Check if the join block uses any of these conflicting temps
                    int usedTemp = -1;
                    for (auto &[pid, tid] : predTempForReg) {
                        int capturedTid = tid;
                        for (auto &stmt : bb.stmts) {
                            // Non-recursive scan for temp ID
                            auto checkExpr = [&](const IRExpr *e) -> bool {
                                if (!e) return false;
                                std::vector<const IRExpr*> stk = {e};
                                while (!stk.empty()) {
                                    auto *n = stk.back(); stk.pop_back();
                                    if (n->op == IROp::Temp && n->tempId() == capturedTid) return true;
                                    for (auto &k : n->kids) if (k) stk.push_back(k.get());
                                }
                                return false;
                            };
                            if (checkExpr(stmt.expr.get()) || checkExpr(stmt.addr.get()))
                                { usedTemp = capturedTid; break; }
                        }
                        if (usedTemp >= 0) break;
                    }
                    if (usedTemp < 0) continue;
                    // Conflict detected! Create a shared variable name
                    std::string varName = "var_xmm" + std::to_string(xr - X86_REG_XMM0);
                    // In each predecessor, convert the last Assign for this temp to VarSet
                    for (auto &[pid, tid] : predTempForReg) {
                        if (pid < 0 || pid >= (int)func.blocks.size()) continue;
                        auto &predBB = func.blocks[pid];
                        // Find the Assign(tid, value) in this predecessor
                        for (int si = (int)predBB.stmts.size() - 1; si >= 0; --si) {
                            auto &s = predBB.stmts[si];
                            if (s.kind == IRStmtKind::Assign && s.destTemp == tid) {
                                // Insert a VarSet AFTER this Assign
                                auto vs = IRStmt::mkVarSet(varName, IRExpr::mkTemp(tid, func.tempType(tid)));
                                predBB.stmts.insert(predBB.stmts.begin() + si + 1, std::move(vs));
                                break;
                            }
                        }
                    }
                    // In the join block, replace uses of usedTemp with Var(varName)
                    for (auto &stmt : bb.stmts) {
                        auto replaceTemp = [&](std::unique_ptr<IRExpr> &e) {
                            if (!e) return;
                            std::vector<IRExpr*> stk = {e.get()};
                            while (!stk.empty()) {
                                auto *n = stk.back(); stk.pop_back();
                                for (auto &k : n->kids) {
                                    if (k && k->op == IROp::Temp && k->tempId() == usedTemp)
                                        k = IRExpr::mkVar(varName);
                                    else if (k) stk.push_back(k.get());
                                }
                            }
                            if (e->op == IROp::Temp && e->tempId() == usedTemp)
                                e = IRExpr::mkVar(varName);
                        };
                        replaceTemp(stmt.expr);
                        replaceTemp(stmt.addr);
                    }
                }
            }
        }

        // ── Pass 7c: fix GP register conflicts at non-loop joins ───
        // Forward joins can be reached before all address-later predecessors
        // have been lifted.  In that case the join block is emitted using one
        // predecessor's register temps, and equivalent temps from later
        // predecessors look unused.  Materialize a phi-like temp at the end of
        // each predecessor and use it inside the join block.
        {
            auto insertBeforeTerminator = [](BasicBlock &predBlock, IRStmt copy) {
                if (!predBlock.stmts.empty()) {
                    auto k = predBlock.stmts.back().kind;
                    if (k == IRStmtKind::Branch || k == IRStmtKind::Jump ||
                        k == IRStmtKind::Switch || k == IRStmtKind::Return)
                        predBlock.stmts.insert(predBlock.stmts.end() - 1, std::move(copy));
                    else
                        predBlock.stmts.push_back(std::move(copy));
                } else {
                    predBlock.stmts.push_back(std::move(copy));
                }
            };
            auto exprUsesAnyTemp = [](const IRExpr *e, const std::set<int> &temps) -> bool {
                if (!e) return false;
                std::vector<const IRExpr*> stk = {e};
                while (!stk.empty()) {
                    auto *n = stk.back();
                    stk.pop_back();
                    if (n->op == IROp::Temp && temps.count(n->tempId()))
                        return true;
                    for (auto &k : n->kids)
                        if (k) stk.push_back(k.get());
                }
                return false;
            };
            auto replaceTemps = [](std::unique_ptr<IRExpr> &e,
                                   const std::set<int> &oldTemps,
                                   int newTemp, TypeRef newType) {
                if (!e) return;
                if (e->op == IROp::Temp && oldTemps.count(e->tempId())) {
                    e = IRExpr::mkTemp(newTemp, newType);
                    return;
                }
                std::vector<IRExpr*> stk = {e.get()};
                while (!stk.empty()) {
                    auto *n = stk.back();
                    stk.pop_back();
                    for (auto &k : n->kids) {
                        if (k && k->op == IROp::Temp &&
                            oldTemps.count(k->tempId()))
                            k = IRExpr::mkTemp(newTemp, newType);
                        else if (k)
                            stk.push_back(k.get());
                    }
                }
            };
            auto tempIsAggregateValue = [&](int tid) -> bool {
                bool hasDrilledFieldDef = false;
                for (auto &pb : func.blocks) {
                    for (auto &s : pb.stmts) {
                        if (s.kind == IRStmtKind::Assign && s.destTemp == tid &&
                            s.expr && s.expr->op == IROp::Field &&
                            (s.expr->name.find('.') != std::string::npos ||
                             s.expr->name.find('[') != std::string::npos)) {
                            hasDrilledFieldDef = true;
                            break;
                        }
                    }
                    if (hasDrilledFieldDef)
                        break;
                }
                if (hasDrilledFieldDef)
                    return false;
                TypeRef tr = func.tempType(tid);
                if (tr != NullType) {
                    auto *tt = m_types.resolveType(tr);
                    if (tt && (tt->kind == StabsTypeKind::Struct ||
                               tt->kind == StabsTypeKind::Union ||
                               tt->kind == StabsTypeKind::Array))
                        return true;
                }
                for (auto &pb : func.blocks) {
                    for (auto &s : pb.stmts) {
                        if (s.kind != IRStmtKind::Assign || s.destTemp != tid ||
                            !s.expr)
                            continue;
                        TypeRef et = s.expr->typeRef;
                        if (et == NullType && s.expr->op == IROp::Var) {
                            if (auto *g = m_types.globalByName(s.expr->name))
                                et = g->typeRef;
                            if (et == NullType) {
                                for (auto &p : func.params)
                                    if (p.name == s.expr->name) { et = p.typeRef; break; }
                            }
                            if (et == NullType) {
                                for (auto &l : func.locals)
                                    if (l.name == s.expr->name) { et = l.typeRef; break; }
                            }
                        }
                        if (et != NullType) {
                            auto *etInfo = m_types.resolveType(et);
                            if (etInfo && (etInfo->kind == StabsTypeKind::Struct ||
                                           etInfo->kind == StabsTypeKind::Union ||
                                           etInfo->kind == StabsTypeKind::Array))
                                return true;
                        }
                    }
                }
                return false;
            };

            static const x86_reg gpRegs[] = {
                X86_REG_EAX, X86_REG_EBX, X86_REG_ECX,
                X86_REG_EDX, X86_REG_ESI, X86_REG_EDI
            };
            for (auto &bb : func.blocks) {
                if (bb.preds.size() < 2 || bb.isLoopHeader ||
                    domLoopHeaders.count(bb.id) ||
                    loopHeaderAddrs.count(bb.startAddr))
                    continue;
                for (x86_reg reg : gpRegs) {
                    std::map<int, int> predTempForReg;
                    int firstTemp = -1;
                    bool hasConflict = false;
                    bool missingPred = false;
                    for (int pid : bb.preds) {
                        auto bit = blockEndRegs.find(pid);
                        if (bit == blockEndRegs.end()) { missingPred = true; break; }
                        auto rit = bit->second.find(reg);
                        if (rit == bit->second.end()) { missingPred = true; break; }
                        predTempForReg[pid] = rit->second;
                        if (firstTemp < 0)
                            firstTemp = rit->second;
                        else if (rit->second != firstTemp)
                            hasConflict = true;
                    }
                    if (missingPred || !hasConflict)
                        continue;

                    std::set<int> sourceTemps;
                    for (auto &[pid, tid] : predTempForReg)
                        sourceTemps.insert(tid);
                    bool hasAggregateSource = false;
                    for (int tid : sourceTemps) {
                        if (tempIsAggregateValue(tid)) {
                            hasAggregateSource = true;
                            break;
                        }
                    }
                    if (hasAggregateSource)
                        continue;

                    bool usedInJoin = false;
                    for (auto &stmt : bb.stmts) {
                        if (exprUsesAnyTemp(stmt.expr.get(), sourceTemps) ||
                            exprUsesAnyTemp(stmt.addr.get(), sourceTemps)) {
                            usedInJoin = true;
                            break;
                        }
                        for (auto &a : stmt.args) {
                            if (exprUsesAnyTemp(a.get(), sourceTemps)) {
                                usedInJoin = true;
                                break;
                            }
                        }
                        if (usedInJoin)
                            break;
                    }
                    if (!usedInJoin)
                        continue;

                    TypeRef phiType = func.tempType(firstTemp);
                    int phiTemp = func.newTemp(phiType);
                    func.phiTemps.insert(phiTemp);
                    for (auto &[pid, tid] : predTempForReg) {
                        if (pid < 0 || pid >= (int)func.blocks.size())
                            continue;
                        auto copy = IRStmt::mkAssign(
                            phiTemp, IRExpr::mkTemp(tid, func.tempType(tid)),
                            func.tempType(tid));
                        insertBeforeTerminator(func.blocks[pid], std::move(copy));
                        blockEndRegs[pid][reg] = phiTemp;
                    }

                    for (auto &stmt : bb.stmts) {
                        replaceTemps(stmt.expr, sourceTemps, phiTemp, phiType);
                        replaceTemps(stmt.addr, sourceTemps, phiTemp, phiType);
                        for (auto &a : stmt.args)
                            replaceTemps(a, sourceTemps, phiTemp, phiType);
                    }
                }
            }
        }

        // ── Pass 8: fix loop-carried register state ────────────────
        if ((int)func.blocks.size() >= 3) {
            // Compute dominators
            int n = (int)func.blocks.size();
            func.idom.assign(n, -1);
            func.idom[0] = 0;
            if (n > 1) {
                std::vector<int> rpo;
                std::vector<int> rpoNum(n, -1);
                {
                    std::vector<bool> vis(n, false);
                    std::vector<int> po;
                    std::vector<std::pair<int,int>> stk = {{0, 0}};
                    vis[0] = true;
                    while (!stk.empty()) {
                        auto &[nd, ci] = stk.back();
                        auto &sc = func.blocks[nd].succs;
                        if (ci < (int)sc.size()) {
                            int s = sc[ci++];
                            if (s >= 0 && s < n && !vis[s]) { vis[s] = true; stk.push_back({s, 0}); }
                        } else { po.push_back(nd); stk.pop_back(); }
                    }
                    rpo.resize(po.size());
                    for (int i = 0; i < (int)po.size(); ++i) {
                        rpo[po.size()-1-i] = po[i];
                        rpoNum[po[i]] = (int)po.size()-1-i;
                    }
                }
                auto intersect = [&](int b1, int b2) -> int {
                    while (b1 != b2) {
                        while (rpoNum[b1] > rpoNum[b2]) b1 = func.idom[b1];
                        while (rpoNum[b2] > rpoNum[b1]) b2 = func.idom[b2];
                    }
                    return b1;
                };
                bool changed = true;
                for (int iter = 0; iter < n && changed; ++iter) {
                    changed = false;
                    for (int idx = 1; idx < (int)rpo.size(); ++idx) {
                        int b = rpo[idx];
                        int newIdom = -1;
                        for (int p : func.blocks[b].preds) {
                            if (p < 0 || p >= n || func.idom[p] == -1) continue;
                            newIdom = (newIdom == -1) ? p : intersect(newIdom, p);
                        }
                        if (newIdom == -1) newIdom = 0;
                        if (func.idom[b] != newIdom) { func.idom[b] = newIdom; changed = true; }
                    }
                }
            }

            // Detect back edges: B→H where H dominates B
            std::map<int, std::set<int>> loopHeaders;
            for (auto &bb : func.blocks) {
                for (int succ : bb.succs) {
                    if (succ < 0 || succ >= n) continue;
                    int runner = bb.id;
                    bool dominates = false;
                    int limit = n;
                    while (runner >= 0 && limit-- > 0) {
                        if (runner == succ) { dominates = true; break; }
                        if (runner == func.idom[runner]) break;
                        runner = func.idom[runner];
                    }
                    if (dominates)
                        loopHeaders[succ].insert(bb.id);
                }
            }

            // Pre-compute dominator children for efficient subtree queries
            std::vector<std::vector<int>> domChildren(n);
            for (int b = 1; b < n; ++b)
                if (func.idom[b] >= 0 && func.idom[b] < n)
                    domChildren[func.idom[b]].push_back(b);

            for (auto &[headerId, backEdgeSources] : loopHeaders) {
                auto &header = func.blocks[headerId];

                // Efficiently find all blocks dominated by header (DFS on dom tree)
                std::set<int> loopBlocks;
                {
                    std::vector<int> stk = {headerId};
                    while (!stk.empty()) {
                        int b = stk.back(); stk.pop_back();
                        loopBlocks.insert(b);
                        for (int c : domChildren[b]) stk.push_back(c);
                    }
                }

                // Collect induction patterns from latch blocks: t2 = t1 + const.
                // Restricting to back-edge sources avoids treating derived address
                // setup inside the loop body as loop-carried state.
                // Map: baseTemp → loopTemp for each induction variable
                std::map<int, int> inductionMap; // baseTemp → updatedTemp
                for (int bi : loopBlocks) {
                    if (!backEdgeSources.count(bi)) continue;
                    auto &lb = func.blocks[bi];
                    for (auto &stmt : lb.stmts) {
                        if (stmt.kind != IRStmtKind::Assign || stmt.destTemp < 0) continue;
                        if (!stmt.expr) continue;
                        if ((stmt.expr->op == IROp::Add || stmt.expr->op == IROp::Sub) &&
                            stmt.expr->kids.size() == 2) {
                            auto *lhs = stmt.expr->kids[0].get();
                            auto *rhs = stmt.expr->kids[1].get();
                            int baseTemp = -1;
                            if (lhs && lhs->op == IROp::Temp && rhs && rhs->isConst())
                                baseTemp = lhs->tempId();
                            else if (rhs && rhs->op == IROp::Temp && lhs && lhs->isConst())
                                baseTemp = rhs->tempId();
                            if (baseTemp >= 0)
                                inductionMap[baseTemp] = stmt.destTemp;
                        }
                    }
                }

                // Limit: only process a few induction variables per loop
                // to avoid cascading replacements and performance issues
                int inductionCount = 0;
                for (auto &[baseTemp, loopTemp] : inductionMap) {
                    if (inductionCount++ >= 5) break; // limit per loop

                    // Sanity: skip if baseTemp == loopTemp (no actual induction)
                    if (baseTemp == loopTemp) continue;
                    // Avoid cascading through freshly-created non-phi temps.
                    // Header phi temps are legitimate loop-carried bases; fresh
                    // derived address temps are not.
                    if (baseTemp >= func.nextTemp - 20 &&
                        !func.phiTemps.count(baseTemp))
                        continue;

                    auto insertBeforeTerminator = [&](BasicBlock &predBlock,
                                                      IRStmt copy) {
                        if (!predBlock.stmts.empty()) {
                            auto k = predBlock.stmts.back().kind;
                            if (k == IRStmtKind::Branch || k == IRStmtKind::Jump ||
                                k == IRStmtKind::Switch || k == IRStmtKind::Return)
                                predBlock.stmts.insert(predBlock.stmts.end() - 1,
                                                       std::move(copy));
                            else
                                predBlock.stmts.push_back(std::move(copy));
                        } else {
                            predBlock.stmts.push_back(std::move(copy));
                        }
                    };

                    if (func.phiTemps.count(baseTemp)) {
                        std::unique_ptr<IRExpr> initialExpr;
                        TypeRef phiType = func.tempType(baseTemp);
                        for (auto it = header.stmts.begin();
                             it != header.stmts.end(); ++it) {
                            if (it->kind == IRStmtKind::Assign &&
                                it->destTemp == baseTemp) {
                                if (it->expr) initialExpr = it->expr->clone();
                                header.stmts.erase(it);
                                break;
                            }
                        }

                        for (int pred : header.preds) {
                            if (pred < 0 || pred >= n) continue;
                            auto &predBlock = func.blocks[pred];
                            std::unique_ptr<IRExpr> src =
                                backEdgeSources.count(pred)
                                    ? IRExpr::mkTemp(loopTemp,
                                                     func.tempType(loopTemp))
                                    : (initialExpr ? initialExpr->clone()
                                                   : IRExpr::mkTemp(baseTemp,
                                                       phiType));
                            insertBeforeTerminator(predBlock,
                                IRStmt::mkAssign(baseTemp, std::move(src),
                                                 phiType));
                        }
                        continue;
                    }

                    int phiTemp = func.newTemp(func.tempType(baseTemp));
                    func.phiTemps.insert(phiTemp); // mark as phi for copy-prop skip
                    bool hasSources = false;
                    for (int pred : header.preds) {
                        if (pred < 0 || pred >= n) continue;
                        auto &predBlock = func.blocks[pred];
                        int srcTemp = backEdgeSources.count(pred) ? loopTemp : baseTemp;
                        // Insert copy before the terminal statement
                        auto copy = IRStmt::mkAssign(phiTemp,
                            IRExpr::mkTemp(srcTemp, func.tempType(srcTemp)),
                            func.tempType(srcTemp));
                        insertBeforeTerminator(predBlock, std::move(copy));
                        hasSources = true;
                    }
                    if (!hasSources) continue;

                    // Replace baseTemp → phiTemp in all loop blocks
                    int capturedBase = baseTemp;
                    for (int bi : loopBlocks) {
                        auto &lb = func.blocks[bi];
                        for (auto &stmt : lb.stmts) {
                            if (stmt.kind == IRStmtKind::Phi) continue;
                            auto replTemp = [&](std::unique_ptr<IRExpr> &e) {
                                if (!e) return;
                                std::vector<IRExpr*> stk = {e.get()};
                                while (!stk.empty()) {
                                    auto *nd = stk.back(); stk.pop_back();
                                    if (nd->op == IROp::Temp && nd->tempId() == capturedBase)
                                        nd->value = phiTemp;
                                    for (auto &k : nd->kids) if (k) stk.push_back(k.get());
                                }
                            };
                            replTemp(stmt.expr);
                            replTemp(stmt.addr);
                            for (auto &a : stmt.args) replTemp(a);
                        }
                    }
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
    int                   m_curSourceFileIdx = -1;  // CU of current function
    csh                   m_cs;

    // Prologue/PIC state
    bool     m_hasFrame = false;
    int      m_frameSize = 0;
    size_t   m_prologueEnd = 0;
    bool     m_hasPIC = false;
    uint32_t m_picBase = 0;
    uint32_t m_picThunkAddr = 0;
    bool     m_suppressNextNot = false;  // after repne scasb (strlen), skip next NOT

    // Param/local lookup
    std::map<int, const StabsTypedVar*> m_paramByOffset;
    std::map<int, const StabsTypedVar*> m_localByOffset;
    std::map<x86_reg, const StabsTypedVar*> m_regParamRegs;  // register params (regparm)
    std::set<x86_reg> m_regParamInjected;  // which reg params we've already injected
    std::list<StabsTypedVar> m_regParamLocals;  // stable storage for regparm stack locals
    // Instruction array reference (set during lift)
    cs_insn *m_insn = nullptr;
    size_t m_insnCount = 0;

    // Cache: which call target addresses use regparm(3) (static — shared across all lifts)
    static inline std::map<uint32_t, bool> m_regparmCache;

    struct StackArrayAccess {
        const StabsTypedVar *local = nullptr;
        TypeRef arrayType = NullType;
        TypeRef elemType = NullType;
        int elemSize = 0;
        int arraySize = 0;
        int byteOffset = 0;
        int elemIndex = 0;
    };

    int arrayElemSize(const StabsTypeInfo *arrayType) const {
        if (!arrayType || arrayType->kind != StabsTypeKind::Array)
            return 0;
        auto *elem = m_types.resolveType(arrayType->targetType);
        return elem && elem->sizeBytes > 0 ? elem->sizeBytes : 0;
    }

    int arrayStorageSize(const StabsTypeInfo *arrayType) const {
        if (!arrayType || arrayType->kind != StabsTypeKind::Array)
            return 0;
        if (arrayType->sizeBytes > 0)
            return arrayType->sizeBytes;
        int elemSz = arrayElemSize(arrayType);
        int count = arrayType->arrayHigh - arrayType->arrayLow + 1;
        if (elemSz > 0 && count > 0)
            return elemSz * count;
        return 0;
    }

    bool stackArrayAtOffset(int disp, StackArrayAccess &out) const {
        const StabsTypedVar *bestLocal = nullptr;
        const StabsTypeInfo *bestArray = nullptr;
        int bestByteOffset = 0x7fffffff;

        for (auto &[off, loc] : m_localByOffset) {
            auto *arrayType = m_types.resolveType(loc->typeRef);
            if (!arrayType || arrayType->kind != StabsTypeKind::Array)
                continue;
            int elemSz = arrayElemSize(arrayType);
            int arraySz = arrayStorageSize(arrayType);
            if (elemSz <= 0 || arraySz <= 0)
                continue;
            if (disp < off || disp >= off + arraySz)
                continue;
            int byteOffset = disp - off;
            if (byteOffset < bestByteOffset) {
                bestLocal = loc;
                bestArray = arrayType;
                bestByteOffset = byteOffset;
            }
        }

        if (!bestLocal || !bestArray)
            return false;
        int elemSz = arrayElemSize(bestArray);
        if (elemSz <= 0 || bestByteOffset % elemSz != 0)
            return false;
        out.local = bestLocal;
        out.arrayType = bestLocal->typeRef;
        out.elemType = bestArray->targetType;
        out.elemSize = elemSz;
        out.arraySize = arrayStorageSize(bestArray);
        out.byteOffset = bestByteOffset;
        out.elemIndex = bestByteOffset / elemSz;
        return true;
    }

    static std::string stackArrayElementName(const StackArrayAccess &access) {
        char name[256];
        snprintf(name, sizeof(name), "%s[%d]",
                 access.local->name.c_str(), access.elemIndex);
        return name;
    }

    std::unique_ptr<IRExpr> stackIndexedArrayAddress(x86_op_mem &m,
                                                     int accessSize,
                                                     StackArrayAccess *outAccess = nullptr) {
        if (m.base != X86_REG_EBP || m.index == X86_REG_INVALID ||
            m.disp >= 0 || accessSize <= 0)
            return nullptr;

        StackArrayAccess access;
        if (!stackArrayAtOffset((int)m.disp, access))
            return nullptr;
        if (access.elemSize <= 0 || accessSize != access.elemSize)
            return nullptr;

        auto index = readReg(m.index);
        if (!index)
            return nullptr;

        if ((int)m.scale != access.elemSize) {
            if (access.elemSize != 1 || m.scale <= 1)
                return nullptr;
            index = IRExpr::mkBinary(IROp::Mul, std::move(index),
                                     IRExpr::mkConst((int)m.scale));
        }
        if (access.elemIndex != 0) {
            index = IRExpr::mkBinary(IROp::Add, std::move(index),
                                     IRExpr::mkConst(access.elemIndex));
        }

        if (outAccess)
            *outAccess = access;
        return IRExpr::mkBinary(
            IROp::Add,
            IRExpr::mkVar(access.local->name, access.arrayType),
            std::move(index));
    }

    // Detect if a function at the given address uses regparm calling convention
    // by scanning its prologue bytes for: mov [ebp-N], eax/edx/ecx patterns.
    // Uses raw byte scanning for speed (no Capstone disassembly needed).
    bool isCalleeRegparm(uint32_t addr) {
        auto cit = m_regparmCache.find(addr);
        if (cit != m_regparmCache.end()) return cit->second;
        bool result = false;
        const StabsFunction *sf = m_mf.stabsFunctionAt(addr);
        if (sf && sf->isRegparm) { result = true; }
        else if (sf && !sf->params.empty()) {
            int64_t fo = m_mf.fileOffsetForAddress(addr);
            if (fo >= 0) {
                const uint8_t *code = m_mf.bytesAt((uint32_t)fo, 32);
                if (code) {
                    // Scan prologue for regparm patterns in first 32 bytes:
                    // 1. mov [ebp-N], eax/edx/ecx (save to stack)
                    // 2. mov edi/esi/ebx, eax/edx/ecx (save to callee-saved reg)
                    int regSaves = 0;
                    for (int i = 0; i < 28; ++i) {
                        if (code[i] == 0x89 && i + 1 < 32) {
                            uint8_t modrm = code[i+1];
                            uint8_t srcReg = (modrm >> 3) & 7;
                            // Pattern 1: mov [ebp+disp8], eax/ecx/edx
                            if (i + 2 < 32 && (modrm & 0xC7) == 0x45) {
                                int8_t disp = (int8_t)code[i+2];
                                if (disp < 0 && (srcReg == 0 || srcReg == 1 || srcReg == 2))
                                    regSaves++;
                            }
                            // Pattern 2: mov reg, eax/ecx/edx (reg-to-reg, mod=11)
                            else if ((modrm & 0xC0) == 0xC0) {
                                uint8_t dstReg = modrm & 7;
                                if ((srcReg == 0 || srcReg == 1 || srcReg == 2) &&
                                    (dstReg == 7 || dstReg == 6 || dstReg == 3))
                                    regSaves++; // mov edi/esi/ebx, eax/ecx/edx
                            }
                        }
                    }
                    if (regSaves >= 1) result = true; // even 1 save suggests regparm
                }
            }
        }
        m_regparmCache[addr] = result;
        return result;
    }

    std::set<uint32_t> m_floatReturnAddrs;   // call target addresses known to return float
    std::set<uint32_t> m_floatRetCallSites;  // instruction addresses of float-returning calls

    // Register → temp mapping (current state)
    std::map<x86_reg, int> m_regTemps;

    // Register → global struct source
    struct RegGlobalInfo {
        std::string globalName;
        TypeRef     typeRef;
    };
    std::map<x86_reg, RegGlobalInfo> m_regGlobalSource;

    // Register → resolved function name
    std::map<x86_reg, std::string> m_regFuncPtrName;

    // Per-block register state for CFG-aware tracking
    struct BlockLiftState {
        std::map<x86_reg, int> regTemps;
        std::map<x86_reg, RegGlobalInfo> regGlobalSource;
        std::map<x86_reg, std::string> regFuncPtrName;
        int flagsTemp = -1;
        IROp flagsOp = IROp::Eq;
        std::vector<int> fpuStack;
    };
    std::map<int, BlockLiftState> m_blockExitState;

    void saveBlockState(int blockId) {
        auto &s = m_blockExitState[blockId];
        s.regTemps = m_regTemps;
        s.regGlobalSource = m_regGlobalSource;
        s.regFuncPtrName = m_regFuncPtrName;
        s.flagsTemp = m_flags.temp;
        s.flagsOp = m_flags.op;
        s.fpuStack = m_fpuStack;
    }

    void restoreBlockState(const BlockLiftState &s) {
        m_regTemps = s.regTemps;
        m_regGlobalSource = s.regGlobalSource;
        m_regFuncPtrName = s.regFuncPtrName;
        m_flags.temp = s.flagsTemp;
        m_flags.op = s.flagsOp;
        m_flags.lhs.reset();
        m_flags.rhs.reset();
        m_flags.carryLhs.reset();
        m_flags.carryRhs.reset();
        m_fpuStack = s.fpuStack;
    }

    void mergeBlockState(int blockId, const std::vector<std::set<int>> &prePreds, IRFunc &func) {
        auto &preds = prePreds[blockId];
        // Collect processed predecessor states
        std::vector<const BlockLiftState*> predStates;
        for (int p : preds) {
            auto it = m_blockExitState.find(p);
            if (it != m_blockExitState.end())
                predStates.push_back(&it->second);
        }
        if (predStates.empty()) return;  // no predecessors processed; keep current
        if (predStates.size() == 1) { restoreBlockState(*predStates[0]); return; }

        // Multiple predecessors: merge register state.
        // At loop headers, create phi temps for registers that disagree
        // between predecessors, so the loop body uses fresh temps instead
        // of stale values from the pre-loop path.
        m_regGlobalSource.clear();
        m_regFuncPtrName.clear();
        m_flags = {-1, IROp::Eq, nullptr, nullptr};
        m_fpuStack.clear();

        static const x86_reg gpRegs[] = {
            X86_REG_EAX, X86_REG_EBX, X86_REG_ECX,
            X86_REG_EDX, X86_REG_ESI, X86_REG_EDI
        };
        auto &hdr = func.blocks[blockId];
        std::map<x86_reg, int> newRegTemps;
        for (x86_reg reg : gpRegs) {
            int firstTemp = -1;
            bool allSame = true;
            bool anyMissing = false;
            for (auto *ps : predStates) {
                auto it = ps->regTemps.find(reg);
                if (it == ps->regTemps.end()) { anyMissing = true; break; }
                if (firstTemp < 0) firstTemp = it->second;
                else if (it->second != firstTemp) allSame = false;
            }
            if (anyMissing) continue;
            if (allSame) {
                newRegTemps[reg] = firstTemp;
            } else {
                // Disagreement: create a phi temp so the loop body gets
                // a fresh temp instead of using a stale pre-loop value.
                TypeRef t = func.tempType(firstTemp);
                int phiTemp = func.newTemp(t);
                func.phiTemps.insert(phiTemp);
                hdr.stmts.push_back(IRStmt::mkAssign(phiTemp,
                    IRExpr::mkTemp(firstTemp, t), t));
                newRegTemps[reg] = phiTemp;
            }
        }
        m_regTemps = newRegTemps;
    }

    // Flags state: which temp holds the flag result and what comparison produced it
    struct FlagsState {
        int   temp = -1;
        IROp  op   = IROp::Eq;
        std::unique_ptr<IRExpr> lhs, rhs;
        std::unique_ptr<IRExpr> carryLhs, carryRhs;
    } m_flags;

    // Call argument collection
    std::map<int, std::unique_ptr<IRExpr>> m_espArgs;
    std::vector<std::unique_ptr<IRExpr>>   m_pushArgs;
    std::unique_ptr<IRExpr>                m_fpTableIndex; // index for fptable_ calls

    struct TailStackArg {
        std::unique_ptr<IRExpr> expr;
        int blockId = -1;
        size_t stmtIndex = 0;
    };
    std::map<int, TailStackArg> m_tailStackArgs;

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

    int assignReg(x86_reg reg, std::unique_ptr<IRExpr> val, BasicBlock &bb, TypeRef t = NullType) {
        int temp = m_func->newTemp(t);
        bb.stmts.push_back(IRStmt::mkAssign(temp, std::move(val), t));
        writeReg(reg, temp, bb);
        return temp;
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
        case X86_OP_MEM: {
            auto result = readMem(op.mem, op.size);
            // Propagate operand size for correct cast width
            if (result && op.size > 0 && op.size < 4) {
                if (result->op == IROp::Load)
                    result->loadSize = op.size;
                // For Field nodes created by struct resolution, propagate via loadSize
                else if (result->op == IROp::Field)
                    result->loadSize = op.size;
            }
            return result;
        }
        default: return IRExpr::mkConst(0);
        }
    }

    std::unique_ptr<IRExpr> readImm(int64_t imm) {
        uint32_t v = (uint32_t)imm;
        // Global variable address (from STABS)?
        // An immediate that matches a global address is &global, not *global.
        // Loading the value would be mov eax, [addr] (memory operand), not mov eax, addr (imm).
        auto *g = m_types.globalAtAddress(v, m_curSourceFileIdx);
        if (g) return IRExpr::mkAddrOf(IRExpr::mkVar(g->name, g->typeRef));
        if (auto elem = globalArrayElementAtAddress(v, true))
            return elem;
        // String literal?
        std::string s = tryString(v);
        if (!s.empty()) return IRExpr::mkString(s);
        // Don't resolve function addresses here — they'd be misidentified as data.
        // Function refs are handled in the 'call' and 'lea' instruction handlers.
        return IRExpr::mkConst(imm);
    }

    static std::pair<std::string, int> syntheticStackSlot(int disp) {
        char buf[32];
        if (disp > 0) {
            snprintf(buf, sizeof(buf), "arg_%x", (disp - 8) / 4);
            return {buf, 0};
        }
        int q = -disp;
        int slot = (q + 3) / 4;
        int baseQ = slot * 4;
        int byteOffset = baseQ - q;
        snprintf(buf, sizeof(buf), "var_%x", slot);
        return {buf, byteOffset};
    }

    static std::unique_ptr<IRExpr> syntheticStackAddress(const std::string &name,
                                                        int byteOffset) {
        auto addr = IRExpr::mkAddrOf(IRExpr::mkVar(name));
        if (byteOffset == 0)
            return addr;
        return IRExpr::mkBinary(IROp::Add, std::move(addr),
                                IRExpr::mkConst(byteOffset));
    }

    std::unique_ptr<IRExpr> readMem(x86_op_mem &m, int accessSize = 4) {
        // EBP-relative: param or local
        if (m.base == X86_REG_EBP && m.index == X86_REG_INVALID) {
            int d = (int)m.disp;
            if (d > 0) {
                auto it = m_paramByOffset.find(d);
                if (it != m_paramByOffset.end())
                    return IRExpr::mkVar(it->second->name, it->second->typeRef);
            }
            if (d < 0) {
                StackArrayAccess arrayAccess;
                if (stackArrayAtOffset(d, arrayAccess) &&
                    accessSize > 0 && accessSize == arrayAccess.elemSize) {
                    return IRExpr::mkVar(stackArrayElementName(arrayAccess),
                                         arrayAccess.elemType);
                }
                auto it = m_localByOffset.find(d);
                if (it != m_localByOffset.end()) {
                    auto var = IRExpr::mkVar(it->second->name, it->second->typeRef);
                    // For array-typed locals, wrap in Load to distinguish
                    // value access (movss → first element) from address access (lea)
                    auto *lt = m_types.resolveType(it->second->typeRef);
                    if (lt && lt->kind == StabsTypeKind::Array)
                        return IRExpr::mkLoad(std::move(var));
                    return var;
                }
            }
            // Unnamed stack slot
            auto [name, byteOffset] = syntheticStackSlot(d);
            if (byteOffset == 0)
                return IRExpr::mkVar(name);
            auto load = IRExpr::mkLoad(syntheticStackAddress(name, byteOffset));
            load->loadSize = accessSize;
            return load;
        }

        StackArrayAccess indexedAccess;
        if (auto addr = stackIndexedArrayAddress(m, accessSize, &indexedAccess)) {
            auto load = IRExpr::mkLoad(std::move(addr), indexedAccess.elemType);
            load->loadSize = accessSize;
            return load;
        }

        // PIC-relative (EBX + disp)
        if (m_hasPIC && m.base == X86_REG_EBX && m.index == X86_REG_INVALID && m_picBase) {
            uint32_t addr = m_picBase + (int)m.disp;
            if (auto elem = globalArrayElementAtAddress(addr, false))
                return elem;
            auto *g = m_types.globalAtAddress(addr, m_curSourceFileIdx);
            if (g) return IRExpr::mkVar(g->name, g->typeRef);
            std::string s = tryString(addr);
            if (!s.empty()) return IRExpr::mkString(s);
            auto fit = m_mf.functionMap().find(addr);
            if (fit != m_mf.functionMap().end())
                return IRExpr::mkAddrOf(IRExpr::mkFunc(fit->second));
            { std::string sn = m_mf.symbolNameAtAddress(addr);
              if (!sn.empty()) return IRExpr::mkVar(sn); }
            // Try nearest symbol for struct field access: globalVar + offset
            { std::string nearest = m_mf.nearestSymbolName(addr);
              if (!nearest.empty()) return IRExpr::mkVar(nearest); }
            const Section *dSec = m_mf.sectionForAddress(addr);
            if (dSec && m_mf.isDataSection(*dSec)) {
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
            // Skip offset 0 for struct pointers: [reg+0] is *reg, not reg->field
            if (m.disp != 0 && baseType != NullType && m_types.isStructPointer(baseType)) {
                TypeRef structRef = m_types.getPointedStruct(baseType);
                if (structRef != NullType) {
                    std::string access = m_types.formatFieldAccess(structRef, (int)m.disp);
                    if (!access.empty()) {
                        auto *field = m_types.findFieldAtOffset(structRef, (int)m.disp);
                        TypeRef ft = field ? field->typeRef : NullType;
                        // Skip ONLY if the field is a large struct/union AND the access
                        // didn't drill deeper (no '.' or '[' in the access string).
                        // If formatFieldAccess drilled into a sub-struct (access contains '.')
                        // then it reached a scalar — that's a valid access.
                        bool skipField = false;
                        if (ft != NullType && access.find('.') == std::string::npos &&
                            access.find('[') == std::string::npos) {
                            auto *fti = m_types.resolveType(ft);
                            if (fti && (fti->kind == StabsTypeKind::Struct ||
                                        fti->kind == StabsTypeKind::Union) &&
                                fti->sizeBytes > 4)
                                skipField = true;
                            // Also skip large array fields (char buf[N]) — reading 4 bytes
                            // from an array should use pointer arithmetic, not field name
                            if (fti && fti->kind == StabsTypeKind::Array && fti->sizeBytes > 4)
                                skipField = true;
                        }
                        if (!skipField) {
                            base->typeRef = baseType;
                            auto field = IRExpr::mkField(std::move(base), access, (int)m.disp, ft);
                            // Mark float fields for correct load cast
                            if (ft != NullType) {
                                auto *fti = m_types.resolveType(ft);
                                if (fti && fti->kind == StabsTypeKind::Float)
                                    field->loadSize = 5;
                            }
                            return field;
                        }
                    }
                }
            }
            // Struct-by-value: base holds address of struct (not pointer to pointer).
            // Type is the struct itself, accessed via [base + disp] = base.field
            if (m.disp != 0 && baseType != NullType) {
                auto *bt = m_types.resolveType(baseType);
                if (bt && (bt->kind == StabsTypeKind::Struct || bt->kind == StabsTypeKind::Union ||
                           bt->kind == StabsTypeKind::ForwardRef)) {
                    std::string access = m_types.formatFieldAccess(baseType, (int)m.disp);
                    if (!access.empty()) {
                        auto *field = m_types.findFieldAtOffset(baseType, (int)m.disp);
                        TypeRef ft = field ? field->typeRef : NullType;
                        // Skip large struct/array fields (reading 4 bytes from a large field)
                        bool skip = false;
                        if (ft != NullType && access.find('.') == std::string::npos &&
                            access.find('[') == std::string::npos) {
                            auto *fti = m_types.resolveType(ft);
                            if (fti && ((fti->kind == StabsTypeKind::Struct ||
                                         fti->kind == StabsTypeKind::Union) && fti->sizeBytes > 4))
                                skip = true;
                            // Arrays: sizeBytes may be 0; compute from count * elemSize
                            if (fti && fti->kind == StabsTypeKind::Array) {
                                int arrSize = fti->sizeBytes;
                                if (arrSize <= 0) {
                                    auto *et = m_types.resolveType(fti->targetType);
                                    int ec = fti->arrayHigh - fti->arrayLow + 1;
                                    if (et && ec > 0) arrSize = et->sizeBytes * ec;
                                }
                                if (arrSize > 4) skip = true;
                            }
                        }
                        if (!skip) {
                            base->typeRef = baseType;
                            return IRExpr::mkField(std::move(base), access, (int)m.disp, ft);
                        }
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
            if (auto elem = globalArrayElementAtAddress(addr, false))
                return elem;
            auto *g = m_types.globalAtAddress(addr, m_curSourceFileIdx);
            if (g) return IRExpr::mkVar(g->name, g->typeRef);
            // Check function map for import pointers
            auto fit = m_mf.functionMap().find(addr);
            if (fit != m_mf.functionMap().end())
                return IRExpr::mkVar(fit->second);
            std::string s = tryString(addr);
            if (!s.empty()) return IRExpr::mkString(s);
            // Try nlist symbol table for named globals
            std::string symName = m_mf.symbolNameAtAddress(addr);
            if (!symName.empty()) {
                auto *gn = m_types.globalByName(symName, m_curSourceFileIdx);
                if (gn && gn->typeRef != NullType) {
                    auto *gt = m_types.resolveType(gn->typeRef);
                    if (gt && gt->kind == StabsTypeKind::Pointer)
                        return IRExpr::mkVar(symName, gn->typeRef);
                    if (gt && (gt->kind == StabsTypeKind::Struct ||
                               gt->kind == StabsTypeKind::Union)) {
                        const Section *sec = m_mf.sectionForAddress(addr);
                        if (sec && m_mf.isImportSection(*sec))
                            return IRExpr::mkVar(symName, gn->typeRef);
                    }
                }
                return IRExpr::mkVar(symName);
            }
            // Try nearest symbol for base+offset access
            { std::string nearest = m_mf.nearestSymbolName(addr);
              if (!nearest.empty()) {
                // Resolve (global + offset) to global.field for struct/array-of-struct globals
                size_t plus = nearest.find(" + 0x");
                if (plus != std::string::npos && nearest.front() == '(' && nearest.back() == ')') {
                    std::string gname = nearest.substr(1, plus - 1);
                    unsigned goff = 0;
                    sscanf(nearest.c_str() + plus + 3, "%x", &goff);
                    auto *gn = m_types.globalByName(gname, m_curSourceFileIdx);
                    if (gn && gn->typeRef != NullType) {
                        auto *gt = m_types.resolveType(gn->typeRef);
                        TypeRef structType = NullType;
                        if (gt && (gt->kind == StabsTypeKind::Struct || gt->kind == StabsTypeKind::Union))
                            structType = gn->typeRef;
                        else if (gt && gt->kind == StabsTypeKind::Array) {
                            auto *et = m_types.resolveType(gt->targetType);
                            if (et && (et->kind == StabsTypeKind::Struct || et->kind == StabsTypeKind::Union)) {
                                int elemSz = et->sizeBytes;
                                if (elemSz > 0 && (int)goff < elemSz)
                                    structType = gt->targetType;
                            }
                        }
                        if (structType != NullType) {
                            std::string access = m_types.formatFieldAccess(structType, (int)goff);
                            if (!access.empty()) {
                                auto base = IRExpr::mkVar(gname, gn->typeRef);
                                auto *field = m_types.findFieldAtOffset(structType, (int)goff);
                                TypeRef ft = field ? field->typeRef : NullType;
                                return IRExpr::mkField(std::move(base), access, (int)goff, ft);
                            }
                            return IRExpr::mkLoad(IRExpr::mkConst(addr));
                        }
                    }
                }
                return IRExpr::mkVar(nearest);
              } }
            // For addresses in data sections, use a synthetic global name
            const Section *dataSec = m_mf.sectionForAddress(addr);
            if (dataSec && m_mf.isDataSection(*dataSec)) {
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
    void writeMem(x86_op_mem &m, std::unique_ptr<IRExpr> val, BasicBlock &bb, int storeSize = 4) {
        // EBP-relative
        if (m.base == X86_REG_EBP && m.index == X86_REG_INVALID) {
            int d = (int)m.disp;
            if (d > 0) {
                auto it = m_paramByOffset.find(d);
                if (it != m_paramByOffset.end()) {
                    size_t stmtIndex = bb.stmts.size();
                    rememberTailStackArg(d, val.get(), bb.id, stmtIndex);
                    bb.stmts.push_back(IRStmt::mkVarSet(it->second->name, std::move(val), it->second->typeRef));
                    return;
                }
            }
            if (d < 0) {
                StackArrayAccess arrayAccess;
                if (stackArrayAtOffset(d, arrayAccess) &&
                    storeSize > 0 && storeSize == arrayAccess.elemSize) {
                    bb.stmts.push_back(IRStmt::mkVarSet(
                        stackArrayElementName(arrayAccess), std::move(val),
                        arrayAccess.elemType, storeSize));
                    return;
                }
                auto it = m_localByOffset.find(d);
                if (it != m_localByOffset.end()) {
                    bb.stmts.push_back(IRStmt::mkVarSet(it->second->name, std::move(val), it->second->typeRef));
                    return;
                }
            }
            auto [name, byteOffset] = syntheticStackSlot(d);
            if (byteOffset == 0 && storeSize == 4) {
                size_t stmtIndex = bb.stmts.size();
                if (d > 0)
                    rememberTailStackArg(d, val.get(), bb.id, stmtIndex);
                bb.stmts.push_back(IRStmt::mkVarSet(name, std::move(val)));
            } else {
                bb.stmts.push_back(IRStmt::mkStore(
                    syntheticStackAddress(name, byteOffset), std::move(val),
                    storeSize));
            }
            return;
        }
        if (auto addr = stackIndexedArrayAddress(m, storeSize)) {
            bb.stmts.push_back(IRStmt::mkStore(std::move(addr), std::move(val), storeSize));
            return;
        }
        // Struct field write (skip offset 0: [reg+0] = *reg, not field access)
        if (m.base != X86_REG_INVALID && m.index == X86_REG_INVALID) {
            auto base = readReg(m.base);
            TypeRef baseType = NullType;
            int bt = regTemp(m.base);
            if (bt >= 0) baseType = m_func->tempType(bt);
            if (m.disp != 0 && baseType != NullType && m_types.isStructPointer(baseType)) {
                TypeRef structRef = m_types.getPointedStruct(baseType);
                if (structRef != NullType) {
                    std::string access = m_types.formatFieldAccess(structRef, (int)m.disp);
                    if (!access.empty()) {
                        auto *field = m_types.findFieldAtOffset(structRef, (int)m.disp);
                        TypeRef ft = field ? field->typeRef : NullType;
                        // Skip sub-struct fields ONLY if the access didn't drill deeper
                        bool skip = false;
                        if (ft != NullType && access.find('.') == std::string::npos &&
                            access.find('[') == std::string::npos) {
                            auto *fti = m_types.resolveType(ft);
                            if (fti && (fti->kind == StabsTypeKind::Struct ||
                                        fti->kind == StabsTypeKind::Union) && fti->sizeBytes > 4)
                                skip = true;
                        }
                        if (!skip) {
                            auto fld = IRExpr::mkField(std::move(base), access, (int)m.disp, ft);
                            bb.stmts.push_back(IRStmt::mkStore(std::move(fld), std::move(val), storeSize));
                            return;
                        }
                    }
                }
            }
            // Struct-by-value store: base.field = value
            if (m.disp != 0 && baseType != NullType) {
                auto *btt = m_types.resolveType(baseType);
                if (btt && (btt->kind == StabsTypeKind::Struct || btt->kind == StabsTypeKind::Union)) {
                    std::string access = m_types.formatFieldAccess(baseType, (int)m.disp);
                    if (!access.empty()) {
                        auto *field = m_types.findFieldAtOffset(baseType, (int)m.disp);
                        TypeRef ft = field ? field->typeRef : NullType;
                        auto fld = IRExpr::mkField(std::move(base), access, (int)m.disp, ft);
                        bb.stmts.push_back(IRStmt::mkStore(std::move(fld), std::move(val), storeSize));
                        return;
                    }
                }
            }
            // Scalar pointer store at offset 0: [reg+0] = *reg
            if (m.disp == 0) {
                bb.stmts.push_back(IRStmt::mkStore(std::move(base), std::move(val), storeSize));
                return;
            }
        }
        // Direct address store: [disp] with no base/index
        if (m.base == X86_REG_INVALID && m.index == X86_REG_INVALID && m.disp) {
            uint32_t addr = (uint32_t)m.disp;
            auto *g = m_types.globalAtAddress(addr, m_curSourceFileIdx);
            if (g) {
                bb.stmts.push_back(IRStmt::mkVarSet(g->name, std::move(val), g->typeRef, storeSize));
                return;
            }
            // Try nlist symbol table
            std::string symName = m_mf.symbolNameAtAddress(addr);
            if (!symName.empty()) {
                bb.stmts.push_back(IRStmt::mkVarSet(symName, std::move(val), NullType, storeSize));
                return;
            }
            // Resolve (global + offset) to global.field for struct/array-of-struct globals
            {
                std::string nearest = m_mf.nearestSymbolName(addr);
                if (!nearest.empty()) {
                    size_t plus = nearest.find(" + 0x");
                    if (plus != std::string::npos && nearest.front() == '(' && nearest.back() == ')') {
                        std::string gname = nearest.substr(1, plus - 1);
                        unsigned goff = 0;
                        sscanf(nearest.c_str() + plus + 3, "%x", &goff);
                        auto *gn = m_types.globalByName(gname, m_curSourceFileIdx);
                        if (gn && gn->typeRef != NullType) {
                            auto *gt = m_types.resolveType(gn->typeRef);
                            TypeRef structType = NullType;
                            if (gt && (gt->kind == StabsTypeKind::Struct || gt->kind == StabsTypeKind::Union))
                                structType = gn->typeRef;
                            else if (gt && gt->kind == StabsTypeKind::Array) {
                                auto *et = m_types.resolveType(gt->targetType);
                                if (et && (et->kind == StabsTypeKind::Struct || et->kind == StabsTypeKind::Union)) {
                                    int elemSz = et->sizeBytes;
                                    if (elemSz > 0 && (int)goff < elemSz)
                                        structType = gt->targetType;
                                }
                            }
                            if (structType != NullType) {
                                std::string access = m_types.formatFieldAccess(structType, (int)goff);
                                if (!access.empty()) {
                                    auto base = IRExpr::mkVar(gname, gn->typeRef);
                                    auto *field = m_types.findFieldAtOffset(structType, (int)goff);
                                    TypeRef ft = field ? field->typeRef : NullType;
                                    auto fld = IRExpr::mkField(std::move(base), access, (int)goff, ft);
                                    bb.stmts.push_back(IRStmt::mkStore(std::move(fld), std::move(val), storeSize));
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            // Synthetic global name for data section addresses
            const Section *dSec = m_mf.sectionForAddress(addr);
            if (dSec && m_mf.isDataSection(*dSec)) {
                char gn[32]; snprintf(gn, sizeof(gn), "g_%X", addr);
                bb.stmts.push_back(IRStmt::mkVarSet(gn, std::move(val), NullType, storeSize));
                return;
            }
        }
        // General store
        auto addr = readMem_addr(m);
        if (addr)
            bb.stmts.push_back(IRStmt::mkStore(std::move(addr), std::move(val), storeSize));
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
    // Cached float TypeRef from STABS (resolved once per function)
    TypeRef m_floatTypeRef = NullType;
    bool m_floatTypeResolved = false;

    TypeRef getFloatTypeRef() {
        if (!m_floatTypeResolved) {
            m_floatTypeResolved = true;
            // Find a float TypeRef from STABS locals/params
            for (auto &l : m_func->locals)
                if (l.typeRef != NullType) {
                    std::string fmt = m_types.formatType(l.typeRef);
                    if (fmt == "float" || fmt == "vec_t") {
                        m_floatTypeRef = l.typeRef; break;
                    }
                }
            if (m_floatTypeRef == NullType)
                for (auto &p : m_func->params)
                    if (p.typeRef != NullType) {
                        std::string fmt = m_types.formatType(p.typeRef);
                        if (fmt == "float" || fmt == "vec_t") {
                            m_floatTypeRef = p.typeRef; break;
                        }
                    }
        }
        return m_floatTypeRef;
    }

    void writeOp(cs_x86_op &op, std::unique_ptr<IRExpr> val, BasicBlock &bb, TypeRef t = NullType) {
        if (op.type == X86_OP_REG) {
            // XMM register values are always float
            if (t == NullType) {
                x86_reg cr = canonReg(op.reg);
                if (cr >= X86_REG_XMM0 && cr <= X86_REG_XMM7)
                    t = getFloatTypeRef();
            }
            assignReg(op.reg, std::move(val), bb, t);
        } else if (op.type == X86_OP_MEM) {
            // Preserve byte-width stores for matching
            if (op.size == 1)
                val = IRExpr::mkCast(CastKind::Trunc8, std::move(val));
            else if (op.size == 2)
                val = IRExpr::mkCast(CastKind::Trunc16, std::move(val));
            writeMem(op.mem, std::move(val), bb, op.size);
        }
    }

    // ── String resolution ───────────────────────────────────────────
    bool appendArrayIndexForOffset(TypeRef arrayRef, int byteOffset,
                                   std::string &suffix,
                                   TypeRef &elemRef,
                                   int depth = 0) const {
        if (arrayRef == NullType || byteOffset < 0 || depth > 8)
            return false;
        auto *array = m_types.resolveType(arrayRef);
        if (!array || array->kind != StabsTypeKind::Array)
            return false;
        elemRef = array->targetType;
        auto *elem = m_types.resolveType(elemRef);
        if (!elem || elem->sizeBytes <= 0)
            return false;
        int idx = byteOffset / elem->sizeBytes;
        int rem = byteOffset % elem->sizeBytes;
        int count = array->arrayHigh >= array->arrayLow
            ? array->arrayHigh - array->arrayLow + 1 : 0;
        if (count > 0 && idx >= count)
            return false;
        suffix += "[" + std::to_string(idx) + "]";
        if (rem == 0)
            return true;
        if (elem->kind == StabsTypeKind::Array)
            return appendArrayIndexForOffset(elemRef, rem, suffix, elemRef, depth + 1);
        return false;
    }

    std::unique_ptr<IRExpr> globalArrayElementAtAddress(uint32_t addr,
                                                        bool addressOf) const {
        int byteOffset = 0;
        auto *g = m_types.globalContainingAddress(addr, byteOffset,
                                                  m_curSourceFileIdx);
        if (!g || g->typeRef == NullType)
            return nullptr;
        auto *gt = m_types.resolveType(g->typeRef);
        if (!gt || gt->kind != StabsTypeKind::Array)
            return nullptr;
        std::string suffix;
        TypeRef elemRef = NullType;
        if (!appendArrayIndexForOffset(g->typeRef, byteOffset, suffix, elemRef))
            return nullptr;
        auto elem = IRExpr::mkVar(g->name + suffix, elemRef);
        if (addressOf)
            return IRExpr::mkAddrOf(std::move(elem));
        return elem;
    }

    std::string tryString(uint32_t addr) const {
        int64_t off = m_mf.fileOffsetForAddress(addr);
        if (off < 0) return "";
        const Section *sec = m_mf.sectionForAddress(addr);
        if (!sec || !m_mf.isCStringSection(*sec)) return "";
        const uint8_t *p = m_mf.bytesAt(off, std::min((uint32_t)80, (uint32_t)(m_mf.size() - off)));
        if (!p) return "";
        std::string s;
        for (int i = 0; i < 72 && p[i]; ++i) {
            if (p[i] >= 0x20 && p[i] < 0x7F) {
                if (p[i] == '"') s += "\\\"";
                else if (p[i] == '\\') s += "\\\\";
                else s += (char)p[i];
            } else if (p[i] == '\n') { s += "\\n"; }
              else if (p[i] == '\t') { s += "\\t"; }
              else if (p[i] == '\r') { s += "\\r"; }
              else { char b[8]; snprintf(b, 8, "\\x%02X", p[i]); s += b; }
        }
        // Empty string (just NUL byte) is still a valid string literal
        if (s.empty() && p && p[0] == 0) return "\"\"";
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
            // test reg, reg → flags based on reg value (OF=0 after test)
            rhs = IRExpr::mkConst(0);
            if      (jmn == "je"  || jmn == "jz")   cmpOp = IROp::Eq;
            else if (jmn == "jne" || jmn == "jnz")  cmpOp = IROp::Ne;
            else if (jmn == "js"  || jmn == "jl" || jmn == "jnge")  cmpOp = IROp::Slt;
            else if (jmn == "jns" || jmn == "jge" || jmn == "jnl")  cmpOp = IROp::Sge;
            else if (jmn == "jle" || jmn == "jng")   cmpOp = IROp::Sle;
            else if (jmn == "jg"  || jmn == "jnle")  cmpOp = IROp::Sgt;
            else cmpOp = IROp::Ne;
        } else if (isTest) {
            // test with different operands: condition is (lhs & rhs) vs 0 (OF=0)
            auto andExpr = IRExpr::mkBinary(IROp::And, std::move(lhs), std::move(rhs));
            lhs = std::move(andExpr);
            rhs = IRExpr::mkConst(0);
            if      (jmn == "je"  || jmn == "jz")   cmpOp = IROp::Eq;
            else if (jmn == "jne" || jmn == "jnz")  cmpOp = IROp::Ne;
            else if (jmn == "js"  || jmn == "jl" || jmn == "jnge")  cmpOp = IROp::Slt;
            else if (jmn == "jns" || jmn == "jge" || jmn == "jnl")  cmpOp = IROp::Sge;
            else if (jmn == "jle" || jmn == "jng")   cmpOp = IROp::Sle;
            else if (jmn == "jg"  || jmn == "jnle")  cmpOp = IROp::Sgt;
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
            // jp/jnp after ucomiss: parity = unordered (NaN)
            // jp = "is NaN", jnp = "is not NaN"
            // For float comparisons, jp means the operands are unordered.
            // Emit as Ne/Eq against self (NaN != NaN is true)
            else if (jmn == "jp") {
                // isnan(x) ↔ x != x (NaN is the only value not equal to itself)
                auto lhs2 = lhs->clone();
                return IRExpr::mkBinary(IROp::Ne, std::move(lhs), std::move(lhs2));
            }
            else if (jmn == "jnp") {
                // !isnan(x) ↔ x == x
                auto lhs2 = lhs->clone();
                return IRExpr::mkBinary(IROp::Eq, std::move(lhs), std::move(lhs2));
            }
            else cmpOp = IROp::Ne;
        }
        return IRExpr::mkBinary(cmpOp, std::move(lhs), std::move(rhs));
    }

    // ── Struct-by-value arg consolidation ───────────────────────────
    // The lifter captures each pushed/copied word as one call arg.  For a
    // callee whose prototype expects a struct-by-value >4 bytes, those
    // N words need to collapse to a single arg.  When the ABI setup was
    // a memcpy-from-pointer (each word is a Load from base + i*4 off the
    // same base register), we can recover the source pointer and emit
    // `*(struct X *)base` — byte-for-byte equivalent to the original
    // sequence of pushes.  When the pattern isn't recognized (struct
    // assembled from scratch), we leave the arg list alone; the call
    // won't compile, but that's honest — we don't know the struct body.
    static bool irExprEqual(const IRExpr *a, const IRExpr *b) {
        if (!a && !b) return true;
        if (!a || !b) return false;
        if (a->op != b->op || a->value != b->value ||
            a->name != b->name || a->castKind != b->castKind ||
            a->kids.size() != b->kids.size())
            return false;
        for (size_t i = 0; i < a->kids.size(); ++i)
            if (!irExprEqual(a->kids[i].get(), b->kids[i].get())) return false;
        return true;
    }

    int abiArgWords(TypeRef ref) const {
        int size = 4;
        if (ref != NullType) {
            auto *t = m_types.resolveType(ref);
            if (t) {
                if (t->kind == StabsTypeKind::Void)
                    return 0;
                if (t->sizeBytes > 0)
                    size = t->sizeBytes;
            }
        }
        return std::max(1, (size + 3) / 4);
    }

    int stackWordsAfterRegparm(const StabsFunction &callee, int regArgs) const {
        int words = 0;
        for (int i = regArgs; i < (int)callee.params.size(); ++i)
            words += abiArgWords(callee.params[(size_t)i].typeRef);
        return words;
    }

    int inferRegparmArgCount(const StabsFunction &callee, int capturedStackWords) const {
        int maxRegs = std::min(3, (int)callee.params.size());
        for (int r = maxRegs; r >= 0; --r) {
            if (stackWordsAfterRegparm(callee, r) == capturedStackWords)
                return r;
        }

        // Fallback for incomplete prototypes or missed stack writes: preserve the
        // old scalar count heuristic when ABI-width matching cannot decide.
        return std::min(3, std::max(0, (int)callee.params.size() - capturedStackWords));
    }

    std::vector<std::unique_ptr<IRExpr>>
    collectRegparmArgs(const StabsFunction &callee, int capturedStackWords) {
        static const x86_reg regparmOrder[] = {X86_REG_EAX, X86_REG_EDX, X86_REG_ECX};
        int nRegArgs = inferRegparmArgCount(callee, capturedStackWords);
        std::vector<std::unique_ptr<IRExpr>> regArgs;
        for (int ri = 0; ri < nRegArgs; ++ri) {
            auto it = m_regTemps.find(regparmOrder[ri]);
            if (it == m_regTemps.end())
                break;
            regArgs.push_back(IRExpr::mkTemp(it->second, m_func->tempType(it->second)));
        }
        if ((int)regArgs.size() != nRegArgs)
            regArgs.clear();
        return regArgs;
    }

    void prependRegparmArgs(const StabsFunction &callee,
                            std::vector<std::unique_ptr<IRExpr>> &args) {
        auto regArgs = collectRegparmArgs(callee, (int)args.size());
        for (int ri = (int)regArgs.size() - 1; ri >= 0; --ri)
            args.insert(args.begin(), std::move(regArgs[(size_t)ri]));
    }

    void rememberTailStackArg(int offset, const IRExpr *expr,
                              int blockId, size_t stmtIndex) {
        if (!expr)
            return;
        TailStackArg arg;
        arg.expr = expr->clone();
        arg.blockId = blockId;
        arg.stmtIndex = stmtIndex;
        m_tailStackArgs[offset] = std::move(arg);
    }

    void removeTailStackSetupStores(const std::set<int> &offsets) {
        std::map<int, std::vector<size_t>> byBlock;
        for (int off : offsets) {
            auto it = m_tailStackArgs.find(off);
            if (it == m_tailStackArgs.end() || it->second.blockId < 0)
                continue;
            byBlock[it->second.blockId].push_back(it->second.stmtIndex);
        }
        for (auto &[blockId, indices] : byBlock) {
            if (!m_func || blockId < 0 || blockId >= (int)m_func->blocks.size())
                continue;
            auto &stmts = m_func->blocks[(size_t)blockId].stmts;
            std::sort(indices.begin(), indices.end());
            indices.erase(std::unique(indices.begin(), indices.end()), indices.end());
            for (auto rit = indices.rbegin(); rit != indices.rend(); ++rit) {
                if (*rit < stmts.size())
                    stmts.erase(stmts.begin() + (ptrdiff_t)*rit);
            }
        }
    }

    std::vector<std::unique_ptr<IRExpr>>
    collectTailStackArgs(std::set<int> *usedOffsets = nullptr) const {
        std::vector<std::unique_ptr<IRExpr>> args;
        for (auto &kv : m_tailStackArgs) {
            if (!kv.second.expr)
                continue;
            if (usedOffsets)
                usedOffsets->insert(kv.first);
            args.push_back(kv.second.expr->clone());
        }
        return args;
    }

    std::vector<std::unique_ptr<IRExpr>>
    consolidateStructByValueArgs(const std::string &target,
                                 std::vector<std::unique_ptr<IRExpr>> args) {
        if (target.empty()) return args;
        const StabsFunction *callee = m_mf.stabsFunctionByName(target);
        if (!callee || callee->params.empty()) return args;

        std::vector<std::unique_ptr<IRExpr>> out;
        size_t argIdx = 0;
        for (auto &p : callee->params) {
            if (argIdx >= args.size()) break;
            int pSize = 4;
            bool isLargeStruct = false;
            if (p.typeRef != NullType) {
                auto *pt = m_types.resolveType(p.typeRef);
                if (pt && pt->sizeBytes > 0) {
                    pSize = pt->sizeBytes;
                    isLargeStruct =
                        (pt->kind == StabsTypeKind::Struct ||
                         pt->kind == StabsTypeKind::Union) &&
                        pSize > 4;
                }
            }
            if (!isLargeStruct) {
                out.push_back(std::move(args[argIdx++]));
                continue;
            }
            int words = (pSize + 3) / 4;
            if (argIdx + (size_t)words > args.size()) {
                // Not enough words captured — leave remaining args alone.
                while (argIdx < args.size()) out.push_back(std::move(args[argIdx++]));
                break;
            }
            // Try to match the memcpy-from-pointer pattern: every word is
            // Load(Add(base, startOff + i*4)) for the same base IRExpr.
            IRExpr *base = nullptr;
            int startOff = 0;
            bool matched = true;
            for (int i = 0; i < words; ++i) {
                auto *w = args[argIdx + (size_t)i].get();
                if (!w || w->op != IROp::Load || w->kids.empty() || !w->kids[0]) {
                    matched = false; break;
                }
                auto *addr = w->kids[0].get();
                IRExpr *thisBase = nullptr;
                int thisOff = 0;
                if (addr->op == IROp::Add && addr->kids.size() == 2 &&
                    addr->kids[0] && addr->kids[1] && addr->kids[1]->isConst()) {
                    thisBase = addr->kids[0].get();
                    thisOff = (int)addr->kids[1]->value;
                } else {
                    thisBase = addr;
                    thisOff = 0;
                }
                if (i == 0) { base = thisBase; startOff = thisOff; }
                else if (!irExprEqual(base, thisBase) ||
                         thisOff != startOff + i * 4) {
                    matched = false; break;
                }
            }
            // Special case: word 0 is a Var (or Temp coalesced to a param)
            // whose type matches the struct param.  This handles forwarding
            // a struct-by-value parameter (`from`) to another function
            // expecting that struct.  Restricted to function PARAMETERS
            // (not locals) because the emitter downgrades local
            // by-value structs to `int` — passing the local would then
            // fail with the same "int where struct expected" error.
            if (!matched && words >= 1 && m_func) {
                auto *first = args[argIdx].get();
                std::string varName;
                if (first && first->op == IROp::Var && !first->name.empty()) {
                    varName = first->name;
                } else if (first && first->op == IROp::Temp) {
                    int tid = (int)first->value;
                    auto vit = m_func->tempToVar.find(tid);
                    if (vit != m_func->tempToVar.end()) {
                        auto nit = m_func->varNames.find(vit->second);
                        if (nit != m_func->varNames.end()) varName = nit->second;
                    }
                }
                // Find the candidate type: from named-var lookup, or from the
                // temp's tempType if no name found.
                TypeRef vtRef = NullType;
                if (!varName.empty()) {
                    for (auto &fp : m_func->params)
                        if (fp.name == varName && fp.typeRef != NullType)
                            { vtRef = fp.typeRef; break; }
                    if (vtRef == NullType)
                        for (auto &fl : m_func->locals)
                            if (fl.name == varName && fl.typeRef != NullType)
                                { vtRef = fl.typeRef; break; }
                }
                if (vtRef == NullType && first && first->op == IROp::Temp) {
                    vtRef = m_func->tempType((int)first->value);
                }
                if (vtRef != NullType) {
                    auto *vt = m_types.resolveType(vtRef);
                    auto *pt = m_types.resolveType(p.typeRef);
                    if (vt && pt &&
                        (vt->kind == StabsTypeKind::Struct ||
                         vt->kind == StabsTypeKind::Union) &&
                        vt->kind == pt->kind &&
                        !vt->name.empty() && vt->name == pt->name) {
                        out.push_back(std::move(args[argIdx]));
                        argIdx += (size_t)words;
                        continue;
                    }
                }
            }
            if (matched && base) {
                auto baseClone = base->clone();
                std::unique_ptr<IRExpr> addr;
                if (startOff != 0) {
                    addr = IRExpr::mkBinary(IROp::Add,
                                            std::move(baseClone),
                                            IRExpr::mkConst((uint64_t)startOff));
                } else {
                    addr = std::move(baseClone);
                }
                auto structLoad = std::make_unique<IRExpr>();
                structLoad->op = IROp::Load;
                structLoad->typeRef = p.typeRef;
                structLoad->loadSize = pSize;
                structLoad->kids.push_back(std::move(addr));
                out.push_back(std::move(structLoad));
            } else {
                // Pattern didn't match: the caller assembled the struct from
                // individual word values (stack-materialized locals, register
                // spills, etc.).  Synthesize an IR node that the emitter will
                // expand into a compound-literal cast so all N words land in
                // the call arg's stack slot byte-for-byte.  This is modelled
                // as a Call to the synthetic name `__pack_struct` with the
                // captured words as kids — the emitter recognizes it.
                auto packExpr = std::make_unique<IRExpr>();
                packExpr->op = IROp::Call;
                packExpr->name = "__pack_struct";
                packExpr->typeRef = p.typeRef;
                packExpr->loadSize = pSize;
                for (int i = 0; i < words; ++i)
                    packExpr->kids.push_back(std::move(args[argIdx + (size_t)i]));
                out.push_back(std::move(packExpr));
            }
            argIdx += (size_t)words;
        }
        while (argIdx < args.size()) out.push_back(std::move(args[argIdx++]));
        return out;
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
            // Track register-to-global source for indirect call resolution.
            if (o[0].type == X86_OP_REG) {
                x86_reg canon = canonReg(o[0].reg);
                m_regGlobalSource.erase(canon);
                m_regFuncPtrName.erase(canon);

                if (o[1].type == X86_OP_MEM) {
                    auto &smem = o[1].mem;
                    if (smem.base == X86_REG_INVALID && smem.index == X86_REG_INVALID &&
                        smem.disp != 0) {
                        // mov reg, [addr] — direct address load
                        uint32_t loadAddr = (uint32_t)smem.disp;
                        // Check if the loaded value is a named global with struct type
                        if (src->op == IROp::Var && !src->name.empty()) {
                            auto *g = m_types.globalByName(src->name, m_curSourceFileIdx);
                            if (g && g->typeRef != NullType) {
                                auto *gt = m_types.resolveType(g->typeRef);
                                if (gt && (gt->kind == StabsTypeKind::Struct ||
                                           gt->kind == StabsTypeKind::ForwardRef)) {
                                    m_regGlobalSource[canon] = {src->name, g->typeRef};
                                    // Loading from struct base (offset 0) = first field
                                    std::string f0 = m_types.formatFieldAccess(g->typeRef, 0);
                                    if (!f0.empty())
                                        m_regFuncPtrName[canon] = src->name + "." + f0;
                                }
                            }
                        }
                        // Also check if addr is within a known global struct
                        // (e.g., mov eax, [re + 0x148] loads re.Shutdown)
                        if (m_regFuncPtrName.find(canon) == m_regFuncPtrName.end()) {
                            std::string nearest = m_mf.nearestSymbolName(loadAddr);
                            if (!nearest.empty()) {
                                size_t plus = nearest.find(" + 0x");
                                if (plus != std::string::npos && nearest.front() == '(' && nearest.back() == ')') {
                                    std::string gname = nearest.substr(1, plus - 1);
                                    unsigned goff = 0;
                                    sscanf(nearest.c_str() + plus + 3, "%x", &goff);
                                    auto *g = m_types.globalByName(gname, m_curSourceFileIdx);
                                    if (g && g->typeRef != NullType) {
                                        auto *gt = m_types.resolveType(g->typeRef);
                                        if (gt && (gt->kind == StabsTypeKind::Struct ||
                                                   gt->kind == StabsTypeKind::Union)) {
                                            std::string fieldName = m_types.formatFieldAccess(g->typeRef, (int)goff);
                                            if (!fieldName.empty())
                                                m_regFuncPtrName[canon] = gname + "." + fieldName;
                                        }
                                    }
                                }
                            }
                        }
                    } else if (smem.base != X86_REG_INVALID && smem.index == X86_REG_INVALID &&
                               smem.disp >= 0) {
                        // mov reg, [base + offset] — check if base is a global struct
                        auto git = m_regGlobalSource.find(canonReg(smem.base));
                        if (git != m_regGlobalSource.end()) {
                            std::string fieldName = m_types.formatFieldAccess(
                                git->second.typeRef, (int)smem.disp);
                            if (!fieldName.empty()) {
                                m_regFuncPtrName[canon] =
                                    git->second.globalName + "." + fieldName;
                            }
                        }
                    }
                }
            }
            writeOp(o[0], std::move(src), bb, t);
            return;
        }
        if (mn == "lea" && n == 2) {
            // LEA: compute address, don't load
            auto addr = readMem_addr(o[1].mem);
            if (!addr) addr = IRExpr::mkConst(0);
            // When LEA computes an interior pointer (base + nonzero offset),
            // try to resolve the field type so subsequent accesses through this
            // pointer can resolve sub-struct fields (e.g., &world->sunParse → SunLightParseParams*).
            if (o[1].mem.disp != 0 && o[1].mem.base != X86_REG_INVALID) {
                int bt = regTemp(o[1].mem.base);
                if (bt >= 0) {
                    TypeRef btype = m_func->tempType(bt);
                    if (btype != NullType && m_types.isStructPointer(btype)) {
                        TypeRef structRef = m_types.getPointedStruct(btype);
                        if (structRef != NullType) {
                            auto *field = m_types.findFieldAtOffset(structRef, (int)o[1].mem.disp);
                            if (field && field->typeRef != NullType) {
                                auto *ft = m_types.resolveType(field->typeRef);
                                if (ft && (ft->kind == StabsTypeKind::Struct ||
                                           ft->kind == StabsTypeKind::Union ||
                                           ft->kind == StabsTypeKind::ForwardRef)) {
                                    // Field is a struct/union — result is pointer to it
                                    addr->typeRef = field->typeRef;
                                } else {
                                    addr->typeRef = NullType;
                                }
                            } else {
                                addr->typeRef = NullType;
                            }
                        } else {
                            addr->typeRef = NullType;
                        }
                    }
                }
            }

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
                auto *g = m_types.globalAtAddress(target, m_curSourceFileIdx);
                if (g) addr = IRExpr::mkAddrOf(IRExpr::mkVar(g->name, g->typeRef));
                else if (auto elem = globalArrayElementAtAddress(target, true))
                    addr = std::move(elem);
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
            {
                TypeRef leaType = addr ? addr->typeRef : NullType;
                writeOp(o[0], std::move(addr), bb, leaType);
            }
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
                m_flags.lhs = IRExpr::mkConst(0);
                m_flags.rhs = IRExpr::mkConst(0);
                m_flags.op = IROp::Sub;
                m_flags.carryLhs.reset();
                m_flags.carryRhs.reset();
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
                TypeRef resultType = NullType;
                // For add reg, const: if reg is a struct pointer, resolve the
                // sub-struct field type so interior pointer accesses work
                if (mn == "add" && o[0].type == X86_OP_REG && o[1].type == X86_OP_IMM &&
                    o[1].imm > 0) {
                    int bt = regTemp(o[0].reg);
                    if (bt >= 0) {
                        TypeRef btype = m_func->tempType(bt);
                        if (btype != NullType && m_types.isStructPointer(btype)) {
                            TypeRef structRef = m_types.getPointedStruct(btype);
                            if (structRef != NullType) {
                                auto *field = m_types.findFieldAtOffset(structRef, (int)o[1].imm);
                                if (field && field->typeRef != NullType) {
                                    auto *ft = m_types.resolveType(field->typeRef);
                                    if (ft && (ft->kind == StabsTypeKind::Struct ||
                                               ft->kind == StabsTypeKind::Union ||
                                               ft->kind == StabsTypeKind::ForwardRef))
                                        resultType = field->typeRef;
                                }
                            }
                        }
                    }
                }
                auto res = IRExpr::mkBinary(irop, lhs->clone(), rhs->clone());
                auto flagExpr = res->clone();
                if (mn == "sub") {
                    m_flags.carryLhs = lhs->clone();
                    m_flags.carryRhs = rhs->clone();
                } else if (mn == "and") {
                    m_flags.carryLhs.reset();
                    m_flags.carryRhs.reset();
                } else {
                    m_flags.carryLhs.reset();
                    m_flags.carryRhs.reset();
                }
                if (o[0].type == X86_OP_REG) {
                    int destTemp = assignReg(o[0].reg, std::move(res), bb,
                                             resultType);
                    m_flags.lhs = IRExpr::mkTemp(destTemp,
                                                 func.tempType(destTemp));
                } else {
                    m_flags.lhs = std::move(flagExpr);
                    writeOp(o[0], std::move(res), bb, resultType);
                }
                m_flags.rhs = IRExpr::mkConst(0);
                m_flags.op = IROp::Sub;
            }
            return;
        }
        if (mn == "inc" && n == 1) {
            auto v = readOp(o[0]);
            if (v) {
                auto res = IRExpr::mkBinary(IROp::Add, v->clone(), IRExpr::mkConst(1));
                m_flags.carryLhs.reset();
                m_flags.carryRhs.reset();
                if (o[0].type == X86_OP_REG) {
                    int destTemp = assignReg(o[0].reg, std::move(res), bb);
                    m_flags.lhs = IRExpr::mkTemp(destTemp,
                                                 func.tempType(destTemp));
                } else {
                    m_flags.lhs = res->clone();
                    writeOp(o[0], std::move(res), bb);
                }
                m_flags.rhs = IRExpr::mkConst(0);
                m_flags.op = IROp::Sub;
            }
            return;
        }
        if (mn == "dec" && n == 1) {
            auto v = readOp(o[0]);
            if (v) {
                auto res = IRExpr::mkBinary(IROp::Sub, v->clone(), IRExpr::mkConst(1));
                m_flags.carryLhs.reset();
                m_flags.carryRhs.reset();
                if (o[0].type == X86_OP_REG) {
                    int destTemp = assignReg(o[0].reg, std::move(res), bb);
                    m_flags.lhs = IRExpr::mkTemp(destTemp,
                                                 func.tempType(destTemp));
                } else {
                    m_flags.lhs = res->clone();
                    writeOp(o[0], std::move(res), bb);
                }
                m_flags.rhs = IRExpr::mkConst(0);
                m_flags.op = IROp::Sub;
            }
            return;
        }
        if (mn == "neg" && n == 1) {
            auto v = readOp(o[0]);
            if (v) writeOp(o[0], IRExpr::mkUnary(IROp::Neg, std::move(v)), bb);
            return;
        }
        if (mn == "not" && n == 1) {
            if (m_suppressNextNot) {
                m_suppressNextNot = false;
                return; // part of repne scasb (strlen) idiom — already handled
            }
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
            IRExpr *cfLhs = m_flags.carryLhs ? m_flags.carryLhs.get() : m_flags.lhs.get();
            IRExpr *cfRhs = m_flags.carryRhs ? m_flags.carryRhs.get() : m_flags.rhs.get();
            if (cfLhs) {
                // CF=1 when lhs < rhs (unsigned) → sbb reg,reg = -(lhs < rhs) = (lhs < rhs) ? -1 : 0
                auto cond = IRExpr::mkBinary(IROp::Ult, cfLhs->clone(),
                    cfRhs ? cfRhs->clone() : IRExpr::mkConst(0));
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
            IRExpr *cfLhs = m_flags.carryLhs ? m_flags.carryLhs.get() : m_flags.lhs.get();
            IRExpr *cfRhs = m_flags.carryRhs ? m_flags.carryRhs.get() : m_flags.rhs.get();
            if (cfLhs) {
                auto carry = IRExpr::mkBinary(IROp::Ult, cfLhs->clone(),
                    cfRhs ? cfRhs->clone() : IRExpr::mkConst(0));
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
            m_flags.carryLhs = m_flags.lhs ? m_flags.lhs->clone() : nullptr;
            m_flags.carryRhs = m_flags.rhs ? m_flags.rhs->clone() : nullptr;
            // Preserve sub-dword width for correct comparison codegen
            if (o[0].type == X86_OP_MEM && o[0].size == 1 && m_flags.lhs)
                m_flags.lhs = IRExpr::mkCast(CastKind::Trunc8, std::move(m_flags.lhs));
            if (o[0].type == X86_OP_MEM && o[0].size == 2 && m_flags.lhs)
                m_flags.lhs = IRExpr::mkCast(CastKind::Trunc16, std::move(m_flags.lhs));
            m_flags.op = IROp::Sub;
            return;
        }
        if (mn == "test" && n == 2) {
            m_flags.lhs = readOp(o[0]);
            m_flags.rhs = readOp(o[1]);
            m_flags.carryLhs.reset();
            m_flags.carryRhs.reset();
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
                // Build tail call: return target(args)
                std::vector<std::unique_ptr<IRExpr>> args;
                bool recoveredTailArgs = false;
                std::set<int> usedTailOffsets;
                auto stackArgs = collectTailStackArgs(&usedTailOffsets);
                if (callee && callee->address && isCalleeRegparm(callee->address)) {
                    auto regArgs = collectRegparmArgs(*callee, (int)stackArgs.size());
                    if (!regArgs.empty() || !stackArgs.empty() || callee->params.empty()) {
                        for (auto &arg : regArgs)
                            args.push_back(std::move(arg));
                        for (auto &arg : stackArgs)
                            args.push_back(std::move(arg));
                        recoveredTailArgs = true;
                    }
                } else if (!stackArgs.empty()) {
                    for (auto &arg : stackArgs)
                        args.push_back(std::move(arg));
                    recoveredTailArgs = true;
                }

                if (recoveredTailArgs) {
                    removeTailStackSetupStores(usedTailOffsets);
                } else {
                    // Fallback for unresolved tail calls: reuse caller params by
                    // position, which is the best information available here.
                    int nCalleeParams = callee ? (int)callee->params.size() : (int)func.params.size();
                    for (int pi = 0; pi < std::min(nCalleeParams, (int)func.params.size()); ++pi)
                        args.push_back(IRExpr::mkVar(func.params[pi].name, func.params[pi].typeRef));
                }
                args = consolidateStructByValueArgs(target, std::move(args));
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
            // Return handling
            // Check if return type is void (including through typedef chains)
            if (m_func->returnType != NullType) {
                auto *rt = m_types.resolveType(m_func->returnType);
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
                // FPU stack has a value → return it as float, regardless of declared type.
                // The presence of a value on the FPU stack at ret is the strongest signal
                // for float return. STABS type refs can be wrong (e.g., CU-scoped int
                // when the actual type is const float from a different CU).
                if (!m_fpuStack.empty()) {
                    bb.stmts.push_back(IRStmt::mkReturn(fpuRead(0)));
                    return;
                }
                // Float/double return → use last popped FPU value
                if (rt && (rt->kind == StabsTypeKind::Float ||
                           rt->kind == StabsTypeKind::Double ||
                           rt->kind == StabsTypeKind::LongDouble)) {
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
                    bool isVoid = false;
                    // If the block has NO statements, the function is an empty stub → void
                    if (bb.stmts.empty()) isVoid = true;
                    else {
                        // If the last statement is a Store/VarSet, EAX is leftover → void
                        auto &lastStmt = bb.stmts.back();
                        if (lastStmt.kind == IRStmtKind::Store ||
                            lastStmt.kind == IRStmtKind::VarSet)
                            isVoid = true;
                        // If the last statement is a Call (void call), the function is void
                        if (lastStmt.kind == IRStmtKind::Call)
                            isVoid = true;
                        // If the last statement assigns from a Call and the function just
                        // returns that value, the function is a void wrapper: it calls a
                        // void function and returns whatever happened to be in EAX.
                        if (lastStmt.kind == IRStmtKind::Assign && lastStmt.expr &&
                            lastStmt.expr->op == IROp::Call)
                            isVoid = true;
                    }
                    // Safety: if MULTIPLE other blocks already have Return with a value,
                    // the function is NOT void (multi-path return)
                    if (isVoid) {
                        int returnWithValue = 0;
                        for (auto &ob : func.blocks) {
                            for (auto &s : ob.stmts) {
                                if (s.kind == IRStmtKind::Return && s.expr)
                                    returnWithValue++;
                            }
                        }
                        if (returnWithValue >= 2) isVoid = false;
                    }
                    if (isVoid) {
                        m_func->detectedVoid = true;
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
                if (o[0].type == X86_OP_MEM) {
                    // Detect vtable call pattern: call [reg + offset]
                    // where reg was loaded from [this] (i.e., vtable pointer)
                    auto &mem = o[0].mem;
                    if (mem.base != X86_REG_INVALID && mem.index == X86_REG_INVALID && mem.disp >= 0) {
                        // Check if base register came from a known global struct
                        // (e.g., ri = refimport_t with function pointer fields)
                        bool resolved = false;
                        auto git = m_regGlobalSource.find(canonReg(mem.base));
                        if (git != m_regGlobalSource.end()) {
                            // Look up field name at the given offset in the struct
                            std::string fieldName = m_types.formatFieldAccess(
                                git->second.typeRef, (int)mem.disp);
                            if (!fieldName.empty()) {
                                target = git->second.globalName + "." + fieldName;
                                resolved = true;
                            }
                        }
                        if (!resolved) {
                            int slot = (int)mem.disp / 4;
                            char buf[32]; snprintf(buf, sizeof(buf), "vfunc_%d", slot);
                            target = buf;
                        }
                    } else if (mem.base == X86_REG_INVALID && mem.index != X86_REG_INVALID) {
                        // call [reg*4 + table_addr] — function pointer table
                        char buf[64]; snprintf(buf, sizeof(buf), "fptable_%X_%d",
                            (unsigned)(uint32_t)mem.disp, mem.scale);
                        target = buf;
                        // Save index expression to prepend to args later
                        m_fpTableIndex = readReg(mem.index);
                    } else if (mem.base == X86_REG_INVALID && mem.index == X86_REG_INVALID &&
                               mem.disp != 0) {
                        // call [direct_addr] — may be a function pointer in a global struct
                        // Check if addr falls within a known global struct
                        uint32_t callAddr = (uint32_t)mem.disp;
                        std::string nearest = m_mf.nearestSymbolName(callAddr);
                        bool resolved = false;
                        if (!nearest.empty()) {
                            // Parse "(name + 0xNN)" format
                            size_t plus = nearest.find(" + 0x");
                            if (plus != std::string::npos && nearest.front() == '(' && nearest.back() == ')') {
                                std::string gname = nearest.substr(1, plus - 1);
                                unsigned offset = 0;
                                sscanf(nearest.c_str() + plus + 3, "%x", &offset);
                                auto *g = m_types.globalByName(gname, m_curSourceFileIdx);
                                if (g && g->typeRef != NullType) {
                                    auto *gt = m_types.resolveType(g->typeRef);
                                    if (gt && (gt->kind == StabsTypeKind::Struct ||
                                               gt->kind == StabsTypeKind::Union)) {
                                        std::string fieldName = m_types.formatFieldAccess(
                                            g->typeRef, (int)offset);
                                        if (!fieldName.empty()) {
                                            target = gname + "." + fieldName;
                                            resolved = true;
                                        }
                                    }
                                }
                            }
                        }
                        if (!resolved) {
                            auto tgt = readOp(o[0]);
                            int fpTemp = func.newTemp();
                            bb.stmts.push_back(IRStmt::mkAssign(fpTemp, std::move(tgt)));
                            target = "t" + std::to_string(fpTemp);
                        }
                    } else {
                        auto tgt = readOp(o[0]);
                        int fpTemp = func.newTemp();
                        bb.stmts.push_back(IRStmt::mkAssign(fpTemp, std::move(tgt)));
                        target = "t" + std::to_string(fpTemp);
                    }
                } else if (o[0].type == X86_OP_REG) {
                    // call reg — function pointer in register
                    // Check if reg was loaded from a known global struct field
                    auto fit = m_regFuncPtrName.find(canonReg(o[0].reg));
                    if (fit != m_regFuncPtrName.end()) {
                        target = fit->second;
                    } else {
                        auto tgt = readReg(o[0].reg);
                        int fpTemp = func.newTemp();
                        bb.stmts.push_back(IRStmt::mkAssign(fpTemp, std::move(tgt)));
                        target = "t" + std::to_string(fpTemp);
                    }
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
            // Detect regparm(3) calls: check if callee uses regparm by
            // scanning its prologue for register saves (mov [ebp-N], eax/edx/ecx).
            {
                const StabsFunction *callee = m_mf.stabsFunctionByName(target);
                if (callee && callee->address && isCalleeRegparm(callee->address) &&
                    !callee->params.empty()) {
                    prependRegparmArgs(*callee, args);
                }
            }
            m_espArgs.clear();
            m_pushArgs.clear();
            // Prepend fptable index if present
            if (m_fpTableIndex) {
                args.insert(args.begin(), std::move(m_fpTableIndex));
                m_fpTableIndex.reset();
            }

            // Collapse struct-by-value args that were captured word-by-word
            // back into a single argument when the memcpy-from-pointer
            // pattern is present.  Preserves semantics; otherwise leaves
            // args untouched (compile fails honestly).
            args = consolidateStructByValueArgs(target, std::move(args));

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
            auto callExpr = IRExpr::mkCall("__builtin_memcmp", std::move(args));
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
            // repne scasb produces ~(strlen+1) in ECX. The usual following
            // `not ecx` yields strlen+1, which is often passed to memcpy so
            // the copied string includes its terminator.  Model that post-NOT
            // value directly and suppress the explicit NOT.
            assignReg(X86_REG_ECX,
                IRExpr::mkBinary(IROp::Add, IRExpr::mkTemp(t), IRExpr::mkConst(1)), bb);
            m_suppressNextNot = true;
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
                    // If loading from a local variable, ensure it's typed as float
                    // (flds always loads a float, so the local IS a float)
                    if (o[0].type == X86_OP_MEM && o[0].mem.base == X86_REG_EBP &&
                        o[0].mem.index == X86_REG_INVALID && o[0].mem.disp < 0) {
                        auto it = m_localByOffset.find((int)o[0].mem.disp);
                        if (it != m_localByOffset.end()) {
                            auto *rt = m_types.resolveType(it->second->typeRef);
                            if (!rt || rt->kind == StabsTypeKind::Int ||
                                rt->kind == StabsTypeKind::UInt) {
                                // Override int → float for this local
                                const_cast<StabsTypedVar*>(it->second)->typeRef = getFloatTypeRef();
                            }
                        }
                    }
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
                    // For memory stores, mark as float store size
                    if (o[0].type == X86_OP_MEM)
                        writeMem(o[0].mem, std::move(st0), bb, 5);
                    else
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
            bool dbl = (mn == "movsd");
            // movss/movsd [esp+N], xmm → collect as call argument
            if (o[0].type == X86_OP_MEM && o[0].mem.base == X86_REG_ESP &&
                o[0].mem.index == X86_REG_INVALID) {
                auto src = readSSEOp(o[1], dbl);
                if (src) m_espArgs[(int)o[0].mem.disp] = std::move(src);
                return true;
            }
            auto src = readSSEOp(o[1], dbl);
            if (src) {
                // For memory stores, use float/double store size so the
                // decompiler emits *(float*) instead of *(int*)
                if (o[0].type == X86_OP_MEM)
                    writeMem(o[0].mem, std::move(src), bb, dbl ? 9 : 5);
                else
                    writeOp(o[0], std::move(src), bb);
            }
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
            if (a && b) {
                std::vector<std::unique_ptr<IRExpr>> args;
                args.push_back(std::move(a));
                args.push_back(std::move(b));
                writeOp(o[0], IRExpr::mkCall("fminf", std::move(args)), bb);
            }
            return true;
        }
        if ((mn == "maxss" || mn == "maxsd" || mn == "maxps" || mn == "maxpd") && n == 2) {
            auto a = readSSEOp(o[0], mn.find('d') != std::string::npos);
            auto b = readSSEOp(o[1], mn.find('d') != std::string::npos);
            if (a && b) {
                std::vector<std::unique_ptr<IRExpr>> args;
                args.push_back(std::move(a));
                args.push_back(std::move(b));
                writeOp(o[0], IRExpr::mkCall("fmaxf", std::move(args)), bb);
            }
            return true;
        }
        if ((mn == "sqrtss" || mn == "sqrtsd" || mn == "sqrtps" || mn == "sqrtpd") && n == 2) {
            auto src = readSSEOp(o[1], mn.find('d') != std::string::npos);
            if (src) {
                std::vector<std::unique_ptr<IRExpr>> args;
                args.push_back(std::move(src));
                writeOp(o[0], IRExpr::mkCall("sqrtf", std::move(args)), bb);
            }
            return true;
        }
        if ((mn == "rsqrtss" || mn == "rsqrtps") && n == 2) {
            auto src = readSSEOp(o[1], false);
            if (src) {
                std::vector<std::unique_ptr<IRExpr>> args;
                args.push_back(std::move(src));
                auto sqrtCall = IRExpr::mkCall("sqrtf", std::move(args));
                writeOp(o[0], IRExpr::mkBinary(IROp::SDiv,
                    IRExpr::mkVar("1.0f"), std::move(sqrtCall)), bb);
            }
            return true;
        }
        if ((mn == "rcpss" || mn == "rcpps") && n == 2) {
            auto src = readSSEOp(o[1], false);
            if (src) {
                writeOp(o[0], IRExpr::mkBinary(IROp::SDiv,
                    IRExpr::mkVar("1.0f"), std::move(src)), bb);
            }
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
            // Fall back to regular memory read. For SSE float instructions,
            // mark Loads as float (loadSize=5) and drill into union Fields
            // to select the float member (e.g., dvar->current → current.value).
            auto mem = readMem(op.mem);
            if (mem) {
                if (mem->op == IROp::Load) {
                    mem->loadSize = isDouble ? 9 : 5;
                } else if (mem->op == IROp::Field && !isDouble && mem->typeRef != NullType) {
                    auto *fti = m_types.resolveType(mem->typeRef);
                    if (fti && fti->kind == StabsTypeKind::Union) {
                        for (auto &uf : fti->fields) {
                            auto *uft = m_types.resolveType(uf.typeRef);
                            if (uft && uft->kind == StabsTypeKind::Float) {
                                mem = IRExpr::mkField(std::move(mem), uf.name,
                                    uf.bitOffset / 8, uf.typeRef);
                                break;
                            }
                        }
                    }
                }
            }
            return mem;
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
        auto *g = m_types.globalAtAddress(addr, m_curSourceFileIdx);
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
