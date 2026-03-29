#pragma once
#include "ir.h"
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cassert>

// ── SSA Builder ─────────────────────────────────────────────────────
// Simplified SSA construction using cross-block reaching definitions.
// Instead of full Cytron algorithm, we:
//   1. Compute dominators (reuse from cfg.h pattern)
//   2. Compute dominance frontiers
//   3. Track which "register" each temp corresponds to
//   4. Insert phi nodes at join points where different predecessors
//      have different temps for the same register
//   5. Rename temps via dominator tree DFS
//
// This is sufficient for type inference and variable coalescing.

class SSABuilder {
public:
    // Compute only immediate dominators (no phi insertion or renaming).
    // This provides dominance information for other analyses without
    // modifying the IR.
    void computeIdomOnly(IRFunc &func) {
        int n = (int)func.blocks.size();
        if (n == 0) return;
        computeIdom(func);
        buildRegMap(func);
    }

    // Build SSA form for the function.  Inserts phi nodes and renames temps.
    void buildSSA(IRFunc &func) {
        int n = (int)func.blocks.size();
        if (n == 0) return;

        // Step 1: Compute immediate dominators
        computeIdom(func);

        // Step 2: Build register mapping from existing temps
        // The lifter creates unique temps per assignment, but the same x86
        // register may produce different temps in different blocks.  We need
        // to group temps that represent the "same variable" across blocks.
        buildRegMap(func);

        // Step 3: Compute dominance frontiers
        std::vector<std::set<int>> df(n);
        computeDomFrontiers(func, df);

        // Step 4: Find registers defined in each block
        // reg -> set of blocks where it is defined
        std::map<int, std::set<int>> regDefs;
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0) {
                    auto rit = func.tempToReg.find(stmt.destTemp);
                    if (rit != func.tempToReg.end())
                        regDefs[rit->second].insert(bb.id);
                }
            }
        }

        // Step 5: Insert phi nodes using iterated dominance frontier
        for (auto &[reg, defs] : regDefs) {
            if (defs.size() <= 1) continue; // no join needed

            std::set<int> hasAlready;  // blocks with phi for this reg
            std::set<int> everOnWork;
            std::vector<int> work(defs.begin(), defs.end());
            everOnWork = defs;

            while (!work.empty()) {
                int x = work.back(); work.pop_back();
                for (int y : df[x]) {
                    if (hasAlready.count(y)) continue;
                    hasAlready.insert(y);

                    // Insert phi at start of block y
                    // Propagate type from existing definitions of this register
                    TypeRef phiType = NullType;
                    for (auto &[tid, reg2] : func.tempToReg) {
                        if (reg2 == reg && func.tempType(tid) != NullType) {
                            phiType = func.tempType(tid);
                            break;
                        }
                    }
                    int phiTemp = func.newTemp(phiType);
                    func.tempToReg[phiTemp] = reg;

                    // Build phi sources from predecessors
                    std::vector<std::pair<int,int>> sources;
                    for (int pred : func.blocks[y].preds) {
                        // Will be filled during rename; use -1 as placeholder
                        sources.push_back({pred, -1});
                    }
                    auto phi = IRStmt::mkPhi(phiTemp, std::move(sources));
                    func.blocks[y].stmts.insert(func.blocks[y].stmts.begin(), std::move(phi));

                    if (!everOnWork.count(y)) {
                        everOnWork.insert(y);
                        work.push_back(y);
                    }
                }
            }
        }

        // Step 6: Rename temps via dominator tree DFS
        // For each register, maintain a stack of current version (temp id)
        std::map<int, std::vector<int>> regStacks;

        // Initialize stacks with the first definition in block 0 (entry)
        // Process entry block's initial definitions
        renameDFS(func, 0, regStacks);
    }

    // Remove phi nodes and insert explicit copies for out-of-SSA
    void destroySSA(IRFunc &func) {
        for (auto &bb : func.blocks) {
            // Collect phis to process
            std::vector<IRStmt> phis;
            std::vector<IRStmt> nonPhis;
            for (auto &stmt : bb.stmts) {
                if (stmt.kind == IRStmtKind::Phi)
                    phis.push_back(std::move(stmt));
                else
                    nonPhis.push_back(std::move(stmt));
            }
            bb.stmts = std::move(nonPhis);

            // For each phi, insert a copy at the end of each predecessor
            for (auto &phi : phis) {
                for (auto &[predId, srcTemp] : phi.phiSources) {
                    if (srcTemp < 0) continue;
                    if (predId < 0 || predId >= (int)func.blocks.size()) continue;
                    auto &pred = func.blocks[predId];
                    // Insert copy before the terminal statement (branch/jump)
                    TypeRef copyType = func.tempType(phi.destTemp);
                    if (copyType == NullType) copyType = func.tempType(srcTemp);
                    auto copy = IRStmt::mkAssign(phi.destTemp,
                        IRExpr::mkTemp(srcTemp, copyType), copyType);
                    if (!pred.stmts.empty()) {
                        auto k = pred.stmts.back().kind;
                        if (k == IRStmtKind::Branch || k == IRStmtKind::Jump ||
                            k == IRStmtKind::Switch || k == IRStmtKind::Return) {
                            pred.stmts.insert(pred.stmts.end() - 1, std::move(copy));
                        } else {
                            pred.stmts.push_back(std::move(copy));
                        }
                    } else {
                        pred.stmts.push_back(std::move(copy));
                    }
                }
            }
        }
    }

private:
    // Compute immediate dominators using Cooper-Harvey-Kennedy
    void computeIdom(IRFunc &func) {
        int n = (int)func.blocks.size();
        func.idom.assign(n, -1);
        func.idom[0] = 0;
        if (n <= 1) return;

        // Compute reverse postorder
        std::vector<int> rpo;
        std::vector<int> rpoNum(n, -1);
        {
            std::vector<bool> visited(n, false);
            std::vector<int> postorder;
            std::vector<std::pair<int,int>> stack = {{0, 0}};
            visited[0] = true;
            while (!stack.empty()) {
                auto &[node, ci] = stack.back();
                auto &succs = func.blocks[node].succs;
                if (ci < (int)succs.size()) {
                    int s = succs[ci++];
                    if (s >= 0 && s < n && !visited[s]) {
                        visited[s] = true;
                        stack.push_back({s, 0});
                    }
                } else {
                    postorder.push_back(node);
                    stack.pop_back();
                }
            }
            rpo.resize(postorder.size());
            for (int i = 0; i < (int)postorder.size(); ++i) {
                rpo[postorder.size() - 1 - i] = postorder[i];
                rpoNum[postorder[i]] = (int)postorder.size() - 1 - i;
            }
        }

        auto intersect = [&](int b1, int b2) -> int {
            int f1 = b1, f2 = b2;
            while (f1 != f2) {
                while (rpoNum[f1] > rpoNum[f2]) f1 = func.idom[f1];
                while (rpoNum[f2] > rpoNum[f1]) f2 = func.idom[f2];
            }
            return f1;
        };

        bool changed = true;
        for (int iter = 0; iter < n && changed; ++iter) {
            changed = false;
            for (int idx = 1; idx < (int)rpo.size(); ++idx) {
                int b = rpo[idx];
                int newIdom = -1;
                for (int p : func.blocks[b].preds) {
                    if (p < 0 || p >= n || func.idom[p] == -1) continue;
                    if (newIdom == -1) newIdom = p;
                    else newIdom = intersect(newIdom, p);
                }
                if (newIdom == -1) newIdom = 0;
                if (func.idom[b] != newIdom) {
                    func.idom[b] = newIdom;
                    changed = true;
                }
            }
        }
    }

    // Compute dominance frontiers
    void computeDomFrontiers(IRFunc &func, std::vector<std::set<int>> &df) {
        int n = (int)func.blocks.size();
        for (int b = 0; b < n; ++b) {
            auto &preds = func.blocks[b].preds;
            if ((int)preds.size() < 2) continue;
            for (int p : preds) {
                if (p < 0 || p >= n) continue;
                int runner = p;
                int limit = n; // safety counter
                while (runner >= 0 && runner != func.idom[b] && --limit > 0) {
                    df[runner].insert(b);
                    if (runner == func.idom[runner]) break; // root
                    runner = func.idom[runner];
                }
            }
        }
    }

    // Build mapping from temp IDs to canonical "register" IDs.
    // We use a simple heuristic: temps assigned in the same position
    // (same VarSet target or same x86 register) get the same reg ID.
    // For temps without explicit register info, we assign unique reg IDs.
    void buildRegMap(IRFunc &func) {
        // Strategy: Each VarSet destination and each temp that participates
        // in a copy chain gets a canonical register.  The lifter's pattern is:
        //   assignReg(reg, val, bb) -> newTemp() + writeReg(reg, temp, bb)
        // We can infer register identity by looking at which temps are used
        // in the same "slot" - e.g., same VarSet target.

        // Simple approach: assign a unique reg ID to each temp that doesn't
        // already have one.  Group temps that are connected through copies.
        int nextReg = 0;

        // First pass: assign unique regs
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0) {
                    if (func.tempToReg.find(stmt.destTemp) == func.tempToReg.end()) {
                        // Check if this is a copy from another temp
                        if (stmt.expr && stmt.expr->op == IROp::Temp) {
                            int srcTemp = stmt.expr->tempId();
                            auto sit = func.tempToReg.find(srcTemp);
                            if (sit != func.tempToReg.end()) {
                                func.tempToReg[stmt.destTemp] = sit->second;
                                continue;
                            }
                        }
                        // Check for induction variable: t2 = t1 + const or t2 = t1 - const
                        // These represent the same logical register across loop iterations
                        if (stmt.expr && (stmt.expr->op == IROp::Add || stmt.expr->op == IROp::Sub) &&
                            stmt.expr->kids.size() == 2) {
                            IRExpr *lhs = stmt.expr->kids[0].get();
                            IRExpr *rhs = stmt.expr->kids[1].get();
                            int srcTemp = -1;
                            if (lhs && lhs->op == IROp::Temp && rhs && rhs->isConst())
                                srcTemp = lhs->tempId();
                            else if (rhs && rhs->op == IROp::Temp && lhs && lhs->isConst())
                                srcTemp = rhs->tempId();
                            if (srcTemp >= 0) {
                                auto sit = func.tempToReg.find(srcTemp);
                                if (sit != func.tempToReg.end()) {
                                    func.tempToReg[stmt.destTemp] = sit->second;
                                    continue;
                                }
                            }
                        }
                        func.tempToReg[stmt.destTemp] = nextReg++;
                    }
                }
            }
        }
        // Also assign regs to temps referenced but never defined in an Assign
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                auto assignReg = [&](const IRExpr *e) {
                    if (!e) return;
                    std::vector<const IRExpr *> stack = {e};
                    while (!stack.empty()) {
                        auto *n = stack.back(); stack.pop_back();
                        if (n->op == IROp::Temp) {
                            int tid = n->tempId();
                            if (func.tempToReg.find(tid) == func.tempToReg.end())
                                func.tempToReg[tid] = nextReg++;
                        }
                        for (auto &k : n->kids) if (k) stack.push_back(k.get());
                    }
                };
                assignReg(stmt.expr.get());
                assignReg(stmt.addr.get());
                for (auto &a : stmt.args) assignReg(a.get());
            }
        }
    }

    // Rename temps via dominator tree DFS
    void renameDFS(IRFunc &func, int blockId, std::map<int, std::vector<int>> &stacks) {
        int n = (int)func.blocks.size();
        if (blockId < 0 || blockId >= n) return;
        auto &bb = func.blocks[blockId];

        // Save stack state for restoration
        std::map<int, int> savedStackSizes;
        for (auto &[reg, st] : stacks) savedStackSizes[reg] = (int)st.size();

        // Process phi nodes at this block - they define new versions
        for (auto &stmt : bb.stmts) {
            if (stmt.kind == IRStmtKind::Phi && stmt.destTemp >= 0) {
                auto rit = func.tempToReg.find(stmt.destTemp);
                if (rit != func.tempToReg.end()) {
                    stacks[rit->second].push_back(stmt.destTemp);
                }
            }
        }

        // Process non-phi statements: rename uses then defs
        for (auto &stmt : bb.stmts) {
            if (stmt.kind == IRStmtKind::Phi) continue;

            // Rename uses in expressions
            auto renameExpr = [&](std::unique_ptr<IRExpr> &e) {
                if (!e) return;
                renameExprImpl(e, func, stacks);
            };
            renameExpr(stmt.expr);
            renameExpr(stmt.addr);
            for (auto &a : stmt.args) renameExpr(a);

            // Rename definitions
            if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0) {
                auto rit = func.tempToReg.find(stmt.destTemp);
                if (rit != func.tempToReg.end()) {
                    stacks[rit->second].push_back(stmt.destTemp);
                }
            }
        }

        // Fill in phi sources in successor blocks
        for (int succId : bb.succs) {
            if (succId < 0 || succId >= n) continue;
            auto &succ = func.blocks[succId];
            for (auto &stmt : succ.stmts) {
                if (stmt.kind != IRStmtKind::Phi) break; // phis are at the front
                auto rit = func.tempToReg.find(stmt.destTemp);
                if (rit == func.tempToReg.end()) continue;
                int reg = rit->second;
                // Find the source slot for this predecessor
                for (auto &[predId, srcTemp] : stmt.phiSources) {
                    if (predId == blockId) {
                        auto sit = stacks.find(reg);
                        if (sit != stacks.end() && !sit->second.empty())
                            srcTemp = sit->second.back();
                        break;
                    }
                }
            }
        }

        // Recurse into dominated children
        for (int c = 0; c < n; ++c) {
            if (c != blockId && func.idom[c] == blockId)
                renameDFS(func, c, stacks);
        }

        // Restore stacks
        for (auto &[reg, st] : stacks) {
            auto sit = savedStackSizes.find(reg);
            int savedSz = (sit != savedStackSizes.end()) ? sit->second : 0;
            while ((int)st.size() > savedSz) st.pop_back();
        }
    }

    void renameExprImpl(std::unique_ptr<IRExpr> &e, IRFunc &func,
                        std::map<int, std::vector<int>> &stacks) {
        if (!e) return;
        if (e->op == IROp::Temp) {
            int tid = e->tempId();
            auto rit = func.tempToReg.find(tid);
            if (rit != func.tempToReg.end()) {
                auto sit = stacks.find(rit->second);
                if (sit != stacks.end() && !sit->second.empty()) {
                    int curVer = sit->second.back();
                    if (curVer != tid) {
                        TypeRef t = e->typeRef;
                        if (t == NullType) t = func.tempType(curVer);
                        e = IRExpr::mkTemp(curVer, t);
                    }
                }
            }
        }
        for (auto &k : e->kids) renameExprImpl(k, func, stacks);
    }
};
