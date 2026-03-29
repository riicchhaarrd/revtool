#pragma once
#include "ir.h"
#include "stabs_types.h"
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cassert>
#include <functional>

// ── Variable Coalescer ──────────────────────────────────────────────
// Merges non-interfering temporaries into named variables.
//
// Algorithm:
//   1. Compute liveness via backward dataflow (bitvectors)
//   2. Build interference graph (two temps interfere if both live
//      at the same program point)
//   3. Coalesce non-interfering temps connected by copy/phi edges
//   4. Assign human-readable names from STABS or generate v0, v1, ...
//   5. Populate IRFunc::tempToVar and IRFunc::varNames

class VarCoalescer {
public:
    void coalesce(IRFunc &func, const StabsTypeTable &types) {
        m_func = &func;
        m_types = &types;
        int n = (int)func.blocks.size();
        if (n == 0) return;

        // Collect all temp IDs used in the function
        std::set<int> allTemps;
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0)
                    allTemps.insert(stmt.destTemp);
                if (stmt.kind == IRStmtKind::Phi && stmt.destTemp >= 0) {
                    allTemps.insert(stmt.destTemp);
                    for (auto &[_, src] : stmt.phiSources)
                        if (src >= 0) allTemps.insert(src);
                }
                collectExprTemps(stmt.expr.get(), allTemps);
                collectExprTemps(stmt.addr.get(), allTemps);
                for (auto &a : stmt.args) collectExprTemps(a.get(), allTemps);
            }
        }
        if (allTemps.empty()) return;

        // Build compact temp ID mapping for bitvectors
        std::vector<int> tempList(allTemps.begin(), allTemps.end());
        std::map<int, int> tempIdx; // tempId -> index in bitvector
        for (int i = 0; i < (int)tempList.size(); ++i)
            tempIdx[tempList[i]] = i;
        int numTemps = (int)tempList.size();

        // Safety: skip liveness for very large functions
        if (numTemps > 5000 || n > 500) {
            assignSimpleNames(func, types, allTemps);
            return;
        }

        // Step 1: Compute liveness (backward dataflow with bitvectors)
        // Use a simple bitset represented as vector<bool>
        struct BitVec {
            std::vector<bool> bits;
            BitVec() = default;
            explicit BitVec(int sz) : bits(sz, false) {}
            void set(int i) { bits[i] = true; }
            void clear(int i) { bits[i] = false; }
            bool test(int i) const { return bits[i]; }
            bool operator==(const BitVec &o) const { return bits == o.bits; }
            void unionWith(const BitVec &o) {
                for (int i = 0; i < (int)bits.size(); ++i)
                    if (o.bits[i]) bits[i] = true;
            }
            void minus(const BitVec &o) {
                for (int i = 0; i < (int)bits.size(); ++i)
                    if (o.bits[i]) bits[i] = false;
            }
        };

        // Compute USE and DEF sets for each block
        std::vector<BitVec> use(n, BitVec(numTemps));
        std::vector<BitVec> def(n, BitVec(numTemps));

        for (int bi = 0; bi < n; ++bi) {
            auto &bb = func.blocks[bi];
            // Walk forward: a temp is in USE if used before defined in this block
            BitVec localDef(numTemps);
            for (auto &stmt : bb.stmts) {
                // Uses come first
                auto markUse = [&](const IRExpr *e) {
                    if (!e) return;
                    std::vector<const IRExpr *> stack = {e};
                    while (!stack.empty()) {
                        auto *node = stack.back(); stack.pop_back();
                        if (node->op == IROp::Temp) {
                            auto it = tempIdx.find(node->tempId());
                            if (it != tempIdx.end() && !localDef.test(it->second))
                                use[bi].set(it->second);
                        }
                        for (auto &k : node->kids) if (k) stack.push_back(k.get());
                    }
                };
                // For phi: sources are uses from predecessors, not this block
                if (stmt.kind == IRStmtKind::Phi) {
                    // Phi defs
                    if (stmt.destTemp >= 0) {
                        auto it = tempIdx.find(stmt.destTemp);
                        if (it != tempIdx.end()) {
                            def[bi].set(it->second);
                            localDef.set(it->second);
                        }
                    }
                    continue;
                }
                markUse(stmt.expr.get());
                markUse(stmt.addr.get());
                for (auto &a : stmt.args) markUse(a.get());
                // Then def
                if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0) {
                    auto it = tempIdx.find(stmt.destTemp);
                    if (it != tempIdx.end()) {
                        def[bi].set(it->second);
                        localDef.set(it->second);
                    }
                }
            }
        }

        // Iterative liveness: LiveIn(B) = USE(B) U (LiveOut(B) - DEF(B))
        //                      LiveOut(B) = U LiveIn(S) for S in succs(B)
        std::vector<BitVec> liveIn(n, BitVec(numTemps));
        std::vector<BitVec> liveOut(n, BitVec(numTemps));

        bool changed = true;
        for (int iter = 0; iter < n * 2 + 10 && changed; ++iter) {
            changed = false;
            // Reverse order for faster convergence
            for (int bi = n - 1; bi >= 0; --bi) {
                BitVec newOut(numTemps);
                for (int s : func.blocks[bi].succs) {
                    if (s >= 0 && s < n)
                        newOut.unionWith(liveIn[s]);
                }
                BitVec newIn = use[bi];
                BitVec temp = newOut;
                temp.minus(def[bi]);
                newIn.unionWith(temp);
                if (!(newIn == liveIn[bi]) || !(newOut == liveOut[bi])) {
                    liveIn[bi] = newIn;
                    liveOut[bi] = newOut;
                    changed = true;
                }
            }
        }

        // Step 2: Build interference graph
        // Two temps interfere if both live at the same program point
        // We check at each stmt: after processing uses, before def
        std::set<std::pair<int,int>> interference;

        for (int bi = 0; bi < n; ++bi) {
            BitVec live = liveOut[bi];
            auto &bb = func.blocks[bi];
            // Walk backward through statements
            for (int si = (int)bb.stmts.size() - 1; si >= 0; --si) {
                auto &stmt = bb.stmts[si];
                // Def: the defined temp interferes with all currently live temps
                int defTemp = -1;
                if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0)
                    defTemp = stmt.destTemp;
                else if (stmt.kind == IRStmtKind::Phi && stmt.destTemp >= 0)
                    defTemp = stmt.destTemp;

                if (defTemp >= 0) {
                    auto dit = tempIdx.find(defTemp);
                    if (dit != tempIdx.end()) {
                        for (int j = 0; j < numTemps; ++j) {
                            if (live.test(j) && j != dit->second) {
                                int a = std::min(dit->second, j);
                                int b = std::max(dit->second, j);
                                interference.insert({a, b});
                            }
                        }
                        live.clear(dit->second); // remove from live (defined here)
                    }
                }
                // Uses: add to live
                auto addUses = [&](const IRExpr *e) {
                    if (!e) return;
                    std::vector<const IRExpr *> stack = {e};
                    while (!stack.empty()) {
                        auto *nd = stack.back(); stack.pop_back();
                        if (nd->op == IROp::Temp) {
                            auto it = tempIdx.find(nd->tempId());
                            if (it != tempIdx.end()) live.set(it->second);
                        }
                        for (auto &k : nd->kids) if (k) stack.push_back(k.get());
                    }
                };
                if (stmt.kind != IRStmtKind::Phi) {
                    addUses(stmt.expr.get());
                    addUses(stmt.addr.get());
                    for (auto &a : stmt.args) addUses(a.get());
                }
            }
        }

        // Step 3: Collect copy/phi edges (candidates for coalescing)
        std::vector<std::pair<int,int>> copyEdges;
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0 &&
                    stmt.expr && stmt.expr->op == IROp::Temp) {
                    int a = stmt.destTemp, b = stmt.expr->tempId();
                    auto ai = tempIdx.find(a), bi = tempIdx.find(b);
                    if (ai != tempIdx.end() && bi != tempIdx.end())
                        copyEdges.push_back({ai->second, bi->second});
                }
                if (stmt.kind == IRStmtKind::Phi && stmt.destTemp >= 0) {
                    auto di = tempIdx.find(stmt.destTemp);
                    if (di == tempIdx.end()) continue;
                    for (auto &[_, src] : stmt.phiSources) {
                        if (src >= 0) {
                            auto si = tempIdx.find(src);
                            if (si != tempIdx.end())
                                copyEdges.push_back({di->second, si->second});
                        }
                    }
                }
            }
        }

        // Step 4: Greedy coalescing using union-find
        std::vector<int> parent(numTemps);
        for (int i = 0; i < numTemps; ++i) parent[i] = i;
        auto ufFind = [&](int x) -> int {
            while (parent[x] != x) { parent[x] = parent[parent[x]]; x = parent[x]; }
            return x;
        };
        auto ufUnion = [&](int a, int b) {
            int ra = ufFind(a), rb = ufFind(b);
            if (ra != rb) parent[rb] = ra;
        };
        auto interferes = [&](int a, int b) -> bool {
            // Check if any temp in group a interferes with any in group b
            // For efficiency, just check the pair directly
            int x = std::min(a, b), y = std::max(a, b);
            return interference.count({x, y}) > 0;
        };

        // Process copy edges: merge if no interference between representatives
        for (auto &[a, b] : copyEdges) {
            int ra = ufFind(a), rb = ufFind(b);
            if (ra == rb) continue;
            if (!interferes(ra, rb))
                ufUnion(ra, rb);
        }

        // Step 5: Assign names
        // Group temps by their coalesced representative
        std::map<int, std::vector<int>> groups; // rep -> list of temp indices
        for (int i = 0; i < numTemps; ++i)
            groups[ufFind(i)].push_back(i);

        int nextVarId = 0;
        for (auto &[rep, members] : groups) {
            int varId = nextVarId++;

            // Try to find a good name from STABS params/locals
            std::string bestName;
            TypeRef bestType = NullType;

            for (int idx : members) {
                int tid = tempList[idx];
                // Check if this temp was copy-propagated from a named var
                // (the lifter creates temps from var reads)
                // Look through the defining statement
                for (auto &bb : func.blocks) {
                    for (auto &stmt : bb.stmts) {
                        if (stmt.kind == IRStmtKind::Assign && stmt.destTemp == tid) {
                            if (stmt.expr && stmt.expr->op == IROp::Var &&
                                !stmt.expr->name.empty()) {
                                // Check if this var name is a param/local
                                for (auto &p : func.params) {
                                    if (p.name == stmt.expr->name) {
                                        bestName = p.name;
                                        if (p.typeRef != NullType) bestType = p.typeRef;
                                        break;
                                    }
                                }
                                if (bestName.empty()) {
                                    for (auto &l : func.locals) {
                                        if (l.name == stmt.expr->name) {
                                            bestName = l.name;
                                            if (l.typeRef != NullType) bestType = l.typeRef;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (!bestName.empty()) break;
                }
                if (!bestName.empty()) break;

                // Check tempTypes for a known type
                if (bestType == NullType) {
                    auto it = func.tempTypes.find(tid);
                    if (it != func.tempTypes.end() && it->second != NullType)
                        bestType = it->second;
                }
            }

            // Generate name if none found from STABS
            if (bestName.empty()) {
                bestName = "v" + std::to_string(varId);
            }

            // Validate type: don't apply param struct/pointer types to large groups.
            // When many unrelated temps get coalesced, the param's type is likely wrong
            // for the other members (e.g., float ops coalesced with struct pointer).
            if (bestType != NullType) {
                auto *rt = types.resolveType(bestType);
                bool isStructPtrType = false;
                if (rt && (rt->kind == StabsTypeKind::Struct || rt->kind == StabsTypeKind::Union))
                    isStructPtrType = true;
                if (rt && rt->kind == StabsTypeKind::Pointer) {
                    auto *pt = types.resolveType(rt->targetType);
                    if (pt && (pt->kind == StabsTypeKind::Struct || pt->kind == StabsTypeKind::Union))
                        isStructPtrType = true;
                }
                // Also check by formatted name — STABS type table conflicts can
                // cause resolveType to return Int for what's actually a struct
                if (!isStructPtrType) {
                    std::string fmtType = types.formatType(bestType);
                    // Only flag as struct if the name ends with _s (struct tag convention)
                    // or contains "State" / "struct" (common game struct names)
                    // Exclude scalar typedefs like vec_t, qboolean, etc.
                    static const std::set<std::string> scalarTypes = {
                        "vec_t", "int", "float", "char", "void", "double", "short", "long",
                        "unsigned", "qboolean", "BOOL", "Bool", "byte", "OSStatus", "OSErr",
                        "fileHandle_t", "MaterialHandle", "r_index_t", "Boolean",
                    };
                    if (!fmtType.empty() && !scalarTypes.count(fmtType) &&
                        fmtType.find("*") == std::string::npos) {
                        // Check if it looks like a struct (has _s or State in name)
                        if (fmtType.find("_s") != std::string::npos ||
                            fmtType.find("State") != std::string::npos ||
                            fmtType.find("Info") != std::string::npos) {
                            isStructPtrType = true;
                        }
                    }
                }
                // Count how many temps in this group were assigned from this param
                if (isStructPtrType) {
                    // Check if any temp in this group is:
                    // 1) Used as operand of Mul/Div, OR
                    // 2) Defined by an expression containing Mul/Add/Sub
                    // Structs are never multiplied or added.
                    std::set<int> groupTids;
                    for (int idx : members) groupTids.insert(tempList[idx]);
                    bool usedInArith = false;
                    for (auto &bb : func.blocks) {
                        for (auto &stmt : bb.stmts) {
                            // Check 1: group temp used as operand of Mul/Div
                            std::function<bool(const IRExpr*, bool)> scan;
                            scan = [&](const IRExpr *e, bool parentIsArith) -> bool {
                                if (!e) return false;
                                if (e->op == IROp::Temp && groupTids.count(e->tempId()) && parentIsArith)
                                    return true;
                                bool isArith = (e->op == IROp::Mul || e->op == IROp::SDiv ||
                                                e->op == IROp::UDiv);
                                for (auto &k : e->kids)
                                    if (scan(k.get(), isArith)) return true;
                                return false;
                            };
                            if (scan(stmt.expr.get(), false) ||
                                scan(stmt.addr.get(), false)) { usedInArith = true; break; }
                            for (auto &a : stmt.args)
                                if (scan(a.get(), false)) { usedInArith = true; break; }
                            // Check 2: group temp defined by Mul/Add/Sub expression
                            if (stmt.kind == IRStmtKind::Assign &&
                                groupTids.count(stmt.destTemp) && stmt.expr) {
                                std::function<bool(const IRExpr*)> hasMul;
                                hasMul = [&](const IRExpr *e) -> bool {
                                    if (!e) return false;
                                    if (e->op == IROp::Mul || e->op == IROp::SDiv) return true;
                                    for (auto &k : e->kids)
                                        if (hasMul(k.get())) return true;
                                    return false;
                                };
                                if (hasMul(stmt.expr.get())) { usedInArith = true; break; }
                            }
                            if (usedInArith) break;
                        }
                        if (usedInArith) break;
                    }
                    if (usedInArith) {
                        bestType = NullType;
                        // Also clear tempTypes for all temps in this group
                        // to prevent the emitter from falling back to the wrong type
                        for (int idx : members)
                            func.tempTypes.erase(tempList[idx]);
                    }
                }
            }

            // Record mapping for all temps in this group
            func.varNames[varId] = bestName;
            if (bestType != NullType)
                func.varTypes[varId] = bestType;
            for (int idx : members)
                func.tempToVar[tempList[idx]] = varId;
        }
    }

private:
    IRFunc *m_func = nullptr;
    const StabsTypeTable *m_types = nullptr;

    void collectExprTemps(const IRExpr *e, std::set<int> &temps) {
        if (!e) return;
        if (e->op == IROp::Temp) temps.insert(e->tempId());
        for (auto &k : e->kids) collectExprTemps(k.get(), temps);
    }

    // Simple name assignment without full liveness (fallback for large functions)
    void assignSimpleNames(IRFunc &func, const StabsTypeTable &types,
                           const std::set<int> &allTemps) {
        int nextVarId = 0;
        for (int tid : allTemps) {
            int varId = nextVarId++;
            // Try to find a name from the defining statement
            std::string name;
            for (auto &bb : func.blocks) {
                for (auto &stmt : bb.stmts) {
                    if (stmt.kind == IRStmtKind::Assign && stmt.destTemp == tid &&
                        stmt.expr && stmt.expr->op == IROp::Var && !stmt.expr->name.empty()) {
                        // Check if it's a param/local name
                        for (auto &p : func.params)
                            if (p.name == stmt.expr->name) { name = p.name; break; }
                        if (name.empty()) {
                            for (auto &l : func.locals)
                                if (l.name == stmt.expr->name) { name = l.name; break; }
                        }
                    }
                    if (!name.empty()) break;
                }
                if (!name.empty()) break;
            }
            if (name.empty()) name = "v" + std::to_string(varId);
            func.varNames[varId] = name;
            func.tempToVar[tid] = varId;

            // Copy type if available
            auto it = func.tempTypes.find(tid);
            if (it != func.tempTypes.end() && it->second != NullType)
                func.varTypes[varId] = it->second;
        }
    }
};
