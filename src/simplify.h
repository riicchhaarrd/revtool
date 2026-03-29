#pragma once
#include "ir.h"
#include <set>
#include <map>
#include <vector>
#include <algorithm>

// ── IR-Level Expression Simplification ──────────────────────────────
// Bottom-up rewrite pass on IR expression trees.  Runs before the
// emitter to clean up redundant patterns produced by the lifter.
//
// Rules:
//   - Constant folding:    BinOp(Const(a), Const(b)) → Const(a op b)
//   - Identity elimination: x+0→x, x*1→x, x*0→0, x|0→x, x^0→x, x&-1→x
//   - Double negation:     ~~x→x, !!x→x, --x→x
//   - XOR-NOT:             Xor(x, -1) → Not(x)
//   - Double XOR-NOT:      Xor(Xor(x,-1),-1) → x
//   - Self-cancellation:   Sub(x,x)→0, Xor(x,x)→0
//   - Dead temp elimination: assigned but never used (non-Call) → remove

class IRSimplifier {
public:
    void simplify(IRFunc &func) {
        // IR-level copy/const propagation: replace temps that are assigned
        // from a Const or Var with the value directly in all uses
        propagateConsts(func);

        // Run expression simplification on all statements
        bool changed = true;
        for (int iter = 0; iter < 4 && changed; ++iter) {
            changed = false;
            for (auto &bb : func.blocks) {
                for (auto &stmt : bb.stmts) {
                    changed |= simplifyStmt(stmt);
                }
            }
        }

        // Dead temp elimination
        eliminateDeadTemps(func);
    }

private:
    // ── IR-level const propagation ────────────────────────────────
    // Replace Temp references with Const values where the temp is assigned
    // a simple constant.  This enables constant folding of branches like
    // (0 & 32) != 0 which become dead code.
    void propagateConsts(IRFunc &func) {
        // Pass 1: collect temps assigned to constants
        std::map<int, int64_t> constTemps;
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0 &&
                    stmt.expr && stmt.expr->isConst()) {
                    constTemps[stmt.destTemp] = stmt.expr->value;
                }
            }
        }
        if (constTemps.empty()) return;

        // Pass 1b: find temps used in Load address computation.
        // Propagating constants into these can cause the Load to resolve
        // to a BSS/static value instead of the runtime value.
        std::set<int> usedInLoadAddr;
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                // Scan for Load(Add(Temp(t), ...)) or Load(Temp(t))
                auto findLoadAddrTemps = [&](const IRExpr *e) {
                    if (!e) return;
                    std::vector<const IRExpr*> stk = {e};
                    while (!stk.empty()) {
                        auto *n = stk.back(); stk.pop_back();
                        if (n->op == IROp::Load && !n->kids.empty()) {
                            // Mark all temps in the address expression
                            auto *addr = n->kids[0].get();
                            std::vector<const IRExpr*> addrStk = {addr};
                            while (!addrStk.empty()) {
                                auto *a = addrStk.back(); addrStk.pop_back();
                                if (a->op == IROp::Temp)
                                    usedInLoadAddr.insert(a->tempId());
                                for (auto &k : a->kids) if (k) addrStk.push_back(k.get());
                            }
                        }
                        for (auto &k : n->kids) if (k) stk.push_back(k.get());
                    }
                };
                findLoadAddrTemps(stmt.expr.get());
                findLoadAddrTemps(stmt.addr.get());
                for (auto &a : stmt.args) findLoadAddrTemps(a.get());
            }
        }
        // Remove Load-address temps from const propagation
        for (int tid : usedInLoadAddr)
            constTemps.erase(tid);

        if (constTemps.empty()) return;

        // Pass 2: replace all Temp refs with the constant value
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                propagateConstsInExpr(stmt.expr, constTemps);
                propagateConstsInExpr(stmt.addr, constTemps);
                for (auto &a : stmt.args) propagateConstsInExpr(a, constTemps);
            }
        }
    }

    static void propagateConstsInExpr(std::unique_ptr<IRExpr> &e,
                                       const std::map<int, int64_t> &consts) {
        if (!e) return;
        if (e->op == IROp::Temp) {
            auto it = consts.find(e->tempId());
            if (it != consts.end()) {
                TypeRef t = e->typeRef;
                e = IRExpr::mkConst(it->second, t);
                return;
            }
        }
        for (auto &k : e->kids) propagateConstsInExpr(k, consts);
    }

    // ── Structural expression equality ──────────────────────────────
    static bool exprEqual(const IRExpr *a, const IRExpr *b) {
        if (!a && !b) return true;
        if (!a || !b) return false;
        if (a->op != b->op) return false;
        if (a->value != b->value) return false;
        if (a->name != b->name) return false;
        if (a->castKind != b->castKind) return false;
        if (a->kids.size() != b->kids.size()) return false;
        for (size_t i = 0; i < a->kids.size(); ++i)
            if (!exprEqual(a->kids[i].get(), b->kids[i].get()))
                return false;
        return true;
    }

    // ── Check if expression has side effects ────────────────────────
    static bool hasSideEffects(const IRExpr *e) {
        if (!e) return false;
        if (e->op == IROp::Call) return true;
        for (auto &k : e->kids)
            if (hasSideEffects(k.get())) return true;
        return false;
    }

    // ── Simplify all expressions in a statement ─────────────────────
    bool simplifyStmt(IRStmt &stmt) {
        bool changed = false;
        changed |= simplifyExpr(stmt.expr);
        changed |= simplifyExpr(stmt.addr);
        for (auto &a : stmt.args) changed |= simplifyExpr(a);
        return changed;
    }

    // ── Bottom-up expression rewrite ────────────────────────────────
    bool simplifyExpr(std::unique_ptr<IRExpr> &e) {
        if (!e) return false;

        // Recurse into children first (bottom-up)
        bool changed = false;
        for (auto &k : e->kids)
            changed |= simplifyExpr(k);

        // ── Constant folding: BinOp(Const, Const) → Const ──────────
        if (e->kids.size() == 2 && e->kids[0] && e->kids[1] &&
            e->kids[0]->isConst() && e->kids[1]->isConst()) {
            int64_t a = e->kids[0]->value, b = e->kids[1]->value;
            int64_t r = 0;
            bool folded = true;
            switch (e->op) {
            case IROp::Add: r = (int32_t)((uint32_t)a + (uint32_t)b); break;
            case IROp::Sub: r = (int32_t)((uint32_t)a - (uint32_t)b); break;
            case IROp::Mul: r = (int32_t)((uint32_t)a * (uint32_t)b); break;
            case IROp::SDiv: r = b ? (int32_t)(a / b) : 0; break;
            case IROp::UDiv: r = b ? (int32_t)((uint32_t)a / (uint32_t)b) : 0; break;
            case IROp::SMod: r = b ? (int32_t)(a % b) : 0; break;
            case IROp::UMod: r = b ? (int32_t)((uint32_t)a % (uint32_t)b) : 0; break;
            case IROp::Shl: r = (int32_t)((uint32_t)a << (b & 31)); break;
            case IROp::Shr: r = (int32_t)((uint32_t)a >> (b & 31)); break;
            case IROp::Sar: r = (int32_t)((int32_t)a >> (b & 31)); break;
            case IROp::And: r = a & b; break;
            case IROp::Or:  r = a | b; break;
            case IROp::Xor: r = a ^ b; break;
            case IROp::Eq:  r = (a == b) ? 1 : 0; break;
            case IROp::Ne:  r = (a != b) ? 1 : 0; break;
            case IROp::Slt: r = (a < b) ? 1 : 0; break;
            case IROp::Sle: r = (a <= b) ? 1 : 0; break;
            case IROp::Sgt: r = (a > b) ? 1 : 0; break;
            case IROp::Sge: r = (a >= b) ? 1 : 0; break;
            case IROp::Ult: r = ((uint32_t)a < (uint32_t)b) ? 1 : 0; break;
            case IROp::Ule: r = ((uint32_t)a <= (uint32_t)b) ? 1 : 0; break;
            case IROp::Ugt: r = ((uint32_t)a > (uint32_t)b) ? 1 : 0; break;
            case IROp::Uge: r = ((uint32_t)a >= (uint32_t)b) ? 1 : 0; break;
            default: folded = false;
            }
            if (folded) {
                TypeRef t = e->typeRef;
                e = IRExpr::mkConst(r, t);
                return true;
            }
        }

        // ── Unary constant folding ──────────────────────────────────
        if (e->kids.size() == 1 && e->kids[0] && e->kids[0]->isConst()) {
            int64_t a = e->kids[0]->value;
            bool folded = true;
            int64_t r = 0;
            switch (e->op) {
            case IROp::Neg:     r = (int32_t)(-(uint32_t)a); break;
            case IROp::Not:     r = (int32_t)(~(uint32_t)a); break;
            case IROp::BoolNot: r = (a == 0) ? 1 : 0; break;
            default: folded = false;
            }
            if (folded) {
                TypeRef t = e->typeRef;
                e = IRExpr::mkConst(r, t);
                return true;
            }
        }

        // ── Identity elimination ────────────────────────────────────
        if (e->kids.size() == 2 && e->kids[0] && e->kids[1]) {
            auto *lhs = e->kids[0].get();
            auto *rhs = e->kids[1].get();

            // Right-identity: x op const
            if (rhs->isConst()) {
                int64_t b = rhs->value;
                // x + 0, x - 0, x | 0, x ^ 0 → x
                if ((e->op == IROp::Add || e->op == IROp::Sub ||
                     e->op == IROp::Or  || e->op == IROp::Xor) && b == 0) {
                    e = std::move(e->kids[0]);
                    return true;
                }
                // x * 1, x / 1 → x
                if ((e->op == IROp::Mul || e->op == IROp::SDiv || e->op == IROp::UDiv) && b == 1) {
                    e = std::move(e->kids[0]);
                    return true;
                }
                // x * 0 → 0
                if (e->op == IROp::Mul && b == 0) {
                    e = IRExpr::mkConst(0, e->typeRef);
                    return true;
                }
                // x & -1 (all ones) → x
                if (e->op == IROp::And && (b == -1 || b == 0xFFFFFFFF)) {
                    e = std::move(e->kids[0]);
                    return true;
                }
                // x & 0 → 0
                if (e->op == IROp::And && b == 0) {
                    e = IRExpr::mkConst(0, e->typeRef);
                    return true;
                }
                // x << 0, x >> 0 → x
                if ((e->op == IROp::Shl || e->op == IROp::Shr || e->op == IROp::Sar) && b == 0) {
                    e = std::move(e->kids[0]);
                    return true;
                }
            }

            // Left-identity: const op x
            if (lhs->isConst()) {
                int64_t a = lhs->value;
                // 0 + x, 0 | x, 0 ^ x → x
                if ((e->op == IROp::Add || e->op == IROp::Or || e->op == IROp::Xor) && a == 0) {
                    e = std::move(e->kids[1]);
                    return true;
                }
                // 1 * x → x
                if (e->op == IROp::Mul && a == 1) {
                    e = std::move(e->kids[1]);
                    return true;
                }
                // 0 * x → 0
                if (e->op == IROp::Mul && a == 0) {
                    e = IRExpr::mkConst(0, e->typeRef);
                    return true;
                }
            }

            // ── Self-cancellation: x op x → 0 ──────────────────────
            if ((e->op == IROp::Sub || e->op == IROp::Xor) && exprEqual(lhs, rhs)) {
                e = IRExpr::mkConst(0, e->typeRef);
                return true;
            }

            // ── XOR with -1 → Not ──────────────────────────────────
            if (e->op == IROp::Xor && rhs->isConst() &&
                (rhs->value == -1 || rhs->value == (int64_t)0xFFFFFFFF)) {
                auto inner = std::move(e->kids[0]);
                TypeRef t = e->typeRef;
                e = IRExpr::mkUnary(IROp::Not, std::move(inner));
                e->typeRef = t;
                return true;
            }
        }

        // ── Double negation: Not(Not(x)) → x ───────────────────────
        if (e->op == IROp::Not && e->kids.size() == 1 && e->kids[0] &&
            e->kids[0]->op == IROp::Not && e->kids[0]->kids.size() == 1 && e->kids[0]->kids[0]) {
            e = std::move(e->kids[0]->kids[0]);
            return true;
        }

        // ── Double boolean negation: BoolNot(BoolNot(x)) → x ───────
        if (e->op == IROp::BoolNot && e->kids.size() == 1 && e->kids[0] &&
            e->kids[0]->op == IROp::BoolNot && e->kids[0]->kids.size() == 1 && e->kids[0]->kids[0]) {
            e = std::move(e->kids[0]->kids[0]);
            return true;
        }

        // ── Double arithmetic negation: Neg(Neg(x)) → x ────────────
        if (e->op == IROp::Neg && e->kids.size() == 1 && e->kids[0] &&
            e->kids[0]->op == IROp::Neg && e->kids[0]->kids.size() == 1 && e->kids[0]->kids[0]) {
            e = std::move(e->kids[0]->kids[0]);
            return true;
        }

        // ── BoolNot of comparison → negated comparison ──────────────
        if (e->op == IROp::BoolNot && e->kids.size() == 1 && e->kids[0]) {
            IROp inner = e->kids[0]->op;
            IROp neg = negateCompare(inner);
            if (neg != inner) {
                e->kids[0]->op = neg;
                e = std::move(e->kids[0]);
                return true;
            }
        }

        return changed;
    }

    // ── Negate a comparison op ──────────────────────────────────────
    static IROp negateCompare(IROp op) {
        switch (op) {
        case IROp::Eq:  return IROp::Ne;
        case IROp::Ne:  return IROp::Eq;
        case IROp::Slt: return IROp::Sge;
        case IROp::Sle: return IROp::Sgt;
        case IROp::Sgt: return IROp::Sle;
        case IROp::Sge: return IROp::Slt;
        case IROp::Ult: return IROp::Uge;
        case IROp::Ule: return IROp::Ugt;
        case IROp::Ugt: return IROp::Ule;
        case IROp::Uge: return IROp::Ult;
        default: return op;
        }
    }

    // ── Dead temp elimination ───────────────────────────────────────
    void eliminateDeadTemps(IRFunc &func) {
        // Count uses of each temp
        std::map<int, int> useCount;
        std::set<int> defined;

        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0)
                    defined.insert(stmt.destTemp);
                countUses(stmt.expr.get(), useCount);
                countUses(stmt.addr.get(), useCount);
                for (auto &a : stmt.args) countUses(a.get(), useCount);
                // Phi sources count as uses
                for (auto &[predId, srcTemp] : stmt.phiSources)
                    if (srcTemp >= 0) useCount[srcTemp]++;
            }
        }

        // Remove assignments to temps that are never used
        for (auto &bb : func.blocks) {
            bb.stmts.erase(
                std::remove_if(bb.stmts.begin(), bb.stmts.end(),
                    [&](const IRStmt &stmt) {
                        if (stmt.kind != IRStmtKind::Assign) return false;
                        if (stmt.destTemp < 0) return false;
                        if (useCount[stmt.destTemp] > 0) return false;
                        // Don't remove if RHS has side effects
                        if (hasSideEffects(stmt.expr.get())) return false;
                        return true;
                    }),
                bb.stmts.end());
        }
    }

    static void countUses(const IRExpr *e, std::map<int, int> &counts) {
        if (!e) return;
        if (e->op == IROp::Temp) counts[e->tempId()]++;
        for (auto &k : e->kids) countUses(k.get(), counts);
    }
};
