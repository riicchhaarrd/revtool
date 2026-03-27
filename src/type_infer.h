#pragma once
#include "ir.h"
#include "stabs_types.h"
#include <vector>
#include <map>
#include <set>
#include <algorithm>

// ── Type Inference ──────────────────────────────────────────────────
// Constraint-based type inference for IR temps.
//
// Collects constraints from IR usage patterns:
//   - Load(Temp(t)) or Store(Temp(t), ...) -> t is a pointer
//   - Field(Temp(t), name, offset) -> t points to struct with field
//   - Call(name, args) with known prototype -> arg/ret types
//   - Phi(t1, t2) or Assign(t, t2) -> same type
//   - STABS annotations -> known type
//
// Solves using union-find for SameAs constraints, then propagates
// known types through groups.

class TypeInferer {
public:
    void infer(IRFunc &func, const StabsTypeTable &types) {
        m_func = &func;
        m_types = &types;
        m_parent.clear();
        m_rank.clear();
        m_knownType.clear();

        // Initialize union-find for all temps
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0)
                    initTemp(stmt.destTemp);
                initExprTemps(stmt.expr.get());
                initExprTemps(stmt.addr.get());
                for (auto &a : stmt.args) initExprTemps(a.get());
            }
        }

        // Seed known types from STABS tempTypes
        for (auto &[tid, tref] : func.tempTypes) {
            if (tref != NullType)
                m_knownType[find(tid)] = tref;
        }

        // Collect constraints
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                collectStmtConstraints(stmt);
            }
        }

        // Propagate: each temp gets the type of its union-find root
        for (auto &[tid, tref] : func.tempTypes) {
            (void)tid; (void)tref; // just to iterate
        }
        // Write back inferred types to func.tempTypes
        for (auto &[tid, _] : m_parent) {
            int root = find(tid);
            auto kit = m_knownType.find(root);
            if (kit != m_knownType.end() && kit->second != NullType) {
                if (func.tempTypes.find(tid) == func.tempTypes.end() ||
                    func.tempTypes[tid] == NullType) {
                    func.tempTypes[tid] = kit->second;
                }
            }
        }

        // Second pass: infer pointer types from dereference patterns
        inferPointerTypes(func);
    }

private:
    IRFunc *m_func = nullptr;
    const StabsTypeTable *m_types = nullptr;

    // Union-find
    std::map<int, int> m_parent;
    std::map<int, int> m_rank;
    std::map<int, TypeRef> m_knownType;

    void initTemp(int tid) {
        if (m_parent.find(tid) == m_parent.end()) {
            m_parent[tid] = tid;
            m_rank[tid] = 0;
        }
    }

    int find(int x) {
        if (m_parent.find(x) == m_parent.end()) { initTemp(x); return x; }
        if (m_parent[x] != x)
            m_parent[x] = find(m_parent[x]); // path compression
        return m_parent[x];
    }

    void unite(int a, int b) {
        int ra = find(a), rb = find(b);
        if (ra == rb) return;
        // Merge by rank
        if (m_rank[ra] < m_rank[rb]) std::swap(ra, rb);
        m_parent[rb] = ra;
        if (m_rank[ra] == m_rank[rb]) m_rank[ra]++;
        // Propagate known type
        auto ka = m_knownType.find(ra);
        auto kb = m_knownType.find(rb);
        if (ka == m_knownType.end() && kb != m_knownType.end())
            m_knownType[ra] = kb->second;
        else if (ka != m_knownType.end() && kb == m_knownType.end())
            m_knownType[ra] = ka->second;
        // If both have types, prefer the more specific (non-int) one
        else if (ka != m_knownType.end() && kb != m_knownType.end()) {
            auto *ta = m_types->resolveType(ka->second);
            auto *tb = m_types->resolveType(kb->second);
            if (ta && tb) {
                // Prefer pointer/struct over plain int
                if (ta->kind == StabsTypeKind::Int && tb->kind != StabsTypeKind::Int)
                    m_knownType[ra] = kb->second;
            }
        }
    }

    void initExprTemps(const IRExpr *e) {
        if (!e) return;
        if (e->op == IROp::Temp) initTemp(e->tempId());
        for (auto &k : e->kids) initExprTemps(k.get());
    }

    void collectStmtConstraints(IRStmt &stmt) {
        switch (stmt.kind) {
        case IRStmtKind::Assign: {
            if (stmt.destTemp < 0 || !stmt.expr) break;

            // t = expr -> t has type of expr
            TypeRef exprT = inferExprType(stmt.expr.get());
            if (exprT != NullType) {
                int root = find(stmt.destTemp);
                if (m_knownType.find(root) == m_knownType.end())
                    m_knownType[root] = exprT;
            }

            // t = otherTemp -> same type (union)
            if (stmt.expr->op == IROp::Temp) {
                unite(stmt.destTemp, stmt.expr->tempId());
            }
            break;
        }
        case IRStmtKind::Phi: {
            if (stmt.destTemp < 0) break;
            // All phi sources have the same type as the dest
            for (auto &[predId, srcTemp] : stmt.phiSources) {
                if (srcTemp >= 0)
                    unite(stmt.destTemp, srcTemp);
            }
            break;
        }
        case IRStmtKind::Store: {
            // Store(addr, val): if addr is a Temp, it's a pointer
            if (stmt.addr && stmt.addr->op == IROp::Temp) {
                markAsPointer(stmt.addr->tempId());
            }
            // Also check addr children for pointer temps
            collectPointerConstraints(stmt.addr.get());
            break;
        }
        case IRStmtKind::Call: {
            // Function call: try to match argument types from prototype
            if (stmt.expr && stmt.expr->op == IROp::Call)
                collectCallConstraints(stmt.expr.get());
            break;
        }
        default:
            break;
        }

        // Walk all expressions for Load and Field constraints
        collectExprConstraints(stmt.expr.get());
        collectExprConstraints(stmt.addr.get());
        for (auto &a : stmt.args) collectExprConstraints(a.get());
    }

    void collectExprConstraints(const IRExpr *e) {
        if (!e) return;

        // Load(Temp(t)) -> t is a pointer
        if (e->op == IROp::Load && !e->kids.empty() && e->kids[0]) {
            auto *addr = e->kids[0].get();
            if (addr->op == IROp::Temp)
                markAsPointer(addr->tempId());
            collectPointerConstraints(addr);
        }

        // Field(Temp(t), name, offset) -> t points to a struct
        if (e->op == IROp::Field && !e->kids.empty() && e->kids[0]) {
            auto *base = e->kids[0].get();
            if (base->op == IROp::Temp)
                markAsPointer(base->tempId());
        }

        // Call expression: collect arg type constraints
        if (e->op == IROp::Call)
            collectCallConstraints(e);

        for (auto &k : e->kids) collectExprConstraints(k.get());
    }

    void collectPointerConstraints(const IRExpr *e) {
        if (!e) return;
        // Add(Temp(t), ...) in a dereference context -> t is a pointer
        if (e->op == IROp::Add && !e->kids.empty()) {
            if (e->kids[0] && e->kids[0]->op == IROp::Temp)
                markAsPointer(e->kids[0]->tempId());
        }
    }

    void collectCallConstraints(const IRExpr *call) {
        if (!call || call->op != IROp::Call) return;
        // Try to resolve the function prototype from STABS
        const StabsFunction *sfn = nullptr;
        if (!call->name.empty()) {
            // Look up by name in STABS
            // We don't have direct access to MachOFile here, but we have the type table
            // Use the call's return type annotation if present
        }
        // If the call itself has a return type annotation, propagate it
        // (handled by parent Assign statement)
    }

    void markAsPointer(int tid) {
        int root = find(tid);
        // Don't override a known struct pointer with plain pointer
        auto kit = m_knownType.find(root);
        if (kit != m_knownType.end() && kit->second != NullType) {
            auto *t = m_types->resolveType(kit->second);
            if (t && t->kind == StabsTypeKind::Pointer) return; // already a pointer type
        }
        // We note this temp is a pointer but can't infer the pointee type
        // without more context.  Just mark it for the emitter.
        m_func->tempTypes[tid]; // ensure entry exists (default NullType)
    }

    TypeRef inferExprType(const IRExpr *e) {
        if (!e) return NullType;
        if (e->typeRef != NullType) return e->typeRef;
        if (e->op == IROp::Temp) {
            int root = find(e->tempId());
            auto kit = m_knownType.find(root);
            if (kit != m_knownType.end()) return kit->second;
            return m_func->tempType(e->tempId());
        }
        if (e->op == IROp::Var) {
            // Look up var type from params/locals
            for (auto &p : m_func->params)
                if (p.name == e->name && p.typeRef != NullType) return p.typeRef;
            for (auto &l : m_func->locals)
                if (l.name == e->name && l.typeRef != NullType) return l.typeRef;
        }
        if (e->op == IROp::Field) return e->typeRef;
        if (e->op == IROp::Call) return e->typeRef;
        return NullType;
    }

    // Second pass: mark temps as pointer type when they are dereferenced
    void inferPointerTypes(IRFunc &func) {
        // Collect pointer-used temps
        std::set<int> ptrTemps;
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                if (stmt.kind == IRStmtKind::Store && stmt.addr) {
                    collectDereferencedTemps(stmt.addr.get(), ptrTemps);
                }
                collectLoadPtrTemps(stmt.expr.get(), ptrTemps);
                collectLoadPtrTemps(stmt.addr.get(), ptrTemps);
                for (auto &a : stmt.args) collectLoadPtrTemps(a.get(), ptrTemps);
            }
        }
        // For each pointer temp without a type, mark it
        // (this info is used by the emitter for pointer declarations)
        for (int tid : ptrTemps) {
            if (func.tempTypes.find(tid) == func.tempTypes.end())
                func.tempTypes[tid] = NullType; // ensure exists for emitter detection
        }
    }

    void collectDereferencedTemps(const IRExpr *e, std::set<int> &out) {
        if (!e) return;
        if (e->op == IROp::Temp) out.insert(e->tempId());
        for (auto &k : e->kids) {
            if (k && k->op == IROp::Temp) out.insert(k->tempId());
        }
    }

    void collectLoadPtrTemps(const IRExpr *e, std::set<int> &out) {
        if (!e) return;
        if (e->op == IROp::Load && !e->kids.empty() && e->kids[0]) {
            auto *addr = e->kids[0].get();
            if (addr->op == IROp::Temp) out.insert(addr->tempId());
        }
        if (e->op == IROp::Field && !e->kids.empty() && e->kids[0]) {
            auto *base = e->kids[0].get();
            if (base->op == IROp::Temp) out.insert(base->tempId());
        }
        for (auto &k : e->kids) collectLoadPtrTemps(k.get(), out);
    }
};
