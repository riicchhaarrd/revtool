#pragma once
#include "ir.h"
#include "stabs_types.h"
#include <vector>
#include <map>
#include <set>
#include <algorithm>

// Forward declaration — full definition in macho.h (included before us by decompiler.h)
class MachOFile;
struct StabsFunction;

// ── Type Inference ──────────────────────────────────────────────────
// Constraint-based type inference for IR temps.
//
// Collects constraints from IR usage patterns:
//   - Load(Temp(t)) or Store(Temp(t), ...) -> t is a pointer
//   - Field(Temp(t), name, offset) -> t points to struct with field
//   - Call(name, args) with known prototype -> arg/ret types
//   - Phi(t1, t2) or Assign(t, t2) -> same type
//   - STABS annotations -> known type
//   - Binary ops: float + float -> float, ptr + int -> ptr
//
// Solves using union-find for SameAs constraints, then propagates
// known types through groups.

class TypeInferer {
public:
    void infer(IRFunc &func, const StabsTypeTable &types, const MachOFile *mf = nullptr) {
        m_func = &func;
        m_types = &types;
        m_mf = mf;
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

        // Collect constraints (two passes for convergence)
        for (int pass = 0; pass < 2; ++pass) {
            for (auto &bb : func.blocks) {
                for (auto &stmt : bb.stmts) {
                    collectStmtConstraints(stmt);
                }
            }
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
    const MachOFile *m_mf = nullptr;

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
        // If both have types, prefer the more specific one
        else if (ka != m_knownType.end() && kb != m_knownType.end()) {
            auto *ta = m_types->resolveType(ka->second);
            auto *tb = m_types->resolveType(kb->second);
            if (ta && tb) {
                // Float is highest priority (SSE operations are definitively float)
                bool aFloat = (ta->kind == StabsTypeKind::Float || ta->kind == StabsTypeKind::Double);
                bool bFloat = (tb->kind == StabsTypeKind::Float || tb->kind == StabsTypeKind::Double);
                if (bFloat && !aFloat)
                    m_knownType[ra] = kb->second;
                else if (!aFloat && !bFloat) {
                    // Prefer pointer/struct over plain int
                    if (ta->kind == StabsTypeKind::Int && tb->kind != StabsTypeKind::Int)
                        m_knownType[ra] = kb->second;
                }
            }
        }
    }

    void setType(int tid, TypeRef tref) {
        if (tref == NullType) return;
        int root = find(tid);
        auto kit = m_knownType.find(root);
        if (kit == m_knownType.end()) {
            m_knownType[root] = tref;
        } else {
            // Prefer more specific type: Float > Pointer > Struct > Int
            auto *existing = m_types->resolveType(kit->second);
            auto *candidate = m_types->resolveType(tref);
            if (existing && candidate) {
                bool candFloat = (candidate->kind == StabsTypeKind::Float || candidate->kind == StabsTypeKind::Double);
                bool exFloat = (existing->kind == StabsTypeKind::Float || existing->kind == StabsTypeKind::Double);
                if (candFloat && !exFloat)
                    m_knownType[root] = tref;
                else if (existing->kind == StabsTypeKind::Int && candidate->kind != StabsTypeKind::Int)
                    m_knownType[root] = tref;
            }
        }
    }

    void initExprTemps(const IRExpr *e) {
        if (!e) return;
        if (e->op == IROp::Temp) initTemp(e->tempId());
        for (auto &k : e->kids) initExprTemps(k.get());
    }

    bool isFloatType(TypeRef ref) const {
        auto *t = m_types->resolveType(ref);
        return t && (t->kind == StabsTypeKind::Float ||
                     t->kind == StabsTypeKind::Double ||
                     t->kind == StabsTypeKind::LongDouble);
    }

    bool isPointerType(TypeRef ref) const {
        auto *t = m_types->resolveType(ref);
        return t && t->kind == StabsTypeKind::Pointer;
    }

    void collectStmtConstraints(IRStmt &stmt) {
        switch (stmt.kind) {
        case IRStmtKind::Assign: {
            if (stmt.destTemp < 0 || !stmt.expr) break;

            // t = expr -> t has type of expr
            TypeRef exprT = inferExprType(stmt.expr.get());
            if (exprT != NullType) {
                // Don't propagate union/struct types to scalar temps
                auto *et = m_types->resolveType(exprT);
                if (et && (et->kind == StabsTypeKind::Union || et->kind == StabsTypeKind::Struct))
                    exprT = NullType;
                // Also check by formatted name (cross-CU type conflicts)
                // But preserve pointer-to-struct types (they're valid for temps)
                if (exprT != NullType) {
                    std::string fmt = m_types->formatType(exprT);
                    bool isPointer = fmt.find('*') != std::string::npos;
                    if (!isPointer) {
                        if (fmt.find("DvarValue") != std::string::npos ||
                            fmt.find("DvarLimits") != std::string::npos ||
                            fmt.find("union ") == 0 || fmt.find("struct ") == 0)
                            exprT = NullType;
                    }
                }
                if (exprT != NullType)
                    setType(stmt.destTemp, exprT);
            }

            // t = otherTemp -> propagate type (but don't unite if struct/union
            // to avoid spreading struct types to unrelated temps)
            if (stmt.expr->op == IROp::Temp) {
                int srcTemp = stmt.expr->tempId();
                TypeRef srcType = NullType;
                auto sit = m_knownType.find(find(srcTemp));
                if (sit != m_knownType.end()) srcType = sit->second;
                bool isStructType = false;
                if (srcType != NullType) {
                    auto *st = m_types->resolveType(srcType);
                    // Only block by-value struct types, not pointers-to-struct
                    isStructType = st && (st->kind == StabsTypeKind::Struct ||
                                          st->kind == StabsTypeKind::Union);
                    // Allow struct pointers to propagate
                    if (st && st->kind == StabsTypeKind::Pointer)
                        isStructType = false;
                    // Also check formatted name for cross-CU conflicts (only non-pointer)
                    if (!isStructType && srcType != NullType) {
                        std::string fmt = m_types->formatType(srcType);
                        if (fmt.find('*') == std::string::npos) {
                            if (fmt.find("State") != std::string::npos ||
                                fmt.find("_s") != std::string::npos)
                                isStructType = true;
                        }
                    }
                }
                if (isStructType) {
                    // Only set type, don't merge — prevents struct type spreading
                    if (exprT == NullType) setType(stmt.destTemp, srcType);
                } else {
                    unite(stmt.destTemp, srcTemp);
                }
            }

            // Assign from Call: propagate return type and match arg types
            if (stmt.expr->op == IROp::Call) {
                collectCallConstraints(stmt.expr.get());
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
            // Store(addr, val): addr (or addr's base) is a pointer
            if (stmt.addr) {
                auto *a = stmt.addr.get();
                if (a->op == IROp::Temp)
                    markAsPointer(a->tempId());
                else if (a->op == IROp::Add && !a->kids.empty() && a->kids[0] &&
                         a->kids[0]->op == IROp::Temp)
                    markAsPointer(a->kids[0]->tempId());
                else if (a->op == IROp::Field && !a->kids.empty() && a->kids[0] &&
                         a->kids[0]->op == IROp::Temp)
                    markAsPointer(a->kids[0]->tempId());
            }
            // Propagate: if we know the addr's pointee type, the stored value has that type
            if (stmt.addr && stmt.expr) {
                TypeRef addrType = inferExprType(stmt.addr.get());
                if (addrType != NullType) {
                    TypeRef pointeeType = m_types->derefPointer(addrType);
                    if (pointeeType != NullType && stmt.expr->op == IROp::Temp) {
                        setType(stmt.expr->tempId(), pointeeType);
                    }
                }
            }
            collectPointerConstraints(stmt.addr.get());
            break;
        }
        case IRStmtKind::VarSet: {
            // var = expr: if var has a known type, propagate to expr temp
            if (!stmt.destVar.empty() && stmt.expr && stmt.expr->op == IROp::Temp) {
                TypeRef varType = NullType;
                for (auto &p : m_func->params)
                    if (p.name == stmt.destVar && p.typeRef != NullType) { varType = p.typeRef; break; }
                if (varType == NullType) {
                    for (auto &l : m_func->locals)
                        if (l.name == stmt.destVar && l.typeRef != NullType) { varType = l.typeRef; break; }
                }
                if (varType != NullType)
                    setType(stmt.expr->tempId(), varType);
            }
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
            if (base->op == IROp::Temp) {
                // If the base has a type annotation (struct pointer), propagate it
                if (base->typeRef != NullType)
                    setType(base->tempId(), base->typeRef);
                else
                    markAsPointer(base->tempId());
            }
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
        if (!call || call->op != IROp::Call || !m_mf) return;
        if (call->name.empty()) return;

        // Look up the callee prototype from STABS
        const StabsFunction *sfn = m_mf->stabsFunctionByName(call->name);
        if (!sfn) return;

        // Match call arguments to parameter types
        int nArgs = std::min((int)call->kids.size(), (int)sfn->params.size());
        for (int i = 0; i < nArgs; ++i) {
            TypeRef paramType = sfn->params[i].typeRef;
            if (paramType == NullType) continue;
            auto *arg = call->kids[i].get();
            if (arg && arg->op == IROp::Temp) {
                setType(arg->tempId(), paramType);
            }
        }
    }

    void markAsPointer(int tid) {
        // Mark this temp as a pointer in the IRFunc so the emitter knows
        m_func->pointerTemps.insert(tid);
        int root = find(tid);
        // Don't override a known struct pointer type
        auto kit = m_knownType.find(root);
        if (kit != m_knownType.end() && kit->second != NullType) {
            auto *t = m_types->resolveType(kit->second);
            if (t && t->kind == StabsTypeKind::Pointer) return;
        }
        m_func->tempTypes[tid]; // ensure entry exists
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
        // &expr → pointer to expr's type (don't propagate struct types through AddrOf)
        if (e->op == IROp::AddrOf) return NullType;

        // Load(addr) -> type is the pointee type of addr
        if (e->op == IROp::Load && !e->kids.empty()) {
            // Special case: Load(Add(structPtr, const)) → field type
            auto *addr = e->kids[0].get();
            if (addr && addr->op == IROp::Add && addr->kids.size() == 2 &&
                addr->kids[1] && addr->kids[1]->isConst()) {
                TypeRef baseType = inferExprType(addr->kids[0].get());
                if (baseType != NullType) {
                    TypeRef pointee = m_types->derefPointer(baseType);
                    if (pointee != NullType) {
                        auto *pt = m_types->resolveType(pointee);
                        if (pt && (pt->kind == StabsTypeKind::Struct || pt->kind == StabsTypeKind::Union)) {
                            // Look up the actual field type at this offset
                            int offset = (int)addr->kids[1]->value;
                            auto *field = m_types->findFieldAtOffset(pointee, offset);
                            if (field && field->typeRef != NullType) {
                                auto *ft = m_types->resolveType(field->typeRef);
                                // Return the field type if it's a pointer or scalar
                                if (ft && ft->kind == StabsTypeKind::Pointer)
                                    return field->typeRef;
                                if (ft && ft->kind != StabsTypeKind::Struct &&
                                    ft->kind != StabsTypeKind::Union)
                                    return field->typeRef;
                            }
                            // Fall through to NullType for struct/union fields
                            return NullType;
                        }
                    }
                }
            }
            TypeRef addrType = inferExprType(e->kids[0].get());
            if (addrType != NullType) {
                TypeRef pointee = m_types->derefPointer(addrType);
                if (pointee != NullType) return pointee;
            }
        }

        // Binary ops: propagate float and pointer types
        if (e->kids.size() == 2) {
            TypeRef lhsT = inferExprType(e->kids[0].get());
            TypeRef rhsT = inferExprType(e->kids[1].get());

            // Comparisons always produce int
            if (e->op >= IROp::Eq && e->op <= IROp::Uge)
                return NullType;

            // If either operand is float, result is float
            if (isFloatType(lhsT)) return lhsT;
            if (isFloatType(rhsT)) return rhsT;

            // Pointer arithmetic: ptr + int → ptr, ptr - int → ptr
            if (e->op == IROp::Add || e->op == IROp::Sub) {
                if (isPointerType(lhsT)) return lhsT;
                if (e->op == IROp::Add && isPointerType(rhsT)) return rhsT;
            }

            // For Mul/Div, never propagate struct/union types (arithmetic = scalar)
            if (e->op == IROp::Mul || e->op == IROp::SDiv || e->op == IROp::UDiv ||
                e->op == IROp::SMod || e->op == IROp::UMod) {
                auto check = [&](TypeRef t) -> bool {
                    if (t == NullType) return false;
                    auto *rt = m_types->resolveType(t);
                    if (rt && (rt->kind == StabsTypeKind::Struct ||
                               rt->kind == StabsTypeKind::Union ||
                               rt->kind == StabsTypeKind::Pointer))
                        return true;
                    // Check formatted name for cross-CU conflicts
                    std::string fmt = m_types->formatType(t);
                    return fmt.find("State") != std::string::npos;
                };
                if (check(lhsT)) lhsT = NullType;
                if (check(rhsT)) rhsT = NullType;
            }
            // Otherwise propagate non-null types
            if (lhsT != NullType) return lhsT;
            if (rhsT != NullType) return rhsT;
        }

        // Unary ops: propagate operand type
        if (e->kids.size() == 1 && !e->kids.empty()) {
            return inferExprType(e->kids[0].get());
        }

        // Cast: return target type
        if (e->op == IROp::Cast) {
            if (e->castKind == CastKind::IntToFloat) {
                // Find the STABS float type
                // Search for a common float type in the type table
                for (auto &p : m_func->params)
                    if (isFloatType(p.typeRef)) return p.typeRef;
                for (auto &l : m_func->locals)
                    if (isFloatType(l.typeRef)) return l.typeRef;
            }
        }

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
