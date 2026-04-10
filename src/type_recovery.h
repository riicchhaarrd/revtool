#pragma once
#include "ir.h"
#include "stabs_types.h"
#include <map>
#include <set>

// ── Type Recovery Pass ─────────────────────────────────────────────────
// Transforms raw pointer arithmetic on struct globals into typed field accesses.
//
// Before: Store(Add(Var("lagometer"), Mul(reg, 4)), val)
//         → lagometer[reg] = val   (BROKEN: lagometer is struct, not array)
//
// After:  Store(Add(AddrOf(Field(Var("lagometer"), "frameSamples", 0, arrType)),
//                   Mul(reg, 4)), val)
//         → lagometer.frameSamples[reg] = val   (CORRECT)
//
// Also handles:
//   Add(Var("struct_global"), const_offset)  → Field(Var(...), "fieldName", off)
//   Load(Add(Var("struct_global"), const))   → Load(AddrOf(Field(...)))
//   VarSet("struct_global", val)             → Store(AddrOf(Field(..., 0)), val)

class TypeRecovery {
public:
    void run(IRFunc &func, const StabsTypeTable &types) {
        m_func = &func;
        m_types = &types;

        // Build map: global name → (typeRef, resolved StabsTypeInfo)
        // Only for struct/union globals
        m_structGlobals.clear();
        for (auto &g : types.globals()) {
            if (g.name.empty() || g.address == 0) continue;
            TypeRef tr = g.typeRef;
            if (tr == NullType) continue;
            auto *t = types.resolveType(tr);
            if (!t) continue;
            if (t->kind == StabsTypeKind::Struct || t->kind == StabsTypeKind::Union) {
                if (t->sizeBytes > 0 && !t->fields.empty())
                    m_structGlobals[g.name] = {tr, t};
            }
        }
        if (m_structGlobals.empty()) return;

        // Walk all statements and transform expressions
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                // Transform Store addresses
                if (stmt.kind == IRStmtKind::Store && stmt.addr) {
                    stmt.addr = transformExpr(std::move(stmt.addr), true);
                }
                // Transform Load/other expressions
                if (stmt.expr)
                    stmt.expr = transformExpr(std::move(stmt.expr), false);

                // Transform VarSet to struct globals:
                // VarSet("struct_global", val) where storeSize < struct size
                // → Store(AddrOf(Field(Var(name), field0)), val)
                if (stmt.kind == IRStmtKind::VarSet && !stmt.destVar.empty()) {
                    auto git = m_structGlobals.find(stmt.destVar);
                    if (git != m_structGlobals.end()) {
                        auto *st = git->second.info;
                        if (st && stmt.storeSize > 0 && stmt.storeSize < (int)st->sizeBytes) {
                            std::string field0 = m_types->formatFieldAccess(git->second.typeRef, 0);
                            auto *f0 = m_types->findFieldAtOffset(git->second.typeRef, 0);
                            if (f0 && !field0.empty()) {
                                // Convert VarSet → Store(AddrOf(Field(Var, field0)), expr)
                                auto var = IRExpr::mkVar(stmt.destVar, git->second.typeRef);
                                auto fld = IRExpr::mkField(std::move(var), field0, 0, f0->typeRef);
                                auto addr = IRExpr::mkAddrOf(std::move(fld));
                                stmt.kind = IRStmtKind::Store;
                                stmt.addr = std::move(addr);
                                // Keep stmt.expr as is
                                stmt.destVar.clear();
                            }
                        }
                    }
                }
            }
        }
    }

private:
    IRFunc *m_func = nullptr;
    const StabsTypeTable *m_types = nullptr;

    struct StructInfo {
        TypeRef typeRef;
        const StabsTypeInfo *info;
    };
    std::map<std::string, StructInfo> m_structGlobals;

    // Check if an expression is Var(structGlobal)
    const StructInfo* getStructGlobal(const IRExpr *e) {
        if (!e || e->op != IROp::Var || e->name.empty()) return nullptr;
        auto it = m_structGlobals.find(e->name);
        return (it != m_structGlobals.end()) ? &it->second : nullptr;
    }

    // Transform an expression tree, replacing struct global arithmetic with Field accesses
    std::unique_ptr<IRExpr> transformExpr(std::unique_ptr<IRExpr> e, bool isAddr) {
        if (!e) return e;

        // Recursively transform children first (bottom-up)
        for (auto &k : e->kids) {
            if (k) k = transformExpr(std::move(k), false);
        }

        // Pattern 1: Add(Var(structGlobal), Const(offset))
        // → AddrOf(Field(Var(structGlobal), fieldName, offset))
        if (e->op == IROp::Add && e->kids.size() == 2) {
            IRExpr *base = nullptr;
            IRExpr *offset = nullptr;
            int constOff = 0;
            bool hasConstOffset = false;

            // Check both orderings: Add(var, const) or Add(const, var)
            for (int i = 0; i < 2; ++i) {
                auto *a = e->kids[i].get();
                auto *b = e->kids[1-i].get();
                if (b && b->isConst() && b->value >= 0) {
                    auto *sg = getStructGlobal(a);
                    if (sg) {
                        base = a;
                        constOff = (int)b->value;
                        hasConstOffset = true;
                        break;
                    }
                }
            }

            if (hasConstOffset && base) {
                auto *sg = getStructGlobal(base);
                if (constOff > 0 && constOff < (int)sg->info->sizeBytes) {
                    std::string fieldName = m_types->formatFieldAccess(sg->typeRef, constOff);
                    auto *fld = m_types->findFieldAtOffset(sg->typeRef, constOff);
                    if (fld && !fieldName.empty()) {
                        auto var = IRExpr::mkVar(base->name, sg->typeRef);
                        auto field = IRExpr::mkField(std::move(var), fieldName, constOff, fld->typeRef);
                        return IRExpr::mkAddrOf(std::move(field));
                    }
                }
            }

            // Pattern 2: Add(Var(structGlobal), Mul(idx, scale))
            // → Add(AddrOf(Field(Var(structGlobal), arrayField)), Mul(idx, scale))
            // This handles array element access at offset 0 in a struct
            for (int i = 0; i < 2; ++i) {
                auto *a = e->kids[i].get();
                auto *b = e->kids[1-i].get();
                auto *sg = getStructGlobal(a);
                if (sg && b && b->op == IROp::Mul) {
                    // Array at offset 0: check if first field is an array
                    auto *f0 = m_types->findFieldAtOffset(sg->typeRef, 0);
                    if (f0) {
                        auto *f0t = m_types->resolveType(f0->typeRef);
                        if (f0t && f0t->kind == StabsTypeKind::Array) {
                            std::string fieldName = f0->name;
                            auto var = IRExpr::mkVar(a->name, sg->typeRef);
                            auto field = IRExpr::mkField(std::move(var), fieldName, 0, f0->typeRef);
                            auto addr = IRExpr::mkAddrOf(std::move(field));
                            // Reconstruct: Add(AddrOf(Field), Mul(idx, scale))
                            auto newAdd = std::make_unique<IRExpr>();
                            newAdd->op = IROp::Add;
                            newAdd->kids.push_back(std::move(addr));
                            newAdd->kids.push_back(e->kids[1-i]->clone());
                            return newAdd;
                        }
                    }
                }
            }

            // Pattern 3: Add(Var(structGlobal), Add(Mul(idx, scale), const_offset))
            // → Add(AddrOf(Field(Var, arrayField, off)), Mul(idx, scale))
            // Handles array fields at non-zero offsets
            for (int i = 0; i < 2; ++i) {
                auto *a = e->kids[i].get();
                auto *b = e->kids[1-i].get();
                auto *sg = getStructGlobal(a);
                if (sg && b && b->op == IROp::Add && b->kids.size() == 2) {
                    IRExpr *mulPart = nullptr, *constPart = nullptr;
                    for (int j = 0; j < 2; ++j) {
                        if (b->kids[j]->op == IROp::Mul) mulPart = b->kids[j].get();
                        if (b->kids[j]->isConst()) constPart = b->kids[j].get();
                    }
                    // Also check: Mul could be Shl (shift left = multiply by power of 2)
                    if (!mulPart) {
                        for (int j = 0; j < 2; ++j) {
                            if (b->kids[j]->op == IROp::Shl) mulPart = b->kids[j].get();
                        }
                    }
                    if (mulPart && constPart) {
                        int off = (int)constPart->value;
                        if (off >= 0 && off < (int)sg->info->sizeBytes) {
                            auto *fld = m_types->findFieldAtOffset(sg->typeRef, off);
                            if (fld) {
                                auto *ft = m_types->resolveType(fld->typeRef);
                                if (ft && ft->kind == StabsTypeKind::Array) {
                                    auto var = IRExpr::mkVar(a->name, sg->typeRef);
                                    auto field = IRExpr::mkField(std::move(var), fld->name, off, fld->typeRef);
                                    auto addr = IRExpr::mkAddrOf(std::move(field));
                                    auto newAdd = std::make_unique<IRExpr>();
                                    newAdd->op = IROp::Add;
                                    newAdd->kids.push_back(std::move(addr));
                                    newAdd->kids.push_back(mulPart->clone());
                                    return newAdd;
                                }
                                // Non-array field with index: just resolve the constant offset
                                std::string fieldName = m_types->formatFieldAccess(sg->typeRef, off);
                                if (!fieldName.empty()) {
                                    auto var = IRExpr::mkVar(a->name, sg->typeRef);
                                    auto field = IRExpr::mkField(std::move(var), fieldName, off, fld->typeRef);
                                    auto addr = IRExpr::mkAddrOf(std::move(field));
                                    auto newAdd = std::make_unique<IRExpr>();
                                    newAdd->op = IROp::Add;
                                    newAdd->kids.push_back(std::move(addr));
                                    newAdd->kids.push_back(mulPart->clone());
                                    return newAdd;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Pattern 4: Load(Var(structGlobal))
        // → Load(AddrOf(Field(Var, field0)))  — load of first field
        if (e->op == IROp::Load && e->kids.size() == 1) {
            auto *sg = getStructGlobal(e->kids[0].get());
            if (sg) {
                auto *f0 = m_types->findFieldAtOffset(sg->typeRef, 0);
                if (f0) {
                    std::string f0name = f0->name;
                    auto var = IRExpr::mkVar(e->kids[0]->name, sg->typeRef);
                    auto field = IRExpr::mkField(std::move(var), f0name, 0, f0->typeRef);
                    e->kids[0] = IRExpr::mkAddrOf(std::move(field));
                }
            }
        }

        return e;
    }
};
