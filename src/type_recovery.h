#pragma once
#include "ir.h"
#include "stabs_types.h"
#include <map>
#include <set>
#include <vector>
#include <algorithm>

// ── Type Recovery Pass ─────────────────────────────────────────────────
// Two-phase pass:
//
// Phase 1 — Struct Inference:
//   Scans IR for memory access patterns on globals/variables.
//   For globals typed as opaque blobs (char[], int, or no STABS struct body),
//   infers struct layouts from access offsets, sizes, and value types.
//   Works even WITHOUT debug info — purely from usage patterns.
//
// Phase 2 — IR Transformation:
//   Rewrites raw pointer arithmetic into typed Field access nodes using
//   both STABS struct definitions and inferred struct layouts.

class TypeRecovery {
public:
    void run(IRFunc &func, const StabsTypeTable &types) {
        m_func = &func;
        m_types = &types;
        m_inferredStructs.clear();

        // Struct-globals map is the same across every function in a binary —
        // the type table and globals list don't change per-function.  Scanning
        // ~1160 globals per function dominates TypeRecovery cost for large
        // source files (rb_backend: 50 funcs × 1160 = 58k wasted scans).
        // Cache on first call keyed by the type table pointer so a rebuild
        // only happens if the binary (and thus its types) changes.
        static const StabsTypeTable *cachedTypes = nullptr;
        static std::map<std::string, StructInfo> cachedGlobals;
        if (cachedTypes != &types) {
            cachedGlobals.clear();
            for (auto &g : types.globals()) {
                if (g.name.empty() || g.address == 0) continue;
                TypeRef tr = g.typeRef;
                if (tr == NullType) continue;
                auto *t = types.resolveType(tr);
                if (!t) continue;
                if (t->kind == StabsTypeKind::Struct || t->kind == StabsTypeKind::Union) {
                    if (t->sizeBytes > 0 && !t->fields.empty())
                        cachedGlobals[g.name] = {tr, t};
                }
            }
            cachedTypes = &types;
        }
        m_structGlobals = cachedGlobals;

        // Phase 1: Infer struct layouts from access patterns
        inferStructLayouts(func);

        // Merge inferred structs into the lookup table
        // (only for globals NOT already in m_structGlobals)
        for (auto &[name, layout] : m_inferredStructs) {
            if (m_structGlobals.count(name)) continue;
            if (layout.fields.size() >= 2) // need at least 2 fields to be a struct
                m_structGlobals[name] = {NullType, nullptr};
        }

        if (m_structGlobals.empty() && m_inferredStructs.empty()) return;

        // Phase 2: Transform IR expressions
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                if (stmt.kind == IRStmtKind::Store && stmt.addr)
                    stmt.addr = transformExpr(std::move(stmt.addr), true);
                if (stmt.expr)
                    stmt.expr = transformExpr(std::move(stmt.expr), false);

                // VarSet to struct global → Store to first field
                if (stmt.kind == IRStmtKind::VarSet && !stmt.destVar.empty()) {
                    auto git = m_structGlobals.find(stmt.destVar);
                    if (git != m_structGlobals.end() && git->second.info) {
                        auto *st = git->second.info;
                        if (st && stmt.storeSize > 0 && stmt.storeSize < (int)st->sizeBytes) {
                            std::string field0 = m_types->formatFieldAccess(git->second.typeRef, 0);
                            auto *f0 = m_types->findFieldAtOffset(git->second.typeRef, 0);
                            if (f0 && !field0.empty()) {
                                auto var = IRExpr::mkVar(stmt.destVar, git->second.typeRef);
                                auto fld = IRExpr::mkField(std::move(var), field0, 0, f0->typeRef);
                                auto addr = IRExpr::mkAddrOf(std::move(fld));
                                stmt.kind = IRStmtKind::Store;
                                stmt.addr = std::move(addr);
                                stmt.destVar.clear();
                            }
                        }
                    }
                    // Also handle inferred structs (no STABS type info)
                    else {
                        auto iit = m_inferredStructs.find(stmt.destVar);
                        if (iit != m_inferredStructs.end() && iit->second.fields.size() >= 2) {
                            auto &layout = iit->second;
                            auto fit = layout.fields.find(0);
                            if (fit != layout.fields.end() &&
                                stmt.storeSize > 0 && stmt.storeSize < layout.totalSize) {
                                auto var = IRExpr::mkVar(stmt.destVar);
                                auto fld = IRExpr::mkField(std::move(var), fit->second.name, 0);
                                auto addr = IRExpr::mkAddrOf(std::move(fld));
                                stmt.kind = IRStmtKind::Store;
                                stmt.addr = std::move(addr);
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

    // ── Inferred Field ──
    struct InferredField {
        std::string name;      // "field_0x10" or resolved name
        int offset;            // byte offset
        int size;              // access size (1, 2, 4, 8)
        bool isFloat = false;  // accessed as float?
        bool isPointer = false;// used as pointer (dereferenced)?
        bool isArray = false;  // accessed with variable index?
        int arrayScale = 0;    // element size for arrays
    };

    struct InferredStruct {
        std::map<int, InferredField> fields;  // offset → field
        int totalSize = 0;
    };
    std::map<std::string, InferredStruct> m_inferredStructs;

    // ── Phase 1: Scan IR and infer struct layouts ──

    void inferStructLayouts(IRFunc &func) {
        // Collect all access patterns: (globalName, offset, size, type_hints)
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                // Store(Add(Var(g), const), val) → field at const offset
                if (stmt.kind == IRStmtKind::Store && stmt.addr) {
                    scanAddrForAccess(stmt.addr.get(), stmt.storeSize,
                                     stmt.expr.get(), true);
                }
                // Scan expressions for Load(Add(Var(g), const))
                scanExprForAccess(stmt.expr.get());
                scanExprForAccess(stmt.addr.get());
                for (auto &a : stmt.args) scanExprForAccess(a.get());
            }
        }

        // Post-process: name fields and detect arrays
        for (auto &[name, layout] : m_inferredStructs) {
            // Compute total size from max offset + size
            int maxEnd = 0;
            for (auto &[off, f] : layout.fields) {
                int end = off + f.size;
                if (end > maxEnd) maxEnd = end;
            }
            layout.totalSize = maxEnd;

            // Name fields
            for (auto &[off, f] : layout.fields) {
                if (f.isFloat)
                    f.name = "f_0x" + toHex(off);
                else if (f.isPointer)
                    f.name = "p_0x" + toHex(off);
                else
                    f.name = "field_0x" + toHex(off);
            }

            // Detect array patterns: consecutive accesses at regular intervals
            detectArrayFields(layout);
        }
    }

    // Check if a global should be analyzed (not already a known struct)
    bool shouldInfer(const std::string &name) {
        if (name.empty()) return false;
        // Skip if already a fully-defined struct
        if (m_structGlobals.count(name)) return false;
        // Skip small/temp names
        if (name[0] == 'v' && name.size() <= 4) return false;
        if (name[0] == 't' && isdigit(name[1])) return false;
        return true;
    }

    void recordAccess(const std::string &globalName, int offset, int size,
                      bool isFloat, bool isPointer, bool isStore) {
        if (!shouldInfer(globalName)) return;
        if (offset < 0 || offset > 65536) return; // sanity check
        if (size <= 0 || size > 8) size = 4;

        auto &layout = m_inferredStructs[globalName];
        auto &f = layout.fields[offset];
        f.offset = offset;
        if (f.size == 0) f.size = size;
        if (isFloat) f.isFloat = true;
        if (isPointer) f.isPointer = true;
    }

    void recordArrayAccess(const std::string &globalName, int baseOffset, int scale) {
        if (!shouldInfer(globalName)) return;
        auto &layout = m_inferredStructs[globalName];
        auto &f = layout.fields[baseOffset];
        f.offset = baseOffset;
        f.isArray = true;
        f.arrayScale = scale;
        if (f.size == 0) f.size = 4;
    }

    void scanAddrForAccess(const IRExpr *addr, int storeSize,
                           const IRExpr *val, bool isStore) {
        if (!addr) return;

        // Add(Var(g), Const(off)) → field access at offset
        if (addr->op == IROp::Add && addr->kids.size() == 2) {
            for (int i = 0; i < 2; ++i) {
                auto *a = addr->kids[i].get();
                auto *b = addr->kids[1-i].get();
                if (a && a->op == IROp::Var && b && b->isConst() && b->value >= 0) {
                    bool isFloat = (storeSize == 5) || isFloatExpr(val);
                    bool isPtr = false;
                    recordAccess(a->name, (int)b->value, storeSize == 5 ? 4 : storeSize,
                                isFloat, isPtr, isStore);
                }
                // Add(Var(g), Mul(idx, scale)) → array at offset 0
                if (a && a->op == IROp::Var && b && b->op == IROp::Mul &&
                    b->kids.size() == 2 && b->kids[1] && b->kids[1]->isConst()) {
                    int scale = (int)b->kids[1]->value;
                    if (scale > 0 && scale <= 256)
                        recordArrayAccess(a->name, 0, scale);
                }
                // Add(Var(g), Add(Mul(idx, scale), const_off)) → array at const_off
                if (a && a->op == IROp::Var && b && b->op == IROp::Add &&
                    b->kids.size() == 2) {
                    IRExpr *mul = nullptr, *con = nullptr;
                    for (int j = 0; j < 2; ++j) {
                        if (b->kids[j]->op == IROp::Mul || b->kids[j]->op == IROp::Shl)
                            mul = b->kids[j].get();
                        if (b->kids[j]->isConst()) con = b->kids[j].get();
                    }
                    if (mul && con && con->value >= 0) {
                        int scale = 4;
                        if (mul->op == IROp::Mul && mul->kids.size() == 2 &&
                            mul->kids[1] && mul->kids[1]->isConst())
                            scale = (int)mul->kids[1]->value;
                        else if (mul->op == IROp::Shl && mul->kids.size() == 2 &&
                                 mul->kids[1] && mul->kids[1]->isConst())
                            scale = 1 << (int)mul->kids[1]->value;
                        if (scale > 0 && scale <= 256)
                            recordArrayAccess(a->name, (int)con->value, scale);
                    }
                }
            }
        }
    }

    void scanExprForAccess(const IRExpr *e) {
        if (!e) return;

        // Load(Add(Var(g), Const)) → read at offset
        if (e->op == IROp::Load && !e->kids.empty()) {
            auto *addr = e->kids[0].get();
            int loadSize = e->loadSize > 0 ? e->loadSize : 4;
            if (loadSize == 5) loadSize = 4; // float load
            scanAddrForAccess(addr, loadSize, nullptr, false);

            // Also: the Load result might be used as a pointer — check parent context
            // (done by caller scanning Load results)
        }

        // Recurse
        for (auto &k : e->kids) scanExprForAccess(k.get());
    }

    bool isFloatExpr(const IRExpr *e) {
        if (!e) return false;
        if (e->op == IROp::Const) {
            // Check if it's a float constant (has decimal point in name)
            if (e->name.find('.') != std::string::npos) return true;
            // Check type annotation
            if (e->typeRef != NullType) {
                auto *t = m_types->resolveType(e->typeRef);
                if (t && (t->kind == StabsTypeKind::Float ||
                          t->kind == StabsTypeKind::Double))
                    return true;
            }
        }
        return false;
    }

    void detectArrayFields(InferredStruct &layout) {
        // Look for sequences of fields at regular intervals
        std::vector<int> offsets;
        for (auto &[off, f] : layout.fields)
            offsets.push_back(off);

        if (offsets.size() < 3) return;
        std::sort(offsets.begin(), offsets.end());

        // Check for arithmetic sequences
        for (size_t i = 0; i + 2 < offsets.size(); ++i) {
            int d1 = offsets[i+1] - offsets[i];
            int d2 = offsets[i+2] - offsets[i+1];
            if (d1 == d2 && d1 > 0 && d1 <= 256) {
                // Found regular spacing — mark as array
                layout.fields[offsets[i]].isArray = true;
                layout.fields[offsets[i]].arrayScale = d1;
            }
        }
    }

    static std::string toHex(int v) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%X", v);
        return buf;
    }

    // ── Phase 2: IR Transformation ──

    const StructInfo* getStructGlobal(const IRExpr *e) {
        if (!e || e->op != IROp::Var || e->name.empty()) return nullptr;
        auto it = m_structGlobals.find(e->name);
        return (it != m_structGlobals.end()) ? &it->second : nullptr;
    }

    // Check if global has an inferred layout
    const InferredStruct* getInferredStruct(const std::string &name) {
        auto it = m_inferredStructs.find(name);
        if (it != m_inferredStructs.end() && it->second.fields.size() >= 2)
            return &it->second;
        return nullptr;
    }

    // Look up field name for a global at given offset (STABS first, then inferred)
    std::string resolveFieldName(const std::string &globalName, int offset) {
        // Try STABS first
        auto sit = m_structGlobals.find(globalName);
        if (sit != m_structGlobals.end() && sit->second.info) {
            std::string name = m_types->formatFieldAccess(sit->second.typeRef, offset);
            if (!name.empty()) return name;
        }
        // Try inferred
        auto iit = m_inferredStructs.find(globalName);
        if (iit != m_inferredStructs.end()) {
            auto fit = iit->second.fields.find(offset);
            if (fit != iit->second.fields.end())
                return fit->second.name;
        }
        return "";
    }

    int getStructSize(const std::string &globalName) {
        auto sit = m_structGlobals.find(globalName);
        if (sit != m_structGlobals.end() && sit->second.info)
            return sit->second.info->sizeBytes;
        auto iit = m_inferredStructs.find(globalName);
        if (iit != m_inferredStructs.end())
            return iit->second.totalSize;
        return 0;
    }

    bool isKnownGlobal(const IRExpr *e) {
        if (!e || e->op != IROp::Var || e->name.empty()) return false;
        return m_structGlobals.count(e->name) || getInferredStruct(e->name);
    }

    std::unique_ptr<IRExpr> transformExpr(std::unique_ptr<IRExpr> e, bool isAddr) {
        if (!e) return e;

        // Bottom-up: transform children first
        for (auto &k : e->kids) {
            if (k) k = transformExpr(std::move(k), false);
        }

        // Pattern 1: Add(Var(global), Const(offset)) → AddrOf(Field(...))
        if (e->op == IROp::Add && e->kids.size() == 2) {
            for (int i = 0; i < 2; ++i) {
                auto *a = e->kids[i].get();
                auto *b = e->kids[1-i].get();
                if (b && b->isConst() && b->value > 0 && isKnownGlobal(a)) {
                    int off = (int)b->value;
                    int sz = getStructSize(a->name);
                    if (off < sz) {
                        std::string fieldName = resolveFieldName(a->name, off);
                        if (!fieldName.empty()) {
                            auto var = IRExpr::mkVar(a->name);
                            auto field = IRExpr::mkField(std::move(var), fieldName, off);
                            return IRExpr::mkAddrOf(std::move(field));
                        }
                    }
                }
            }

            // Pattern 2: Add(Var(global), Mul/Shl(idx, scale)) → array field at offset 0
            // Also matches And(expr, mask) when used as index (common loop pattern)
            for (int i = 0; i < 2; ++i) {
                auto *a = e->kids[i].get();
                auto *b = e->kids[1-i].get();
                bool isScaledIndex = b && (b->op == IROp::Mul || b->op == IROp::Shl);
                // Also match bare And/Add that isn't a const — could be unscaled index
                // (e.g., int array where compiler doesn't multiply by 4 because
                //  the index is already a byte offset from prior computation)
                if (!isScaledIndex && b && !b->isConst() &&
                    b->op != IROp::Var && b->op != IROp::Load)
                    isScaledIndex = true;
                if (isKnownGlobal(a) && isScaledIndex) {
                    std::string f0name = resolveFieldName(a->name, 0);
                    if (!f0name.empty()) {
                        // Check if field at offset 0 is array-typed (STABS) or inferred array
                        bool isArray = false;
                        auto sit = m_structGlobals.find(a->name);
                        if (sit != m_structGlobals.end() && sit->second.info) {
                            auto *f0 = m_types->findFieldAtOffset(sit->second.typeRef, 0);
                            if (f0) {
                                auto *f0t = m_types->resolveType(f0->typeRef);
                                if (f0t && f0t->kind == StabsTypeKind::Array)
                                    isArray = true;
                            }
                        }
                        auto *inf = getInferredStruct(a->name);
                        if (inf) {
                            auto fit = inf->fields.find(0);
                            if (fit != inf->fields.end() && fit->second.isArray)
                                isArray = true;
                        }
                        if (isArray) {
                            auto var = IRExpr::mkVar(a->name);
                            auto field = IRExpr::mkField(std::move(var), f0name, 0);
                            auto addr = IRExpr::mkAddrOf(std::move(field));
                            auto newAdd = std::make_unique<IRExpr>();
                            newAdd->op = IROp::Add;
                            newAdd->kids.push_back(std::move(addr));
                            newAdd->kids.push_back(e->kids[1-i]->clone());
                            return newAdd;
                        }
                    }
                }
            }

            // Pattern 3: Add(Var(global), Add(Mul(idx, scale), const_off))
            for (int i = 0; i < 2; ++i) {
                auto *a = e->kids[i].get();
                auto *b = e->kids[1-i].get();
                if (isKnownGlobal(a) && b && b->op == IROp::Add && b->kids.size() == 2) {
                    IRExpr *mulPart = nullptr, *constPart = nullptr;
                    for (int j = 0; j < 2; ++j) {
                        if (b->kids[j]->op == IROp::Mul || b->kids[j]->op == IROp::Shl)
                            mulPart = b->kids[j].get();
                        if (b->kids[j]->isConst()) constPart = b->kids[j].get();
                    }
                    if (mulPart && constPart) {
                        int off = (int)constPart->value;
                        int sz = getStructSize(a->name);
                        if (off >= 0 && off < sz) {
                            std::string fieldName = resolveFieldName(a->name, off);
                            if (!fieldName.empty()) {
                                auto var = IRExpr::mkVar(a->name);
                                auto field = IRExpr::mkField(std::move(var), fieldName, off);
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

        // Pattern 4: Load(Var(structGlobal)) → Load(AddrOf(Field(Var, field0)))
        if (e->op == IROp::Load && e->kids.size() == 1 && isKnownGlobal(e->kids[0].get())) {
            std::string f0name = resolveFieldName(e->kids[0]->name, 0);
            if (!f0name.empty()) {
                auto var = IRExpr::mkVar(e->kids[0]->name);
                auto field = IRExpr::mkField(std::move(var), f0name, 0);
                e->kids[0] = IRExpr::mkAddrOf(std::move(field));
            }
        }

        return e;
    }
};
