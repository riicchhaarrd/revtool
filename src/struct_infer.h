#pragma once
#include "ir.h"
#include "stabs_types.h"
#include "lifter.h"
#include <map>
#include <set>
#include <vector>
#include <algorithm>

// Forward declaration
class MachOFile;

// ── Struct Inference Engine ────────────────────────────────────────────
// Analyzes memory access patterns across functions to infer struct layouts
// for opaque data blobs (char[], int, or forward-declared structs).
//
// Works WITHOUT debug info — purely from access patterns:
//   Store(Add(globalAddr, 0x10), floatVal) → field at offset 0x10 is float
//   Load(Add(globalAddr, 0x20))            → field at offset 0x20 exists
//   Store(Add(globalAddr, Add(Mul(idx,4), 0x30)), val) → array at offset 0x30
//
// With STABS: refines char[] fields into sub-structs using access patterns.
// Creates synthetic StabsTypeInfo entries in the type table.

class StructInferer {
public:
    // Run inference over all functions in a source file, then update the type table.
    // Call this ONCE before decompiling individual functions.
    void run(MachOFile &mf, int srcIdx) {
        m_mf = &mf;
        m_types = &mf.mutableTypeTable();
        m_accesses.clear();
        m_created.clear();

        auto &sources = mf.stabsSourceFiles();
        if (srcIdx < 0 || srcIdx >= (int)sources.size()) return;
        auto &sf = sources[srcIdx];

        // Lift each function and scan for access patterns
        Lifter lifter(mf);
        for (size_t fi : sf.functionIndices) {
            auto &fn = mf.stabsFunctions()[fi];
            if (fn.address == 0 || fn.size == 0) continue;
            IRFunc func = lifter.liftFunction(fn.address);
            if (func.blocks.empty()) continue;
            scanFunction(func);
        }

        // Analyze collected accesses and create synthetic struct types
        synthesizeStructs();
    }

    // Get the number of structs created
    int created() const { return (int)m_created.size(); }

private:
    MachOFile *m_mf = nullptr;
    StabsTypeTable *m_types = nullptr;

    // ── Access record ──
    struct FieldAccess {
        int offset;
        int size;             // 1, 2, 4, 8
        bool isFloat = false;
        bool isArray = false;
        int arrayScale = 0;
        int accessCount = 0;
    };

    // globalName → offset → FieldAccess
    std::map<std::string, std::map<int, FieldAccess>> m_accesses;
    std::vector<std::string> m_created;

    void scanFunction(const IRFunc &func) {
        for (auto &bb : func.blocks) {
            for (auto &stmt : bb.stmts) {
                // Store(addr, val): scan addr for global+offset pattern
                if (stmt.kind == IRStmtKind::Store && stmt.addr) {
                    int storeSize = stmt.storeSize;
                    if (storeSize == 5) storeSize = 4; // float
                    bool isFloat = (stmt.storeSize == 5);
                    if (!isFloat && stmt.expr)
                        isFloat = checkFloat(stmt.expr.get());
                    scanAddr(stmt.addr.get(), storeSize, isFloat);
                }
                // Scan all expressions for Load patterns
                scanExpr(stmt.expr.get());
                scanExpr(stmt.addr.get());
                for (auto &a : stmt.args) scanExpr(a.get());
            }
        }
    }

    void scanAddr(const IRExpr *addr, int size, bool isFloat) {
        if (!addr) return;

        // Add(Var(global), Const(offset))
        if (addr->op == IROp::Add && addr->kids.size() == 2) {
            for (int i = 0; i < 2; ++i) {
                auto *a = addr->kids[i].get();
                auto *b = addr->kids[1-i].get();
                if (a && a->op == IROp::Var && !a->name.empty() &&
                    b && b->isConst() && b->value >= 0 && b->value < 65536) {
                    recordAccess(a->name, (int)b->value, size, isFloat);
                }
                // Add(Var(global), Mul(idx, scale)) — array at offset 0
                if (a && a->op == IROp::Var && !a->name.empty() &&
                    b && (b->op == IROp::Mul || b->op == IROp::Shl)) {
                    int scale = getScale(b);
                    if (scale > 0)
                        recordArray(a->name, 0, scale);
                }
                // Add(Var(global), Add(Mul/Shl, Const)) — array at offset
                if (a && a->op == IROp::Var && !a->name.empty() &&
                    b && b->op == IROp::Add && b->kids.size() == 2) {
                    const IRExpr *mul = nullptr, *con = nullptr;
                    for (int j = 0; j < 2; ++j) {
                        if (b->kids[j]->op == IROp::Mul || b->kids[j]->op == IROp::Shl)
                            mul = b->kids[j].get();
                        if (b->kids[j]->isConst())
                            con = b->kids[j].get();
                    }
                    if (mul && con && con->value >= 0 && con->value < 65536) {
                        int scale = getScale(mul);
                        if (scale > 0)
                            recordArray(a->name, (int)con->value, scale);
                    }
                }
            }
        }
    }

    void scanExpr(const IRExpr *e) {
        if (!e) return;
        if (e->op == IROp::Load && !e->kids.empty()) {
            int loadSize = e->loadSize > 0 ? e->loadSize : 4;
            bool isFloat = (loadSize == 5);
            if (loadSize == 5) loadSize = 4;
            scanAddr(e->kids[0].get(), loadSize, isFloat);
        }
        for (auto &k : e->kids) scanExpr(k.get());
    }

    int getScale(const IRExpr *e) {
        if (!e) return 0;
        if (e->op == IROp::Mul && e->kids.size() == 2 &&
            e->kids[1] && e->kids[1]->isConst()) {
            int s = (int)e->kids[1]->value;
            return (s > 0 && s <= 256) ? s : 0;
        }
        if (e->op == IROp::Shl && e->kids.size() == 2 &&
            e->kids[1] && e->kids[1]->isConst()) {
            int shift = (int)e->kids[1]->value;
            return (shift >= 0 && shift <= 8) ? (1 << shift) : 0;
        }
        return 0;
    }

    bool checkFloat(const IRExpr *e) {
        if (!e) return false;
        if (e->typeRef != NullType) {
            auto *t = m_types->resolveType(e->typeRef);
            if (t && (t->kind == StabsTypeKind::Float || t->kind == StabsTypeKind::Double))
                return true;
        }
        // Float constant pattern: name contains "."
        if (e->op == IROp::Const && e->name.find('.') != std::string::npos)
            return true;
        return false;
    }

    void recordAccess(const std::string &name, int offset, int size, bool isFloat) {
        if (name.empty() || offset < 0) return;
        // Skip local vars (vN, tN)
        if ((name[0] == 'v' || name[0] == 't') && name.size() <= 4 && isdigit(name[1]))
            return;
        auto &fa = m_accesses[name][offset];
        fa.offset = offset;
        if (fa.size == 0) fa.size = size;
        if (isFloat) fa.isFloat = true;
        fa.accessCount++;
    }

    void recordArray(const std::string &name, int offset, int scale) {
        if (name.empty() || offset < 0) return;
        if ((name[0] == 'v' || name[0] == 't') && name.size() <= 4 && isdigit(name[1]))
            return;
        auto &fa = m_accesses[name][offset];
        fa.offset = offset;
        fa.isArray = true;
        fa.arrayScale = scale;
        if (fa.size == 0) fa.size = 4;
        fa.accessCount++;
    }

    void synthesizeStructs() {
        for (auto &[globalName, offsets] : m_accesses) {
            if (offsets.size() < 2) continue; // need multiple accesses

            // Check if this global has a STABS type
            auto *g = m_types->globalByName(globalName);
            if (!g) continue;
            TypeRef gType = g->typeRef;
            if (gType == NullType) continue;
            auto *gt = m_types->resolveType(gType);
            if (!gt) continue;

            // Case 1: Global is a struct with char[] fields — refine the char[] fields
            if (gt->kind == StabsTypeKind::Struct && !gt->fields.empty()) {
                refineStructFields(globalName, gType, gt, offsets);
            }
            // Case 2: Global is a basic type (int) or forward-declared struct
            // with no fields — create a full synthetic struct
            else if (gt->kind == StabsTypeKind::Int || gt->kind == StabsTypeKind::UInt ||
                     (gt->kind == StabsTypeKind::Struct && gt->fields.empty()) ||
                     gt->kind == StabsTypeKind::ForwardRef) {
                createSyntheticStruct(globalName, gType, offsets);
            }
        }
    }

    void refineStructFields(const std::string &globalName, TypeRef structRef,
                            const StabsTypeInfo *st,
                            const std::map<int, FieldAccess> &offsets) {
        // Find char[] fields and check if we have sub-field accesses inside them
        auto *mut = m_types->getMutableType(structRef);
        if (!mut) return;

        for (auto &field : mut->fields) {
            if (field.typeRef == NullType) continue;
            auto *ft = m_types->resolveType(field.typeRef);
            if (!ft || ft->kind != StabsTypeKind::Array) continue;
            // Check if this is a char[] or int[] blob
            auto *elemT = m_types->resolveType(ft->targetType);
            if (!elemT) continue;
            bool isCharArray = (elemT->kind == StabsTypeKind::Char ||
                               elemT->kind == StabsTypeKind::UChar);
            if (!isCharArray) continue;

            int fieldStart = field.bitOffset / 8;
            int fieldEnd = fieldStart + ft->sizeBytes;

            // Collect accesses within this char[] field
            std::map<int, FieldAccess> subAccesses;
            for (auto &[off, fa] : offsets) {
                if (off >= fieldStart && off < fieldEnd)
                    subAccesses[off - fieldStart] = fa;
            }
            if (subAccesses.size() < 2) continue;

            // Create a synthetic sub-struct for this char[] field
            std::vector<StabsTypeField> subFields;
            for (auto &[subOff, fa] : subAccesses) {
                StabsTypeField sf;
                sf.bitOffset = subOff * 8;
                sf.bitSize = fa.size * 8;
                // Generate field name from offset
                char nameBuf[64];
                if (fa.isFloat)
                    snprintf(nameBuf, sizeof(nameBuf), "f_0x%X", subOff);
                else if (fa.isArray)
                    snprintf(nameBuf, sizeof(nameBuf), "arr_0x%X", subOff);
                else
                    snprintf(nameBuf, sizeof(nameBuf), "field_0x%X", subOff);
                sf.name = nameBuf;
                // Create type for the field
                if (fa.isFloat) {
                    // Try to find existing float TypeRef
                    sf.typeRef = findBasicType(StabsTypeKind::Float);
                } else {
                    sf.typeRef = findBasicType(StabsTypeKind::Int);
                }
                subFields.push_back(sf);
            }

            // Create the synthetic struct type
            std::string subStructName = field.name + "_t";
            TypeRef subRef = m_types->createSyntheticStruct(subStructName, subFields, ft->sizeBytes);

            // Replace the field's type in the parent struct
            field.typeRef = subRef;
            // Update field bitSize to match
            field.bitSize = ft->sizeBytes * 8;

            m_created.push_back(globalName + "." + field.name + " → struct " + subStructName);
        }
    }

    void createSyntheticStruct(const std::string &globalName, TypeRef origType,
                               const std::map<int, FieldAccess> &offsets) {
        // Build fields from access patterns
        std::vector<StabsTypeField> fields;
        int maxEnd = 0;

        for (auto &[off, fa] : offsets) {
            StabsTypeField sf;
            sf.bitOffset = off * 8;
            sf.bitSize = fa.size * 8;

            char nameBuf[64];
            if (fa.isFloat)
                snprintf(nameBuf, sizeof(nameBuf), "f_0x%X", off);
            else if (fa.isArray)
                snprintf(nameBuf, sizeof(nameBuf), "arr_0x%X", off);
            else
                snprintf(nameBuf, sizeof(nameBuf), "field_0x%X", off);
            sf.name = nameBuf;

            if (fa.isFloat)
                sf.typeRef = findBasicType(StabsTypeKind::Float);
            else
                sf.typeRef = findBasicType(StabsTypeKind::Int);

            fields.push_back(sf);
            int end = off + fa.size;
            if (end > maxEnd) maxEnd = end;
        }

        // Create struct
        std::string structName = globalName + "_inferred_t";
        TypeRef newRef = m_types->createSyntheticStruct(structName, fields, maxEnd);

        // Update the global's type to point to this struct
        // (We can't easily change the global's typeRef, so we update the type in-place)
        auto *ti = m_types->getMutableType(origType);
        if (ti && (ti->kind == StabsTypeKind::Int || ti->kind == StabsTypeKind::UInt)) {
            // Replace the int type with a struct (risky — only for globals with many accesses)
            if (offsets.size() >= 4) {
                ti->kind = StabsTypeKind::Struct;
                ti->name = structName;
                ti->sizeBytes = maxEnd;
                ti->fields = fields;
                m_created.push_back(globalName + " → struct " + structName +
                                    " (" + std::to_string(fields.size()) + " fields)");
            }
        }
        else if (ti && ti->kind == StabsTypeKind::Struct && ti->fields.empty()) {
            // Forward-declared struct with no body — fill in the body
            ti->sizeBytes = maxEnd;
            ti->fields = fields;
            m_created.push_back(globalName + " → filled struct " + ti->name +
                                " (" + std::to_string(fields.size()) + " fields)");
        }
    }

    TypeRef findBasicType(StabsTypeKind kind) {
        // Search for an existing basic type with this kind
        for (auto &[ref, ti] : m_types->allTypes()) {
            if (ti.kind == kind && ti.sizeBytes == 4)
                return ref;
        }
        return NullType;
    }
};
