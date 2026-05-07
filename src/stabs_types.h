#pragma once
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <functional>
#include <set>
#include <utility>

// ── STABS type system parser ─────────────────────────────────────────
// Parses STABS debug type encoding strings into structured type info.
// Handles structs, unions, enums, pointers, typedefs, arrays, qualifiers,
// globals, statics, and include files.

// ── Type reference: (file_num, type_num) within a compilation unit ───
using TypeRef = std::pair<int,int>;
static const TypeRef NullType = {-1, -1};

// ── Type kinds ───────────────────────────────────────────────────────
enum class StabsTypeKind {
    Unknown, Void, Int, UInt, Float, Char, UChar, Bool, Long, ULong,
    LongLong, ULongLong, Short, UShort, Double, LongDouble,
    Pointer, Reference, Const, Volatile,
    Struct, Union, Enum, Array, Function, Typedef,
    ForwardRef
};

struct StabsTypeField {
    std::string name;
    TypeRef     typeRef = NullType;
    int         bitOffset = 0;
    int         bitSize   = 0;
};

struct StabsEnumVal {
    std::string name;
    int64_t     value = 0;
};

struct StabsTypeInfo {
    StabsTypeKind kind = StabsTypeKind::Unknown;
    std::string   name;
    int           sizeBytes = 0;  // from struct size or @s attribute

    // pointer, reference, const, volatile, typedef, array element, function return
    TypeRef targetType = NullType;

    // struct / union
    std::vector<StabsTypeField> fields;

    // enum
    std::vector<StabsEnumVal> enumValues;

    // array
    int arrayLow  = 0;
    int arrayHigh = 0;

    // range (primitive) — self-referential range = base type
    int64_t rangeLow  = 0;
    int64_t rangeHigh = 0;
    bool    isSelfRef = false;

    // forward ref tag name
    std::string forwardTag;
    bool        isUnionFwd = false;
};

struct StabsTypedVar {
    std::string name;
    TypeRef     typeRef = NullType;
    int         stackOffset = 0; // ebp-relative (n_value for N_PSYM/N_LSYM)
    int         regNum = -1;     // STABS register number (-1 = not a register var)
};

struct StabsGlobalVar {
    std::string name;
    uint32_t    address = 0;
    TypeRef     typeRef = NullType;
    bool        isStatic = false;
    int         sourceFileIdx = -1;
};

struct StabsFunction {
    std::string name;
    std::string rawName;     // with type info
    uint32_t    address = 0;
    uint32_t    size = 0;
    bool        isGlobal = false;
    int         sourceFileIdx = -1;
    TypeRef     returnType = NullType;
    std::vector<std::pair<uint32_t, int>> lineMap; // addr -> line number
    std::vector<StabsTypedVar> params;
    std::vector<StabsTypedVar> locals;
    int frameBaseBias = 8; // DWARF fbreg-to-ebp adjustment; STABS keeps the default.
    bool isRegparm = false;  // true if function uses regparm(3) calling convention
};

struct StabsSourceFile {
    std::string directory;
    std::string filename;
    uint32_t    address = 0;
    std::vector<size_t> functionIndices;
};

// ── STABS Type Table ─────────────────────────────────────────────────
// Stores all types for one compilation unit (between N_SO boundaries).
// For a whole binary we keep a per-unit table and merge lookups.

class StabsTypeTable {
public:
    // Set the current compilation unit index. Call this when encountering
    // each new N_SO (source file) boundary. Types are scoped per unit so
    // that (0,5) in unit 0 doesn't collide with (0,5) in unit 1.
    void setCompilationUnit(int unit) { m_unit = unit; }
    int  compilationUnit() const { return m_unit; }

    // ── Parse a raw STABS symbol string ──────────────────────────────
    // Called for each STABS symbol during binary parsing.
    // stabType: the N_xxx type (N_LSYM, N_GSYM, N_PSYM, etc.)
    // raw: the symbol name string (e.g. "int:t(0,2)=r(0,2);-2147483648;2147483647;")
    // value: the n_value field (address or stack offset)
    // Returns: for N_PSYM/N_LSYM variables, fills out typed var info.

    struct ParsedVar {
        std::string name;
        TypeRef     typeRef = NullType;
        bool        isType  = false; // true if this was a type def, not a variable
        char        descriptor = 0;  // 't','T','G','S','V','F','f','p','r', or 0
    };

    ParsedVar parseSymbol(const std::string &raw) {
        ParsedVar result;
        if (raw.empty()) return result;

        // Find the first colon that separates name from descriptor+type
        size_t colon = findDescriptorColon(raw);
        if (colon == std::string::npos) return result;

        result.name = raw.substr(0, colon);
        size_t pos = colon + 1;
        if (pos >= raw.size()) return result;

        // Parse descriptor
        char ch = raw[pos];
        if (ch == 'T') {
            // Could be 'T' (tag) or 'Tt' (combined tag+typedef)
            if (pos + 1 < raw.size() && raw[pos + 1] == 't') {
                result.descriptor = 'T'; // treat Tt as T
                pos += 2;
            } else {
                result.descriptor = 'T';
                pos += 1;
            }
            result.isType = true;
        } else if (ch == 't' || ch == 'G' || ch == 'S' || ch == 'V' ||
                   ch == 'F' || ch == 'f' || ch == 'p' || ch == 'P' || ch == 'r') {
            result.descriptor = ch;
            pos += 1;
            result.isType = (ch == 't');
        } else if (ch == '(' || (ch >= '0' && ch <= '9') || ch == '-') {
            // No descriptor — local variable or anonymous
            result.descriptor = 0;
        } else {
            // Unknown descriptor, skip
            result.descriptor = ch;
            pos += 1;
        }

        // Parse type reference
        result.typeRef = parseTypeRef(raw, pos);
        if (result.typeRef == NullType) return result;

        // If '=' follows, parse type definition
        if (pos < raw.size() && raw[pos] == '=') {
            pos++; // skip '='
            parseTypeDef(raw, pos, result.typeRef);
        }

        // Set name on type if this is a type/tag definition
        if (result.isType || result.descriptor == 'T') {
            auto it = m_types.find(result.typeRef);
            if (it != m_types.end() && it->second.name.empty())
                it->second.name = result.name;
        }

        return result;
    }

    bool isWeakGlobalType(TypeRef ref) const {
        if (ref == NullType)
            return true;
        auto *t = resolveType(ref);
        if (!t)
            return true;
        return t->kind == StabsTypeKind::Int ||
               t->kind == StabsTypeKind::UInt ||
               t->kind == StabsTypeKind::Void;
    }

    bool isConstPointerGlobalType(TypeRef ref) const {
        bool sawConst = false;
        for (int depth = 0; ref != NullType && depth < 12; ++depth) {
            auto *t = getType(ref);
            if (!t)
                return false;
            if (t->kind == StabsTypeKind::Typedef ||
                t->kind == StabsTypeKind::Volatile) {
                ref = t->targetType;
                continue;
            }
            if (t->kind == StabsTypeKind::Const) {
                sawConst = true;
                ref = t->targetType;
                continue;
            }
            return sawConst && t->kind == StabsTypeKind::Pointer;
        }
        return false;
    }

    // Register a global/static variable
    void addGlobal(const std::string &name, uint32_t addr, TypeRef type, bool isStatic, int srcIdx = -1) {
        TypeRef useType = type;
        if (addr && isWeakGlobalType(useType)) {
            for (auto &g : m_globals) {
                if (g.name == name && isConstPointerGlobalType(g.typeRef)) {
                    useType = g.typeRef;
                    break;
                }
            }
        } else if (!addr && isConstPointerGlobalType(useType)) {
            for (auto &g : m_globals) {
                if (g.name == name && g.address && isWeakGlobalType(g.typeRef))
                    g.typeRef = useType;
            }
        }
        m_globals.push_back({name, addr, useType, isStatic, srcIdx >= 0 ? srcIdx : m_unit});
        if (addr) m_globalByAddr[addr].push_back(m_globals.size() - 1);
    }

    void configureCNameDisambiguation(const std::vector<TypeRef> &roots) const {
        if (m_cNamesConfigured) return;
        m_cNamesConfigured = true;
        m_useDisambiguatedCNames = true;
        buildCNameMaps(roots);
    }

    // Register an include file
    void addInclude(const std::string &path) {
        if (!path.empty() && std::find(m_includes.begin(), m_includes.end(), path) == m_includes.end())
            m_includes.push_back(path);
    }

    // ── Lookups ──────────────────────────────────────────────────────

    const StabsTypeInfo* getType(TypeRef ref) const {
        auto it = m_types.find(ref);
        return it != m_types.end() ? &it->second : nullptr;
    }

    // Resolve through typedefs, const, volatile, and forward refs to the underlying type
    const StabsTypeInfo* resolveType(TypeRef ref, int depth = 0) const {
        if (depth > 20 || ref == NullType) return nullptr;
        auto *t = getType(ref);
        if (!t) return nullptr;
        if (t->kind == StabsTypeKind::Typedef || t->kind == StabsTypeKind::Const ||
            t->kind == StabsTypeKind::Volatile) {
            if (t->targetType != NullType && t->targetType != ref)
                return resolveType(t->targetType, depth + 1);
        }
        // Resolve forward references by searching for a struct/union with the same tag
        // Prefer a match from the same CU (same m_unit * 10000 prefix)
        if (t->kind == StabsTypeKind::ForwardRef && !t->forwardTag.empty()) {
            int refCU = ref.first / 10000;
            const StabsTypeInfo *fallback = nullptr;
            for (auto &[tref, ti] : m_types) {
                if (tref == ref) continue;
                if ((ti.kind == StabsTypeKind::Struct || ti.kind == StabsTypeKind::Union) &&
                    ti.name == t->forwardTag && !ti.fields.empty()) {
                    // Sanity check: verify fields are plausible for this struct name.
                    // If the struct name doesn't match ANY field name pattern, the
                    // fields likely came from a different struct (CU type collision).
                    // Skip such definitions to avoid ConDrawInputGlob fields on scrVarPub_t.
                    bool fieldsPlausible = true;
                    if (ti.fields.size() >= 3 && ti.name.size() >= 8) {
                        // Check if first field name has ANY commonality with struct name
                        std::string sn = ti.name;
                        if (sn.size() > 2 && sn.substr(sn.size()-2) == "_t") sn = sn.substr(0, sn.size()-2);
                        if (sn.size() > 2 && sn.substr(sn.size()-2) == "_s") sn = sn.substr(0, sn.size()-2);
                        // Look for another struct with the same name but different fields
                        // (indicates the definition was corrupted by CU collision)
                        int matchCount = 0;
                        for (auto &[tref2, ti2] : m_types) {
                            if (tref2 == tref) continue;
                            if (ti2.name == ti.name && !ti2.fields.empty() &&
                                ti2.fields.size() != ti.fields.size())
                                matchCount++;
                        }
                        if (matchCount > 0) {
                            // Multiple definitions with different field counts — pick
                            // the one with more fields (likely the correct one)
                            for (auto &[tref2, ti2] : m_types) {
                                if (tref2 == tref) continue;
                                if (ti2.name == ti.name && !ti2.fields.empty() &&
                                    ti2.fields.size() > ti.fields.size()) {
                                    fallback = &ti2;
                                    break;
                                }
                            }
                            if (fallback) continue; // skip this one, we have a better one
                        }
                    }
                    if (tref.first / 10000 == refCU)
                        return &ti;  // same CU — best match
                    if (!fallback) fallback = &ti;
                }
            }
            if (fallback) return fallback;
        }
        // CU type unification: when this is a complete Struct/Union with a
        // real (non-anonymous) name, look across all CUs for a sibling with
        // the SAME name AND the SAME size-in-bytes that has MORE fields.
        // CU collisions cause the same struct to be parsed with truncated
        // field lists in some CUs; the size-match check filters out
        // accidental name overlaps from unrelated structs.
        if ((t->kind == StabsTypeKind::Struct || t->kind == StabsTypeKind::Union) &&
            !t->name.empty() && t->name.find("$_") != 0 &&
            t->sizeBytes > 0) {
            // Cache canonical lookups (mutable to keep resolveType const).
            auto cit = m_canonicalCache.find(ref);
            if (cit != m_canonicalCache.end()) return cit->second;
            const StabsTypeInfo *best = t;
            size_t bestFields = t->fields.size();
            for (auto &[tref2, ti2] : m_types) {
                if (tref2 == ref) continue;
                if (ti2.kind != t->kind) continue;
                if (ti2.name != t->name) continue;
                if (ti2.sizeBytes != t->sizeBytes) continue;
                if (ti2.fields.size() > bestFields) {
                    best = &ti2;
                    bestFields = ti2.fields.size();
                }
            }
            m_canonicalCache[ref] = best;
            return best;
        }
        return t;
    }

    // Resolve getting the TypeRef (not just the info)
    TypeRef resolveTypeRef(TypeRef ref, int depth = 0) const {
        if (depth > 20 || ref == NullType) return ref;
        auto *t = getType(ref);
        if (!t) return ref;
        if (t->kind == StabsTypeKind::Typedef || t->kind == StabsTypeKind::Const ||
            t->kind == StabsTypeKind::Volatile) {
            if (t->targetType != NullType && t->targetType != ref)
                return resolveTypeRef(t->targetType, depth + 1);
        }
        return ref;
    }

    // Get the pointed-to type (dereference a pointer type)
    TypeRef derefPointer(TypeRef ref) const {
        auto *t = resolveType(ref);
        if (t && t->kind == StabsTypeKind::Pointer)
            return t->targetType;
        return NullType;
    }

    // Format a C type name string
    std::string formatType(TypeRef ref, int depth = 0) const {
        if (depth > 20 || ref == NullType) return "int";
        auto *t = getType(ref);
        if (!t) return "int";

        switch (t->kind) {
        case StabsTypeKind::Void:       return "void";
        case StabsTypeKind::Bool:       return "bool";
        case StabsTypeKind::Char:       return "char";
        case StabsTypeKind::UChar:      return "unsigned char";
        case StabsTypeKind::Short:      return "short";
        case StabsTypeKind::UShort:     return "unsigned short";
        case StabsTypeKind::Int:        return "int";
        case StabsTypeKind::UInt:       return "unsigned int";
        case StabsTypeKind::Long:       return "long";
        case StabsTypeKind::ULong:      return "unsigned long";
        case StabsTypeKind::LongLong:   return "long long";
        case StabsTypeKind::ULongLong:  return "unsigned long long";
        case StabsTypeKind::Float:      return "float";
        case StabsTypeKind::Double:     return "double";
        case StabsTypeKind::LongDouble: return "long double";

        case StabsTypeKind::Pointer: {
            auto *tgt = resolveType(t->targetType);
            std::string inner = formatType(t->targetType, depth + 1);
            // Check if target is a function pointer
            auto *rawTgt = getType(t->targetType);
            if (rawTgt && rawTgt->kind == StabsTypeKind::Function)
                return inner; // already formatted as function pointer
            // Fix array pointer syntax: "int[N] *" → "int *"
            if (inner.find('[') != std::string::npos)
                inner = inner.substr(0, inner.find('['));
            return inner + " *";
        }
        case StabsTypeKind::Reference: return formatType(t->targetType, depth + 1) + " *"; // C++ ref → C ptr
        case StabsTypeKind::Const: {
            std::string inner = formatType(t->targetType, depth + 1);
            if (inner.find("const ") == 0) return inner; // avoid double const
            return "const " + inner;
        }
        case StabsTypeKind::Volatile: {
            std::string inner = formatType(t->targetType, depth + 1);
            if (inner.find("volatile ") == 0) return inner;
            return "volatile " + inner;
        }

        case StabsTypeKind::Typedef:
            if (!t->name.empty()) return typedefCName(ref);
            return formatType(t->targetType, depth + 1);

        case StabsTypeKind::Struct:
            return t->name.empty() ? "struct" : "struct " + aggregateCName(ref);
        case StabsTypeKind::Union:
            return t->name.empty() ? "union" : "union " + aggregateCName(ref);
        case StabsTypeKind::Enum:
            return t->name.empty() ? "enum" : "enum " + t->name;

        case StabsTypeKind::Array: {
            std::string elem = formatType(t->targetType, depth + 1);
            int count = t->arrayHigh - t->arrayLow + 1;
            return elem + "[" + std::to_string(count) + "]";
        }
        case StabsTypeKind::Function: {
            std::string ret = formatType(t->targetType, depth + 1);
            return ret + " (*)()";
        }
        case StabsTypeKind::ForwardRef:
            if (!t->forwardTag.empty())
                return (t->isUnionFwd ? "union " : "struct ") + t->forwardTag;
            return "void";

        default:
            if (!t->name.empty()) return t->name;
            return "int";
        }
    }

    // Format a type for a variable declaration: "type name"
    std::string formatDecl(TypeRef ref, const std::string &varName) const {
        auto formatArrayDecl = [&](TypeRef start, std::string &out) -> bool {
            TypeRef cur = start;
            std::vector<std::string> qualifiers;
            auto *ct = getType(cur);
            while (ct && (ct->kind == StabsTypeKind::Const ||
                          ct->kind == StabsTypeKind::Volatile)) {
                qualifiers.push_back(ct->kind == StabsTypeKind::Const
                    ? "const " : "volatile ");
                cur = ct->targetType;
                ct = getType(cur);
            }
            if (!ct || ct->kind != StabsTypeKind::Array)
                return false;

            std::string dims;
            while (ct && ct->kind == StabsTypeKind::Array) {
                int count = ct->arrayHigh - ct->arrayLow + 1;
                dims += "[" + std::to_string(count) + "]";
                cur = ct->targetType;
                ct = getType(cur);
            }
            std::string elem = formatType(cur);
            for (const auto &q : qualifiers)
                if (elem.find(q) != 0)
                    elem = q + elem;
            out = elem + " " + varName + dims;
            return true;
        };

        std::string arrayDecl;
        if (formatArrayDecl(ref, arrayDecl))
            return arrayDecl;

        auto *t = getType(ref);
        if (!t) return "int " + varName;

        // Handle arrays specially — collect all dimensions for multi-dimensional arrays
        if (t->kind == StabsTypeKind::Array) {
            std::string dims;
            TypeRef cur = ref;
            auto *ct = t;
            while (ct && ct->kind == StabsTypeKind::Array) {
                int count = ct->arrayHigh - ct->arrayLow + 1;
                dims += "[" + std::to_string(count) + "]";
                cur = ct->targetType;
                ct = getType(cur);
            }
            std::string elem = formatType(cur);
            return elem + " " + varName + dims;
        }
        // Handle function pointers
        if (t->kind == StabsTypeKind::Pointer) {
            auto *tgt = resolveType(t->targetType);
            if (tgt && tgt->kind == StabsTypeKind::Function) {
                std::string ret = formatType(tgt->targetType);
                return ret + " (*" + varName + ")()";
            }
        }
        std::string typeStr = formatType(ref);
        // void* can't be subscripted or used in arithmetic — use char*
        // void*→char* too broad, disabled
        return typeStr + " " + varName;
    }

    std::string aggregateCName(TypeRef ref) const {
        auto *t = getType(ref);
        if (!t || (t->kind != StabsTypeKind::Struct && t->kind != StabsTypeKind::Union))
            return t ? t->name : std::string();
        if (m_useDisambiguatedCNames) {
            auto it = m_aggregateCNames.find(ref);
            if (it != m_aggregateCNames.end())
                return it->second;
        }
        return t->name;
    }

    std::string aggregateCNameForType(TypeRef ref) const {
        TypeRef aggRef = aggregateRefForType(ref);
        if (aggRef == NullType) {
            auto *t = resolveType(ref);
            return t ? t->name : std::string();
        }
        return aggregateCName(aggRef);
    }

    std::string typedefCName(TypeRef ref) const {
        auto *t = getType(ref);
        if (!t || t->kind != StabsTypeKind::Typedef)
            return t ? t->name : std::string();
        if (m_useDisambiguatedCNames) {
            auto it = m_typedefCNames.find(ref);
            if (it != m_typedefCNames.end())
                return it->second;
        }
        return t->name;
    }

    std::vector<TypeRef> renamedTypedefRefs() const {
        std::vector<TypeRef> refs;
        for (auto &kv : m_typedefCNames) {
            auto *t = getType(kv.first);
            if (t && t->kind == StabsTypeKind::Typedef && kv.second != t->name)
                refs.push_back(kv.first);
        }
        return refs;
    }

    TypeRef aggregateRefForType(TypeRef ref, int depth = 0) const {
        if (ref == NullType || depth > 20) return NullType;
        auto *t = getType(ref);
        if (!t) return NullType;
        if (t->kind == StabsTypeKind::Typedef ||
            t->kind == StabsTypeKind::Const ||
            t->kind == StabsTypeKind::Volatile)
            return aggregateRefForType(t->targetType, depth + 1);
        if (t->kind == StabsTypeKind::Struct || t->kind == StabsTypeKind::Union)
            return ref;
        if (t->kind == StabsTypeKind::ForwardRef && !t->forwardTag.empty()) {
            int refCU = ref.first / 10000;
            TypeRef fallback = NullType;
            for (auto &[tref, ti] : m_types) {
                if (tref == ref) continue;
                if ((ti.kind == StabsTypeKind::Struct || ti.kind == StabsTypeKind::Union) &&
                    ti.name == t->forwardTag && !ti.fields.empty()) {
                    if (tref.first / 10000 == refCU)
                        return tref;
                    if (fallback == NullType)
                        fallback = tref;
                }
            }
            return fallback;
        }
        return NullType;
    }

    // Field bit size with fallback to the field type's size in bits.
    // STABS sometimes omits the explicit bit width for typedef'd array fields
    // (e.g., `D3DMATRIX viewProjectionMatrix` — D3DMATRIX is typedef int[16]).
    // Without the fallback, range checks like `bitTarget < f.bitOffset + f.bitSize`
    // collapse to strict-equality and we lose `field[i]` resolution entirely.
    //
    // IMPORTANT: the fallback is gated on the resolved type being Array or an
    // opaque Struct/Union.  Applying it to fully-defined struct fields makes
    // the "falls inside larger field" path drill into every unrelated sub-
    // struct (sharedUiInfo_t.serverStatus — char[] in the header, struct in
    // STABS — would emit serverStatus.sortKey etc.), breaking ui_main_mp/
    // ui_shared_obj by ~150 errors each.
    int fieldBitSize(const StabsTypeField &f) const {
        if (f.bitSize > 0) return f.bitSize;
        auto *ft = resolveType(f.typeRef);
        if (!ft || ft->sizeBytes <= 0) return 0;
        if (ft->kind == StabsTypeKind::Array) return ft->sizeBytes * 8;
        if ((ft->kind == StabsTypeKind::Struct || ft->kind == StabsTypeKind::Union) &&
            ft->fields.empty())
            return ft->sizeBytes * 8;
        return 0;
    }

    // Find struct/union field at a given byte offset
    const StabsTypeField* findFieldAtOffset(TypeRef ref, int byteOffset) const {
        auto *t = resolveType(ref);
        if (!t || (t->kind != StabsTypeKind::Struct && t->kind != StabsTypeKind::Union))
            return nullptr;
        int bitTarget = byteOffset * 8;
        for (auto &f : t->fields) {
            if (f.bitOffset == bitTarget) return &f;
            if (f.bitOffset / 8 == byteOffset) return &f;
        }
        // Try nested: find the field whose range contains the offset
        for (auto &f : t->fields) {
            int sz = fieldBitSize(f);
            if (sz > 0 && bitTarget >= f.bitOffset && bitTarget < f.bitOffset + sz)
                return &f;
        }
        return nullptr;
    }

    // Format a field access with array subscript when the offset falls inside an array field.
    // Returns "fieldName" for exact match, "fieldName[i]" for array, "fieldName.subfield" for nested struct.
    std::string formatFieldAccess(TypeRef ref, int byteOffset, bool debug = false, bool scalarAccess = false) const {
        auto *t = resolveType(ref);
        if (!t || (t->kind != StabsTypeKind::Struct && t->kind != StabsTypeKind::Union))
            return "";
        int bitTarget = byteOffset * 8;
        (void)debug;

        // Check "inside larger field" FIRST — prefer array element access over
        // overlapping field exact matches
        for (auto &f : t->fields) {
            if (f.name.empty() || f.name[0] == '!' || f.name[0] == '/' ||
                f.name.find("::") != std::string::npos ||
                (f.bitSize == 0 && f.bitOffset == 0 && f.name.size() > 1))
                continue;
            int fBitSize = fieldBitSize(f);
            if (bitTarget > f.bitOffset && bitTarget < f.bitOffset + fBitSize) {
                int fieldByteStart = f.bitOffset / 8;
                int offsetInField = byteOffset - fieldByteStart;
                auto *ft = resolveType(f.typeRef);
                // Opaque struct (declared but no body) — treat as int array so
                // accesses into it round-trip as `field[i]` instead of the bare
                // field name.  Covers cases like `D3DMATRIX viewProjectionMatrix`
                // where the typedef chain resolves to a struct with sizeBytes
                // set but no fields parsed.
                if (ft && (ft->kind == StabsTypeKind::Struct ||
                           ft->kind == StabsTypeKind::Union)) {
                    if (ft->fields.empty() && ft->sizeBytes > 0) {
                        int elemSize = 4;
                        int idx = offsetInField / elemSize;
                        int subOff = offsetInField % elemSize;
                        if (subOff == 0)
                            return f.name + "[" + std::to_string(idx) + "]";
                    } else if (!ft->fields.empty()) {
                        // Only drill into sub-struct fields that are scalar (not
                        // nested structs), to avoid accessing opaque char[N] fields
                        // in port headers
                        auto *subField = findFieldAtOffset(f.typeRef, offsetInField);
                        if (subField && subField->typeRef != NullType) {
                            auto *sft = resolveType(subField->typeRef);
                            if (sft && sft->kind != StabsTypeKind::Struct &&
                                sft->kind != StabsTypeKind::Union &&
                                sft->kind != StabsTypeKind::Array) {
                                return f.name + "." + subField->name;
                            }
                        }
                    }
                }
                if (ft && ft->kind == StabsTypeKind::Array) {
                    auto *elemT = resolveType(ft->targetType);
                    int elemSize = elemT ? elemT->sizeBytes : 4;
                    // For array-of-array (2D), compute element size from inner array
                    if (elemSize <= 0 && elemT && elemT->kind == StabsTypeKind::Array) {
                        auto *innerElem = resolveType(elemT->targetType);
                        int innerSize = innerElem ? innerElem->sizeBytes : 4;
                        if (innerSize <= 0) innerSize = 4;
                        int innerCount = elemT->arrayHigh - elemT->arrayLow + 1;
                        if (innerCount > 0) elemSize = innerSize * innerCount;
                    }
                    if (elemSize <= 0) elemSize = 4;
                    int idx = offsetInField / elemSize;
                    int subOff = offsetInField % elemSize;
                    // For 2D arrays (element is also an array), emit [row][col]
                    if (elemT && elemT->kind == StabsTypeKind::Array) {
                        auto *innerElem = resolveType(elemT->targetType);
                        int innerSize = innerElem ? innerElem->sizeBytes : 4;
                        if (innerSize <= 0) innerSize = 4;
                        int col = subOff / innerSize;
                        if (subOff % innerSize == 0)
                            return f.name + "[" + std::to_string(idx) + "][" + std::to_string(col) + "]";
                    }
                    if (subOff == 0)
                        return f.name + "[" + std::to_string(idx) + "]";
                }
            }
        }

        // Exact match
        for (auto &f : t->fields) {
            // Skip C++ artifacts (inheritance markers, methods, operators, etc.)
            if (f.name.empty() || f.name[0] == '!' || f.name[0] == '/' ||
                f.name[0] == '~' || f.name[0] == '#' || f.name[0] == '$' ||
                f.name.find("::") != std::string::npos ||
                f.name.find("(") != std::string::npos ||
                f.name.find("<") != std::string::npos ||
                f.name.find("operator") == 0 ||
                (f.bitSize == 0 && f.bitOffset == 0 && f.name.size() > 1))
                continue;
            if (f.bitOffset == bitTarget || f.bitOffset / 8 == byteOffset) {
                // Check if this field is actually inside a larger array field
                // (STABS may have overlapping fields for array elements)
                for (auto &af : t->fields) {
                    if (af.name.empty()) continue;
                    int afBitSize = fieldBitSize(af);
                    if (afBitSize == 0) continue;
                    auto *aft = resolveType(af.typeRef);
                    if (aft && aft->kind == StabsTypeKind::Array &&
                        bitTarget >= af.bitOffset && bitTarget < af.bitOffset + afBitSize &&
                        af.bitOffset != bitTarget) {
                        // This offset is inside a larger array field — prefer array access
                        auto *elemT = resolveType(aft->targetType);
                        int elemSize = elemT ? elemT->sizeBytes : 4;
                        // For 2D arrays, compute outer element size from inner array
                        if (elemSize <= 0 && elemT && elemT->kind == StabsTypeKind::Array) {
                            auto *innerE = resolveType(elemT->targetType);
                            int iSz = innerE ? innerE->sizeBytes : 4;
                            if (iSz <= 0) iSz = 4;
                            int iCnt = elemT->arrayHigh - elemT->arrayLow + 1;
                            if (iCnt > 0) elemSize = iSz * iCnt;
                        }
                        if (elemSize <= 0) elemSize = 4;
                        int elemOff = (byteOffset - af.bitOffset/8);
                        int idx = elemOff / elemSize;
                        int subOff = elemOff % elemSize;
                        // 2D array: emit [row][col]
                        if (elemT && elemT->kind == StabsTypeKind::Array) {
                            auto *innerE = resolveType(elemT->targetType);
                            int iSz = innerE ? innerE->sizeBytes : 4;
                            if (iSz <= 0) iSz = 4;
                            int col = subOff / iSz;
                            if (subOff % iSz == 0)
                                return af.name + "[" + std::to_string(idx) + "][" + std::to_string(col) + "]";
                        }
                        if (subOff == 0)
                            return af.name + "[" + std::to_string(idx) + "]";
                    }
                }
                // If this field is a 2D array (array of arrays), return [0][0]
                {
                    auto *fta = resolveType(f.typeRef);
                    if (fta && fta->kind == StabsTypeKind::Array) {
                        auto *elemT = resolveType(fta->targetType);
                        if (elemT && elemT->kind == StabsTypeKind::Array)
                            return f.name + "[0][0]";
                    }
                }
                // If this field is a struct/union, drill down to a sub-field.
                // For unions, try to pick the member that best matches the access.
                auto *ft = resolveType(f.typeRef);
                if (ft && (ft->kind == StabsTypeKind::Struct || ft->kind == StabsTypeKind::Union) &&
                    !ft->fields.empty()) {
                    if (ft->kind == StabsTypeKind::Union) {
                        // For unions, prefer the first scalar that matches common sizes:
                        // 4 bytes → int (over Bool), float matches too
                        const StabsTypeField *best = nullptr;
                        for (auto &uf : ft->fields) {
                            if (uf.name.empty() || uf.bitOffset != 0) continue;
                            auto *ut = resolveType(uf.typeRef);
                            if (!ut) continue;
                            if (ut->kind == StabsTypeKind::Struct || ut->kind == StabsTypeKind::Union ||
                                ut->kind == StabsTypeKind::Array) continue;
                            if (!best) { best = &uf; continue; }
                            auto *bestT = resolveType(best->typeRef);
                            // Prefer larger scalars (int over Bool) for general access
                            if (bestT && ut->sizeBytes > bestT->sizeBytes) best = &uf;
                        }
                        if (best && !best->name.empty())
                            return f.name + "." + best->name;
                    } else {
                        auto *firstField = &ft->fields[0];
                        auto *firstType = resolveType(firstField->typeRef);
                        // Only drill if first field is a simple scalar (not another struct)
                        if (firstType && firstType->kind != StabsTypeKind::Struct &&
                            firstType->kind != StabsTypeKind::Union &&
                            firstType->kind != StabsTypeKind::Array &&
                            firstField->bitOffset == 0 && !firstField->name.empty()) {
                            return f.name + "." + firstField->name;
                        }
                    }
                }
                // If field is an array, accessing at its base offset = first element
                if (ft && ft->kind == StabsTypeKind::Array) {
                    if (scalarAccess) {
                        auto *elemT2 = resolveType(ft->targetType);
                        if (elemT2 && (elemT2->kind == StabsTypeKind::Struct ||
                                       elemT2->kind == StabsTypeKind::Union) &&
                            elemT2->sizeBytes > 4) {
                            std::string sub = formatFieldAccess(ft->targetType, 0, false, true);
                            if (!sub.empty())
                                return f.name + "[0]." + sub;
                        }
                    }
                    return f.name + "[0]";
                }
                // Opaque struct with known size — treat as int array [0]
                if (ft && (ft->kind == StabsTypeKind::Struct ||
                           ft->kind == StabsTypeKind::Union) &&
                    ft->fields.empty() && ft->sizeBytes >= 4)
                    return f.name + "[0]";
                if (f.name == "_")
                    return "";
                return f.name;
            }
        }
        // Check if offset falls inside a larger field (array or sub-struct)
        for (auto &f : t->fields) {
            // Skip C++ artifacts
            if (f.name.empty() || f.name[0] == '!' || f.name[0] == '/' ||
                f.name.find("::") != std::string::npos ||
                (f.bitSize == 0 && f.bitOffset == 0))
                continue;
            int fBitSize2 = fieldBitSize(f);
            if (fBitSize2 > 0 && bitTarget >= f.bitOffset && bitTarget < f.bitOffset + fBitSize2) {
                int fieldByteStart = f.bitOffset / 8;
                int offsetInField = byteOffset - fieldByteStart;
                // Check if field type is an array.
                // NOTE: keep getType (not resolveType) here.  Using resolveType
                // here follows typedefs onto large struct buffers (serverStatus
                // char[] that STABS types as struct serverStatus_s) and drills
                // into the struct body, producing wrong `.sub` accesses on
                // what the header carries as char[].  The viewProjectionMatrix
                // array case is handled earlier by the opaque-struct-as-int-
                // array block in the "inside larger field FIRST" loop.
                auto *ft = getType(f.typeRef);
                if (ft && ft->kind == StabsTypeKind::Array) {
                    auto *elemT = resolveType(ft->targetType);
                    int elemSize = elemT ? elemT->sizeBytes : 4;
                    if (elemSize <= 0) elemSize = 4;
                    int idx = offsetInField / elemSize;
                    int subOff = offsetInField % elemSize;
                    if (subOff == 0)
                        return f.name + "[" + std::to_string(idx) + "]";
                    // Access into array element's sub-field
                    std::string sub = formatFieldAccess(ft->targetType, subOff);
                    if (!sub.empty())
                        return f.name + "[" + std::to_string(idx) + "]." + sub;
                    return f.name + "[" + std::to_string(idx) + "]";
                }
                // Sub-struct access
                if (ft && (ft->kind == StabsTypeKind::Struct || ft->kind == StabsTypeKind::Union)) {
                    std::string sub = formatFieldAccess(f.typeRef, offsetInField);
                    if (!sub.empty()) return f.name + "." + sub;
                }
                return f.name;
            }
        }
        return "";
    }

    // Find enum value name
    std::string findEnumName(TypeRef ref, int64_t value) const {
        auto *t = resolveType(ref);
        if (!t || t->kind != StabsTypeKind::Enum) return "";
        for (auto &ev : t->enumValues)
            if (ev.value == value) return ev.name;
        return "";
    }

    // Check if a type is an enum (resolving through typedefs)
    bool isEnum(TypeRef ref) const {
        auto *t = resolveType(ref);
        return t && t->kind == StabsTypeKind::Enum;
    }

    // Check if a TypeRef resolves to a valid type (not NullType and getType returns non-null)
    bool isValidType(TypeRef ref) const {
        if (ref == NullType) return false;
        return getType(ref) != nullptr;
    }

    // Find a pointer-to-struct TypeRef given a struct TypeRef
    TypeRef findPointerTo(TypeRef structRef) const {
        auto resolved = resolveTypeRef(structRef);
        for (auto &[tref, ti] : m_types) {
            if (ti.kind != StabsTypeKind::Pointer) continue;
            if (ti.targetType == structRef || ti.targetType == resolved ||
                resolveTypeRef(ti.targetType) == resolved)
                return tref;
        }
        return NullType;
    }

    // Check if a type is a pointer to a struct
    bool isStructPointer(TypeRef ref) const {
        auto *t = resolveType(ref);
        if (!t || t->kind != StabsTypeKind::Pointer) return false;
        auto *inner = resolveType(t->targetType);
        return inner && (inner->kind == StabsTypeKind::Struct || inner->kind == StabsTypeKind::Union);
    }

    // Get the struct type pointed to by a pointer type
    TypeRef getPointedStruct(TypeRef ref) const {
        auto *t = resolveType(ref);
        if (!t || t->kind != StabsTypeKind::Pointer) return NullType;
        auto resolved = resolveTypeRef(t->targetType);
        auto *inner = getType(resolved);
        if (inner && (inner->kind == StabsTypeKind::Struct || inner->kind == StabsTypeKind::Union))
            return resolved;
        return NullType;
    }

    // ── Synthetic type creation (for struct inference) ──────────────
    // Allocate a new TypeRef for a synthetic type
    TypeRef allocSyntheticType() {
        int id = --m_syntheticCounter;
        return TypeRef{-99, id}; // unit -99 to avoid collision with real types
    }

    TypeRef createSyntheticType(StabsTypeKind kind = StabsTypeKind::Unknown,
                                const std::string &name = "",
                                int sizeBytes = 0) {
        TypeRef ref = allocSyntheticType();
        auto &ti = m_types[ref];
        ti.kind = kind;
        ti.name = name;
        ti.sizeBytes = sizeBytes;
        return ref;
    }

    // Create a synthetic struct type and return its TypeRef
    TypeRef createSyntheticStruct(const std::string &name,
                                  const std::vector<StabsTypeField> &fields,
                                  int sizeBytes) {
        TypeRef ref = allocSyntheticType();
        auto &ti = m_types[ref];
        ti.kind = StabsTypeKind::Struct;
        ti.name = name;
        ti.sizeBytes = sizeBytes;
        ti.fields = fields;
        return ref;
    }

    // Replace a char[] field in an existing struct with a sub-struct type
    bool replaceFieldType(TypeRef structRef, int fieldByteOffset, TypeRef newFieldType) {
        auto it = m_types.find(structRef);
        if (it == m_types.end()) return false;
        int bitTarget = fieldByteOffset * 8;
        for (auto &f : it->second.fields) {
            if (f.bitOffset == bitTarget || f.bitOffset / 8 == fieldByteOffset) {
                f.typeRef = newFieldType;
                // Update the field name to use the new type's name
                auto *nt = getType(newFieldType);
                if (nt && !nt->name.empty())
                    f.name = f.name; // keep original name
                return true;
            }
        }
        return false;
    }

    // Get mutable access to a type (for field modification)
    StabsTypeInfo* getMutableType(TypeRef ref) {
        auto it = m_types.find(ref);
        return it != m_types.end() ? &it->second : nullptr;
    }

    // Global/static variable lookups
    const std::vector<StabsGlobalVar>& globals() const { return m_globals; }

    const StabsGlobalVar* globalAtAddress(uint32_t addr, int cuIdx = -1) const {
        auto it = m_globalByAddr.find(addr);
        if (it == m_globalByAddr.end()) return nullptr;
        auto &indices = it->second;
        if (indices.empty()) return nullptr;
        // If a CU is specified, prefer the entry from that CU
        if (cuIdx >= 0) {
            // First pass: exact CU match with struct/pointer type (prefer over basic int)
            for (size_t idx : indices) {
                if (m_globals[idx].sourceFileIdx != cuIdx || m_globals[idx].typeRef == NullType)
                    continue;
                auto *t = resolveType(m_globals[idx].typeRef);
                if (t && t->kind != StabsTypeKind::Int && t->kind != StabsTypeKind::UInt)
                    return &m_globals[idx];
            }
            // Second pass: any entry with a struct/union type that has fields
            for (size_t idx : indices) {
                if (m_globals[idx].typeRef == NullType) continue;
                auto *t = resolveType(m_globals[idx].typeRef);
                if (t && (t->kind == StabsTypeKind::Struct || t->kind == StabsTypeKind::Union)
                       && !t->fields.empty())
                    return &m_globals[idx];
            }
            // Third pass: exact CU match with any type
            for (size_t idx : indices)
                if (m_globals[idx].sourceFileIdx == cuIdx && m_globals[idx].typeRef != NullType)
                    return &m_globals[idx];
        }
        // Fallback: prefer entry with non-null type, then any entry
        for (size_t idx : indices)
            if (m_globals[idx].typeRef != NullType) return &m_globals[idx];
        return &m_globals[indices.back()];
    }

    const StabsGlobalVar* globalByName(const std::string &name, int cuIdx = -1) const {
        const StabsGlobalVar *best = nullptr;
        bool hasConstPointerCandidate = false;
        for (auto &g : m_globals) {
            if (g.name == name && isConstPointerGlobalType(g.typeRef)) {
                hasConstPointerCandidate = true;
                break;
            }
        }
        for (auto &g : m_globals) {
            if (g.name != name) continue;
            if (!hasConstPointerCandidate) {
                if (cuIdx >= 0 && g.sourceFileIdx == cuIdx && g.typeRef != NullType)
                    return &g;
                if (!best || (best->typeRef == NullType && g.typeRef != NullType))
                    best = &g;
                continue;
            }
            auto score = [&](const StabsGlobalVar &gv) {
                int s = 0;
                if (cuIdx >= 0 && gv.sourceFileIdx == cuIdx) s += 100;
                if (!isWeakGlobalType(gv.typeRef)) s += 40;
                else if (gv.typeRef != NullType) s += 10;
                if (gv.address) s += 20;
                return s;
            };
            if (!best || score(g) > score(*best))
                best = &g;
        }
        return best;
    }

    const StabsGlobalVar* globalByAddress(uint32_t address) const {
        for (auto &g : m_globals)
            if (g.address == address && g.typeRef != NullType) return &g;
        return nullptr;
    }

    const StabsGlobalVar* globalContainingAddress(uint32_t address,
                                                  int &byteOffset,
                                                  int cuIdx = -1) const {
        const StabsGlobalVar *best = nullptr;
        int bestScore = -1;
        byteOffset = 0;
        for (auto &g : m_globals) {
            if (!g.address || g.typeRef == NullType || address < g.address)
                continue;
            auto *t = resolveType(g.typeRef);
            if (!t || t->sizeBytes <= 0)
                continue;
            uint32_t end = g.address + (uint32_t)t->sizeBytes;
            if (end < g.address || address >= end)
                continue;
            int off = (int)(address - g.address);
            int score = 100000 - off;
            if (cuIdx >= 0 && g.sourceFileIdx == cuIdx)
                score += 1000000;
            if (t->kind == StabsTypeKind::Array ||
                t->kind == StabsTypeKind::Struct ||
                t->kind == StabsTypeKind::Union)
                score += 10000;
            if (!best || score > bestScore) {
                best = &g;
                bestScore = score;
                byteOffset = off;
            }
        }
        return best;
    }

    // Include files
    const std::vector<std::string>& includes() const { return m_includes; }

    // All types (for generating forward declarations)
    const std::map<TypeRef, StabsTypeInfo>& allTypes() const { return m_types; }

    // Generate struct definition as C code
    std::string formatStructDef(
        TypeRef ref,
        const std::function<std::string(const std::string &, const std::string &)> &fieldDeclOverride = {}) const {
        auto *t = getType(ref);
        if (!t || (t->kind != StabsTypeKind::Struct && t->kind != StabsTypeKind::Union))
            return "";
        std::string kw = (t->kind == StabsTypeKind::Union) ? "union" : "struct";
        std::string out = kw;
        if (!t->name.empty()) out += " " + aggregateCName(ref);
        out += " {\n";
        auto skipField = [](const StabsTypeField &f) -> bool {
            if (f.name.empty() || f.name[0] == '/') return true;
            if (f.name.find("::") != std::string::npos) return true;
            if (f.name.find("(") != std::string::npos) return true;
            if (f.name[0] == '!' || f.name[0] == '#' || f.name[0] == '$') return true;
            if (f.name[0] == '~') return true;
            if (f.name.find("_vptr$") != std::string::npos) return true;
            if (f.name.find("operator") == 0) return true;
            if (f.name.find("<") != std::string::npos) return true;
            if (f.name.find("&") != std::string::npos) return true;
            if (f.name.find(">") != std::string::npos) return true;
            if (f.name.find("=") != std::string::npos) return true;
            return f.bitSize == 0 && f.bitOffset == 0;
        };
        auto inlineAnonymousType = [&](TypeRef typeRef) -> const StabsTypeInfo * {
            auto *ft = resolveType(typeRef);
            bool isAnon = false;
            if (ft && (ft->kind == StabsTypeKind::Struct || ft->kind == StabsTypeKind::Union))
                isAnon = ft->name.find("$_") == 0;
            if (!isAnon) {
                auto *rawT = getType(typeRef);
                if (rawT && rawT->kind == StabsTypeKind::ForwardRef &&
                    rawT->forwardTag.find("$_") == 0)
                    isAnon = true;
                if (rawT && (rawT->kind == StabsTypeKind::Struct ||
                             rawT->kind == StabsTypeKind::Union) &&
                    rawT->name.find("$_") == 0)
                    isAnon = true;
            }
            if (isAnon && ft && !ft->fields.empty() && ft->sizeBytes > 0)
                return ft;
            return nullptr;
        };
        std::function<void(const StabsTypeField &, const std::string &)> emitField =
            [&](const StabsTypeField &f, const std::string &indent) {
                if (skipField(f))
                    return;
                if (fieldDeclOverride) {
                    std::string overrideDecl = fieldDeclOverride(t->name, f.name);
                    if (!overrideDecl.empty()) {
                        out += indent + overrideDecl + ";\n";
                        return;
                    }
                }
                if (auto *anon = inlineAnonymousType(f.typeRef)) {
                    std::string kw2 = (anon->kind == StabsTypeKind::Union) ? "union" : "struct";
                    out += indent + kw2 + " {\n";
                    for (auto &sf : anon->fields)
                        emitField(sf, indent + "    ");
                    out += indent + "} " + f.name + ";\n";
                    return;
                }
                auto *rawT = getType(f.typeRef);
                if (rawT && rawT->kind == StabsTypeKind::ForwardRef &&
                    rawT->forwardTag.find("$_") == 0) {
                    int sz = 4;
                    int fBitSz = fieldBitSize(f);
                    if (fBitSz > 0)
                        sz = fBitSz / 8;
                    out += indent + "char " + f.name + "[" + std::to_string(sz) + "];\n";
                    return;
                }
                if (t->name == "fileHandleData_t" && f.name == "handleFiles") {
                    out += indent + "FILE * handleFiles;\n";
                    return;
                }
                auto *fieldType = resolveType(f.typeRef);
                int storageBits = fieldType && fieldType->sizeBytes > 0
                    ? fieldType->sizeBytes * 8 : 0;
                bool isBitField = f.bitSize > 0 &&
                    (storageBits == 0 || f.bitSize < storageBits ||
                     (f.bitOffset % 8) != 0);
                if (isBitField) {
                    std::string fdecl = formatDecl(f.typeRef, f.name + " : " +
                                                   std::to_string(f.bitSize));
                    out += indent + fdecl + ";\n";
                    return;
                }
                std::string fdecl = formatDecl(f.typeRef, f.name);
                if (fdecl.find("(*)()") != std::string::npos)
                    return;
                out += indent + fdecl + ";\n";
            };
        for (auto &f : t->fields)
            emitField(f, "    ");
        out += "}";
        return out;
    }

    // Generate enum definition as C code
    std::string formatEnumDef(TypeRef ref) const {
        auto *t = getType(ref);
        if (!t || t->kind != StabsTypeKind::Enum) return "";
        std::string out = "enum";
        if (!t->name.empty()) out += " " + t->name;
        out += " {\n";
        for (size_t i = 0; i < t->enumValues.size(); ++i) {
            out += "    " + t->enumValues[i].name + " = " + std::to_string(t->enumValues[i].value);
            if (i + 1 < t->enumValues.size()) out += ",";
            out += "\n";
        }
        out += "}";
        return out;
    }

private:
    static int realFieldCount(const StabsTypeInfo &t) {
        int realFields = 0;
        for (auto &f : t.fields) {
            if (f.name.empty() || f.name[0] == '/' || f.name[0] == '!' ||
                f.name[0] == '#' || f.name[0] == '$' || f.name[0] == '~')
                continue;
            if (f.name == "dummy")
                continue;
            realFields++;
        }
        return realFields;
    }

    static bool weakAggregateDefinition(const StabsTypeInfo &t) {
        if (t.kind != StabsTypeKind::Struct && t.kind != StabsTypeKind::Union)
            return false;
        return t.fields.empty() || realFieldCount(t) == 0;
    }

    static int aggregateDefinitionScore(const StabsTypeInfo &t) {
        return realFieldCount(t) * 100000 + (int)t.fields.size() * 1000 + t.sizeBytes;
    }

    static std::string aggregateKey(const StabsTypeInfo &t) {
        if (t.kind == StabsTypeKind::Struct)
            return "struct " + t.name;
        if (t.kind == StabsTypeKind::Union)
            return "union " + t.name;
        return "";
    }

    static std::string disambiguatedName(const std::string &base, TypeRef ref) {
        std::string out = base + "__stabs_";
        out += std::to_string(ref.first);
        out += "_";
        out += std::to_string(ref.second);
        return out;
    }

    void visitCNameRoot(TypeRef ref, std::map<TypeRef, int> &score,
                        std::set<TypeRef> &seen, int depth) const {
        if (ref == NullType || depth > 32) return;
        if (!seen.insert(ref).second) return;
        score[ref]++;
        auto *t = getType(ref);
        if (!t) return;
        if (t->targetType != NullType)
            visitCNameRoot(t->targetType, score, seen, depth + 1);
        for (auto &f : t->fields)
            visitCNameRoot(f.typeRef, score, seen, depth + 1);
    }

    std::string typedefTargetSignature(TypeRef ref, int depth = 0) const {
        if (ref == NullType || depth > 20) return "null";
        auto *t = getType(ref);
        if (!t) return "missing";
        switch (t->kind) {
        case StabsTypeKind::Pointer:
            return "ptr:" + typedefTargetSignature(t->targetType, depth + 1);
        case StabsTypeKind::Reference:
            return "ref:" + typedefTargetSignature(t->targetType, depth + 1);
        case StabsTypeKind::Const:
            return "const:" + typedefTargetSignature(t->targetType, depth + 1);
        case StabsTypeKind::Volatile:
            return "volatile:" + typedefTargetSignature(t->targetType, depth + 1);
        case StabsTypeKind::Array:
            return "array:" + std::to_string(t->arrayLow) + ":" +
                   std::to_string(t->arrayHigh) + ":" +
                   typedefTargetSignature(t->targetType, depth + 1);
        case StabsTypeKind::Struct:
        case StabsTypeKind::Union:
            return aggregateKey(*t) + ":" + aggregateCName(ref);
        case StabsTypeKind::Typedef:
            return "typedef:" + typedefTargetSignature(t->targetType, depth + 1);
        default:
            return "kind:" + std::to_string((int)t->kind) + ":" +
                   t->name + ":" + std::to_string(t->sizeBytes);
        }
    }

    static bool typedefTargetCanUseForwardAlias(const StabsTypeInfo &t) {
        return t.kind == StabsTypeKind::Struct || t.kind == StabsTypeKind::Union;
    }

    void buildCNameMaps(const std::vector<TypeRef> &roots) const {
        std::map<TypeRef, int> useScore;
        for (auto ref : roots) {
            std::set<TypeRef> seen;
            visitCNameRoot(ref, useScore, seen, 0);
        }

        std::map<std::string, std::vector<TypeRef>> aggregateGroups;
        for (auto &[ref, ti] : m_types) {
            if (ti.kind != StabsTypeKind::Struct && ti.kind != StabsTypeKind::Union)
                continue;
            if (ti.name.empty() || ti.name.find('<') != std::string::npos)
                continue;
            aggregateGroups[aggregateKey(ti)].push_back(ref);
        }

        for (auto &[key, refs] : aggregateGroups) {
            if (refs.empty()) continue;
            auto *first = getType(refs.front());
            if (!first) continue;

            struct Variant {
                int size = 0;
                int use = 0;
                int count = 0;
                int defScore = 0;
                TypeRef representative = NullType;
                std::vector<TypeRef> refs;
            };

            std::map<int, Variant> variants;
            std::vector<TypeRef> weakRefs;
            for (auto ref : refs) {
                auto *t = getType(ref);
                if (!t) continue;
                if (weakAggregateDefinition(*t)) {
                    weakRefs.push_back(ref);
                    continue;
                }
                auto &v = variants[t->sizeBytes];
                v.size = t->sizeBytes;
                v.use += useScore[ref];
                v.count++;
                v.refs.push_back(ref);
                int defScore = aggregateDefinitionScore(*t);
                if (v.representative == NullType || useScore[ref] > useScore[v.representative] ||
                    (useScore[ref] == useScore[v.representative] && defScore > v.defScore)) {
                    v.representative = ref;
                    v.defScore = defScore;
                }
            }

            if (variants.empty()) {
                for (auto ref : refs)
                    m_aggregateCNames[ref] = first->name;
                continue;
            }

            TypeRef originalRep = NullType;
            int bestUse = -1;
            int bestCount = -1;
            int bestDefScore = -1;
            int bestSize = -1;
            for (auto &[size, v] : variants) {
                if (originalRep == NullType ||
                    v.use > bestUse ||
                    (v.use == bestUse && v.count > bestCount) ||
                    (v.use == bestUse && v.count == bestCount && v.defScore > bestDefScore) ||
                    (v.use == bestUse && v.count == bestCount && v.defScore == bestDefScore &&
                     v.size > bestSize)) {
                    originalRep = v.representative;
                    bestUse = v.use;
                    bestCount = v.count;
                    bestDefScore = v.defScore;
                    bestSize = v.size;
                }
            }

            int originalSize = getType(originalRep) ? getType(originalRep)->sizeBytes : 0;
            for (auto &[size, v] : variants) {
                std::string cname = (size == originalSize) ?
                    first->name : disambiguatedName(first->name, v.representative);
                for (auto ref : v.refs)
                    m_aggregateCNames[ref] = cname;
            }
            std::string originalName = first->name;
            for (auto ref : weakRefs)
                m_aggregateCNames[ref] = originalName;
        }

        std::map<std::string, std::vector<TypeRef>> typedefGroups;
        for (auto &[ref, ti] : m_types) {
            if (ti.kind == StabsTypeKind::Typedef && !ti.name.empty() &&
                ti.name.find('<') == std::string::npos)
                typedefGroups[ti.name].push_back(ref);
        }

        for (auto &[name, refs] : typedefGroups) {
            struct Variant {
                std::string signature;
                int use = 0;
                int count = 0;
                TypeRef representative = NullType;
                std::vector<TypeRef> refs;
            };
            std::map<std::string, Variant> variants;
            for (auto ref : refs) {
                auto *t = getType(ref);
                if (!t || t->targetType == NullType) continue;
                TypeRef targetAgg = aggregateRefForType(t->targetType);
                if (targetAgg == NullType) continue;
                auto *agg = getType(targetAgg);
                if (!agg || !typedefTargetCanUseForwardAlias(*agg)) continue;
                std::string sig = typedefTargetSignature(t->targetType);
                auto &v = variants[sig];
                v.signature = sig;
                v.use += useScore[ref] + useScore[targetAgg];
                v.count++;
                v.refs.push_back(ref);
                if (v.representative == NullType ||
                    useScore[ref] > useScore[v.representative])
                    v.representative = ref;
            }
            if (variants.size() <= 1)
                continue;

            std::string originalSignature;
            int bestUse = -1;
            int bestCount = -1;
            for (auto &[sig, v] : variants) {
                if (originalSignature.empty() ||
                    v.use > bestUse ||
                    (v.use == bestUse && v.count > bestCount)) {
                    originalSignature = sig;
                    bestUse = v.use;
                    bestCount = v.count;
                }
            }
            for (auto &[sig, v] : variants) {
                std::string cname = (sig == originalSignature) ?
                    name : disambiguatedName(name, v.representative);
                for (auto ref : v.refs)
                    m_typedefCNames[ref] = cname;
            }
        }
    }

    std::map<TypeRef, StabsTypeInfo>         m_types;
    std::vector<StabsGlobalVar>              m_globals;
    // Mutable cache for resolveType's CU-unification: maps a TypeRef to
    // the fattest sibling-by-name (or itself if no fatter found).
    mutable std::map<TypeRef, const StabsTypeInfo*> m_canonicalCache;
    std::unordered_map<uint32_t, std::vector<size_t>> m_globalByAddr;
    std::vector<std::string>                 m_includes;
    int                                      m_unit = 0;
    int                                      m_syntheticCounter = -1000000; // negative TypeRefs for synthetic types
    mutable bool                             m_useDisambiguatedCNames = false;
    mutable bool                             m_cNamesConfigured = false;
    mutable std::map<TypeRef, std::string>   m_aggregateCNames;
    mutable std::map<TypeRef, std::string>   m_typedefCNames;

    // Check if a type ref should be protected from overwrite.
    // ForwardRefs with real tag names (like clientStatic_t) carry valuable
    // name info that shouldn't be lost when the type number is reused.
    bool shouldProtectType(TypeRef ref) const {
        auto it = m_types.find(ref);
        if (it == m_types.end()) return false;
        auto &existing = it->second;
        if (existing.kind == StabsTypeKind::ForwardRef &&
            !existing.forwardTag.empty() &&
            existing.forwardTag.find("$_") != 0)
            return true;
        return false;
    }

    // ── Find the descriptor colon ────────────────────────────────────
    // STABS uses 'name:descriptor...' but names can contain '::' for C++.
    // We want the FIRST colon that is followed by a descriptor char or type ref.
    static size_t findDescriptorColon(const std::string &s) {
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == ':') {
                // Skip '::' (C++ scope)
                if (i + 1 < s.size() && s[i + 1] == ':') { i++; continue; }
                return i;
            }
        }
        return std::string::npos;
    }

    // ── Parse (file,type) reference ──────────────────────────────────
    TypeRef parseTypeRef(const std::string &s, size_t &pos) const {
        if (pos >= s.size()) return NullType;
        if (s[pos] == '(') {
            pos++; // skip '('
            int fileNum = parseIntVal(s, pos);
            if (pos < s.size() && s[pos] == ',') pos++;
            int typeNum = parseIntVal(s, pos);
            if (pos < s.size() && s[pos] == ')') pos++;
            // Scope by compilation unit to prevent cross-CU type collisions
            return {m_unit * 10000 + fileNum, typeNum};
        }
        // Bare type number (no parens, file=0)
        if (s[pos] == '-' || (s[pos] >= '0' && s[pos] <= '9')) {
            int typeNum = parseIntVal(s, pos);
            return {m_unit * 10000, typeNum};
        }
        return NullType;
    }

    // ── Parse an integer (possibly negative, possibly octal) ─────────
    static int64_t parseIntVal(const std::string &s, size_t &pos) {
        if (pos >= s.size()) return 0;
        bool neg = false;
        if (s[pos] == '-') { neg = true; pos++; }

        // Check for octal (starts with 0 and has more digits)
        bool octal = false;
        if (pos < s.size() && s[pos] == '0' && pos + 1 < s.size() &&
            s[pos + 1] >= '0' && s[pos + 1] <= '7' &&
            // Make sure it's not just "0" followed by a delimiter
            pos + 1 < s.size() && s[pos + 1] >= '0' && s[pos + 1] <= '9') {
            // Heuristic: if all digits are 0-7 until delimiter, treat as octal
            size_t check = pos;
            while (check < s.size() && s[check] >= '0' && s[check] <= '7') check++;
            if (check > pos + 1 && (check >= s.size() || s[check] == ';' || s[check] == ',' || s[check] == ')'))
                octal = true;
        }

        int64_t val = 0;
        if (octal) {
            while (pos < s.size() && s[pos] >= '0' && s[pos] <= '7')
                val = val * 8 + (s[pos++] - '0');
        } else {
            while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9')
                val = val * 10 + (s[pos++] - '0');
        }
        return neg ? -val : val;
    }

    // ── Parse type definition after '=' ──────────────────────────────
    void parseTypeDef(const std::string &s, size_t &pos, TypeRef ref) {
        if (pos >= s.size()) return;
        // Save ForwardRef tag name before potential overwrite.
        // If a named ForwardRef (clientStatic_t) gets overwritten by an anonymous
        // struct ($_NNNN), rename the struct to the forward tag.
        std::string savedForwardTag;
        {
            auto it = m_types.find(ref);
            if (it != m_types.end() && it->second.kind == StabsTypeKind::ForwardRef &&
                !it->second.forwardTag.empty() && it->second.forwardTag.find("$_") != 0)
                savedForwardTag = it->second.forwardTag;
        }

        // Handle @sN; attribute prefix
        if (s[pos] == '@') {
            int sizeBits = 0;
            pos++; // skip '@'
            if (pos < s.size() && s[pos] == 's') {
                pos++;
                sizeBits = (int)parseIntVal(s, pos);
                if (pos < s.size() && s[pos] == ';') pos++;
            } else {
                // Skip unknown attribute until ';'
                while (pos < s.size() && s[pos] != ';') pos++;
                if (pos < s.size()) pos++;
            }

            // Check for built-in type number: @sN;-NUM;
            if (pos < s.size() && s[pos] == '-') {
                int64_t builtinNum = parseIntVal(s, pos);
                if (pos < s.size() && s[pos] == ';') pos++;
                auto &ti = m_types[ref];
                classifyBuiltinType(ti, builtinNum, sizeBits);
                return;
            }
            // Otherwise continue parsing the actual definition
            if (pos < s.size() && s[pos] == '=') {
                pos++;
                parseTypeDef(s, pos, ref);
                auto it = m_types.find(ref);
                if (it != m_types.end() && sizeBits > 0)
                    it->second.sizeBytes = sizeBits / 8;
                return;
            }
            // Might be a range or type ref following
            if (pos < s.size()) {
                parseTypeDef(s, pos, ref);
                auto it = m_types.find(ref);
                if (it != m_types.end() && sizeBits > 0)
                    it->second.sizeBytes = sizeBits / 8;
                return;
            }
            return;
        }

        char ch = s[pos];

        // Range type: r(file,type);low;high;
        if (ch == 'r') {
            pos++;
            TypeRef rangeBase = parseTypeRef(s, pos);
            if (pos < s.size() && s[pos] == ';') pos++;
            int64_t low = parseIntVal(s, pos);
            if (pos < s.size() && s[pos] == ';') pos++;
            int64_t high = parseIntVal(s, pos);
            if (pos < s.size() && s[pos] == ';') pos++;

            auto &ti = m_types[ref];
            ti.rangeLow = low;
            ti.rangeHigh = high;
            ti.isSelfRef = (rangeBase == ref);

            if (ti.isSelfRef) {
                classifyRangeType(ti, low, high);
            } else {
                ti.kind = StabsTypeKind::Typedef;
                ti.targetType = rangeBase;
            }
            return;
        }

        // Struct: sNfields;;
        if (ch == 's') {
            pos++;
            auto &ti = m_types[ref];
            ti.kind = StabsTypeKind::Struct;
            ti.sizeBytes = (int)parseIntVal(s, pos);
            parseStructFields(s, pos, ti);
            // If this overwrote a ForwardRef, inherit the tag name
            if (!savedForwardTag.empty() &&
                (ti.name.empty() || ti.name.find("$_") == 0))
                ti.name = savedForwardTag;
            return;
        }

        // Union: uNfields;;
        if (ch == 'u') {
            pos++;
            auto &ti = m_types[ref];
            ti.kind = StabsTypeKind::Union;
            ti.sizeBytes = (int)parseIntVal(s, pos);
            parseStructFields(s, pos, ti);
            return;
        }

        // Enum: eLABEL:VAL,LABEL:VAL,...,;
        if (ch == 'e') {
            pos++;
            auto &ti = m_types[ref];
            ti.kind = StabsTypeKind::Enum;
            while (pos < s.size() && s[pos] != ';') {
                // Parse label
                size_t nameEnd = s.find(':', pos);
                if (nameEnd == std::string::npos) break;
                std::string label = s.substr(pos, nameEnd - pos);
                pos = nameEnd + 1;
                int64_t val = parseIntVal(s, pos);
                if (pos < s.size() && s[pos] == ',') pos++;
                ti.enumValues.push_back({label, val});
            }
            if (pos < s.size() && s[pos] == ';') pos++;
            return;
        }

        // Pointer: *(type)
        if (ch == '*') {
            pos++;
            auto &ti = m_types[ref];
            ti.kind = StabsTypeKind::Pointer;
            ti.targetType = parseTypeRef(s, pos);
            // Inline definition
            if (pos < s.size() && s[pos] == '=') {
                pos++;
                parseTypeDef(s, pos, ti.targetType);
            }
            return;
        }

        // Reference: &(type)
        if (ch == '&') {
            pos++;
            auto &ti = m_types[ref];
            ti.kind = StabsTypeKind::Reference;
            ti.targetType = parseTypeRef(s, pos);
            if (pos < s.size() && s[pos] == '=') {
                pos++;
                parseTypeDef(s, pos, ti.targetType);
            }
            return;
        }

        // Const: k(type)
        if (ch == 'k') {
            pos++;
            auto &ti = m_types[ref];
            ti.kind = StabsTypeKind::Const;
            ti.targetType = parseTypeRef(s, pos);
            if (pos < s.size() && s[pos] == '=') {
                pos++;
                parseTypeDef(s, pos, ti.targetType);
            }
            return;
        }

        // Volatile: B(type)
        if (ch == 'B') {
            pos++;
            auto &ti = m_types[ref];
            ti.kind = StabsTypeKind::Volatile;
            ti.targetType = parseTypeRef(s, pos);
            if (pos < s.size() && s[pos] == '=') {
                pos++;
                parseTypeDef(s, pos, ti.targetType);
            }
            return;
        }

        // Array: ar(indextype);low;high;(elemtype)
        if (ch == 'a') {
            pos++;
            if (pos < s.size() && s[pos] == 'r') pos++; // skip 'r'
            parseTypeRef(s, pos); // index type (ignored)
            if (pos < s.size() && s[pos] == ';') pos++;
            int low = (int)parseIntVal(s, pos);
            if (pos < s.size() && s[pos] == ';') pos++;
            int high = (int)parseIntVal(s, pos);
            if (pos < s.size() && s[pos] == ';') pos++;

            auto &ti = m_types[ref];
            ti.kind = StabsTypeKind::Array;
            ti.arrayLow = low;
            ti.arrayHigh = high;
            ti.targetType = parseTypeRef(s, pos);
            if (pos < s.size() && s[pos] == '=') {
                pos++;
                parseTypeDef(s, pos, ti.targetType);
            }
            return;
        }

        // Function returning: f(type)
        if (ch == 'f') {
            pos++;
            auto &ti = m_types[ref];
            ti.kind = StabsTypeKind::Function;
            ti.targetType = parseTypeRef(s, pos);
            if (pos < s.size() && s[pos] == '=') {
                pos++;
                parseTypeDef(s, pos, ti.targetType);
            }
            return;
        }

        // Forward reference: xsTAG: or xuTAG:
        if (ch == 'x') {
            pos++;
            bool isUnion = false;
            if (pos < s.size()) {
                if (s[pos] == 'u') isUnion = true;
                pos++; // skip 's' or 'u' or 'e'
            }
            size_t end = s.find(':', pos);
            auto &ti = m_types[ref];
            ti.kind = StabsTypeKind::ForwardRef;
            ti.isUnionFwd = isUnion;
            if (end != std::string::npos) {
                ti.forwardTag = s.substr(pos, end - pos);
                pos = end + 1;
            }
            return;
        }

        // C++ method type: #(...)
        if (ch == '#') {
            // Skip C++ method type definitions
            int depth = 0;
            while (pos < s.size()) {
                if (s[pos] == '(') depth++;
                else if (s[pos] == ')') { depth--; if (depth <= 0) { pos++; break; } }
                else if (s[pos] == ';' && depth <= 0) { pos++; break; }
                pos++;
            }
            auto &ti = m_types[ref];
            ti.kind = StabsTypeKind::Function;
            return;
        }

        // Type reference (alias): just (file,type) with no '='
        if (ch == '(' || (ch >= '0' && ch <= '9')) {
            TypeRef target = parseTypeRef(s, pos);
            auto &ti = m_types[ref];
            ti.kind = StabsTypeKind::Typedef;
            ti.targetType = target;
            if (pos < s.size() && s[pos] == '=') {
                pos++;
                parseTypeDef(s, pos, target);
            }
            return;
        }

        // Built-in type by number: -N
        if (ch == '-') {
            int64_t num = parseIntVal(s, pos);
            if (pos < s.size() && s[pos] == ';') pos++;
            auto &ti = m_types[ref];
            classifyBuiltinType(ti, num, 0);
            return;
        }

        // C++ inheritance: !N,offset,vis,...
        if (ch == '!') {
            pos++;
            int numBases = (int)parseIntVal(s, pos);
            if (pos < s.size() && s[pos] == ',') pos++;
            auto &ti = m_types[ref];
            if (ti.kind == StabsTypeKind::Unknown) ti.kind = StabsTypeKind::Struct;

            for (int b = 0; b < numBases; ++b) {
                // Parse: virtual_flag + visibility_access digits, then base type
                while (pos < s.size() && s[pos] != ',' && s[pos] != ';' && s[pos] != '(') pos++;
                if (pos < s.size() && s[pos] == ',') pos++;
                // Parse base type ref
                TypeRef baseRef = NullType;
                if (pos < s.size() && (s[pos] == '(' || (s[pos] >= '0' && s[pos] <= '9'))) {
                    baseRef = parseTypeRef(s, pos);
                    if (pos < s.size() && s[pos] == '=') {
                        pos++;
                        parseTypeDef(s, pos, baseRef);
                    }
                }
                if (pos < s.size() && s[pos] == ';') pos++;
                if (pos < s.size() && s[pos] == ',') pos++;

                // Copy base class fields into derived class
                if (baseRef != NullType) {
                    auto *baseType = getType(baseRef);
                    if (!baseType) baseType = resolveType(baseRef);
                    if (baseType && (baseType->kind == StabsTypeKind::Struct ||
                                     baseType->kind == StabsTypeKind::Union)) {
                        for (auto &bf : baseType->fields) {
                            if (!bf.name.empty() && bf.name[0] != '/' && bf.name[0] != '!' &&
                                bf.name.find("::") == std::string::npos)
                                ti.fields.push_back(bf);
                        }
                    }
                }
            }
            // Parse derived class's own fields
            parseStructFields(s, pos, ti);
            return;
        }
    }

    // ── Parse struct/union fields ────────────────────────────────────
    void parseStructFields(const std::string &s, size_t &pos, StabsTypeInfo &ti) {
        while (pos < s.size()) {
            // Double semicolon or end = struct end
            if (s[pos] == ';') {
                pos++;
                if (pos < s.size() && s[pos] == ';') { pos++; break; } // end of fields if next is also ;
                // Single ; just ended a field, continue
                // But actually double ; means end... let me check:
                // The end of struct is terminated by ";;" but since each field ends with ;
                // the second ; actually starts the end. Let me handle this differently.
                // Actually after the last field's ";" we just check if next is ';'
                continue;
            }

            // Skip C++ visibility prefix (/0, /1, /2)
            if (s[pos] == '/') {
                pos += 2; // skip /N
            }

            // C++ method definitions start with method name followed by ::
            // We detect this and skip them
            size_t colonPos = findFieldColon(s, pos);
            if (colonPos == std::string::npos || colonPos >= s.size()) break;

            // Check if this is a C++ method (name::type or just ends struct)
            std::string fieldName = s.substr(pos, colonPos - pos);
            pos = colonPos + 1;

            // Empty field name or C++ operators: skip the rest
            if (fieldName.empty()) {
                skipToFieldEnd(s, pos);
                continue;
            }

            // Check for C++ method definition: name::
            if (pos < s.size() && s[pos] == ':') {
                // This is a C++ method — skip until we find end marker
                skipCppMethod(s, pos);
                continue;
            }

            // C++ static member: /vis(typeref):mangled;
            if (pos < s.size() && s[pos] == '/') {
                skipToFieldEnd(s, pos);
                continue;
            }

            // Regular field: (typeref),bitoffset,bitsize;
            StabsTypeField field;
            field.name = fieldName;
            field.typeRef = parseTypeRef(s, pos);
            if (pos < s.size() && s[pos] == '=') {
                pos++;
                parseTypeDef(s, pos, field.typeRef);
            }
            if (pos < s.size() && s[pos] == ',') pos++;
            field.bitOffset = (int)parseIntVal(s, pos);
            if (pos < s.size() && s[pos] == ',') pos++;
            field.bitSize = (int)parseIntVal(s, pos);
            if (pos < s.size() && s[pos] == ';') pos++;

            ti.fields.push_back(field);
        }
    }

    // Find the colon after a field name (not ::)
    static size_t findFieldColon(const std::string &s, size_t pos) {
        while (pos < s.size()) {
            if (s[pos] == ':') {
                if (pos + 1 < s.size() && s[pos + 1] == ':')
                    { pos += 2; continue; } // skip ::
                return pos;
            }
            if (s[pos] == ';') return std::string::npos; // end of struct
            pos++;
        }
        return std::string::npos;
    }

    void skipToFieldEnd(const std::string &s, size_t &pos) {
        int depth = 0;
        while (pos < s.size()) {
            if (s[pos] == '(') depth++;
            else if (s[pos] == ')') depth--;
            else if (s[pos] == ';' && depth <= 0) { pos++; return; }
            pos++;
        }
    }

    void skipCppMethod(const std::string &s, size_t &pos) {
        // Skip past C++ method definitions within a struct
        // Methods end with ";;" pair or we detect the next field
        // Simple approach: skip until we see a pattern that looks like a field start
        // or double semicolon
        while (pos < s.size()) {
            if (s[pos] == ';') {
                pos++;
                // Check if next char starts a new field or ends struct
                if (pos < s.size() && (s[pos] == ';' || s[pos] == '\0')) return;
                // Check if what follows looks like a field name (alpha or /)
                if (pos < s.size() && (std::isalpha(s[pos]) || s[pos] == '_' || s[pos] == '/'))
                    return;
            } else {
                pos++;
            }
        }
    }

    // Skip a type definition without storing it
    void skipTypeDef(const std::string &s, size_t &pos) {
        int depth = 0;
        while (pos < s.size()) {
            if (s[pos] == '(') depth++;
            else if (s[pos] == ')') depth--;
            else if (s[pos] == ';' && depth <= 0) { pos++; return; }
            pos++;
        }
    }

    // ── Classify a self-referential range type (primitive) ───────────
    void classifyRangeType(StabsTypeInfo &ti, int64_t low, int64_t high) {
        if (low == 0 && high == 0) {
            ti.kind = StabsTypeKind::Void;
            ti.sizeBytes = 0;
        } else if (low == 0 && high == 127) {
            ti.kind = StabsTypeKind::Char;
            ti.sizeBytes = 1;
        } else if (low == 0 && high == 255) {
            ti.kind = StabsTypeKind::UChar;
            ti.sizeBytes = 1;
        } else if (low == -128 && high == 127) {
            ti.kind = StabsTypeKind::Char;
            ti.sizeBytes = 1;
        } else if (low == -32768 && high == 32767) {
            ti.kind = StabsTypeKind::Short;
            ti.sizeBytes = 2;
        } else if (low == 0 && high == 65535) {
            ti.kind = StabsTypeKind::UShort;
            ti.sizeBytes = 2;
        } else if (low == (int64_t)-2147483648LL && high == 2147483647) {
            ti.kind = StabsTypeKind::Int;
            ti.sizeBytes = 4;
        } else if (low == 0 && (high == (int64_t)4294967295LL || high == (int64_t)0xFFFFFFFFLL)) {
            ti.kind = StabsTypeKind::UInt;
            ti.sizeBytes = 4;
        } else if (high == 0 && low > 0) {
            // Float types encoded as r(self);SIZE;0;
            if (low == 4) { ti.kind = StabsTypeKind::Float; ti.sizeBytes = 4; }
            else if (low == 8) { ti.kind = StabsTypeKind::Double; ti.sizeBytes = 8; }
            else if (low == 12 || low == 16) { ti.kind = StabsTypeKind::LongDouble; ti.sizeBytes = (int)low; }
            else { ti.kind = StabsTypeKind::Int; ti.sizeBytes = 4; }
        } else if (low < 0 && high > 2147483647LL) {
            ti.kind = StabsTypeKind::LongLong;
            ti.sizeBytes = 8;
        } else if (low == 0 && high > (int64_t)4294967295LL) {
            ti.kind = StabsTypeKind::ULongLong;
            ti.sizeBytes = 8;
        } else {
            // Default to int
            ti.kind = StabsTypeKind::Int;
            ti.sizeBytes = 4;
        }
    }

    // ── Classify built-in type by negative number ────────────────────
    void classifyBuiltinType(StabsTypeInfo &ti, int64_t num, int sizeBits) {
        // GCC built-in type numbers (negative)
        switch ((int)num) {
        case -1:  ti.kind = StabsTypeKind::Int;       ti.sizeBytes = 4; break;
        case -2:  ti.kind = StabsTypeKind::Char;      ti.sizeBytes = 1; break;
        case -3:  ti.kind = StabsTypeKind::Short;     ti.sizeBytes = 2; break;
        case -4:  ti.kind = StabsTypeKind::Long;      ti.sizeBytes = 4; break;
        case -5:  ti.kind = StabsTypeKind::UChar;     ti.sizeBytes = 1; break;
        case -6:  ti.kind = StabsTypeKind::Char;      ti.sizeBytes = 1; break; // signed char
        case -7:  ti.kind = StabsTypeKind::UShort;    ti.sizeBytes = 2; break;
        case -8:  ti.kind = StabsTypeKind::UInt;      ti.sizeBytes = 4; break;
        case -9:  ti.kind = StabsTypeKind::UInt;      ti.sizeBytes = 4; break; // unsigned
        case -10: ti.kind = StabsTypeKind::ULong;     ti.sizeBytes = 4; break;
        case -11: ti.kind = StabsTypeKind::Void;      ti.sizeBytes = 0; break;
        case -12: ti.kind = StabsTypeKind::Float;     ti.sizeBytes = 4; break;
        case -13: ti.kind = StabsTypeKind::Double;    ti.sizeBytes = 8; break;
        case -14: ti.kind = StabsTypeKind::LongDouble;ti.sizeBytes = 12; break;
        case -15: ti.kind = StabsTypeKind::Int;       ti.sizeBytes = 4; break; // integer
        case -16: ti.kind = StabsTypeKind::Bool;      ti.sizeBytes = 1; break;
        case -17: ti.kind = StabsTypeKind::Short;     ti.sizeBytes = 2; break; // short real (float)
        case -18: ti.kind = StabsTypeKind::Double;    ti.sizeBytes = 8; break; // real
        case -31: ti.kind = StabsTypeKind::LongLong;  ti.sizeBytes = 8; break;
        case -32: ti.kind = StabsTypeKind::ULongLong; ti.sizeBytes = 8; break;
        default:  ti.kind = StabsTypeKind::Int;       ti.sizeBytes = 4; break;
        }
        if (sizeBits > 0) ti.sizeBytes = sizeBits / 8;
    }
};
