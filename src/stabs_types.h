#pragma once
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>

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
};

struct StabsGlobalVar {
    std::string name;
    uint32_t    address = 0;
    TypeRef     typeRef = NullType;
    bool        isStatic = false;
};

// ── STABS Type Table ─────────────────────────────────────────────────
// Stores all types for one compilation unit (between N_SO boundaries).
// For a whole binary we keep a per-unit table and merge lookups.

class StabsTypeTable {
public:
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
                   ch == 'F' || ch == 'f' || ch == 'p' || ch == 'r') {
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

    // Register a global/static variable
    void addGlobal(const std::string &name, uint32_t addr, TypeRef type, bool isStatic) {
        m_globals.push_back({name, addr, type, isStatic});
        if (addr) m_globalByAddr[addr] = m_globals.size() - 1;
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

    // Resolve through typedefs, const, volatile to the underlying type
    const StabsTypeInfo* resolveType(TypeRef ref, int depth = 0) const {
        if (depth > 20 || ref == NullType) return nullptr;
        auto *t = getType(ref);
        if (!t) return nullptr;
        if (t->kind == StabsTypeKind::Typedef || t->kind == StabsTypeKind::Const ||
            t->kind == StabsTypeKind::Volatile) {
            if (t->targetType != NullType && t->targetType != ref)
                return resolveType(t->targetType, depth + 1);
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
            std::string inner = formatType(t->targetType, depth + 1);
            // Check if target is a function pointer
            auto *tgt = getType(t->targetType);
            if (tgt && tgt->kind == StabsTypeKind::Function)
                return inner; // already formatted as function pointer
            return inner + " *";
        }
        case StabsTypeKind::Reference: return formatType(t->targetType, depth + 1) + " &";
        case StabsTypeKind::Const:     return "const " + formatType(t->targetType, depth + 1);
        case StabsTypeKind::Volatile:  return "volatile " + formatType(t->targetType, depth + 1);

        case StabsTypeKind::Typedef:
            if (!t->name.empty()) return t->name;
            return formatType(t->targetType, depth + 1);

        case StabsTypeKind::Struct:
            return t->name.empty() ? "struct" : "struct " + t->name;
        case StabsTypeKind::Union:
            return t->name.empty() ? "union" : "union " + t->name;
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
        auto *t = getType(ref);
        if (!t) return "int " + varName;

        // Handle arrays specially
        if (t->kind == StabsTypeKind::Array) {
            std::string elem = formatType(t->targetType);
            int count = t->arrayHigh - t->arrayLow + 1;
            return elem + " " + varName + "[" + std::to_string(count) + "]";
        }
        // Handle function pointers
        if (t->kind == StabsTypeKind::Pointer) {
            auto *tgt = resolveType(t->targetType);
            if (tgt && tgt->kind == StabsTypeKind::Function) {
                std::string ret = formatType(tgt->targetType);
                return ret + " (*" + varName + ")()";
            }
        }
        return formatType(ref) + " " + varName;
    }

    // Find struct/union field at a given byte offset
    const StabsTypeField* findFieldAtOffset(TypeRef ref, int byteOffset) const {
        auto *t = resolveType(ref);
        if (!t || (t->kind != StabsTypeKind::Struct && t->kind != StabsTypeKind::Union))
            return nullptr;
        int bitTarget = byteOffset * 8;
        for (auto &f : t->fields) {
            if (f.bitOffset == bitTarget) return &f;
            // Also match by byte offset for fields wider than 8 bits
            if (f.bitOffset / 8 == byteOffset) return &f;
        }
        // Try nested: find the field whose range contains the offset
        for (auto &f : t->fields) {
            if (bitTarget >= f.bitOffset && bitTarget < f.bitOffset + f.bitSize)
                return &f;
        }
        return nullptr;
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

    // Global/static variable lookups
    const std::vector<StabsGlobalVar>& globals() const { return m_globals; }

    const StabsGlobalVar* globalAtAddress(uint32_t addr) const {
        auto it = m_globalByAddr.find(addr);
        if (it != m_globalByAddr.end()) return &m_globals[it->second];
        return nullptr;
    }

    const StabsGlobalVar* globalByName(const std::string &name) const {
        for (auto &g : m_globals)
            if (g.name == name) return &g;
        return nullptr;
    }

    // Include files
    const std::vector<std::string>& includes() const { return m_includes; }

    // All types (for generating forward declarations)
    const std::map<TypeRef, StabsTypeInfo>& allTypes() const { return m_types; }

    // Generate struct definition as C code
    std::string formatStructDef(TypeRef ref) const {
        auto *t = getType(ref);
        if (!t || (t->kind != StabsTypeKind::Struct && t->kind != StabsTypeKind::Union))
            return "";
        std::string kw = (t->kind == StabsTypeKind::Union) ? "union" : "struct";
        std::string out = kw;
        if (!t->name.empty()) out += " " + t->name;
        out += " {\n";
        for (auto &f : t->fields) {
            if (f.name.empty() || f.name[0] == '/') continue; // skip C++ visibility markers
            out += "    " + formatDecl(f.typeRef, f.name) + ";\n";
        }
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
    std::map<TypeRef, StabsTypeInfo>         m_types;
    std::vector<StabsGlobalVar>              m_globals;
    std::unordered_map<uint32_t, size_t>     m_globalByAddr;
    std::vector<std::string>                 m_includes;

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
            return {fileNum, typeNum};
        }
        // Bare type number (no parens, file=0)
        if (s[pos] == '-' || (s[pos] >= '0' && s[pos] <= '9')) {
            int typeNum = parseIntVal(s, pos);
            return {0, typeNum};
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
            // Parse C++ base class info, then struct body
            pos++;
            int numBases = (int)parseIntVal(s, pos);
            if (pos < s.size() && s[pos] == ',') pos++;
            for (int b = 0; b < numBases; ++b) {
                // Skip: virtual_flag, visibility_access, offset, base_type
                while (pos < s.size() && s[pos] != ',' && s[pos] != ';') pos++;
                if (pos < s.size() && s[pos] == ',') pos++;
                // Skip base type ref (and possible inline def)
                if (pos < s.size() && (s[pos] == '(' || (s[pos] >= '0' && s[pos] <= '9'))) {
                    parseTypeRef(s, pos);
                    if (pos < s.size() && s[pos] == '=') {
                        pos++;
                        skipTypeDef(s, pos);
                    }
                }
                if (pos < s.size() && s[pos] == ';') pos++;
                if (pos < s.size() && s[pos] == ',') pos++;
            }
            // Now parse struct fields
            auto &ti = m_types[ref];
            if (ti.kind == StabsTypeKind::Unknown) {
                ti.kind = StabsTypeKind::Struct;
            }
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
