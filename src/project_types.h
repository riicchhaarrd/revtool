#pragma once

#include "macho.h"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

struct ProjectTypeApplyResult {
    int structs = 0;
    int globals = 0;
};

static inline std::string projectTrim(const std::string &s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

static inline std::string projectSquashSpaces(std::string s) {
    std::string out;
    bool lastSpace = false;
    for (char ch : s) {
        bool isSpace = std::isspace((unsigned char)ch);
        if (isSpace) {
            if (!lastSpace) out += ' ';
        } else {
            out += ch;
        }
        lastSpace = isSpace;
    }
    return projectTrim(out);
}

static inline std::string projectStripComments(const std::string &src) {
    std::string out;
    for (size_t i = 0; i < src.size();) {
        if (i + 1 < src.size() && src[i] == '/' && src[i + 1] == '*') {
            size_t e = src.find("*/", i + 2);
            i = e == std::string::npos ? src.size() : e + 2;
            out += ' ';
        } else if (i + 1 < src.size() && src[i] == '/' && src[i + 1] == '/') {
            size_t e = src.find('\n', i + 2);
            i = e == std::string::npos ? src.size() : e;
            out += '\n';
        } else {
            out += src[i++];
        }
    }
    return out;
}

static inline bool projectIsIdentStart(char ch) {
    return std::isalpha((unsigned char)ch) || ch == '_';
}

static inline bool projectIsIdentChar(char ch) {
    return std::isalnum((unsigned char)ch) || ch == '_';
}

static inline bool projectReadIdentifier(const std::string &src, size_t &pos,
                                         std::string &out) {
    while (pos < src.size() && std::isspace((unsigned char)src[pos])) ++pos;
    if (pos >= src.size() || !projectIsIdentStart(src[pos])) return false;
    size_t start = pos++;
    while (pos < src.size() && projectIsIdentChar(src[pos])) ++pos;
    out = src.substr(start, pos - start);
    return true;
}

static inline int projectParseInt(const std::string &s, int def = 0) {
    char *end = nullptr;
    long v = std::strtol(s.c_str(), &end, 0);
    return end && *end == 0 ? (int)v : def;
}

static inline uint32_t projectParseAddress(const std::string &s) {
    char *end = nullptr;
    unsigned long v = std::strtoul(s.c_str(), &end, 0);
    return end && *end == 0 ? (uint32_t)v : 0;
}

static inline bool projectEndsWithPointer(const std::string &typeText) {
    std::string t = projectTrim(typeText);
    return !t.empty() && t.back() == '*';
}

static inline TypeRef projectScalarType(MachOFile &mf, const std::string &rawType);

static inline int projectTypeSize(MachOFile &mf, const std::string &rawType) {
    std::string t = projectSquashSpaces(rawType);
    t.erase(std::remove(t.begin(), t.end(), '*'), t.end());
    t = projectSquashSpaces(t);
    const int ptrSize = mf.is64Bit() ? 8 : 4;
    if (projectEndsWithPointer(rawType)) return ptrSize;
    if (t == "char" || t == "signed char" || t == "unsigned char" ||
        t == "int8_t" || t == "uint8_t" || t == "bool")
        return 1;
    if (t == "short" || t == "short int" || t == "signed short" ||
        t == "unsigned short" || t == "int16_t" || t == "uint16_t")
        return 2;
    if (t == "long long" || t == "signed long long" ||
        t == "unsigned long long" || t == "int64_t" || t == "uint64_t" ||
        t == "double")
        return 8;
    if (t == "long" || t == "signed long" || t == "unsigned long" ||
        t == "size_t" || t == "ssize_t" || t == "intptr_t" || t == "uintptr_t")
        return ptrSize;
    if (t.rfind("struct ", 0) == 0 || t.rfind("union ", 0) == 0) {
        std::string name = projectTrim(t.substr(t.find(' ') + 1));
        TypeRef ref = mf.typeTable().findTypeByName(name);
        auto *ti = mf.typeTable().resolveType(ref);
        if (ti && ti->sizeBytes > 0) return ti->sizeBytes;
    }
    return 4;
}

static inline TypeRef projectScalarType(MachOFile &mf, const std::string &rawType) {
    StabsTypeTable &types = mf.mutableTypeTable();
    std::string t = projectSquashSpaces(rawType);
    if (projectEndsWithPointer(t)) {
        std::string base = projectTrim(t.substr(0, t.rfind('*')));
        TypeRef target = projectScalarType(mf, base.empty() ? "void" : base);
        TypeRef ptr = types.createSyntheticType(StabsTypeKind::Pointer, "", mf.is64Bit() ? 8 : 4);
        if (auto *pti = types.getMutableType(ptr))
            pti->targetType = target;
        return ptr;
    }
    if (t.rfind("struct ", 0) == 0 || t.rfind("union ", 0) == 0) {
        std::string name = projectTrim(t.substr(t.find(' ') + 1));
        TypeRef ref = types.findTypeByName(name);
        if (ref != NullType) return ref;
    }

    StabsTypeKind kind = StabsTypeKind::Int;
    int size = projectTypeSize(mf, t);
    if (t == "void") kind = StabsTypeKind::Void;
    else if (t == "char" || t == "signed char" || t == "int8_t") kind = StabsTypeKind::Char;
    else if (t == "unsigned char" || t == "uint8_t") kind = StabsTypeKind::UChar;
    else if (t == "short" || t == "short int" || t == "signed short" || t == "int16_t") kind = StabsTypeKind::Short;
    else if (t == "unsigned short" || t == "uint16_t") kind = StabsTypeKind::UShort;
    else if (t == "unsigned int" || t == "uint32_t") kind = StabsTypeKind::UInt;
    else if (t == "long" || t == "signed long") kind = StabsTypeKind::Long;
    else if (t == "unsigned long") kind = StabsTypeKind::ULong;
    else if (t == "long long" || t == "signed long long" || t == "int64_t") kind = StabsTypeKind::LongLong;
    else if (t == "unsigned long long" || t == "uint64_t") kind = StabsTypeKind::ULongLong;
    else if (t == "float") kind = StabsTypeKind::Float;
    else if (t == "double") kind = StabsTypeKind::Double;
    else if (t == "bool") kind = StabsTypeKind::Bool;
    return types.createSyntheticType(kind, "", size);
}

static inline TypeRef projectArrayType(MachOFile &mf, TypeRef elemRef,
                                       int elemSize, int count) {
    StabsTypeTable &types = mf.mutableTypeTable();
    TypeRef ref = types.createSyntheticType(StabsTypeKind::Array, "", elemSize * count);
    if (auto *ti = types.getMutableType(ref)) {
        ti->targetType = elemRef;
        ti->arrayLow = 0;
        ti->arrayHigh = std::max(0, count - 1);
    }
    return ref;
}

static inline bool projectParseField(MachOFile &mf, const std::string &rawDecl,
                                     int &cursor, StabsTypeField &field) {
    std::string decl = projectTrim(rawDecl);
    if (decl.empty()) return false;

    int count = 1;
    size_t nameEnd = decl.size();
    if (!decl.empty() && decl.back() == ']') {
        size_t lb = decl.rfind('[');
        if (lb != std::string::npos) {
            count = std::max(1, projectParseInt(projectTrim(decl.substr(lb + 1, decl.size() - lb - 2)), 1));
            nameEnd = lb;
        }
    }
    while (nameEnd > 0 && std::isspace((unsigned char)decl[nameEnd - 1])) --nameEnd;
    size_t nameStart = nameEnd;
    while (nameStart > 0 && projectIsIdentChar(decl[nameStart - 1])) --nameStart;
    if (nameStart == nameEnd || !projectIsIdentStart(decl[nameStart])) return false;

    std::string name = decl.substr(nameStart, nameEnd - nameStart);
    std::string typeText = projectTrim(decl.substr(0, nameStart));
    if (typeText.empty()) return false;

    int explicitOffset = -1;
    size_t marker = name.find("_0x");
    if (marker != std::string::npos)
        explicitOffset = projectParseInt(name.substr(marker + 1), -1);
    if (explicitOffset >= cursor)
        cursor = explicitOffset;

    int elemSize = std::max(1, projectTypeSize(mf, typeText));
    int totalSize = std::max(1, elemSize * count);
    if (name.rfind("pad_", 0) == 0) {
        cursor += totalSize;
        return false;
    }

    TypeRef elemRef = projectScalarType(mf, typeText);
    field.name = name;
    field.bitOffset = cursor * 8;
    field.bitSize = totalSize * 8;
    field.typeRef = count > 1 ? projectArrayType(mf, elemRef, elemSize, count) : elemRef;
    cursor += totalSize;
    return true;
}

static inline int projectApplyStructs(MachOFile &mf, const std::string &customTypes) {
    std::string src = projectStripComments(customTypes);
    int applied = 0;
    size_t pos = 0;
    while (pos < src.size()) {
        size_t st = src.find("struct", pos);
        if (st == std::string::npos) break;
        bool leftOk = st == 0 || !projectIsIdentChar(src[st - 1]);
        bool rightOk = st + 6 >= src.size() || !projectIsIdentChar(src[st + 6]);
        if (!leftOk || !rightOk) { pos = st + 6; continue; }

        size_t p = st + 6;
        std::string name;
        if (!projectReadIdentifier(src, p, name)) { pos = st + 6; continue; }
        while (p < src.size() && std::isspace((unsigned char)src[p])) ++p;
        if (p >= src.size() || src[p] != '{') { pos = p; continue; }
        size_t bodyStart = ++p;
        int depth = 1;
        while (p < src.size() && depth > 0) {
            if (src[p] == '{') ++depth;
            else if (src[p] == '}') --depth;
            ++p;
        }
        if (depth != 0) break;
        std::string body = src.substr(bodyStart, p - bodyStart - 1);
        pos = p;

        std::vector<StabsTypeField> fields;
        int cursor = 0;
        size_t lineStart = 0;
        while (lineStart < body.size()) {
            size_t semi = body.find(';', lineStart);
            if (semi == std::string::npos) break;
            StabsTypeField field;
            if (projectParseField(mf, body.substr(lineStart, semi - lineStart), cursor, field))
                fields.push_back(field);
            lineStart = semi + 1;
        }
        if (!fields.empty()) {
            mf.mutableTypeTable().upsertSyntheticStruct(name, fields, cursor);
            ++applied;
        }
    }
    return applied;
}

static inline int projectApplyGlobalBindings(MachOFile &mf, const std::string &bindingsText) {
    int applied = 0;
    std::istringstream in(bindingsText);
    std::string line;
    while (std::getline(in, line)) {
        line = projectTrim(line);
        if (line.empty()) continue;
        std::istringstream ls(line);
        std::string addrText, typeName, symbol;
        ls >> addrText >> typeName;
        std::getline(ls, symbol);
        symbol = projectTrim(symbol);
        uint32_t addr = projectParseAddress(addrText);
        if (!addr || typeName.empty()) continue;
        TypeRef ref = mf.typeTable().findTypeByName(typeName);
        if (ref == NullType) continue;
        if (mf.mutableTypeTable().overrideGlobalType(addr, symbol, ref))
            ++applied;
    }
    return applied;
}

static inline ProjectTypeApplyResult applyProjectTypes(MachOFile &mf,
                                                       const std::string &customTypes,
                                                       const std::string &globalBindingsText) {
    ProjectTypeApplyResult result;
    result.structs = projectApplyStructs(mf, customTypes);
    result.globals = projectApplyGlobalBindings(mf, globalBindingsText);
    return result;
}
