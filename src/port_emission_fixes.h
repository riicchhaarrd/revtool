#pragma once

#include <array>
#include <string>

namespace PortEmissionFixes {

struct OpaqueStorageField {
    const char *globalName;
    const char *fieldName;
};

struct StructFieldDeclOverride {
    const char *structName;
    const char *fieldName;
    const char *decl;
};

inline constexpr std::array<OpaqueStorageField, 2> kOpaqueStorageFields = {{
    {"clc", "state"},
    {"cl", "active"},
}};

inline constexpr std::array<StructFieldDeclOverride, 1> kStructFieldDeclOverrides = {{
    // Original 32-bit code treats this 512-byte char buffer as
    // `const char *spawnVars[64][2]`. Use 4-byte words so host builds keep
    // the STABS field size while generated subscripts remain valid C.
    {"SpawnVar", "spawnVars", "int spawnVars[64][2][1]"},
}};

inline bool isOpaqueStorageField(const std::string &globalName,
                                 const std::string &fieldName) {
    for (const auto &rule : kOpaqueStorageFields) {
        if (globalName == rule.globalName && fieldName == rule.fieldName)
            return true;
    }
    return false;
}

inline std::string opaqueStorageFieldNameForGlobal(const std::string &globalName) {
    for (const auto &rule : kOpaqueStorageFields) {
        if (globalName == rule.globalName)
            return rule.fieldName;
    }
    return "";
}

inline std::string structFieldDeclOverride(const std::string &structName,
                                           const std::string &fieldName) {
    for (const auto &rule : kStructFieldDeclOverrides) {
        if (structName == rule.structName && fieldName == rule.fieldName)
            return rule.decl;
    }
    return "";
}

} // namespace PortEmissionFixes
