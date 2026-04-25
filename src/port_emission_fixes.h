#pragma once

#include <array>
#include <string>

namespace PortEmissionFixes {

struct OpaqueStorageField {
    const char *globalName;
    const char *fieldName;
};

inline constexpr std::array<OpaqueStorageField, 2> kOpaqueStorageFields = {{
    {"clc", "state"},
    {"cl", "active"},
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

} // namespace PortEmissionFixes
