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

inline std::string opaqueStorageFieldZeroAddress(const std::string &globalName,
                                                 const std::string &fieldName) {
    if (!isOpaqueStorageField(globalName, fieldName))
        return "";
    return "(int)&" + globalName;
}

inline void replaceAll(std::string &text, const std::string &from,
                       const std::string &to) {
    if (from.empty())
        return;
    size_t pos = 0;
    while ((pos = text.find(from, pos)) != std::string::npos) {
        text.replace(pos, from.size(), to);
        pos += to.size();
    }
}

inline std::string rewriteOpaqueStorageFieldExpr(std::string expr) {
    if (expr.empty())
        return expr;

    for (const auto &rule : kOpaqueStorageFields) {
        const std::string name = rule.globalName;
        const std::string field = rule.fieldName;
        const std::string addr = "&" + name;
        for (const std::string &qual : {"void", "const void"}) {
            const std::string member = "((" + qual + " *)" + name + ")->" + field;

            replaceAll(expr, "((char *)(" + member + "))",
                       "((char *)" + addr + ")");
            replaceAll(expr, "((char *)(" + member + ")",
                       "((char *)" + addr);
            replaceAll(expr, "((char *)" + member,
                       "((char *)" + addr);
            replaceAll(expr, member, "(int)" + addr);
        }
    }
    return expr;
}

} // namespace PortEmissionFixes
