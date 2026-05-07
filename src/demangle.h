#pragma once
#include <string>
#include <cstdlib>
#include <cctype>
#include <cxxabi.h>

inline std::string demangle(const std::string &name) {
    if (name.empty()) return name;

    // Try demangling the full name first (works for _Z... mangled names)
    int status = -1;
    char *d = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);
    if (status == 0 && d) { std::string r(d); free(d); return r; }

    // Mach-O adds a leading '_' — strip it and try again
    if (name.size() > 1 && name[0] == '_') {
        const char *stripped = name.c_str() + 1;
        // Only try demangling if it looks like a real C++ mangled name.
        // Itanium ABI mangled names start with _Z (or Z after Mach-O underscore strip).
        // Short names like "rg", "ri" are valid C symbols but happen to be valid
        // Itanium ABI type manglings (rg = "__float128 restrict", ri = "int restrict"),
        // causing false positive demanglings.
        if (stripped[0] == 'Z' || (stripped[0] == '_' && stripped[1] == 'Z')) {
            d = abi::__cxa_demangle(stripped, nullptr, nullptr, &status);
            if (status == 0 && d) { std::string r(d); free(d); return r; }
        }
        // Not mangled — just strip the Mach-O underscore
        return name.substr(1);
    }
    return name;
}

// Strip the parameter list from a demangled C++ name.
// "FxRange::SetRange(float, float)" → "FxRange::SetRange"
// "foo" → "foo" (no change for plain C names)
inline std::string demangleNameOnly(const std::string &name) {
    std::string full = demangle(name);
    // Find the outermost '(' that starts the parameter list.
    // Must handle nested templates like "Foo<Bar(int)>::baz(float)".
    // The param list is the LAST top-level '(' ... ')' at the end.
    // Strip trailing " const" or " volatile" qualifiers
    while (true) {
        if (full.size() > 6 && full.substr(full.size() - 6) == " const")
            full = full.substr(0, full.size() - 6);
        else if (full.size() > 9 && full.substr(full.size() - 9) == " volatile")
            full = full.substr(0, full.size() - 9);
        else break;
    }
    if (full.empty() || full.back() != ')') return full;
    int depth = 0;
    for (int i = (int)full.size() - 1; i >= 0; --i) {
        if (full[i] == ')') depth++;
        else if (full[i] == '(') {
            depth--;
            if (depth == 0) {
                // Check this isn't operator()
                if (i >= 8 && full.substr(i - 8, 8) == "operator") return full;
                return full.substr(0, i);
            }
        }
    }
    return full;
}

inline bool isCIdentifierName(const std::string &name) {
    if (name.empty()) return false;
    if (!std::isalpha((unsigned char)name[0]) && name[0] != '_')
        return false;
    for (char c : name)
        if (!std::isalnum((unsigned char)c) && c != '_')
            return false;
    return true;
}

inline std::string cIdentifierFromName(const std::string &name) {
    std::string out = name;

    auto paren = out.find('(');
    auto scope = out.rfind("::");
    if (paren != std::string::npos && scope != std::string::npos &&
        paren < scope && scope + 2 < out.size())
        out = out.substr(scope + 2);

    size_t pos = 0;
    while ((pos = out.find("::", pos)) != std::string::npos) {
        out.replace(pos, 2, "__");
        pos += 2;
    }
    pos = 0;
    while ((pos = out.find(" ", pos)) != std::string::npos)
        out.replace(pos, 1, "_");
    pos = 0;
    while ((pos = out.find("~", pos)) != std::string::npos) {
        out.replace(pos, 1, "dtor_");
        pos += 5;
    }
    pos = 0;
    while ((pos = out.find("&", pos)) != std::string::npos)
        out.erase(pos, 1);

    for (auto &c : out)
        if (!std::isalnum((unsigned char)c) && c != '_')
            c = '_';
    if (out.empty())
        return "_";
    if (std::isdigit((unsigned char)out[0]))
        out = "_" + out;
    return out;
}
