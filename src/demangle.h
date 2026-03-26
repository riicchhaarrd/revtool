#pragma once
#include <string>
#include <cstdlib>
#include <cxxabi.h>

inline std::string demangle(const std::string &name) {
    if (name.empty()) return name;

    // Try demangling the full name first (works for _Z... mangled names)
    int status = -1;
    char *d = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);
    if (status == 0 && d) { std::string r(d); free(d); return r; }

    // Mach-O adds a leading '_' — strip it and try again
    if (name.size() > 1 && name[0] == '_') {
        d = abi::__cxa_demangle(name.c_str() + 1, nullptr, nullptr, &status);
        if (status == 0 && d) { std::string r(d); free(d); return r; }
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
