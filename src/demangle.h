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
