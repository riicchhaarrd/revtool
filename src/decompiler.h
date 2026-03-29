#pragma once
#include "ir.h"
#include "lifter.h"
#include "cfg.h"
#include "ssa.h"
#include "type_infer.h"
#include "coalesce.h"
#include "simplify.h"
#include "macho.h"
#include <QString>
#include <QProcess>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <cstdio>
#include <cstring>
#include <functional>

// ── Decompiler: x86 → IR → CFG → Structured C ──────────────────────
// Full pipeline: lift, build CFG, recover structure, fold expressions,
// emit compilable C with STABS types.

class Decompiler {
public:
    static inline bool s_useSSA = false;

    // Decompile a single function
    static QString decompile(const MachOFile &mf, uint32_t funcAddr, bool format = true) {
        Lifter lifter(mf);
        IRFunc func = lifter.liftFunction(funcAddr);
        if (func.blocks.empty()) return "/* could not decompile */\n";

        // Analysis + optimization pipeline
        if (s_useSSA) {
            SSABuilder ssa;
            ssa.buildSSA(func);
            IRSimplifier().simplify(func);
            TypeInferer().infer(func, mf.typeTable(), &mf);
            ssa.destroySSA(func);
            IRSimplifier().simplify(func);  // clean up copies from destroySSA
        } else {
            SSABuilder().computeIdomOnly(func);
            IRSimplifier().simplify(func);
            TypeInferer().infer(func, mf.typeTable(), &mf);
        }
        VarCoalescer().coalesce(func, mf.typeTable());

        CfgStructurer structurer;
        auto tree = structurer.structure(func);

        Emitter em(mf, func);
        QString code = em.generate(tree.get());
        return format ? clangFormat(cleanupOutput(code)) : cleanupOutput(code);
    }

    // Decompile a whole source file
    static QString decompileFile(const MachOFile &mf, int srcIdx) {
        auto &sources = mf.stabsSourceFiles();
        if (srcIdx < 0 || srcIdx >= (int)sources.size()) return "";
        auto &sf = sources[srcIdx];
        auto &types = mf.typeTable();

        QString dir = QString::fromStdString(sf.directory);
        QString fname = QString::fromStdString(sf.filename);
        QString path = fname.startsWith(dir) ? fname : dir + fname;

        QString out;
        out += "/* " + path + " */\n\n";
        out += platformTypedefs();
        out += "\n";

        // Emit includes relevant to this source file
        std::set<std::string> emitted;
        for (auto &inc : types.includes()) {
            // Only emit .h files, skip the source file itself
            if (inc.find(".h") == std::string::npos) continue;
            std::string incName = inc;
            // Normalize backslashes
            for (auto &c : incName) if (c == '\\') c = '/';
            size_t slash = incName.rfind('/');
            if (slash != std::string::npos) incName = incName.substr(slash + 1);
            if (emitted.count(incName)) continue;
            emitted.insert(incName);
            if (inc.find("/usr/") != std::string::npos || inc.find("/System/") != std::string::npos)
                out += QString("#include <%1>\n").arg(QString::fromStdString(incName));
            else
                out += QString("#include \"%1\"\n").arg(QString::fromStdString(incName));
        }
        if (!emitted.empty()) out += "\n";

        // Emit type definitions used by functions in this file
        std::set<TypeRef> usedTypes;
        for (size_t fi : sf.functionIndices) {
            auto &fn = mf.stabsFunctions()[fi];
            if (fn.returnType != NullType) usedTypes.insert(fn.returnType);
            for (auto &p : fn.params) if (p.typeRef != NullType) usedTypes.insert(p.typeRef);
            for (auto &l : fn.locals) if (l.typeRef != NullType) usedTypes.insert(l.typeRef);
        }
        emitTypeDefs(out, types, usedTypes);

        // Emit global/static variables that belong to this source file
        std::set<std::string> emittedGlobals;
        bool anyGlobals = false;
        for (auto &g : types.globals()) {
            if (g.address == 0) continue;
            if (g.sourceFileIdx != srcIdx) continue;
            if (emittedGlobals.count(g.name)) continue;
            emittedGlobals.insert(g.name);
            out += QString::fromStdString(
                (g.isStatic ? "static " : "") + types.formatDecl(g.typeRef, g.name)) + ";\n";
            anyGlobals = true;
        }

        // Also emit extern declarations for globals from other source files
        // that might be referenced by functions in this file
        // (Build a lookup map by name for quick cross-file global resolution)
        std::map<std::string, const StabsGlobalVar*> globalByName;
        for (auto &g : types.globals()) {
            if (g.address == 0 || g.name.empty()) continue;
            if (g.sourceFileIdx == srcIdx) continue; // already emitted
            if (!globalByName.count(g.name))
                globalByName[g.name] = &g;
        }

        if (anyGlobals) out += "\n";

        // Decompile each function
        std::vector<size_t> sorted = sf.functionIndices;
        std::sort(sorted.begin(), sorted.end(), [&](size_t a, size_t b) {
            return mf.stabsFunctions()[a].address < mf.stabsFunctions()[b].address;
        });

        // Collect addresses of functions defined in this file
        std::set<uint32_t> localAddrs;
        for (size_t fi : sorted) localAddrs.insert(mf.stabsFunctions()[fi].address);

        // Generate forward declarations for cross-CU functions by scanning
        // the function map for call targets (lightweight — no lifting needed)
        {
            std::set<std::string> emittedProtos;
            auto &funcMap = mf.functionMap();
            // Collect all call target addresses from all functions in this file
            // by quick-scanning for x86 CALL instructions in binary data
            std::set<uint32_t> callTargets;
            for (size_t fi : sorted) {
                auto &fn = mf.stabsFunctions()[fi];
                if (fn.address == 0 || fn.size == 0) continue;
                const Section *sec = mf.sectionForAddress(fn.address);
                if (!sec || fn.address < sec->addr) continue;
                uint32_t foff = fn.address - sec->addr;
                if (foff >= sec->size) continue;
                uint32_t avail = sec->size - foff;
                const uint8_t *code = mf.bytesAt(sec->offset + foff,
                    std::min(fn.size, avail));
                if (!code) continue;
                // Scan for E8 xx xx xx xx (near call) instructions
                for (uint32_t j = 0; j + 4 < fn.size; ++j) {
                    if (code[j] == 0xE8) {
                        int32_t rel;
                        memcpy(&rel, code + j + 1, 4);
                        uint32_t target = fn.address + j + 5 + rel;
                        callTargets.insert(target);
                        j += 4; // skip operand
                    }
                }
            }
            for (uint32_t target : callTargets) {
                if (localAddrs.count(target)) continue;
                auto fit = funcMap.find(target);
                if (fit == funcMap.end()) continue;
                const std::string &calleeName = fit->second;
                if (calleeName.empty() || emittedProtos.count(calleeName)) continue;
                // Look up STABS info (by addr first, then by name)
                const StabsFunction *callee = mf.stabsFunctionAt(target);
                if (!callee) callee = mf.stabsFunctionByName(calleeName);
                if (!callee || callee->returnType == NullType) continue;
                emittedProtos.insert(calleeName);
                // Sanitize C++ names for C
                std::string cname = calleeName;
                { size_t p = 0; while ((p = cname.find("::", p)) != std::string::npos)
                    cname.replace(p, 2, "_"); }
                { size_t p = 0; while ((p = cname.find("~", p)) != std::string::npos)
                    cname.replace(p, 1, "dtor_"); }
                std::string retStr = types.formatType(callee->returnType);
                std::string proto = retStr + " " + cname + "(";
                if (!callee->params.empty()) {
                    for (size_t p = 0; p < callee->params.size(); ++p) {
                        if (p) proto += ", ";
                        auto &par = callee->params[p];
                        proto += par.typeRef != NullType ?
                            types.formatType(par.typeRef) : "int";
                    }
                }
                proto += ");\n";
                out += QString::fromStdString(proto);
            }
            if (!emittedProtos.empty()) out += "\n";
        }

        // Emit forward declarations only for static functions
        // (needed when a static func is referenced before its definition)
        {
            for (size_t fi : sorted) {
                auto &fn = mf.stabsFunctions()[fi];
                if (fn.address == 0 || fn.isGlobal) continue; // only static functions
                std::string cname = fn.name;
                { size_t p = 0; while ((p = cname.find("::", p)) != std::string::npos)
                    cname.replace(p, 2, "_"); }
                { size_t p = 0; while ((p = cname.find("~", p)) != std::string::npos)
                    cname.replace(p, 1, "dtor_"); }
                { size_t p = 0; while ((p = cname.find(" ", p)) != std::string::npos)
                    cname.replace(p, 1, "_"); }
                // Skip names with C++ template characters
                if (cname.find('<') != std::string::npos || cname.find('>') != std::string::npos)
                    continue;
                std::string retStr = fn.returnType != NullType ?
                    types.formatType(fn.returnType) : "int";
                out += QString::fromStdString("static " + retStr + " " + cname + "();\n");
            }
            out += "\n";
        }

        QString funcBodies;
        for (size_t fi : sorted) {
            auto &fn = mf.stabsFunctions()[fi];
            if (fn.address == 0) continue;
            funcBodies += decompile(mf, fn.address, false); // skip per-function formatting
            funcBodies += "\n";
        }

        // Scan function bodies for references to cross-file globals
        // and emit extern declarations for them
        if (!globalByName.empty()) {
            std::string body = funcBodies.toStdString();
            bool anyExterns = false;
            for (auto &[name, gvar] : globalByName) {
                if (emittedGlobals.count(name)) continue;
                // Check if this global name appears in the function bodies
                if (body.find(name) != std::string::npos) {
                    emittedGlobals.insert(name);
                    // Emit as initialized definition for direct addressing
                    // Structs/unions/arrays with unknown size must stay extern
                    std::string decl = types.formatDecl(gvar->typeRef, name);
                    auto *gt = types.resolveType(gvar->typeRef);
                    bool isStruct = (gt && (gt->kind == StabsTypeKind::Struct ||
                                            gt->kind == StabsTypeKind::Union));
                    bool isArray = (gt && gt->kind == StabsTypeKind::Array);
                    bool isPtr = (gt && gt->kind == StabsTypeKind::Pointer);
                    if (isStruct || isArray)
                        out += QString::fromStdString("extern " + decl) + ";\n";
                    else
                        out += QString::fromStdString(decl + " = 0") + ";\n";
                    anyExterns = true;
                }
            }
            if (anyExterns) out += "\n";
        }

        // Also scan for named variables used but not declared anywhere
        // (globals resolved from nlist but not in STABS globals table)
        {
            std::string body = funcBodies.toStdString();
            // Collect all known names (params, locals, globals, functions, types)
            std::set<std::string> knownNames = emittedGlobals;
            for (size_t fi : sorted) {
                auto &fn = mf.stabsFunctions()[fi];
                knownNames.insert(fn.name);
                for (auto &p : fn.params) knownNames.insert(p.name);
                for (auto &l : fn.locals) knownNames.insert(l.name);
            }
            // C keywords to exclude
            static const std::set<std::string> kw = {
                "if","else","while","for","do","return","switch","case","break",
                "continue","default","goto","int","char","void","float","double",
                "unsigned","long","short","const","static","struct","enum","typedef",
                "sizeof","extern","NULL","true","false","inline","register","volatile",
                "signed","union","auto","this","memcpy","memcmp","memset","strlen",
                "memchr","printf","sprintf","fprintf","snprintf","strcmp","strcpy",
                "strcat","strncpy","strncmp","atoi","atof","free","malloc"
            };
            // Scan function bodies for identifiers that look like globals
            bool anyUndeclared = false;
            std::set<std::string> checked;
            for (size_t i = 0; i < body.size(); ++i) {
                if (isalpha(body[i]) || body[i] == '_') {
                    size_t start = i;
                    while (i < body.size() && (isalnum(body[i]) || body[i] == '_')) ++i;
                    std::string name = body.substr(start, i - start);
                    // Skip temps, vars, short names, keywords
                    if (name.size() < 3) continue;
                    if (name[0] == 'v' && name.size() <= 4 && isdigit(name[1])) continue;
                    if (name[0] == 't' && isdigit(name[1])) continue;
                    if (name.find("var_") == 0 || name.find("arg_") == 0 ||
                        name.find("bb_") == 0 || name.find("g_") == 0 ||
                        name.find("field_") == 0) continue;
                    if (kw.count(name) || knownNames.count(name) || checked.count(name)) continue;
                    checked.insert(name);
                    // Only declare if followed by usage context (not inside string/type/label)
                    bool isUsed = (body.find(name + " =") != std::string::npos ||
                                   body.find("= " + name) != std::string::npos ||
                                   body.find(": " + name) != std::string::npos ||
                                   body.find("(" + name + ")") != std::string::npos ||
                                   body.find("(" + name + ",") != std::string::npos ||
                                   body.find(", " + name + ")") != std::string::npos ||
                                   body.find(", " + name + ",") != std::string::npos);
                    // Exclude function calls (name followed by '(')
                    bool isFunc = (body.find(name + "(") != std::string::npos);
                    if (isUsed && !isFunc) {
                        knownNames.insert(name);
                        out += QString::fromStdString("int " + name + " = 0;\n");
                        anyUndeclared = true;
                    }
                }
            }
            if (anyUndeclared) out += "\n";
        }

        out += funcBodies;
        return clangFormat(cleanupOutput(out)); // cleanup + format
    }

    // Dump all STABS types as a C header
    static QString dumpTypes(const MachOFile &mf) {
        auto &types = mf.typeTable();
        QString out;
        out += "/* Auto-generated type definitions from STABS debug info */\n";
        out += "#pragma once\n\n";
        out += platformTypedefs(true); // self-contained, no system headers
        out += "\n";

        // Collect ALL type refs used across all functions
        std::set<TypeRef> allTypes;
        for (auto &fn : mf.stabsFunctions()) {
            if (fn.returnType != NullType) allTypes.insert(fn.returnType);
            for (auto &p : fn.params)
                if (p.typeRef != NullType) allTypes.insert(p.typeRef);
            for (auto &l : fn.locals)
                if (l.typeRef != NullType) allTypes.insert(l.typeRef);
        }
        // Also add all globals
        for (auto &g : types.globals())
            if (g.typeRef != NullType) allTypes.insert(g.typeRef);

        // Names already defined in platformTypedefs — skip these in type emission
        static const std::set<std::string> platformNames = {
            "BOOL","Bool","qboolean","DWORD","UINT","UINT32","UINT16","UINT8",
            "INT32","INT16","HRESULT","ULONG","LONG","BYTE","byte",
            "GLubyte","GLenum","GLint","GLuint","GLfloat","GLsizei",
            "HANDLE","HCURSOR","HWND","WindowRef","ControlRef",
            "EventLoopTimerRef","EventTargetRef","TXNObject",
            "Handle","Movie","Track","Media","CGDirectDisplayID",
            "CGGammaValue","CFStringRef","CFURLRef","CGDisplayFadeReservationToken",
            "CGFloat","Boolean","SInt16","SInt32","SInt64",
            "UInt8","UInt16","UInt32","UInt64","OSErr","OSStatus","OSType",
            "Str255","vec_t","vec2_t","vec3_t","vec4_t",
            "fileHandle_t","r_index_t","MaterialHandle","XAnim","XAnimNotify",
            "ContextRef","FSRef","CGPoint","CGSize","CGRect","MacRect","Point",
            "FourCharCode","ItemCount","ByteCount","MenuItemIndex","UniChar",
            "MenuRef","EventRef","EventQueueRef","EventHandlerRef",
            "EventHandlerCallRef","EventLoopRef","EventHandlerUPP",
            "EventLoopTimerUPP","AGLContext","AGLPixelFormat",
            "RgnHandle","PicHandle","PixMapHandle","GrafPtr","CGrafPtr",
            "BitMap","Ptr","StringPtr","TextEncoding","ScriptCode",
            "Fixed","Fract","Float32","Float64","URefCon","RefCon",
            "CFBundleRef","CFArrayRef","CFDictionaryRef","CFTypeRef",
            "IOSurfaceRef","ProcessSerialNumber","GDHandle",
            "ATSUFontFeatureType","ATSUFontFeatureSelector","ATSUStyle",
            "ATSUTextLayout","ATSUAttributeTag","ATSUFontID",
            "D3DTEXTUREFILTERTYPE","D3DFORMAT","D3DDEVTYPE","D3DPRIMITIVETYPE",
            "D3DTRANSFORMSTATETYPE","D3DRENDERSTATETYPE","D3DTEXTURESTAGESTATETYPE",
            "D3DSAMPLERSTATETYPE","D3DSTATEBLOCKTYPE","D3DMULTISAMPLE_TYPE",
            "D3DSWAPEFFECT","D3DRESOURCETYPE",
            "Byte","ColorSearchUPP","ColorComplementUPP","CTabHandle","ITabHandle",
            "CSpecArray","PixPatHandle","CCrsrHandle","CIconHandle","Rect",
            "MacRGBColor","QElemPtr","FSVolumeRefNum","StrFileName","EventKind",
            "EventModifiers","UniCharCount","AGLDrawable","Bits16","DInfo","DXInfo",
            "CursPtr","SFNTLookupFormatSpecificHeader",
        };

        // Emit forward declarations for all structs/unions
        std::set<std::string> fwdDeclared;
        for (auto ref : allTypes) {
            auto *t = types.resolveType(ref);
            if (!t) continue;
            if (t->kind == StabsTypeKind::Struct || t->kind == StabsTypeKind::Union) {
                if (t->name.empty() || t->name.find('<') != std::string::npos) continue;
                if (fwdDeclared.count(t->name) || platformNames.count(t->name)) continue;
                fwdDeclared.insert(t->name);
                std::string kw = (t->kind == StabsTypeKind::Union) ? "union" : "struct";
                out += QString::fromStdString(kw + " " + t->name + ";\n");
            }
        }
        if (!fwdDeclared.empty()) out += "\n";

        // Emit full type definitions (skip names already in platform typedefs)
        {
            std::set<TypeRef> emitted;
            std::set<std::string> emittedNames(platformNames);
            for (auto ref : allTypes)
                emitTypeDefsRecursive(out, types, ref, emitted, emittedNames);
            if (!emitted.empty()) out += "\n";
        }

        // Emit extern declarations for globals
        std::set<std::string> globalDeclared;
        for (auto &g : types.globals()) {
            if (g.address == 0 || g.name.empty()) continue;
            if (globalDeclared.count(g.name)) continue;
            if (g.name.find('<') != std::string::npos) continue;
            globalDeclared.insert(g.name);
            std::string decl;
            if (g.typeRef != NullType)
                decl = types.formatDecl(g.typeRef, g.name);
            else
                decl = "int " + g.name;
            out += "extern " + QString::fromStdString(decl) + ";\n";
        }

        // Emit function prototypes
        out += "\n/* Function prototypes */\n";
        std::set<std::string> protoDeclared;
        for (auto &fn : mf.stabsFunctions()) {
            if (fn.address == 0 || fn.name.empty()) continue;
            std::string cname = fn.name;
            for (auto &c : cname) { if (c == ':') c = '_'; if (c == '~') c = 'd'; }
            if (protoDeclared.count(cname)) continue;
            if (cname.find('<') != std::string::npos) continue;
            protoDeclared.insert(cname);
            std::string retStr = fn.returnType != NullType ?
                types.formatType(fn.returnType) : "int";
            out += QString::fromStdString(retStr + " " + cname + "(");
            if (fn.params.empty()) {
                out += "void";
            } else {
                for (size_t i = 0; i < fn.params.size(); ++i) {
                    if (i) out += ", ";
                    auto &p = fn.params[i];
                    if (p.typeRef != NullType)
                        out += QString::fromStdString(types.formatDecl(p.typeRef, p.name));
                    else
                        out += "int " + QString::fromStdString(p.name);
                }
            }
            out += ");\n";
        }

        return out;
    }

    // Platform type definitions for compilable output
    static QString platformTypedefs(bool selfContained = false) {
        QString out = "/* Platform types */\n";
        if (selfContained) {
            // Self-contained mode: no system headers needed (for cross-compiler)
            out += "typedef unsigned int size_t;\n"
                   "typedef int ssize_t;\n"
                   "typedef int ptrdiff_t;\n"
                   "typedef int intptr_t;\n"
                   "typedef __builtin_va_list va_list;\n"
                   "#define NULL ((void*)0)\n"
                   "typedef int int8_t __attribute__((mode(QI)));\n"
                   "typedef unsigned int uint8_t __attribute__((mode(QI)));\n"
                   "typedef int int16_t __attribute__((mode(HI)));\n"
                   "typedef unsigned int uint16_t __attribute__((mode(HI)));\n"
                   "typedef int int32_t __attribute__((mode(SI)));\n"
                   "typedef unsigned int uint32_t __attribute__((mode(SI)));\n"
                   "typedef int int64_t __attribute__((mode(DI)));\n"
                   "typedef unsigned int uint64_t __attribute__((mode(DI)));\n";
        } else {
            out += "#include <stdint.h>\n"
                   "#include <stddef.h>\n"
                   "#include <stdarg.h>\n"
                   "#include <math.h>\n"
                   "#include <string.h>\n"
                   "#include <stdio.h>\n";
        }
        if (selfContained) out += QString(
            "/* C library stubs */\n"
            "void *memset(void*,int,size_t);\n"
            "void *memcpy(void*,const void*,size_t);\n"
            "void *memmove(void*,const void*,size_t);\n"
            "int memcmp(const void*,const void*,size_t);\n"
            "size_t strlen(const char*);\n"
            "char *strcpy(char*,const char*);\n"
            "char *strncpy(char*,const char*,size_t);\n"
            "char *strcat(char*,const char*);\n"
            "int strcmp(const char*,const char*);\n"
            "int strncmp(const char*,const char*,size_t);\n"
            "char *strstr(const char*,const char*);\n"
            "char *strchr(const char*,int);\n"
            "int sprintf(char*,const char*,...);\n"
            "int snprintf(char*,size_t,const char*,...);\n"
            "int vsprintf(char*,const char*,va_list);\n"
            "int vsnprintf(char*,size_t,const char*,va_list);\n"
            "int printf(const char*,...);\n"
            "int sscanf(const char*,const char*,...);\n"
            "int atoi(const char*);\n"
            "double atof(const char*);\n"
            "void *malloc(size_t);\n"
            "void *calloc(size_t,size_t);\n"
            "void *realloc(void*,size_t);\n"
            "void free(void*);\n"
            "void exit(int);\n"
            "int abs(int);\n"
            "int rand(void);\n"
            "void srand(unsigned int);\n"
            "int setjmp(void*);\n"
            "void longjmp(void*,int);\n"
            "int toupper(int);\n"
            "int tolower(int);\n"
            "int isalpha(int);\n"
            "int isdigit(int);\n"
            "/* Math */\n"
            "float floorf(float); float ceilf(float); float sqrtf(float);\n"
            "float sinf(float); float cosf(float); float tanf(float);\n"
            "float fabsf(float); float fminf(float,float); float fmaxf(float,float);\n"
            "float acosf(float); float asinf(float); float atanf(float);\n"
            "float atan2f(float,float); float fmodf(float,float); float powf(float,float);\n"
            "float logf(float); float expf(float); float log10f(float);\n"
            "double floor(double); double ceil(double); double sqrt(double);\n"
            "double sin(double); double cos(double); double tan(double);\n"
            "double fabs(double); double fmin(double,double); double fmax(double,double);\n"
            "double acos(double); double asin(double); double atan(double);\n"
            "double atan2(double,double); double fmod(double,double); double pow(double,double);\n"
            "double log(double); double exp(double); double log10(double);\n");
        out += QString(
            "/* Carbon/Mac OS types */\n"
            "typedef unsigned int FourCharCode;\n"
            "typedef FourCharCode OSType;\n"
            "typedef unsigned int ItemCount;\n"
            "typedef unsigned int ByteCount;\n"
            "typedef unsigned int MenuItemIndex;\n"
            "typedef unsigned short UniChar;\n"
            "typedef void *MenuRef;\n"
            "typedef void *EventRef;\n"
            "typedef void *EventQueueRef;\n"
            "typedef void *EventHandlerRef;\n"
            "typedef void *EventHandlerCallRef;\n"
            "typedef void *EventLoopRef;\n"
            "typedef void *EventHandlerUPP;\n"
            "typedef void *EventLoopTimerUPP;\n"
            "typedef void *AGLContext;\n"
            "typedef void *AGLPixelFormat;\n"
            "typedef void *RgnHandle;\n"
            "typedef void *PicHandle;\n"
            "typedef void *PixMapHandle;\n"
            "typedef void *GrafPtr;\n"
            "typedef void *CGrafPtr;\n"
            "typedef void *BitMap;\n"
            "typedef void *Ptr;\n"
            "typedef void *StringPtr;\n"
            "typedef unsigned int TextEncoding;\n"
            "typedef int ScriptCode;\n"
            "typedef int Fixed;\n"
            "typedef int Fract;\n"
            "typedef float Float32;\n"
            "typedef double Float64;\n"
            "typedef unsigned int URefCon;\n"
            "typedef int RefCon;\n"
            "typedef void *CFBundleRef;\n"
            "typedef void *CFArrayRef;\n"
            "typedef void *CFDictionaryRef;\n"
            "typedef void *CFTypeRef;\n"
            "typedef void *IOSurfaceRef;\n"
            "typedef int ProcessSerialNumber;\n"
            "typedef void *ATSUFontFeatureType;\n"
            "typedef void *ATSUFontFeatureSelector;\n"
            "typedef void *ATSUStyle;\n"
            "typedef void *ATSUTextLayout;\n"
            "typedef void *ATSUAttributeTag;\n"
            "typedef unsigned int ATSUFontID;\n"
            "typedef unsigned short GDHandle;\n"
            "typedef unsigned char Byte;\n"
            "typedef void *ColorSearchUPP;\n"
            "typedef void *ColorComplementUPP;\n"
            "typedef void *CTabHandle;\n"
            "typedef void *ITabHandle;\n"
            "typedef int CSpecArray;\n"
            "typedef void *PixPatHandle;\n"
            "typedef void *CCrsrHandle;\n"
            "typedef void *CIconHandle;\n"
            "typedef struct { short top, left, bottom, right; } Rect;\n"
            "typedef struct { unsigned short red, green, blue; } MacRGBColor;\n"
            "typedef void *QElemPtr;\n"
            "typedef short FSVolumeRefNum;\n"
            "typedef unsigned char StrFileName[64];\n"
            "typedef unsigned short EventKind;\n"
            "typedef unsigned short EventModifiers;\n"
            "typedef unsigned int UniCharCount;\n"
            "typedef void *AGLDrawable;\n"
            "typedef int Bits16[16];\n"
            "typedef void *DInfo;\n"
            "typedef void *DXInfo;\n"
            "typedef void *CursPtr;\n"
            "typedef int SFNTLookupFormatSpecificHeader;\n"
            "typedef int BOOL;\n"
            "typedef int Bool;\n"
            "typedef int qboolean;\n"
            "typedef unsigned int DWORD;\n"
            "typedef unsigned int UINT;\n"
            "typedef unsigned int UINT32;\n"
            "typedef unsigned short UINT16;\n"
            "typedef unsigned char UINT8;\n"
            "typedef int INT32;\n"
            "typedef short INT16;\n"
            "typedef int HRESULT;\n"
            "typedef unsigned int ULONG;\n"
            "typedef long LONG;\n"
            "typedef unsigned char BYTE;\n"
            "typedef unsigned char byte;\n"
            "typedef unsigned char GLubyte;\n"
            "typedef unsigned int GLenum;\n"
            "typedef int GLint;\n"
            "typedef unsigned int GLuint;\n"
            "typedef float GLfloat;\n"
            "typedef int GLsizei;\n"
            "typedef void *HANDLE;\n"
            "typedef void *HCURSOR;\n"
            "typedef void *HWND;\n"
            "typedef void *WindowRef;\n"
            "typedef void *ControlRef;\n"
            "typedef void *EventLoopTimerRef;\n"
            "typedef void *EventTargetRef;\n"
            "typedef void *TXNObject;\n"
            "typedef void *Handle;\n"
            "typedef void *Movie;\n"
            "typedef void *Track;\n"
            "typedef void *Media;\n"
            "typedef void *CGDirectDisplayID;\n"
            "typedef void *CGGammaValue;\n"
            "typedef void *CFStringRef;\n"
            "typedef void *CFURLRef;\n"
            "typedef unsigned int CGDisplayFadeReservationToken;\n"
            "typedef float CGFloat;\n"
            "/* Game types */\n"
            "typedef int Boolean;\n"
            "typedef short SInt16;\n"
            "typedef int SInt32;\n"
            "typedef long long SInt64;\n"
            "typedef unsigned char UInt8;\n"
            "typedef unsigned short UInt16;\n"
            "typedef unsigned int UInt32;\n"
            "typedef unsigned long long UInt64;\n"
            "typedef short OSErr;\n"
            "typedef int OSStatus;\n"
            "typedef unsigned char Str255[256];\n"
            "typedef float vec_t;\n"
            "typedef vec_t vec2_t[2];\n"
            "typedef vec_t vec3_t[3];\n"
            "typedef vec_t vec4_t[4];\n"
            "typedef int fileHandle_t;\n"
            "typedef unsigned short r_index_t;\n"
            "typedef int MaterialHandle;\n"
            "typedef void *XAnim;\n"
            "typedef void *XAnimNotify;\n"
            "typedef struct { float x, y; } CGPoint;\n"
            "typedef struct { float width, height; } CGSize;\n"
            "typedef struct { CGPoint origin; CGSize size; } CGRect;\n"
            "typedef struct { short top, left, bottom, right; } MacRect;\n"
            "typedef struct { int x, y; } Point;\n"
            "typedef int D3DTEXTUREFILTERTYPE;\n"
            "typedef int D3DFORMAT;\n"
            "typedef int D3DDEVTYPE;\n"
            "typedef int D3DPRIMITIVETYPE;\n"
            "typedef int D3DTRANSFORMSTATETYPE;\n"
            "typedef int D3DRENDERSTATETYPE;\n"
            "typedef int D3DTEXTURESTAGESTATETYPE;\n"
            "typedef int D3DSAMPLERSTATETYPE;\n"
            "typedef int D3DSTATEBLOCKTYPE;\n"
            "typedef int D3DMULTISAMPLE_TYPE;\n"
            "typedef int D3DSWAPEFFECT;\n"
            "typedef int D3DRESOURCETYPE;\n"
            "typedef int D3DQUERYTYPE;\n"
            "typedef int D3DTEXTUREOP;\n"
            "typedef int D3DBASISTYPE;\n"
            "typedef int D3DDEGREETYPE;\n"
            "typedef int D3DPOOL;\n"
            "typedef int D3DBACKBUFFER_TYPE;\n"
            "typedef int D3DCUBEMAP_FACES;\n"
            "typedef int D3DMATRIX[16];\n"
            "typedef void *IDirect3DBaseTexture9;\n"
            "typedef void *IDirect3DSurface9;\n"
            "typedef void *IDirect3DPixelShader9;\n"
            "typedef void *IDirect3DVertexShader9;\n"
            "typedef void *IDirect3DVertexDeclaration9;\n"
            "typedef void *IDirect3DQuery9;\n"
            "typedef int D3DVERTEXELEMENT9[8];\n"
            "typedef struct { int left, top, right, bottom; } RECT;\n"
            "typedef struct { int x, y; } POINT;\n"
            "/* FILE from <stdio.h> */\n"
            "typedef void *YY_BUFFER_STATE;\n"
            "typedef int yy_state_type;\n"
            "typedef unsigned int u_int;\n"
            "typedef int jmp_buf[64];\n"
            "int stricmp(const char *, const char *);\n"
            "int strnicmp(const char *, const char *, size_t);\n"
            "typedef int bool;\n"
            "typedef signed char SInt8;\n"
            "/* StringPtr and Ptr defined in Carbon section above */\n"
            "typedef int INT;\n"
            "/* QElemPtr provided by STABS */\n"
            "typedef void *IOCompletionUPP;\n"
            "typedef struct { unsigned int lo, hi; } UTCDateTime;\n"
            "typedef struct { unsigned int signature; int id; } ControlID;\n"
            "typedef void *voidpf;\n"
            "typedef unsigned short WORD;\n"
            "typedef void *LPCSTR;\n"
            "typedef void *LPVOID;\n"
            "typedef unsigned int WPARAM;\n"
            "typedef unsigned int LPARAM;\n"
            "typedef unsigned int LRESULT;\n"
            "typedef void *HINSTANCE;\n"
            "typedef void *HMENU;\n"
            "typedef unsigned int ATOM;\n"
            "typedef unsigned int UINT_PTR;\n"
            "typedef short DCTELEM;\n"
            "typedef short SHORT;\n"
            "typedef int LONG_PTR;\n"
            "typedef unsigned long uLong;\n"
            "typedef unsigned int uInt;\n"
            "typedef unsigned char Bytef;\n"
            "typedef int JDIMENSION;\n"
            "typedef int boolean;\n"
            "typedef int JCOEF;\n"
            "typedef int JSAMPLE;\n"
            "typedef void *xcommand_t;\n"
            "typedef int D3DXMATRIX[16];\n"
            "typedef float D3DXVECTOR4[4];\n"
            "typedef float FLOAT;\n"
            "/* Common game types (forward declared) */\n"
            "typedef struct playerState_s playerState_t;\n"
            "typedef struct gentity_s gentity_t;\n"
            "typedef struct gclient_s gclient_t;\n"
            "typedef struct entityState_s entityState_t;\n"
            "typedef struct usercmd_s usercmd_t;\n"
            "typedef struct dvar_s dvar_t;\n"
            "typedef struct VariableValue_s VariableValue;\n"
            "typedef struct sval_u sval_t;\n"
            "typedef struct DObjAnimMat_s DObjAnimMat;\n"
            "typedef struct DObj_s DObj;\n"
            "typedef struct XAnimTree_s XAnimTree;\n"
            "typedef struct XAnimParts_s XAnimParts;\n"
            "typedef struct searchpath_s searchpath_t;\n"
            "typedef struct LocalizeString_s LocalizeString;\n"
            "typedef struct dheader_s dheader_t;\n"
            "typedef struct cplane_s cplane_t;\n"
            "typedef struct clipHandle_s { int _; } clipHandle_t;\n"
            "typedef struct leafList_s leafList_t;\n"
            "typedef int scr_entref_t;\n"
            "typedef struct animation_s animation_t;\n"
            "typedef struct rectDef_s rectDef_t;\n"
            "/* Audio codec types */\n"
            "typedef struct { float real; float imag; } complex_t;\n"
            "typedef float spx_sig_t;\n"
            "typedef short spx_word16_t;\n"
            "typedef int spx_int32_t;\n"
            "typedef struct VBRState_s VBRState;\n"
            "typedef int HSAMPLE;\n"
            "typedef short sample_t;\n"
            "/* JPEG types */\n"
            "typedef int *JSAMPARRAY;\n"
            "typedef int *JBLOCKROW;\n"
            "typedef int JCOEFPTR;\n"
            "/* C library */\n"
            "int Gestalt(unsigned int, int *);\n"
            "int sysctl(void *, unsigned int, void *, void *, void *, unsigned int);\n"
            "/* Engine types */\n"
            "typedef struct XVertexInfo_s XVertexInfo;\n"
            "typedef struct source_s source_t;\n"
            "typedef struct Alloc_s Alloc_t;\n"
            "typedef struct scr_block_s scr_block_t;\n"
            "typedef struct token_s token_t;\n"
            "typedef struct XModelParts_s XModelParts;\n"
            "typedef struct cStaticModel_s cStaticModel_t;\n"
            "typedef struct svEntity_s svEntity_t;\n"
            "typedef struct script_s script_t;\n"
            "typedef struct cLeafBrushNode_s cLeafBrushNode_t;\n"
            "typedef struct worldSector_s worldSector_t;\n"
            "typedef struct snd_alias_build_s snd_alias_build_t;\n"
            "typedef struct XSurface_s XSurface;\n"
            "typedef struct GfxSamplerState_s GfxSamplerState;\n"
            "typedef struct XModelCollSurf_s XModelCollSurf;\n"
            "typedef struct AILSOUNDINFO_s AILSOUNDINFO;\n"
            "typedef unsigned int UINT4;\n"
            "typedef struct define_s define_t;\n"
            "typedef struct cmd_function_s cmd_function_t;\n"
            "typedef struct hudelem_s hudelem_t;\n"
            "typedef struct FsListBehavior_s FsListBehavior;\n"
            "typedef struct XPartBits_s { int _[2]; } XPartBits;\n"
            "typedef float XQuat[4];\n"
            "typedef struct FxRange_s FxRange;\n"
            "typedef struct GfxCmdArray_s GfxCmdArray;\n"
            "typedef struct sortedColumn_s sortedColumn_t;\n"
            "typedef struct centity_s centity_t;\n"
            "typedef struct cgs_s cgs_t;\n"
            "typedef struct snapshot_s snapshot_t;\n"
            "typedef struct client_s client_t;\n"
            "typedef int *JSAMPROW;\n"
            "typedef struct ShadowCookieGlob_s { int _[64]; } ShadowCookieGlob;\n"
            "\n"
        );
        return out;
    }

    // Remove empty if blocks from output text
    static QString cleanupOutput(const QString &code) {
        // Pre-pass: fix &EXPR->field_X patterns → (EXPR + 0xX)
        QString cleaned = code;
        // &0->field_X → 0xX
        cleaned.replace("&0->field_", "0x__F");
        cleaned.replace("&(0)->field_", "0x__F");
        // &VAR->field_HEX → (VAR + 0xHEX) — only for synthetic field_XX names
        // Real field names (resolved from type info) are preserved as &VAR->realName
        {
            // Use a simple scan for &WORD->field_HEX patterns
            int pos = 0;
            while ((pos = cleaned.indexOf("&", pos)) != -1) {
                // Check if followed by IDENTIFIER->field_HEX
                int start = pos + 1;
                int nameEnd = start;
                while (nameEnd < cleaned.size() && (cleaned[nameEnd].isLetterOrNumber() || cleaned[nameEnd] == '_'))
                    ++nameEnd;
                if (nameEnd > start && nameEnd + 8 < cleaned.size() &&
                    cleaned.mid(nameEnd, 8) == "->field_") {
                    int hexStart = nameEnd + 8;
                    int hexEnd = hexStart;
                    while (hexEnd < cleaned.size() && QString("0123456789ABCDEFabcdef").contains(cleaned[hexEnd]))
                        ++hexEnd;
                    if (hexEnd > hexStart) {
                        // Check this is purely hex (a synthetic field_XX name, not a real name
                        // like "field_type" that happens to start with "field_")
                        QString hexPart = cleaned.mid(hexStart, hexEnd - hexStart);
                        bool allHex = true;
                        for (int i = 0; i < hexPart.size(); ++i) {
                            QChar c = hexPart[i];
                            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
                                allHex = false; break;
                            }
                        }
                        // Only convert synthetic field_XX names (all hex chars, followed by
                        // non-alpha — not a suffix of a real field name)
                        bool isSynthetic = allHex && (hexEnd >= cleaned.size() ||
                            !cleaned[hexEnd].isLetterOrNumber());
                        if (isSynthetic) {
                            QString varName = cleaned.mid(start, nameEnd - start);
                            QString hexOff = cleaned.mid(hexStart, hexEnd - hexStart);
                            QString replacement = "(" + varName + " + 0x" + hexOff + ")";
                            cleaned.replace(pos, hexEnd - pos, replacement);
                            pos += replacement.size();
                            continue;
                        }
                    }
                }
                ++pos;
            }
        }
        // Fix the marker: "0x__F" followed by hex digits becomes "0x" + hex
        {
            int pos = 0;
            while ((pos = cleaned.indexOf("0x__F", pos)) != -1) {
                cleaned.remove(pos + 2, 3); // remove "__F"
                pos += 2;
            }
        }
        QStringList lines = cleaned.split('\n');
        // Pass 1: Remove empty if blocks
        QStringList pass1;
        for (int i = 0; i < lines.size(); ++i) {
            if (i + 1 < lines.size() &&
                lines[i].trimmed().startsWith("if (") &&
                lines[i].trimmed().endsWith("{") &&
                lines[i+1].trimmed() == "}") {
                ++i; continue;
            }
            // Fix: while (cond) { return/break; } → if (cond) { return/break; }
            if (i + 2 < lines.size() &&
                lines[i].trimmed().startsWith("while (") &&
                lines[i].trimmed().endsWith("{") &&
                (lines[i+1].trimmed().startsWith("return ") || lines[i+1].trimmed() == "break;") &&
                lines[i+2].trimmed() == "}") {
                QString fixed = lines[i];
                fixed.replace("while (", "if (");
                pass1.append(fixed);
                pass1.append(lines[i+1]);
                pass1.append(lines[i+2]);
                i += 2; continue;
            }
            pass1.append(lines[i]);
        }
        // Pass 1b: Strip trailing "return;" at end of void functions
        // Only strip at outermost scope (brace depth 0), not inside if/while blocks
        {
            bool isVoid = false;
            for (auto &l : pass1) {
                if (l.trimmed().startsWith("void ") && l.contains("(")) { isVoid = true; break; }
                if (l.trimmed() == "{") break;
            }
            if (isVoid) {
                // Find and remove "return;" only when it's the last statement
                // before the closing "}" of the function (at brace depth 1→0)
                for (int i = pass1.size() - 1; i >= 0; --i) {
                    QString trimmed = pass1[i].trimmed();
                    if (trimmed == "}") continue;
                    if (trimmed == "return;") {
                        pass1.removeAt(i);
                    }
                    break; // only check the last non-} line
                }
            }
        }
        // Pass 2: Remove unused variable declarations
        // Scan forward through the entire remaining function body for references
        QStringList pass2;
        for (int i = 0; i < pass1.size(); ++i) {
            QString trimmed = pass1[i].trimmed();
            // Match more variable declaration patterns
            if (trimmed.startsWith("int v") || trimmed.startsWith("float v") ||
                trimmed.startsWith("int *v") ||
                trimmed.startsWith("int var_") || trimmed.startsWith("float var_")) {
                // Extract the variable name (find first 'v' for the var name)
                QString varName;
                int nameStart = trimmed.indexOf('v');
                int nameEnd = trimmed.indexOf(';', nameStart);
                if (nameStart >= 0 && nameEnd > nameStart)
                    varName = trimmed.mid(nameStart, nameEnd - nameStart);
                // Check if this var is used anywhere in the rest of the enclosing scope
                // Track brace depth to find the matching closing brace
                if (!varName.isEmpty()) {
                    bool used = false;
                    int depth = 0;
                    for (int j = i + 1; j < pass1.size(); ++j) {
                        QString line = pass1[j];
                        // Track brace depth
                        for (int c = 0; c < line.size(); ++c) {
                            if (line[c] == '{') depth++;
                            else if (line[c] == '}') depth--;
                        }
                        if (line.contains(varName)) { used = true; break; }
                        if (depth < 0) break; // reached the matching closing brace
                    }
                    if (!used) continue; // skip unused declaration
                }
            }
            pass2.append(pass1[i]);
        }
        QString result;
        for (auto &l : pass2) result += l + '\n';
        return result;
    }

    // Run clang-format on the output for clean formatting
    static QString clangFormat(const QString &code) {
        // Skip clang-format for very large outputs (>500KB) to avoid timeout
        if (code.size() > 500000) return code;
        QProcess proc;
        proc.start("clang-format", QStringList()
            << "-style={BasedOnStyle: LLVM, IndentWidth: 4, ColumnLimit: 100}"
            << "-assume-filename=decompiled.c");
        if (!proc.waitForStarted(1000)) return code;
        proc.write(code.toUtf8());
        proc.closeWriteChannel();
        if (!proc.waitForFinished(30000)) { proc.kill(); return code; }
        if (proc.exitCode() != 0) return code;
        return QString::fromUtf8(proc.readAllStandardOutput());
    }

private:
    // ── Emit type definitions ───────────────────────────────────────
    static void emitTypeDefs(QString &out, const StabsTypeTable &types,
                             const std::set<TypeRef> &used) {
        std::set<TypeRef> emitted;
        std::set<std::string> emittedNames;
        for (auto ref : used) {
            emitTypeDefsRecursive(out, types, ref, emitted, emittedNames);
        }
        if (!emitted.empty()) out += "\n";
    }

    static void emitTypeDefsRecursive(QString &out, const StabsTypeTable &types,
                                      TypeRef ref, std::set<TypeRef> &emitted,
                                      std::set<std::string> &emittedNames, int depth = 0) {
        if (ref == NullType || emitted.count(ref) || depth > 30) return;
        emitted.insert(ref); // mark visited BEFORE recursing to break cycles
        auto *t = types.getType(ref);
        if (!t) return;

        // Resolve through pointers/typedefs/arrays to find underlying struct/enum
        if (t->kind == StabsTypeKind::Pointer || t->kind == StabsTypeKind::Typedef ||
            t->kind == StabsTypeKind::Const || t->kind == StabsTypeKind::Volatile ||
            t->kind == StabsTypeKind::Array) {
            if (t->targetType != NullType)
                emitTypeDefsRecursive(out, types, t->targetType, emitted, emittedNames, depth + 1);
            return;
        }
        if (t->kind == StabsTypeKind::Struct || t->kind == StabsTypeKind::Union) {
            if (t->name.empty()) return;
            // Skip C++ template types (not valid C)
            if (t->name.find('<') != std::string::npos) return;
            // Skip if already emitted a struct/union with this name (cross-CU dedup)
            if (emittedNames.count(t->name)) return;
            emittedNames.insert(t->name);
            if (t->fields.empty()) {
                // Struct with no STABS fields — generate int fields at known offsets
                // to support field_X access patterns
                std::string kw = (t->kind == StabsTypeKind::Union) ? "union" : "struct";
                int sz = t->sizeBytes > 0 ? t->sizeBytes : 0;
                if (sz > 0 && sz <= 65536) {
                    // Emit as a struct padded with ints to cover the full size
                    // Fields will be accessed as ->field_X where X is hex offset
                    out += QString::fromStdString(kw + " " + t->name + " {\n");
                    int numInts = (sz + 3) / 4;
                    for (int i = 0; i < numInts; ++i) {
                        char fname[32];
                        snprintf(fname, sizeof(fname), "    int field_%X;\n", i * 4);
                        out += fname;
                    }
                    out += "};\n\n";
                } else if (sz > 65536) {
                    out += QString::fromStdString(kw + " " + t->name +
                        " { char _opaque[" + std::to_string(sz) + "]; };\n\n");
                } else {
                    out += QString::fromStdString(kw + " " + t->name + ";\n");
                }
                return;
            }
            // Pre-emit union dependencies (small, self-contained types)
            for (auto &f : t->fields) {
                if (f.typeRef == NullType) continue;
                auto *ft = types.resolveType(f.typeRef);
                if (ft && ft->kind == StabsTypeKind::Union &&
                    !ft->name.empty() && ft->name != t->name &&
                    !emittedNames.count(ft->name))
                    emitTypeDefsRecursive(out, types, f.typeRef, emitted, emittedNames, depth + 1);
            }
            // Check if all field types compile without undefined types.
            // Emit structs with unknown field types as offset-based int arrays.
            {
                bool allFieldsOk = true;
                for (auto &f : t->fields) {
                    if (f.bitSize == 0 && f.bitOffset == 0) continue;
                    if (f.name.empty() || f.name[0] == '/' || f.name[0] == '!' ||
                        f.name[0] == '#' || f.name[0] == '$' || f.name[0] == '~') continue;
                    if (f.name.find("::") != std::string::npos) continue;
                    if (f.name.find("(") != std::string::npos) continue;
                    if (f.name.find("<") != std::string::npos) continue;
                    // Check that the field's type resolves to something we've defined
                    auto *ft = types.resolveType(f.typeRef);
                    if (!ft) { allFieldsOk = false; break; }
                    // Pointer to anything is fine (forward-declared structs ok)
                    auto *rawFt = types.getType(f.typeRef);
                    if (rawFt && rawFt->kind == StabsTypeKind::Pointer) continue;
                    // Primitives are always fine
                    if (ft->kind <= StabsTypeKind::LongDouble) continue;
                    // Struct/union by value — must be already emitted
                    if (ft->kind == StabsTypeKind::Struct || ft->kind == StabsTypeKind::Union) {
                        if (!ft->name.empty() && !emittedNames.count(ft->name) &&
                            ft->name != t->name) {
                            allFieldsOk = false; break;
                        }
                    }
                    // Enum — must be already emitted
                    if (ft->kind == StabsTypeKind::Enum) {
                        if (!ft->name.empty() && !emittedNames.count(ft->name)) {
                            allFieldsOk = false; break;
                        }
                    }
                    // Array — check element type
                    if (ft->kind == StabsTypeKind::Array) {
                        auto *elem = types.resolveType(ft->targetType);
                        if (!elem || (elem->kind == StabsTypeKind::Struct &&
                            !emittedNames.count(elem->name))) {
                            allFieldsOk = false; break;
                        }
                    }
                }
                if (!allFieldsOk) {
                    // Emit struct with STABS field names but simplified types.
                    // Use int/pointer for fields whose types can't be resolved.
                    std::string kw = (t->kind == StabsTypeKind::Union) ? "union" : "struct";
                    out += QString::fromStdString(kw + " " + t->name + " {\n");
                    int prevEnd = 0; // track offset for padding
                    for (auto &f : t->fields) {
                        if (f.bitSize == 0 && f.bitOffset == 0) continue;
                        if (f.name.empty() || f.name[0] == '/' || f.name[0] == '~') continue;
                        if (f.name.find("::") != std::string::npos) continue;
                        if (f.name.find("(") != std::string::npos) continue;
                        if (f.name.find("<") != std::string::npos) continue;
                        if (f.name.find("=") != std::string::npos) continue;
                        if (f.name[0] == '!' || f.name[0] == '#' || f.name[0] == '$') continue;
                        if (f.name.find("operator") == 0) continue;
                        if (f.name.find("&") != std::string::npos) continue;
                        if (f.name.find(">") != std::string::npos) continue;
                        int byteOff = f.bitOffset / 8;
                        int byteSize = f.bitSize / 8;
                        if (byteSize <= 0) byteSize = 4;
                        // Add padding if needed
                        if (byteOff > prevEnd) {
                            int pad = byteOff - prevEnd;
                            char pname[32];
                            snprintf(pname, sizeof(pname), "    char _pad_%X[%d];\n", prevEnd, pad);
                            out += pname;
                        }
                        // Try to use the real type, fallback to int/char array
                        std::string ftype;
                        auto *ft = types.resolveType(f.typeRef);
                        auto *rawFt = types.getType(f.typeRef);
                        bool typeOk = false;
                        if (ft) {
                            if (ft->kind <= StabsTypeKind::LongDouble) typeOk = true;
                            if (rawFt && rawFt->kind == StabsTypeKind::Pointer) typeOk = true;
                            if ((ft->kind == StabsTypeKind::Struct || ft->kind == StabsTypeKind::Union)
                                && !ft->name.empty() && emittedNames.count(ft->name)) typeOk = true;
                            if (ft->kind == StabsTypeKind::Enum && !ft->name.empty()
                                && emittedNames.count(ft->name)) typeOk = true;
                            if (ft->kind == StabsTypeKind::Array) {
                                auto *elem = types.resolveType(ft->targetType);
                                if (elem && elem->kind <= StabsTypeKind::LongDouble) typeOk = true;
                            }
                        }
                        if (typeOk) {
                            ftype = types.formatDecl(f.typeRef, f.name);
                        } else if (byteSize == 1) {
                            ftype = "char " + f.name;
                        } else if (byteSize == 2) {
                            ftype = "short " + f.name;
                        } else if (byteSize <= 4) {
                            ftype = "int " + f.name;
                        } else {
                            char buf[64];
                            snprintf(buf, sizeof(buf), "char %s[%d]", f.name.c_str(), byteSize);
                            ftype = buf;
                        }
                        out += "    " + QString::fromStdString(ftype) + ";\n";
                        prevEnd = byteOff + byteSize;
                    }
                    // Pad to full size
                    int totalSize = t->sizeBytes > 0 ? t->sizeBytes : prevEnd;
                    if (prevEnd < totalSize) {
                        char pname[32];
                        snprintf(pname, sizeof(pname), "    char _pad_%X[%d];\n",
                                 prevEnd, totalSize - prevEnd);
                        out += pname;
                    }
                    out += "};\n\n";
                    return;
                }
            }
            // Emit fields' types first
            for (auto &f : t->fields)
                emitTypeDefsRecursive(out, types, f.typeRef, emitted, emittedNames, depth + 1);
            out += QString::fromStdString(types.formatStructDef(ref)) + ";\n\n";
            return;
        }
        if (t->kind == StabsTypeKind::Enum) {
            if (t->name.empty() || t->enumValues.empty()) return;
            if (emittedNames.count(t->name)) return;
            emittedNames.insert(t->name);
            out += QString::fromStdString(types.formatEnumDef(ref)) + ";\n\n";
            return;
        }
    }

    // ── C code emitter ──────────────────────────────────────────────
    class Emitter {
    public:
        Emitter(const MachOFile &mf, IRFunc &func)
            : m_mf(mf), m_func(func), m_types(mf.typeTable()) {
            // Copy propagation: if a temp is just assigned from a Var or another Temp,
            // propagate the source everywhere and eliminate the temp.
            runCopyPropagation();
            // NOTE: cross-group const propagation was removed because many "= 0"
            // values are actually loop induction variables (xor reg,reg) whose
            // initial value is 0 but are updated in loop iterations.
            // Count temp uses for inlining decisions
            for (auto &bb : func.blocks)
                for (auto &stmt : bb.stmts)
                    countTempUses(stmt);
            // Force-declare temps whose def and use are in different blocks
            // (cross-block inlining is unsafe because the defining expr's context may differ)
            forceDeclCrossBlockTemps();
        }

        QString generate(StructNode *root) {
            QString out;

            // Function signature
            std::string retType = "int";
            if (m_func.detectedVoid)
                retType = "void";
            else if (m_func.returnType != NullType)
                retType = m_types.formatType(m_func.returnType);

            std::string qual = m_func.isStatic ? "static " : "";
            std::string funcName = cName(m_func.name);
            out += QString::fromStdString(qual + retType) + " " +
                   QString::fromStdString(funcName) + "(";

            if (!m_func.params.empty()) {
                for (size_t i = 0; i < m_func.params.size(); ++i) {
                    if (i) out += ", ";
                    auto &p = m_func.params[i];
                    std::string decl;
                    if (p.typeRef != NullType) {
                        decl = m_types.formatDecl(p.typeRef, p.name);
                        // Strip const from 'this' pointer (C++ const methods make this const T*)
                        if (p.name == "this" && decl.find("const ") == 0)
                            decl = decl.substr(6);
                    } else {
                        decl = "int " + p.name;
                    }
                    out += QString::fromStdString(decl);
                }
            } else {
                out += "void";
            }
            out += ")\n{\n";

            // Local variable declarations — skip params (already declared in signature)
            std::set<std::string> paramNames;
            for (auto &p : m_func.params) paramNames.insert(p.name);

            std::set<std::string> declared;
            for (auto &l : m_func.locals) {
                if (l.name.empty() || declared.count(l.name) || paramNames.count(l.name)) continue;
                declared.insert(l.name);
                std::string decl;
                if (l.typeRef != NullType) {
                    decl = m_types.formatDecl(l.typeRef, l.name);
                    // Strip const from local declarations (locals may be reassigned)
                    if (decl.substr(0, 6) == "const " && decl.find('*') == std::string::npos)
                        decl = decl.substr(6);
                } else {
                    decl = "int " + l.name;
                }
                out += "    " + QString::fromStdString(decl) + ";\n";
            }

            // Collect goto targets and emitted blocks BEFORE declaring temps
            std::set<int> emittedBlocks;
            collectGotoTargets(root, m_gotoTargets);
            collectEmittedBlocks(root, emittedBlocks);

            // Find temps used as pointers (dereferenced in Load/Store)
            for (auto &bb : m_func.blocks)
                for (auto &stmt : bb.stmts) {
                    // Store: addr is the pointer being dereferenced
                    if (stmt.kind == IRStmtKind::Store && stmt.addr) {
                        if (stmt.addr->op == IROp::Temp)
                            m_pointerTemps.insert(stmt.addr->tempId());
                        // Also check children of addr for temps used as base pointers
                        for (auto &k : stmt.addr->kids)
                            if (k && k->op == IROp::Temp) m_pointerTemps.insert(k->tempId());
                    }
                    // Load expressions with Temp address
                    auto checkLoadPtrs = [&](const IRExpr *e) {
                        if (!e) return;
                        std::vector<const IRExpr *> stack = {e};
                        while (!stack.empty()) {
                            auto *n = stack.back(); stack.pop_back();
                            if (n->op == IROp::Load && !n->kids.empty() && n->kids[0]) {
                                auto *addr = n->kids[0].get();
                                if (addr->op == IROp::Temp)
                                    m_pointerTemps.insert(addr->tempId());
                            }
                            for (auto &k : n->kids) if (k) stack.push_back(k.get());
                        }
                    };
                    checkLoadPtrs(stmt.expr.get());
                    checkLoadPtrs(stmt.addr.get());
                }

            // Collect struct pointer types from Field expressions
            // If temp->field_X and the temp's Field has a base with typeRef, record it
            for (auto &bb : m_func.blocks)
                for (auto &stmt : bb.stmts) {
                    auto scanFieldTypes = [&](const IRExpr *e) {
                        if (!e) return;
                        std::vector<const IRExpr *> stack = {e};
                        while (!stack.empty()) {
                            auto *n = stack.back(); stack.pop_back();
                            if (n->op == IROp::Field && !n->kids.empty() && n->kids[0]) {
                                auto *base = n->kids[0].get();
                                if (base->op == IROp::Temp && base->typeRef != NullType) {
                                    m_tempStructPtr[base->tempId()] = base->typeRef;
                                }
                            }
                            for (auto &k : n->kids) if (k) stack.push_back(k.get());
                        }
                    };
                    scanFieldTypes(stmt.expr.get());
                    scanFieldTypes(stmt.addr.get());
                    for (auto &a : stmt.args) scanFieldTypes(a.get());
                }

            // Force-declare temps used in fallback (goto target) blocks
            for (int bbId : m_gotoTargets) {
                if (emittedBlocks.count(bbId)) continue;
                if (bbId < 0 || bbId >= (int)m_func.blocks.size()) continue;
                for (auto &stmt : m_func.blocks[bbId].stmts)
                    forceDeclareTempRefs(stmt);
            }

            // Declare temps that are used more than once (or used in fallback blocks)
            // Use coalesced variable names and inferred types where available
            std::set<int> declaredVarIds; // track which coalesced var IDs we've declared
            for (auto &[id, type] : m_func.tempTypes) {
                if (m_tempUseCount[id] > 1 && !m_copyPropagated.count(id)) {
                    std::string tname = tempName(id);
                    // Skip if this coalesced variable was already declared
                    auto vit = m_func.tempToVar.find(id);
                    if (vit != m_func.tempToVar.end()) {
                        if (declaredVarIds.count(vit->second)) continue;
                        declaredVarIds.insert(vit->second);
                    }
                    if (declared.count(tname) || paramNames.count(tname)) continue;
                    // Use coalesced var type, then tempTypes, then inferred
                    std::string ttype;
                    TypeRef resolvedType = NullType;
                    if (vit != m_func.tempToVar.end()) {
                        auto vtit = m_func.varTypes.find(vit->second);
                        if (vtit != m_func.varTypes.end() && vtit->second != NullType)
                            resolvedType = vtit->second;
                    }
                    if (resolvedType == NullType && type != NullType)
                        resolvedType = type;
                    if (resolvedType != NullType) {
                        auto *rt = m_types.resolveType(resolvedType);
                        // Array types decay to pointers when assigned to temps
                        if (rt && rt->kind == StabsTypeKind::Array)
                            ttype = m_types.formatType(rt->targetType) + " *";
                        // Union/struct by value for a temp → use int
                        // (temps should never hold struct values; the type is from inference leakage)
                        else if (rt && (rt->kind == StabsTypeKind::Union ||
                                        rt->kind == StabsTypeKind::Struct))
                            ttype = "int";
                        else {
                            ttype = m_types.formatType(resolvedType);
                            // Also check formatted name for cross-CU conflicts
                            if (ttype.find("union ") == 0 || ttype.find("struct ") == 0)
                                ttype = "int";
                        }
                    }
                    if (ttype.empty())
                        ttype = inferTempType(id);
                    // If type is a pointer but the temp is used in multiplication,
                    // it's actually a scalar value (not a pointer)
                    if (ttype.find("*") != std::string::npos && ttype.find("char *") == std::string::npos && ttype.find("const") == std::string::npos) {
                        // Collect all temps in this coalesced group
                        std::set<int> groupTemps;
                        if (vit != m_func.tempToVar.end()) {
                            int vid = vit->second;
                            for (auto &[t2, v2] : m_func.tempToVar)
                                if (v2 == vid) groupTemps.insert(t2);
                        }
                        groupTemps.insert(id);
                        bool usedInMul = false;
                        std::function<bool(const IRExpr*, int)> hasMulChild;
                        hasMulChild = [&](const IRExpr *e, int depth) -> bool {
                            if (!e || depth > 5) return false;
                            if (e->op == IROp::Mul || e->op == IROp::SDiv) return true;
                            // Follow through Temp definitions
                            if (e->op == IROp::Temp) {
                                auto dit = m_tempDef.find(e->tempId());
                                if (dit != m_tempDef.end() && dit->second)
                                    return hasMulChild(dit->second, depth + 1);
                            }
                            for (auto &k : e->kids) if (hasMulChild(k.get(), depth + 1)) return true;
                            return false;
                        };
                        for (auto &bb : m_func.blocks) {
                            for (auto &stmt : bb.stmts) {
                                // Check if any group temp is used as Mul operand
                                if (stmt.expr && (stmt.expr->op == IROp::Mul ||
                                    stmt.expr->op == IROp::SDiv))
                                    for (auto &k : stmt.expr->kids)
                                        if (k && k->op == IROp::Temp && groupTemps.count(k->tempId()))
                                            usedInMul = true;
                                // Check if any group temp is DEFINED by an expression containing Mul
                                if (stmt.kind == IRStmtKind::Assign && groupTemps.count(stmt.destTemp))
                                    if (hasMulChild(stmt.expr.get(), 0))
                                        usedInMul = true;
                            }
                        }
                        if (usedInMul) {
                            size_t star = ttype.find(" *");
                            if (star != std::string::npos)
                                ttype = ttype.substr(0, star);
                        }
                    }
                    // Override to struct pointer if temp is used with -> field access
                    if (ttype == "int" || ttype == "int *") {
                        auto sit = m_tempStructPtr.find(id);
                        if (sit != m_tempStructPtr.end() && sit->second != NullType)
                            ttype = m_types.formatType(sit->second);
                        else if (m_pointerTemps.count(id) && ttype == "int")
                            ttype = "char *";
                    }
                    // Strip const from temp declarations (temps are always assignable)
                    if (ttype.substr(0, 6) == "const ") ttype = ttype.substr(6);
                    out += "    " + QString::fromStdString(ttype + " " + tname) + ";\n";
                    declared.insert(tname);
                }
            }
            // Also scan for any temp references not in tempTypes
            for (auto &[id, count] : m_tempUseCount) {
                if (count <= 1 || m_copyPropagated.count(id)) continue;
                std::string tname = tempName(id);
                if (declared.count(tname) || paramNames.count(tname)) continue;
                auto vit = m_func.tempToVar.find(id);
                if (vit != m_func.tempToVar.end()) {
                    if (declaredVarIds.count(vit->second)) continue;
                    declaredVarIds.insert(vit->second);
                }
                std::string itype = inferTempType(id);
                // Override float type for vars with float/pointer conflict
                if ((itype == "float" || itype == "vec_t") && vit != m_func.tempToVar.end() &&
                    m_func.noFloatVars.count(vit->second))
                    itype = "int";
                out += "    " + QString::fromStdString(itype + " " + tname) + ";\n";
                declared.insert(tname);
            }
            // Declare synthetic stack variables (var_XX, arg_XX) not covered by STABS
            std::set<std::string> synthVars;
            for (auto &bb : m_func.blocks)
                for (auto &stmt : bb.stmts)
                    collectSynthVars(stmt, synthVars);
            for (auto &name : synthVars) {
                if (declared.count(name) || paramNames.count(name)) continue;
                declared.insert(name);
                out += "    int " + QString::fromStdString(name) + ";\n";
            }
            if (!declared.empty()) out += "\n";

            // Emit structured body into a temporary buffer, then check for leaked temps
            QString bodyOut;
            emitNode(bodyOut, root, 1);

            // Also emit fallback blocks into the body buffer
            // so leaked temps from gotos are captured too
            for (int bbId : m_gotoTargets) {
                if (emittedBlocks.count(bbId)) continue;
                if (bbId < 0 || bbId >= (int)m_func.blocks.size()) continue;
                auto &bb = m_func.blocks[bbId];
                if (!m_emittedLabels.count(bbId)) {
                    m_emittedLabels.insert(bbId);
                    bodyOut += QString("bb_%1:\n").arg(bbId);
                }
                for (int i = 0; i < (int)bb.stmts.size(); ++i) {
                    auto &s = bb.stmts[i];
                    if (i == (int)bb.stmts.size() - 1 &&
                        (s.kind == IRStmtKind::Branch || s.kind == IRStmtKind::Jump))
                        continue;
                    emitStmt(bodyOut, s, 1);
                }
            }

            // Declare any temps that leaked during emission (phi temps, raw tN names)
            for (int id : m_forceDeclareTemps) {
                // Use coalesced name if available
                std::string tname;
                auto vit = m_func.tempToVar.find(id);
                if (vit != m_func.tempToVar.end()) {
                    if (declaredVarIds.count(vit->second)) continue;
                    declaredVarIds.insert(vit->second);
                    auto nit = m_func.varNames.find(vit->second);
                    if (nit != m_func.varNames.end() && !nit->second.empty())
                        tname = nit->second;
                }
                if (tname.empty())
                    tname = "t" + std::to_string(id);
                if (declared.count(tname)) continue;
                declared.insert(tname);
                std::string itype = inferTempType(id);
                // Override float type for vars with float/pointer conflict
                if ((itype == "float" || itype == "vec_t") && vit != m_func.tempToVar.end() &&
                    m_func.noFloatVars.count(vit->second))
                    itype = "int";
                out += "    " + QString::fromStdString(itype + " " + tname) + ";\n";
            }
            if (!m_forceDeclareTemps.empty()) out += "\n";

            out += bodyOut;
            out += "}\n";
            return out;
        }

    private:
        const MachOFile      &m_mf;
        IRFunc               &m_func;
        const StabsTypeTable &m_types;
        std::map<int, int>    m_tempUseCount;
        std::map<int, IRExpr*> m_tempDef;
        std::set<int>         m_copyPropagated; // temps eliminated by copy prop
        // Copy prop: temp → replacement name
        std::map<int, std::string> m_copyMap;
        // Const prop: temp → constant value
        std::map<int, int64_t> m_constMap;
        std::set<int>         m_gotoTargets;    // block IDs that are goto targets
        std::set<int>         m_emittedLabels;  // labels already emitted (avoid duplicates)
        std::set<std::pair<int,int>> m_suppressedStmts; // (blockId, stmtIdx) to skip in emission
        std::set<int>         m_pointerTemps;   // temps used as pointers (dereference targets)
        std::map<int, TypeRef> m_tempStructPtr;   // temp → struct pointer type (from Field access)
        std::set<int>         m_forceDeclareTemps; // temps that leak as raw tN and need declaration
        std::set<int>         m_inliningTemps;    // cycle guard for temp inlining in emitExpr
        int                   m_addrDepth = 0;     // >0 when emitting Load/Store address sub-exprs
        std::set<int>         m_loadAddrTemps;    // temps used in Load address expressions

        // Force temps with cross-block def/use to be declared (not inlined)
        void forceDeclCrossBlockTemps() {
            // Build: temp → defining block id
            std::map<int, int> defBlock;
            for (auto &bb : m_func.blocks)
                for (auto &stmt : bb.stmts)
                    if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0)
                        defBlock[stmt.destTemp] = bb.id;
            // Single pass: flag temps used in a different block than their definition
            std::set<int> crossBlock;
            for (auto &bb : m_func.blocks)
                for (auto &stmt : bb.stmts) {
                    auto checkExpr = [&](const IRExpr *e) {
                        if (!e) return;
                        // Flat iteration to avoid deep recursion overhead
                        std::vector<const IRExpr *> stack = {e};
                        while (!stack.empty()) {
                            auto *n = stack.back(); stack.pop_back();
                            if (n->op == IROp::Temp) {
                                int tid = n->tempId();
                                auto it = defBlock.find(tid);
                                if (it != defBlock.end() && it->second != bb.id)
                                    crossBlock.insert(tid);
                            }
                            for (auto &k : n->kids) if (k) stack.push_back(k.get());
                        }
                    };
                    checkExpr(stmt.expr.get());
                    checkExpr(stmt.addr.get());
                    for (auto &a : stmt.args) checkExpr(a.get());
                }
            for (int tid : crossBlock)
                m_tempUseCount[tid] = std::max(m_tempUseCount[tid], 2);
        }
        void collectTempIds(const IRExpr *e, std::set<int> &ids) {
            if (!e) return;
            if (e->op == IROp::Temp) ids.insert(e->tempId());
            for (auto &k : e->kids) collectTempIds(k.get(), ids);
        }

        // Copy propagation: replace temps that are simple copies of vars/other temps
        void runCopyPropagation() {
            // Find temps used in Load address expressions — don't const-propagate these
            // (propagating 0 into a Load address resolves to BSS value instead of runtime)
            std::set<int> usedInLoadAddr;
            for (auto &bb : m_func.blocks)
                for (auto &stmt : bb.stmts) {
                    auto scanLoads = [&](const IRExpr *e) {
                        if (!e) return;
                        std::vector<const IRExpr*> stk = {e};
                        while (!stk.empty()) {
                            auto *n = stk.back(); stk.pop_back();
                            if (n->op == IROp::Load && !n->kids.empty()) {
                                std::vector<const IRExpr*> as = {n->kids[0].get()};
                                while (!as.empty()) {
                                    auto *a = as.back(); as.pop_back();
                                    if (!a) continue;
                                    if (a->op == IROp::Temp) usedInLoadAddr.insert(a->tempId());
                                    for (auto &k : a->kids) if (k) as.push_back(k.get());
                                }
                            }
                            for (auto &k : n->kids) if (k) stk.push_back(k.get());
                        }
                    };
                    scanLoads(stmt.expr.get());
                    scanLoads(stmt.addr.get());
                    for (auto &a : stmt.args) scanLoads(a.get());
                }
            // Transitively expand: if t_x is in usedInLoadAddr and t_x = op(t_y, ...),
            // then t_y is also in usedInLoadAddr
            {
                bool changed = true;
                for (int iter = 0; iter < 5 && changed; ++iter) {
                    changed = false;
                    for (auto &bb : m_func.blocks)
                        for (auto &stmt : bb.stmts) {
                            if (stmt.kind != IRStmtKind::Assign || stmt.destTemp < 0) continue;
                            if (!usedInLoadAddr.count(stmt.destTemp)) continue;
                            if (!stmt.expr) continue;
                            // Mark all Temp children as load-addr temps
                            std::vector<const IRExpr*> stk = {stmt.expr.get()};
                            while (!stk.empty()) {
                                auto *n = stk.back(); stk.pop_back();
                                if (!n) continue;
                                if (n->op == IROp::Temp && !usedInLoadAddr.count(n->tempId())) {
                                    usedInLoadAddr.insert(n->tempId());
                                    changed = true;
                                }
                                for (auto &k : n->kids) if (k) stk.push_back(k.get());
                            }
                        }
                }
            }
            m_loadAddrTemps = usedInLoadAddr; // save for use in emitExpr
            // Also find temps with non-constant assignments (loop-updated)
            std::set<int> hasNonConstAssign;
            for (auto &bb : m_func.blocks)
                for (auto &stmt : bb.stmts)
                    if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0 &&
                        stmt.expr && !stmt.expr->isConst())
                        hasNonConstAssign.insert(stmt.destTemp);

            for (auto &bb : m_func.blocks) {
                for (auto &stmt : bb.stmts) {
                    if (stmt.kind != IRStmtKind::Assign) continue;
                    if (!stmt.expr) continue;
                    // t = var → replace all uses of t with var
                    // BUT skip phi temps (they have loop-updated values too)
                    if (stmt.expr->op == IROp::Var &&
                        !m_func.phiTemps.count(stmt.destTemp)) {
                        m_copyMap[stmt.destTemp] = stmt.expr->name;
                        m_copyPropagated.insert(stmt.destTemp);
                    }
                    // t = otherTemp → propagate temp name (but not phi temps)
                    if (stmt.expr->op == IROp::Temp &&
                        !m_func.phiTemps.count(stmt.destTemp)) {
                        int srcId = stmt.expr->tempId();
                        auto sit = m_copyMap.find(srcId);
                        if (sit != m_copyMap.end()) {
                            m_copyMap[stmt.destTemp] = sit->second;
                            m_copyPropagated.insert(stmt.destTemp);
                        }
                    }
                    // t = const → propagate constant
                    // Skip if: temp is also assigned non-constant (loop phi)
                    if (stmt.expr->op == IROp::Const) {
                        if (!hasNonConstAssign.count(stmt.destTemp)) {
                            m_constMap[stmt.destTemp] = stmt.expr->value;
                            m_copyPropagated.insert(stmt.destTemp);
                        }
                    }
                }
            }
            // Pass 2: rewrite all Temp refs in all expressions
            // Skip phi temp assignments (don't const-prop inside their definitions)
            if (!m_copyMap.empty() || !m_constMap.empty()) {
                for (auto &bb : m_func.blocks)
                    for (auto &stmt : bb.stmts) {
                        if (stmt.kind == IRStmtKind::Assign &&
                            m_func.phiTemps.count(stmt.destTemp))
                            continue; // preserve phi temp definitions
                        propagateInExpr(stmt.expr);
                        propagateInExpr(stmt.addr);
                        for (auto &a : stmt.args) propagateInExpr(a);
                    }
            }
        }

        void propagateInExpr(std::unique_ptr<IRExpr> &e) {
            if (!e) return;
            if (e->op == IROp::Temp) {
                // Constant propagation: t = const → replace with const
                auto cit = m_constMap.find(e->tempId());
                if (cit != m_constMap.end()) {
                    TypeRef t = e->typeRef;
                    if (t == NullType) t = m_func.tempType(e->tempId());
                    e = IRExpr::mkConst(cit->second, t);
                    return;
                }
                auto it = m_copyMap.find(e->tempId());
                if (it != m_copyMap.end()) {
                    // Preserve the best available type: prefer expr annotation, then tempTypes
                    TypeRef t = e->typeRef;
                    if (t == NullType) t = m_func.tempType(e->tempId());
                    e = IRExpr::mkVar(it->second, t);
                    return;
                }
            }
            for (auto &k : e->kids) propagateInExpr(k);
        }

        void countTempUses(IRStmt &stmt) {
            if (stmt.expr) countInExpr(stmt.expr.get());
            if (stmt.addr) countInExpr(stmt.addr.get());
            for (auto &a : stmt.args) countInExpr(a.get());
            if (stmt.kind == IRStmtKind::Assign) {
                m_tempDef[stmt.destTemp] = stmt.expr.get();
            }
        }

        void countInExpr(IRExpr *e) {
            if (!e) return;
            if (e->op == IROp::Temp) m_tempUseCount[e->tempId()]++;
            for (auto &k : e->kids) countInExpr(k.get());
        }

        QString pad(int indent) { return QString(indent * 4, ' '); }

        // Find synthetic variable names (var_XX, arg_XX) used in IR
        void collectSynthVars(const IRStmt &stmt, std::set<std::string> &vars) {
            collectSynthVarsExpr(stmt.expr.get(), vars);
            collectSynthVarsExpr(stmt.addr.get(), vars);
            for (auto &a : stmt.args) collectSynthVarsExpr(a.get(), vars);
            if (stmt.kind == IRStmtKind::VarSet &&
                (stmt.destVar.find("var_") == 0 || stmt.destVar.find("arg_") == 0))
                vars.insert(stmt.destVar);
        }
        bool tempUsedInStmt(const IRStmt &stmt, int tempId) const {
            if (tempUsedInExpr(stmt.expr.get(), tempId)) return true;
            if (tempUsedInExpr(stmt.addr.get(), tempId)) return true;
            for (auto &a : stmt.args)
                if (tempUsedInExpr(a.get(), tempId)) return true;
            return false;
        }
        bool tempUsedInExpr(const IRExpr *e, int tempId) const {
            if (!e) return false;
            if (e->op == IROp::Temp && e->tempId() == tempId) return true;
            for (auto &k : e->kids)
                if (tempUsedInExpr(k.get(), tempId)) return true;
            return false;
        }

        void forceDeclareTempRefs(IRStmt &stmt) {
            forceDeclareExpr(stmt.expr.get());
            forceDeclareExpr(stmt.addr.get());
            for (auto &a : stmt.args) forceDeclareExpr(a.get());
            // Also force the dest temp to be declared
            if (stmt.kind == IRStmtKind::Assign)
                m_tempUseCount[stmt.destTemp] = std::max(m_tempUseCount[stmt.destTemp], 2);
        }
        void forceDeclareExpr(IRExpr *e) {
            if (!e) return;
            if (e->op == IROp::Temp)
                m_tempUseCount[e->tempId()] = std::max(m_tempUseCount[e->tempId()], 2);
            for (auto &k : e->kids) forceDeclareExpr(k.get());
        }

        void collectSynthVarsExpr(const IRExpr *e, std::set<std::string> &vars) {
            if (!e) return;
            if (e->op == IROp::Var &&
                (e->name.find("var_") == 0 || e->name.find("arg_") == 0))
                vars.insert(e->name);
            for (auto &k : e->kids) collectSynthVarsExpr(k.get(), vars);
        }

        // Check if a struct node produces any actual output
        bool nodeHasContent(StructNode *node) {
            if (!node) return false;
            if (node->kind == StructKind::Seq) {
                if (node->bbId < 0 || node->bbId >= (int)m_func.blocks.size()) return false;
                auto &bb = m_func.blocks[node->bbId];
                for (int i = node->stmtStart; i < node->stmtEnd && i < (int)bb.stmts.size(); ++i) {
                    if (m_suppressedStmts.count({node->bbId, i})) continue;
                    auto k = bb.stmts[i].kind;
                    // Skip terminal branch/jump, phi nodes, and suppressed assigns
                    if (k == IRStmtKind::Branch || k == IRStmtKind::Jump ||
                        k == IRStmtKind::Label || k == IRStmtKind::Phi)
                        continue;
                    if (k == IRStmtKind::Assign && m_tempUseCount[bb.stmts[i].destTemp] <= 1 &&
                        !(bb.stmts[i].expr && bb.stmts[i].expr->op == IROp::Call))
                        continue; // would be inlined, not emitted
                    return true;
                }
                return false;
            }
            if (node->kind == StructKind::Block) {
                for (auto &c : node->children)
                    if (nodeHasContent(c.get())) return true;
                return false;
            }
            // All other kinds (If, While, Goto, Return, etc.) produce content
            return true;
        }
        bool nodeHasContent(const std::vector<std::unique_ptr<StructNode>> &children) {
            for (auto &c : children)
                if (nodeHasContent(c.get())) return true;
            return false;
        }

        // Evaluate a condition expression to a known constant (0=false, 1=true, -1=unknown)
        int evalConstCond(IRExpr *cond, bool negated) {
            if (!cond) return -1;
            // Constant value
            if (cond->isConst()) {
                bool val = (cond->value != 0);
                return (val != negated) ? 1 : 0;
            }
            // Comparison of two constants
            if (cond->kids.size() == 2 && cond->kids[0] && cond->kids[1] &&
                cond->kids[0]->isConst() && cond->kids[1]->isConst()) {
                int64_t a = cond->kids[0]->value, b = cond->kids[1]->value;
                bool val = false;
                switch (cond->op) {
                case IROp::Eq:  val = (a == b); break;
                case IROp::Ne:  val = (a != b); break;
                case IROp::Slt: case IROp::Ult: val = (a < b); break;
                case IROp::Sle: case IROp::Ule: val = (a <= b); break;
                case IROp::Sgt: case IROp::Ugt: val = (a > b); break;
                case IROp::Sge: case IROp::Uge: val = (a >= b); break;
                default: return -1;
                }
                return (val != negated) ? 1 : 0;
            }
            return -1; // unknown
        }

        void collectGotoTargets(StructNode *node, std::set<int> &targets) {
            if (!node) return;
            if (node->kind == StructKind::Goto) targets.insert(node->gotoTarget);
            for (auto &c : node->children) collectGotoTargets(c.get(), targets);
            if (node->elseNode) collectGotoTargets(node->elseNode.get(), targets);
        }

        void collectEmittedBlocks(StructNode *node, std::set<int> &blocks) {
            if (!node) return;
            if (node->kind == StructKind::Seq && node->bbId >= 0) blocks.insert(node->bbId);
            for (auto &c : node->children) collectEmittedBlocks(c.get(), blocks);
            if (node->elseNode) collectEmittedBlocks(node->elseNode.get(), blocks);
        }

        void emitNode(QString &out, StructNode *node, int indent) {
            if (!node) return;

            switch (node->kind) {
            case StructKind::Block:
                for (auto &child : node->children)
                    emitNode(out, child.get(), indent);
                break;

            case StructKind::Seq:
                emitBlockStmts(out, node->bbId, node->stmtStart, node->stmtEnd, indent);
                break;

            case StructKind::If: {
                // Skip empty if blocks with no else
                bool hasBody = nodeHasContent(node->children);
                bool hasElse = node->elseNode && nodeHasContent(node->elseNode.get());
                if (!hasBody && !hasElse) break;
                // Evaluate constant conditions
                if (node->cond) {
                    int constResult = evalConstCond(node->cond, node->negated);
                    if (constResult == 0) {
                        // Always false — emit else body only (if any)
                        if (hasElse) {
                            for (auto &child : node->elseNode->children)
                                emitNode(out, child.get(), indent);
                        }
                        break;
                    }
                    if (constResult == 1) {
                        // Always true — emit body without if wrapper
                        if (hasBody) {
                            for (auto &child : node->children)
                                emitNode(out, child.get(), indent);
                        }
                        break;
                    }
                }
                // If body is empty but else exists, invert the condition
                if (!hasBody && hasElse) {
                    std::string cond = node->cond ? emitExpr(node->cond, !node->negated) : "1";
                    out += pad(indent) + "if (" + QString::fromStdString(cond) + ") {\n";
                    emitNode(out, node->elseNode.get(), indent + 1);
                    out += pad(indent) + "}\n";
                    break;
                }
                std::string cond = node->cond ? emitExpr(node->cond, node->negated) : "1";
                // String-level constant folding for emitted conditions
                bool condTrue = (cond == "1" || cond == "0 == 0" || cond == "0 != 1");
                bool condFalse = (cond == "0" || cond == "0 != 0" || cond == "0 == 1" || cond == "1 == 0");
                // Also check "N == M" patterns where N != M
                if (!condTrue && !condFalse && cond.find(" == ") != std::string::npos) {
                    // Simple: if both sides are numeric and different, it's false
                    auto eqPos = cond.find(" == ");
                    std::string lhs = cond.substr(0, eqPos), rhs = cond.substr(eqPos + 4);
                    char *endL, *endR;
                    long lv = strtol(lhs.c_str(), &endL, 0);
                    long rv = strtol(rhs.c_str(), &endR, 0);
                    if (*endL == '\0' && *endR == '\0') condFalse = (lv != rv);
                    if (*endL == '\0' && *endR == '\0') condTrue = (lv == rv);
                }
                if (condFalse && !hasElse) break; // if(false) with no else — skip
                if (condFalse && hasElse) {
                    emitNode(out, node->elseNode.get(), indent); break;
                }
                if (condTrue && !hasElse) {
                    for (auto &child : node->children) emitNode(out, child.get(), indent);
                    break;
                }
                if (condTrue && hasElse) {
                    for (auto &child : node->children) emitNode(out, child.get(), indent);
                    break;
                }
                // When the condition was negated by the structurer (the if-body
                // corresponds to the original's fall-through/likely path),
                // add __builtin_expect to preserve the original branch direction.
                // Only for simple conditions (pointer != 0, func() != 0, etc.)
                // to avoid changing complex control flow unnecessarily.
                if (node->negated && !hasElse && !condTrue && !condFalse) {
                    // Only add for simple integer zero-check conditions
                    // (not float comparisons like "x == 0.0f")
                    bool isSimpleZeroCheck = false;
                    for (auto &sfx : {" != 0", " == 0", " > 0", " <= 0"}) {
                        size_t len = strlen(sfx);
                        if (cond.size() >= len &&
                            cond.compare(cond.size() - len, len, sfx) == 0) {
                            isSimpleZeroCheck = true; break;
                        }
                    }
                    if (isSimpleZeroCheck)
                        cond = "__builtin_expect(" + cond + ", 1)";
                }
                out += pad(indent) + "if (" + QString::fromStdString(cond) + ") {\n";
                for (auto &child : node->children)
                    emitNode(out, child.get(), indent + 1);
                if (hasElse) {
                    out += pad(indent) + "} else {\n";
                    emitNode(out, node->elseNode.get(), indent + 1);
                }
                out += pad(indent) + "}\n";
                break;
            }

            case StructKind::While: {
                // Evaluate constant while conditions
                if (node->cond) {
                    int cv = evalConstCond(node->cond, node->negated);
                    if (cv == 0) break; // while(false) — dead loop, skip entirely
                }
                std::string cond = node->cond ? emitExpr(node->cond, node->negated) : "1";
                // Simplify constant while conditions
                if (cond == "0 == 0" || cond == "1 == 1" || cond == "0 != 1" ||
                    cond == "1" || cond == "(1)") cond = "1";
                // Dead while loops: while(false)
                if (cond == "0 != 0" || cond == "0 == 1" || cond == "1 == 0" ||
                    cond == "0" || cond == "(0)") break;
                out += pad(indent) + "while (" + QString::fromStdString(cond) + ") {\n";
                for (auto &child : node->children)
                    emitNode(out, child.get(), indent + 1);
                out += pad(indent) + "}\n";
                break;
            }

            case StructKind::For: {
                std::string cond = node->cond ? emitExpr(node->cond, node->negated) : "1";
                // Emit init expression
                std::string init;
                if (node->forInitBB >= 0 && node->forInitBB < (int)m_func.blocks.size() &&
                    node->forInitStmt >= 0) {
                    auto &s = m_func.blocks[node->forInitBB].stmts[node->forInitStmt];
                    if (s.kind == IRStmtKind::VarSet)
                        init = s.destVar + " = " + (s.expr ? emitExpr(s.expr.get()) : "0");
                    else if (s.kind == IRStmtKind::Assign)
                        init = tempName(s.destTemp) + " = " + (s.expr ? emitExpr(s.expr.get()) : "0");
                }
                // Emit increment expression
                std::string incr;
                if (node->forIncrBB >= 0 && node->forIncrBB < (int)m_func.blocks.size() &&
                    node->forIncrStmt >= 0) {
                    auto &s = m_func.blocks[node->forIncrBB].stmts[node->forIncrStmt];
                    std::string varName;
                    if (s.kind == IRStmtKind::VarSet) varName = s.destVar;
                    else if (s.kind == IRStmtKind::Assign) varName = tempName(s.destTemp);
                    if (!varName.empty()) {
                        // Simplify "i = i + 1" → "i++"
                        if (s.expr && s.expr->op == IROp::Add && s.expr->kids.size() == 2 &&
                            s.expr->kids[1]->isConst() && s.expr->kids[1]->value == 1)
                            incr = varName + "++";
                        else if (s.expr && s.expr->op == IROp::Sub && s.expr->kids.size() == 2 &&
                                 s.expr->kids[1]->isConst() && s.expr->kids[1]->value == 1)
                            incr = varName + "--";
                        else {
                            std::string val = s.expr ? emitExpr(s.expr.get()) : "0";
                            incr = varName + " = " + val;
                        }
                    }
                }
                // Suppress init and increment stmts from being emitted in body
                if (node->forInitBB >= 0 && node->forInitStmt >= 0)
                    m_suppressedStmts.insert({node->forInitBB, node->forInitStmt});
                if (node->forIncrBB >= 0 && node->forIncrStmt >= 0)
                    m_suppressedStmts.insert({node->forIncrBB, node->forIncrStmt});
                out += pad(indent) + "for (" + QString::fromStdString(init) + "; " +
                       QString::fromStdString(cond) + "; " +
                       QString::fromStdString(incr) + ") {\n";
                for (auto &child : node->children)
                    emitNode(out, child.get(), indent + 1);
                out += pad(indent) + "}\n";
                break;
            }

            case StructKind::DoWhile: {
                out += pad(indent) + "do {\n";
                for (auto &child : node->children)
                    emitNode(out, child.get(), indent + 1);
                std::string cond = node->cond ? emitExpr(node->cond, node->negated) : "1";
                out += pad(indent) + "} while (" + QString::fromStdString(cond) + ");\n";
                break;
            }

            case StructKind::Goto: {
                int gt = node->gotoTarget;
                // Optimize: if target block is empty or has only a return, inline it
                if (gt >= 0 && gt < (int)m_func.blocks.size()) {
                    auto &tbb = m_func.blocks[gt];
                    // Empty block → skip goto entirely
                    bool allEmpty = true;
                    IRStmt *retStmt = nullptr;
                    for (auto &s : tbb.stmts) {
                        if (s.kind == IRStmtKind::Return) { retStmt = &s; break; }
                        if (s.kind != IRStmtKind::Jump && s.kind != IRStmtKind::Branch &&
                            s.kind != IRStmtKind::Label) {
                            // Check if this is a suppressed assign
                            if (s.kind == IRStmtKind::Assign && m_tempUseCount[s.destTemp] <= 1 &&
                                !(s.expr && s.expr->op == IROp::Call))
                                continue;
                            allEmpty = false; break;
                        }
                    }
                    if (retStmt) {
                        // Inline the return (label stays for other gotos to same target)
                        emitStmt(out, *retStmt, indent);
                        break;
                    }
                    if (allEmpty) break; // skip goto to empty block
                }
                out += pad(indent) + QString("goto bb_%1;\n").arg(gt);
                break;
            }

            case StructKind::Break:
                out += pad(indent) + "break;\n";
                break;

            case StructKind::Continue:
                out += pad(indent) + "continue;\n";
                break;

            default:
                break;
            }
        }

        // ── Emit IR statements from a basic block range ─────────────
        void emitBlockStmts(QString &out, int bbId, int start, int end, int indent) {
            if (bbId < 0 || bbId >= (int)m_func.blocks.size()) return;
            // Emit label if this block is a goto target (track to avoid duplicates)
            if (start == 0 && m_gotoTargets.count(bbId) && !m_emittedLabels.count(bbId)) {
                m_emittedLabels.insert(bbId);
                out += QString("bb_%1:\n").arg(bbId);
            }
            auto &bb = m_func.blocks[bbId];
            for (int i = start; i < end && i < (int)bb.stmts.size(); ++i) {
                if (m_suppressedStmts.count({bbId, i})) continue;
                emitStmt(out, bb.stmts[i], indent);
            }
        }

        void emitStmt(QString &out, IRStmt &stmt, int indent) {
            switch (stmt.kind) {
            case IRStmtKind::Assign: {
                std::string rhs = stmt.expr ? emitExpr(stmt.expr.get()) : "0";
                // Skip assignment for inlined temps — BUT keep calls with truly unused results
                if (m_tempUseCount[stmt.destTemp] <= 1) {
                    if (stmt.expr && stmt.expr->op == IROp::Call &&
                        m_tempUseCount[stmt.destTemp] == 0) {
                        // Return value truly unused — emit as standalone call
                        out += pad(indent) + QString::fromStdString(rhs) + ";\n";
                    }
                    return;
                }
                if (m_copyPropagated.count(stmt.destTemp)) return;
                std::string lhs = tempName(stmt.destTemp);
                // Skip self-assignment (v = v) and trivial alias (v = param)
                if (lhs == rhs) return;
                out += pad(indent) + QString::fromStdString(lhs + " = " + rhs) + ";\n";
                break;
            }
            case IRStmtKind::Store: {
                std::string val = stmt.expr ? emitExpr(stmt.expr.get()) : "0";
                if (!stmt.addr) break;
                auto *a = stmt.addr.get();
                struct AddrGuard { int &d; AddrGuard(int &d):d(d){d++;} ~AddrGuard(){d--;} } _ag(m_addrDepth);
                std::string storeCast = "int";
                if (stmt.storeSize == 1) storeCast = "char";
                else if (stmt.storeSize == 2) storeCast = "short";
                // Field expression → base->field = val
                if (a->op == IROp::Field) {
                    out += pad(indent) + QString::fromStdString(emitExpr(a) + " = " + val) + ";\n";
                }
                // Add(base, const) → base->field_XX = val or base[N] = val for scalar ptrs
                else if (a->op == IROp::Add && a->kids.size() == 2 &&
                         a->kids[1]->isConst() && a->kids[1]->value > 0 &&
                         a->kids[1]->value < 0x10000 &&
                         (a->kids[0]->op == IROp::Var || a->kids[0]->op == IROp::Temp)) {
                    std::string base = emitExpr(a->kids[0].get());
                    int off = (int)a->kids[1]->value;
                    // Check for scalar pointer types → use array notation
                    bool usedArrayNotation = false;
                    {
                        TypeRef baseType = exprType(a->kids[0].get());
                        // Try resolving from var/temp names back to params/locals
                        if (baseType == NullType) {
                            std::string baseName;
                            if (a->kids[0]->op == IROp::Var) baseName = a->kids[0]->name;
                            else if (a->kids[0]->op == IROp::Temp) {
                                auto vit = m_func.tempToVar.find(a->kids[0]->tempId());
                                if (vit != m_func.tempToVar.end()) {
                                    auto nit = m_func.varNames.find(vit->second);
                                    if (nit != m_func.varNames.end()) baseName = nit->second;
                                }
                            }
                            if (!baseName.empty()) {
                                for (auto &p : m_func.params)
                                    if (p.name == baseName && p.typeRef != NullType)
                                        { baseType = p.typeRef; break; }
                                if (baseType == NullType)
                                    for (auto &l : m_func.locals)
                                        if (l.name == baseName && l.typeRef != NullType)
                                            { baseType = l.typeRef; break; }
                            }
                        }
                        if (baseType != NullType) {
                            auto *bt = m_types.resolveType(baseType);
                            if (bt && bt->kind == StabsTypeKind::Pointer) {
                                auto *target = m_types.resolveType(bt->targetType);
                                if (target && target->sizeBytes > 0 && target->sizeBytes <= 8 &&
                                    target->kind != StabsTypeKind::Struct &&
                                    target->kind != StabsTypeKind::Union &&
                                    target->kind != StabsTypeKind::Array &&
                                    target->kind != StabsTypeKind::ForwardRef) {
                                    int elemSize = target->sizeBytes;
                                    int idx = off / elemSize;
                                    if (idx * elemSize == off && idx >= 0) {
                                        out += pad(indent) + QString::fromStdString(
                                            base + "[" + std::to_string(idx) + "] = " + val) + ";\n";
                                        usedArrayNotation = true;
                                    }
                                }
                            }
                        }
                    }
                    if (!usedArrayNotation) {
                        // Try type-aware struct field access
                        TypeRef stBaseType = exprType(a->kids[0].get());
                        std::string access;
                        if (stBaseType != NullType && m_types.isStructPointer(stBaseType)) {
                            TypeRef structRef = m_types.getPointedStruct(stBaseType);
                            if (structRef != NullType)
                                access = m_types.formatFieldAccess(structRef, off);
                        }
                        if (!access.empty()) {
                            out += pad(indent) + QString::fromStdString(
                                base + "->" + access + " = " + val) + ";\n";
                        } else {
                            char buf[128];
                            snprintf(buf, sizeof(buf), "*(%s *)((char *)%s + 0x%X) = %s",
                                     storeCast.c_str(), base.c_str(), (unsigned)off, val.c_str());
                            out += pad(indent) + QString::fromStdString(buf) + ";\n";
                        }
                    }
                }
                // Add(base, Mul(idx, scale)) or Add(Mul(idx, scale), base) → base[idx] = val
                else if (a->op == IROp::Add && a->kids.size() == 2) {
                    IRExpr *storeBase = nullptr, *storeIdx = nullptr;
                    int storeScale = 0;
                    for (int side = 0; side < 2; ++side) {
                        auto *maybeIdx = a->kids[side].get();
                        auto *maybeBase = a->kids[1-side].get();
                        if (maybeIdx && maybeIdx->op == IROp::Mul && maybeIdx->kids.size() == 2 &&
                            maybeIdx->kids[1]->isConst() &&
                            (maybeBase->op == IROp::Var || maybeBase->op == IROp::Temp || maybeBase->op == IROp::Const)) {
                            storeBase = maybeBase;
                            storeIdx = maybeIdx->kids[0].get();
                            storeScale = (int)maybeIdx->kids[1]->value;
                            break;
                        }
                    }
                    if (storeBase && storeIdx && storeScale == 4) {
                        std::string bs = emitExpr(storeBase);
                        std::string is = emitExpr(storeIdx);
                        out += pad(indent) + QString::fromStdString(bs + "[" + is + "] = " + val) + ";\n";
                    } else if (storeBase && storeIdx) {
                        std::string bs = emitExpr(storeBase);
                        std::string is = emitExpr(storeIdx);
                        out += pad(indent) + QString::fromStdString(
                            "*(" + storeCast + " *)((char *)" + bs + " + " + is + " * " + std::to_string(storeScale) + ") = " + val) + ";\n";
                    }
                    // handled — skip remaining else-ifs
                }
                // Add(Add(base, Mul(idx, scale)), const) → base->arr_NN[idx] = val
                else if (a->op == IROp::Add && a->kids.size() == 2 &&
                         a->kids[1]->isConst() && a->kids[1]->value > 0 &&
                         a->kids[0]->op == IROp::Add && a->kids[0]->kids.size() == 2 &&
                         a->kids[0]->kids[1]->op == IROp::Mul &&
                         a->kids[0]->kids[1]->kids.size() == 2 &&
                         a->kids[0]->kids[1]->kids[1]->isConst() &&
                         (a->kids[0]->kids[0]->op == IROp::Var || a->kids[0]->kids[0]->op == IROp::Temp)) {
                    std::string base = emitExpr(a->kids[0]->kids[0].get());
                    std::string idx = emitExpr(a->kids[0]->kids[1]->kids[0].get());
                    int off = (int)a->kids[1]->value;
                    char fname[64]; snprintf(fname, sizeof(fname), "arr_%X[%s]", (unsigned)off, idx.c_str());
                    out += pad(indent) + QString::fromStdString(
                        base + "->" + fname + " = " + val) + ";\n";
                }
                // General Add/Sub expression → *(expr) = val without ugly cast
                else if ((a->op == IROp::Add || a->op == IROp::Sub) && a->kids.size() == 2) {
                    out += pad(indent) + QString::fromStdString(
                        "*(" + emitExpr(a) + ") = " + val) + ";\n";
                }
                else if (a->op == IROp::Var || a->op == IROp::Temp) {
                    // For scalar pointers (float*, int*), use base[0] = val
                    TypeRef at = exprType(a);
                    auto *atInfo = (at != NullType) ? m_types.resolveType(at) : nullptr;
                    if (atInfo && atInfo->kind == StabsTypeKind::Pointer) {
                        auto *tgt = m_types.resolveType(atInfo->targetType);
                        if (tgt && tgt->sizeBytes > 0 && tgt->sizeBytes <= 8 &&
                            tgt->kind != StabsTypeKind::Struct && tgt->kind != StabsTypeKind::Union) {
                            out += pad(indent) + QString::fromStdString(
                                emitExpr(a) + "[0] = " + val) + ";\n";
                            break;
                        }
                    }
                    std::string addr = emitExpr(a);
                    out += pad(indent) + QString::fromStdString(
                        "*(" + storeCast + " *)(" + addr + ") = " + val) + ";\n";
                } else {
                    std::string addr = emitExpr(a);
                    out += pad(indent) + QString::fromStdString(
                        "*(" + storeCast + " *)(" + addr + ") = " + val) + ";\n";
                }
                break;
            }
            case IRStmtKind::VarSet: {
                std::string val = stmt.expr ? emitExpr(stmt.expr.get()) : "0";
                std::string dest = stmt.destVar;
                // Suppress parameter slot reuse when assigning a string literal to a param
                // (clear indicator of Com_Error/Com_Printf call argument setup)
                {
                    bool isParam = false;
                    for (auto &p : m_func.params)
                        if (p.name == dest) { isParam = true; break; }
                    if (isParam && stmt.expr && stmt.expr->op == IROp::String)
                        break; // suppress string-to-param assignment
                }
                // Suppress dead stores to 'this' from register reuse
                if (dest == "this" && stmt.expr) {
                    bool bogus = false;
                    if (stmt.expr->isConst()) bogus = true;  // this = 2884
                    if (stmt.expr->op == IROp::Var && stmt.expr->name == "this") bogus = true;  // this = this
                    if (stmt.expr->op == IROp::Var && stmt.expr->name != "this") bogus = true;  // this = keys
                    if (stmt.expr->op == IROp::Add || stmt.expr->op == IROp::Sub) bogus = true;  // this = (this + 136)
                    if (stmt.expr->op == IROp::Temp) bogus = true;  // this = t7
                    if (bogus) break;
                }
                // Check if destination is an array type — use dest[0] instead
                if (stmt.destType != NullType) {
                    auto *dt = m_types.resolveType(stmt.destType);
                    if (dt && dt->kind == StabsTypeKind::Array)
                        dest += "[0]";
                    // If dest is a struct/union and value is a scalar, cast the store
                    if (dt && (dt->kind == StabsTypeKind::Struct || dt->kind == StabsTypeKind::Union)) {
                        out += pad(indent) + QString::fromStdString(
                            "*(int *)(&" + cName(dest) + ") = (int)" + val) + ";\n";
                        break;
                    }
                }
                out += pad(indent) + QString::fromStdString(cName(dest) + " = " + val) + ";\n";
                break;
            }
            case IRStmtKind::Call: {
                std::string call = stmt.expr ? emitExpr(stmt.expr.get()) : "()";
                out += pad(indent) + QString::fromStdString(call) + ";\n";
                break;
            }
            case IRStmtKind::Return: {
                if (stmt.expr) {
                    std::string val = emitExpr(stmt.expr.get());
                    out += pad(indent) + "return " + QString::fromStdString(val) + ";\n";
                } else {
                    out += pad(indent) + "return;\n";
                }
                break;
            }
            case IRStmtKind::Intrinsic: {
                // Rename tN → vN in intrinsic text using coalescing map
                std::string text = stmt.intrinsicComment;
                if (!m_func.tempToVar.empty()) {
                    for (auto &[tid, vid] : m_func.tempToVar) {
                        std::string from = "t" + std::to_string(tid);
                        std::string to = m_func.varNames.count(vid) ? m_func.varNames[vid] :
                                         "v" + std::to_string(vid);
                        size_t pos = 0;
                        while ((pos = text.find(from, pos)) != std::string::npos) {
                            // Only replace if it's a whole word (not part of a longer name)
                            size_t end = pos + from.size();
                            bool wholeWord = (pos == 0 || !isalnum(text[pos-1])) &&
                                             (end >= text.size() || !isalnum(text[end]));
                            if (wholeWord) {
                                text.replace(pos, from.size(), to);
                                pos += to.size();
                            } else {
                                pos += from.size();
                            }
                        }
                    }
                }
                out += pad(indent) + QString::fromStdString(text) + ";\n";
                break;
            }
            case IRStmtKind::Switch: {
                std::string expr;
                // Try to recover the original switch variable by looking through
                // the base subtraction: if expr is (var - base), switch on var directly
                bool simplified = false;
                if (stmt.switchBase != 0 && stmt.expr) {
                    IRExpr *inner = stmt.expr.get();
                    // Follow temp inlining
                    if (inner->op == IROp::Temp && m_tempUseCount[inner->tempId()] <= 1) {
                        auto it = m_tempDef.find(inner->tempId());
                        if (it != m_tempDef.end()) inner = it->second;
                    }
                    // Check for (var - base) pattern
                    if (inner && inner->op == IROp::Sub && inner->kids.size() == 2 &&
                        inner->kids[1]->isConst() && inner->kids[1]->value == stmt.switchBase) {
                        expr = emitExpr(inner->kids[0].get());
                        simplified = true;
                    }
                }
                if (!simplified) {
                    expr = stmt.expr ? emitExpr(stmt.expr.get()) : "0";
                    if (stmt.switchBase != 0)
                        expr = "(" + expr + " + " + std::to_string(stmt.switchBase) + ")";
                }
                out += pad(indent) + "switch (" + QString::fromStdString(expr) + ") {\n";
                // Group cases by target block and sort by block order
                std::map<int, std::vector<int>> blockCases;
                std::set<int> caseTargets;
                for (auto &[caseVal, target] : stmt.switchCases) {
                    blockCases[target].push_back(caseVal);
                    caseTargets.insert(target);
                }
                if (stmt.switchDefault >= 0) caseTargets.insert(stmt.switchDefault);

                // Determine which blocks are reachable only from this switch
                // (safe to inline vs. needing goto for shared targets)
                std::set<int> inlinedBlocks;

                // Emit cases in block order
                for (auto &[target, vals] : blockCases) {
                    std::sort(vals.begin(), vals.end());
                    for (int v : vals)
                        out += pad(indent) + QString("case %1:\n").arg(v);
                    // Inline the case body: emit statements from the target block
                    if (target >= 0 && target < (int)m_func.blocks.size()) {
                        auto &cbb = m_func.blocks[target];
                        inlinedBlocks.insert(target);
                        // Emit non-terminal statements
                        for (int si = 0; si < (int)cbb.stmts.size(); ++si) {
                            auto &s = cbb.stmts[si];
                            // Skip terminal jump/branch — we'll add break instead
                            if (si == (int)cbb.stmts.size() - 1 &&
                                (s.kind == IRStmtKind::Jump || s.kind == IRStmtKind::Branch))
                                continue;
                            if (s.kind == IRStmtKind::Return) {
                                emitStmt(out, s, indent + 1);
                                goto next_case; // return already exits, no break needed
                            }
                            emitStmt(out, s, indent + 1);
                        }
                        // Check if the block falls through to the next case target
                        // (don't emit break for fall-through)
                        if (!cbb.succs.empty() && caseTargets.count(cbb.succs[0])) {
                            // Fall through to next case — no break
                            out += pad(indent + 1) + "/* fall through */\n";
                        } else {
                            out += pad(indent + 1) + "break;\n";
                        }
                    } else {
                        out += pad(indent + 1) + "break;\n";
                    }
                    next_case:;
                }
                if (stmt.switchDefault >= 0) {
                    out += pad(indent) + "default:\n";
                    if (stmt.switchDefault >= 0 && stmt.switchDefault < (int)m_func.blocks.size()) {
                        auto &dbb = m_func.blocks[stmt.switchDefault];
                        inlinedBlocks.insert(stmt.switchDefault);
                        for (int si = 0; si < (int)dbb.stmts.size(); ++si) {
                            auto &s = dbb.stmts[si];
                            if (si == (int)dbb.stmts.size() - 1 &&
                                (s.kind == IRStmtKind::Jump || s.kind == IRStmtKind::Branch))
                                continue;
                            emitStmt(out, s, indent + 1);
                        }
                    }
                    out += pad(indent + 1) + "break;\n";
                }
                out += pad(indent) + "}\n";
                // Only add goto targets for blocks NOT inlined
                for (auto &[caseVal, target] : stmt.switchCases)
                    if (!inlinedBlocks.count(target)) m_gotoTargets.insert(target);
                if (stmt.switchDefault >= 0 && !inlinedBlocks.count(stmt.switchDefault))
                    m_gotoTargets.insert(stmt.switchDefault);
                break;
            }
            case IRStmtKind::Branch:
            case IRStmtKind::Jump:
            case IRStmtKind::Label:
            case IRStmtKind::Phi:
                // These are handled by the structured emitter / SSA, not here
                break;
            }
        }

        // ── Emit an IR expression as a C string ─────────────────────
        std::string emitExpr(IRExpr *e, bool negate = false) {
            if (!e) return "0"; // null expression fallback

            std::string result;

            switch (e->op) {
            case IROp::Const: {
                // Try enum resolution if type is known
                if (e->typeRef != NullType) {
                    std::string en = m_types.findEnumName(e->typeRef, e->value);
                    if (!en.empty()) { result = en; break; }
                }
                // Check for IEEE 754 float bit patterns for common constants
                result = tryFloatConst((uint32_t)e->value);
                // Check for FourCC constants (4 printable ASCII bytes)
                if (result.empty()) result = tryFourCC((uint32_t)e->value);
                // Try to resolve large constants as global variable/function addresses
                if (result.empty() && e->value > 0x10000) {
                    std::string sym = m_mf.symbolNameAtAddress((uint32_t)e->value);
                    if (!sym.empty()) {
                        result = cName(sym);
                    } else {
                        std::string nearest = m_mf.nearestSymbolName((uint32_t)e->value);
                        if (!nearest.empty()) result = cName(nearest);
                    }
                    // Data symbols need & (address-of) since the constant IS
                    // the address, not the value at the address.
                    // Exception: inside Load/Store address expressions, the constant
                    // is already being used as an address — no & needed.
                    // Function symbols don't need & (function names decay to pointers).
                    if (!result.empty() && m_addrDepth == 0) {
                        auto *sec = m_mf.sectionForAddress((uint32_t)e->value);
                        bool isData = sec && sec->segname != "__TEXT";
                        if (isData)
                            result = "&" + result;
                    }
                }
                if (result.empty()) {
                    // Detect sign-extended negatives: 0xFFFFFF80 → -128
                    int32_t sv = (int32_t)(uint32_t)e->value;
                    if (sv < 0 && sv >= -65536 && (uint32_t)e->value > 0x7FFFFFFF) {
                        result = std::to_string(sv);
                    } else if (e->value >= -65536 && e->value <= 65536) {
                        result = std::to_string(e->value);
                    } else {
                        char buf[32]; snprintf(buf, sizeof(buf), "0x%X", (unsigned)(uint32_t)e->value);
                        result = buf;
                    }
                }
                break;
            }
            case IROp::Temp: {
                int id = e->tempId();
                // Cycle guard: prevent infinite recursion through temp chains
                if (m_inliningTemps.count(id)) {
                    // Already inlining this temp — break the cycle
                    auto vit = m_func.tempToVar.find(id);
                    if (vit != m_func.tempToVar.end())
                        return m_func.varNames[vit->second];
                    return "t" + std::to_string(id);
                }
                // Phi temps: always use variable name (don't inline their definition
                // because it's the pre-loop value; the actual value changes per iteration)
                if (m_func.phiTemps.count(id)) {
                    // Force-declare this temp so its name is available
                    m_forceDeclareTemps.insert(id);
                    auto vit = m_func.tempToVar.find(id);
                    if (vit != m_func.tempToVar.end()) {
                        auto nit = m_func.varNames.find(vit->second);
                        if (nit != m_func.varNames.end())
                            return nit->second;
                    }
                    return tempName(id);
                }
                // Inline temps used only once
                if (m_tempUseCount[id] <= 1) {
                    auto it = m_tempDef.find(id);
                    if (it != m_tempDef.end() && it->second) {
                        m_inliningTemps.insert(id);
                        std::string inlined = emitExpr(it->second, negate);
                        m_inliningTemps.erase(id);
                        if (!inlined.empty()) return inlined;
                    }
                    // Inlining failed — emit variable name if available, else 0
                    {
                        auto vit = m_func.tempToVar.find(id);
                        if (vit != m_func.tempToVar.end()) {
                            auto nit = m_func.varNames.find(vit->second);
                            if (nit != m_func.varNames.end())
                                return nit->second;
                        }
                    }
                    return "0";
                }
                // Also inline temps used exactly twice (1 def + 1 use) when def is simple
                // BUT don't inline if the temp has a declared variable name (v2, v3 etc.)
                // — using the variable name produces better register allocation matching
                if (m_tempUseCount[id] == 2) {
                    // Check if this temp has a coalesced variable name
                    std::string varName = tempName(id);
                    bool hasVarName = (varName.size() >= 2 && varName[0] == 'v' &&
                                       varName[1] >= '0' && varName[1] <= '9');
                    if (!hasVarName) {
                        auto it = m_tempDef.find(id);
                        if (it != m_tempDef.end() && it->second) {
                            auto *def = it->second;
                            bool isSimple = (def->op == IROp::Var || def->op == IROp::Field ||
                                            def->op == IROp::Const || def->op == IROp::Load ||
                                            def->op == IROp::Call || def->op == IROp::String ||
                                            def->op == IROp::Cast);
                            if (isSimple) {
                                m_inliningTemps.insert(id);
                                std::string inlined = emitExpr(def, negate);
                                m_inliningTemps.erase(id);
                                if (!inlined.empty() && inlined != "0") return inlined;
                            }
                        }
                    }
                }
                // Use coalesced variable name if available
                result = tempName(id);
                // If we'd emit a raw "tN" name, force-declare it
                if (result.size() >= 2 && result[0] == 't' && result[1] >= '0' && result[1] <= '9') {
                    m_forceDeclareTemps.insert(id);
                }
                break;
            }
            case IROp::Var: {
                // Only sanitize names that aren't numeric literals or expressions
                std::string vn = e->name;
                if (!vn.empty() && (isdigit(vn[0]) || vn[0] == '-' || vn[0] == '"' || vn[0] == '('))
                    result = vn;
                else
                    result = cName(vn);
                // Don't add [0] here — array-typed Vars used in expressions are
                // handled by the caller (Store/Load/VarSet) or by context.
                // Adding [0] unconditionally breaks synthetic stack vars.
                break;
            }
            case IROp::String: result = e->name; break;
            case IROp::FuncRef: result = e->name; break;

            case IROp::Load: {
                auto *addr = e->kids[0].get();
                m_addrDepth++;
                // (base + index*scale + const) → base->array_NN[index] pattern
                if (addr && addr->op == IROp::Add && addr->kids.size() == 2 &&
                    addr->kids[1]->isConst() && addr->kids[1]->value > 0 &&
                    addr->kids[0]->op == IROp::Add && addr->kids[0]->kids.size() == 2) {
                    auto *inner = addr->kids[0].get();
                    // Check for (base + index*4) + const
                    bool isArray = false;
                    IRExpr *base = nullptr, *index = nullptr;
                    int elemSize = 0;
                    if (inner->kids[1]->op == IROp::Mul && inner->kids[1]->kids.size() == 2 &&
                        inner->kids[1]->kids[1]->isConst()) {
                        base = inner->kids[0].get();
                        index = inner->kids[1]->kids[0].get();
                        elemSize = (int)inner->kids[1]->kids[1]->value;
                        isArray = (elemSize > 0 && elemSize <= 256);
                    }
                    if (isArray && base && index &&
                        (base->op == IROp::Var || base->op == IROp::Temp)) {
                        std::string baseStr = emitExpr(base);
                        std::string idxStr = emitExpr(index);
                        int off = (int)addr->kids[1]->value;
                        char fname[64];
                        if (elemSize == 4)
                            snprintf(fname, sizeof(fname), "arr_%X[%s]", (unsigned)off, idxStr.c_str());
                        else
                            snprintf(fname, sizeof(fname), "arr_%X_%d[%s]", (unsigned)off, elemSize, idxStr.c_str());
                        result = baseStr + "->" + fname;
                        break;
                    }
                }
                // (base + idx*4) or (idx*4 + base) → base[idx] (only for Var/Temp base)
                if (addr && addr->op == IROp::Add && addr->kids.size() == 2) {
                    IRExpr *arrBase = nullptr, *arrIdx = nullptr;
                    for (int side = 0; side < 2; ++side) {
                        auto *maybeIdx = addr->kids[side].get();
                        auto *maybeBase = addr->kids[1-side].get();
                        if (maybeIdx->op == IROp::Mul && maybeIdx->kids.size() == 2 &&
                            maybeIdx->kids[1]->isConst() && maybeIdx->kids[1]->value == 4 &&
                            (maybeBase->op == IROp::Var || maybeBase->op == IROp::Temp || maybeBase->op == IROp::Const)) {
                            arrBase = maybeBase; arrIdx = maybeIdx->kids[0].get();
                            break;
                        }
                    }
                    if (arrBase && arrIdx) {
                        std::string bs = emitExpr(arrBase);
                        std::string is = emitExpr(arrIdx);
                        if (!bs.empty() && !is.empty()) {
                            result = bs + "[" + is + "]";
                            break;
                        }
                    }
                }
                // (base + const) → base->field for struct pointers, else *(int*)((char*)base + off)
                if (result.empty() && addr && addr->op == IROp::Add && addr->kids.size() == 2 &&
                    addr->kids[1]->isConst() &&
                    (int64_t)addr->kids[1]->value != 0 &&
                    std::abs((int64_t)addr->kids[1]->value) < 0x10000 &&
                    (addr->kids[0]->op == IROp::Var || addr->kids[0]->op == IROp::Temp)) {
                    std::string base = emitExpr(addr->kids[0].get());
                    int64_t off = (int64_t)addr->kids[1]->value;
                    // Try type-aware struct field access
                    TypeRef baseType = exprType(addr->kids[0].get());
                    if (baseType != NullType && m_types.isStructPointer(baseType)) {
                        TypeRef structRef = m_types.getPointedStruct(baseType);
                        std::string access = structRef != NullType ?
                            m_types.formatFieldAccess(structRef, (int)off) : "";
                        if (!access.empty()) {
                            result = base + "->" + access;
                        }
                    }
                    if (result.empty()) {
                        char buf[64];
                        snprintf(buf, sizeof(buf), "*(int *)((char *)%s + 0x%llX)",
                                 base.c_str(), (unsigned long long)off);
                        result = buf;
                    }
                }
                // General Add/Sub expression → *(expr) without ugly cast
                else if (addr && (addr->op == IROp::Add || addr->op == IROp::Sub) &&
                         addr->kids.size() == 2) {
                    result = "*(" + emitExpr(addr) + ")";
                }
                // bare pointer dereference of a simple var/temp → use clean *(var) syntax
                else if (addr && (addr->op == IROp::Var || addr->op == IROp::Temp)) {
                    TypeRef addrType = exprType(addr);
                    if (addrType != NullType && m_types.isStructPointer(addrType)) {
                        TypeRef structRef = m_types.getPointedStruct(addrType);
                        std::string access = structRef != NullType ?
                            m_types.formatFieldAccess(structRef, 0) : "";
                        if (!access.empty())
                            result = emitExpr(addr) + "->" + access;
                        else
                            result = "*(" + emitExpr(addr) + ")";
                    } else if (addrType != NullType) {
                        auto *at = m_types.resolveType(addrType);
                        if (at && at->kind == StabsTypeKind::Pointer) {
                            auto *tgt = m_types.resolveType(at->targetType);
                            if (tgt && tgt->sizeBytes > 0 && tgt->sizeBytes <= 8 &&
                                tgt->kind != StabsTypeKind::Struct && tgt->kind != StabsTypeKind::Union)
                                result = emitExpr(addr) + "[0]";
                            else
                                result = "*(" + emitExpr(addr) + ")";
                        } else {
                            result = "*(" + emitExpr(addr) + ")";
                        }
                    } else {
                        result = "*(" + emitExpr(addr) + ")";
                    }
                } else {
                    result = "*(" + emitExpr(addr) + ")";
                }
                // If result uses *(expr), ensure it's a valid dereference
                if (!result.empty() && result[0] == '*' && addr) {
                    // Always cast plain *(var) to *(int*)(var) to avoid void* dereference
                    // and to handle cases where the var type is unknown
                    if (addr->op == IROp::Var || addr->op == IROp::Temp) {
                        std::string addrStr = emitExpr(addr);
                        result = "*(int *)(" + addrStr + ")";
                    }
                }
                m_addrDepth--;
                break;
            }

            case IROp::AddrOf: {
                auto *inner = e->kids[0].get();
                if (inner && inner->op == IROp::Field && !inner->kids.empty()) {
                    // &(base->field_X) where field_X is synthetic = base + offset
                    if (inner->name.find("field_") == 0) {
                        std::string base = emitExpr(inner->kids[0].get());
                        int off = (int)inner->value;
                        // Strip parens from base for cleaner output
                        std::string stripped = base;
                        while (!stripped.empty() && stripped.front() == '(' && stripped.back() == ')')
                            stripped = stripped.substr(1, stripped.size() - 2);
                        if (stripped == "0") {
                            result = std::to_string(off);
                        } else {
                            result = "(" + base + " + " + std::to_string(off) + ")";
                        }
                    } else {
                        // Check if inner is a field_X on a non-pointer base
                        // → use pointer arithmetic instead of ->
                        std::string innerStr = emitExpr(inner);
                        if (innerStr.find("->field_") != std::string::npos) {
                            // Convert &(base->field_N) to (base + N)
                            std::string base2 = emitExpr(inner->kids[0].get());
                            int off2 = (int)inner->value;
                            result = "(" + base2 + " + " + std::to_string(off2) + ")";
                        } else {
                            result = "&" + innerStr;
                        }
                    }
                } else {
                    result = "&" + emitExpr(inner);
                }
                break;
            }

            case IROp::Field: {
                std::string base = emitExpr(e->kids[0].get());
                // If base is literal 0 (NULL or Temp that inlined to "0"), emit as offset constant
                // Also handle parenthesized zero: "(0)" from sub-expressions
                {
                    std::string stripped = base;
                    while (!stripped.empty() && stripped.front() == '(' && stripped.back() == ')')
                        stripped = stripped.substr(1, stripped.size() - 2);
                    if ((e->kids[0] && e->kids[0]->isConst() && e->kids[0]->value == 0) ||
                        stripped == "0") {
                        result = std::to_string((int)e->value);
                        break;
                    }
                }
                if (false) { // dead — handled above
                    result = std::to_string((int)e->value);
                    break;
                }
                // For scalar pointer types (float*, int*), use array notation
                // field_4 on float* → base[1], field_8 → base[2], etc.
                if (e->name.find("field_") == 0 && e->kids[0]) {
                    TypeRef baseType = exprType(e->kids[0].get());
                    // Try resolving from var/temp names back to params/locals
                    if (baseType == NullType) {
                        std::string baseName;
                        if (e->kids[0]->op == IROp::Var) baseName = e->kids[0]->name;
                        else if (e->kids[0]->op == IROp::Temp) {
                            auto vit = m_func.tempToVar.find(e->kids[0]->tempId());
                            if (vit != m_func.tempToVar.end()) {
                                auto nit = m_func.varNames.find(vit->second);
                                if (nit != m_func.varNames.end()) baseName = nit->second;
                            }
                        }
                        if (!baseName.empty()) {
                            for (auto &p : m_func.params)
                                if (p.name == baseName && p.typeRef != NullType)
                                    { baseType = p.typeRef; break; }
                            if (baseType == NullType)
                                for (auto &l : m_func.locals)
                                    if (l.name == baseName && l.typeRef != NullType)
                                        { baseType = l.typeRef; break; }
                        }
                    }
                    if (baseType != NullType) {
                        auto *bt = m_types.resolveType(baseType);
                        if (bt && bt->kind == StabsTypeKind::Pointer) {
                            auto *target = m_types.resolveType(bt->targetType);
                            // Scalar types: float, int, char, etc. (not struct/union/array)
                            if (target &&
                                target->kind != StabsTypeKind::Struct &&
                                target->kind != StabsTypeKind::Union &&
                                target->kind != StabsTypeKind::Array &&
                                target->kind != StabsTypeKind::ForwardRef) {
                                int elemSize = target->sizeBytes > 0 ? target->sizeBytes : 4;
                                int off = (int)e->value;
                                int idx = off / elemSize;
                                if (idx * elemSize == off && idx >= 0) {
                                    result = base + "[" + std::to_string(idx) + "]";
                                    break;
                                }
                            }
                        }
                    }
                }
                // Check if this is a synthetic field (field_XX) from an opaque/empty struct
                bool isSynthField = (e->name.find("field_") == 0);
                bool fieldValid = true;
                if (isSynthField) {
                    // Synthetic field_X: ALWAYS use cast-based access.
                    // The struct definition may not have a field at this exact offset,
                    // or the field may be at a different sub-offset within a larger field.
                    fieldValid = false;
                }
                if (isSynthField) {
                    // Synthetic field: always use cast-based pointer arithmetic
                    int off = (int)e->value;
                    result = "*(int *)((char *)(" + base + ") + " + std::to_string(off) + ")";
                } else {
                    result = base + "->" + e->name;
                }
                break;
            }

            case IROp::Neg:     result = "-" + emitExpr(e->kids[0].get()); break;
            case IROp::Not:
                // Simplify ~~x → x
                if (e->kids[0] && e->kids[0]->op == IROp::Not && !e->kids[0]->kids.empty())
                    result = emitExpr(e->kids[0]->kids[0].get(), negate);
                else
                    result = "~" + emitExpr(e->kids[0].get());
                break;
            case IROp::BoolNot: result = "!" + emitExpr(e->kids[0].get()); break;

            case IROp::Cast:
                result = emitCast(e);
                break;

            case IROp::Add: case IROp::Sub: case IROp::Mul:
            case IROp::SDiv: case IROp::UDiv: case IROp::SMod: case IROp::UMod:
            case IROp::Shl: case IROp::Shr: case IROp::Sar:
            case IROp::And: case IROp::Or: case IROp::Xor: {
                // Constant folding: evaluate at compile time if both operands are constant
                if (e->kids.size() >= 2 && e->kids[0] && e->kids[1] &&
                    e->kids[0]->isConst() && e->kids[1]->isConst()) {
                    int64_t a = e->kids[0]->value, b = e->kids[1]->value;
                    int64_t r = 0;
                    bool folded = true;
                    switch (e->op) {
                    case IROp::Add: r = a + b; break;
                    case IROp::Sub: r = a - b; break;
                    case IROp::Mul: r = a * b; break;
                    case IROp::SDiv: case IROp::UDiv: r = b ? a / b : 0; break;
                    case IROp::SMod: case IROp::UMod: r = b ? a % b : 0; break;
                    case IROp::Shl: r = a << b; break;
                    case IROp::Shr: case IROp::Sar: r = a >> b; break;
                    case IROp::And: r = a & b; break;
                    case IROp::Or:  r = a | b; break;
                    case IROp::Xor: r = a ^ b; break;
                    default: folded = false;
                    }
                    if (folded) {
                        result = tryFloatConst((uint32_t)r);
                        if (result.empty()) result = std::to_string(r);
                        break;
                    }
                }
                // Identity folding: x + 0, x * 1, x - 0, x | 0, x & -1, x ^ 0
                if (e->kids.size() >= 2 && e->kids[1] && e->kids[1]->isConst()) {
                    int64_t b = e->kids[1]->value;
                    if ((e->op == IROp::Add || e->op == IROp::Sub || e->op == IROp::Or ||
                         e->op == IROp::Xor) && b == 0) {
                        result = emitExpr(e->kids[0].get()); break;
                    }
                    if ((e->op == IROp::Mul || e->op == IROp::SDiv || e->op == IROp::UDiv) && b == 1) {
                        result = emitExpr(e->kids[0].get()); break;
                    }
                    if (e->op == IROp::Mul && b == 0) { result = "0"; break; }
                }
                if (e->kids.size() >= 2 && e->kids[0] && e->kids[0]->isConst()) {
                    int64_t a = e->kids[0]->value;
                    if ((e->op == IROp::Add || e->op == IROp::Or || e->op == IROp::Xor) && a == 0) {
                        result = emitExpr(e->kids[1].get()); break;
                    }
                    if (e->op == IROp::Mul && a == 1) {
                        result = emitExpr(e->kids[1].get()); break;
                    }
                    if (e->op == IROp::Mul && a == 0) { result = "0"; break; }
                }
                if (e->kids.size() < 2 || !e->kids[0] || !e->kids[1]) {
                    result = "0"; break;
                }
                // Try to evaluate to a simpler form: detect compiler multiply expansion
                // e.g. (x + (x + x*4) * 8) * 4 = x * 164
                std::set<int> evalMulVisited;
                std::function<std::pair<IRExpr*, int64_t>(IRExpr*)> evalMul;
                evalMul = [&](IRExpr *expr) -> std::pair<IRExpr*, int64_t> {
                    // Returns (baseVar, multiplier) if expr is baseVar * N
                    if (!expr) return {nullptr, 0};
                    // For Temp nodes: if the temp has a known definition, recurse into it
                    // so that multi-use temps don't block chain folding
                    if (expr->op == IROp::Temp) {
                        int tid = expr->tempId();
                        if (evalMulVisited.count(tid)) return {expr, 1}; // cycle guard
                        auto dit = m_tempDef.find(tid);
                        if (dit != m_tempDef.end() && dit->second) {
                            evalMulVisited.insert(tid);
                            auto [b, m] = evalMul(dit->second);
                            if (b && m != 0) return {b, m};
                        }
                        return {expr, 1};
                    }
                    if (expr->op == IROp::Var)
                        return {expr, 1};
                    if (expr->op == IROp::Mul && expr->kids.size() == 2) {
                        if (expr->kids[1]->isConst()) {
                            auto [b, m] = evalMul(expr->kids[0].get());
                            return {b, m * expr->kids[1]->value};
                        }
                        if (expr->kids[0]->isConst()) {
                            auto [b, m] = evalMul(expr->kids[1].get());
                            return {b, m * expr->kids[0]->value};
                        }
                    }
                    if (expr->op == IROp::Shl && expr->kids.size() == 2 && expr->kids[1]->isConst()) {
                        auto [b, m] = evalMul(expr->kids[0].get());
                        return {b, m << expr->kids[1]->value};
                    }
                    if (expr->op == IROp::Add && expr->kids.size() == 2) {
                        auto [b1, m1] = evalMul(expr->kids[0].get());
                        auto [b2, m2] = evalMul(expr->kids[1].get());
                        if (b1 && b2 && b1->op == b2->op &&
                            ((b1->op == IROp::Var && b1->name == b2->name) ||
                             (b1->op == IROp::Temp && b1->value == b2->value)))
                            return {b1, m1 + m2};
                    }
                    return {nullptr, 0};
                };
                {
                    // Try folding the whole expression
                    auto [mulBase, mulFactor] = evalMul(e);
                    if (mulBase && mulFactor > 1) {
                        std::string baseStr = emitExpr(mulBase);
                        result = "(" + baseStr + " * " + std::to_string(mulFactor) + ")";
                        break;
                    }
                }
                // Try folding each child individually for partial simplification
                // Helper: emit a child expression, adding [0] for array-typed vars
                // used in scalar arithmetic context (Mul/Div)
                auto emitScalar = [&](IRExpr *child) -> std::string {
                    std::string s = emitExpr(child);
                    if (e->op == IROp::Mul || e->op == IROp::SDiv || e->op == IROp::UDiv) {
                        // Check if emitted result is a bare local array variable name
                        for (auto &l : m_func.locals) {
                            if (l.typeRef != NullType && cName(l.name) == s) {
                                auto *lt = m_types.resolveType(l.typeRef);
                                if (lt && lt->kind == StabsTypeKind::Array) {
                                    s += "[0]";
                                    break;
                                }
                            }
                        }
                    }
                    return s;
                };
                auto emitChild = [&](IRExpr *child) -> std::string {
                    auto [mb, mf] = evalMul(child);
                    if (mb && mf > 1) return "(" + emitScalar(mb) + " * " + std::to_string(mf) + ")";
                    return emitScalar(child);
                };
                std::string lhs = emitChild(e->kids[0].get());
                // (base + const) in expression context → &base->field_XX
                // This handles the common "sub-object pointer" pattern: t = (this + 1520)
                if (e->op == IROp::Add && e->kids[1] && e->kids[1]->isConst() &&
                    e->kids[1]->value > 0 && e->kids[1]->value < 0x10000 &&
                    (e->kids[0]->op == IROp::Var || e->kids[0]->op == IROp::Temp)) {
                    // Only use &base->field_X when the emitted base is a simple identifier
                    // (not an arithmetic expression like -(v16 * 2))
                    if (!lhs.empty() && (isalpha(lhs[0]) || lhs[0] == '_')) {
                        int off = (int)e->kids[1]->value;
                        // Try type-aware field name
                        TypeRef baseType = exprType(e->kids[0].get());
                        std::string access;
                        if (baseType != NullType && m_types.isStructPointer(baseType)) {
                            TypeRef structRef = m_types.getPointedStruct(baseType);
                            if (structRef != NullType)
                                access = m_types.formatFieldAccess(structRef, off);
                        }
                        if (!access.empty())
                            result = "&" + lhs + "->" + access;
                        else {
                            char fname[32]; snprintf(fname, sizeof(fname), "field_%X", (unsigned)off);
                            result = "&" + lhs + "->" + fname;
                        }
                        break;
                    }
                }
                // Simplify: (x + -N) → (x - N)
                if (e->op == IROp::Add && e->kids[1] && e->kids[1]->isConst() &&
                    e->kids[1]->value < 0) {
                    result = "(" + lhs + " - " + std::to_string(-e->kids[1]->value) + ")";
                    break;
                }
                std::string rhs = emitChild(e->kids[1].get());
                {
                    auto [lb, lf] = evalMul(e->kids[0].get());
                    if (lb && lf > 1)
                        lhs = "(" + emitExpr(lb) + " * " + std::to_string(lf) + ")";
                    auto [rb, rf] = evalMul(e->kids[1].get());
                    if (rb && rf > 1)
                        rhs = "(" + emitExpr(rb) + " * " + std::to_string(rf) + ")";
                }
                // String-level dead-code simplifications
                if (lhs == "0" && rhs == "0" && e->op == IROp::Sub) { result = "0"; break; }
                if (rhs == "0" && (e->op == IROp::Add || e->op == IROp::Sub ||
                                    e->op == IROp::Or || e->op == IROp::Xor)) { result = lhs; break; }
                if (lhs == "0" && (e->op == IROp::Add || e->op == IROp::Or ||
                                    e->op == IROp::Xor)) { result = rhs; break; }
                if (rhs == "1" && (e->op == IROp::Mul || e->op == IROp::SDiv || e->op == IROp::UDiv))
                    { result = lhs; break; }
                if (lhs == "1" && e->op == IROp::Mul) { result = rhs; break; }
                if (lhs == "0" && e->op == IROp::Mul) { result = "0"; break; }
                if (rhs == "0" && e->op == IROp::Mul) { result = "0"; break; }
                if (lhs == rhs && e->op == IROp::Sub) { result = "0"; break; }
                if (lhs == rhs && e->op == IROp::Xor) { result = "0"; break; }
                // (x ^ -1) ^ -1 → x  [double XOR with -1 = identity]
                if (e->op == IROp::Xor && e->kids[1]->isConst() && e->kids[1]->value == -1 &&
                    e->kids[0]->op == IROp::Xor && e->kids[0]->kids.size() == 2 &&
                    e->kids[0]->kids[1]->isConst() && e->kids[0]->kids[1]->value == -1) {
                    result = emitExpr(e->kids[0]->kids[0].get(), negate);
                    break;
                }
                std::string op;
                switch (e->op) {
                case IROp::Add:  op = " + "; break;
                case IROp::Sub:  op = " - "; break;
                case IROp::Mul:  op = " * "; break;
                case IROp::SDiv: case IROp::UDiv: op = " / "; break;
                case IROp::SMod: case IROp::UMod: op = " % "; break;
                case IROp::Shl:  op = " << "; break;
                case IROp::Shr: case IROp::Sar: op = " >> "; break;
                case IROp::And:  op = " & "; break;
                case IROp::Or:   op = " | "; break;
                case IROp::Xor:  op = " ^ "; break;
                default: op = " + "; break; // fallback: treat unknown binary as addition
                }
                result = "(" + lhs + op + rhs + ")";
                break;
            }

            case IROp::Eq: case IROp::Ne:
            case IROp::Slt: case IROp::Sle: case IROp::Sgt: case IROp::Sge:
            case IROp::Ult: case IROp::Ule: case IROp::Ugt: case IROp::Uge: {
                std::string lhs = emitExpr(e->kids[0].get());
                std::string rhs = emitExpr(e->kids[1].get());
                std::string op;
                IROp cmp = negate ? negateOp(e->op) : e->op;
                switch (cmp) {
                case IROp::Eq:  op = " == "; break;
                case IROp::Ne:  op = " != "; break;
                case IROp::Slt: case IROp::Ult: op = " < ";  break;
                case IROp::Sle: case IROp::Ule: op = " <= "; break;
                case IROp::Sgt: case IROp::Ugt: op = " > ";  break;
                case IROp::Sge: case IROp::Uge: op = " >= "; break;
                default: op = " == "; break;
                }

                // Try enum resolution for the rhs if lhs has a known enum type
                if (e->kids[1] && e->kids[1]->isConst() && e->kids[0]) {
                    TypeRef lhsType = exprType(e->kids[0].get());
                    if (lhsType != NullType && m_types.isEnum(lhsType)) {
                        std::string en = m_types.findEnumName(lhsType, e->kids[1]->value);
                        if (!en.empty()) rhs = en;
                    }
                }

                result = lhs + op + rhs;
                if (negate) negate = false; // already handled
                break;
            }

            case IROp::Ternary: {
                std::string cond = (e->kids.size() > 0) ? emitExpr(e->kids[0].get()) : "";
                std::string tval = (e->kids.size() > 1) ? emitExpr(e->kids[1].get()) : "0";
                std::string fval = (e->kids.size() > 2) ? emitExpr(e->kids[2].get()) : "0";
                if (cond.empty()) cond = "0";
                result = "(" + cond + " ? " + tval + " : " + fval + ")";
                break;
            }

            case IROp::Call: {
                result = cName(e->name) + "(";
                for (size_t i = 0; i < e->kids.size(); ++i) {
                    if (i) result += ", ";
                    std::string arg = emitExpr(e->kids[i].get());
                    // Sanitize any remaining non-C identifiers in arguments
                    result += arg;
                }
                result += ")";
                break;
            }

            default:
                result = "/* unknown */";
                break;
            }

            // Safety: never return empty — fallback to temp/var name or 0
            if (result.empty()) {
                if (e->op == IROp::Temp) result = tempName(e->tempId());
                else if (e->op == IROp::Var) result = e->name.empty() ? "0" : e->name;
                else result = "0";
            }

            if (negate && !result.empty()) {
                if (result[0] == '!') return result.substr(1);
                return "!(" + result + ")";
            }

            return result;
        }

        // Get display name for a temp (coalesced name or tN fallback)
        // Only use the coalesced name for temps that are actually declared
        // (use count > 1); single-use temps get inlined and don't need names.
        std::string tempName(int id) {
            if (m_tempUseCount[id] > 1 && !m_copyPropagated.count(id)) {
                auto vit = m_func.tempToVar.find(id);
                if (vit != m_func.tempToVar.end()) {
                    auto nit = m_func.varNames.find(vit->second);
                    if (nit != m_func.varNames.end() && !nit->second.empty())
                        return nit->second;
                }
            }
            return "t" + std::to_string(id);
        }

        // Infer temp type from its defining expression (with cycle detection)
        std::string inferTempType(int id, int depth = 0) {
            if (depth > 10) return "int"; // depth limit to prevent infinite recursion
            auto it = m_tempDef.find(id);
            if (it == m_tempDef.end() || !it->second) return "int";
            auto *e = it->second;
            // If the expression itself has a type annotation, use it
            if (e->typeRef != NullType) {
                auto *rt = m_types.resolveType(e->typeRef);
                // For array types assigned to temps, use pointer to element type
                // UNLESS the temp is defined by arithmetic (Mul/Add/Sub → scalar result)
                if (rt && rt->kind == StabsTypeKind::Array) {
                    if (e->op == IROp::Mul || e->op == IROp::Add || e->op == IROp::Sub ||
                        e->op == IROp::SDiv || e->op == IROp::Neg)
                        return m_types.formatType(rt->targetType);  // element type, no pointer
                    return m_types.formatType(rt->targetType) + " *";
                }
                // Don't propagate struct/union/pointer types through arithmetic
                if (rt && (rt->kind == StabsTypeKind::Struct || rt->kind == StabsTypeKind::Union))
                    return "int";
                std::string fmt = m_types.formatType(e->typeRef);
                if (fmt.find("*") != std::string::npos &&
                    (e->op == IROp::Mul || e->op == IROp::Add || e->op == IROp::Sub)) {
                    // Pointer type from arithmetic → strip pointer
                    size_t star = fmt.find(" *");
                    if (star != std::string::npos) fmt = fmt.substr(0, star);
                }
                return fmt;
            }
            // Float operations → float
            if (e->op == IROp::Const && !tryFloatConst((uint32_t)e->value).empty()) return "float";
            if (e->op == IROp::Cast &&
                (e->castKind == CastKind::IntToFloat || e->castKind == CastKind::FloatToInt))
                return e->castKind == CastKind::IntToFloat ? "float" : "int";
            if (e->op == IROp::Var) {
                // Float literal names
                if (!e->name.empty() && (e->name.find(".0f") != std::string::npos ||
                    e->name.find(".0") != std::string::npos))
                    return "float";
                // Check STABS type of the variable
                for (auto &l : m_func.locals)
                    if (l.name == e->name && l.typeRef != NullType) {
                        auto *lt = m_types.resolveType(l.typeRef);
                        if (lt && (lt->kind == StabsTypeKind::Float || lt->kind == StabsTypeKind::Double))
                            return "float";
                        std::string fmt = m_types.formatType(l.typeRef);
                        if (fmt == "float" || fmt == "double" || fmt == "vec_t")
                            return "float";
                    }
                for (auto &p : m_func.params)
                    if (p.name == e->name && p.typeRef != NullType) {
                        std::string fmt = m_types.formatType(p.typeRef);
                        if (fmt.find("float") != std::string::npos || fmt.find("vec_t") != std::string::npos)
                            return "float";
                    }
            }
            // Comparison results → int (boolean)
            if (e->op >= IROp::Eq && e->op <= IROp::Uge) return "int";
            // If this temp has a known struct pointer type from Field access, use it
            {
                auto sit = m_tempStructPtr.find(id);
                if (sit != m_tempStructPtr.end() && sit->second != NullType)
                    return m_types.formatType(sit->second);
            }
            // If this temp is used as a pointer (dereferenced), declare as char*
            if (m_pointerTemps.count(id)) return "int *";
            // Check if defined by arithmetic with float operands
            if (e->op == IROp::Mul || e->op == IROp::Add || e->op == IROp::Sub ||
                e->op == IROp::Neg || e->op == IROp::SDiv) {
                for (auto &k : e->kids) {
                    if (!k) continue;
                    // Check if operand is a known float
                    if (k->op == IROp::Var) {
                        // Float literal names (e.g., "1.0f", "0.5f")
                        if (!k->name.empty() && (k->name.find('.') != std::string::npos ||
                            k->name.back() == 'f'))
                            return "float";
                        // STABS locals/params with float type
                        for (auto &l : m_func.locals)
                            if (l.name == k->name && l.typeRef != NullType) {
                                auto *lt = m_types.resolveType(l.typeRef);
                                if (lt && (lt->kind == StabsTypeKind::Float ||
                                           lt->kind == StabsTypeKind::Double))
                                    return "float";
                            }
                        for (auto &p : m_func.params)
                            if (p.name == k->name && p.typeRef != NullType) {
                                auto *pt = m_types.resolveType(p.typeRef);
                                if (pt && (pt->kind == StabsTypeKind::Float ||
                                           pt->kind == StabsTypeKind::Double))
                                    return "float";
                            }
                    }
                    // Check if operand is a Temp with known float type
                    if (k->op == IROp::Temp) {
                        auto tit = m_func.tempTypes.find(k->tempId());
                        if (tit != m_func.tempTypes.end() && tit->second != NullType) {
                            auto *tt = m_types.resolveType(tit->second);
                            if (tt && (tt->kind == StabsTypeKind::Float ||
                                       tt->kind == StabsTypeKind::Double))
                                return "float";
                        }
                        // Check the coalesced var type
                        auto vit = m_func.tempToVar.find(k->tempId());
                        if (vit != m_func.tempToVar.end()) {
                            auto vtit = m_func.varTypes.find(vit->second);
                            if (vtit != m_func.varTypes.end() && vtit->second != NullType) {
                                std::string fmt = m_types.formatType(vtit->second);
                                if (fmt == "float" || fmt == "double" || fmt == "vec_t")
                                    return "float";
                            }
                        }
                        // Recursive: check if the operand temp itself infers to float
                        if (inferTempType(k->tempId(), depth + 1) == "float")
                            return "float";
                    }
                    // Check if operand is a Call to a known float-returning function
                    if (k->op == IROp::Call) {
                        std::string cname = k->name;
                        if (cname == "fabsf" || cname == "sqrtf" || cname == "fminf" ||
                            cname == "fmaxf" || cname == "sinf" || cname == "cosf" ||
                            cname == "floorf" || cname == "ceilf" || cname == "acosf")
                            return "float";
                    }
                }
            }
            // Check if the defining expression is a Load or Temp copy
            // that can be traced to a float value
            if (e->op == IROp::Temp) {
                // Copy from another temp — recurse
                return inferTempType(e->tempId(), depth + 1);
            }
            return "int";
        }

        // Convert C++ scope operator :: to _ for valid C identifiers
        static std::string cName(const std::string &name) {
            std::string out = name;
            // Replace :: with _
            size_t pos = 0;
            while ((pos = out.find("::", pos)) != std::string::npos) {
                out.replace(pos, 2, "_");
            }
            // Replace operator symbols
            pos = 0;
            while ((pos = out.find(" ", pos)) != std::string::npos) out.replace(pos, 1, "_");
            pos = 0;
            while ((pos = out.find("~", pos)) != std::string::npos) out.replace(pos, 1, "dtor_");
            // Remove & from references in names
            pos = 0;
            while ((pos = out.find("&", pos)) != std::string::npos) out.erase(pos, 1);
            // Replace remaining non-identifier characters
            for (auto &c : out)
                if (!isalnum(c) && c != '_') c = '_';
            // Remove leading digits
            if (!out.empty() && isdigit(out[0])) out = "_" + out;
            return out;
        }

        // Emit a pointer dereference, adding a cast if the address isn't a pointer type.
        // This prevents "invalid type argument of unary '*' (have 'int')" errors.
        std::string emitDeref(const std::string &addrStr, TypeRef loadType = NullType,
                              TypeRef addrType = NullType) {
            return "*(" + addrStr + ")";
        }

        std::string emitStoreDeref(const std::string &addrStr, TypeRef storeType = NullType,
                                   TypeRef addrType = NullType) {
            return "*(" + addrStr + ")";
        }

        std::string emitCast(IRExpr *e) {
            if (e->kids.empty() || !e->kids[0]) return "0";
            IRExpr *inner_e = e->kids[0].get();
            std::string inner = emitExpr(inner_e);
            if (inner.empty()) return "0";
            // Casting 0 to any type is still 0
            if (inner == "0") return "0";
            // Elide identity casts: Cast(A, Cast(A, x)) → Cast(A, x)
            // and Cast(A, Cast(B, x)) where both narrow to same target
            if (inner_e->op == IROp::Cast) {
                CastKind outer = e->castKind, inner_k = inner_e->castKind;
                // Same cast twice is idempotent
                if (outer == inner_k) return inner;
                // SignExt/ZeroExt then same Trunc is identity for same width
                if ((outer == CastKind::Trunc8  && inner_k == CastKind::ZeroExt8)  ||
                    (outer == CastKind::Trunc8  && inner_k == CastKind::SignExt8)  ||
                    (outer == CastKind::Trunc16 && inner_k == CastKind::ZeroExt16) ||
                    (outer == CastKind::Trunc16 && inner_k == CastKind::SignExt16))
                    return emitCast(inner_e); // reduce to single cast
                // FloatToInt(IntToFloat(x)) → x (round-trip through same-width is lossy but common pattern)
                if (outer == CastKind::FloatToInt && inner_k == CastKind::IntToFloat)
                    return emitExpr(inner_e->kids[0].get());
            }
            switch (e->castKind) {
            case CastKind::ZeroExt8:   return "(unsigned char)(" + inner + ")";
            case CastKind::ZeroExt16:  return "(unsigned short)(" + inner + ")";
            case CastKind::SignExt8:   return "(signed char)(" + inner + ")";
            case CastKind::SignExt16:  return "(short)(" + inner + ")";
            case CastKind::Trunc8:     return "(unsigned char)(" + inner + ")";
            case CastKind::Trunc16:    return "(short)(" + inner + ")";
            case CastKind::IntToFloat: return "(double)(" + inner + ")";
            case CastKind::FloatToInt: return "(int)(" + inner + ")";
            case CastKind::BitCast:    return inner;
            default: return inner;
            }
        }

        // Detect FourCC constants (e.g., 0x6E756C6C → 'null', 0x54455854 → 'TEXT')
        static std::string tryFourCC(uint32_t val) {
            if (val < 0x20202020) return ""; // at least all spaces
            char c[4];
            c[0] = (val >> 24) & 0xFF;
            c[1] = (val >> 16) & 0xFF;
            c[2] = (val >> 8) & 0xFF;
            c[3] = val & 0xFF;
            // All 4 bytes must be printable ASCII (0x20-0x7E)
            for (int i = 0; i < 4; ++i)
                if (c[i] < 0x20 || c[i] > 0x7E) return "";
            // Emit as multi-character constant: 'abcd'
            std::string r = "'";
            for (int i = 0; i < 4; ++i) {
                if (c[i] == '\'') r += "\\'";
                else if (c[i] == '\\') r += "\\\\";
                else r += c[i];
            }
            r += "'";
            return r;
        }

        // Detect IEEE 754 float bit patterns in integer constants
        static std::string tryFloatConst(uint32_t bits) {
            // Only trigger for values that look like floats (exponent != 0 and != 0xFF)
            uint32_t exp = (bits >> 23) & 0xFF;
            if (exp == 0 || exp == 0xFF) return ""; // 0, denormal, inf, nan
            if (bits < 0x3E000000) return ""; // too small to be a common float constant
            float f;
            memcpy(&f, &bits, 4);
            // Only show as float if it's a "nice" value (integral, or simple fraction)
            if (f == (int)f && f >= -1000 && f <= 1000) {
                char buf[32]; snprintf(buf, sizeof(buf), "%.1ff", f);
                return buf;
            }
            // Common constants
            if (bits == 0x3F800000) return "1.0f";
            if (bits == 0x40000000) return "2.0f";
            if (bits == 0x3F000000) return "0.5f";
            if (bits == 0x40490FDB) return "3.14159f"; // pi
            if (bits == 0x3FC90FDB) return "1.5708f";  // pi/2
            if (bits == 0x40C90FDB) return "6.28318f"; // 2*pi
            if (bits == 0x42C80000) return "100.0f";
            if (bits == 0x447A0000) return "1000.0f";
            if (bits == 0x3DCCCCCD) return "0.1f";
            if (bits == 0xBF800000) return "-1.0f";
            if (bits == 0xC0000000) return "-2.0f";
            // For other float-range values, show the float
            if ((f > 0.001f && f < 1000000.0f) || (f < -0.001f && f > -1000000.0f)) {
                char buf[32]; snprintf(buf, sizeof(buf), "%.6g", f);
                // Ensure decimal point before 'f' suffix
                if (strchr(buf, '.') == nullptr && strchr(buf, 'e') == nullptr)
                    strcat(buf, ".0");
                strcat(buf, "f");
                return buf;
            }
            return "";
        }

        // Get the STABS type of an expression
        TypeRef exprType(IRExpr *e) const {
            if (!e) return NullType;
            if (e->typeRef != NullType) return e->typeRef;
            if (e->op == IROp::Temp) return m_func.tempType(e->tempId());
            if (e->op == IROp::Field) return e->typeRef;
            // For Var: look up type from function params/locals
            if (e->op == IROp::Var && !e->name.empty()) {
                for (auto &p : m_func.params)
                    if (p.name == e->name && p.typeRef != NullType) return p.typeRef;
                for (auto &l : m_func.locals)
                    if (l.name == e->name && l.typeRef != NullType) return l.typeRef;
            }
            return NullType;
        }

        // Negate a comparison op
        static IROp negateOp(IROp op) {
            switch (op) {
            case IROp::Eq:  return IROp::Ne;
            case IROp::Ne:  return IROp::Eq;
            case IROp::Slt: return IROp::Sge;
            case IROp::Sle: return IROp::Sgt;
            case IROp::Sgt: return IROp::Sle;
            case IROp::Sge: return IROp::Slt;
            case IROp::Ult: return IROp::Uge;
            case IROp::Ule: return IROp::Ugt;
            case IROp::Ugt: return IROp::Ule;
            case IROp::Uge: return IROp::Ult;
            default: return op;
            }
        }
    };
};
