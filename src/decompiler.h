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
    static inline bool s_flatMode = false;
    static inline bool s_cosmeticMode = false;  // prefer readable output over byte-matching
    static inline bool s_portMode = false;      // port mode: skip per-file type preamble

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
        if (s_flatMode) {
            QString code = em.generateFlat(tree.get());
            return cleanupOutput(code);
        }
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
        if (s_portMode) {
            out += "#include \"cod2_types.h\"\n\n";
        } else {
        out += platformTypedefs();
        out += "\n";
        }

        // Emit includes relevant to this source file (skip in port mode)
        std::set<std::string> emitted;
        if (!s_portMode)
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
        if (!s_portMode) {
            std::set<TypeRef> usedTypes;
            for (size_t fi : sf.functionIndices) {
                auto &fn = mf.stabsFunctions()[fi];
                if (fn.returnType != NullType) usedTypes.insert(fn.returnType);
                for (auto &p : fn.params) if (p.typeRef != NullType) usedTypes.insert(p.typeRef);
                for (auto &l : fn.locals) if (l.typeRef != NullType) usedTypes.insert(l.typeRef);
            }
            emitTypeDefs(out, types, usedTypes);
        }

        // Emit global/static variables and extern declarations (skip in port mode)
        std::set<std::string> emittedGlobals;
        // Emit globals and build cross-file global map
        std::map<std::string, const StabsGlobalVar*> globalByName;
        bool anyGlobals = false;
        if (!s_portMode) {
            for (auto &g : types.globals()) {
                if (g.address == 0) continue;
                if (g.sourceFileIdx != srcIdx) continue;
                if (emittedGlobals.count(g.name)) continue;
                emittedGlobals.insert(g.name);
                out += QString::fromStdString(
                    (g.isStatic ? "static " : "") + types.formatDecl(g.typeRef, g.name)) + ";\n";
                anyGlobals = true;
            }
            if (anyGlobals) out += "\n";
        }
        // Build cross-file global map (for extern scanning in non-port mode)
        if (!s_portMode) {
            for (auto &g : types.globals()) {
                if (g.address == 0 || g.name.empty()) continue;
                if (g.sourceFileIdx == srcIdx) continue;
                if (!globalByName.count(g.name))
                    globalByName[g.name] = &g;
            }
        }

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
                // In port mode, skip forward declarations — the types header
                // already provides prototypes and extra decls cause conflicts
                if (s_portMode) continue;
                emittedProtos.insert(calleeName);
                // Sanitize C++ names for C
                std::string cname = calleeName;
                { size_t p = 0; while ((p = cname.find("::", p)) != std::string::npos)
                    { cname.replace(p, 2, "__"); p += 2; } }
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
                // Detect variadic functions: format string param followed by args
                static const std::set<std::string> variadicFuncs = {
                    "Com_Printf", "Com_DPrintf", "Com_Error", "Com_sprintf",
                    "va", "Cbuf_AddText", "dprintf", "Sys_Error",
                    "Scr_Error", "Scr_ParamError", "CG_Printf", "SV_SendServerCommand",
                    "NET_OutOfBandPrint", "MSG_WriteString"
                };
                if (variadicFuncs.count(calleeName)) {
                    if (proto.back() != '(' && !callee->params.empty())
                        proto += ", ...";
                    else
                        proto += "...";
                }
                proto += ");\n";
                out += QString::fromStdString(proto);
            }
            if (!emittedProtos.empty()) out += "\n";
        } // end cross-CU prototype generation

        // Emit forward declarations only for static functions
        // (needed when a static func is referenced before its definition)
        // Skip in port mode — types header may have conflicting non-static decl
        if (!s_portMode) {
            for (size_t fi : sorted) {
                auto &fn = mf.stabsFunctions()[fi];
                if (fn.address == 0 || fn.isGlobal) continue; // only static functions
                std::string cname = fn.name;
                { size_t p = 0; while ((p = cname.find("::", p)) != std::string::npos)
                    { cname.replace(p, 2, "__"); p += 2; } }
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
        std::set<uint32_t> emittedAddrs; // track to avoid duplicate function definitions
        std::set<std::string> emittedNames;
        for (size_t fi : sorted) {
            auto &fn = mf.stabsFunctions()[fi];
            if (fn.address == 0) continue;
            if (emittedAddrs.count(fn.address)) continue; // skip duplicate addr
            std::string cname = fn.name;
            { size_t p = 0; while ((p = cname.find("::", p)) != std::string::npos) { cname.replace(p, 2, "__"); p += 2; } }
            { size_t p = 0; while ((p = cname.find("~", p)) != std::string::npos) cname.replace(p, 1, "dtor_"); }
            if (emittedNames.count(cname)) continue; // skip duplicate name
            emittedAddrs.insert(fn.address);
            emittedNames.insert(cname);
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
        // In port mode, skip — globals come from cod2_types.h
        if (!s_portMode) {
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
        // Port mode: strip "const" from dvar_t pointers to match types header
        if (s_portMode) {
            out.replace("const dvar_t *", "dvar_t *");
            out.replace("const struct dvar_s *", "struct dvar_s *");
        }
        // Skip file-level cleanupOutput — it already ran per-function inside decompile().
        // Running it again would clobber per-function variable declarations (pass 3).
        return clangFormat(out);
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
        // Build best-type map: prefer non-int, non-null types for each global name
        std::map<std::string, TypeRef> bestGlobalType;
        for (auto &g : types.globals()) {
            if (g.name.empty()) continue;
            auto it = bestGlobalType.find(g.name);
            if (it == bestGlobalType.end()) {
                bestGlobalType[g.name] = g.typeRef;
            } else if (g.typeRef != NullType) {
                auto *oldT = it->second != NullType ? types.getType(it->second) : nullptr;
                auto *newT = types.getType(g.typeRef);
                bool oldBasic = !oldT || oldT->kind == StabsTypeKind::Int || oldT->kind == StabsTypeKind::UInt;
                bool newBasic = !newT || newT->kind == StabsTypeKind::Int || newT->kind == StabsTypeKind::UInt;
                if (oldBasic && !newBasic) it->second = g.typeRef;
            }
        }
        for (auto &g : types.globals()) {
            if (g.address == 0 || g.name.empty()) continue;
            if (globalDeclared.count(g.name)) continue;
            // Use the best type for this global name
            if (g.name.find('<') != std::string::npos) continue;
            globalDeclared.insert(g.name);
            std::string decl;
            TypeRef useType = g.typeRef;
            auto bit = bestGlobalType.find(g.name);
            if (bit != bestGlobalType.end() && bit->second != NullType)
                useType = bit->second;
            if (useType != NullType)
                decl = types.formatDecl(useType, g.name);
            else
                decl = "int " + g.name;
            out += "extern " + QString::fromStdString(decl) + ";\n";
        }

        // For ForwardRef-typed globals, check if the forward tag resolves to
        // an anonymous struct with fields. If so, add a typedef connecting them.
        // This makes clientStatic_t → $_3791 visible so asmcheck can compile.
        for (auto &g : types.globals()) {
            if (g.typeRef == NullType) continue;
            auto *rawT = types.getType(g.typeRef);
            if (!rawT || rawT->kind != StabsTypeKind::ForwardRef) continue;
            if (rawT->forwardTag.empty() || rawT->forwardTag.find("$_") == 0) continue;
            // Check if the tag already has a struct body
            bool hasBody = false;
            for (auto &[tref, ti] : types.allTypes()) {
                if ((ti.kind == StabsTypeKind::Struct || ti.kind == StabsTypeKind::Union) &&
                    ti.name == rawT->forwardTag && !ti.fields.empty()) {
                    hasBody = true; break;
                }
            }
            if (hasBody) continue;
            // No body — try to find the resolved struct (may be anonymous)
            auto *resolved = types.resolveType(g.typeRef);
            if (resolved && (resolved->kind == StabsTypeKind::Struct || resolved->kind == StabsTypeKind::Union) &&
                !resolved->fields.empty() && !resolved->name.empty() && resolved->name != rawT->forwardTag) {
                // Emit typedef: struct $_NNNN → tag_name
                out += "typedef struct " + QString::fromStdString(resolved->name) + " " +
                       QString::fromStdString(rawT->forwardTag) + ";\n";
            }
        }

        // Emit function prototypes
        out += "\n/* Function prototypes */\n";
        std::set<std::string> protoDeclared;
        for (auto &fn : mf.stabsFunctions()) {
            if (fn.address == 0 || fn.name.empty()) continue;
            std::string cname = fn.name;
            { size_t p = 0; while ((p = cname.find("::", p)) != std::string::npos) { cname.replace(p, 2, "__"); p += 2; } }
            { size_t p = 0; while ((p = cname.find("~", p)) != std::string::npos) cname.replace(p, 1, "dtor_"); }
            if (protoDeclared.count(cname)) continue;
            if (cname.find('<') != std::string::npos) continue;
            // Skip names with spaces (C++ constructor/destructor stubs)
            if (cname.find(' ') != std::string::npos) continue;
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
            // Add variadic markers for known variadic functions
            static const std::set<std::string> variadicProtos = {
                "Com_Printf", "Com_DPrintf", "Com_Error", "Com_sprintf",
                "va", "Cbuf_AddText", "Sys_Error", "CG_Printf", "G_Printf",
                "Scr_Error", "Scr_ParamError", "SV_SendServerCommand",
                "NET_OutOfBandPrint"
            };
            if (variadicProtos.count(fn.name))
                out += ", ...";
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
        QString cleaned = code;
        // Pre-pass: fix &EXPR->field_X patterns → (EXPR + 0xX)
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
        // Inline trivial pointer aliases: "TYPE *v = srcName;" → replace v with srcName
        // Looks for declaration + assignment pattern and replaces all uses.
        {
            QStringList lines = cleaned.split('\n');
            for (int i = 0; i < lines.size(); ++i) {
                QString trimmed = lines[i].trimmed();
                // Find assignment: "NAME = SOURCE;" as a standalone statement
                int eq = trimmed.indexOf(" = ");
                if (eq <= 0 || !trimmed.endsWith(';')) continue;
                QString varName = trimmed.left(eq).trimmed();
                QString srcName = trimmed.mid(eq + 3, trimmed.size() - eq - 4).trimmed();
                // Both must be simple identifiers
                if (varName.isEmpty() || srcName.isEmpty()) continue;
                bool varOk = true, srcOk = true;
                for (auto c : varName) if (!c.isLetterOrNumber() && c != '_') { varOk = false; break; }
                for (auto c : srcName) if (!c.isLetterOrNumber() && c != '_') { srcOk = false; break; }
                if (!varOk || !srcOk || srcName[0].isDigit()) continue;
                if (varName == srcName) continue;
                // Check: is there a declaration "TYPE *varName;" earlier in the function?
                bool hasDecl = false;
                int declLine = -1;
                for (int j = 0; j < i; ++j) {
                    QString dt = lines[j].trimmed();
                    if (dt.endsWith("*" + varName + ";") || dt.endsWith("* " + varName + ";")) {
                        hasDecl = true; declLine = j; break;
                    }
                }
                if (!hasDecl) continue;
                // Count uses after the assignment
                int useCount = 0;
                bool usedWithArrow = false;
                for (int j = i + 1; j < lines.size(); ++j) {
                    if (lines[j].contains(varName)) useCount++;
                    if (lines[j].contains(varName + "->")) usedWithArrow = true;
                }
                if (useCount == 0) continue;
                // Don't inline if the variable is used with -> (it's a loop variable
                // that traverses a struct, not a trivial alias)
                if (usedWithArrow) continue;
                // Replace all uses of varName with srcName (whole word)
                for (int j = i + 1; j < lines.size(); ++j) {
                    // Simple whole-word replacement
                    int pos = 0;
                    while ((pos = lines[j].indexOf(varName, pos)) >= 0) {
                        bool before = (pos == 0 || !lines[j][pos-1].isLetterOrNumber());
                        bool after = (pos + varName.size() >= lines[j].size() ||
                                     !lines[j][pos + varName.size()].isLetterOrNumber());
                        if (before && after) {
                            lines[j].replace(pos, varName.size(), srcName);
                            pos += srcName.size();
                        } else {
                            pos += varName.size();
                        }
                    }
                }
                // Remove declaration and assignment
                lines.removeAt(i); // remove assignment
                if (declLine < i) { lines.removeAt(declLine); i -= 2; }
                else i--;
            }
            cleaned = lines.join('\n');
        }
        // Convert interior pointer offset accesses to array notation:
        // Given "v = &expr[0];" then "*(TYPE *)((char *)v + 0xN)" → "v[N/sizeof]"
        {
            // Find interior pointer assignments: "NAME = &EXPR[0];"
            std::map<QString, int> interiorPtrs; // name → element size (4 for float/int)
            int pos2 = 0;
            while ((pos2 = cleaned.indexOf("[0];", pos2)) != -1) {
                // Walk back to find "NAME = &"
                int lineStart = cleaned.lastIndexOf('\n', pos2) + 1;
                QString line = cleaned.mid(lineStart, pos2 + 4 - lineStart).trimmed();
                // Match: NAME = &EXPR[0];
                int eqPos = line.indexOf(" = &");
                if (eqPos > 0) {
                    QString varName = line.left(eqPos).trimmed();
                    // varName should be a simple identifier
                    bool ok = !varName.isEmpty();
                    // Skip if this variable is used with -> (struct pointer, not array)
                    if (ok && cleaned.contains(varName + "->")) ok = false;
                    for (auto c : varName) if (!c.isLetterOrNumber() && c != '_') { ok = false; break; }
                    if (ok) interiorPtrs[varName] = 4;
                }
                pos2 += 4;
            }
            // Replace: *(TYPE *)((char *)NAME + 0xN) → NAME[N/elemSize]
            for (auto &[name, elemSz] : interiorPtrs) {
                for (auto &castType : {"*(int *)((char *)", "*(unsigned short *)((char *)",
                                        "*(unsigned char *)((char *)", "*(char *)((char *)"}) {
                    QString prefix = QString(castType) + name + " + 0x";
                    int rp = 0;
                    while ((rp = cleaned.indexOf(prefix, rp)) != -1) {
                        int hexStart = rp + prefix.size();
                        int hexEnd = hexStart;
                        while (hexEnd < cleaned.size() && cleaned[hexEnd].isLetterOrNumber()) hexEnd++;
                        // Must end with ) — the closing paren of the outer cast expression
                        if (hexEnd < cleaned.size() && cleaned[hexEnd] == ')') {
                            bool hexOk;
                            int offset = cleaned.mid(hexStart, hexEnd - hexStart).toInt(&hexOk, 16);
                            if (hexOk && offset > 0 && offset % elemSz == 0) {
                                int idx = offset / elemSz;
                                int exprEnd = hexEnd + 1; // past the closing )
                                QString replacement = name + "[" + QString::number(idx) + "]";
                                cleaned.replace(rp, exprEnd - rp, replacement);
                                rp += replacement.size();
                                continue;
                            }
                        }
                        rp++;
                    }
                }
            }
        }
        // Optimize global struct access: when (char *)GLOBAL is used multiple times,
        // introduce a local pointer to force register-based access (matching original asm)
        // Skip in cosmetic mode — _p variables are a byte-matching trick, not readable
        if (!s_cosmeticMode) {
            // Count occurrences of (char *)NAME + 0x patterns
            std::map<QString, int> globalCounts;
            QString marker = "(char *)";
            int pos = 0;
            while ((pos = cleaned.indexOf(marker, pos)) != -1) {
                int nameStart = pos + marker.size();
                // Skip whitespace
                while (nameStart < cleaned.size() && cleaned[nameStart] == ' ') nameStart++;
                int nameEnd = nameStart;
                while (nameEnd < cleaned.size() && (cleaned[nameEnd].isLetterOrNumber() || cleaned[nameEnd] == '_'))
                    nameEnd++;
                if (nameEnd > nameStart) {
                    QString gname = cleaned.mid(nameStart, nameEnd - nameStart);
                    // Check followed by " + 0x"
                    int afterName = nameEnd;
                    while (afterName < cleaned.size() && cleaned[afterName] == ' ') afterName++;
                    if (afterName < cleaned.size() && cleaned[afterName] == '+') {
                        // Only count real globals (not locals)
                        // Only real globals, not decompiler-generated locals (vN, varN, tN)
                        bool isDecompLocal = (gname[0] == 'v' && gname.size() >= 2 && gname[1].isDigit()) ||
                                             gname.startsWith("var_") || gname.startsWith("t");
                        if (gname.size() >= 2 && gname[0].isLower() && !isDecompLocal) {
                            globalCounts[gname]++;
                        }
                    }
                }
                pos = nameStart;
            }
            for (auto &[gname, count] : globalCounts) {
                if (count < 3) continue;
                QString ptrName = "_" + gname + "_p";
                int bracePos = cleaned.indexOf('{');
                if (bracePos >= 0) {
                    int insertPos = cleaned.indexOf('\n', bracePos) + 1;
                    cleaned.insert(insertPos, "    char *" + ptrName + " = (char *)" + gname + ";\n");
                }
                cleaned.replace("(char *)" + gname + " ", ptrName + " ");
                cleaned.replace("(char *)" + gname + ")", ptrName + ")");
                // Also replace *(type*)(GLOBAL) patterns to use the pointer
                cleaned.replace("*(int *)(" + gname + ")", "*(int *)(" + ptrName + ")");
                cleaned.replace("*(char *)(" + gname + ")", "*(char *)(" + ptrName + ")");
            }
        }
        // (NLP pointer caching removed — changing variable count affects GCC register allocation)
        // Simplify redundant double (char *) casts:
        // *(TYPE *)((char *)((char *)X + N)) → *(TYPE *)((char *)X + N)
        cleaned.replace("((char *)((char *)", "((char *)(");
        // Fix invalid array pointer syntax in declarations: "float[4] * mtx" → "float * mtx"
        // Only on declaration lines (function signature or local variable declarations)
        {
            QStringList cl = cleaned.split('\n');
            for (int i = 0; i < cl.size(); ++i) {
                QString t = cl[i].trimmed();
                // Only process declaration-like lines (function signatures and variable decls)
                bool isDecl = (t.contains('(') && t.contains(')') && !t.contains('=') && !t.contains("if ") && !t.contains("while ")) ||
                              (t.endsWith(';') && !t.contains('=') && !t.contains('('));
                if (!isDecl) continue;
                // Replace TYPE[N] * NAME with TYPE * NAME
                int pos = 0;
                while ((pos = cl[i].indexOf('[', pos)) != -1) {
                    int be = cl[i].indexOf(']', pos);
                    if (be < 0) break;
                    bool allDig = true;
                    for (int ci = pos + 1; ci < be; ++ci)
                        if (!cl[i][ci].isDigit()) { allDig = false; break; }
                    if (!allDig || be == pos + 1) { pos = be + 1; continue; }
                    int after = be + 1;
                    while (after < cl[i].size() && cl[i][after] == ' ') after++;
                    if (after < cl[i].size() && cl[i][after] == '*') {
                        cl[i].remove(pos, after - pos);
                    } else {
                        pos = be + 1;
                    }
                }
            }
            cleaned = cl.join('\n');
        }
        // Remove redundant double casts: (type)((type)(x)) → (type)(x)
        {
            int pos = 0;
            while ((pos = cleaned.indexOf("((unsigned char)(", pos)) != -1) {
                // Check if preceded by "(unsigned char)"
                int outer = cleaned.lastIndexOf("(unsigned char)", pos);
                if (outer >= 0 && outer + 15 == pos) {
                    // Remove the outer cast: "(unsigned char)((unsigned char)(x))" → "(unsigned char)(x)"
                    cleaned.remove(outer, 16); // remove "(unsigned char)("
                    // Find matching close paren
                    int depth = 1;
                    int cp = outer;
                    while (cp < cleaned.size() && depth > 0) {
                        if (cleaned[cp] == '(') depth++;
                        if (cleaned[cp] == ')') depth--;
                        cp++;
                    }
                    if (cp > 0 && cp <= cleaned.size()) {
                        cleaned.remove(cp - 1, 1); // remove extra close paren
                    }
                    continue;
                }
                pos += 1;
            }
        }
        // Simplify redundant casts on literals: (unsigned char)(1) → 1
        cleaned.replace("(unsigned char)(0)", "0");
        cleaned.replace("(unsigned char)(1)", "1");
        // Remove trailing "return;" at end of void functions
        // (the last statement before the closing brace)
        if (cleaned.contains("void ") && !cleaned.contains("return ")) {
            // Only if the function is void and has no return-with-value
            int lastReturn = cleaned.lastIndexOf("    return;\n}");
            if (lastReturn >= 0)
                cleaned.remove(lastReturn, 12); // remove "    return;\n"
        }

        // Fix variadic functions: detect va_list usage and fix signature + va_start
        {
            bool hasVaList = cleaned.contains("va_list ");
            bool hasVsnprintf = cleaned.contains("vsnprintf") || cleaned.contains("vsprintf");
            if (hasVaList && hasVsnprintf) {
                // Add ... to function signature if not present
                int sigEnd = cleaned.indexOf(")");
                if (sigEnd > 0 && !cleaned.left(sigEnd).contains("...")) {
                    cleaned.insert(sigEnd, ", ...");
                }
                // Find the last named parameter
                QString lastParam;
                {
                    int ps = cleaned.indexOf('(');
                    int pe = cleaned.indexOf(", ...)");
                    if (pe < 0) pe = cleaned.indexOf(')');
                    if (ps > 0 && pe > ps) {
                        QString params = cleaned.mid(ps + 1, pe - ps - 1);
                        QStringList parts = params.split(',');
                        if (!parts.isEmpty()) {
                            QStringList words = parts.last().trimmed().split(' ');
                            if (!words.isEmpty()) {
                                lastParam = words.last().remove('*');
                            }
                        }
                    }
                }
                // Replace va_list init with va_start
                if (!lastParam.isEmpty()) {
                    // Capture the temp name: "vN = &arg_1" → tempName = "vN"
                    int argPos = cleaned.indexOf("= &arg_1;");
                    QString vaTempName;
                    if (argPos >= 0) {
                        int lineStart = cleaned.lastIndexOf('\n', argPos) + 1;
                        QString line = cleaned.mid(lineStart, argPos - lineStart).trimmed();
                        vaTempName = line; // "vN"
                        // Find end of next line (argptr = vN;)
                        int nextLine = cleaned.indexOf('\n', argPos);
                        int lineEnd = cleaned.indexOf(';', nextLine);
                        if (lineEnd > nextLine) {
                            cleaned.replace(lineStart, lineEnd - lineStart + 1,
                                "    va_start(argptr, " + lastParam + ");");
                        }
                    }
                    // Replace remaining references to the temp with argptr
                    if (!vaTempName.isEmpty()) {
                        cleaned.replace(", " + vaTempName + ")", ", argptr)");
                        cleaned.replace("(" + vaTempName + ",", "(argptr,");
                    }
                }
                // Remove unused declarations
                QStringList cl = cleaned.split('\n');
                QStringList cl2;
                for (auto &l : cl) {
                    QString t = l.trimmed();
                    if (t.startsWith("va_list v") && t.endsWith(";")) continue;
                    if (t == "int arg_1;") continue;
                    cl2.append(l);
                }
                cleaned = cl2.join('\n');
            }
        }
        // Fix array element references: msg_OFFSET_ = 0 → msg[OFFSET] = 0
        {
            // Find arrays: "TYPE NAME[SIZE]" or "vecN_t NAME" (typedef'd arrays)
            // For vecN_t types, derive the array size from the typedef
            std::map<QString, int> vecTypeSizes = {
                {"vec2_t", 2}, {"vec3_t", 3}, {"vec4_t", 4}
            };
            // First handle vecN_t variables: "vec3_t name;" → name is float[3]
            for (auto &[vecType, vecSize] : vecTypeSizes) {
                int vp = 0;
                while ((vp = cleaned.indexOf(vecType + " ", vp)) != -1) {
                    int ns = vp + vecType.size() + 1;
                    while (ns < cleaned.size() && cleaned[ns] == ' ') ns++;
                    int ne = ns;
                    while (ne < cleaned.size() && (cleaned[ne].isLetterOrNumber() || cleaned[ne] == '_')) ne++;
                    if (ne > ns) {
                        QString arrName = cleaned.mid(ns, ne - ns).trimmed();
                        // Replace arrName_N_ with arrName[N] for N < vecSize
                        QString prefix = arrName + "_";
                        int sp = 0;
                        while ((sp = cleaned.indexOf(prefix, sp)) != -1) {
                            // Don't match inside other identifiers
                            if (sp > 0 && (cleaned[sp-1].isLetterOrNumber() || cleaned[sp-1] == '_'))
                                { sp++; continue; }
                            int numStart = sp + prefix.size();
                            int numEnd = numStart;
                            while (numEnd < cleaned.size() && cleaned[numEnd].isDigit()) numEnd++;
                            if (numEnd > numStart && numEnd < cleaned.size() && cleaned[numEnd] == '_') {
                                int idx = cleaned.mid(numStart, numEnd - numStart).toInt();
                                if (idx >= 0 && idx < vecSize) {
                                    QString oldPat = cleaned.mid(sp, numEnd + 1 - sp);
                                    QString newPat = arrName + "[" + QString::number(idx) + "]";
                                    cleaned.replace(sp, oldPat.size(), newPat);
                                    sp += newPat.size();
                                    continue;
                                }
                            }
                            sp++;
                        }
                    }
                    vp = ns;
                }
            }
            for (auto &arrType : {"char ", "byte ", "int ", "float ", "short ", "unsigned char "}) {
            int pos = 0;
            while ((pos = cleaned.indexOf(arrType, pos)) != -1) {
                int nameStart = pos + (int)strlen(arrType);
                int bracket = cleaned.indexOf('[', nameStart);
                int semi = cleaned.indexOf(';', nameStart);
                if (bracket > nameStart && bracket < semi) {
                    QString arrName = cleaned.mid(nameStart, bracket - nameStart).trimmed();
                    int closeBracket = cleaned.indexOf(']', bracket);
                    if (closeBracket > bracket) {
                        int arrSize = cleaned.mid(bracket + 1, closeBracket - bracket - 1).toInt();
                        // Replace arrName_OFFSET_ with arrName[OFFSET]
                        if (arrSize > 0 && !arrName.isEmpty()) {
                            // Search for pattern: arrName_DIGITS_ =
                            QString prefix = arrName + "_";
                            int sp = 0;
                            while ((sp = cleaned.indexOf(prefix, sp)) != -1) {
                                int numStart = sp + prefix.size();
                                int numEnd = numStart;
                                while (numEnd < cleaned.size() && cleaned[numEnd].isDigit()) numEnd++;
                                if (numEnd > numStart && numEnd < cleaned.size() && cleaned[numEnd] == '_') {
                                    int offset = cleaned.mid(numStart, numEnd - numStart).toInt();
                                    if (offset >= 0 && offset < arrSize) {
                                        QString oldPat = cleaned.mid(sp, numEnd + 1 - sp);
                                        QString newPat = arrName + "[" + QString::number(offset) + "]";
                                        cleaned.replace(sp, oldPat.size(), newPat);
                                        // Also remove synthetic declaration
                                        QString synthDecl = "\n    int " + oldPat + ";\n";
                                        cleaned.replace(synthDecl, "\n");
                                        continue;
                                    }
                                }
                                sp = numEnd;
                            }
                        }
                    }
                }
                pos = nameStart;
            }
            } // for arrType
        }
        // Fix impossible nested conditions: if (x == V) { if (x != V) {
        // The outer condition makes the inner always-false → dead code.
        // Fix by inverting the outer condition.
        // Also handle: if (V == x) { if (V != x) { (reversed operand order)
        {
            QStringList cl = cleaned.split('\n');
            for (int i = 0; i < cl.size(); ++i) {
                QString t = cl[i].trimmed();
                if (!t.startsWith("if (") || !t.endsWith("{")) continue;
                // Extract: if (EXPR == VALUE) or if (VALUE == EXPR)
                int eqPos = t.indexOf(" == ");
                if (eqPos < 0) continue;
                QString lhs = t.mid(4, eqPos - 4).trimmed();
                int bracePos = t.lastIndexOf('{');
                QString rhs = t.mid(eqPos + 4, bracePos - eqPos - 4).trimmed().chopped(1).trimmed();
                // rhs might have trailing ")"
                while (rhs.endsWith(')') && lhs.count('(') <= lhs.count(')'))
                    rhs.chop(1);

                // Check next few lines for contradictory inner if
                for (int j = i + 1; j < std::min(i + 4, (int)cl.size()); ++j) {
                    QString t2 = cl[j].trimmed();
                    // Inner condition contradicts outer
                    if (t2.startsWith("if (") &&
                        ((t2.contains(lhs) && t2.contains("!=")) ||
                         (t2.contains(lhs) && (t2.contains("> ") || t2.contains("< "))))) {
                        // Verify it's actually contradictory (same expression, different comparison)
                        if (t2.contains(lhs + " != ") || t2.contains(lhs + " > ") || t2.contains(lhs + " < ") ||
                            t2.contains("!= " + lhs) || t2.contains("> " + lhs) || t2.contains("< " + lhs)) {
                            cl[i].replace(" == ", " != ");
                            break;
                        }
                    }
                    if (!t2.isEmpty() && t2 != "}" && !t2.startsWith("if (") && t2 != "return;")
                        break;
                }
            }
            cleaned = cl.join('\n');
        }
        // Fix hex integer constants used as float arguments in Dvar_Register* calls.
        // The decompiler emits float bits as hex (0x3DCCCCCD) instead of float literals (0.1f).
        // When passed to a function expecting float, this causes wrong values.
        {
            for (auto &fn : {"Dvar_RegisterFloat", "Dvar_RegisterColor",
                             "Dvar_RegisterVec2", "Dvar_RegisterVec3", "Dvar_RegisterVec4"}) {
                QString qfn = QString::fromUtf8(fn);
                int pos = 0;
                while ((pos = cleaned.indexOf(qfn + "(", pos)) != -1) {
                    int paren = cleaned.indexOf('(', pos);
                    if (paren < 0) { pos++; continue; }
                    // Scan args for hex constants: 0xHHHHHHHH
                    int depth = 0;
                    for (int ci = paren; ci < cleaned.size(); ++ci) {
                        if (cleaned[ci] == '(') depth++;
                        if (cleaned[ci] == ')') { depth--; if (depth == 0) break; }
                        // Match 0xHHHHHHHH (exactly 8 hex digits)
                        if (cleaned[ci] == '0' && ci + 9 < cleaned.size() &&
                            (cleaned[ci+1] == 'x' || cleaned[ci+1] == 'X')) {
                            QString hex = cleaned.mid(ci, 10);
                            // Check it's exactly 0x + 8 hex chars followed by non-alnum
                            bool isHex8 = hex.size() == 10;
                            for (int h = 2; h < 10 && isHex8; ++h)
                                isHex8 = QString("0123456789ABCDEFabcdef").contains(hex[h]);
                            if (isHex8 && (ci + 10 >= cleaned.size() || !cleaned[ci+10].isLetterOrNumber())) {
                                bool ok;
                                uint32_t bits = hex.toUInt(&ok, 16);
                                if (ok && bits > 0x100) {
                                    float fval;
                                    memcpy(&fval, &bits, 4);
                                    if (fval == fval && fval > -1e10f && fval < 1e10f) {
                                        QString floatStr = QString::number((double)fval, 'g', 8) + "f";
                                        cleaned.replace(ci, 10, floatStr);
                                        ci += floatStr.size() - 1;
                                    }
                                }
                            }
                        }
                    }
                    pos = paren + 1;
                }
            }
        }
        // Fix integer 0 used as float argument: AngleDelta(0, ...) → AngleDelta(0.0f, ...)
        // The compiler generates cvtsi2ss for int→float conversion, but the original
        // uses raw 0 bits (same as float 0.0) with no conversion.
        {
            // Replace bare integer 0 in function calls where we know the param is float
            // Pattern: known_float_func(... 0, ...) or (... 0)
            for (auto &fn : {"AngleDelta", "AngleNormalize180", "AngleNormalize180Accurate",
                             "BG_CheckProne"}) {
                QString qfn = QString::fromUtf8(fn);
                int pos = 0;
                while ((pos = cleaned.indexOf(qfn + "(", pos)) != -1) {
                    // Find the argument list and replace bare 0 with 0.0f
                    int pstart = cleaned.indexOf('(', pos);
                    if (pstart < 0) { pos++; continue; }
                    int depth = 0;
                    for (int ci = pstart; ci < cleaned.size(); ++ci) {
                        if (cleaned[ci] == '(') depth++;
                        if (cleaned[ci] == ')') {
                            depth--;
                            if (depth == 0) {
                                // Replace ", 0)" and "(0," patterns within this call
                                QString args = cleaned.mid(pstart, ci - pstart + 1);
                                args.replace(", 0)", ", 0.0f)");
                                args.replace(", 0,", ", 0.0f,");
                                args.replace("(0,", "(0.0f,");
                                args.replace("(0)", "(0.0f)");
                                cleaned.replace(pstart, ci - pstart + 1, args);
                                break;
                            }
                        }
                    }
                    pos = pstart + 1;
                }
            }
        }
        // Fix STABS int→float mismatch: when "int var_X" is assigned from a
        // float-returning function (AngleDelta etc.) and used in float context,
        // change declaration to "float var_X" to avoid spurious truncation.
        {
            static const char *floatFuncs[] = {
                "AngleDelta", "AngleNormalize180", "AngleNormalize180Accurate",
                "PitchForYawOnNormal", "Vec3Normalize", "Vec2Normalize",
                "floorf", "ceilf", "sinf", "cosf", "tanf", "sqrtf", "fabsf",
                "asinf", "acosf", "atanf", "atan2f", "fmodf", "powf",
                "fminf", "fmaxf", "Scr_GetFloat", nullptr
            };
            QStringList cl = cleaned.split('\n');
            // Find int var_X declarations where all uses are float-like
            for (int i = 0; i < cl.size(); ++i) {
                QString t = cl[i].trimmed();
                if (!t.startsWith("int var_")) continue;
                int semi = t.indexOf(';');
                if (semi < 0) continue;
                QString varName = t.mid(4, semi - 4).trimmed();
                if (varName.isEmpty()) continue;
                // Check all lines for this variable's usage
                bool assignedFromFloat = false;
                bool usedAsInt = false;
                for (int j = i + 1; j < cl.size(); ++j) {
                    QString line = cl[j];
                    if (!line.contains(varName)) continue;
                    // Check if assigned from a float function
                    if (line.contains(varName + " = ")) {
                        for (int fi = 0; floatFuncs[fi]; ++fi) {
                            if (line.contains(QString::fromUtf8(floatFuncs[fi]) + "(")) {
                                assignedFromFloat = true;
                                break;
                            }
                        }
                    }
                    // Check if used in float context (0.0f comparison, fabsf, mulsd, etc.)
                    if (line.contains(varName) &&
                        (line.contains("0.0f") || line.contains("fabsf") ||
                         line.contains("57.29") || line.contains("Scr_AddFloat"))) {
                        assignedFromFloat = true;
                    }
                    // Check if assigned from a float-typed variable
                    if (line.contains(varName + " = ") &&
                        (line.contains("= v") || line.contains("= (v"))) {
                        // Check if the RHS variable is declared as float
                        for (int k = 0; k < i; ++k) {
                            if (cl[k].trimmed().startsWith("float ") &&
                                line.contains(cl[k].trimmed().mid(6).split(';').first().trimmed())) {
                                assignedFromFloat = true;
                                break;
                            }
                        }
                    }
                    // Check if returned and function returns float
                    if (line.trimmed().startsWith("return " + varName)) {
                        assignedFromFloat = true;
                    }
                    // Check if used as a pure integer (bit ops, array index, etc.)
                    if (line.contains(varName + " &") || line.contains(varName + " |") ||
                        line.contains(varName + " <<") || line.contains("[" + varName + "]")) {
                        usedAsInt = true;
                    }
                }
                if (assignedFromFloat && !usedAsInt) {
                    cl[i].replace("int " + varName, "float " + varName);
                }
            }
            cleaned = cl.join('\n');
        }
        // Fix duplicate nested conditions: if (X) { if (X) { → if (X) { if (1) {
        // The inner condition is always true → replace with constant true.
        {
            QStringList cl = cleaned.split('\n');
            for (int i = 0; i < cl.size() - 1; ++i) {
                QString t = cl[i].trimmed();
                if (!t.startsWith("if (") || !t.endsWith("{")) continue;
                int j = i + 1;
                while (j < cl.size() && cl[j].trimmed().isEmpty()) j++;
                if (j < cl.size() && cl[j].trimmed() == t) {
                    // Replace inner duplicate with if (1) — always true, no branch
                    QString indent = cl[j];
                    indent.truncate(cl[j].indexOf('i'));
                    cl[j] = indent + "if (1) {";
                }
            }
            cleaned = cl.join('\n');
        }
        QStringList lines = cleaned.split('\n');
        // Pass 1: Remove empty if blocks
        QStringList pass1;
        for (int i = 0; i < lines.size(); ++i) {
            // Remove self-assignments: "x = x;"
            {
                QString t = lines[i].trimmed();
                if (t.endsWith(';') && t.contains(" = ")) {
                    int eq = t.indexOf(" = ");
                    QString lhs = t.left(eq).trimmed();
                    QString rhs = t.mid(eq + 3).chopped(1).trimmed(); // remove trailing ;
                    if (lhs == rhs && !lhs.isEmpty()) continue;
                }
            }
            if (i + 1 < lines.size() &&
                lines[i].trimmed().startsWith("if (") &&
                lines[i].trimmed().endsWith("{") &&
                lines[i+1].trimmed() == "}") {
                ++i; continue;
            }
            // Remove empty else blocks: "} else {\n}" → "}"
            if (i + 1 < lines.size() &&
                lines[i].trimmed() == "} else {" &&
                lines[i+1].trimmed() == "}") {
                pass1.append(lines[i+1]); // just the closing }
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
                    if (trimmed == "}" || trimmed.isEmpty()) continue;
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
            // Match variable declaration: TYPE NAME; (no assignment, no function body)
            // Detect: line ends with ";", contains no "=", no "(", and starts with a type keyword
            bool isDecl = false;
            QString varName;
            if (trimmed.endsWith(';') && !trimmed.contains('=') && !trimmed.contains('(') && !trimmed.contains('[')) {
                // Check starts with known type or looks like TYPE NAME;
                static const char *typeKw[] = {"int ", "float ", "char ", "short ", "unsigned ",
                    "void *", "const ", "vec_t ", "vec3_t ", "vec2_t ", "byte ",
                    "playerState_t ", "qboolean ", "Bool ", "dvar_t ", "cmd_function_t ",
                    "struct ", "char *", "int *", "float *", nullptr};
                for (int k = 0; typeKw[k]; ++k) {
                    if (trimmed.startsWith(typeKw[k])) { isDecl = true; break; }
                }
                if (isDecl) {
                    // Extract variable name: last word before ";"
                    int semi = trimmed.lastIndexOf(';');
                    int nameEnd2 = semi;
                    while (nameEnd2 > 0 && trimmed[nameEnd2-1] == ' ') nameEnd2--;
                    int ns = nameEnd2 - 1;
                    while (ns > 0 && (trimmed[ns-1].isLetterOrNumber() || trimmed[ns-1] == '_'))
                        ns--;
                    varName = trimmed.mid(ns, nameEnd2 - ns).trimmed();
                    // Don't remove if the name starts with * (pointer decl)
                    if (varName.startsWith('*')) varName = varName.mid(1);
                }
            }
            if (isDecl && !varName.isEmpty()) {
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
        // Remove unused labels (label defined but no goto references it)
        {
            QStringList p3;
            for (int i = 0; i < pass2.size(); ++i) {
                QString t = pass2[i].trimmed();
                if (t.endsWith(':') && t.startsWith("bb_")) {
                    QString label = t.chopped(1); // remove ':'
                    bool used = false;
                    for (auto &line : pass2) {
                        if (line.contains("goto " + label)) { used = true; break; }
                    }
                    if (!used) continue; // skip unused label
                }
                p3.append(pass2[i]);
            }
            pass2 = p3;
        }
        // Pass 3: Add declarations for undeclared variables
        // Scan for vN/tN/var_N identifiers used but not declared.
        {
            std::set<QString> declared;
            std::set<QString> used;
            int bracePos = -1;
            for (int i = 0; i < pass2.size(); ++i) {
                QString t = pass2[i].trimmed();
                if (t.contains('{') && bracePos < 0) { bracePos = i; continue; }
                // Collect declarations (TYPE NAME; lines, not statements)
                if (bracePos >= 0 && t.endsWith(';') && !t.contains('=') && !t.contains('(') &&
                    !t.startsWith("goto ") && !t.startsWith("return ") && !t.startsWith("break") &&
                    !t.startsWith("continue") && !t.startsWith("if ") && !t.startsWith("while ") &&
                    !t.startsWith("for ") && !t.startsWith("switch ") && !t.startsWith("case ")) {
                    int semi = t.lastIndexOf(';');
                    int ne = semi;
                    while (ne > 0 && t[ne-1] == ' ') ne--;
                    int ns = ne - 1;
                    while (ns > 0 && (t[ns-1].isLetterOrNumber() || t[ns-1] == '_')) ns--;
                    QString name = t.mid(ns, ne - ns).trimmed();
                    if (name.startsWith('*')) name = name.mid(1);
                    if (!name.isEmpty()) declared.insert(name);
                }
                // Collect used LOCAL identifiers: vN, tN, var_N, arg_N
                // (NOT g_XXXXX which are globals, NOT _name___0xN_ which are struct offsets)
                int p = 0;
                while (p < t.size()) {
                    if ((t[p] == 'v' || t[p] == 't') && (p == 0 || !t[p-1].isLetterOrNumber())) {
                        int s = p;
                        while (p < t.size() && (t[p].isLetterOrNumber() || t[p] == '_')) p++;
                        QString word = t.mid(s, p - s);
                        if (word.size() >= 2 && (word[0] == 'v' || word[0] == 't') &&
                            word[1].isDigit())
                            used.insert(word);
                        else if (word.startsWith("var_") || word.startsWith("arg_"))
                            used.insert(word);
                    } else p++;
                }
            }
            // Params from function signature
            if (!pass2.isEmpty()) {
                QString sig = pass2[0];
                int p = 0;
                while (p < sig.size()) {
                    if (sig[p].isLetter() || sig[p] == '_') {
                        int s = p;
                        while (p < sig.size() && (sig[p].isLetterOrNumber() || sig[p] == '_')) p++;
                        declared.insert(sig.mid(s, p - s));
                    } else p++;
                }
            }
            // Also scan ALL lines for existing declarations (not just header)
            for (int i = 0; i < pass2.size(); ++i) {
                QString t = pass2[i].trimmed();
                // Match "TYPE NAME;" patterns anywhere in the function
                if (t.endsWith(';') && !t.contains('=') && !t.contains('(') &&
                    !t.contains('{') && !t.contains('}') && t.size() < 80) {
                    int semi = t.lastIndexOf(';');
                    int ne2 = semi;
                    while (ne2 > 0 && t[ne2-1] == ' ') ne2--;
                    int ns2 = ne2 - 1;
                    while (ns2 > 0 && (t[ns2-1].isLetterOrNumber() || t[ns2-1] == '_')) ns2--;
                    QString nm = t.mid(ns2, ne2 - ns2).trimmed();
                    if (nm.startsWith('*')) nm = nm.mid(1);
                    if (!nm.isEmpty()) declared.insert(nm);
                }
            }
            QStringList newDecls;
            for (auto &name : used) {
                if (declared.count(name)) continue;
                newDecls.append("    int " + name + ";");
            }
            if (!newDecls.isEmpty() && bracePos >= 0) {
                std::sort(newDecls.begin(), newDecls.end());
                for (int i = newDecls.size() - 1; i >= 0; --i)
                    pass2.insert(bracePos + 1, newDecls[i]);
            }
        }
        QString result;
        for (auto &l : pass2) result += l + '\n';
        // Cosmetic mode: simplify redundant (char *) casts and pointer dereferences
        if (s_cosmeticMode) {
            // Remove redundant (char *) in: *(TYPE *)((char *)(EXPR)) → *(TYPE *)(EXPR)
            // Only when inner expression has no pointer arithmetic (no + at depth 0)
            QString marker = "((char *)";
            int pos = 0;
            while ((pos = result.indexOf(marker, pos)) != -1) {
                // Check this is preceded by "*(TYPE *)" — look backward for "*("
                int pre = pos - 1;
                while (pre >= 0 && result[pre] == ' ') pre--;
                if (pre < 0 || result[pre] != ')') { pos++; continue; }
                // Find the matching content after ((char *)
                int inner = pos + marker.size();
                // Scan forward to find the balanced closing )) for ((char *)EXPR)
                int depth = 1; // we're inside the outer ( of ((char *)
                int end = inner;
                bool hasPlus = false;
                while (end < result.size() && depth > 0) {
                    if (result[end] == '(') depth++;
                    else if (result[end] == ')') depth--;
                    else if (result[end] == '+' && depth == 1) hasPlus = true;
                    if (depth > 0) end++;
                }
                // end is at the closing ) that matches the outer (
                if (hasPlus || depth != 0) { pos++; continue; }
                // Remove "(char *)" (8 chars) from pos+1
                result.remove(pos + 1, 8);
                // If result now has double-paren "((EXPR))", remove one pair
                if (pos + 1 < result.size() && result[pos] == '(' && result[pos+1] == '(') {
                    result.remove(pos, 1); // remove extra opening paren
                    // Find and remove the matching extra closing paren
                    int d = 0;
                    for (int k = pos; k < result.size(); ++k) {
                        if (result[k] == '(') d++;
                        else if (result[k] == ')') {
                            d--;
                            if (d == 0) { result.remove(k, 1); break; }
                        }
                    }
                }
                // Don't advance pos — re-check in case of nested patterns
            }
            // Replace __builtin intrinsics with standard library names
            result.replace("__builtin_memcmp", "memcmp");
            result.replace("__builtin_memcpy", "memcpy");
            result.replace("__builtin_memset", "memset");
            // Strip redundant truncation casts in assignments: "field = (short)(expr)" → "field = expr"
            // The assignment to a narrower field does implicit truncation in C
            for (auto &cast : {"= (short)(", "= (unsigned char)(", "= (char)("}) {
                QString qc = QString(cast);
                int pos = 0;
                while ((pos = result.indexOf(qc, pos)) != -1) {
                    int castStart = pos + 2; // skip "= "
                    int innerStart = castStart + qc.size() - 2; // position after "(short)("
                    // Find matching close paren
                    int depth = 1;
                    int end = innerStart;
                    while (end < result.size() && depth > 0) {
                        if (result[end] == '(') depth++;
                        else if (result[end] == ')') depth--;
                        end++;
                    }
                    // end is just past the closing )
                    // Replace "= (short)(EXPR)" with "= EXPR"
                    if (depth == 0) {
                        // Remove the cast wrapper and trailing )
                        result.remove(end - 1, 1); // remove closing )
                        result.remove(castStart, qc.size() - 2); // remove "(short)("
                        continue;
                    }
                    pos++;
                }
            }
        }
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
                            char buf[256];
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
            buildCosmeticTypeMap();
        }

        QString generate(StructNode *root) {
            QString out;

            // Function signature
            std::string retType = "int";
            // In port mode, trust STABS return type to avoid conflicting types
            // with the types header prototype. Void heuristic can disagree.
            if (m_func.detectedVoid && !s_portMode)
                retType = "void";
            else if (m_func.returnType != NullType)
                retType = m_types.formatType(m_func.returnType);

            // In port mode, skip "static" to avoid conflicts with types header
            std::string qual = (m_func.isStatic && !s_portMode) ? "static " : "";
            std::string funcName = cName(m_func.name);
            out += QString::fromStdString(qual + retType) + " " +
                   QString::fromStdString(funcName) + "(";

            if (!m_func.params.empty()) {
                for (size_t i = 0; i < m_func.params.size(); ++i) {
                    if (i) out += ", ";
                    auto &p = m_func.params[i];
                    std::string decl;
                    if (p.typeRef != NullType) {
                        // Small structs (≤4 bytes) passed by value are equivalent
                        // to int on x86. Use int to avoid invalid C like
                        // "(unsigned)(struct_var)" when the code treats it as int.
                        auto *pt = m_types.resolveType(p.typeRef);
                        if (pt && pt->kind == StabsTypeKind::Struct &&
                            pt->sizeBytes > 0 && pt->sizeBytes <= 4) {
                            decl = "int " + p.name;
                        } else {
                            decl = m_types.formatDecl(p.typeRef, p.name);
                            // Strip const from non-pointer params — decompiler may
                            // reassign them. Keep const on pointer params to match
                            // the types header prototype.
                            if (decl.find("const ") == 0 && decl.find('*') == std::string::npos)
                                decl = decl.substr(6);
                        }
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
                    // Replace void (non-pointer) with int — can't have void locals
                    if (decl.substr(0, 5) == "void " && decl.find('*') == std::string::npos)
                        decl = "int " + l.name;
                    // In port mode, replace struct/union by-value locals with int
                    // (decompiler uses int for all scalar values; struct types leak from inference)
                    if (s_portMode) {
                        auto *lt = m_types.resolveType(l.typeRef);
                        if (lt && (lt->kind == StabsTypeKind::Struct || lt->kind == StabsTypeKind::Union) &&
                            decl.find('*') == std::string::npos)
                            decl = "int " + l.name;
                    }
                } else {
                    decl = "int " + l.name;
                }
                // Override int → char* for locals used as pointers
                if (m_pointerVars.count(l.name) && decl == "int " + l.name)
                    decl = "char *" + l.name;
                out += "    " + QString::fromStdString(decl) + ";\n";
            }

            // Collect goto targets and emitted blocks BEFORE declaring temps
            std::set<int> emittedBlocks;
            collectGotoTargets(root, m_gotoTargets);
            collectEmittedBlocks(root, emittedBlocks);

            // Find temps AND vars used as pointers (dereferenced in Load/Store)
            auto markPointer = [&](const IRExpr *e) {
                if (!e) return;
                if (e->op == IROp::Temp) m_pointerTemps.insert(e->tempId());
                if (e->op == IROp::Var && !e->name.empty()) m_pointerVars.insert(e->name);
            };
            for (auto &bb : m_func.blocks)
                for (auto &stmt : bb.stmts) {
                    // Store: addr is the pointer being dereferenced
                    if (stmt.kind == IRStmtKind::Store && stmt.addr) {
                        markPointer(stmt.addr.get());
                        for (auto &k : stmt.addr->kids)
                            if (k) markPointer(k.get());
                    }
                    // Load expressions with Temp/Var address
                    auto checkLoadPtrs = [&](const IRExpr *e) {
                        if (!e) return;
                        std::vector<const IRExpr *> stack = {e};
                        while (!stack.empty()) {
                            auto *n = stack.back(); stack.pop_back();
                            if (n->op == IROp::Load && !n->kids.empty() && n->kids[0]) {
                                auto *addr = n->kids[0].get();
                                markPointer(addr);
                                // Also check Add(base, offset) and Add(base, Mul(idx, scale))
                                if (addr->op == IROp::Add && !addr->kids.empty()) {
                                    markPointer(addr->kids[0].get());
                                    // Array subscript: Add(base, Mul(idx, scale))
                                    for (int side = 0; side < 2 && addr->kids.size() == 2; ++side) {
                                        auto *maybeIdx = addr->kids[side].get();
                                        auto *maybeBase = addr->kids[1-side].get();
                                        if (maybeIdx && maybeIdx->op == IROp::Mul)
                                            markPointer(maybeBase);
                                    }
                                }
                            }
                            for (auto &k : n->kids) if (k) stack.push_back(k.get());
                        }
                    };
                    checkLoadPtrs(stmt.expr.get());
                    checkLoadPtrs(stmt.addr.get());
                    for (auto &a : stmt.args) checkLoadPtrs(a.get());
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
                        else {
                            // Check if ANY temp in the coalesced group is a pointer
                            bool anyPointer = m_pointerTemps.count(id) > 0 ||
                                              m_func.pointerTemps.count(id) > 0;
                            if (!anyPointer && vit != m_func.tempToVar.end()) {
                                for (auto &[t2, v2] : m_func.tempToVar)
                                    if (v2 == vit->second &&
                                        (m_pointerTemps.count(t2) || m_func.pointerTemps.count(t2)))
                                        { anyPointer = true; break; }
                            }
                            if (anyPointer && ttype == "int")
                                ttype = "char *";
                        }
                    }
                    // Strip const from temp declarations (temps are always assignable)
                    if (ttype.substr(0, 6) == "const ") ttype = ttype.substr(6);
                    // Replace void (non-pointer) with int — can't have void locals
                    if (ttype == "void") ttype = "int";
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
            // Detect variables that should be short: ALL assignments have Trunc16 cast
            std::map<std::string, int> varTrunc16;  // name → count of Trunc16 assigns
            std::map<std::string, int> varAnyAssign; // name → count of any assigns
            for (auto &bb : m_func.blocks) {
                for (auto &stmt : bb.stmts) {
                    if (stmt.kind == IRStmtKind::VarSet && !stmt.destVar.empty() && stmt.expr) {
                        varAnyAssign[stmt.destVar]++;
                        if (stmt.expr->op == IROp::Cast &&
                            stmt.expr->castKind == CastKind::Trunc16)
                            varTrunc16[stmt.destVar]++;
                    }
                }
            }
            for (auto &name : synthVars) {
                if (declared.count(name) || paramNames.count(name)) continue;
                declared.insert(name);
                // If ALL assignments to this var use Trunc16, declare as short
                bool isShort = (varTrunc16.count(name) && varAnyAssign.count(name) &&
                                varTrunc16[name] == varAnyAssign[name] && varTrunc16[name] > 0);
                if (isShort)
                    out += "    short " + QString::fromStdString(name) + ";\n";
                else if (m_pointerVars.count(name))
                    out += "    char *" + QString::fromStdString(name) + ";\n";
                else
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

        // Flat (goto-based) code generation: uses the structured mode's
        // declarations + signature, but emits basic blocks in address order
        // with explicit goto/if-goto. This preserves the original's block layout.
        QString generateFlat(StructNode *root) {
            // First, generate the structured output to get proper declarations
            QString structOut = generate(root);
            // Extract everything up to and including the opening brace + declarations
            // Then replace the body with flat blocks
            int bodyStart = structOut.indexOf("{\n") + 2;
            // Find where declarations end (first line that's not a declaration or blank)
            QStringList lines = structOut.split('\n');
            int declEnd = 0;
            bool pastBrace = false;
            for (int i = 0; i < lines.size(); ++i) {
                if (lines[i].trimmed() == "{") { pastBrace = true; continue; }
                if (!pastBrace) continue;
                QString t = lines[i].trimmed();
                if (t.isEmpty()) { declEnd = i + 1; continue; }
                // Declaration patterns
                if (t.startsWith("int ") || t.startsWith("float ") || t.startsWith("char ") ||
                    t.startsWith("char *") || t.startsWith("void *") || t.startsWith("const ") ||
                    t.startsWith("register ") || t.startsWith("unsigned ") ||
                    t.startsWith("playerState_t") || t.startsWith("qboolean") ||
                    t.startsWith("struct ") || t.startsWith("vec_t") || t.startsWith("vec3_t") ||
                    t.startsWith("OSStatus") || t.startsWith("Str255") || t.startsWith("MenuRef") ||
                    t.startsWith("WindowRef") || t.startsWith("UInt32") || t.startsWith("size_t") ||
                    t.startsWith("CGDirect") || t.startsWith("dvar_t") || t.startsWith("Bool") ||
                    t.startsWith("byte ") || t.startsWith("cmd_function_t") ||
                    t.startsWith("DObjAnimMat") || t.startsWith("XModel") || t.startsWith("short ")) {
                    declEnd = i + 1;
                    continue;
                }
                break;
            }
            // Build output: signature + declarations + flat body
            QString out;
            for (int i = 0; i < declEnd && i < lines.size(); ++i)
                out += lines[i] + "\n";
            // Helper: resolve a return expression through temp assignments.
            // If "return TEMP" and TEMP was assigned EXPR in the same block, return EXPR.
            auto resolveReturnExpr = [&](const BasicBlock &bb, int retIdx) -> std::string {
                auto &retStmt = bb.stmts[retIdx];
                if (!retStmt.expr) return "";
                std::string retStr = emitExpr(retStmt.expr.get());
                if (retStmt.expr->op == IROp::Temp && retIdx > 0) {
                    auto &prev = bb.stmts[retIdx - 1];
                    if (prev.kind == IRStmtKind::Assign &&
                        prev.destTemp == retStmt.expr->tempId() && prev.expr) {
                        return emitExpr(prev.expr.get());
                    }
                }
                return retStr;
            };
            // Find canonical return blocks: blocks that end with a Return,
            // preceded only by assignments (no side effects).
            // Other blocks returning the same value can use "goto bb_X" instead,
            // allowing the compiler to share the return path (tail merge).
            std::map<std::string, int> canonicalReturn; // return expr string → block ID
            for (int bbId = 0; bbId < (int)m_func.blocks.size(); ++bbId) {
                auto &bb = m_func.blocks[bbId];
                if (bb.stmts.empty()) continue;
                auto &lastStmt = bb.stmts.back();
                if (lastStmt.kind != IRStmtKind::Return) continue;
                bool onlyAssigns = true;
                for (int si = 0; si < (int)bb.stmts.size() - 1; ++si) {
                    if (bb.stmts[si].kind != IRStmtKind::Assign) {
                        onlyAssigns = false; break;
                    }
                }
                if (!onlyAssigns) continue;
                int retIdx = (int)bb.stmts.size() - 1;
                std::string retExpr = resolveReturnExpr(bb, retIdx);
                if (!canonicalReturn.count(retExpr))
                    canonicalReturn[retExpr] = bbId;
            }
            // Emit flat blocks in DFS order so GCC sees natural code flow.
            // This prevents the optimizer from eliminating "unreachable" blocks
            // that are actually reachable via gotos from later blocks.
            std::vector<int> blockOrder;
            {
                int n = (int)m_func.blocks.size();
                std::vector<bool> visited(n, false);
                std::vector<int> stack;
                stack.push_back(0);
                while (!stack.empty()) {
                    int bbId = stack.back();
                    stack.pop_back();
                    if (bbId < 0 || bbId >= n || visited[bbId]) continue;
                    visited[bbId] = true;
                    blockOrder.push_back(bbId);
                    // Push successors (reverse order for DFS left-first)
                    auto &bb = m_func.blocks[bbId];
                    std::vector<int> succs;
                    for (auto &s : bb.stmts) {
                        if (s.kind == IRStmtKind::Branch) {
                            succs.push_back(s.falseTarget);
                            succs.push_back(s.trueTarget);
                        } else if (s.kind == IRStmtKind::Jump) {
                            succs.push_back(s.jumpTarget);
                        }
                    }
                    for (auto it = succs.rbegin(); it != succs.rend(); ++it)
                        stack.push_back(*it);
                }
                // Add any remaining unvisited blocks
                for (int i = 0; i < n; ++i)
                    if (!visited[i]) blockOrder.push_back(i);
            }
            for (int bbId : blockOrder) {
                auto &bb = m_func.blocks[bbId];
                out += QString("bb_%1:\n").arg(bbId);
                for (int si = 0; si < (int)bb.stmts.size(); ++si) {
                    auto &stmt = bb.stmts[si];
                    if (stmt.kind == IRStmtKind::Branch) {
                        std::string cond = stmt.expr ? emitExpr(stmt.expr.get()) : "1";
                        // Simplify constant branches to plain gotos
                        if (cond == "1" || cond == "(1)") {
                            out += QString("    goto bb_%1;\n").arg(stmt.trueTarget);
                        } else if (cond == "0" || cond == "(0)") {
                            out += QString("    goto bb_%1;\n").arg(stmt.falseTarget);
                        } else {
                            out += QString("    if (%1) goto bb_%2; else goto bb_%3;\n")
                                .arg(QString::fromStdString(cond))
                                .arg(stmt.trueTarget).arg(stmt.falseTarget);
                        }
                    } else if (stmt.kind == IRStmtKind::Jump) {
                        out += QString("    goto bb_%1;\n").arg(stmt.jumpTarget);
                    } else if (stmt.kind == IRStmtKind::Return) {
                        // Check if return can be redirected to a canonical return block
                        std::string resolved = resolveReturnExpr(bb, si);
                        auto cit = canonicalReturn.find(resolved);
                        if (cit != canonicalReturn.end() && cit->second != bbId) {
                            out += QString("    goto bb_%1;\n").arg(cit->second);
                        } else {
                            if (stmt.expr) {
                                // If the return value is a call to a void function,
                                // split into call + bare return
                                bool isVoidCall = isVoidCallExpr(stmt.expr.get());
                                if (isVoidCall) {
                                    out += "    " + QString::fromStdString(emitExpr(stmt.expr.get())) + ";\n";
                                    out += "    return;\n";
                                } else {
                                    out += "    return " + QString::fromStdString(emitExpr(stmt.expr.get())) + ";\n";
                                }
                            } else {
                                out += "    return;\n";
                            }
                        }
                    } else {
                        // Skip assignments to temps that feed into a redirected return
                        bool skipForReturn = false;
                        if (stmt.kind == IRStmtKind::Assign && si + 1 < (int)bb.stmts.size()) {
                            auto &next = bb.stmts[si + 1];
                            if (next.kind == IRStmtKind::Return && next.expr &&
                                next.expr->op == IROp::Temp && next.expr->tempId() == stmt.destTemp) {
                                std::string resolved = resolveReturnExpr(bb, si + 1);
                                auto cit = canonicalReturn.find(resolved);
                                if (cit != canonicalReturn.end() && cit->second != bbId)
                                    skipForReturn = true;
                            }
                        }
                        if (!skipForReturn)
                            emitStmt(out, stmt, 1);
                    }
                }
            }
            // Post-pass: find any undeclared variables in the flat body and add declarations.
            {
                std::set<std::string> declared, used;
                std::string outStr = out.toStdString();
                // Find all identifiers that look like variable names
                // (vNNN, tNNN, var_XX, wavelet*, bb_N labels are excluded)
                auto scanIdents = [](const std::string &s, std::set<std::string> &out) {
                    for (size_t i = 0; i < s.size(); ++i) {
                        if (!isalpha(s[i]) && s[i] != '_') continue;
                        if (i > 0 && (isalnum(s[i-1]) || s[i-1] == '_')) continue;
                        size_t start = i;
                        while (i < s.size() && (isalnum(s[i]) || s[i] == '_')) i++;
                        std::string word = s.substr(start, i - start);
                        // Only track vN, tN patterns (synthetic temp names)
                        if ((word[0] == 'v' || word[0] == 't') && word.size() > 1 &&
                            isdigit(word[1])) {
                            out.insert(word);
                        }
                    }
                };
                // Find declarations
                for (auto &line : out.split('\n')) {
                    QString t = line.trimmed();
                    if (t.startsWith("int ") || t.startsWith("float ") || t.startsWith("char ") ||
                        t.startsWith("byte ") || t.startsWith("short ") || t.startsWith("unsigned ") ||
                        t.startsWith("DWORD ") || t.startsWith("const ") || t.startsWith("struct ")) {
                        scanIdents(t.toStdString(), declared);
                    }
                }
                // Find all references
                scanIdents(outStr, used);
                // Add missing declarations
                QString decls;
                for (auto &v : used) {
                    if (!declared.count(v))
                        decls += "    int " + QString::fromStdString(v) + ";\n";
                }
                if (!decls.isEmpty()) {
                    int insertPos = out.indexOf("\nbb_");
                    if (insertPos >= 0) out.insert(insertPos + 1, decls);
                }
            }

            // Fix float→int: if a variable is declared float but used in
            // bitwise/shift operations (>>, <<, &, |, ^), redeclare as int.
            {
                QStringList oLines = out.split('\n');
                for (int li = 0; li < oLines.size(); ++li) {
                    QString t = oLines[li].trimmed();
                    if (!t.startsWith("float ") && !t.startsWith("byte ")) continue;
                    // Extract variable name
                    int semi = t.indexOf(';');
                    if (semi < 0) continue;
                    QString typePart = t.startsWith("float ") ? "float " : "byte ";
                    QString varName = t.mid(typePart.size(), semi - typePart.size()).trimmed();
                    if (varName.isEmpty()) continue;
                    // Check if this var is used in bitwise/shift ops
                    bool usedInBitwise = false;
                    for (int lj = li + 1; lj < oLines.size(); ++lj) {
                        if (oLines[lj].contains(varName + " >>") || oLines[lj].contains(varName + " <<") ||
                            oLines[lj].contains(varName + " &") || oLines[lj].contains(varName + " |") ||
                            oLines[lj].contains(varName + " ^") ||
                            oLines[lj].contains(varName + ") >>") || oLines[lj].contains(varName + ") <<")) {
                            usedInBitwise = true;
                            break;
                        }
                    }
                    if (usedInBitwise) {
                        oLines[li].replace(typePart + varName, "int " + varName);
                    }
                }
                out = oLines.join('\n');
            }

            out += "}\n";
            return out;
        }

    private:
        const MachOFile      &m_mf;
        IRFunc               &m_func;
        const StabsTypeTable &m_types;
        std::map<int, int>    m_tempUseCount;
        std::map<int, IRExpr*> m_tempDef;
        std::set<std::string> m_interiorPtrVars; // vars assigned from AddrOf(Field) — interior pointers
        std::set<int>         m_copyPropagated; // temps eliminated by copy prop
        // Copy prop: temp → replacement name
        std::map<int, std::string> m_copyMap;
        // Const prop: temp → constant value
        std::map<int, int64_t> m_constMap;
        std::set<int>         m_gotoTargets;    // block IDs that are goto targets
        std::set<int>         m_emittedLabels;  // labels already emitted (avoid duplicates)
        std::set<std::pair<int,int>> m_suppressedStmts; // (blockId, stmtIdx) to skip in emission
        std::set<int>         m_pointerTemps;   // temps used as pointers (dereference targets)
        std::set<std::string> m_pointerVars;   // var NAMES used as pointers
        std::map<int, TypeRef> m_tempStructPtr;   // temp → struct pointer type (from Field access)
        std::set<int>         m_forceDeclareTemps; // temps that leak as raw tN and need declaration
        std::set<int>         m_inliningTemps;    // cycle guard for temp inlining in emitExpr
        int                   m_addrDepth = 0;     // >0 when emitting Load/Store address sub-exprs
        std::set<int>         m_loadAddrTemps;    // temps used in Load address expressions
        std::map<int, TypeRef> m_cosmeticTypes;    // cosmetic: inferred types for temps/vars
        std::map<std::string, TypeRef> m_cosmeticVarTypes; // cosmetic: inferred types for named vars

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
            // Find temps with non-constant assignments (loop-updated)
            std::set<int> hasNonConstAssign;
            // Find temps with multiple definitions (defined in more than one block)
            std::map<int, int> tempDefBlock;  // temp → first defining block
            std::set<int> multiDefTemps;      // temps defined in multiple blocks
            for (auto &bb : m_func.blocks)
                for (auto &stmt : bb.stmts) {
                    if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0) {
                        if (stmt.expr && !stmt.expr->isConst())
                            hasNonConstAssign.insert(stmt.destTemp);
                        auto it = tempDefBlock.find(stmt.destTemp);
                        if (it == tempDefBlock.end())
                            tempDefBlock[stmt.destTemp] = bb.id;
                        else if (it->second != bb.id)
                            multiDefTemps.insert(stmt.destTemp);
                    }
                }

            for (auto &bb : m_func.blocks) {
                for (auto &stmt : bb.stmts) {
                    if (stmt.kind != IRStmtKind::Assign) continue;
                    if (!stmt.expr) continue;
                    // t = var → replace all uses of t with var
                    // BUT skip phi temps (they have loop-updated values too)
                    if (stmt.expr->op == IROp::Var &&
                        !m_func.phiTemps.count(stmt.destTemp) &&
                        !multiDefTemps.count(stmt.destTemp)) {
                        m_copyMap[stmt.destTemp] = stmt.expr->name;
                        m_copyPropagated.insert(stmt.destTemp);
                    }
                    // t = otherTemp → propagate temp name (but not phi temps or multi-defs)
                    if (stmt.expr->op == IROp::Temp &&
                        !m_func.phiTemps.count(stmt.destTemp) &&
                        !multiDefTemps.count(stmt.destTemp)) {
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
            // Track variables assigned from AddrOf (interior pointers into structs)
            if (stmt.kind == IRStmtKind::VarSet && stmt.expr &&
                stmt.expr->op == IROp::AddrOf && !stmt.expr->kids.empty() &&
                stmt.expr->kids[0]->op == IROp::Field) {
                m_interiorPtrVars.insert(stmt.destVar);
            }
            // Also for Assign→Temp→VarSet chain
            if (stmt.kind == IRStmtKind::Assign && stmt.expr &&
                stmt.expr->op == IROp::AddrOf && !stmt.expr->kids.empty() &&
                stmt.expr->kids[0]->op == IROp::Field) {
                m_interiorPtrVars.insert("__temp_" + std::to_string(stmt.destTemp));
            }
            // Track variables used as struct pointer bases in Load/Store field access
            // This ensures they get declared as pointers, not int
            {
                // Helper: mark a base expression as a pointer
                auto markAsPointer = [&](IRExpr *base) {
                    if (!base) return;
                    if (base->op == IROp::Var && !base->name.empty())
                        m_pointerVars.insert(base->name);
                    if (base->op == IROp::Temp)
                        m_pointerTemps.insert(base->tempId());
                };
                // Store address analysis
                if (stmt.kind == IRStmtKind::Store && stmt.addr) {
                    auto *a = stmt.addr.get();
                    // Store(Add(base, const), val) - pointer arithmetic store
                    if (a->op == IROp::Add && a->kids.size() == 2 && a->kids[1]->isConst())
                        markAsPointer(a->kids[0].get());
                    // Store(Add(base, Mul(idx, scale)), val) - array subscript store
                    if (a->op == IROp::Add && a->kids.size() == 2) {
                        for (int side = 0; side < 2; ++side) {
                            auto *maybeIdx = a->kids[side].get();
                            auto *maybeBase = a->kids[1-side].get();
                            if (maybeIdx && maybeIdx->op == IROp::Mul)
                                markAsPointer(maybeBase);
                        }
                    }
                    // Store(Field(base, ...), val) - struct field store
                    if (a->op == IROp::Field && !a->kids.empty())
                        markAsPointer(a->kids[0].get());
                    // Store(Var/Temp, val) - bare pointer dereference
                    markAsPointer(a);
                }
                // Load address analysis (in expressions)
                std::function<void(IRExpr*)> scanLoads = [&](IRExpr *e) {
                    if (!e) return;
                    if (e->op == IROp::Load && !e->kids.empty()) {
                        auto *loadAddr = e->kids[0].get();
                        if (loadAddr) {
                            if (loadAddr->op == IROp::Add && loadAddr->kids.size() == 2 &&
                                loadAddr->kids[1]->isConst())
                                markAsPointer(loadAddr->kids[0].get());
                            // Load(Add(base, Mul(idx, scale))) - array subscript load
                            if (loadAddr->op == IROp::Add && loadAddr->kids.size() == 2) {
                                for (int side = 0; side < 2; ++side) {
                                    auto *mi = loadAddr->kids[side].get();
                                    auto *mb = loadAddr->kids[1-side].get();
                                    if (mi && mi->op == IROp::Mul)
                                        markAsPointer(mb);
                                }
                            }
                            if (loadAddr->op == IROp::Field && !loadAddr->kids.empty())
                                markAsPointer(loadAddr->kids[0].get());
                        }
                    }
                    for (auto &k : e->kids) scanLoads(k.get());
                };
                if (stmt.expr) scanLoads(stmt.expr.get());
                if (stmt.addr) scanLoads(stmt.addr.get());
            }
            // Also catch Add(structPtr, const) patterns — these are LEA instructions
            // that create pointers into the middle of a struct (e.g., &ent->r.origin).
            // The emitter renders them as &base->field, but the IR has Add(base, const).
            {
                auto *expr = (stmt.kind == IRStmtKind::Assign || stmt.kind == IRStmtKind::VarSet)
                             ? stmt.expr.get() : nullptr;
                if (expr && expr->op == IROp::Add && expr->kids.size() == 2 &&
                    expr->kids[1]->isConst() && expr->kids[1]->value > 0 &&
                    expr->kids[1]->value < 0x10000 &&
                    (expr->kids[0]->op == IROp::Var || expr->kids[0]->op == IROp::Temp)) {
                    TypeRef baseType = NullType;
                    if (expr->kids[0]->op == IROp::Temp) {
                        int bt = expr->kids[0]->tempId();
                        baseType = m_func.tempType(bt);
                    } else if (expr->kids[0]->typeRef != NullType) {
                        baseType = expr->kids[0]->typeRef;
                    }
                    if (baseType != NullType && m_types.isStructPointer(baseType)) {
                        if (stmt.kind == IRStmtKind::VarSet)
                            m_interiorPtrVars.insert(stmt.destVar);
                        else if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0)
                            m_interiorPtrVars.insert("__temp_" + std::to_string(stmt.destTemp));
                    }
                }
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
                if (!condTrue && !condFalse && !hasElse && !s_cosmeticMode) {
                    bool isSimpleZeroCheck = false;
                    for (auto &sfx : {" != 0", " == 0", " > 0", " <= 0"}) {
                        size_t len = strlen(sfx);
                        if (cond.size() >= len &&
                            cond.compare(cond.size() - len, len, sfx) == 0) {
                            isSimpleZeroCheck = true; break;
                        }
                    }
                    if (isSimpleZeroCheck) {
                        if (node->negated)
                            cond = "__builtin_expect(" + cond + ", 1)";
                        // Non-negated "== 0" conditions: these are typically
                        // error/init checks where the == 0 path is unlikely.
                        // Mark as unlikely to match the original's forward-branch-not-taken.
                        else if (cond.find("== 0") != std::string::npos)
                            cond = "__builtin_expect(" + cond + ", 0)";
                    }
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
                // When header statements are hoisted into the body, emit as:
                //   while(1) { header_stmts; if (!cond) break; body; }
                // This preserves correct execution order (body before condition).
                if (node->whileHasHeaderStmts && !node->children.empty() &&
                    node->children[0]->kind == StructKind::Block &&
                    node->children[0]->children.size() >= 2) {
                    out += pad(indent) + "while (1) {\n";
                    // Emit first child of wrapper (header statements)
                    emitNode(out, node->children[0]->children[0].get(), indent + 1);
                    // Emit break condition
                    std::string breakCond = node->cond ?
                        emitExpr(node->cond, !node->negated) : "0";
                    out += pad(indent + 1) + "if (" +
                           QString::fromStdString(breakCond) + ") break;\n";
                    // Emit remaining body children
                    for (size_t ci = 1; ci < node->children[0]->children.size(); ++ci)
                        emitNode(out, node->children[0]->children[ci].get(), indent + 1);
                    out += pad(indent) + "}\n";
                } else {
                    out += pad(indent) + "while (" + QString::fromStdString(cond) + ") {\n";
                    for (auto &child : node->children)
                        emitNode(out, child.get(), indent + 1);
                    out += pad(indent) + "}\n";
                }
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
                    if (retStmt && allEmpty) {
                        // Only inline return if all preceding statements are empty
                        // (no Stores, Calls, or other side-effects before the Return)
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
                // When storing from an array variable, use [0] to get first element
                if (stmt.expr && stmt.expr->op == IROp::Var && stmt.expr->typeRef != NullType) {
                    auto *vti = m_types.resolveType(stmt.expr->typeRef);
                    if (vti && vti->kind == StabsTypeKind::Array)
                        val += "[0]";
                }
                if (!stmt.addr) break;
                auto *a = stmt.addr.get();
                struct AddrGuard { int &d; AddrGuard(int &d):d(d){d++;} ~AddrGuard(){d--;} } _ag(m_addrDepth);
                std::string storeCast = "int";
                if (stmt.storeSize == 1) storeCast = "char";
                else if (stmt.storeSize == 2) storeCast = "short";
                else if (stmt.storeSize == 5) storeCast = "float";
                else if (stmt.storeSize == 9) storeCast = "double";
                // Field expression → base->field = val
                if (a->op == IROp::Field) {
                    // Check if the Field base is an interior pointer (temp from Add(structPtr, const)).
                    // If so, fold back to the original struct base with combined offset.
                    // e.g., v8 = &ent->r.origin → v8.field = X becomes ent->r.origin_field = X
                    bool folded = false;
                    if (!a->kids.empty() && a->kids[0]->op == IROp::Temp) {
                        auto dit = m_tempDef.find(a->kids[0]->tempId());
                        if (dit != m_tempDef.end() && dit->second &&
                            dit->second->op == IROp::Add && dit->second->kids.size() == 2 &&
                            dit->second->kids[1]->isConst() && dit->second->kids[1]->value > 0) {
                            // Fold: base = original struct ptr, offset = inner + field
                            auto *origBase = dit->second->kids[0].get();
                            int innerOff = (int)dit->second->kids[1]->value;
                            int fieldOff = (int)a->value;
                            int combinedOff = innerOff + fieldOff;
                            TypeRef origType = exprType(origBase);
                            if (origType != NullType && m_types.isStructPointer(origType)) {
                                TypeRef structRef = m_types.getPointedStruct(origType);
                                std::string access = structRef != NullType ?
                                    m_types.formatFieldAccess(structRef, combinedOff) : "";
                                if (!access.empty()) {
                                    std::string origStr = emitExpr(origBase);
                                    out += pad(indent) + QString::fromStdString(
                                        origStr + "->" + access + " = " + val) + ";\n";
                                    folded = true;
                                }
                            }
                            if (!folded) {
                                // Can't resolve field — use raw pointer arithmetic on original base
                                std::string origStr = emitExpr(origBase);
                                char buf[512];
                                snprintf(buf, sizeof(buf), "*(%s *)((char *)%s + 0x%X) = %s",
                                         storeCast.c_str(), origStr.c_str(), (unsigned)combinedOff, val.c_str());
                                out += pad(indent) + QString::fromStdString(buf) + ";\n";
                                folded = true;
                            }
                        }
                    }
                    if (!folded) {
                        out += pad(indent) + QString::fromStdString(emitExpr(a) + " = " + val) + ";\n";
                    }
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
                        TypeRef baseType = s_cosmeticMode ? safeExprType(a->kids[0].get())
                                                          : exprType(a->kids[0].get());
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
                            const StabsTypeInfo *target = nullptr;
                            if (bt && bt->kind == StabsTypeKind::Pointer) {
                                target = m_types.resolveType(bt->targetType);
                            } else if (bt && bt->kind == StabsTypeKind::Array) {
                                // Array param (e.g. vec3_t = float[3]) → use array notation
                                target = m_types.resolveType(bt->targetType);
                            }
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
                    if (!usedArrayNotation) {
                        // Try to fold interior pointers back to original struct base.
                        // When base temp = Add(structPtr, innerOff), fold to structPtr->(innerOff+off)
                        bool foldedInterior = false;
                        if (a->kids[0]->op == IROp::Temp) {
                            auto dit = m_tempDef.find(a->kids[0]->tempId());
                            if (dit != m_tempDef.end() && dit->second &&
                                dit->second->op == IROp::Add && dit->second->kids.size() == 2 &&
                                dit->second->kids[1]->isConst() && dit->second->kids[1]->value > 0) {
                                auto *origBase = dit->second->kids[0].get();
                                int innerOff = (int)dit->second->kids[1]->value;
                                int combinedOff = innerOff + off;
                                TypeRef origType = exprType(origBase);
                                if (origType != NullType && m_types.isStructPointer(origType)) {
                                    TypeRef structRef = m_types.getPointedStruct(origType);
                                    std::string access = structRef != NullType ?
                                        m_types.formatFieldAccess(structRef, combinedOff) : "";
                                    if (!access.empty()) {
                                        std::string origStr = emitExpr(origBase);
                                        out += pad(indent) + QString::fromStdString(
                                            origStr + "->" + access + " = " + val) + ";\n";
                                        foldedInterior = true;
                                    }
                                }
                            }
                        }
                        if (foldedInterior) { /* done */ }
                        else {
                        // Try type-aware struct field access
                        // Skip for interior pointers (vars from &struct->field)
                        TypeRef stBaseType = s_cosmeticMode ? safeExprType(a->kids[0].get())
                                                            : exprType(a->kids[0].get());
                        bool stIsInterior = false;
                        if (a->kids[0]->op == IROp::Var && !a->kids[0]->name.empty())
                            stIsInterior = m_interiorPtrVars.count(a->kids[0]->name) > 0;
                        else if (a->kids[0]->op == IROp::Temp) {
                            int tid = a->kids[0]->tempId();
                            stIsInterior = m_interiorPtrVars.count("__temp_" + std::to_string(tid)) > 0;
                            if (!stIsInterior) {
                                auto dit = m_tempDef.find(tid);
                                if (dit != m_tempDef.end() && dit->second &&
                                    dit->second->op == IROp::Add && dit->second->kids.size() == 2 &&
                                    dit->second->kids[1]->isConst() &&
                                    dit->second->kids[1]->value > 0) {
                                    stIsInterior = true;
                                }
                            }
                        }
                        std::string access;
                        if (!stIsInterior && stBaseType != NullType && m_types.isStructPointer(stBaseType)) {
                            TypeRef structRef = m_types.getPointedStruct(stBaseType);
                            if (structRef != NullType)
                                access = m_types.formatFieldAccess(structRef, off);
                            // Validate: don't resolve to bare large struct field
                            if (!access.empty() && access.find('.') == std::string::npos &&
                                access.find('[') == std::string::npos) {
                                auto *field = m_types.findFieldAtOffset(structRef, off);
                                if (field && field->typeRef != NullType) {
                                    auto *ft = m_types.resolveType(field->typeRef);
                                    if (ft && (ft->kind == StabsTypeKind::Struct ||
                                               ft->kind == StabsTypeKind::Union) && ft->sizeBytes > 4)
                                        access.clear();
                                }
                            }
                        }
                        if (!access.empty()) {
                            // For NLP temps (Temp defined as Load(Var)), use global name directly
                            std::string fieldBase = base;
                            if (s_cosmeticMode && a->kids[0]->op == IROp::Temp) {
                                auto dit = m_tempDef.find(a->kids[0]->tempId());
                                if (dit != m_tempDef.end() && dit->second &&
                                    dit->second->op == IROp::Load && !dit->second->kids.empty() &&
                                    dit->second->kids[0]->op == IROp::Var)
                                    fieldBase = dit->second->kids[0]->name;
                            }
                            out += pad(indent) + QString::fromStdString(
                                fieldBase + "->" + access + " = " + val) + ";\n";
                        } else {
                            char buf[512];
                            snprintf(buf, sizeof(buf), "*(%s *)((char *)%s + 0x%X) = %s",
                                     storeCast.c_str(), base.c_str(), (unsigned)off, val.c_str());
                            out += pad(indent) + QString::fromStdString(buf) + ";\n";
                        }
                    } // else (not foldedInterior)
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
                        // Mark base as pointer (used in array subscript)
                        if (storeBase->op == IROp::Var && !storeBase->name.empty())
                            m_pointerVars.insert(storeBase->name);
                        else if (storeBase->op == IROp::Temp)
                            m_pointerTemps.insert(storeBase->tempId());
                        std::string bs = emitExpr(storeBase);
                        std::string is = emitExpr(storeIdx);
                        out += pad(indent) + QString::fromStdString(bs + "[" + is + "] = " + val) + ";\n";
                    } else if (storeBase && storeIdx) {
                        std::string bs = emitExpr(storeBase);
                        std::string is = emitExpr(storeIdx);
                        out += pad(indent) + QString::fromStdString(
                            "*(" + storeCast + " *)((char *)" + bs + " + " + is + " * " + std::to_string(storeScale) + ") = " + val) + ";\n";
                    } else {
                        // No Mul pattern found — emit general pointer store
                        out += pad(indent) + QString::fromStdString(
                            "*(" + storeCast + " *)((char *)(" + emitExpr(a) + ")) = " + val) + ";\n";
                    }
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
                    // Try to resolve field name from struct type
                    std::string fieldAccess;
                    TypeRef stBaseType = exprType(a->kids[0]->kids[0].get());
                    if (stBaseType != NullType && m_types.isStructPointer(stBaseType)) {
                        TypeRef structRef = m_types.getPointedStruct(stBaseType);
                        if (structRef != NullType)
                            fieldAccess = m_types.formatFieldAccess(structRef, off);
                    }
                    if (!fieldAccess.empty()) {
                        size_t bracket = fieldAccess.find('[');
                        if (bracket != std::string::npos && fieldAccess.substr(bracket) == "[0]")
                            fieldAccess = fieldAccess.substr(0, bracket);
                        out += pad(indent) + QString::fromStdString(
                            base + "->" + fieldAccess + "[" + idx + "] = " + val) + ";\n";
                    } else {
                        TypeRef stType = exprType(a->kids[0]->kids[0].get());
                        if (stType != NullType && m_types.isStructPointer(stType)) {
                            char fname[64]; snprintf(fname, sizeof(fname), "arr_%X[%s]", (unsigned)off, idx.c_str());
                            out += pad(indent) + QString::fromStdString(
                                base + "->" + fname + " = " + val) + ";\n";
                        } else {
                            int sc = (int)a->kids[0]->kids[1]->kids[1]->value;
                            out += pad(indent) + QString::fromStdString(
                                "*(" + storeCast + " *)((char *)(" + base + ") + " + idx +
                                " * " + std::to_string(sc) + " + " + std::to_string(off) +
                                ") = " + val) + ";\n";
                        }
                    }
                }
                // General Add/Sub expression → *(type *)((char *)(expr)) = val
                else if ((a->op == IROp::Add || a->op == IROp::Sub) && a->kids.size() == 2) {
                    // Cosmetic: try struct field resolution for Add(base, const)
                    bool resolved = false;
                    if (s_cosmeticMode && a->op == IROp::Add && a->kids.size() == 2) {
                        // Determine which child is the const offset and which is the base
                        IRExpr *base0 = nullptr;
                        int off = 0;
                        if (a->kids[1]->isConst() && a->kids[1]->value > 0) {
                            base0 = a->kids[0].get(); off = (int)a->kids[1]->value;
                        } else if (a->kids[0]->isConst() && a->kids[0]->value > 0) {
                            base0 = a->kids[1].get(); off = (int)a->kids[0]->value;
                        }
                        // Find the base variable name: Var, Temp→Var, Load(Var) for NLP,
                        // or Temp→Load(Var) for NLP through temp
                        std::string gname;
                        if (base0->op == IROp::Var) gname = base0->name;
                        else if (base0->op == IROp::Temp) {
                            auto dit = m_tempDef.find(base0->tempId());
                            if (dit != m_tempDef.end() && dit->second) {
                                if (dit->second->op == IROp::Var)
                                    gname = dit->second->name;
                                else if (dit->second->op == IROp::Load && !dit->second->kids.empty() &&
                                         dit->second->kids[0]->op == IROp::Var)
                                    gname = dit->second->kids[0]->name;
                            }
                        }
                        else if (base0->op == IROp::Load && !base0->kids.empty() &&
                                 base0->kids[0]->op == IROp::Var)
                            gname = base0->kids[0]->name;
                        if (!gname.empty()) {
                            auto *gn = m_types.globalByName(gname);
                            if (gn && gn->typeRef != NullType && m_types.isStructPointer(gn->typeRef)) {
                                TypeRef structRef = m_types.getPointedStruct(gn->typeRef);
                                if (structRef != NullType) {
                                    std::string access = m_types.formatFieldAccess(structRef, off);
                                    if (!access.empty()) {
                                        out += pad(indent) + QString::fromStdString(
                                            gname + "->" + access + " = " + val) + ";\n";
                                        resolved = true;
                                    }
                                }
                            }
                        }
                    }
                    if (!resolved)
                        out += pad(indent) + QString::fromStdString(
                            "*(" + storeCast + " *)((char *)(" + emitExpr(a) + ")) = " + val) + ";\n";
                }
                else if (a->op == IROp::Var || a->op == IROp::Temp) {
                    std::string addrS = emitExpr(a);
                    TypeRef at = s_cosmeticMode ? safeExprType(a) : exprType(a);
                    auto *atInfo = (at != NullType) ? m_types.resolveType(at) : nullptr;
                    if (atInfo && atInfo->kind == StabsTypeKind::Pointer) {
                        auto *tgt = m_types.resolveType(atInfo->targetType);
                        if (s_cosmeticMode && stmt.storeSize == 4) {
                            // Cosmetic: store to pointer var = simple assignment
                            out += pad(indent) + QString::fromStdString(
                                addrS + " = " + val) + ";\n";
                        } else if (tgt && tgt->sizeBytes > 0 && tgt->sizeBytes <= 8 &&
                            tgt->kind != StabsTypeKind::Struct &&
                            tgt->kind != StabsTypeKind::Union) {
                            out += pad(indent) + QString::fromStdString(
                                addrS + "[0] = " + val) + ";\n";
                        } else if (tgt && (tgt->kind == StabsTypeKind::Struct ||
                                           tgt->kind == StabsTypeKind::Union)) {
                            // Struct pointer at offset 0: use first field name
                            std::string field0 = m_types.formatFieldAccess(atInfo->targetType, 0);
                            if (!field0.empty())
                                out += pad(indent) + QString::fromStdString(
                                    addrS + "->" + field0 + " = " + val) + ";\n";
                            else
                                out += pad(indent) + QString::fromStdString(
                                    "*(" + storeCast + " *)(" + addrS + ") = " + val) + ";\n";
                        } else {
                            out += pad(indent) + QString::fromStdString(
                                "*(" + storeCast + " *)(" + addrS + ") = " + val) + ";\n";
                        }
                    } else if (atInfo && atInfo->kind == StabsTypeKind::Array) {
                        // Array at offset 0: arr[0] = val
                        out += pad(indent) + QString::fromStdString(
                            addrS + "[0] = " + val) + ";\n";
                    } else if (atInfo && (atInfo->kind == StabsTypeKind::Struct ||
                                           atInfo->kind == StabsTypeKind::Union)) {
                        // Struct/union at offset 0: *(type *)(&var) = val
                        out += pad(indent) + QString::fromStdString(
                            "*(" + storeCast + " *)(&" + addrS + ") = " + val) + ";\n";
                    } else {
                        out += pad(indent) + QString::fromStdString(
                            "*(" + storeCast + " *)((char *)(" + addrS + ")) = " + val) + ";\n";
                    }
                } else {
                    std::string addrS = emitExpr(a);
                    out += pad(indent) + QString::fromStdString(
                        "*(" + storeCast + " *)((char *)(" + addrS + ")) = " + val) + ";\n";
                }
                break;
            }
            case IRStmtKind::VarSet: {
                std::string val = stmt.expr ? emitExpr(stmt.expr.get()) : "0";
                // Array var as value source → add [0] (only for direct Vars, not temps)
                if (stmt.expr && stmt.expr->op == IROp::Var && stmt.expr->typeRef != NullType) {
                    auto *vsti = m_types.resolveType(stmt.expr->typeRef);
                    if (vsti && vsti->kind == StabsTypeKind::Array) val += "[0]";
                }
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
                {
                    TypeRef destTypeRef = stmt.destType;
                    // Fallback: check global type by name
                    if (destTypeRef == NullType) {
                        auto *g = m_types.globalByName(stmt.destVar);
                        if (g) destTypeRef = g->typeRef;
                    }
                    // Fallback: check local type
                    if (destTypeRef == NullType) {
                        for (auto &l : m_func.locals)
                            if (l.name == stmt.destVar && l.typeRef != NullType)
                                { destTypeRef = l.typeRef; break; }
                    }
                if (destTypeRef != NullType) {
                    auto *dt = m_types.resolveType(destTypeRef);
                    if (dt && dt->kind == StabsTypeKind::Array)
                        dest += "[0]";
                    // If dest is a struct/union and value is a scalar, cast the store
                    // But respect storeSize — sub-word stores need proper width cast
                    if (dt && (dt->kind == StabsTypeKind::Struct || dt->kind == StabsTypeKind::Union) &&
                        stmt.storeSize != 2 && stmt.storeSize != 1) {
                        if (s_cosmeticMode) {
                            // Cosmetic: simple assignment for readability
                            out += pad(indent) + QString::fromStdString(
                                cName(dest) + " = " + val) + ";\n";
                        } else {
                            out += pad(indent) + QString::fromStdString(
                                "*(int *)(&" + cName(dest) + ") = (int)" + val) + ";\n";
                        }
                        break;
                    }
                }
                } // end array/struct type check
                // For sub-word stores (16-bit/8-bit), use pointer cast to force
                // the correct store width: *(short *)(&dest) = val
                if (s_cosmeticMode && (stmt.storeSize == 2 || stmt.storeSize == 1)) {
                    // Cosmetic: simple assignment for readability
                    out += pad(indent) + QString::fromStdString(
                        cName(dest) + " = " + val) + ";\n";
                } else if (stmt.storeSize == 2) {
                    out += pad(indent) + QString::fromStdString(
                        "*(short *)(&" + cName(dest) + ") = " + val) + ";\n";
                } else if (stmt.storeSize == 1) {
                    out += pad(indent) + QString::fromStdString(
                        "*(char *)(&" + cName(dest) + ") = " + val) + ";\n";
                } else {
                    // Check if source is a struct/union variable — cast to int
                    bool srcIsStruct = false;
                    if (stmt.expr && stmt.expr->op == IROp::Var && !stmt.expr->name.empty()) {
                        auto *g = m_types.globalByName(stmt.expr->name);
                        TypeRef stype = stmt.expr->typeRef;
                        if (stype == NullType && g) stype = g->typeRef;
                        if (stype != NullType) {
                            auto *st = m_types.resolveType(stype);
                            std::string sname = m_types.formatType(stype);
                            if ((st && (st->kind == StabsTypeKind::Struct ||
                                        st->kind == StabsTypeKind::Union)) ||
                                sname.find("struct ") == 0 || sname.find("union ") == 0)
                                srcIsStruct = true;
                        }
                    }
                    if (srcIsStruct)
                        out += pad(indent) + QString::fromStdString(
                            cName(dest) + " = *(int *)(&" + val + ")") + ";\n";
                    else
                        out += pad(indent) + QString::fromStdString(cName(dest) + " = " + val) + ";\n";
                }
                break;
            }
            case IRStmtKind::Call: {
                std::string call = stmt.expr ? emitExpr(stmt.expr.get()) : "()";
                out += pad(indent) + QString::fromStdString(call) + ";\n";
                break;
            }
            case IRStmtKind::Return: {
                if (stmt.expr) {
                    // Check if the return value is a call to a void function
                    bool isVoidCall = isVoidCallExpr(stmt.expr.get());
                    std::string val = emitExpr(stmt.expr.get());
                    if (isVoidCall) {
                        out += pad(indent) + QString::fromStdString(val) + ";\n";
                        out += pad(indent) + "return;\n";
                    } else {
                        out += pad(indent) + "return " + QString::fromStdString(val) + ";\n";
                    }
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
        // Get the cast type name for a Load based on its access size
        static const char* loadCastType(int loadSize) {
            switch (loadSize) {
            case 1: return "unsigned char";
            case 2: return "unsigned short";
            case 5: return "float";   // special: 4-byte float load (from SSE)
            case 9: return "double";  // special: 8-byte double load
            default: return "int";
            }
        }

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
                    // If phi temp has no variable name, try to inherit from its
                    // source temp (the pre-loop value it was assigned from)
                    auto dit = m_tempDef.find(id);
                    if (dit != m_tempDef.end() && dit->second &&
                        dit->second->op == IROp::Temp) {
                        int srcId = dit->second->tempId();
                        auto svit = m_func.tempToVar.find(srcId);
                        if (svit != m_func.tempToVar.end()) {
                            auto snit = m_func.varNames.find(svit->second);
                            if (snit != m_func.varNames.end())
                                return snit->second;
                        }
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
                std::string vn = e->name;
                if (!vn.empty() && (isdigit(vn[0]) || vn[0] == '-' || vn[0] == '"' || vn[0] == '('))
                    result = vn;
                else
                    result = cName(vn);
                break;
            }
            case IROp::String: result = e->name; break;
            case IROp::FuncRef: result = e->name; break;

            case IROp::Load: {
                auto *addr = e->kids[0].get();
                struct LoadDepthGuard { int &d; LoadDepthGuard(int &d):d(d){d++;} ~LoadDepthGuard(){d--;} } _ldg(m_addrDepth);
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
                        // Try to resolve the field name from struct type info
                        std::string fieldAccess;
                        TypeRef baseType = exprType(base);
                        if (baseType != NullType && m_types.isStructPointer(baseType)) {
                            TypeRef structRef = m_types.getPointedStruct(baseType);
                            if (structRef != NullType)
                                fieldAccess = m_types.formatFieldAccess(structRef, off);
                        }
                        if (!fieldAccess.empty()) {
                            // Check if this is base[idx].field pattern:
                            // elemSize matches struct size → array of structs
                            TypeRef structRef2 = NullType;
                            if (baseType != NullType && m_types.isStructPointer(baseType))
                                structRef2 = m_types.getPointedStruct(baseType);
                            auto *structInfo = structRef2 != NullType ? m_types.resolveType(structRef2) : nullptr;
                            if (structInfo && structInfo->sizeBytes > 0 &&
                                elemSize == structInfo->sizeBytes) {
                                // Array of structs: base[idx].field
                                result = baseStr + "[" + idxStr + "]." + fieldAccess;
                            } else {
                                // Scalar field with dynamic subscript
                                size_t bracket = fieldAccess.find('[');
                                if (bracket != std::string::npos &&
                                    fieldAccess.substr(bracket) == "[0]")
                                    fieldAccess = fieldAccess.substr(0, bracket);
                                result = baseStr + "->" + fieldAccess + "[" + idxStr + "]";
                            }
                        } else {
                            // Only use ->arr_XX when base is a struct pointer
                            if (baseType != NullType && m_types.isStructPointer(baseType)) {
                                char fname[64];
                                if (elemSize == 4)
                                    snprintf(fname, sizeof(fname), "arr_%X[%s]", (unsigned)off, idxStr.c_str());
                                else
                                    snprintf(fname, sizeof(fname), "arr_%X_%d[%s]", (unsigned)off, elemSize, idxStr.c_str());
                                result = baseStr + "->" + fname;
                            } else {
                                // Non-struct base: use raw pointer arithmetic
                                result = std::string("*(") + loadCastType(e->loadSize) +
                                    " *)((char *)(" + baseStr + ") + " + idxStr + " * " +
                                    std::to_string(elemSize) + " + " + std::to_string(off) + ")";
                            }
                        }
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
                            // Mark the base as a pointer (used in array subscript)
                            if (arrBase->op == IROp::Var && !arrBase->name.empty())
                                m_pointerVars.insert(arrBase->name);
                            else if (arrBase->op == IROp::Temp)
                                m_pointerTemps.insert(arrBase->tempId());
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
                    (addr->kids[0]->op == IROp::Var || addr->kids[0]->op == IROp::Temp ||
                     addr->kids[0]->op == IROp::Load)) {
                    std::string base = emitExpr(addr->kids[0].get());
                    int64_t off = (int64_t)addr->kids[1]->value;
                    // Try folding interior pointers back to original struct base
                    if (addr->kids[0]->op == IROp::Temp) {
                        auto dit = m_tempDef.find(addr->kids[0]->tempId());
                        if (dit != m_tempDef.end() && dit->second &&
                            dit->second->op == IROp::Add && dit->second->kids.size() == 2 &&
                            dit->second->kids[1]->isConst() && dit->second->kids[1]->value > 0) {
                            auto *origBase = dit->second->kids[0].get();
                            int innerOff = (int)dit->second->kids[1]->value;
                            int combinedOff = innerOff + (int)off;
                            TypeRef origType = exprType(origBase);
                            if (origType != NullType && m_types.isStructPointer(origType)) {
                                TypeRef structRef = m_types.getPointedStruct(origType);
                                std::string access = structRef != NullType ?
                                    m_types.formatFieldAccess(structRef, combinedOff) : "";
                                if (!access.empty()) {
                                    std::string origStr = emitExpr(origBase);
                                    char buf[256];
                                    snprintf(buf, sizeof(buf), "*(%s *)((char *)%s + 0x%llX)",
                                             loadCastType(e->loadSize), origStr.c_str(),
                                             (unsigned long long)combinedOff);
                                    result = origStr + "->" + access;
                                    break;
                                }
                            }
                        }
                    }
                    // Try type-aware struct field access
                    TypeRef baseType = s_cosmeticMode ? safeExprType(addr->kids[0].get())
                                                      : exprType(addr->kids[0].get());
                    // For untyped expressions, try resolving type from STABS globals.
                    // Handles two patterns:
                    //   Load(Add(Var("global_ptr"), offset)) → global_ptr->field
                    //   Load(Add(Load(Var("global_ptr")), offset)) → (*global_ptr)->field (NLP)
                    // Also try when baseType doesn't resolve (e.g. invalid (0,0) refs from NLP globals)
                    if (baseType == NullType || (s_cosmeticMode && !m_types.resolveType(baseType))) {
                        // Walk through temp defs and loads to find the source global name
                        IRExpr *src = addr->kids[0].get();
                        // Follow temp chain (up to 3 levels)
                        for (int depth = 0; depth < 3 && src; ++depth) {
                            if (src->op == IROp::Temp) {
                                auto dit = m_tempDef.find(src->tempId());
                                if (dit != m_tempDef.end() && dit->second)
                                    src = dit->second;
                                else break;
                            } else break;
                        }
                        // Extract global name
                        std::string gname;
                        if (src && src->op == IROp::Var && !src->name.empty())
                            gname = src->name;
                        else if (src && src->op == IROp::Load && !src->kids.empty()) {
                            // Load(Var) = dereference of a global pointer
                            IRExpr *inner = src->kids[0].get();
                            for (int d = 0; d < 3 && inner && inner->op == IROp::Temp; ++d) {
                                auto dit = m_tempDef.find(inner->tempId());
                                if (dit != m_tempDef.end() && dit->second)
                                    inner = dit->second;
                                else break;
                            }
                            if (inner && inner->op == IROp::Var && !inner->name.empty())
                                gname = inner->name;
                        }
                        if (!gname.empty()) {
                            auto *gn = m_types.globalByName(gname);
                            if (gn && gn->typeRef != NullType) {
                                auto *gt = m_types.resolveType(gn->typeRef);
                                if (gt && gt->kind == StabsTypeKind::Pointer) {
                                    baseType = gn->typeRef;
                                }
                            }
                        }
                    }
                    // Skip struct field resolution for interior pointers
                    // (vars assigned from &struct->field — they point into the middle)
                    bool isInterior = false;
                    if (addr->kids[0]->op == IROp::Var && !addr->kids[0]->name.empty())
                        isInterior = m_interiorPtrVars.count(addr->kids[0]->name) > 0;
                    else if (addr->kids[0]->op == IROp::Temp)
                        isInterior = m_interiorPtrVars.count("__temp_" + std::to_string(addr->kids[0]->tempId())) > 0;
                    // Also check if baseType is a struct directly (from Load through pointer, e.g. NLP globals)
                    bool isDirectStruct = false;
                    TypeRef structRef = NullType;
                    if (baseType != NullType && m_types.isStructPointer(baseType) && !isInterior) {
                        structRef = m_types.getPointedStruct(baseType);
                    } else if (baseType != NullType && !isInterior) {
                        auto *bt = m_types.resolveType(baseType);
                        if (bt && (bt->kind == StabsTypeKind::Struct || bt->kind == StabsTypeKind::Union)) {
                            structRef = baseType;
                            isDirectStruct = true;
                        }
                    }
                    if (structRef != NullType) {
                        std::string access =
                            m_types.formatFieldAccess(structRef, (int)off);
                        // Debug: trace incorrect field resolution
                        if (!access.empty()) {
                            // Check if the resolved field makes sense for this access:
                            // 1. Subscript on non-array field is wrong
                            if (access.find("[") != std::string::npos &&
                                access.find("arr_") == std::string::npos)
                                access.clear();
                            // 2. Accessing a struct/union field as a scalar read is wrong
                            //    (e.g., entity->s where s is entityState_t but we're loading 4 bytes)
                            if (!access.empty() && access.find('.') == std::string::npos &&
                                access.find('[') == std::string::npos) {
                                auto *field = m_types.findFieldAtOffset(structRef, (int)off);
                                if (field && field->typeRef != NullType) {
                                    auto *ft = m_types.resolveType(field->typeRef);
                                    if (ft && (ft->kind == StabsTypeKind::Struct ||
                                               ft->kind == StabsTypeKind::Union) &&
                                        ft->sizeBytes > 4)
                                        access.clear();
                                    // Also skip large array fields
                                    if (ft && ft->kind == StabsTypeKind::Array) {
                                        int arrSz = ft->sizeBytes;
                                        if (arrSz <= 0) {
                                            auto *et = m_types.resolveType(ft->targetType);
                                            int ec = ft->arrayHigh - ft->arrayLow + 1;
                                            if (et && ec > 0) arrSz = et->sizeBytes * ec;
                                        }
                                        if (arrSz > 4) access.clear();
                                    }
                                }
                            }
                        }
                        if (!access.empty()) {
                            if (isDirectStruct && addr->kids[0]->op == IROp::Load &&
                                !addr->kids[0]->kids.empty()) {
                                // Base is Load(expr) giving a struct — use expr->field directly
                                // This turns Load(Add(Load(Var("ptr")), off)) into ptr->field
                                std::string ptrBase = emitExpr(addr->kids[0]->kids[0].get());
                                result = ptrBase + "->" + access;
                            } else if (s_cosmeticMode && !isDirectStruct && addr->kids[0]->op == IROp::Temp) {
                                // Cosmetic: Check if temp is defined as Load(Var) — NLP double deref
                                // Use the original pointer name: ptr->field instead of *(int*)(ptr)->field
                                auto dit = m_tempDef.find(addr->kids[0]->tempId());
                                if (dit != m_tempDef.end() && dit->second &&
                                    dit->second->op == IROp::Load && !dit->second->kids.empty() &&
                                    dit->second->kids[0]->op == IROp::Var) {
                                    result = dit->second->kids[0]->name + "->" + access;
                                } else {
                                    result = base + "->" + access;
                                }
                            } else {
                                result = base + (isDirectStruct ? "." : "->") + access;
                            }
                        }
                    }
                    if (result.empty()) {
                        // Check if base is a struct/union (needs &)
                        std::string baseRef = base;
                        TypeRef bt = exprType(addr->kids[0].get());
                        if (bt != NullType) {
                            auto *bti = m_types.resolveType(bt);
                            std::string btName = m_types.formatType(bt);
                            if ((bti && (bti->kind == StabsTypeKind::Struct ||
                                         bti->kind == StabsTypeKind::Union)) ||
                                btName.find("struct ") == 0 || btName.find("union ") == 0)
                                baseRef = "&" + base;
                        }
                        char buf[256];
                        snprintf(buf, sizeof(buf), "*(%s *)((char *)%s + 0x%llX)",
                                 loadCastType(e->loadSize), baseRef.c_str(), (unsigned long long)off);
                        result = buf;
                    }
                }
                // General Add/Sub expression → *(int *)((char *)(expr))
                else if (addr && (addr->op == IROp::Add || addr->op == IROp::Sub) &&
                         addr->kids.size() == 2) {
                    result = std::string("*(") + loadCastType(e->loadSize) + " *)((char *)(" + emitExpr(addr) + "))";
                }
                // bare pointer dereference of a simple var/temp: Load(Var) = *var
                // For pointer types, this just reads the pointer value — no field access.
                // Field access only happens at Load(Add(Var, Const(offset))) above.
                else if (addr && (addr->op == IROp::Var || addr->op == IROp::Temp)) {
                    TypeRef addrType = s_cosmeticMode ? safeExprType(addr) : exprType(addr);
                    if (addrType != NullType) {
                        auto *at = m_types.resolveType(addrType);
                        if (at && at->kind == StabsTypeKind::Pointer) {
                            auto *tgt = m_types.resolveType(at->targetType);
                            // Simple scalar pointer (int*, float*): var[0] notation
                            if (tgt && tgt->sizeBytes > 0 && tgt->sizeBytes <= 8 &&
                                tgt->kind != StabsTypeKind::Struct &&
                                tgt->kind != StabsTypeKind::Union &&
                                tgt->kind != StabsTypeKind::Pointer)
                                result = emitExpr(addr) + "[0]";
                            else if (tgt && (tgt->kind == StabsTypeKind::Struct ||
                                             tgt->kind == StabsTypeKind::Union)) {
                                // Struct pointer at offset 0: use first field name
                                std::string field0 = m_types.formatFieldAccess(at->targetType, 0);
                                std::string base = emitExpr(addr);
                                if (!field0.empty())
                                    result = base + "->" + field0;
                                else
                                    result = "*(" + base + ")";
                            } else
                                result = "*(" + emitExpr(addr) + ")";
                        } else if (at && at->kind == StabsTypeKind::Array) {
                            // Array variable at offset 0: arr[0]
                            result = emitExpr(addr) + "[0]";
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
                // Cast through (char *) to handle int→pointer and const→pointer safely
                // Skip when result already has a proper type cast from Load emission
                if (!result.empty() && result[0] == '*' && result.find("*(int *)") != 0 &&
                    result.find("*(char *)") != 0 && result.find("*(short *)") != 0 &&
                    result.find("*(float *)") != 0 && result.find("*(double *)") != 0 &&
                    result.find("*(unsigned char *)") != 0 &&
                    result.find("*(unsigned short *)") != 0) {
                    std::string addrStr = emitExpr(addr);
                    TypeRef addrT = exprType(addr);
                    bool isPtr = false;
                    bool isAggregate = false;
                    if (addrT != NullType) {
                        auto *rt = m_types.resolveType(addrT);
                        isPtr = rt && rt->kind == StabsTypeKind::Pointer;
                        isAggregate = rt && (rt->kind == StabsTypeKind::Struct ||
                                             rt->kind == StabsTypeKind::Union ||
                                             rt->kind == StabsTypeKind::Array);
                    }
                    const char *lct = loadCastType(e->loadSize);
                    if (isPtr)
                        result = std::string("*(") + lct + " *)(" + addrStr + ")";
                    else if (isAggregate)
                        result = std::string("*(") + lct + " *)(&" + addrStr + ")";
                    else
                        result = std::string("*(") + lct + " *)((char *)(" + addrStr + "))";
                }
                // m_addrDepth decremented by LoadDepthGuard RAII
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
                    // For array variables, &array == array (same address)
                    // Skip the & to avoid producing float(*)[3] instead of float*
                    bool isArray = false;
                    if (inner && inner->op == IROp::Var && !inner->name.empty()) {
                        TypeRef vt = exprType(inner);
                        if (vt != NullType) {
                            auto *vti = m_types.resolveType(vt);
                            isArray = vti && vti->kind == StabsTypeKind::Array;
                        }
                    }
                    if (isArray)
                        result = emitExpr(inner);
                    else
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
                    result = std::string("*(") + loadCastType(e->loadSize) + " *)((char *)(" + base + ") + " + std::to_string(off) + ")";
                } else {
                    // Use -> for pointer-to-struct, . for struct-by-value
                    TypeRef baseType = e->kids[0] ? exprType(e->kids[0].get()) : NullType;
                    bool useArrow = true;
                    if (baseType != NullType) {
                        auto *bt = m_types.resolveType(baseType);
                        if (bt && (bt->kind == StabsTypeKind::Struct || bt->kind == StabsTypeKind::Union))
                            useArrow = false;  // struct-by-value: use dot
                    }
                    result = base + (useArrow ? "->" : ".") + e->name;
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
                // (base + const) in expression context → &base->field_XX (pointer base)
                // or ((char *)&base + offset) (struct base)
                if (e->op == IROp::Add && e->kids[1] && e->kids[1]->isConst() &&
                    e->kids[1]->value > 0 && e->kids[1]->value < 0x10000 &&
                    (e->kids[0]->op == IROp::Var || e->kids[0]->op == IROp::Temp)) {
                    if (!lhs.empty() && (isalpha(lhs[0]) || lhs[0] == '_')) {
                        int off = (int)e->kids[1]->value;
                        TypeRef baseType = exprType(e->kids[0].get());
                        // Also check global type
                        if (baseType == NullType && e->kids[0]->op == IROp::Var &&
                            !e->kids[0]->name.empty()) {
                            auto *g = m_types.globalByName(e->kids[0]->name);
                            if (g) baseType = g->typeRef;
                        }
                        std::string access;
                        bool isPtr = false;
                        bool isStruct = false;
                        if (baseType != NullType) {
                            if (m_types.isStructPointer(baseType)) {
                                isPtr = true;
                                TypeRef structRef = m_types.getPointedStruct(baseType);
                                if (structRef != NullType)
                                    access = m_types.formatFieldAccess(structRef, off);
                            } else {
                                auto *bt = m_types.resolveType(baseType);
                                std::string btName = m_types.formatType(baseType);
                                if ((bt && (bt->kind == StabsTypeKind::Struct ||
                                            bt->kind == StabsTypeKind::Union)) ||
                                    btName.find("struct ") == 0 || btName.find("union ") == 0) {
                                    isStruct = true;
                                    access = m_types.formatFieldAccess(baseType, off);
                                }
                            }
                        }
                        if (isPtr) {
                            if (!access.empty())
                                result = "&" + lhs + "->" + access;
                            else {
                                char fname[32]; snprintf(fname, sizeof(fname), "field_%X", (unsigned)off);
                                result = "&" + lhs + "->" + fname;
                            }
                            break;
                        } else if (isStruct) {
                            if (!access.empty())
                                result = "&" + lhs + "." + access;
                            else
                                result = "((char *)&" + lhs + " + " + std::to_string(off) + ")";
                            break;
                        }
                        // Not a struct/pointer base — fall through to other handlers
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
                // Helper: resolve temp to its definition for pattern matching
                auto resolveToLoad = [&](IRExpr *expr) -> IRExpr* {
                    if (!expr) return expr;
                    if (expr->op == IROp::Temp) {
                        auto it = m_tempDef.find(expr->tempId());
                        if (it != m_tempDef.end() && it->second)
                            return it->second;
                    }
                    return expr;
                };
                // SSE fabsf pattern: And(val, Load(mask_addr)) where mask=0x7FFFFFFF
                if (e->op == IROp::And) {
                    auto checkFabsMask = [&](IRExpr *maskExpr) -> bool {
                        if (!maskExpr) return false;
                        maskExpr = resolveToLoad(maskExpr);
                        // Load(Const(addr)) where *addr == 0x7FFFFFFF
                        if (maskExpr->op == IROp::Load && !maskExpr->kids.empty()) {
                            auto *addrExpr = resolveToLoad(maskExpr->kids[0].get());
                            if (addrExpr && addrExpr->isConst()) {
                                uint32_t addr = (uint32_t)addrExpr->value;
                                int64_t fo = m_mf.fileOffsetForAddress(addr);
                                if (fo >= 0) {
                                    const uint8_t *p = m_mf.bytesAt((uint32_t)fo, 4);
                                    uint32_t val = p ? *(const uint32_t*)p : 0;
                                    return val == 0x7FFFFFFF;
                                }
                            }
                        }
                        // Direct constant 0x7FFFFFFF
                        if (maskExpr->isConst() && (uint32_t)maskExpr->value == 0x7FFFFFFF)
                            return true;
                        return false;
                    };
                    // Check both operand orders: And(val, mask) or And(mask, val)
                    if (e->kids.size() == 2) {
                        if (checkFabsMask(e->kids[1].get())) {
                            result = "fabsf(" + lhs + ")"; break;
                        }
                        if (checkFabsMask(e->kids[0].get())) {
                            result = "fabsf(" + rhs + ")"; break;
                        }
                    }
                }
                // SSE negation pattern: Xor(val, Load(mask_addr)) where mask=0x80000000
                if (e->op == IROp::Xor) {
                    auto checkNegMask = [&](IRExpr *maskExpr) -> bool {
                        if (!maskExpr) return false;
                        maskExpr = resolveToLoad(maskExpr);
                        if (maskExpr->op == IROp::Load && !maskExpr->kids.empty()) {
                            auto *addrExpr = resolveToLoad(maskExpr->kids[0].get());
                            if (addrExpr && addrExpr->isConst()) {
                                uint32_t addr = (uint32_t)addrExpr->value;
                                int64_t fo = m_mf.fileOffsetForAddress(addr);
                                if (fo >= 0) {
                                    const uint8_t *p = m_mf.bytesAt((uint32_t)fo, 4);
                                    uint32_t val = p ? *(const uint32_t*)p : 0;
                                    return val == 0x80000000;
                                }
                            }
                        }
                        if (maskExpr->isConst() && (uint32_t)maskExpr->value == 0x80000000)
                            return true;
                        return false;
                    };
                    if (e->kids.size() == 2) {
                        if (checkNegMask(e->kids[1].get())) {
                            result = "(-(" + lhs + "))"; break;
                        }
                        if (checkNegMask(e->kids[0].get())) {
                            result = "(-(" + rhs + "))"; break;
                        }
                    }
                }
                std::string op;
                switch (e->op) {
                case IROp::Add:  op = " + "; break;
                case IROp::Sub:  op = " - "; break;
                case IROp::Mul:  op = " * "; break;
                case IROp::SDiv: case IROp::UDiv: op = " / "; break;
                case IROp::SMod: case IROp::UMod: op = " % "; break;
                case IROp::Shl:  op = " << "; break;
                case IROp::Sar: op = " >> "; break;
                case IROp::Shr:  op = " >> "; break; // handled below with unsigned cast
                case IROp::And:  op = " & "; break;
                case IROp::Or: {
                    // Use logical || when both sides are comparisons (boolean context)
                    bool lhsBool = e->kids[0] && (e->kids[0]->op >= IROp::Eq && e->kids[0]->op <= IROp::Uge);
                    bool rhsBool = e->kids[1] && (e->kids[1]->op >= IROp::Eq && e->kids[1]->op <= IROp::Uge);
                    op = (lhsBool && rhsBool) ? " || " : " | ";
                    break;
                }
                case IROp::Xor:  op = " ^ "; break;
                default: op = " + "; break;
                }
                if (e->op == IROp::Shr || e->op == IROp::Sar) {
                    // Check if operand is float (SSE bit manipulation pattern)
                    bool lhsFloat = isFloatExpr(e->kids[0].get());
                    if (!lhsFloat) {
                        // Also check if lhs string matches a float param/local name
                        // Use formatType (not resolveType) to handle typedefs named "float"
                        for (auto &p : m_func.params)
                            if (cName(p.name) == lhs && p.typeRef != NullType) {
                                std::string ts = m_types.formatType(p.typeRef);
                                if (ts == "float" || ts == "double")
                                    lhsFloat = true;
                            }
                        if (!lhsFloat) {
                            for (auto &l : m_func.locals)
                                if (cName(l.name) == lhs && l.typeRef != NullType) {
                                    std::string ts = m_types.formatType(l.typeRef);
                                    if (ts == "float" || ts == "double")
                                        lhsFloat = true;
                                }
                        }
                    }
                    if (lhsFloat)
                        result = "((unsigned)(int)(" + lhs + ") >> " + rhs + ")";
                    else if (e->op == IROp::Shr)
                        result = "((unsigned)(" + lhs + ") >> " + rhs + ")";
                    else
                        result = "(" + lhs + op + rhs + ")";
                } else if (e->op == IROp::Add) {
                    // When adding to an address-of or struct/array expression,
                    // cast to (char*) to prevent pointer arithmetic scaling.
                    // Returns 0=no cast, 1=has & already, 2=struct/union/array (needs &)
                    auto needsCast = [&](const std::string &s, IRExpr *kid) -> int {
                        if (s.find("&") != std::string::npos) return 1;
                        // Check if the operand is a struct/array typed variable
                        if (kid && kid->op == IROp::Var) {
                            // Check IR type annotation
                            TypeRef kidType = kid->typeRef;
                            if (kidType != NullType) {
                                auto *t = m_types.resolveType(kidType);
                                if (t && (t->kind == StabsTypeKind::Struct ||
                                          t->kind == StabsTypeKind::Union ||
                                          t->kind == StabsTypeKind::Array))
                                    return 2;
                            }
                            // Check params, locals, and globals by name
                            if (!kid->name.empty()) {
                                TypeRef found = NullType;
                                for (auto &p : m_func.params)
                                    if (p.name == kid->name && p.typeRef != NullType)
                                        { found = p.typeRef; break; }
                                if (found == NullType)
                                    for (auto &l : m_func.locals)
                                        if (l.name == kid->name && l.typeRef != NullType)
                                            { found = l.typeRef; break; }
                                if (found == NullType) {
                                    auto *g = m_types.globalByName(kid->name);
                                    if (g) found = g->typeRef;
                                }
                                if (found != NullType) {
                                    auto *t = m_types.resolveType(found);
                                    if (t && (t->kind == StabsTypeKind::Struct ||
                                              t->kind == StabsTypeKind::Union ||
                                              t->kind == StabsTypeKind::Array))
                                        return 2;
                                }
                            }
                        }
                        return 0;
                    };
                    int lhsCast = needsCast(lhs, e->kids[0].get());
                    int rhsCast = needsCast(rhs, e->kids[1].get());
                    if (lhsCast)
                        result = "(" + rhs + " + (char*)" + (lhsCast == 2 ? "&" : "") + lhs + ")";
                    else if (rhsCast)
                        result = "(" + lhs + " + (char*)" + (rhsCast == 2 ? "&" : "") + rhs + ")";
                    else
                        result = "(" + lhs + op + rhs + ")";
                } else if ((e->op == IROp::And || e->op == IROp::Or || e->op == IROp::Xor ||
                            e->op == IROp::Shr || e->op == IROp::Sar || e->op == IROp::Shl) &&
                           e->kids[0] && e->kids[1] &&
                           // Only for actual float operands, NOT comparisons
                           !(e->kids[0]->op >= IROp::Eq && e->kids[0]->op <= IROp::Uge) &&
                           !(e->kids[1]->op >= IROp::Eq && e->kids[1]->op <= IROp::Uge) &&
                           (isFloatExpr(e->kids[0].get()) || isFloatExpr(e->kids[1].get()))) {
                    // Float bitwise/shift: cast operands to int (SSE bit manipulation)
                    result = "((int)(" + lhs + ")" + op + "(int)(" + rhs + "))";
                } else {
                    result = "(" + lhs + op + rhs + ")";
                }
                break;
            }

            case IROp::Eq: case IROp::Ne:
            case IROp::Slt: case IROp::Sle: case IROp::Sgt: case IROp::Sge:
            case IROp::Ult: case IROp::Ule: case IROp::Ugt: case IROp::Uge: {
                std::string lhs = emitExpr(e->kids[0].get());
                std::string rhs = emitExpr(e->kids[1].get());
                // Array-typed Vars in arithmetic should use [0] (first element)
                auto fixArrayVar = [&](std::string &s, IRExpr *kid) {
                    if (!kid) return;
                    IRExpr *src = kid;
                    // Follow temp → Var chain (only through simple Var definitions)
                    for (int d = 0; d < 3 && src && src->op == IROp::Temp; ++d) {
                        auto dit = m_tempDef.find(src->tempId());
                        if (dit != m_tempDef.end() && dit->second &&
                            dit->second->op == IROp::Var)
                            src = dit->second;
                        else break;
                    }
                    // Only use the Var's own typeRef (not exprType which may match wrong locals)
                    if (src && src->op == IROp::Var && src->typeRef != NullType) {
                        auto *kt = m_types.resolveType(src->typeRef);
                        if (kt && kt->kind == StabsTypeKind::Array)
                            s += "[0]";
                    }
                };
                fixArrayVar(lhs, e->kids[0].get());
                fixArrayVar(rhs, e->kids[1].get());
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

                // For unsigned comparisons (Ult/Ule/Ugt/Uge) against small constants,
                // add (unsigned) cast to generate unsigned instructions (setbe etc.)
                // Only apply when: rhs is a small constant AND lhs looks like an
                // integer expression (not a float or function call result).
                bool isUnsigned = (cmp == IROp::Ult || cmp == IROp::Ule ||
                                   cmp == IROp::Ugt || cmp == IROp::Uge);
                bool addUnsignedCast = false;
                if (isUnsigned && e->kids[1] && e->kids[1]->isConst() &&
                    e->kids[1]->value >= 0 && e->kids[1]->value <= 0xFFFF &&
                    lhs.find("(unsigned)") == std::string::npos &&
                    lhs.find("0.") == std::string::npos &&
                    lhs.find("0f") == std::string::npos) {
                    // Only cast when lhs is arithmetic (contains - or +),
                    // indicating a range check pattern like (x - N) <= M
                    if (lhs.find(" - ") != std::string::npos ||
                        lhs.find(" + ") != std::string::npos) {
                        addUnsignedCast = true;
                    }
                }
                if (addUnsignedCast) {
                    result = "(unsigned)(" + lhs + ")" + op + rhs;
                } else {
                    result = lhs + op + rhs;
                }
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
                std::string funcName = cName(e->name);
                // Function pointer table calls: fptable_ADDR_SCALE(index, args...)
                // Emits: ((int(*)(void*))(((void**)TABLE)[index]))(args...)
                // This produces: calll *TABLE(, %reg, SCALE)
                if (e->name.compare(0, 8, "fptable_") == 0 && !e->kids.empty()) {
                    // Parse table address and scale from name
                    unsigned tableAddr = 0;
                    int scale = 4;
                    sscanf(e->name.c_str() + 8, "%X_%d", &tableAddr, &scale);
                    std::string indexExpr = emitExpr(e->kids[0].get());
                    // Build function pointer type with correct number of params
                    int nargs = (int)e->kids.size() - 1; // first kid is index
                    std::string fptype = "int(*)(";
                    for (int p = 0; p < nargs; ++p) {
                        if (p) fptype += ", ";
                        fptype += "int";
                    }
                    fptype += ")";
                    char buf[256];
                    snprintf(buf, sizeof(buf),
                        "((%s)(((void**)0x%X)[%s]))(",
                        fptype.c_str(), tableAddr, indexExpr.c_str());
                    result = buf;
                    for (size_t i = 1; i < e->kids.size(); ++i) {
                        if (i > 1) result += ", ";
                        result += emitExpr(e->kids[i].get());
                    }
                    result += ")";
                    break;
                }
                // Vtable calls: vfunc_N(this, ...) → indirect call through vtable
                int vslot = -1;
                if (e->name.compare(0, 6, "vfunc_") == 0) {
                    vslot = atoi(e->name.c_str() + 6);
                }
                if (vslot >= 0 && !e->kids.empty()) {
                    std::string thisArg = emitExpr(e->kids[0].get());
                    // Build function pointer type matching argument count
                    int nargs = (int)e->kids.size();
                    std::string fptype = "int(*)(";
                    for (int p = 0; p < nargs; ++p) {
                        if (p) fptype += ", ";
                        fptype += (p == 0) ? "void *" : "int";
                    }
                    fptype += ")";
                    char buf[256];
                    snprintf(buf, sizeof(buf),
                        "((%s)(((void**)(*(void**)%s))[%d]))(",
                        fptype.c_str(), thisArg.c_str(), vslot);
                    result = buf;
                    for (size_t i = 0; i < e->kids.size(); ++i) {
                        if (i) result += ", ";
                        result += emitExpr(e->kids[i].get());
                    }
                    result += ")";
                } else {
                    // Look up the called function's demangled parameter types
                    // to cast integer args to float when the parameter is float.
                    // STABS parameter typeRefs may resolve to wrong types due to
                    // CU scoping, so use the demangled C++ signature instead.
                    std::vector<std::string> dParamTypes;
                    {
                        const StabsFunction *calledFn = m_mf.stabsFunctionByName(e->name);
                        if (calledFn && !calledFn->rawName.empty() &&
                            calledFn->rawName.find("_Z") != std::string::npos) {
                            std::string rn = calledFn->rawName;
                            auto col = rn.find(':');
                            if (col != std::string::npos) rn = rn.substr(0, col);
                            std::string full = demangle(rn);
                            size_t po = full.rfind('('), pc = full.rfind(')');
                            if (po != std::string::npos && pc != std::string::npos && pc > po) {
                                std::string ps = full.substr(po + 1, pc - po - 1);
                                size_t start = 0; int depth = 0;
                                for (size_t c = 0; c <= ps.size(); ++c) {
                                    if (c < ps.size() && ps[c] == '<') depth++;
                                    else if (c < ps.size() && ps[c] == '>') depth--;
                                    else if ((c == ps.size() || ps[c] == ',') && depth == 0) {
                                        std::string pt = ps.substr(start, c - start);
                                        while (!pt.empty() && pt.front() == ' ') pt.erase(pt.begin());
                                        while (!pt.empty() && pt.back() == ' ') pt.pop_back();
                                        if (pt.compare(0, 6, "const ") == 0) pt = pt.substr(6);
                                        dParamTypes.push_back(pt);
                                        start = c + 1;
                                    }
                                }
                            }
                        }
                    }
                    // Limit arg count to prototype when the prototype
                    // specifies fewer args than the IR detected (false positives
                    // from leftover register values)
                    size_t argCount = e->kids.size();
                    const StabsFunction *calledFn2 = m_mf.stabsFunctionByName(e->name);
                    if (calledFn2 && !calledFn2->params.empty() &&
                        calledFn2->params.size() < argCount) {
                        // Check it's not a variadic function
                        static const std::set<std::string> variadics = {
                            "Com_Printf", "Com_Error", "Com_DPrintf", "Com_sprintf",
                            "va", "Sys_Error", "CG_Printf", "G_Printf",
                            "Scr_Error", "Scr_ParamError"
                        };
                        if (!variadics.count(e->name))
                            argCount = calledFn2->params.size();
                    }
                    result = funcName + "(";
                    for (size_t i = 0; i < argCount; ++i) {
                        if (i) result += ", ";
                        std::string arg = emitExpr(e->kids[i].get());
                        // Cast *(int *) loads to *(float *) for float params
                        if (i < dParamTypes.size() &&
                            (dParamTypes[i] == "float" || dParamTypes[i] == "double") &&
                            arg.find("*(int *)") == 0) {
                            arg = "*(float *)" + arg.substr(8);
                        }
                        // Cast scalar args to union/struct types when prototype expects them
                        // (small unions/structs passed by value are int-sized on x86)
                        if (calledFn2 && i < calledFn2->params.size()) {
                            auto &par = calledFn2->params[i];
                            if (par.typeRef != NullType) {
                                auto *pt = m_types.resolveType(par.typeRef);
                                if (pt && (pt->kind == StabsTypeKind::Union ||
                                          (pt->kind == StabsTypeKind::Struct &&
                                           pt->sizeBytes > 0 && pt->sizeBytes <= 4))) {
                                    std::string ptype = m_types.formatType(par.typeRef);
                                    // Skip C++ template types and complex names
                                    if (ptype.find('<') == std::string::npos &&
                                        ptype.find("std::") == std::string::npos &&
                                        arg.find(ptype) == std::string::npos &&
                                        arg.find("union ") != 0 && arg.find("struct ") != 0)
                                        arg = "*(" + ptype + " *)&(int){" + arg + "}";
                                }
                            }
                        }
                        result += arg;
                    }
                    result += ")";
                }
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
        // Check if an expression evaluates to float type
        // Check if expression is a call to a function that returns void
        bool isVoidCallExpr(IRExpr *e) {
            if (!e) return false;
            IRExpr *re = e;
            if (re->op == IROp::Temp) {
                auto dit = m_tempDef.find(re->tempId());
                if (dit != m_tempDef.end() && dit->second)
                    re = dit->second;
            }
            if (re->op == IROp::Call) {
                const StabsFunction *cf = m_mf.stabsFunctionByName(re->name);
                if (cf && cf->returnType != NullType) {
                    std::string rt = m_types.formatType(cf->returnType);
                    if (rt == "void") return true;
                }
            }
            return false;
        }

        bool isFloatExpr(IRExpr *e) {
            if (!e) return false;
            if (e->op == IROp::Temp) {
                if (inferTempType(e->tempId()) == "float") return true;
                // Follow temp definition
                auto it = m_tempDef.find(e->tempId());
                if (it != m_tempDef.end() && it->second)
                    return isFloatExpr(it->second);
                // Check copy map and tempToVar for source variable
                std::string srcName;
                auto cit = m_copyMap.find(e->tempId());
                if (cit != m_copyMap.end()) srcName = cit->second;
                if (srcName.empty()) {
                    auto tvit = m_func.tempToVar.find(e->tempId());
                    if (tvit != m_func.tempToVar.end()) {
                        auto nit = m_func.varNames.find(tvit->second);
                        if (nit != m_func.varNames.end()) srcName = nit->second;
                    }
                }
                if (!srcName.empty()) {
                    for (auto &p : m_func.params)
                        if (p.name == srcName && p.typeRef != NullType) {
                            std::string ts = m_types.formatType(p.typeRef);
                            if (ts == "float" || ts == "double") return true;
                        }
                    for (auto &l : m_func.locals)
                        if (l.name == srcName && l.typeRef != NullType) {
                            std::string ts = m_types.formatType(l.typeRef);
                            if (ts == "float" || ts == "double") return true;
                        }
                }
                return false;
            }
            if (e->op == IROp::Var && !e->name.empty()) {
                // Check if variable is declared as float
                for (auto &l : m_func.locals)
                    if (l.name == e->name && l.typeRef != NullType) {
                        std::string ts = m_types.formatType(l.typeRef);
                        return ts == "float" || ts == "double";
                    }
                for (auto &p : m_func.params)
                    if (p.name == e->name && p.typeRef != NullType) {
                        std::string ts = m_types.formatType(p.typeRef);
                        return ts == "float" || ts == "double";
                    }
            }
            // Constants that emit as float literals (e.g. 0x3F800000 → 1.0f)
            if (e->op == IROp::Const && !tryFloatConst((uint32_t)e->value).empty()) return true;
            if (e->op == IROp::Load && e->loadSize == 5) return true;
            if (e->op == IROp::Cast && (e->castKind == CastKind::IntToFloat)) return true;
            // Call to a function that returns float
            if (e->op == IROp::Call) {
                const StabsFunction *cf = m_mf.stabsFunctionByName(e->name);
                if (cf && cf->returnType != NullType) {
                    std::string rt = m_types.formatType(cf->returnType);
                    if (rt == "float" || rt == "double" || rt == "vec_t")
                        return true;
                }
                static const std::set<std::string> floatFuncs = {
                    "atof", "strtof", "strtod",
                    "sinf", "cosf", "tanf", "asinf", "acosf", "atanf", "atan2f",
                    "sqrtf", "fabsf", "fminf", "fmaxf", "floorf", "ceilf",
                    "powf", "fmodf", "expf", "logf", "log10f",
                    "sin", "cos", "tan", "sqrt", "fabs", "floor", "ceil",
                    "pow", "fmod", "exp", "log", "atan2",
                };
                if (floatFuncs.count(e->name)) return true;
            }
            // Bitwise/shift ops on float: if any child is float, propagate
            if ((e->op == IROp::And || e->op == IROp::Or || e->op == IROp::Xor ||
                 e->op == IROp::Shr || e->op == IROp::Sar || e->op == IROp::Shl) &&
                !e->kids.empty()) {
                for (auto &k : e->kids)
                    if (k && isFloatExpr(k.get())) return true;
            }
            // Float arithmetic propagates
            if ((e->op == IROp::Add || e->op == IROp::Sub || e->op == IROp::Mul || e->op == IROp::Neg) &&
                !e->kids.empty() && isFloatExpr(e->kids[0].get())) return true;
            return false;
        }

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
                                std::string fmt = m_types.formatType(l.typeRef);
                                if (fmt == "float" || fmt == "double" || fmt == "vec_t")
                                    return "float";
                            }
                        for (auto &p : m_func.params)
                            if (p.name == k->name && p.typeRef != NullType) {
                                std::string fmt = m_types.formatType(p.typeRef);
                                if (fmt == "float" || fmt == "double" || fmt == "vec_t")
                                    return "float";
                            }
                    }
                    // Check if operand is a Temp with known float type
                    if (k->op == IROp::Temp) {
                        auto tit = m_func.tempTypes.find(k->tempId());
                        if (tit != m_func.tempTypes.end() && tit->second != NullType) {
                            std::string fmt = m_types.formatType(tit->second);
                            if (fmt == "float" || fmt == "double" || fmt == "vec_t")
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
                    // Check if operand is a Call to a float-returning function
                    if (k->op == IROp::Call) {
                        const StabsFunction *cf = m_mf.stabsFunctionByName(k->name);
                        if (cf && cf->returnType != NullType) {
                            std::string rt = m_types.formatType(cf->returnType);
                            if (rt == "float" || rt == "double" || rt == "vec_t")
                                return "float";
                        }
                        // Hardcoded float-returning C library functions
                        static const std::set<std::string> floatFuncs = {
                            "atof", "strtof", "strtod",
                            "sinf", "cosf", "tanf", "asinf", "acosf", "atanf", "atan2f",
                            "sqrtf", "fabsf", "fminf", "fmaxf", "floorf", "ceilf",
                            "powf", "fmodf", "expf", "logf", "log10f",
                            "sin", "cos", "tan", "asin", "acos", "atan", "atan2",
                            "sqrt", "fabs", "fmin", "fmax", "floor", "ceil",
                            "pow", "fmod", "exp", "log", "log10",
                        };
                        if (floatFuncs.count(k->name)) return "float";
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
        // Wrap an expression for use as a pointer (e.g., in (char *)EXPR).
        // For struct/union/array expressions, adds & to take the address.
        std::string asPointer(const std::string &exprStr, IRExpr *expr) {
            if (!expr) return exprStr;
            TypeRef t = exprType(expr);
            if (t != NullType) {
                auto *rt = m_types.resolveType(t);
                if (rt && (rt->kind == StabsTypeKind::Struct ||
                           rt->kind == StabsTypeKind::Union ||
                           rt->kind == StabsTypeKind::Array))
                    return "&" + exprStr;
            }
            return exprStr;
        }

        static std::string cName(const std::string &name) {
            std::string out = name;
            // Replace :: with __ (double underscore to match types header)
            size_t pos = 0;
            while ((pos = out.find("::", pos)) != std::string::npos) {
                out.replace(pos, 2, "__");
                pos += 2;
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
            // For ZeroExt/SignExt of Load expressions, use typed pointer dereference
            // instead of casting the loaded value. This produces movzbl/movzwl (byte/word load)
            // instead of movl + truncation.
            if ((e->castKind == CastKind::ZeroExt8 || e->castKind == CastKind::Trunc8 ||
                 e->castKind == CastKind::ZeroExt16 || e->castKind == CastKind::Trunc16) &&
                inner_e->op == IROp::Load && !inner_e->kids.empty()) {
                // Cosmetic mode: try struct field resolution for the Load address
                if (s_cosmeticMode) {
                    auto *loadAddr = inner_e->kids[0].get();
                    if (loadAddr && loadAddr->op == IROp::Add && loadAddr->kids.size() == 2 &&
                        loadAddr->kids[1]->isConst() && loadAddr->kids[1]->value > 0 &&
                        loadAddr->kids[0]->op == IROp::Var) {
                        std::string gname = loadAddr->kids[0]->name;
                        int off = (int)loadAddr->kids[1]->value;
                        auto *gn = m_types.globalByName(gname);
                        if (gn && gn->typeRef != NullType && m_types.isStructPointer(gn->typeRef)) {
                            TypeRef structRef = m_types.getPointedStruct(gn->typeRef);
                            if (structRef != NullType) {
                                std::string access = m_types.formatFieldAccess(structRef, off);
                                if (!access.empty())
                                    return gname + "->" + access;
                            }
                        }
                    }
                }
                bool is8 = (e->castKind == CastKind::ZeroExt8 || e->castKind == CastKind::Trunc8);
                const char *castType = is8 ? "unsigned char" : "unsigned short";
                m_addrDepth++;
                std::string addr = emitExpr(inner_e->kids[0].get());
                m_addrDepth--;
                if (addr.find("_p + ") != std::string::npos || addr.find("_p)") != std::string::npos)
                    return std::string("*(") + castType + " *)(" + addr + ")";
                return std::string("*(") + castType + " *)((char *)" + addr + ")";
            }
            switch (e->castKind) {
            case CastKind::ZeroExt8:   return "(unsigned char)(" + inner + ")";
            case CastKind::ZeroExt16:  return "(unsigned short)(" + inner + ")";
            case CastKind::SignExt8:   return "(signed char)(" + inner + ")";
            case CastKind::SignExt16:  return "(short)(" + inner + ")";
            case CastKind::Trunc8:     return "(unsigned char)(" + inner + ")";
            case CastKind::Trunc16:
                // If inner is a variable (not an expression), use *(short*)&var
                // to read the 16-bit value at the variable's address
                if (inner_e->op == IROp::Var)
                    return "*(short *)(&" + inner + ")";
                return "(short)(" + inner + ")";
            case CastKind::IntToFloat: return "(float)(" + inner + ")";
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

        // Cosmetic-safe type lookup: validates typeRef, checks inferred types
        TypeRef safeExprType(IRExpr *e) const {
            if (!e) return NullType;
            // In cosmetic mode, prefer inferred struct pointer types over generic types
            if (s_cosmeticMode) {
                if (e->op == IROp::Temp) {
                    auto it = m_cosmeticTypes.find(e->tempId());
                    if (it != m_cosmeticTypes.end()) return it->second;
                    // Follow temp → copy-propagated var name → type from params/locals/globals
                    auto cit = m_copyMap.find(e->tempId());
                    if (cit != m_copyMap.end()) {
                        auto vit = m_cosmeticVarTypes.find(cit->second);
                        if (vit != m_cosmeticVarTypes.end()) return vit->second;
                        // Prefer params/locals over globals (params have semantic type)
                        for (auto &p : m_func.params)
                            if (p.name == cit->second && p.typeRef != NullType && m_types.isValidType(p.typeRef))
                                return p.typeRef;
                        for (auto &l : m_func.locals)
                            if (l.name == cit->second && l.typeRef != NullType && m_types.isValidType(l.typeRef))
                                return l.typeRef;
                        auto *gn = m_types.globalByName(cit->second);
                        if (gn && gn->typeRef != NullType && m_types.isValidType(gn->typeRef))
                            return gn->typeRef;
                    }
                    // Follow temp def: Temp = Load(Var("global")) → dereference pointer type
                    auto tdit = m_tempDef.find(e->tempId());
                    if (tdit != m_tempDef.end() && tdit->second &&
                        tdit->second->op == IROp::Load && !tdit->second->kids.empty()) {
                        IRExpr *inner = tdit->second->kids[0].get();
                        if (inner && inner->op == IROp::Var && !inner->name.empty()) {
                            auto *gn = m_types.globalByName(inner->name);
                            if (gn && gn->typeRef != NullType && m_types.isValidType(gn->typeRef) &&
                                m_types.isStructPointer(gn->typeRef))
                                return gn->typeRef; // Return the pointer type (caller uses isStructPointer)
                        }
                    }
                    // Also check tempToVar → param/local name
                    auto tvit = m_func.tempToVar.find(e->tempId());
                    if (tvit != m_func.tempToVar.end()) {
                        auto nit = m_func.varNames.find(tvit->second);
                        if (nit != m_func.varNames.end()) {
                            for (auto &p : m_func.params)
                                if (p.name == nit->second && p.typeRef != NullType && m_types.isValidType(p.typeRef))
                                    return p.typeRef;
                            for (auto &l : m_func.locals)
                                if (l.name == nit->second && l.typeRef != NullType && m_types.isValidType(l.typeRef))
                                    return l.typeRef;
                        }
                    }
                }
                if (e->op == IROp::Var && !e->name.empty()) {
                    auto it = m_cosmeticVarTypes.find(e->name);
                    if (it != m_cosmeticVarTypes.end()) return it->second;
                    // Also check globals
                    auto *gn = m_types.globalByName(e->name);
                    if (gn && gn->typeRef != NullType && m_types.isValidType(gn->typeRef))
                        return gn->typeRef;
                }
            }
            // Fall back to normal exprType with validation
            TypeRef t = exprType(e);
            if (t != NullType && !m_types.isValidType(t)) return NullType;
            return t;
        }

        // Build cosmetic type inference map: propagate types from assignments/globals
        void buildCosmeticTypeMap() {
            if (!s_cosmeticMode) return;
            // Pass 1: VarSet(global, temp) → propagate global type to temp
            // Also: Assign(temp, Var(global)) → propagate global type to temp
            for (auto &bb : m_func.blocks) {
                for (auto &stmt : bb.stmts) {
                    // VarSet("name", expr) — propagate dest's type to the source temp
                    if (stmt.kind == IRStmtKind::VarSet && stmt.expr && !stmt.destVar.empty()) {
                        TypeRef destType = NullType;
                        // Check globals
                        auto *gn = m_types.globalByName(stmt.destVar);
                        if (gn && gn->typeRef != NullType && m_types.isValidType(gn->typeRef))
                            destType = gn->typeRef;
                        // Check params/locals (prefer pointer types for backward propagation)
                        if (destType == NullType || !m_types.isStructPointer(destType)) {
                            for (auto &p : m_func.params) {
                                if (p.name == stmt.destVar && p.typeRef != NullType && m_types.isValidType(p.typeRef)) {
                                    auto *pt = m_types.resolveType(p.typeRef);
                                    if (pt && pt->kind == StabsTypeKind::Pointer) destType = p.typeRef;
                                    break;
                                }
                            }
                        }
                        if (destType != NullType && m_types.isValidType(destType)) {
                            auto *dt = m_types.resolveType(destType);
                            if (dt && dt->kind == StabsTypeKind::Pointer) {
                                if (stmt.expr->op == IROp::Temp)
                                    m_cosmeticTypes[stmt.expr->tempId()] = destType;
                                m_cosmeticVarTypes[stmt.destVar] = destType;
                            }
                        }
                    }
                    // Store(Var/Temp, val) to a struct pointer global → record the type
                    if (stmt.kind == IRStmtKind::Store && stmt.addr) {
                        if (stmt.addr->op == IROp::Var && !stmt.addr->name.empty()) {
                            auto *gn = m_types.globalByName(stmt.addr->name);
                            if (gn && gn->typeRef != NullType && m_types.isValidType(gn->typeRef))
                                m_cosmeticVarTypes[stmt.addr->name] = gn->typeRef;
                        }
                    }
                    // Assign(temp, expr) where expr is Var(global) or Call → propagate
                    if (stmt.kind == IRStmtKind::Assign && stmt.expr && stmt.destTemp >= 0) {
                        if (stmt.expr->op == IROp::Var && !stmt.expr->name.empty()) {
                            auto *gn = m_types.globalByName(stmt.expr->name);
                            if (gn && gn->typeRef != NullType && m_types.isValidType(gn->typeRef))
                                m_cosmeticTypes[stmt.destTemp] = gn->typeRef;
                        }
                    }
                }
            }
            // Pass 2: Transitive propagation: Assign(t2, Temp(t1)) inherits t1's type
            // Also: VarSet(name, Temp(t)) and Store(Temp(t), ...) — propagate temp type to var
            bool changed = true;
            for (int iter = 0; iter < 5 && changed; ++iter) {
                changed = false;
                for (auto &bb : m_func.blocks) {
                    for (auto &stmt : bb.stmts) {
                        if (stmt.kind == IRStmtKind::Assign && stmt.expr && stmt.destTemp >= 0 &&
                            !m_cosmeticTypes.count(stmt.destTemp)) {
                            if (stmt.expr->op == IROp::Temp) {
                                auto it = m_cosmeticTypes.find(stmt.expr->tempId());
                                if (it != m_cosmeticTypes.end()) {
                                    m_cosmeticTypes[stmt.destTemp] = it->second;
                                    changed = true;
                                }
                            }
                        }
                        // Backward: VarSet(name, temp) where name has cosmetic type → propagate to temp
                        if (stmt.kind == IRStmtKind::VarSet && stmt.expr &&
                            stmt.expr->op == IROp::Temp && !stmt.destVar.empty()) {
                            auto vit = m_cosmeticVarTypes.find(stmt.destVar);
                            if (vit != m_cosmeticVarTypes.end() &&
                                !m_cosmeticTypes.count(stmt.expr->tempId())) {
                                m_cosmeticTypes[stmt.expr->tempId()] = vit->second;
                                changed = true;
                            }
                        }
                    }
                }
            }
            // Pass 3: Fix C++ 'this' pointer type from function name
            for (auto &p : m_func.params) {
                if (p.name != "this") continue;
                if (p.typeRef != NullType && m_types.isValidType(p.typeRef)) break;
                // Extract class name from "ClassName::Method" or "CClassName_Method"
                size_t sep = m_func.name.find("::");
                std::string className;
                if (sep != std::string::npos)
                    className = m_func.name.substr(0, sep);
                else if (m_func.name.size() > 2 && m_func.name[0] == 'C') {
                    // Try CClassName_Method pattern
                    size_t us = m_func.name.find('_');
                    if (us != std::string::npos)
                        className = m_func.name.substr(0, us);
                }
                if (className.empty()) break;
                for (auto &[tref, ti] : m_types.allTypes()) {
                    if ((ti.kind == StabsTypeKind::Struct || ti.kind == StabsTypeKind::Union) &&
                        ti.name == className && !ti.fields.empty()) {
                        TypeRef ptrType = m_types.findPointerTo(tref);
                        if (ptrType != NullType) p.typeRef = ptrType;
                        break;
                    }
                }
                break;
            }
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
