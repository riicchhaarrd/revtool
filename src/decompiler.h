#pragma once
#include "ir.h"
#include "lifter.h"
#include "cfg.h"
#include "macho.h"
#include <QString>
#include <QProcess>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <cstdio>
#include <cstring>

// ── Decompiler: x86 → IR → CFG → Structured C ──────────────────────
// Full pipeline: lift, build CFG, recover structure, fold expressions,
// emit compilable C with STABS types.

class Decompiler {
public:
    // Decompile a single function
    static QString decompile(const MachOFile &mf, uint32_t funcAddr, bool format = true) {
        Lifter lifter(mf);
        IRFunc func = lifter.liftFunction(funcAddr);
        if (func.blocks.empty()) return "/* could not decompile */\n";

        CfgStructurer structurer;
        auto tree = structurer.structure(func);

        Emitter em(mf, func);
        QString code = em.generate(tree.get());
        return format ? clangFormat(cleanupEmptyIfs(code)) : cleanupEmptyIfs(code);
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

        for (size_t fi : sorted) {
            auto &fn = mf.stabsFunctions()[fi];
            if (fn.address == 0) continue;
            out += decompile(mf, fn.address, false); // skip per-function formatting
            out += "\n";
        }

        return clangFormat(cleanupEmptyIfs(out)); // cleanup + format
    }

    // Platform type definitions for compilable output
    static QString platformTypedefs() {
        return QString(
            "/* Platform types */\n"
            "#include <stdint.h>\n"
            "#include <stddef.h>\n"
            "#include <stdarg.h>\n"
            "#include <math.h>\n"
            "#include <string.h>\n"
            "#include <stdio.h>\n"
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
            "typedef unsigned int OSType;\n"
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
            "typedef void *ContextRef;\n"
            "typedef void *FSRef;\n"
            "typedef struct { float x, y; } CGPoint;\n"
            "typedef struct { float width, height; } CGSize;\n"
            "typedef struct { CGPoint origin; CGSize size; } CGRect;\n"
            "typedef struct { short top, left, bottom, right; } MacRect;\n"
            "typedef struct { int x, y; } Point;\n"
            "typedef int D3DTEXTUREFILTERTYPE;\n"
            "typedef int D3DFORMAT;\n"
            "typedef int D3DDEVTYPE;\n"
            "/* FILE from <stdio.h> */\n"
            "typedef void *YY_BUFFER_STATE;\n"
            "typedef int yy_state_type;\n"
            "typedef unsigned int u_int;\n"
            "typedef int jmp_buf[64];\n"
            "int stricmp(const char *, const char *);\n"
            "int strnicmp(const char *, const char *, size_t);\n"
            "typedef int bool;\n"
            "typedef signed char SInt8;\n"
            "typedef char *StringPtr;\n"
            "typedef char *Ptr;\n"
            "typedef int INT;\n"
            "typedef int QElemPtr;\n"
            "typedef void *IOCompletionUPP;\n"
            "typedef struct { unsigned int lo, hi; } UTCDateTime;\n"
            "typedef struct { unsigned int signature; int id; } ControlID;\n"
            "\n"
        );
    }

    // Remove empty if blocks from output text
    static QString cleanupEmptyIfs(const QString &code) {
        QString result;
        QStringList lines = code.split('\n');
        for (int i = 0; i < lines.size(); ++i) {
            // Pattern: "if (...) {" followed by "}" (with only whitespace)
            if (i + 1 < lines.size() &&
                lines[i].trimmed().startsWith("if (") &&
                lines[i].trimmed().endsWith("{") &&
                lines[i+1].trimmed() == "}") {
                ++i; // skip both lines
                continue;
            }
            result += lines[i] + '\n';
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
        for (auto ref : used) {
            emitTypeDefsRecursive(out, types, ref, emitted);
        }
        if (!emitted.empty()) out += "\n";
    }

    static void emitTypeDefsRecursive(QString &out, const StabsTypeTable &types,
                                      TypeRef ref, std::set<TypeRef> &emitted, int depth = 0) {
        if (ref == NullType || emitted.count(ref) || depth > 30) return;
        emitted.insert(ref); // mark visited BEFORE recursing to break cycles
        auto *t = types.getType(ref);
        if (!t) return;

        // Resolve through pointers/typedefs/arrays to find underlying struct/enum
        if (t->kind == StabsTypeKind::Pointer || t->kind == StabsTypeKind::Typedef ||
            t->kind == StabsTypeKind::Const || t->kind == StabsTypeKind::Volatile ||
            t->kind == StabsTypeKind::Array) {
            if (t->targetType != NullType)
                emitTypeDefsRecursive(out, types, t->targetType, emitted, depth + 1);
            return;
        }
        if (t->kind == StabsTypeKind::Struct || t->kind == StabsTypeKind::Union) {
            if (t->name.empty()) return;
            if (t->fields.empty()) {
                // Forward declaration for struct with no known fields
                std::string kw = (t->kind == StabsTypeKind::Union) ? "union" : "struct";
                // Emit as opaque struct with size placeholder if we know the size
                if (t->sizeBytes > 0) {
                    out += QString::fromStdString(kw + " " + t->name +
                        " { char _opaque[" + std::to_string(t->sizeBytes) + "]; };\n\n");
                } else {
                    out += QString::fromStdString(kw + " " + t->name + ";\n");
                }
                return;
            }
            // Emit fields' types first
            for (auto &f : t->fields)
                emitTypeDefsRecursive(out, types, f.typeRef, emitted, depth + 1);
            out += QString::fromStdString(types.formatStructDef(ref)) + ";\n\n";
            return;
        }
        if (t->kind == StabsTypeKind::Enum) {
            if (t->name.empty() || t->enumValues.empty()) return;
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
            if (m_func.returnType != NullType)
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
                out += "    " + QString::fromStdString(
                    l.typeRef != NullType ? m_types.formatDecl(l.typeRef, l.name)
                                          : "int " + l.name) + ";\n";
            }

            // Collect goto targets and emitted blocks BEFORE declaring temps
            std::set<int> emittedBlocks;
            collectGotoTargets(root, m_gotoTargets);
            collectEmittedBlocks(root, emittedBlocks);

            // Force-declare temps used in fallback (goto target) blocks
            for (int bbId : m_gotoTargets) {
                if (emittedBlocks.count(bbId)) continue;
                if (bbId < 0 || bbId >= (int)m_func.blocks.size()) continue;
                for (auto &stmt : m_func.blocks[bbId].stmts)
                    forceDeclareTempRefs(stmt);
            }

            // Declare temps that are used more than once (or used in fallback blocks)
            for (auto &[id, type] : m_func.tempTypes) {
                if (m_tempUseCount[id] > 1) {
                    std::string tname = "t" + std::to_string(id);
                    std::string ttype = (type != NullType) ? m_types.formatType(type) : inferTempType(id);
                    out += "    " + QString::fromStdString(ttype + " " + tname) + ";\n";
                    declared.insert(tname);
                }
            }
            // Also scan for any temp references not in tempTypes
            for (auto &[id, count] : m_tempUseCount) {
                if (count <= 1) continue;
                std::string tname = "t" + std::to_string(id);
                if (declared.count(tname)) continue;
                out += "    " + QString::fromStdString(inferTempType(id) + " " + tname) + ";\n";
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

            // Emit structured body
            emitNode(out, root, 1);

            // Emit fallback blocks for goto targets not in structured tree
            for (int bbId : m_gotoTargets) {
                if (emittedBlocks.count(bbId)) continue;
                if (bbId < 0 || bbId >= (int)m_func.blocks.size()) continue;
                auto &bb = m_func.blocks[bbId];
                if (!m_emittedLabels.count(bbId)) {
                    m_emittedLabels.insert(bbId);
                    out += QString("bb_%1:\n").arg(bbId);
                }
                for (int i = 0; i < (int)bb.stmts.size(); ++i) {
                    auto &s = bb.stmts[i];
                    // Skip terminal branch/jump (structurer handles control flow)
                    if (i == (int)bb.stmts.size() - 1 &&
                        (s.kind == IRStmtKind::Branch || s.kind == IRStmtKind::Jump))
                        continue;
                    emitStmt(out, s, 1);
                }
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
        std::set<int>         m_copyPropagated; // temps eliminated by copy prop
        // Copy prop: temp → replacement name
        std::map<int, std::string> m_copyMap;
        std::set<int>         m_gotoTargets;    // block IDs that are goto targets
        std::set<int>         m_emittedLabels;  // labels already emitted (avoid duplicates)
        std::set<std::pair<int,int>> m_suppressedStmts; // (blockId, stmtIdx) to skip in emission

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
            // Pass 1: find all temps that are simple copies
            for (auto &bb : m_func.blocks) {
                for (auto &stmt : bb.stmts) {
                    if (stmt.kind != IRStmtKind::Assign) continue;
                    if (!stmt.expr) continue;
                    // t = var → replace all uses of t with var
                    if (stmt.expr->op == IROp::Var) {
                        m_copyMap[stmt.destTemp] = stmt.expr->name;
                        m_copyPropagated.insert(stmt.destTemp);
                    }
                }
            }
            // Pass 2: rewrite all Temp refs in all expressions
            if (!m_copyMap.empty()) {
                for (auto &bb : m_func.blocks)
                    for (auto &stmt : bb.stmts) {
                        propagateInExpr(stmt.expr);
                        propagateInExpr(stmt.addr);
                        for (auto &a : stmt.args) propagateInExpr(a);
                    }
            }
        }

        void propagateInExpr(std::unique_ptr<IRExpr> &e) {
            if (!e) return;
            if (e->op == IROp::Temp) {
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
                    // Skip terminal branch/jump and suppressed assigns
                    if (k == IRStmtKind::Branch || k == IRStmtKind::Jump || k == IRStmtKind::Label)
                        continue;
                    if (k == IRStmtKind::Assign && m_tempUseCount[bb.stmts[i].destTemp] <= 1)
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
                // If body is empty but else exists, invert the condition
                if (!hasBody && hasElse) {
                    std::string cond = node->cond ? emitExpr(node->cond, !node->negated) : "1";
                    out += pad(indent) + "if (" + QString::fromStdString(cond) + ") {\n";
                    emitNode(out, node->elseNode.get(), indent + 1);
                    out += pad(indent) + "}\n";
                    break;
                }
                // Constant true condition — emit body without the if wrapper
                if (node->cond && node->cond->isConst() && node->cond->value != 0 && !node->negated && !hasElse) {
                    for (auto &child : node->children)
                        emitNode(out, child.get(), indent);
                    break;
                }
                std::string cond = node->cond ? emitExpr(node->cond, node->negated) : "1";
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
                std::string cond = node->cond ? emitExpr(node->cond, node->negated) : "1";
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
                        init = "t" + std::to_string(s.destTemp) + " = " + (s.expr ? emitExpr(s.expr.get()) : "0");
                }
                // Emit increment expression
                std::string incr;
                if (node->forIncrBB >= 0 && node->forIncrBB < (int)m_func.blocks.size() &&
                    node->forIncrStmt >= 0) {
                    auto &s = m_func.blocks[node->forIncrBB].stmts[node->forIncrStmt];
                    std::string varName;
                    if (s.kind == IRStmtKind::VarSet) varName = s.destVar;
                    else if (s.kind == IRStmtKind::Assign) varName = "t" + std::to_string(s.destTemp);
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
                std::string cond = node->cond ? emitExpr(node->cond, false) : "1";
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
                            if (s.kind == IRStmtKind::Assign && m_tempUseCount[s.destTemp] <= 1)
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
                // If temp is used only once, skip the assignment (will be inlined)
                if (m_tempUseCount[stmt.destTemp] <= 1) return;
                std::string lhs = "t" + std::to_string(stmt.destTemp);
                out += pad(indent) + QString::fromStdString(lhs + " = " + rhs) + ";\n";
                break;
            }
            case IRStmtKind::Store: {
                std::string val = stmt.expr ? emitExpr(stmt.expr.get()) : "0";
                if (!stmt.addr) break;
                auto *a = stmt.addr.get();
                // Field expression → base->field = val
                if (a->op == IROp::Field) {
                    out += pad(indent) + QString::fromStdString(emitExpr(a) + " = " + val) + ";\n";
                }
                // Add(base, const) → base->field_XX = val
                else if (a->op == IROp::Add && a->kids.size() == 2 &&
                         a->kids[1]->isConst() && a->kids[1]->value > 0 &&
                         a->kids[1]->value < 0x10000 &&
                         (a->kids[0]->op == IROp::Var || a->kids[0]->op == IROp::Temp)) {
                    std::string base = emitExpr(a->kids[0].get());
                    int off = (int)a->kids[1]->value;
                    char fname[32]; snprintf(fname, sizeof(fname), "field_%X", (unsigned)off);
                    out += pad(indent) + QString::fromStdString(base + "->" + fname + " = " + val) + ";\n";
                }
                // Add(base, Mul(idx, scale)) → base->arr_0[idx] = val
                else if (a->op == IROp::Add && a->kids.size() == 2 &&
                         a->kids[1]->op == IROp::Mul && a->kids[1]->kids.size() == 2 &&
                         a->kids[1]->kids[1]->isConst() &&
                         (a->kids[0]->op == IROp::Var || a->kids[0]->op == IROp::Temp)) {
                    std::string base = emitExpr(a->kids[0].get());
                    std::string idx = emitExpr(a->kids[1]->kids[0].get());
                    out += pad(indent) + QString::fromStdString(
                        base + "->arr_0[" + idx + "] = " + val) + ";\n";
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
                else if (a->op == IROp::Var || a->op == IROp::Temp) {
                    out += pad(indent) + QString::fromStdString(
                        "*(" + emitExpr(a) + ") = " + val) + ";\n";
                } else {
                    out += pad(indent) + QString::fromStdString(
                        emitStoreDeref(emitExpr(a), stmt.destType, exprType(a)) + " = " + val) + ";\n";
                }
                break;
            }
            case IRStmtKind::VarSet: {
                std::string val = stmt.expr ? emitExpr(stmt.expr.get()) : "0";
                std::string dest = stmt.destVar;
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
                }
                out += pad(indent) + QString::fromStdString(dest + " = " + val) + ";\n";
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
                out += pad(indent) + QString::fromStdString(stmt.intrinsicComment) + ";\n";
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
                // These are handled by the structured emitter, not here
                break;
            }
        }

        // ── Emit an IR expression as a C string ─────────────────────
        std::string emitExpr(IRExpr *e, bool negate = false) {
            if (!e) return "0";

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
                // Try to resolve large constants as global variable addresses
                if (result.empty() && e->value > 0x10000) {
                    std::string sym = m_mf.symbolNameAtAddress((uint32_t)e->value);
                    if (!sym.empty()) {
                        result = sym;
                    } else {
                        // Check if address is base+offset into a known global (array element field)
                        // Search for the nearest symbol below this address
                        std::string nearest = m_mf.nearestSymbolName((uint32_t)e->value);
                        if (!nearest.empty()) result = nearest;
                    }
                }
                if (result.empty()) {
                    if (e->value >= -256 && e->value <= 4096)
                        result = std::to_string(e->value);
                    else {
                        char buf[32]; snprintf(buf, sizeof(buf), "0x%X", (unsigned)(uint32_t)e->value);
                        result = buf;
                    }
                }
                break;
            }
            case IROp::Temp: {
                int id = e->tempId();
                // Inline temps used only once
                if (m_tempUseCount[id] <= 1) {
                    auto it = m_tempDef.find(id);
                    if (it != m_tempDef.end() && it->second) {
                        std::string inlined = emitExpr(it->second, negate);
                        if (!inlined.empty()) return inlined;
                    }
                }
                result = "t" + std::to_string(id);
                break;
            }
            case IROp::Var:    result = e->name; break;
            case IROp::String: result = e->name; break;
            case IROp::FuncRef: result = e->name; break;

            case IROp::Load: {
                auto *addr = e->kids[0].get();
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
                            (maybeBase->op == IROp::Var || maybeBase->op == IROp::Temp)) {
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
                // (base + const) → base->field_XX for pointer-like expressions
                else if (addr && addr->op == IROp::Add && addr->kids.size() == 2 &&
                    addr->kids[1]->isConst() && addr->kids[1]->value > 0 &&
                    addr->kids[1]->value < 0x10000 &&
                    (addr->kids[0]->op == IROp::Var || addr->kids[0]->op == IROp::Temp)) {
                    // Use -> notation: cleaner than *((int*)((base + off)))
                    std::string base = emitExpr(addr->kids[0].get());
                    int off = (int)addr->kids[1]->value;
                    char fname[32]; snprintf(fname, sizeof(fname), "field_%X", (unsigned)off);
                    result = base + "->" + fname;
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
                    } else {
                        // Simple var/temp being dereferenced — no need for cast
                        result = "*(" + emitExpr(addr) + ")";
                    }
                } else {
                    result = emitDeref(emitExpr(addr), e->typeRef, exprType(addr));
                }
                break;
            }

            case IROp::AddrOf:
                result = "&" + emitExpr(e->kids[0].get());
                break;

            case IROp::Field: {
                std::string base = emitExpr(e->kids[0].get());
                // Check if this is a synthetic field (field_XX) from an opaque/empty struct
                bool isSynthField = (e->name.find("field_") == 0);
                bool fieldValid = true;
                if (isSynthField) {
                    // Verify the struct type actually has a field at this offset
                    TypeRef baseType = exprType(e->kids[0].get());
                    if (baseType != NullType) {
                        TypeRef structRef = m_types.getPointedStruct(baseType);
                        if (structRef != NullType) {
                            // Check if there's a real field at this offset
                            auto *field = m_types.findFieldAtOffset(structRef, (int)e->value);
                            if (!field || field->name.empty() || field->name[0] == '!')
                                fieldValid = false;
                        }
                    } else {
                        // No type info at all — use cast-based access for synthetic fields
                        fieldValid = false;
                    }
                }
                // Always use arrow notation for field access — more readable
                // (struct definitions will include synthetic fields as needed)
                result = base + "->" + e->name;
                break;
            }

            case IROp::Neg:     result = "-" + emitExpr(e->kids[0].get()); break;
            case IROp::Not:     result = "~" + emitExpr(e->kids[0].get()); break;
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
                std::string lhs = emitExpr(e->kids[0].get());
                // Simplify: (x + -N) → (x - N)
                if (e->op == IROp::Add && e->kids[1] && e->kids[1]->isConst() &&
                    e->kids[1]->value < 0) {
                    result = "(" + lhs + " - " + std::to_string(-e->kids[1]->value) + ")";
                    break;
                }
                std::string rhs = emitExpr(e->kids[1].get());
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
                default: op = " ? "; break;
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

            case IROp::Ternary:
                result = "(" + emitExpr(e->kids[0].get()) + " ? " +
                         emitExpr(e->kids[1].get()) + " : " +
                         emitExpr(e->kids[2].get()) + ")";
                break;

            case IROp::Call: {
                result = cName(e->name) + "(";
                for (size_t i = 0; i < e->kids.size(); ++i) {
                    if (i) result += ", ";
                    result += emitExpr(e->kids[i].get());
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
                if (e->op == IROp::Temp) result = "t" + std::to_string(e->tempId());
                else if (e->op == IROp::Var) result = e->name.empty() ? "0" : e->name;
                else result = "0";
            }

            if (negate && !result.empty()) {
                if (result[0] == '!') return result.substr(1);
                return "!(" + result + ")";
            }

            return result;
        }

        // Infer temp type from its defining expression
        std::string inferTempType(int id) {
            auto it = m_tempDef.find(id);
            if (it == m_tempDef.end() || !it->second) return "int";
            auto *e = it->second;
            // If the expression itself has a type annotation, use it
            if (e->typeRef != NullType) {
                auto *rt = m_types.resolveType(e->typeRef);
                // For array types assigned to temps, use pointer to element type
                // (arrays decay to pointers when assigned in C)
                if (rt && rt->kind == StabsTypeKind::Array)
                    return m_types.formatType(rt->targetType) + " *";
                return m_types.formatType(e->typeRef);
            }
            // Float operations → float
            if (e->op == IROp::Const && !tryFloatConst((uint32_t)e->value).empty()) return "float";
            if (e->op == IROp::Cast &&
                (e->castKind == CastKind::IntToFloat || e->castKind == CastKind::FloatToInt))
                return e->castKind == CastKind::IntToFloat ? "float" : "int";
            if (e->op == IROp::Var && (e->name.find(".0f") != std::string::npos ||
                                        e->name.find(".0") != std::string::npos))
                return "float";
            // Comparison results → int (boolean)
            if (e->op >= IROp::Eq && e->op <= IROp::Uge) return "int";
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
            return out;
        }

        // Emit a pointer dereference, adding a cast if the address isn't a pointer type.
        // This prevents "invalid type argument of unary '*' (have 'int')" errors.
        std::string emitDeref(const std::string &addrStr, TypeRef loadType = NullType,
                              TypeRef addrType = NullType) {
            // If the address is already a pointer type, just dereference without cast
            if (addrType != NullType) {
                auto *at = m_types.resolveType(addrType);
                if (at && at->kind == StabsTypeKind::Pointer)
                    return "*(" + addrStr + ")";
            }
            if (loadType != NullType) {
                std::string t = m_types.formatType(loadType);
                return "*((" + t + " *)(" + addrStr + "))";
            }
            return "*((int *)(" + addrStr + "))";
        }

        // Emit a store through a pointer, adding a cast if needed.
        std::string emitStoreDeref(const std::string &addrStr, TypeRef storeType = NullType,
                                   TypeRef addrType = NullType) {
            if (addrType != NullType) {
                auto *at = m_types.resolveType(addrType);
                if (at && at->kind == StabsTypeKind::Pointer)
                    return "*(" + addrStr + ")";
            }
            if (storeType != NullType) {
                std::string t = m_types.formatType(storeType);
                return "*((" + t + " *)(" + addrStr + "))";
            }
            return "*((int *)(" + addrStr + "))";
        }

        std::string emitCast(IRExpr *e) {
            if (e->kids.empty() || !e->kids[0]) return "0";
            std::string inner = emitExpr(e->kids[0].get());
            if (inner.empty()) return "0";
            switch (e->castKind) {
            case CastKind::ZeroExt8:   return "(unsigned char)(" + inner + ")";
            case CastKind::ZeroExt16:  return "(unsigned short)(" + inner + ")";
            case CastKind::SignExt8:   return "(signed char)(" + inner + ")";
            case CastKind::SignExt16:  return "(short)(" + inner + ")";
            case CastKind::Trunc8:     return "(char)(" + inner + ")";
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
