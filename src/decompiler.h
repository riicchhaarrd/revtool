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
    static QString decompile(const MachOFile &mf, uint32_t funcAddr) {
        Lifter lifter(mf);
        IRFunc func = lifter.liftFunction(funcAddr);
        if (func.blocks.empty()) return "/* could not decompile */\n";

        CfgStructurer structurer;
        auto tree = structurer.structure(func);

        Emitter em(mf, func);
        return clangFormat(em.generate(tree.get()));
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

        // Emit includes relevant to this source file
        std::set<std::string> emitted;
        for (auto &inc : types.includes()) {
            // Only emit .h files, skip the source file itself
            if (inc.find(".h") == std::string::npos) continue;
            std::string incName = inc;
            size_t slash = inc.rfind('/');
            if (slash != std::string::npos) incName = inc.substr(slash + 1);
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

        // Emit global/static variables for this file
        for (auto &g : types.globals()) {
            if (g.address == 0) continue;
            std::string typeStr = types.formatType(g.typeRef);
            if (typeStr.empty()) typeStr = "int";
            out += QString::fromStdString(
                (g.isStatic ? "static " : "") + types.formatDecl(g.typeRef, g.name)) + ";\n";
        }
        if (!types.globals().empty()) out += "\n";

        // Decompile each function
        std::vector<size_t> sorted = sf.functionIndices;
        std::sort(sorted.begin(), sorted.end(), [&](size_t a, size_t b) {
            return mf.stabsFunctions()[a].address < mf.stabsFunctions()[b].address;
        });

        for (size_t fi : sorted) {
            auto &fn = mf.stabsFunctions()[fi];
            if (fn.address == 0) continue;
            out += decompile(mf, fn.address);
            out += "\n";
        }

        return clangFormat(out);
    }

    // Run clang-format on the output for clean formatting
    static QString clangFormat(const QString &code) {
        QProcess proc;
        proc.start("clang-format", QStringList()
            << "-style={BasedOnStyle: LLVM, IndentWidth: 4, ColumnLimit: 100}"
            << "-assume-filename=decompiled.c");
        if (!proc.waitForStarted(1000)) return code;
        proc.write(code.toUtf8());
        proc.closeWriteChannel();
        if (!proc.waitForFinished(5000)) return code;
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

        // Resolve through pointers/typedefs to find underlying struct/enum
        if (t->kind == StabsTypeKind::Pointer || t->kind == StabsTypeKind::Typedef ||
            t->kind == StabsTypeKind::Const || t->kind == StabsTypeKind::Volatile) {
            if (t->targetType != NullType)
                emitTypeDefsRecursive(out, types, t->targetType, emitted, depth + 1);
            return;
        }
        if (t->kind == StabsTypeKind::Struct || t->kind == StabsTypeKind::Union) {
            if (t->name.empty() || t->fields.empty()) return;
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
        }

        QString generate(StructNode *root) {
            QString out;

            // Function signature
            std::string retType = "int";
            if (m_func.returnType != NullType)
                retType = m_types.formatType(m_func.returnType);

            std::string qual = m_func.isStatic ? "static " : "";
            out += QString::fromStdString(qual + retType) + " " +
                   QString::fromStdString(m_func.name) + "(";

            if (!m_func.params.empty()) {
                for (size_t i = 0; i < m_func.params.size(); ++i) {
                    if (i) out += ", ";
                    auto &p = m_func.params[i];
                    out += QString::fromStdString(
                        p.typeRef != NullType ? m_types.formatDecl(p.typeRef, p.name)
                                              : "int " + p.name);
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

            // Declare temps that are used more than once and aren't copy-propagated away
            for (auto &[id, type] : m_func.tempTypes) {
                if (m_tempUseCount[id] > 1 && !m_copyPropagated.count(id)) {
                    std::string tname = "t" + std::to_string(id);
                    std::string ttype = (type != NullType) ? m_types.formatType(type) : "int";
                    out += "    " + QString::fromStdString(ttype + " " + tname) + ";\n";
                    declared.insert(tname);
                }
            }
            if (!declared.empty()) out += "\n";

            // Emit structured body
            emitNode(out, root, 1);

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
                    TypeRef t = e->typeRef;
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
                bool hasBody = !node->children.empty();
                bool hasElse = node->elseNode != nullptr;
                if (!hasBody && !hasElse) break;
                // If body is empty but else exists, invert the condition
                if (!hasBody && hasElse) {
                    std::string cond = node->cond ? emitExpr(node->cond, !node->negated) : "1";
                    out += pad(indent) + "if (" + QString::fromStdString(cond) + ") {\n";
                    emitNode(out, node->elseNode.get(), indent + 1);
                    out += pad(indent) + "}\n";
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

            case StructKind::DoWhile: {
                out += pad(indent) + "do {\n";
                for (auto &child : node->children)
                    emitNode(out, child.get(), indent + 1);
                std::string cond = node->cond ? emitExpr(node->cond, false) : "1";
                out += pad(indent) + "} while (" + QString::fromStdString(cond) + ");\n";
                break;
            }

            case StructKind::Goto:
                out += pad(indent) + QString("goto bb_%1;\n").arg(node->gotoTarget);
                break;

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
            auto &bb = m_func.blocks[bbId];
            for (int i = start; i < end && i < (int)bb.stmts.size(); ++i) {
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
                         (a->kids[0]->op == IROp::Var || a->kids[0]->op == IROp::Temp)) {
                    std::string base = emitExpr(a->kids[0].get());
                    int off = (int)a->kids[1]->value;
                    char fname[32]; snprintf(fname, sizeof(fname), "field_%X", (unsigned)off);
                    out += pad(indent) + QString::fromStdString(base + "->" + fname + " = " + val) + ";\n";
                } else {
                    out += pad(indent) + QString::fromStdString("*(" + emitExpr(a) + ") = " + val) + ";\n";
                }
                break;
            }
            case IRStmtKind::VarSet: {
                std::string val = stmt.expr ? emitExpr(stmt.expr.get()) : "0";
                out += pad(indent) + QString::fromStdString(stmt.destVar + " = " + val) + ";\n";
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
                    if (it != m_tempDef.end() && it->second)
                        return emitExpr(it->second, negate);
                }
                result = "t" + std::to_string(id);
                break;
            }
            case IROp::Var:    result = e->name; break;
            case IROp::String: result = e->name; break;
            case IROp::FuncRef: result = e->name; break;

            case IROp::Load: {
                auto *addr = e->kids[0].get();
                // (base + const) → base->field_XX
                if (addr && addr->op == IROp::Add && addr->kids.size() == 2 &&
                    addr->kids[1]->isConst() && addr->kids[1]->value >= 0 &&
                    (addr->kids[0]->op == IROp::Var || addr->kids[0]->op == IROp::Temp)) {
                    std::string base = emitExpr(addr->kids[0].get());
                    int off = (int)addr->kids[1]->value;
                    char fname[32]; snprintf(fname, sizeof(fname), "field_%X", (unsigned)off);
                    result = base + "->" + fname;
                }
                // bare var/temp dereference → var->field_0 (first field)
                else if (addr && (addr->op == IROp::Var || addr->op == IROp::Temp)) {
                    result = emitExpr(addr) + "->field_0";
                } else {
                    result = "*(" + emitExpr(addr) + ")";
                }
                break;
            }

            case IROp::AddrOf:
                result = "&" + emitExpr(e->kids[0].get());
                break;

            case IROp::Field:
                result = emitExpr(e->kids[0].get()) + "->" + e->name;
                break;

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
                if (e->kids[0]->isConst() && e->kids[1]->isConst()) {
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
                if (e->kids[1]->isConst()) {
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
                if (e->kids[0]->isConst()) {
                    int64_t a = e->kids[0]->value;
                    if ((e->op == IROp::Add || e->op == IROp::Or || e->op == IROp::Xor) && a == 0) {
                        result = emitExpr(e->kids[1].get()); break;
                    }
                    if (e->op == IROp::Mul && a == 1) {
                        result = emitExpr(e->kids[1].get()); break;
                    }
                    if (e->op == IROp::Mul && a == 0) { result = "0"; break; }
                }
                std::string lhs = emitExpr(e->kids[0].get());
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
                result = e->name + "(";
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

            if (negate && !result.empty()) {
                // Negate the result
                if (result[0] == '!') return result.substr(1);
                return "!(" + result + ")";
            }

            return result;
        }

        std::string emitCast(IRExpr *e) {
            std::string inner = emitExpr(e->kids[0].get());
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
            if (f > 0.001f && f < 1000000.0f) {
                char buf[32]; snprintf(buf, sizeof(buf), "%.6gf", f);
                return buf;
            }
            if (f < -0.001f && f > -1000000.0f) {
                char buf[32]; snprintf(buf, sizeof(buf), "%.6gf", f);
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
