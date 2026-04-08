#pragma once
#include "stabs_types.h"
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <set>
#include <cassert>
#include <cstdio>
#include <algorithm>

// ── Intermediate Representation ──────────────────────────────────────
// Every x86 instruction lifts to one or more IR statements operating on
// IR expressions.  Expressions form trees that map directly to C
// sub-expressions, so emitting C is a straightforward tree walk.

// ── IR expression nodes ──────────────────────────────────────────────

enum class IROp {
    // Leaf nodes
    Const,      // integer / fp literal
    Temp,       // SSA-like temporary  (t0, t1, …)
    Var,        // named variable (param/local/global via STABS)
    String,     // string literal address resolved from __cstring
    FuncRef,    // reference to a known function name

    // Unary
    Neg, Not, BoolNot,
    Load,       // memory dereference  *(expr)
    AddrOf,     // &expr
    Cast,       // (type)expr — castKind says which

    // Binary arithmetic / logic
    Add, Sub, Mul, SDiv, UDiv, SMod, UMod,
    Shl, Shr, Sar,
    And, Or, Xor,

    // Comparisons — produce 1/0
    Eq, Ne, Slt, Sle, Sgt, Sge, Ult, Ule, Ugt, Uge,

    // Struct field access
    Field,      // base->fieldName  (fieldName stored in name, offset in value)

    // Ternary (for cmov)
    Ternary,    // cond ? a : b

    // Call expression (result of a function call)
    Call,
};

enum class CastKind {
    None,
    ZeroExt8, ZeroExt16,   // unsigned widening from 8/16 bits
    SignExt8, SignExt16,    // signed widening
    Trunc8, Trunc16,       // narrowing
    IntToFloat, FloatToInt,
    BitCast,
};

struct IRExpr {
    IROp        op;
    int64_t     value    = 0;       // Const value, Temp id, Field offset
    std::string name;               // Var/Field/FuncRef/String name
    TypeRef     typeRef  = NullType; // STABS type annotation
    CastKind    castKind = CastKind::None;

    // Children (owned)
    std::vector<std::unique_ptr<IRExpr>> kids;

    // How many statements reference this temp (for inlining decisions)
    int useCount = 0;
    int loadSize = 4;  // For Load: memory access size in bytes (1, 2, 4)

    // ── Constructors ────────────────────────────────────────────────
    static std::unique_ptr<IRExpr> mkConst(int64_t v, TypeRef t = NullType) {
        auto e = std::make_unique<IRExpr>();
        e->op = IROp::Const; e->value = v; e->typeRef = t;
        return e;
    }
    static std::unique_ptr<IRExpr> mkTemp(int id, TypeRef t = NullType) {
        auto e = std::make_unique<IRExpr>();
        e->op = IROp::Temp; e->value = id; e->typeRef = t;
        return e;
    }
    static std::unique_ptr<IRExpr> mkVar(const std::string &n, TypeRef t = NullType) {
        auto e = std::make_unique<IRExpr>();
        e->op = IROp::Var; e->name = n; e->typeRef = t;
        return e;
    }
    static std::unique_ptr<IRExpr> mkString(const std::string &s) {
        auto e = std::make_unique<IRExpr>();
        e->op = IROp::String; e->name = s;
        return e;
    }
    static std::unique_ptr<IRExpr> mkFunc(const std::string &n) {
        auto e = std::make_unique<IRExpr>();
        e->op = IROp::FuncRef; e->name = n;
        return e;
    }
    static std::unique_ptr<IRExpr> mkLoad(std::unique_ptr<IRExpr> addr, TypeRef t = NullType) {
        auto e = std::make_unique<IRExpr>();
        e->op = IROp::Load; e->typeRef = t;
        e->kids.push_back(std::move(addr));
        return e;
    }
    static std::unique_ptr<IRExpr> mkAddrOf(std::unique_ptr<IRExpr> inner) {
        auto e = std::make_unique<IRExpr>();
        e->op = IROp::AddrOf;
        e->kids.push_back(std::move(inner));
        return e;
    }
    static std::unique_ptr<IRExpr> mkField(std::unique_ptr<IRExpr> base,
                                           const std::string &fieldName,
                                           int offset, TypeRef t = NullType) {
        auto e = std::make_unique<IRExpr>();
        e->op = IROp::Field; e->name = fieldName; e->value = offset; e->typeRef = t;
        e->kids.push_back(std::move(base));
        return e;
    }
    static std::unique_ptr<IRExpr> mkUnary(IROp op, std::unique_ptr<IRExpr> a) {
        auto e = std::make_unique<IRExpr>();
        e->op = op;
        e->kids.push_back(std::move(a));
        return e;
    }
    static std::unique_ptr<IRExpr> mkBinary(IROp op, std::unique_ptr<IRExpr> a,
                                            std::unique_ptr<IRExpr> b) {
        auto e = std::make_unique<IRExpr>();
        e->op = op;
        e->kids.push_back(std::move(a));
        e->kids.push_back(std::move(b));
        return e;
    }
    static std::unique_ptr<IRExpr> mkCast(CastKind ck, std::unique_ptr<IRExpr> inner,
                                          TypeRef t = NullType) {
        auto e = std::make_unique<IRExpr>();
        e->op = IROp::Cast; e->castKind = ck; e->typeRef = t;
        e->kids.push_back(std::move(inner));
        return e;
    }
    static std::unique_ptr<IRExpr> mkCall(const std::string &target,
                                          std::vector<std::unique_ptr<IRExpr>> args,
                                          TypeRef retType = NullType) {
        auto e = std::make_unique<IRExpr>();
        e->op = IROp::Call; e->name = target; e->typeRef = retType;
        e->kids = std::move(args);
        return e;
    }
    static std::unique_ptr<IRExpr> mkTernary(std::unique_ptr<IRExpr> cond,
                                             std::unique_ptr<IRExpr> a,
                                             std::unique_ptr<IRExpr> b) {
        auto e = std::make_unique<IRExpr>();
        e->op = IROp::Ternary;
        e->kids.push_back(std::move(cond));
        e->kids.push_back(std::move(a));
        e->kids.push_back(std::move(b));
        return e;
    }

    // Deep clone
    std::unique_ptr<IRExpr> clone() const {
        auto e = std::make_unique<IRExpr>();
        e->op = op; e->value = value; e->name = name;
        e->typeRef = typeRef; e->castKind = castKind; e->useCount = useCount;
        e->loadSize = loadSize;
        for (auto &k : kids)
            e->kids.push_back(k->clone());
        return e;
    }

    bool isConst() const { return op == IROp::Const; }
    bool isTemp()  const { return op == IROp::Temp; }
    bool isZero()  const { return op == IROp::Const && value == 0; }
    int  tempId()  const { assert(op == IROp::Temp); return (int)value; }
};

// ── IR statements ────────────────────────────────────────────────────

enum class IRStmtKind {
    Assign,     // temp = expr
    Store,      // *addr = expr
    VarSet,     // named_var = expr  (param/local/global)
    Call,       // expr(args)  — void call, no assignment
    Branch,     // if (cond) goto trueTarget else goto falseTarget
    Jump,       // goto target
    Return,     // return expr (expr may be null for void)
    Label,      // block label (not a real statement, just a marker)
    Intrinsic,  // rep movsb / cpuid / etc — things with no C equivalent, emitted as inline comment or helper call
    Switch,     // switch(expr) { case val: goto block; ... }
    Phi,        // SSA phi node: t = phi(t_from_pred1, t_from_pred2, ...)
};

struct IRStmt {
    IRStmtKind kind;
    int        destTemp = -1;          // for Assign: which temp is being defined
    std::string destVar;               // for VarSet: variable name
    TypeRef    destType = NullType;    // type of destination
    std::unique_ptr<IRExpr> expr;      // main expression (rhs for assign/store, cond for branch, ret val)
    std::unique_ptr<IRExpr> addr;      // for Store: the address expression
    std::vector<std::unique_ptr<IRExpr>> args; // for Call: arguments

    uint32_t   address = 0;           // original instruction address (for debugging)

    // For Branch
    int trueTarget  = -1;             // basic block id
    int falseTarget = -1;

    // For Jump
    int jumpTarget = -1;

    // For Intrinsic
    std::string intrinsicName;
    std::string intrinsicComment;      // C-like comment or helper call text

    // For Label
    int blockId = -1;

    // For Switch: case_value → block_id, plus default block
    std::vector<std::pair<int, int>> switchCases;  // (case_value, target_block_id)
    int switchDefault = -1;
    int switchBase = 0;  // value subtracted before indexing (e.g. sub eax, 7 → base=7)

    // For Phi: (predecessorBlockId, sourceTempId) pairs
    std::vector<std::pair<int,int>> phiSources;

    // ── Factories ───────────────────────────────────────────────────
    static IRStmt mkAssign(int temp, std::unique_ptr<IRExpr> rhs, TypeRef t = NullType) {
        IRStmt s; s.kind = IRStmtKind::Assign;
        s.destTemp = temp; s.expr = std::move(rhs); s.destType = t;
        return s;
    }
    int storeSize = 4; // for Store: memory access size in bytes (1, 2, 4)
    static IRStmt mkStore(std::unique_ptr<IRExpr> address, std::unique_ptr<IRExpr> val, int size = 4) {
        IRStmt s; s.kind = IRStmtKind::Store;
        s.addr = std::move(address); s.expr = std::move(val); s.storeSize = size;
        return s;
    }
    static IRStmt mkVarSet(const std::string &name, std::unique_ptr<IRExpr> val, TypeRef t = NullType, int size = 4) {
        IRStmt s; s.kind = IRStmtKind::VarSet;
        s.destVar = name; s.expr = std::move(val); s.destType = t; s.storeSize = size;
        return s;
    }
    static IRStmt mkCall(std::unique_ptr<IRExpr> callExpr) {
        IRStmt s; s.kind = IRStmtKind::Call;
        s.expr = std::move(callExpr);
        return s;
    }
    static IRStmt mkBranch(std::unique_ptr<IRExpr> cond, int trueB, int falseB) {
        IRStmt s; s.kind = IRStmtKind::Branch;
        s.expr = std::move(cond); s.trueTarget = trueB; s.falseTarget = falseB;
        return s;
    }
    static IRStmt mkJump(int target) {
        IRStmt s; s.kind = IRStmtKind::Jump; s.jumpTarget = target;
        return s;
    }
    static IRStmt mkReturn(std::unique_ptr<IRExpr> val = nullptr) {
        IRStmt s; s.kind = IRStmtKind::Return; s.expr = std::move(val);
        return s;
    }
    static IRStmt mkIntrinsic(const std::string &name, const std::string &cText) {
        IRStmt s; s.kind = IRStmtKind::Intrinsic;
        s.intrinsicName = name; s.intrinsicComment = cText;
        return s;
    }
    static IRStmt mkSwitch(std::unique_ptr<IRExpr> expr,
                           std::vector<std::pair<int, int>> cases,
                           int defaultBlock, int base = 0) {
        IRStmt s; s.kind = IRStmtKind::Switch;
        s.expr = std::move(expr);
        s.switchCases = std::move(cases);
        s.switchDefault = defaultBlock;
        s.switchBase = base;
        return s;
    }
    static IRStmt mkPhi(int destTemp, std::vector<std::pair<int,int>> sources) {
        IRStmt s; s.kind = IRStmtKind::Phi;
        s.destTemp = destTemp;
        s.phiSources = std::move(sources);
        return s;
    }
};

// ── Basic block ──────────────────────────────────────────────────────

struct BasicBlock {
    int                    id = -1;
    uint32_t               startAddr = 0;
    uint32_t               endAddr   = 0;
    std::vector<IRStmt>    stmts;
    std::vector<int>       succs;    // successor block ids
    std::vector<int>       preds;    // predecessor block ids

    // Structure recovery annotations
    enum StructKind { Plain, IfThen, IfElse, WhileHead, DoWhileHead,
                      ForHead, SwitchHead, LoopBreak, LoopContinue };
    StructKind structKind = Plain;
    int structPartner = -1;          // e.g. else block for IfElse
    int structEnd     = -1;          // block after the whole structure
    bool isLoopHeader = false;
    int  loopEnd      = -1;
};

// ── IR function ──────────────────────────────────────────────────────

struct IRFunc {
    std::string              name;
    uint32_t                 address = 0;
    TypeRef                  returnType = NullType;
    bool                     isStatic = false;
    bool                     detectedVoid = false; // heuristic: function returns void despite STABS saying int
    std::set<int>            phiTemps;    // temps from phi nodes — don't const-propagate
    std::set<int>            pointerTemps; // temps known to be pointers (from type inference)
    std::vector<StabsTypedVar> params;
    std::vector<StabsTypedVar> locals;
    int                      sourceFileIdx = -1;

    std::vector<BasicBlock>  blocks;
    int                      nextTemp = 0;

    // Temp type tracking
    std::map<int, TypeRef>   tempTypes;

    // SSA / analysis fields
    std::vector<int>              idom;        // immediate dominators (indexed by block id)
    std::map<int, int>            tempToReg;   // tempId -> canonical register id (for SSA)
    std::map<int, int>            tempToVar;   // tempId -> coalesced variable id
    std::map<int, std::string>    varNames;    // varId -> display name
    std::map<int, TypeRef>        varTypes;    // varId -> inferred type
    std::set<int>                 noFloatVars; // varIds where float type was cleared (float/pointer conflict)

    int newTemp(TypeRef t = NullType) {
        int id = nextTemp++;
        if (t != NullType) tempTypes[id] = t;
        return id;
    }
    TypeRef tempType(int id) const {
        auto it = tempTypes.find(id);
        return it != tempTypes.end() ? it->second : NullType;
    }

    BasicBlock& addBlock(uint32_t addr) {
        int id = (int)blocks.size();
        blocks.push_back({});
        blocks.back().id = id;
        blocks.back().startAddr = addr;
        return blocks.back();
    }
};
