#pragma once

#include "ir.h"
#include "port_emission_fixes.h"
#include "stabs_types.h"

#include <map>
#include <memory>
#include <string>

namespace PortIrFixes {

using TempDefs = std::map<int, std::unique_ptr<IRExpr>>;

inline bool isLocalName(const IRFunc &func, const std::string &name) {
    for (const auto &param : func.params) {
        if (param.name == name)
            return true;
    }
    for (const auto &local : func.locals) {
        if (local.name == name)
            return true;
    }
    return false;
}

inline const IRExpr *unwrapCasts(const IRExpr *expr) {
    const IRExpr *node = expr;
    for (int depth = 0; depth < 8 && node; ++depth) {
        if (node->op == IROp::Cast && !node->kids.empty()) {
            node = node->kids[0].get();
            continue;
        }
        break;
    }
    return node;
}

inline const IRExpr *resolveValue(const IRExpr *expr, const TempDefs &tempDefs,
                                  int depth = 0) {
    const IRExpr *node = unwrapCasts(expr);
    if (!node || depth > 8)
        return node;
    if (node->op == IROp::Temp) {
        auto it = tempDefs.find(node->tempId());
        if (it != tempDefs.end())
            return resolveValue(it->second.get(), tempDefs, depth + 1);
    }
    return node;
}

inline std::string opaqueStorageAddressBase(const IRExpr *expr,
                                            const IRFunc &func,
                                            const TempDefs &tempDefs) {
    const IRExpr *node = resolveValue(expr, tempDefs);
    if (!node)
        return "";

    if (node->op == IROp::Var &&
        !isLocalName(func, node->name) &&
        !PortEmissionFixes::opaqueStorageFieldNameForGlobal(node->name).empty())
        return node->name;

    if (node->op == IROp::Add && node->kids.size() == 2) {
        for (int side = 0; side < 2; ++side) {
            const IRExpr *offset = resolveValue(node->kids[side].get(), tempDefs);
            const IRExpr *base = resolveValue(node->kids[1 - side].get(), tempDefs);
            if (offset && offset->isConst() && offset->value == 0 &&
                base && base->op == IROp::Var &&
                !isLocalName(func, base->name) &&
                !PortEmissionFixes::opaqueStorageFieldNameForGlobal(base->name).empty())
                return base->name;
        }
    }

    return "";
}

inline std::unique_ptr<IRExpr> ptrToStorageAddress(const StabsTypeTable &types,
                                                   const std::string &name) {
    TypeRef typeRef = NullType;
    if (auto *global = types.globalByName(name))
        typeRef = global->typeRef;
    return IRExpr::mkCast(
        CastKind::PtrToInt,
        IRExpr::mkAddrOf(IRExpr::mkVar(name, typeRef)));
}

inline std::unique_ptr<IRExpr> transformExpr(std::unique_ptr<IRExpr> expr,
                                             const IRFunc &func,
                                             const StabsTypeTable &types,
                                             const TempDefs &tempDefs) {
    if (!expr)
        return expr;

    for (auto &kid : expr->kids) {
        if (kid)
            kid = transformExpr(std::move(kid), func, types, tempDefs);
    }

    if (expr->op == IROp::Field && expr->value == 0 && !expr->kids.empty()) {
        const IRExpr *base = resolveValue(expr->kids[0].get(), tempDefs);
        if (base && base->op == IROp::Var &&
            !isLocalName(func, base->name) &&
            PortEmissionFixes::isOpaqueStorageField(base->name, expr->name))
            return ptrToStorageAddress(types, base->name);
    }

    if (expr->op == IROp::Load && expr->kids.size() == 1) {
        std::string baseName = opaqueStorageAddressBase(expr->kids[0].get(), func, tempDefs);
        if (!baseName.empty())
            return ptrToStorageAddress(types, baseName);
    }

    return expr;
}

inline void run(IRFunc &func, const StabsTypeTable &types) {
    TempDefs tempDefs;
    for (auto &block : func.blocks) {
        for (auto &stmt : block.stmts) {
            if (stmt.kind == IRStmtKind::Assign && stmt.destTemp >= 0 && stmt.expr)
                tempDefs[stmt.destTemp] = stmt.expr->clone();
        }
    }

    for (auto &block : func.blocks) {
        for (auto &stmt : block.stmts) {
            if (stmt.addr)
                stmt.addr = transformExpr(std::move(stmt.addr), func, types, tempDefs);
            if (stmt.expr)
                stmt.expr = transformExpr(std::move(stmt.expr), func, types, tempDefs);
            for (auto &arg : stmt.args) {
                if (arg)
                    arg = transformExpr(std::move(arg), func, types, tempDefs);
            }
        }
    }
}

} // namespace PortIrFixes
