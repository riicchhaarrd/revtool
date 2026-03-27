#pragma once
#include "ir.h"
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <cassert>

// ── Control Flow Graph structuring ───────────────────────────────────
// Recovers if/else, while, do-while, and switch from the basic block
// CFG produced by the lifter.  Outputs a structured tree that maps
// directly to C control flow.

// ── Structured node tree ─────────────────────────────────────────────
// This is what the C emitter walks.

enum class StructKind {
    Block,      // sequential list of children
    If,         // if (cond) { then } [else { els }]
    While,      // while (cond) { body }
    For,        // for (init; cond; incr) { body }
    DoWhile,    // do { body } while (cond)
    Switch,     // switch (expr) { cases }
    Goto,       // irreducible: goto label
    Return,     // return expr
    Break,
    Continue,
    Seq,        // sequence of IR stmts from a basic block
};

struct StructNode {
    StructKind kind;
    int bbId = -1;              // source basic block (for Seq)

    // For Seq: the IR statements from this block (indices into IRFunc::blocks[bbId].stmts)
    int stmtStart = 0;
    int stmtEnd   = 0;         // exclusive

    // For If: condition expression (owned, from branch stmt)
    IRExpr *cond = nullptr;     // points into the BB's branch stmt — not owned
    bool negated = false;       // if true, condition was inverted

    // Children
    std::vector<std::unique_ptr<StructNode>> children;
    std::unique_ptr<StructNode> elseNode;   // for If

    // For Goto
    int gotoTarget = -1;

    // For For: init and increment statement indices (in the header block)
    int forInitBB = -1;     // block containing the init statement
    int forInitStmt = -1;   // index of the init statement
    int forIncrBB = -1;     // block containing the increment
    int forIncrStmt = -1;   // index of the increment statement

    static std::unique_ptr<StructNode> mkSeq(int bb, int start, int end) {
        auto n = std::make_unique<StructNode>();
        n->kind = StructKind::Seq; n->bbId = bb; n->stmtStart = start; n->stmtEnd = end;
        return n;
    }
    static std::unique_ptr<StructNode> mkBlock() {
        auto n = std::make_unique<StructNode>();
        n->kind = StructKind::Block;
        return n;
    }
    static std::unique_ptr<StructNode> mkIf(IRExpr *c, bool neg = false) {
        auto n = std::make_unique<StructNode>();
        n->kind = StructKind::If; n->cond = c; n->negated = neg;
        return n;
    }
    static std::unique_ptr<StructNode> mkWhile(IRExpr *c) {
        auto n = std::make_unique<StructNode>();
        n->kind = StructKind::While; n->cond = c;
        return n;
    }
    static std::unique_ptr<StructNode> mkDoWhile(IRExpr *c) {
        auto n = std::make_unique<StructNode>();
        n->kind = StructKind::DoWhile; n->cond = c;
        return n;
    }
    static std::unique_ptr<StructNode> mkGoto(int target) {
        auto n = std::make_unique<StructNode>();
        n->kind = StructKind::Goto; n->gotoTarget = target;
        return n;
    }
    static std::unique_ptr<StructNode> mkBreak() {
        auto n = std::make_unique<StructNode>();
        n->kind = StructKind::Break;
        return n;
    }
    static std::unique_ptr<StructNode> mkContinue() {
        auto n = std::make_unique<StructNode>();
        n->kind = StructKind::Continue;
        return n;
    }
};

// ── CFG Structurer ───────────────────────────────────────────────────

class CfgStructurer {
public:
    std::unique_ptr<StructNode> structure(IRFunc &func) {
        m_func = &func;
        int n = (int)func.blocks.size();
        if (n == 0) return StructNode::mkBlock();

        // For very large functions, skip expensive structuring and emit flat blocks
        if (n > 500) {
            auto block = StructNode::mkBlock();
            for (int i = 0; i < n; ++i)
                if (!func.blocks[i].stmts.empty())
                    block->children.push_back(StructNode::mkSeq(i, 0, (int)func.blocks[i].stmts.size()));
            return block;
        }

        // Compute dominators and loop info
        computeDominators();
        findLoops();

        // Structure from the entry block (using bitvector for fast set ops)
        std::vector<bool> visited(n, false);
        return structureRegion(0, -1, visited);
    }

private:
    IRFunc *m_func = nullptr;
    std::vector<int> m_idom;                       // immediate dominator
    std::set<std::pair<int,int>> m_backEdges;      // (from, to) = back edges (loops)
    std::map<int, int> m_loopEnd;                  // loop header → block after loop

    // ── Dominator computation (simple O(n^2) iterative) ─────────────
    void computeDominators() {
        int n = (int)m_func->blocks.size();
        m_idom.assign(n, -1);
        m_idom[0] = 0;
        if (n <= 1) return;

        // Cooper-Harvey-Kennedy algorithm for immediate dominators
        // Much faster than the iterative set-based approach for large CFGs
        // Uses reverse postorder numbering

        // Compute reverse postorder
        std::vector<int> rpo;       // rpo[i] = block id at position i
        std::vector<int> rpoNum(n, -1); // rpoNum[blockId] = position in rpo
        {
            std::vector<bool> visited(n, false);
            std::vector<int> postorder;
            // Iterative DFS
            std::vector<std::pair<int, int>> stack = {{0, 0}}; // (block, child_index)
            visited[0] = true;
            while (!stack.empty()) {
                auto &[node, ci] = stack.back();
                auto &succs = m_func->blocks[node].succs;
                if (ci < (int)succs.size()) {
                    int s = succs[ci++];
                    if (s >= 0 && s < n && !visited[s]) {
                        visited[s] = true;
                        stack.push_back({s, 0});
                    }
                } else {
                    postorder.push_back(node);
                    stack.pop_back();
                }
            }
            rpo.resize(postorder.size());
            for (int i = 0; i < (int)postorder.size(); ++i) {
                rpo[postorder.size() - 1 - i] = postorder[i];
                rpoNum[postorder[i]] = (int)postorder.size() - 1 - i;
            }
        }

        // Intersect two nodes in the dominator tree
        auto intersect = [&](int b1, int b2) -> int {
            int f1 = b1, f2 = b2;
            while (f1 != f2) {
                while (rpoNum[f1] > rpoNum[f2]) f1 = m_idom[f1];
                while (rpoNum[f2] > rpoNum[f1]) f2 = m_idom[f2];
            }
            return f1;
        };

        // Iterative dominator computation
        bool changed = true;
        for (int iter = 0; iter < n && changed; ++iter) {
            changed = false;
            for (int idx = 1; idx < (int)rpo.size(); ++idx) {
                int b = rpo[idx];
                int newIdom = -1;
                for (int p : m_func->blocks[b].preds) {
                    if (p < 0 || p >= n || m_idom[p] == -1) continue;
                    if (newIdom == -1) newIdom = p;
                    else newIdom = intersect(newIdom, p);
                }
                if (newIdom == -1) newIdom = 0;
                if (m_idom[b] != newIdom) {
                    m_idom[b] = newIdom;
                    changed = true;
                }
            }
        }
    }

    // ── Loop detection via back edges ───────────────────────────────
    void findLoops() {
        int n = (int)m_func->blocks.size();
        // A back edge is (b, h) where h dominates b
        std::set<int> domSet;
        for (int b = 0; b < n; ++b) {
            for (int s : m_func->blocks[b].succs) {
                if (s < 0 || s >= n) continue;
                // Check if s dominates b (simple: walk idom chain from b)
                bool dom = false;
                int x = b;
                for (int step = 0; step < n && x >= 0; ++step) {
                    if (x == s) { dom = true; break; }
                    if (m_idom[x] == x) break;
                    x = m_idom[x];
                }
                if (dom) {
                    m_backEdges.insert({b, s});
                    m_func->blocks[s].isLoopHeader = true;
                }
            }
        }

        // For each loop header, find the last block before the loop exits
        for (auto &[from, header] : m_backEdges) {
            // The loop end is the fall-through block after the back-edge source
            // or the target of the loop-exit branch
            auto &hbb = m_func->blocks[header];
            if (!hbb.stmts.empty() && hbb.stmts.back().kind == IRStmtKind::Branch) {
                auto &br = hbb.stmts.back();
                // One target is the loop body, the other is the loop exit
                int exitBlock = -1;
                if (br.trueTarget > header && br.trueTarget <= from + 1)
                    exitBlock = br.falseTarget;
                else
                    exitBlock = br.trueTarget;
                if (exitBlock >= 0) m_loopEnd[header] = exitBlock;
            } else {
                m_loopEnd[header] = from + 1;
            }
        }
    }

    // ── Structure a region of blocks ────────────────────────────────
    int m_depth = 0;
    int m_totalCalls = 0;
    std::vector<int> m_loopExitStack; // innermost-first stack of active loop exit blocks

    std::unique_ptr<StructNode> structureRegion(int start, int end, std::vector<bool> &visited) {
        auto block = StructNode::mkBlock();
        int n = (int)m_func->blocks.size();
        ++m_depth;
        if (m_depth > 200 || ++m_totalCalls > n * 4) { --m_depth; return block; }
        int cur = start;

        while (cur >= 0 && cur < n && cur != end && !visited[cur]) {
            visited[cur] = true;
            auto &bb = m_func->blocks[cur];

            // Check if this is a loop header
            if (bb.isLoopHeader && m_loopEnd.count(cur)) {
                int loopExit = m_loopEnd[cur];

                // Determine loop kind: while or do-while
                // While: header has a branch, one arm is body, other is exit
                if (!bb.stmts.empty() && bb.stmts.back().kind == IRStmtKind::Branch) {
                    auto &br = bb.stmts.back();
                    int bodyTarget = -1;
                    bool negCond = false;

                    if (br.falseTarget == loopExit) {
                        bodyTarget = br.trueTarget;
                        negCond = false;
                    } else if (br.trueTarget == loopExit) {
                        bodyTarget = br.falseTarget;
                        negCond = true;
                    } else {
                        // Can't determine structure — treat as loop with body=true
                        bodyTarget = br.trueTarget;
                        negCond = false;
                    }

                    // Emit statements before the branch
                    int stmtEnd = (int)bb.stmts.size() - 1; // exclude branch
                    if (stmtEnd > 0)
                        block->children.push_back(StructNode::mkSeq(cur, 0, stmtEnd));

                    // Structure the loop body first
                    std::vector<bool> bodyVisited = visited;
                    m_loopExitStack.push_back(loopExit);
                    auto body = structureRegion(bodyTarget, cur, bodyVisited);
                    m_loopExitStack.pop_back();
                    for (int vi = 0; vi < n; ++vi) if (bodyVisited[vi]) visited[vi] = true;

                    // Try to detect for-loop pattern:
                    // Previous stmt: var = const (init)
                    // Loop body last stmt: var = var + 1 (increment)
                    // Condition uses var
                    bool isForLoop = false;
                    int initBB = -1, initStmt = -1, incrBB = -1, incrStmt = -1;
                    if (bodyTarget >= 0 && bodyTarget < n) {
                        // Look for init: first check this block's pre-branch stmts,
                        // then the previous Seq node (preceding block's statements)
                        int initCandBB = cur, initCandIdx = -1;
                        // Check pre-branch statements in current (header) block
                        for (int ci = stmtEnd - 1; ci >= std::max(0, stmtEnd - 3); --ci) {
                            auto &cs = bb.stmts[ci];
                            if ((cs.kind == IRStmtKind::VarSet || cs.kind == IRStmtKind::Assign) &&
                                cs.expr && cs.expr->isConst()) {
                                initCandIdx = ci; break;
                            }
                        }
                        // If not found, check the last emitted Seq node (previous block)
                        if (initCandIdx < 0 && !block->children.empty()) {
                            auto &prevNode = block->children.back();
                            if (prevNode->kind == StructKind::Seq && prevNode->bbId >= 0 &&
                                prevNode->bbId < n) {
                                auto &prevBB = m_func->blocks[prevNode->bbId];
                                for (int ci = prevNode->stmtEnd - 1;
                                     ci >= std::max(prevNode->stmtStart, prevNode->stmtEnd - 3); --ci) {
                                    auto &cs = prevBB.stmts[ci];
                                    if ((cs.kind == IRStmtKind::VarSet || cs.kind == IRStmtKind::Assign) &&
                                        cs.expr && cs.expr->isConst()) {
                                        initCandBB = prevNode->bbId;
                                        initCandIdx = ci; break;
                                    }
                                }
                            }
                        }
                        IRStmt *initSPtr = (initCandIdx >= 0 && initCandBB >= 0 && initCandBB < n) ?
                            &m_func->blocks[initCandBB].stmts[initCandIdx] : nullptr;
                        // Check body's last block for increment
                        // Find the back-edge source block (the one that jumps back to header)
                        int backSrc = -1;
                        for (auto &[from, hdr] : m_backEdges)
                            if (hdr == cur) { backSrc = from; break; }
                        if (backSrc >= 0 && backSrc < n) {
                            auto &backBB = m_func->blocks[backSrc];
                            // Find last non-branch/jump statement in back-edge block
                            int lastIdx = -1;
                            for (int si = (int)backBB.stmts.size() - 1; si >= 0; --si) {
                                auto k = backBB.stmts[si].kind;
                                if (k != IRStmtKind::Branch && k != IRStmtKind::Jump) {
                                    lastIdx = si; break;
                                }
                            }
                            if (lastIdx >= 0) {
                                auto &incrS = backBB.stmts[lastIdx];
                                // Pattern 1: VarSet init + VarSet increment
                                if (initSPtr &&
                                    initSPtr->kind == IRStmtKind::VarSet && incrS.kind == IRStmtKind::VarSet &&
                                    initSPtr->destVar == incrS.destVar && !initSPtr->destVar.empty() &&
                                    initSPtr->expr && initSPtr->expr->isConst() &&
                                    incrS.expr && (incrS.expr->op == IROp::Add || incrS.expr->op == IROp::Sub) &&
                                    incrS.expr->kids.size() == 2 &&
                                    incrS.expr->kids[0]->op == IROp::Var &&
                                    incrS.expr->kids[0]->name == incrS.destVar &&
                                    incrS.expr->kids[1]->isConst()) {
                                    isForLoop = true;
                                    initBB = initCandBB; initStmt = initCandIdx;
                                    incrBB = backSrc; incrStmt = lastIdx;
                                }
                                // Pattern 2: Assign(temp, const) init + Assign(temp, Add(Temp(temp), const)) increment
                                if (!isForLoop && initSPtr &&
                                    initSPtr->kind == IRStmtKind::Assign && incrS.kind == IRStmtKind::Assign &&
                                    initSPtr->destTemp >= 0 && initSPtr->destTemp == incrS.destTemp &&
                                    initSPtr->expr && initSPtr->expr->isConst() &&
                                    incrS.expr && (incrS.expr->op == IROp::Add || incrS.expr->op == IROp::Sub) &&
                                    incrS.expr->kids.size() == 2 &&
                                    incrS.expr->kids[0]->op == IROp::Temp &&
                                    incrS.expr->kids[0]->tempId() == incrS.destTemp &&
                                    incrS.expr->kids[1]->isConst()) {
                                    isForLoop = true;
                                    initBB = initCandBB; initStmt = initCandIdx;
                                    incrBB = backSrc; incrStmt = lastIdx;
                                }
                            }
                        }
                    }

                    if (isForLoop) {
                        // The init stmt will be suppressed via m_suppressedStmts in the emitter
                        if (!block->children.empty()) {
                            auto &lastChild = block->children.back();
                            (void)lastChild; // init is handled by suppression, not seq trimming
                        }
                        auto forNode = std::make_unique<StructNode>();
                        forNode->kind = StructKind::For;
                        forNode->cond = br.expr.get();
                        forNode->negated = negCond;
                        forNode->forInitBB = initBB; forNode->forInitStmt = initStmt;
                        forNode->forIncrBB = incrBB; forNode->forIncrStmt = incrStmt;
                        forNode->children.push_back(std::move(body));
                        block->children.push_back(std::move(forNode));
                    } else {
                        auto whileNode = StructNode::mkWhile(br.expr.get());
                        whileNode->negated = negCond;
                        whileNode->children.push_back(std::move(body));
                        block->children.push_back(std::move(whileNode));
                    }
                    cur = loopExit;
                    continue;
                } else {
                    // Do-while: header has no branch — condition is at back-edge source
                    int backSrc = -1;
                    for (auto &[from, hdr] : m_backEdges)
                        if (hdr == cur) { backSrc = from; break; }

                    if (backSrc >= 0 && backSrc < n &&
                        !m_func->blocks[backSrc].stmts.empty() &&
                        m_func->blocks[backSrc].stmts.back().kind == IRStmtKind::Branch) {

                        auto &backBB = m_func->blocks[backSrc];
                        auto &backBR = backBB.stmts.back();
                        bool negCond = (backBR.trueTarget == loopExit);

                        // Build body: header stmts + inner body + backSrc pre-branch stmts
                        auto body = StructNode::mkBlock();
                        int hdrStmts = (int)bb.stmts.size();
                        if (hdrStmts > 0)
                            body->children.push_back(StructNode::mkSeq(cur, 0, hdrStmts));

                        int bodyStart = !bb.succs.empty() ? bb.succs[0] : -1;
                        if (bodyStart >= 0 && bodyStart != cur && bodyStart < n && bodyStart != backSrc) {
                            std::vector<bool> bodyVisited = visited;
                            m_loopExitStack.push_back(loopExit);
                            auto inner = structureRegion(bodyStart, backSrc, bodyVisited);
                            m_loopExitStack.pop_back();
                            for (int vi = 0; vi < n; ++vi) if (bodyVisited[vi]) visited[vi] = true;
                            body->children.push_back(std::move(inner));
                        }

                        int backPreBranch = (int)backBB.stmts.size() - 1;
                        if (backPreBranch > 0)
                            body->children.push_back(StructNode::mkSeq(backSrc, 0, backPreBranch));
                        visited[backSrc] = true;

                        auto doNode = StructNode::mkDoWhile(backBR.expr.get());
                        doNode->negated = negCond;
                        doNode->children.push_back(std::move(body));
                        block->children.push_back(std::move(doNode));
                        cur = loopExit;
                        continue;
                    }
                }
            }

            // Emit the block's statements
            int numStmts = (int)bb.stmts.size();
            if (numStmts == 0) {
                // Empty block, fall through
                if (!bb.succs.empty()) cur = bb.succs[0];
                else cur = -1;
                continue;
            }

            auto &last = bb.stmts.back();

            if (last.kind == IRStmtKind::Branch) {
                // Emit pre-branch statements
                if (numStmts > 1)
                    block->children.push_back(StructNode::mkSeq(cur, 0, numStmts - 1));

                int trueB = last.trueTarget;
                int falseB = last.falseTarget;

                // Check for loop break/continue
                for (auto &[from, header] : m_backEdges) {
                    if (trueB == header && header >= 0 && header < n && visited[header]) {
                        // True branch is continue
                        auto ifNode = StructNode::mkIf(last.expr.get(), false);
                        ifNode->children.push_back(StructNode::mkContinue());
                        block->children.push_back(std::move(ifNode));
                        cur = falseB;
                        goto next_block;
                    }
                    if (falseB == header && header >= 0 && header < n && visited[header]) {
                        auto ifNode = StructNode::mkIf(last.expr.get(), true);
                        ifNode->children.push_back(StructNode::mkContinue());
                        block->children.push_back(std::move(ifNode));
                        cur = trueB;
                        goto next_block;
                    }
                }

                // Check for loop break (branch to active loop exit)
                for (int exitBB : m_loopExitStack) {
                    if (trueB == exitBB) {
                        auto ifNode = StructNode::mkIf(last.expr.get(), false);
                        ifNode->children.push_back(StructNode::mkBreak());
                        block->children.push_back(std::move(ifNode));
                        cur = falseB;
                        goto next_block;
                    }
                    if (falseB == exitBB) {
                        auto ifNode = StructNode::mkIf(last.expr.get(), true);
                        ifNode->children.push_back(StructNode::mkBreak());
                        block->children.push_back(std::move(ifNode));
                        cur = trueB;
                        goto next_block;
                    }
                }

                // Determine if/else vs if-then
                // If both targets converge at the same point, it's if/else
                {
                    int convergence = findConvergence(trueB, falseB, end, visited);

                    if (convergence >= 0 && trueB != convergence && falseB != convergence) {
                        // If/else: both arms converge
                        auto ifNode = StructNode::mkIf(last.expr.get(), false);

                        std::vector<bool> thenVisited = visited;
                        ifNode->children.push_back(structureRegion(trueB, convergence, thenVisited));

                        std::vector<bool> elseVisited = visited;
                        ifNode->elseNode = structureRegion(falseB, convergence, elseVisited);

                        for (int vi = 0; vi < n; ++vi) if (thenVisited[vi] || elseVisited[vi]) visited[vi] = true;

                        block->children.push_back(std::move(ifNode));
                        cur = convergence;
                    } else if (falseB == cur + 1 || (falseB >= 0 && falseB < n && !visited[falseB])) {
                        // if (cond) { trueB } — false falls through
                        auto ifNode = StructNode::mkIf(last.expr.get(), false);

                        if (trueB >= 0 && trueB < n && !visited[trueB] && trueB != falseB) {
                            std::vector<bool> thenVisited = visited;
                            ifNode->children.push_back(structureRegion(trueB, falseB, thenVisited));
                            for (int vi = 0; vi < n; ++vi) if (thenVisited[vi]) visited[vi] = true;
                        } else if (trueB >= 0) {
                            ifNode->children.push_back(StructNode::mkGoto(trueB));
                        }

                        block->children.push_back(std::move(ifNode));
                        cur = falseB;
                    } else {
                        // if (!cond) { falseB } — true falls through
                        auto ifNode = StructNode::mkIf(last.expr.get(), true);

                        if (falseB >= 0 && falseB < n && !visited[falseB]) {
                            std::vector<bool> elseVisited = visited;
                            ifNode->children.push_back(structureRegion(falseB, trueB, elseVisited));
                            for (int vi = 0; vi < n; ++vi) if (elseVisited[vi]) visited[vi] = true;
                        } else if (falseB >= 0) {
                            ifNode->children.push_back(StructNode::mkGoto(falseB));
                        }

                        block->children.push_back(std::move(ifNode));
                        cur = trueB;
                    }
                }
                continue;

            } else if (last.kind == IRStmtKind::Switch) {
                // Emit all statements including the switch — case targets will be
                // emitted as labeled blocks by the fallback mechanism
                block->children.push_back(StructNode::mkSeq(cur, 0, numStmts));
                cur = -1;
                continue;

            } else if (last.kind == IRStmtKind::Jump) {
                // Emit all statements except the jump
                if (numStmts > 1)
                    block->children.push_back(StructNode::mkSeq(cur, 0, numStmts - 1));

                int target = last.jumpTarget;
                // Check for loop break (unconditional jump to active loop exit)
                {
                    bool isBreak = false;
                    for (int exitBB : m_loopExitStack) {
                        if (target == exitBB) { isBreak = true; break; }
                    }
                    if (isBreak) {
                        block->children.push_back(StructNode::mkBreak());
                        cur = -1;
                        continue;
                    }
                }
                // Check for loop back-edge
                if (target >= 0 && target < n && visited[target]) {
                    // This might be a continue or end of loop body
                    bool isBackEdge = m_backEdges.count({cur, target}) > 0;
                    if (isBackEdge) {
                        // End of loop body — don't emit goto, structurer handles it
                    } else {
                        block->children.push_back(StructNode::mkGoto(target));
                    }
                    cur = -1;
                } else if (target == end) {
                    cur = -1; // break out of region
                } else {
                    cur = target;
                }
                continue;

            } else if (last.kind == IRStmtKind::Return) {
                block->children.push_back(StructNode::mkSeq(cur, 0, numStmts));
                cur = -1;
                continue;

            } else {
                // Normal block, all statements, fall through
                block->children.push_back(StructNode::mkSeq(cur, 0, numStmts));
                if (!bb.succs.empty() && bb.succs[0] != end)
                    cur = bb.succs[0];
                else
                    cur = -1;
                continue;
            }

            next_block:;
        }

        --m_depth;
        return block;
    }

    // Find where two block paths converge (meet point)
    int findConvergence(int a, int b, int regionEnd, const std::vector<bool> &visited) {
        int n = (int)m_func->blocks.size();
        // Walk both paths forward and find first common reachable block
        std::vector<bool> reachA(n, false), reachB(n, false);
        std::vector<int> workA = {a}, workB = {b};
        int maxSteps = std::min(n, 50);

        for (int step = 0; step < maxSteps; ++step) {
            std::vector<int> nextA, nextB;
            for (int x : workA) {
                if (x < 0 || x >= n || reachA[x]) continue;
                reachA[x] = true;
                if (reachB[x]) return x;
                for (int s : m_func->blocks[x].succs)
                    if (s >= 0 && s < n && (!visited[s] || s == regionEnd)) nextA.push_back(s);
            }
            for (int x : workB) {
                if (x < 0 || x >= n || reachB[x]) continue;
                reachB[x] = true;
                if (reachA[x]) return x;
                for (int s : m_func->blocks[x].succs)
                    if (s >= 0 && s < n && (!visited[s] || s == regionEnd)) nextB.push_back(s);
            }
            workA = nextA;
            workB = nextB;
            if (workA.empty() && workB.empty()) break;
        }
        return -1;
    }
};
