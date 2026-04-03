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

    // For While: if true, the first child is a Block containing header
    // statements that must execute BEFORE the condition each iteration.
    // Emitter renders as: while(1) { header_stmts; if(!cond) break; body; }
    bool whileHasHeaderStmts = false;

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
        auto tree = structureRegion(0, -1, visited);

        // Post-pass: merge if(A){X} else {if(B){X}} → if(A||B){X}
        mergeIfElseOr(tree.get());
        return tree;
    }

    // Merge nested if-else-if patterns where both branches have identical bodies
    // into a single if with || condition.
    // Pattern: if(cond1) { BODY } else { if(cond2) { BODY } }
    // Result:  if(cond1 || cond2) { BODY }
    void mergeIfElseOr(StructNode *node) {
        if (!node) return;
        // Recurse into children first
        for (auto &child : node->children) mergeIfElseOr(child.get());
        if (node->elseNode) mergeIfElseOr(node->elseNode.get());

        // Check: this node is an If with an else
        if (node->kind != StructKind::If || !node->elseNode || !node->cond) return;

        // The else must contain exactly one child which is another If (no else on inner)
        auto *elsNode = node->elseNode.get();
        StructNode *innerIf = nullptr;
        if (elsNode->kind == StructKind::If) {
            innerIf = elsNode;
        } else if (elsNode->kind == StructKind::Block && elsNode->children.size() == 1 &&
                   elsNode->children[0]->kind == StructKind::If) {
            innerIf = elsNode->children[0].get();
        }
        if (!innerIf || !innerIf->cond) return;
        if (innerIf->elseNode) return; // inner if has else → don't merge

        // Both must have exactly one child (the body)
        if (node->children.size() != 1 || innerIf->children.size() != 1) return;

        // Compare bodies: both must be Seq nodes referencing the same BB with same stmt range
        auto *body1 = node->children[0].get();
        auto *body2 = innerIf->children[0].get();
        // For simple bodies (single Seq or Block with single Seq), check if they match
        auto getSeq = [](StructNode *n) -> StructNode* {
            if (n->kind == StructKind::Seq) return n;
            if (n->kind == StructKind::Block && n->children.size() == 1 &&
                n->children[0]->kind == StructKind::Seq)
                return n->children[0].get();
            return nullptr;
        };
        auto *seq1 = getSeq(body1);
        auto *seq2 = getSeq(body2);
        if (!seq1 || !seq2) return;
        // Both must reference the same basic block with the same statement range
        // OR have equivalent statement content (same function calls)
        if (seq1->bbId != seq2->bbId || seq1->stmtStart != seq2->stmtStart ||
            seq1->stmtEnd != seq2->stmtEnd) {
            // Different BBs but maybe same content — check if both are single-stmt
            // function calls to the same function with same args
            if (seq1->bbId < 0 || seq2->bbId < 0) return;
            auto &stmts1 = m_func->blocks[seq1->bbId].stmts;
            auto &stmts2 = m_func->blocks[seq2->bbId].stmts;
            int n1 = seq1->stmtEnd - seq1->stmtStart;
            int n2 = seq2->stmtEnd - seq2->stmtStart;
            if (n1 != n2 || n1 == 0) return;
            // Check each statement matches (using IR text comparison)
            for (int i = 0; i < n1; ++i) {
                auto &s1 = stmts1[seq1->stmtStart + i];
                auto &s2 = stmts2[seq2->stmtStart + i];
                if (s1.kind != s2.kind) return;
                // For calls, compare function name
                if (s1.kind == IRStmtKind::Call && s1.expr && s2.expr) {
                    if (s1.expr->op != s2.expr->op) return;
                    if (s1.expr->name != s2.expr->name) return;
                } else return; // non-trivial statement
            }
        }

        // Merge: create cond1 || cond2
        // Handle negation: if either condition was negated by the structurer,
        // we need to invert it before merging
        auto makeCond = [](IRExpr *cond, bool negated) -> std::unique_ptr<IRExpr> {
            auto c = cond->clone();
            if (!negated) return c;
            // Negate comparison ops: < → >=, > → <=, etc.
            switch (c->op) {
            case IROp::Eq:  c->op = IROp::Ne; break;
            case IROp::Ne:  c->op = IROp::Eq; break;
            case IROp::Slt: c->op = IROp::Sge; break;
            case IROp::Sge: c->op = IROp::Slt; break;
            case IROp::Sgt: c->op = IROp::Sle; break;
            case IROp::Sle: c->op = IROp::Sgt; break;
            case IROp::Ult: c->op = IROp::Uge; break;
            case IROp::Uge: c->op = IROp::Ult; break;
            case IROp::Ugt: c->op = IROp::Ule; break;
            case IROp::Ule: c->op = IROp::Ugt; break;
            default: break;
            }
            return c;
        };
        auto c1 = makeCond(node->cond, node->negated);
        auto c2 = makeCond(innerIf->cond, innerIf->negated);
        auto orExpr = IRExpr::mkBinary(IROp::Or, std::move(c1), std::move(c2));
        // Stash the or expr in the function's block to keep it alive
        int poolBB = node->children[0]->bbId >= 0 ? node->children[0]->bbId : 0;
        if (poolBB >= 0 && poolBB < (int)m_func->blocks.size()) {
            m_func->blocks[poolBB].stmts.push_back(
                IRStmt::mkAssign(-1, std::move(orExpr)));
            node->cond = m_func->blocks[poolBB].stmts.back().expr.get();
            node->negated = false;
            node->elseNode.reset();
        }
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
        if (m_depth > 200 || ++m_totalCalls > n * 20) { --m_depth; return block; }
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

                    // Check for constant loop condition (always true/false)
                    if (br.expr && br.expr->kids.size() == 2 &&
                        br.expr->kids[0] && br.expr->kids[1] &&
                        br.expr->op >= IROp::Eq && br.expr->op <= IROp::Uge) {
                        auto evalC = [&](IRExpr *e) -> std::pair<bool, int64_t> {
                            if (e->isConst()) return {true, e->value};
                            if (e->op == IROp::Temp) {
                                for (auto &blk : m_func->blocks)
                                    for (auto &s : blk.stmts)
                                        if (s.kind == IRStmtKind::Assign && s.destTemp == e->tempId() &&
                                            s.expr && s.expr->isConst())
                                            return {true, s.expr->value};
                            }
                            return {false, 0};
                        };
                        auto [a1, v1] = evalC(br.expr->kids[0].get());
                        auto [a2, v2] = evalC(br.expr->kids[1].get());
                        if (a1 && a2) {
                            bool res = false;
                            switch (br.expr->op) {
                            case IROp::Eq: res = (v1 == v2); break;
                            case IROp::Ne: res = (v1 != v2); break;
                            default: res = (v1 != v2); break;
                            }
                            // Fold: skip loop entirely or treat as unconditional
                            int taken = res ? br.trueTarget : br.falseTarget;
                            int stmtEnd2 = (int)bb.stmts.size() - 1;
                            if (stmtEnd2 > 0)
                                block->children.push_back(StructNode::mkSeq(cur, 0, stmtEnd2));
                            cur = taken;
                            continue;
                        }
                    }

                    int bodyTarget = -1;
                    bool negCond = false;

                    if (br.falseTarget == loopExit) {
                        bodyTarget = br.trueTarget;
                        negCond = false;
                    } else if (br.trueTarget == loopExit) {
                        bodyTarget = br.falseTarget;
                        negCond = true;
                    } else {
                        bodyTarget = br.trueTarget;
                        negCond = false;
                    }

                    // Header block statements before the branch — these are part of the
                    // loop iteration (e.g., function calls evaluated each iteration).
                    // For while loops, they go INSIDE the loop body, not before it.
                    // For for loops, the init goes before and the rest goes inside.
                    int stmtEnd = (int)bb.stmts.size() - 1; // exclude branch
                    // Header statements are loop body content when the header has
                    // multiple calls (e.g., SV_GetConfigstring + I_stricmp in GScr_GetHeadIconIndex).
                    // A single call right before the branch is the condition (e.g., while(strcmp(...)!=0)).
                    bool headerStmtsAreLoopBody = false;
                    {
                        int callCount = 0;
                        for (int si = 0; si < stmtEnd; ++si) {
                            auto &s = bb.stmts[si];
                            if (s.kind == IRStmtKind::Call ||
                                (s.expr && s.expr->op == IROp::Call))
                                callCount++;
                        }
                        headerStmtsAreLoopBody = (callCount >= 2);
                    }

                    if (!headerStmtsAreLoopBody && stmtEnd > 0)
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
                        // If header has loop body statements, wrap them with the body
                        // and mark for while(1)+break emission
                        if (headerStmtsAreLoopBody && stmtEnd > 0) {
                            whileNode->whileHasHeaderStmts = true;
                            auto wrapper = StructNode::mkBlock();
                            wrapper->children.push_back(StructNode::mkSeq(cur, 0, stmtEnd));
                            wrapper->children.push_back(std::move(body));
                            whileNode->children.push_back(std::move(wrapper));
                        } else {
                            whileNode->children.push_back(std::move(body));
                        }
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
                // Detect trivially constant conditions (e.g., "32 != 46" = always true)
                // Fold to unconditional jump to eliminate dead code
                if (last.expr && last.expr->kids.size() == 2 &&
                    last.expr->kids[0] && last.expr->kids[1] &&
                    last.expr->op >= IROp::Eq && last.expr->op <= IROp::Uge) {
                    // Try to evaluate: follow temps to find constants
                    auto evalConst = [&](IRExpr *e) -> std::pair<bool, int64_t> {
                        if (e->isConst()) return {true, e->value};
                        if (e->op == IROp::Temp) {
                            for (auto &blk : m_func->blocks)
                                for (auto &s : blk.stmts)
                                    if (s.kind == IRStmtKind::Assign && s.destTemp == e->tempId() &&
                                        s.expr && s.expr->isConst())
                                        return {true, s.expr->value};
                        }
                        return {false, 0};
                    };
                    auto [aOk, aVal] = evalConst(last.expr->kids[0].get());
                    auto [bOk, bVal] = evalConst(last.expr->kids[1].get());
                    if (aOk && bOk) {
                    int64_t a = aVal, b = bVal;
                    bool result = false;
                    switch (last.expr->op) {
                    case IROp::Eq:  result = (a == b); break;
                    case IROp::Ne:  result = (a != b); break;
                    case IROp::Slt: result = (a < b); break;
                    case IROp::Sle: result = (a <= b); break;
                    case IROp::Sgt: result = (a > b); break;
                    case IROp::Sge: result = (a >= b); break;
                    case IROp::Ult: result = ((uint32_t)a < (uint32_t)b); break;
                    case IROp::Ule: result = ((uint32_t)a <= (uint32_t)b); break;
                    case IROp::Ugt: result = ((uint32_t)a > (uint32_t)b); break;
                    case IROp::Uge: result = ((uint32_t)a >= (uint32_t)b); break;
                    default: break;
                    }
                    // Fold: treat as unconditional jump to the taken branch
                    if (numStmts > 1)
                        block->children.push_back(StructNode::mkSeq(cur, 0, numStmts - 1));
                    cur = result ? last.trueTarget : last.falseTarget;
                    continue;
                    }
                }

                // Emit pre-branch statements
                if (numStmts > 1)
                    block->children.push_back(StructNode::mkSeq(cur, 0, numStmts - 1));

                int trueB = last.trueTarget;
                int falseB = last.falseTarget;

                // Check for loop break/continue (only valid inside a loop body)
                if (!m_loopExitStack.empty()) {
                    for (auto &[from, header] : m_backEdges) {
                        if (trueB == header && header >= 0 && header < n && visited[header]) {
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
                        // Structure both arms and check for excessive duplication.
                        auto ifNode = StructNode::mkIf(last.expr.get(), false);

                        std::vector<bool> thenVisited = visited;
                        ifNode->children.push_back(structureRegion(trueB, convergence, thenVisited));

                        std::vector<bool> elseVisited = visited;
                        ifNode->elseNode = structureRegion(falseB, convergence, elseVisited);

                        // Detect duplication: count blocks visited by both arms
                        int thenCount = 0, elseCount = 0, sharedCount = 0;
                        for (int vi = 0; vi < n; ++vi) {
                            bool inThen = thenVisited[vi] && !visited[vi];
                            bool inElse = elseVisited[vi] && !visited[vi];
                            if (inThen) thenCount++;
                            if (inElse) elseCount++;
                            if (inThen && inElse) sharedCount++;
                        }
                        // If >30% of blocks are shared, use goto for else arm
                        int totalArms = thenCount + elseCount;
                        if (sharedCount > 0 && totalArms > 6 &&
                            sharedCount * 100 / std::max(1, totalArms) > 30) {
                            // Too much duplication — use goto for the larger arm
                            ifNode->elseNode.reset();
                            if (thenCount >= elseCount) {
                                // Keep else inline, use goto for then
                                ifNode->children.clear();
                                ifNode->children.push_back(StructNode::mkGoto(trueB));
                                ifNode->negated = false;
                                // Re-structure else as the inline arm
                                std::vector<bool> ev2 = visited;
                                auto elsBody = structureRegion(falseB, convergence, ev2);
                                ifNode->elseNode = std::move(elsBody);
                                for (int vi = 0; vi < n; ++vi)
                                    if (ev2[vi]) visited[vi] = true;
                            } else {
                                ifNode->children.clear();
                                std::vector<bool> tv2 = visited;
                                ifNode->children.push_back(structureRegion(trueB, convergence, tv2));
                                ifNode->elseNode = std::make_unique<StructNode>();
                                ifNode->elseNode->kind = StructKind::Block;
                                ifNode->elseNode->children.push_back(StructNode::mkGoto(falseB));
                                for (int vi = 0; vi < n; ++vi)
                                    if (tv2[vi]) visited[vi] = true;
                            }
                        } else {
                            for (int vi = 0; vi < n; ++vi)
                                if (thenVisited[vi] || elseVisited[vi]) visited[vi] = true;
                        }

                        block->children.push_back(std::move(ifNode));
                        cur = convergence;
                    } else if (convergence >= 0 && trueB == convergence && falseB != convergence &&
                               falseB >= 0 && falseB < n && !visited[falseB]) {
                        // true IS convergence — structure false path then continue at convergence
                        // This handles: if (initialized) goto common_tail; init_code; common_tail:
                        auto ifNode = StructNode::mkIf(last.expr.get(), true);
                        std::vector<bool> bodyVisited = visited;
                        ifNode->children.push_back(structureRegion(falseB, convergence, bodyVisited));
                        for (int vi = 0; vi < n; ++vi) if (bodyVisited[vi]) visited[vi] = true;
                        block->children.push_back(std::move(ifNode));
                        cur = convergence;
                        // Unvisit convergence if it's a simple return block
                        // (avoids skipping the common tail code)
                        if (cur >= 0 && cur < n) {
                            auto &convBB = m_func->blocks[cur];
                            bool isSimple = !convBB.stmts.empty() &&
                                convBB.stmts.back().kind == IRStmtKind::Return;
                            if (isSimple) visited[cur] = false;
                        }
                    } else if (trueB >= 0 && trueB < n && visited[trueB] &&
                               falseB >= 0 && falseB < n && !visited[falseB]) {
                        // Early exit: true branch already visited (return/exit block)
                        // → emit if (cond) { goto exit; } and continue with false path
                        auto ifNode = StructNode::mkIf(last.expr.get(), false);
                        ifNode->children.push_back(StructNode::mkGoto(trueB));
                        block->children.push_back(std::move(ifNode));
                        cur = falseB;
                    } else if (convergence >= 0 && falseB == convergence && trueB != convergence) {
                        // false IS convergence — the true path has the body
                        auto ifNode = StructNode::mkIf(last.expr.get(), false);
                        std::vector<bool> bodyVisited = visited;
                        ifNode->children.push_back(structureRegion(trueB, convergence, bodyVisited));
                        for (int vi = 0; vi < n; ++vi) if (bodyVisited[vi]) visited[vi] = true;
                        block->children.push_back(std::move(ifNode));
                        cur = convergence;
                        // Unvisit convergence if it's a simple return block
                        if (cur >= 0 && cur < n) {
                            auto &convBB = m_func->blocks[cur];
                            bool isSimple = !convBB.stmts.empty() &&
                                convBB.stmts.back().kind == IRStmtKind::Return;
                            if (isSimple) visited[cur] = false;
                        }
                    } else if (falseB == cur + 1 || (falseB >= 0 && falseB < n && !visited[falseB])) {
                        // if (cond) { trueB } — false falls through
                        auto ifNode = StructNode::mkIf(last.expr.get(), false);

                        if (trueB >= 0 && trueB < n && !visited[trueB] && trueB != falseB) {
                            if (trueB > falseB && (end < 0 || trueB >= end)) {
                                // Forward jump: trueB is past current region.
                                // Check if both paths terminate (no convergence).
                                // If so, prefer: if(cond) { trueB; return; } falseB;
                                // This matches the original asm branch direction.
                                bool trueTerminates = false;
                                if (trueB >= 0 && trueB < n) {
                                    auto &tbb = m_func->blocks[trueB];
                                    if (!tbb.stmts.empty() && tbb.succs.empty())
                                        trueTerminates = true;
                                    if (!tbb.stmts.empty() &&
                                        tbb.stmts.back().kind == IRStmtKind::Return)
                                        trueTerminates = true;
                                }
                                if (convergence < 0 && trueTerminates) {
                                    // Both paths terminate. Check if trueB is small
                                    // (single block with few stmts = error/exit handler).
                                    // If so, swap to preserve the original branch direction.
                                    auto &tbb = m_func->blocks[trueB];
                                    bool trueIsSmall = (tbb.stmts.size() <= 6 && tbb.succs.empty());
                                    if (trueIsSmall) {
                                        // Swap: emit if(!cond) { falseB } trueB
                                        auto swapNode = StructNode::mkIf(last.expr.get(), true);
                                        std::vector<bool> falseVisited = visited;
                                        swapNode->children.push_back(structureRegion(falseB, n, falseVisited));
                                        for (int vi = 0; vi < n; ++vi) if (falseVisited[vi]) visited[vi] = true;
                                        block->children.push_back(std::move(swapNode));
                                        cur = trueB;
                                    } else {
                                        // Keep original order: if(cond) { trueB } falseB
                                        std::vector<bool> thenVisited = visited;
                                        ifNode->children.push_back(structureRegion(trueB, n, thenVisited));
                                        for (int vi = 0; vi < n; ++vi) if (thenVisited[vi]) visited[vi] = true;
                                        block->children.push_back(std::move(ifNode));
                                        cur = falseB;
                                    }
                                } else {
                                    // Emit as if/else
                                    std::vector<bool> thenVisited = visited;
                                    ifNode->children.push_back(structureRegion(trueB, n, thenVisited));
                                    for (int vi = 0; vi < n; ++vi) if (thenVisited[vi]) visited[vi] = true;

                                    std::vector<bool> elseVisited = visited;
                                    auto elseBody = structureRegion(falseB, end, elseVisited);
                                    for (int vi = 0; vi < n; ++vi) if (elseVisited[vi]) visited[vi] = true;
                                    ifNode->elseNode = std::move(elseBody);

                                    block->children.push_back(std::move(ifNode));
                                    cur = -1; // both paths structured
                                }
                                continue;
                            } else {
                                std::vector<bool> thenVisited = visited;
                                int thenEnd = (trueB > falseB) ? end : falseB;
                                ifNode->children.push_back(structureRegion(trueB, (thenEnd >= 0 ? thenEnd : n), thenVisited));
                                for (int vi = 0; vi < n; ++vi) if (thenVisited[vi]) visited[vi] = true;
                            }
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
