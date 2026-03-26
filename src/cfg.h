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

        // Compute dominators and loop info
        computeDominators();
        findLoops();

        // Structure from the entry block
        std::set<int> visited;
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

        // Iterative dominator computation
        std::vector<std::set<int>> doms(n);
        for (int i = 0; i < n; ++i)
            for (int j = 0; j < n; ++j)
                doms[i].insert(j);
        doms[0] = {0};

        bool changed = true;
        for (int iter = 0; iter < n * 2 && changed; ++iter) {
            changed = false;
            for (int i = 1; i < n; ++i) {
                auto &bb = m_func->blocks[i];
                std::set<int> newDom;
                bool first = true;
                for (int p : bb.preds) {
                    if (p < 0 || p >= n) continue;
                    if (first) { newDom = doms[p]; first = false; }
                    else {
                        std::set<int> inter;
                        std::set_intersection(newDom.begin(), newDom.end(),
                                              doms[p].begin(), doms[p].end(),
                                              std::inserter(inter, inter.begin()));
                        newDom = inter;
                    }
                }
                newDom.insert(i);
                if (newDom != doms[i]) { doms[i] = newDom; changed = true; }
            }
        }

        // Extract immediate dominators
        for (int i = 1; i < n; ++i) {
            auto d = doms[i];
            d.erase(i);
            if (d.empty()) { m_idom[i] = 0; continue; }
            // idom = the dominator of i that is dominated by all others in d
            int best = *d.rbegin(); // heuristic: pick the highest-numbered
            for (int c : d)
                if (doms[c].count(best) == 0) best = c;
            m_idom[i] = best;
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
    std::unique_ptr<StructNode> structureRegion(int start, int end, std::set<int> &visited) {
        auto block = StructNode::mkBlock();
        int n = (int)m_func->blocks.size();
        int cur = start;

        while (cur >= 0 && cur < n && cur != end && !visited.count(cur)) {
            visited.insert(cur);
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

                    auto whileNode = StructNode::mkWhile(br.expr.get());
                    whileNode->negated = negCond;

                    // Structure the loop body
                    std::set<int> bodyVisited = visited;
                    auto body = structureRegion(bodyTarget, cur, bodyVisited);
                    whileNode->children.push_back(std::move(body));
                    visited.insert(bodyVisited.begin(), bodyVisited.end());

                    block->children.push_back(std::move(whileNode));
                    cur = loopExit;
                    continue;
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
                    if (trueB == header && visited.count(header)) {
                        // True branch is continue
                        auto ifNode = StructNode::mkIf(last.expr.get(), false);
                        ifNode->children.push_back(StructNode::mkContinue());
                        block->children.push_back(std::move(ifNode));
                        cur = falseB;
                        goto next_block;
                    }
                    if (falseB == header && visited.count(header)) {
                        auto ifNode = StructNode::mkIf(last.expr.get(), true);
                        ifNode->children.push_back(StructNode::mkContinue());
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

                        std::set<int> thenVisited = visited;
                        ifNode->children.push_back(structureRegion(trueB, convergence, thenVisited));

                        std::set<int> elseVisited = visited;
                        ifNode->elseNode = structureRegion(falseB, convergence, elseVisited);

                        visited.insert(thenVisited.begin(), thenVisited.end());
                        visited.insert(elseVisited.begin(), elseVisited.end());

                        block->children.push_back(std::move(ifNode));
                        cur = convergence;
                    } else if (falseB == cur + 1 || !visited.count(falseB)) {
                        // if (cond) { trueB } — false falls through
                        auto ifNode = StructNode::mkIf(last.expr.get(), false);

                        if (trueB >= 0 && !visited.count(trueB) && trueB != falseB) {
                            std::set<int> thenVisited = visited;
                            ifNode->children.push_back(structureRegion(trueB, falseB, thenVisited));
                            visited.insert(thenVisited.begin(), thenVisited.end());
                        } else if (trueB >= 0) {
                            ifNode->children.push_back(StructNode::mkGoto(trueB));
                        }

                        block->children.push_back(std::move(ifNode));
                        cur = falseB;
                    } else {
                        // if (!cond) { falseB } — true falls through
                        auto ifNode = StructNode::mkIf(last.expr.get(), true);

                        if (falseB >= 0 && !visited.count(falseB)) {
                            std::set<int> elseVisited = visited;
                            ifNode->children.push_back(structureRegion(falseB, trueB, elseVisited));
                            visited.insert(elseVisited.begin(), elseVisited.end());
                        } else if (falseB >= 0) {
                            ifNode->children.push_back(StructNode::mkGoto(falseB));
                        }

                        block->children.push_back(std::move(ifNode));
                        cur = trueB;
                    }
                }
                continue;

            } else if (last.kind == IRStmtKind::Jump) {
                // Emit all statements except the jump
                if (numStmts > 1)
                    block->children.push_back(StructNode::mkSeq(cur, 0, numStmts - 1));

                int target = last.jumpTarget;
                // Check for loop back-edge
                if (visited.count(target)) {
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

        return block;
    }

    // Find where two block paths converge (meet point)
    int findConvergence(int a, int b, int regionEnd, const std::set<int> &visited) {
        int n = (int)m_func->blocks.size();
        // Walk both paths forward and find first common reachable block
        std::set<int> reachA, reachB;
        std::vector<int> workA = {a}, workB = {b};

        for (int step = 0; step < n; ++step) {
            std::vector<int> nextA, nextB;
            for (int x : workA) {
                if (x < 0 || x >= n || reachA.count(x)) continue;
                reachA.insert(x);
                if (reachB.count(x)) return x;
                for (int s : m_func->blocks[x].succs)
                    if (!visited.count(s) || s == regionEnd) nextA.push_back(s);
            }
            for (int x : workB) {
                if (x < 0 || x >= n || reachB.count(x)) continue;
                reachB.insert(x);
                if (reachA.count(x)) return x;
                for (int s : m_func->blocks[x].succs)
                    if (!visited.count(s) || s == regionEnd) nextB.push_back(s);
            }
            workA = nextA;
            workB = nextB;
            if (workA.empty() && workB.empty()) break;
        }
        return -1;
    }
};
