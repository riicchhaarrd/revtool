#include "disasmwidget.h"
#include <QPainter>
#include <QApplication>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QContextMenuEvent>
#include <QMenu>
#include <QClipboard>
#include <algorithm>

DisasmWidget::DisasmWidget(QWidget *parent) : QAbstractScrollArea(parent) {
    m_theme = darkTheme();
    m_font = QFont("Monospace", 11);
    m_font.setStyleHint(QFont::Monospace);
    m_font.setFixedPitch(true);
    setFont(m_font);

    QFontMetrics fm(m_font);
    m_charW = fm.horizontalAdvance('0');
    m_charH = fm.height();

    m_addrX    = m_charW;
    m_bytesX   = m_addrX  + m_charW * 10;
    m_mnemoX   = m_bytesX + m_charW * 26;
    m_operX    = m_mnemoX + m_charW * 8;
    m_commentX = m_operX  + m_charW * 32;

    m_csOk = (cs_open(CS_ARCH_X86, CS_MODE_32, &m_cs) == CS_ERR_OK);
    if (m_csOk) cs_option(m_cs, CS_OPT_DETAIL, CS_OPT_ON);
    setFocusPolicy(Qt::StrongFocus);
    viewport()->setCursor(Qt::ArrowCursor);
}

DisasmWidget::~DisasmWidget() { if (m_csOk) cs_close(&m_cs); }

void DisasmWidget::setTheme(const Theme &theme) { m_theme = theme; viewport()->update(); }
void DisasmWidget::setMachO(MachOFile *macho) { m_macho = macho; }

void DisasmWidget::disassembleSection(const Section &sec) {
    if (!m_csOk || !m_macho) return;
    m_lines.clear(); m_currentLine = 0;
    const uint8_t *code = m_macho->bytesAt(sec.offset, sec.size);
    if (!code) return;

    auto &funcMap = m_macho->functionMap();
    cs_insn *insn;
    size_t count = cs_disasm(m_cs, code, sec.size, sec.addr, 0, &insn);
    m_lines.reserve(count + count / 20);

    for (size_t i = 0; i < count; ++i) {
        auto it = funcMap.find(insn[i].address);
        if (it != funcMap.end()) {
            DisasmLine lbl{}; lbl.address = insn[i].address; lbl.label = it->second;
            m_lines.push_back(std::move(lbl));
        }
        DisasmLine dl; dl.address = insn[i].address; dl.size = insn[i].size;
        std::string bytes;
        for (int b = 0; b < insn[i].size && b < 8; ++b) { char buf[4]; snprintf(buf, sizeof(buf), "%02X ", insn[i].bytes[b]); bytes += buf; }
        if (insn[i].size > 8) bytes += ".. ";
        dl.bytes = bytes; dl.mnemonic = insn[i].mnemonic; dl.operands = insn[i].op_str;

        cs_detail *detail = insn[i].detail;
        if (detail) {
            for (uint8_t g = 0; g < detail->groups_count; ++g) {
                if (detail->groups[g] == CS_GRP_CALL) dl.isCall = true;
                if (detail->groups[g] == CS_GRP_JUMP) dl.isJump = true;
                if (detail->groups[g] == CS_GRP_RET)  dl.isRet = true;
            }
        }
        if (dl.mnemonic == "nop" || dl.mnemonic == "fnop") dl.isNop = true;
        if ((dl.isCall || dl.isJump) && detail && detail->x86.op_count > 0) {
            auto &op = detail->x86.operands[0];
            if (op.type == X86_OP_IMM) { auto tgt = funcMap.find((uint32_t)op.imm); if (tgt != funcMap.end()) dl.comment = "; " + tgt->second; }
        }
        m_lines.push_back(std::move(dl));
    }
    if (count > 0) cs_free(insn, count);
    updateScrollBar(); m_currentLine = 0; verticalScrollBar()->setValue(0); viewport()->update();
    emit statusMessage(QString("Disassembled %1  |  %2 instructions").arg(QString::fromStdString(sec.sectname)).arg(m_lines.size()));
}

void DisasmWidget::goToAddress(uint32_t addr) {
    int lo = 0, hi = (int)m_lines.size() - 1, best = 0;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (m_lines[mid].address == addr) { best = mid; if (!m_lines[mid].mnemonic.empty()) break; if (mid+1 < (int)m_lines.size() && m_lines[mid+1].address == addr) { best = mid+1; break; } break; }
        if (m_lines[mid].address < addr) { best = mid; lo = mid + 1; } else hi = mid - 1;
    }
    goToIndex(best);
}

void DisasmWidget::goToIndex(int idx) {
    idx = std::clamp(idx, 0, std::max(0, (int)m_lines.size() - 1));
    m_currentLine = idx;
    int vis = visibleLines(), cur = verticalScrollBar()->value();
    if (m_currentLine < cur || m_currentLine >= cur + vis) verticalScrollBar()->setValue(std::max(0, m_currentLine - vis / 3));
    viewport()->update();
    if (!m_lines.empty()) emit addressChanged(m_lines[m_currentLine].address);
}

uint32_t DisasmWidget::currentAddress() const {
    return (m_currentLine >= 0 && m_currentLine < (int)m_lines.size()) ? m_lines[m_currentLine].address : 0;
}

int DisasmWidget::headerHeight() const { return lineHeight() + 4; }
int DisasmWidget::visibleLines() const { return (viewport()->height() - headerHeight()) / lineHeight(); }
int DisasmWidget::lineHeight() const { return m_charH + 4; }

void DisasmWidget::updateScrollBar() {
    int vis = visibleLines();
    verticalScrollBar()->setRange(0, std::max(0, (int)m_lines.size() - vis));
    verticalScrollBar()->setPageStep(vis); verticalScrollBar()->setSingleStep(1);
}
void DisasmWidget::resizeEvent(QResizeEvent *e) { QAbstractScrollArea::resizeEvent(e); updateScrollBar(); }
int DisasmWidget::indexFromY(int y) const { return (y - headerHeight()) / lineHeight() + verticalScrollBar()->value(); }

void DisasmWidget::mousePressEvent(QMouseEvent *e) {
    if (e->button() == Qt::LeftButton) { int idx = indexFromY(e->pos().y()); if (idx >= 0 && idx < (int)m_lines.size()) { m_currentLine = idx; viewport()->update(); emit addressChanged(m_lines[idx].address); } }
}
void DisasmWidget::mouseDoubleClickEvent(QMouseEvent *e) {
    if (e->button() == Qt::LeftButton) {
        int idx = indexFromY(e->pos().y());
        if (idx >= 0 && idx < (int)m_lines.size()) { auto &line = m_lines[idx]; if (line.isCall || line.isJump) { bool ok; uint32_t target = QString::fromStdString(line.operands).trimmed().replace("0x","").toUInt(&ok,16); if (ok) goToAddress(target); } }
    }
}

void DisasmWidget::contextMenuEvent(QContextMenuEvent *e) {
    if (m_lines.empty()) return;
    int idx = indexFromY(e->pos().y());
    if (idx < 0 || idx >= (int)m_lines.size()) return;
    m_currentLine = idx;
    viewport()->update();

    auto &line = m_lines[idx];
    QMenu menu(this);

    // Decompile
    auto *decompAct = menu.addAction("Decompile Function (F5)");
    connect(decompAct, &QAction::triggered, this, [this, &line]() {
        // Walk backward to find function start (label line)
        uint32_t funcAddr = line.address;
        if (m_macho) {
            auto *fn = m_macho->stabsFunctionContaining(line.address);
            if (fn) funcAddr = fn->address;
            else {
                // Fall back: find nearest label line above
                for (int j = m_currentLine; j >= 0; --j) {
                    if (!m_lines[j].label.empty()) { funcAddr = m_lines[j].address; break; }
                }
            }
        }
        emit decompileRequested(funcAddr);
    });

    menu.addSeparator();

    // Copy
    auto *copyAddr = menu.addAction(QString("Copy Address  (0x%1)").arg(line.address, 8, 16, QChar('0')).toUpper());
    connect(copyAddr, &QAction::triggered, this, [&line]() {
        QApplication::clipboard()->setText(QString("0x%1").arg(line.address, 8, 16, QChar('0')));
    });

    auto *copyLine = menu.addAction("Copy Line");
    connect(copyLine, &QAction::triggered, this, [&line]() {
        QApplication::clipboard()->setText(QString("%1  %2  %3 %4").arg(line.address,8,16,QChar('0'))
            .arg(QString::fromStdString(line.bytes)).arg(QString::fromStdString(line.mnemonic))
            .arg(QString::fromStdString(line.operands)));
    });

    menu.addSeparator();

    // Show in hex
    auto *hexAct = menu.addAction("Show in Hex Editor");
    connect(hexAct, &QAction::triggered, this, [this, &line]() {
        if (m_macho) { int64_t off = m_macho->fileOffsetForAddress(line.address); if (off >= 0) emit goToHexOffset(off); }
    });

    // Follow call/jump
    if (line.isCall || line.isJump) {
        auto *followAct = menu.addAction("Follow Target");
        connect(followAct, &QAction::triggered, this, [this, &line]() {
            bool ok; uint32_t t = QString::fromStdString(line.operands).trimmed().replace("0x","").toUInt(&ok,16);
            if (ok) goToAddress(t);
        });
    }

    menu.exec(e->globalPos());
}

void DisasmWidget::keyPressEvent(QKeyEvent *e) {
    if (m_lines.empty()) return;
    switch (e->key()) {
    case Qt::Key_Down:     goToIndex(m_currentLine + 1); break;
    case Qt::Key_Up:       goToIndex(m_currentLine - 1); break;
    case Qt::Key_PageDown: goToIndex(m_currentLine + visibleLines()); break;
    case Qt::Key_PageUp:   goToIndex(m_currentLine - visibleLines()); break;
    case Qt::Key_Home:     goToIndex(0); break;
    case Qt::Key_End:      goToIndex(m_lines.size() - 1); break;
    case Qt::Key_Return: case Qt::Key_Enter: {
        auto &l = m_lines[m_currentLine]; if (l.isCall || l.isJump) { bool ok; uint32_t t = QString::fromStdString(l.operands).trimmed().replace("0x","").toUInt(&ok,16); if (ok) goToAddress(t); } break; }
    case Qt::Key_G:
        if (e->modifiers() & Qt::ControlModifier) { bool ok; QString text = QInputDialog::getText(this,"Go to Address","Address (hex):",QLineEdit::Normal,"",&ok); if (ok && !text.isEmpty()) { bool c; uint32_t a=text.toUInt(&c,16); if (c) goToAddress(a); } } break;
    case Qt::Key_H:
        if (m_macho && m_currentLine < (int)m_lines.size()) { int64_t foff = m_macho->fileOffsetForAddress(m_lines[m_currentLine].address); if (foff >= 0) emit goToHexOffset(foff); } break;
    case Qt::Key_C:
        if (e->modifiers() & Qt::ControlModifier) { auto &l = m_lines[m_currentLine]; QApplication::clipboard()->setText(QString("%1  %2  %3 %4").arg(l.address,8,16,QChar('0')).arg(QString::fromStdString(l.bytes)).arg(QString::fromStdString(l.mnemonic)).arg(QString::fromStdString(l.operands))); } break;
    case Qt::Key_F5: {
        uint32_t funcAddr = m_lines[m_currentLine].address;
        if (m_macho) {
            auto *fn = m_macho->stabsFunctionContaining(funcAddr);
            if (fn) funcAddr = fn->address;
            else { for (int j = m_currentLine; j >= 0; --j) { if (!m_lines[j].label.empty()) { funcAddr = m_lines[j].address; break; } } }
        }
        emit decompileRequested(funcAddr);
        break;
    }
    default: QAbstractScrollArea::keyPressEvent(e); return;
    }
}

void DisasmWidget::paintEvent(QPaintEvent *) {
    QPainter p(viewport());
    p.setRenderHint(QPainter::TextAntialiasing);
    p.setFont(m_font);

    const auto &T = m_theme;
    const int lh = lineHeight(), hh = headerHeight(), w = viewport()->width();

    p.fillRect(viewport()->rect(), T.bg);

    // ── Column header ───────────────────────────────────────────────
    p.fillRect(0, 0, w, hh, T.headerBg);
    p.setPen(T.headerFg);
    p.drawText(m_addrX,    0, m_bytesX-m_addrX,    hh, Qt::AlignLeft|Qt::AlignVCenter, "ADDRESS");
    p.drawText(m_bytesX,   0, m_mnemoX-m_bytesX,   hh, Qt::AlignLeft|Qt::AlignVCenter, "BYTES");
    p.drawText(m_mnemoX,   0, m_operX-m_mnemoX,    hh, Qt::AlignLeft|Qt::AlignVCenter, "OPCODE");
    p.drawText(m_operX,    0, m_commentX-m_operX,   hh, Qt::AlignLeft|Qt::AlignVCenter, "OPERANDS");
    p.drawText(m_commentX, 0, w-m_commentX,         hh, Qt::AlignLeft|Qt::AlignVCenter, "COMMENT");
    p.setPen(T.divider);
    p.drawLine(0, hh-1, w, hh-1);

    if (m_lines.empty()) return;
    const int firstLine = verticalScrollBar()->value(), numLines = visibleLines() + 1;

    for (int i = 0; i < numLines; ++i) {
        int idx = firstLine + i;
        if (idx >= (int)m_lines.size()) break;
        auto &line = m_lines[idx];
        int y = hh + i * lh;

        // ── Label / function header ─────────────────────────────────
        if (!line.label.empty() && line.mnemonic.empty()) {
            p.fillRect(0, y, w, lh, T.disLabelBg);
            p.setPen(T.disLabelLine); p.drawLine(0, y, w, y);
            p.setPen(T.disLabelFg);
            QFont bold = m_font; bold.setBold(true); p.setFont(bold);
            p.drawText(m_addrX, y, w-m_addrX, lh, Qt::AlignLeft|Qt::AlignVCenter, QString::fromStdString(line.label) + ":");
            p.setFont(m_font);
            continue;
        }

        // Row background
        if (idx == m_currentLine) {
            p.fillRect(0, y, w, lh, T.selection);
            p.setPen(T.selBorder); p.drawLine(0, y, w, y); p.drawLine(0, y+lh-1, w, y+lh-1);
        } else if (idx & 1) {
            p.fillRect(0, y, w, lh, T.bgAlt);
        }

        // Address
        p.setPen(T.disAddr);
        p.drawText(m_addrX, y, m_bytesX-m_addrX, lh, Qt::AlignLeft|Qt::AlignVCenter,
                   QString("%1").arg(line.address, 8, 16, QChar('0')).toUpper());

        // Bytes
        p.setPen(T.disBytes);
        p.drawText(m_bytesX, y, m_mnemoX-m_bytesX, lh, Qt::AlignLeft|Qt::AlignVCenter, QString::fromStdString(line.bytes));

        // Mnemonic
        QColor mc = T.disMnemonic;
        if (line.isNop) mc = T.disNop; else if (line.isCall) mc = T.disCall; else if (line.isJump) mc = T.disJump; else if (line.isRet) mc = T.disRet;
        p.setPen(mc);
        p.drawText(m_mnemoX, y, m_operX-m_mnemoX, lh, Qt::AlignLeft|Qt::AlignVCenter, QString::fromStdString(line.mnemonic));

        // Operands
        p.setPen(T.disOperands);
        p.drawText(m_operX, y, m_commentX-m_operX, lh, Qt::AlignLeft|Qt::AlignVCenter, QString::fromStdString(line.operands));

        // Comment
        if (!line.comment.empty()) {
            p.setPen(T.disComment);
            p.drawText(m_commentX, y, w-m_commentX, lh, Qt::AlignLeft|Qt::AlignVCenter, QString::fromStdString(line.comment));
        }
    }

    // Column dividers
    p.setPen(T.divider);
    for (int cx : {m_bytesX, m_mnemoX, m_operX, m_commentX})
        p.drawLine(cx - m_charW/2, 0, cx - m_charW/2, viewport()->height());
}
