#include "disasmwidget.h"
#include <QPainter>
#include <QApplication>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QClipboard>
#include <algorithm>

DisasmWidget::DisasmWidget(QWidget *parent) : QAbstractScrollArea(parent) {
    m_font = QFont("Monospace", 10);
    m_font.setStyleHint(QFont::Monospace);
    m_font.setFixedPitch(true);
    setFont(m_font);

    QFontMetrics fm(m_font);
    m_charW = fm.horizontalAdvance('0');
    m_charH = fm.height();

    // Column layout
    m_addrX    = m_charW;
    m_bytesX   = m_addrX + m_charW * 11;   // "XXXXXXXX  "
    m_mnemoX   = m_bytesX + m_charW * 25;   // up to ~24 chars of hex bytes
    m_operX    = m_mnemoX + m_charW * 8;     // mnemonic ~7 chars
    m_commentX = m_operX + m_charW * 30;     // operands ~29 chars

    m_csOk = (cs_open(CS_ARCH_X86, CS_MODE_32, &m_cs) == CS_ERR_OK);
    if (m_csOk) {
        cs_option(m_cs, CS_OPT_DETAIL, CS_OPT_ON);
    }

    setFocusPolicy(Qt::StrongFocus);
    viewport()->setCursor(Qt::ArrowCursor);
}

DisasmWidget::~DisasmWidget() {
    if (m_csOk) cs_close(&m_cs);
}

void DisasmWidget::setMachO(MachOFile *macho) {
    m_macho = macho;
}

void DisasmWidget::disassembleSection(const Section &sec) {
    if (!m_csOk || !m_macho) return;

    m_lines.clear();
    m_currentLine = 0;

    const uint8_t *code = m_macho->bytesAt(sec.offset, sec.size);
    if (!code) return;

    auto &funcMap = m_macho->functionMap();

    cs_insn *insn;
    size_t count = cs_disasm(m_cs, code, sec.size, sec.addr, 0, &insn);

    m_lines.reserve(count + count / 20); // room for label lines

    for (size_t i = 0; i < count; ++i) {
        // Check if there's a function/label at this address
        auto it = funcMap.find(insn[i].address);
        if (it != funcMap.end()) {
            DisasmLine labelLine{};
            labelLine.address = insn[i].address;
            labelLine.label = it->second;
            m_lines.push_back(std::move(labelLine));
        }

        DisasmLine dl;
        dl.address = insn[i].address;
        dl.size = insn[i].size;

        // Format raw bytes
        std::string bytes;
        for (int b = 0; b < insn[i].size && b < 8; ++b) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02X ", insn[i].bytes[b]);
            bytes += buf;
        }
        if (insn[i].size > 8) bytes += "...";
        dl.bytes = bytes;

        dl.mnemonic = insn[i].mnemonic;
        dl.operands = insn[i].op_str;

        // Classify instruction
        cs_detail *detail = insn[i].detail;
        if (detail) {
            for (uint8_t g = 0; g < detail->groups_count; ++g) {
                if (detail->groups[g] == CS_GRP_CALL) dl.isCall = true;
                if (detail->groups[g] == CS_GRP_JUMP) dl.isJump = true;
                if (detail->groups[g] == CS_GRP_RET)  dl.isRet = true;
            }
        }

        // Add comment for calls/jumps with known targets
        if ((dl.isCall || dl.isJump) && detail && detail->x86.op_count > 0) {
            auto &op = detail->x86.operands[0];
            if (op.type == X86_OP_IMM) {
                uint32_t target = (uint32_t)op.imm;
                auto tgt = funcMap.find(target);
                if (tgt != funcMap.end()) {
                    dl.comment = "; " + tgt->second;
                }
            }
        }

        m_lines.push_back(std::move(dl));
    }

    if (count > 0) cs_free(insn, count);

    updateScrollBar();
    m_currentLine = 0;
    verticalScrollBar()->setValue(0);
    viewport()->update();

    emit statusMessage(QString("Disassembled %1: %2 instructions")
                       .arg(QString::fromStdString(sec.sectname))
                       .arg(m_lines.size()));
}

void DisasmWidget::goToAddress(uint32_t addr) {
    // Binary search for the address (lines are sorted by address)
    int lo = 0, hi = (int)m_lines.size() - 1;
    int best = 0;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (m_lines[mid].address == addr) {
            // Prefer the instruction line (not label line)
            best = mid;
            if (!m_lines[mid].mnemonic.empty()) break;
            if (mid + 1 < (int)m_lines.size() && m_lines[mid+1].address == addr)
                { best = mid + 1; break; }
            break;
        }
        if (m_lines[mid].address < addr) { best = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    goToIndex(best);
}

void DisasmWidget::goToIndex(int idx) {
    if (idx < 0) idx = 0;
    if (idx >= (int)m_lines.size()) idx = m_lines.size() - 1;
    m_currentLine = idx;

    int vis = visibleLines();
    int cur = verticalScrollBar()->value();
    if (m_currentLine < cur || m_currentLine >= cur + vis)
        verticalScrollBar()->setValue(std::max(0, m_currentLine - vis / 3));

    viewport()->update();
    if (!m_lines.empty())
        emit addressChanged(m_lines[m_currentLine].address);
}

uint32_t DisasmWidget::currentAddress() const {
    if (m_currentLine >= 0 && m_currentLine < (int)m_lines.size())
        return m_lines[m_currentLine].address;
    return 0;
}

int DisasmWidget::visibleLines() const {
    return viewport()->height() / lineHeight();
}

int DisasmWidget::lineHeight() const {
    return m_charH + 2;
}

void DisasmWidget::updateScrollBar() {
    int vis = visibleLines();
    verticalScrollBar()->setRange(0, std::max(0, (int)m_lines.size() - vis));
    verticalScrollBar()->setPageStep(vis);
    verticalScrollBar()->setSingleStep(1);
}

void DisasmWidget::resizeEvent(QResizeEvent *e) {
    QAbstractScrollArea::resizeEvent(e);
    updateScrollBar();
}

int DisasmWidget::indexFromY(int y) const {
    return y / lineHeight() + verticalScrollBar()->value();
}

void DisasmWidget::mousePressEvent(QMouseEvent *e) {
    if (e->button() == Qt::LeftButton) {
        int idx = indexFromY(e->pos().y());
        if (idx >= 0 && idx < (int)m_lines.size()) {
            m_currentLine = idx;
            viewport()->update();
            emit addressChanged(m_lines[idx].address);
        }
    }
}

void DisasmWidget::mouseDoubleClickEvent(QMouseEvent *e) {
    if (e->button() == Qt::LeftButton) {
        int idx = indexFromY(e->pos().y());
        if (idx >= 0 && idx < (int)m_lines.size()) {
            auto &line = m_lines[idx];
            // Double-click on call/jump: navigate to target
            if (line.isCall || line.isJump) {
                // Try to parse target from operands
                bool ok;
                uint32_t target = QString::fromStdString(line.operands).trimmed()
                                  .replace("0x", "").toUInt(&ok, 16);
                if (ok) goToAddress(target);
            }
        }
    }
}

void DisasmWidget::keyPressEvent(QKeyEvent *e) {
    if (m_lines.empty()) return;

    switch (e->key()) {
    case Qt::Key_Down:
        goToIndex(m_currentLine + 1);
        break;
    case Qt::Key_Up:
        goToIndex(m_currentLine - 1);
        break;
    case Qt::Key_PageDown:
        goToIndex(m_currentLine + visibleLines());
        break;
    case Qt::Key_PageUp:
        goToIndex(m_currentLine - visibleLines());
        break;
    case Qt::Key_Home:
        goToIndex(0);
        break;
    case Qt::Key_End:
        goToIndex(m_lines.size() - 1);
        break;
    case Qt::Key_Return:
    case Qt::Key_Enter: {
        // Follow call/jump
        auto &line = m_lines[m_currentLine];
        if (line.isCall || line.isJump) {
            bool ok;
            uint32_t target = QString::fromStdString(line.operands).trimmed()
                              .replace("0x", "").toUInt(&ok, 16);
            if (ok) goToAddress(target);
        }
        break;
    }
    case Qt::Key_G:
        if (e->modifiers() & Qt::ControlModifier) {
            bool ok;
            QString text = QInputDialog::getText(this, "Go to Address",
                "Address (hex):", QLineEdit::Normal, "", &ok);
            if (ok && !text.isEmpty()) {
                bool convOk;
                uint32_t addr = text.toUInt(&convOk, 16);
                if (convOk) goToAddress(addr);
            }
        }
        break;
    case Qt::Key_H:
        // Switch to hex view at current address
        if (m_macho && m_currentLine < (int)m_lines.size()) {
            int64_t foff = m_macho->fileOffsetForAddress(m_lines[m_currentLine].address);
            if (foff >= 0) emit goToHexOffset(foff);
        }
        break;
    case Qt::Key_C:
        if (e->modifiers() & Qt::ControlModifier) {
            auto &line = m_lines[m_currentLine];
            QString text = QString("%1  %2  %3 %4")
                .arg(line.address, 8, 16, QChar('0'))
                .arg(QString::fromStdString(line.bytes))
                .arg(QString::fromStdString(line.mnemonic))
                .arg(QString::fromStdString(line.operands));
            QApplication::clipboard()->setText(text);
        }
        break;
    default:
        QAbstractScrollArea::keyPressEvent(e);
        return;
    }
}

void DisasmWidget::paintEvent(QPaintEvent *) {
    if (m_lines.empty()) return;

    QPainter p(viewport());
    p.setFont(m_font);

    const int lh = lineHeight();
    const int firstLine = verticalScrollBar()->value();
    const int numLines = visibleLines() + 1;

    QColor bgColor = palette().color(QPalette::Base);
    QColor textColor = palette().color(QPalette::Text);
    QColor addrColor(0x60, 0x80, 0xB0);
    QColor bytesColor(0x80, 0x80, 0x80);
    QColor labelColor(0xE0, 0xA0, 0x20);
    QColor callColor(0x40, 0xA0, 0xE0);
    QColor jumpColor(0x40, 0xC0, 0x40);
    QColor retColor(0xE0, 0x60, 0x60);
    QColor commentColor(0x60, 0xA0, 0x60);
    QColor selColor(0x33, 0x55, 0x88);
    QColor mnemoColor(0xD0, 0xD0, 0xD0);
    QColor operColor(0xC0, 0xC0, 0xC0);

    for (int i = 0; i < numLines; ++i) {
        int idx = firstLine + i;
        if (idx >= (int)m_lines.size()) break;

        auto &line = m_lines[idx];
        int y = i * lh;

        // Selected line highlight
        if (idx == m_currentLine) {
            p.fillRect(0, y, viewport()->width(), lh, selColor);
        } else if (idx & 1) {
            p.fillRect(0, y, viewport()->width(), lh, bgColor.darker(105));
        }

        // Label line (function header)
        if (!line.label.empty() && line.mnemonic.empty()) {
            p.setPen(labelColor);
            QString labelText = QString::fromStdString(line.label) + ":";
            p.drawText(m_addrX, y, viewport()->width(), lh,
                       Qt::AlignLeft | Qt::AlignVCenter, labelText);
            continue;
        }

        // Address
        p.setPen(addrColor);
        p.drawText(m_addrX, y, m_bytesX - m_addrX, lh, Qt::AlignLeft | Qt::AlignVCenter,
                   QString("%1").arg(line.address, 8, 16, QChar('0')).toUpper());

        // Bytes
        p.setPen(bytesColor);
        p.drawText(m_bytesX, y, m_mnemoX - m_bytesX, lh, Qt::AlignLeft | Qt::AlignVCenter,
                   QString::fromStdString(line.bytes));

        // Mnemonic — color based on type
        if (line.isCall)      p.setPen(callColor);
        else if (line.isJump) p.setPen(jumpColor);
        else if (line.isRet)  p.setPen(retColor);
        else                  p.setPen(mnemoColor);
        p.drawText(m_mnemoX, y, m_operX - m_mnemoX, lh, Qt::AlignLeft | Qt::AlignVCenter,
                   QString::fromStdString(line.mnemonic));

        // Operands
        p.setPen(operColor);
        p.drawText(m_operX, y, m_commentX - m_operX, lh, Qt::AlignLeft | Qt::AlignVCenter,
                   QString::fromStdString(line.operands));

        // Comment
        if (!line.comment.empty()) {
            p.setPen(commentColor);
            p.drawText(m_commentX, y, viewport()->width() - m_commentX, lh,
                       Qt::AlignLeft | Qt::AlignVCenter,
                       QString::fromStdString(line.comment));
        }
    }
}
