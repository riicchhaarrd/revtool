#include "hexwidget.h"
#include <QPainter>
#include <QApplication>
#include <QClipboard>
#include <algorithm>

// ── Palette ─────────────────────────────────────────────────────────
namespace Hex {
    static const QColor bg        (0x0C, 0x0C, 0x0C);
    static const QColor bgAlt     (0x11, 0x11, 0x11);
    static const QColor headerBg  (0x14, 0x14, 0x14);
    static const QColor headerFg  (0x6E, 0x6E, 0x6E);
    static const QColor gutter    (0x3A, 0x3A, 0x3A);
    static const QColor addr      (0x5A, 0x9E, 0xCF);
    static const QColor byteNorm  (0xCC, 0xCC, 0xCC);
    static const QColor byteZero  (0x40, 0x40, 0x40);
    static const QColor byteHigh  (0xE0, 0x8E, 0x58);  // 0x80-0xFF
    static const QColor ascii     (0x7E, 0xC6, 0x99);
    static const QColor asciiDot  (0x3A, 0x3A, 0x3A);
    static const QColor sel       (0x26, 0x4F, 0x78);
    static const QColor hl        (0x5A, 0x40, 0x10);
    static const QColor cursor    (0xDC, 0xDC, 0xAA, 0x50);
    static const QColor cursorBd  (0xDC, 0xDC, 0xAA);
    static const QColor divider   (0x2A, 0x2A, 0x2A);
}

HexWidget::HexWidget(QWidget *parent) : QAbstractScrollArea(parent) {
    m_font = QFont("Monospace", 11);
    m_font.setStyleHint(QFont::Monospace);
    m_font.setFixedPitch(true);
    setFont(m_font);
    recalcLayout();

    viewport()->setCursor(Qt::IBeamCursor);
    setFocusPolicy(Qt::StrongFocus);
}

void HexWidget::recalcLayout() {
    QFontMetrics fm(m_font);
    m_charW  = fm.horizontalAdvance('0');
    m_charH  = fm.height();
    m_margin = m_charW;
    m_addrColW = m_margin + m_charW * 8 + m_charW; // margin + "XXXXXXXX" + gap
    m_hexColX  = m_addrColW + m_charW;
    // hex: "XX " * 16 + one extra gap in the middle = 49 char-widths
    m_asciiColX = m_hexColX + m_charW * (m_bytesPerLine * 3 + 1) + m_charW * 2;
    setMinimumWidth(m_asciiColX + m_charW * (m_bytesPerLine + 3));
}

void HexWidget::setData(const uint8_t *data, size_t size) {
    m_data = data;
    m_dataSize = size;
    m_cursorPos = 0;
    m_selStart = m_selEnd = -1;
    updateScrollBar();
    viewport()->update();
}

void HexWidget::goToOffset(int64_t offset) {
    if (!m_data || offset < 0) return;
    if ((size_t)offset >= m_dataSize) offset = m_dataSize - 1;
    m_cursorPos = offset;
    int line = offset / m_bytesPerLine;
    int vis = visibleLines();
    int curScroll = verticalScrollBar()->value();
    if (line < curScroll || line >= curScroll + vis)
        verticalScrollBar()->setValue(std::max(0, line - vis / 3));
    viewport()->update();
    emit offsetChanged(m_cursorPos);
}

void HexWidget::setHighlight(int64_t start, int64_t length) {
    m_hlStart = start; m_hlLen = length;
    viewport()->update();
}

void HexWidget::clearHighlight() {
    m_hlStart = -1; m_hlLen = 0;
    viewport()->update();
}

int HexWidget::headerHeight() const { return lineHeight() + 4; }
int HexWidget::visibleLines() const { return (viewport()->height() - headerHeight()) / lineHeight(); }
int HexWidget::lineHeight() const { return m_charH + 4; }

void HexWidget::updateScrollBar() {
    int totalLines = (m_dataSize + m_bytesPerLine - 1) / m_bytesPerLine;
    int vis = visibleLines();
    verticalScrollBar()->setRange(0, std::max(0, totalLines - vis));
    verticalScrollBar()->setPageStep(vis);
    verticalScrollBar()->setSingleStep(1);
}

void HexWidget::resizeEvent(QResizeEvent *e) {
    QAbstractScrollArea::resizeEvent(e);
    updateScrollBar();
}

int64_t HexWidget::posFromPoint(const QPoint &pt) const {
    int line = (pt.y() - headerHeight()) / lineHeight() + verticalScrollBar()->value();
    int col = -1, x = pt.x();
    if (x >= m_hexColX && x < m_asciiColX) {
        int relX = x - m_hexColX;
        int byteIdx = relX / (m_charW * 3);
        if (byteIdx >= 8) {
            int adjX = relX - m_charW;
            byteIdx = adjX / (m_charW * 3);
            if (byteIdx < 8) byteIdx = 8;
        }
        col = std::clamp(byteIdx, 0, m_bytesPerLine - 1);
    } else if (x >= m_asciiColX) {
        col = std::clamp((x - m_asciiColX) / m_charW, 0, m_bytesPerLine - 1);
    }
    if (col < 0) col = 0;
    int64_t pos = (int64_t)line * m_bytesPerLine + col;
    return std::clamp(pos, (int64_t)0, (int64_t)(m_dataSize > 0 ? m_dataSize - 1 : 0));
}

void HexWidget::mousePressEvent(QMouseEvent *e) {
    if (e->button() == Qt::LeftButton) {
        m_cursorPos = posFromPoint(e->pos());
        m_selStart = m_cursorPos;
        m_selEnd = m_cursorPos;
        viewport()->update();
        emit offsetChanged(m_cursorPos);
    }
}

void HexWidget::mouseMoveEvent(QMouseEvent *e) {
    if (e->buttons() & Qt::LeftButton) {
        m_selEnd = posFromPoint(e->pos());
        m_cursorPos = m_selEnd;
        viewport()->update();
        emit selectionChanged(std::min(m_selStart, m_selEnd), std::max(m_selStart, m_selEnd));
    }
}

void HexWidget::keyPressEvent(QKeyEvent *e) {
    if (!m_data) return;
    int64_t maxPos = m_dataSize > 0 ? m_dataSize - 1 : 0;
    bool moved = false;

    switch (e->key()) {
    case Qt::Key_Right:  if (m_cursorPos < maxPos) { m_cursorPos++; moved = true; } break;
    case Qt::Key_Left:   if (m_cursorPos > 0) { m_cursorPos--; moved = true; } break;
    case Qt::Key_Down:   if (m_cursorPos + m_bytesPerLine <= maxPos) { m_cursorPos += m_bytesPerLine; moved = true; } break;
    case Qt::Key_Up:     if (m_cursorPos >= m_bytesPerLine) { m_cursorPos -= m_bytesPerLine; moved = true; } break;
    case Qt::Key_PageDown: m_cursorPos = std::min(m_cursorPos + (int64_t)visibleLines() * m_bytesPerLine, maxPos); moved = true; break;
    case Qt::Key_PageUp:   m_cursorPos = std::max(m_cursorPos - (int64_t)visibleLines() * m_bytesPerLine, (int64_t)0); moved = true; break;
    case Qt::Key_Home:   m_cursorPos = 0; moved = true; break;
    case Qt::Key_End:    m_cursorPos = maxPos; moved = true; break;
    case Qt::Key_G:
        if (e->modifiers() & Qt::ControlModifier) {
            bool ok;
            QString text = QInputDialog::getText(this, "Go to Offset", "Offset (hex):", QLineEdit::Normal, "", &ok);
            if (ok && !text.isEmpty()) { bool c; int64_t off = text.toLongLong(&c, 16); if (c) goToOffset(off); }
        }
        break;
    case Qt::Key_C:
        if (e->modifiers() & Qt::ControlModifier && m_selStart >= 0) {
            int64_t s = std::min(m_selStart, m_selEnd), e2 = std::max(m_selStart, m_selEnd);
            QString hex;
            for (int64_t i = s; i <= e2 && i < (int64_t)m_dataSize; ++i)
                hex += QString("%1 ").arg(m_data[i], 2, 16, QChar('0'));
            QApplication::clipboard()->setText(hex.trimmed());
        }
        break;
    default: QAbstractScrollArea::keyPressEvent(e); return;
    }

    if (moved) {
        m_selStart = m_selEnd = -1;
        int line = m_cursorPos / m_bytesPerLine;
        int vis = visibleLines(), cur = verticalScrollBar()->value();
        if (line < cur) verticalScrollBar()->setValue(line);
        else if (line >= cur + vis) verticalScrollBar()->setValue(line - vis + 1);
        viewport()->update();
        emit offsetChanged(m_cursorPos);
    }
}

void HexWidget::paintEvent(QPaintEvent *) {
    QPainter p(viewport());
    p.setRenderHint(QPainter::TextAntialiasing);
    p.setFont(m_font);

    const int lh = lineHeight();
    const int hh = headerHeight();
    const int w  = viewport()->width();

    // Full background
    p.fillRect(viewport()->rect(), Hex::bg);

    // ── Column header ───────────────────────────────────────────────
    p.fillRect(0, 0, w, hh, Hex::headerBg);
    p.setPen(Hex::headerFg);
    p.drawText(m_margin, 0, m_addrColW, hh, Qt::AlignLeft | Qt::AlignVCenter, "OFFSET");
    for (int b = 0; b < m_bytesPerLine; ++b) {
        int hx = m_hexColX + b * m_charW * 3 + (b >= 8 ? m_charW : 0);
        p.drawText(hx, 0, m_charW * 2, hh, Qt::AlignCenter,
                   QString("%1").arg(b, 2, 16, QChar('0')).toUpper());
    }
    p.drawText(m_asciiColX, 0, m_charW * 16, hh, Qt::AlignLeft | Qt::AlignVCenter, "ASCII");
    // Header bottom line
    p.setPen(Hex::divider);
    p.drawLine(0, hh - 1, w, hh - 1);

    if (!m_data) return;

    const int firstLine = verticalScrollBar()->value();
    const int numLines  = visibleLines() + 1;

    int64_t selLo = -1, selHi = -1;
    if (m_selStart >= 0 && m_selEnd >= 0) {
        selLo = std::min(m_selStart, m_selEnd);
        selHi = std::max(m_selStart, m_selEnd);
    }

    for (int i = 0; i < numLines; ++i) {
        int line = firstLine + i;
        int64_t lineOff = (int64_t)line * m_bytesPerLine;
        if (lineOff >= (int64_t)m_dataSize) break;

        int y = hh + i * lh;
        int bytesInLine = std::min((int64_t)m_bytesPerLine, (int64_t)m_dataSize - lineOff);

        // Alternate row
        if (line & 1)
            p.fillRect(0, y, w, lh, Hex::bgAlt);

        // Address
        p.setPen(Hex::addr);
        p.drawText(m_margin, y, m_addrColW - m_margin, lh, Qt::AlignLeft | Qt::AlignVCenter,
                   QString("%1").arg((uint32_t)lineOff, 8, 16, QChar('0')).toUpper());

        // Hex bytes + ASCII
        for (int b = 0; b < bytesInLine; ++b) {
            int64_t byteOff = lineOff + b;
            int hx = m_hexColX + b * m_charW * 3 + (b >= 8 ? m_charW : 0);
            int ax = m_asciiColX + b * m_charW;
            uint8_t val = m_data[byteOff];

            // Backgrounds: highlight, selection, cursor
            bool isHl  = (m_hlStart >= 0 && byteOff >= m_hlStart && byteOff < m_hlStart + m_hlLen);
            bool isSel = (selLo >= 0 && byteOff >= selLo && byteOff <= selHi);
            bool isCur = (byteOff == m_cursorPos);

            if (isHl) {
                p.fillRect(hx - 1, y, m_charW * 2 + 2, lh, Hex::hl);
                p.fillRect(ax, y, m_charW, lh, Hex::hl);
            }
            if (isSel) {
                p.fillRect(hx - 1, y, m_charW * 2 + 2, lh, Hex::sel);
                p.fillRect(ax, y, m_charW, lh, Hex::sel);
            }
            if (isCur) {
                p.fillRect(hx - 1, y, m_charW * 2 + 2, lh, Hex::cursor);
                p.setPen(Hex::cursorBd);
                p.drawRect(hx - 1, y, m_charW * 2 + 1, lh - 1);
                p.fillRect(ax, y, m_charW, lh, Hex::cursor);
            }

            // Hex digit color
            if (val == 0)            p.setPen(Hex::byteZero);
            else if (val >= 0x80)    p.setPen(Hex::byteHigh);
            else                     p.setPen(Hex::byteNorm);
            p.drawText(hx, y, m_charW * 2, lh, Qt::AlignCenter,
                       QString("%1").arg(val, 2, 16, QChar('0')).toUpper());

            // ASCII
            QChar ch = (val >= 0x20 && val < 0x7F) ? QChar(val) : QChar('.');
            p.setPen(ch == '.' ? Hex::asciiDot : Hex::ascii);
            p.drawText(ax, y, m_charW, lh, Qt::AlignCenter, ch);
        }
    }

    // Column dividers
    p.setPen(Hex::divider);
    int sep1 = m_hexColX - m_charW / 2;
    int sep2 = m_asciiColX - m_charW / 2;
    p.drawLine(sep1, 0, sep1, viewport()->height());
    p.drawLine(sep2, 0, sep2, viewport()->height());
}
