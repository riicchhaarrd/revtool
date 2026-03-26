#include "hexwidget.h"
#include <QPainter>
#include <QApplication>
#include <QClipboard>
#include <algorithm>

HexWidget::HexWidget(QWidget *parent) : QAbstractScrollArea(parent) {
    m_font = QFont("Monospace", 10);
    m_font.setStyleHint(QFont::Monospace);
    m_font.setFixedPitch(true);
    setFont(m_font);

    QFontMetrics fm(m_font);
    m_charW = fm.horizontalAdvance('0');
    m_charH = fm.height();

    // Layout: "XXXXXXXX  " + hex + "  " + ascii
    m_addrColW = m_charW * 9;  // 8 hex digits + space
    m_hexColX  = m_addrColW + m_charW;
    // 16 bytes: "XX " * 16 + extra space in middle = 49 chars
    m_asciiColX = m_hexColX + m_charW * (m_bytesPerLine * 3 + 1) + m_charW;

    setMinimumWidth(m_asciiColX + m_charW * (m_bytesPerLine + 2));
    viewport()->setCursor(Qt::IBeamCursor);
    setFocusPolicy(Qt::StrongFocus);
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
    m_hlStart = start;
    m_hlLen = length;
    viewport()->update();
}

void HexWidget::clearHighlight() {
    m_hlStart = -1;
    m_hlLen = 0;
    viewport()->update();
}

int HexWidget::visibleLines() const {
    return viewport()->height() / lineHeight();
}

int HexWidget::lineHeight() const {
    return m_charH + 2;
}

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
    int line = pt.y() / lineHeight() + verticalScrollBar()->value();
    int col = -1;
    int x = pt.x();

    if (x >= m_hexColX && x < m_asciiColX) {
        // In hex area
        int relX = x - m_hexColX;
        int byteIdx = relX / (m_charW * 3);
        // Account for extra space after byte 7
        if (byteIdx >= 8) {
            int adjX = relX - m_charW; // subtract the extra space
            byteIdx = adjX / (m_charW * 3);
            if (byteIdx < 8) byteIdx = 8;
        }
        col = std::clamp(byteIdx, 0, m_bytesPerLine - 1);
    } else if (x >= m_asciiColX) {
        col = (x - m_asciiColX) / m_charW;
        col = std::clamp(col, 0, m_bytesPerLine - 1);
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
    case Qt::Key_Right:
        if (m_cursorPos < maxPos) { m_cursorPos++; moved = true; }
        break;
    case Qt::Key_Left:
        if (m_cursorPos > 0) { m_cursorPos--; moved = true; }
        break;
    case Qt::Key_Down:
        if (m_cursorPos + m_bytesPerLine <= maxPos) { m_cursorPos += m_bytesPerLine; moved = true; }
        break;
    case Qt::Key_Up:
        if (m_cursorPos >= m_bytesPerLine) { m_cursorPos -= m_bytesPerLine; moved = true; }
        break;
    case Qt::Key_PageDown:
        m_cursorPos = std::min(m_cursorPos + (int64_t)visibleLines() * m_bytesPerLine, maxPos);
        moved = true;
        break;
    case Qt::Key_PageUp:
        m_cursorPos = std::max(m_cursorPos - (int64_t)visibleLines() * m_bytesPerLine, (int64_t)0);
        moved = true;
        break;
    case Qt::Key_Home:
        m_cursorPos = 0; moved = true;
        break;
    case Qt::Key_End:
        m_cursorPos = maxPos; moved = true;
        break;
    case Qt::Key_G:
        if (e->modifiers() & Qt::ControlModifier) {
            bool ok;
            QString text = QInputDialog::getText(this, "Go to Offset",
                "Offset (hex):", QLineEdit::Normal, "", &ok);
            if (ok && !text.isEmpty()) {
                bool convOk;
                int64_t off = text.toLongLong(&convOk, 16);
                if (convOk) goToOffset(off);
            }
        }
        break;
    case Qt::Key_C:
        if (e->modifiers() & Qt::ControlModifier && m_selStart >= 0) {
            int64_t s = std::min(m_selStart, m_selEnd);
            int64_t e2 = std::max(m_selStart, m_selEnd);
            QString hex;
            for (int64_t i = s; i <= e2 && i < (int64_t)m_dataSize; ++i)
                hex += QString("%1 ").arg(m_data[i], 2, 16, QChar('0'));
            QApplication::clipboard()->setText(hex.trimmed());
        }
        break;
    default:
        QAbstractScrollArea::keyPressEvent(e);
        return;
    }

    if (moved) {
        m_selStart = m_selEnd = -1;
        int line = m_cursorPos / m_bytesPerLine;
        int vis = visibleLines();
        int curScroll = verticalScrollBar()->value();
        if (line < curScroll)
            verticalScrollBar()->setValue(line);
        else if (line >= curScroll + vis)
            verticalScrollBar()->setValue(line - vis + 1);
        viewport()->update();
        emit offsetChanged(m_cursorPos);
    }
}

void HexWidget::paintEvent(QPaintEvent *) {
    if (!m_data) return;

    QPainter p(viewport());
    p.setFont(m_font);

    const int lh = lineHeight();
    const int firstLine = verticalScrollBar()->value();
    const int numLines = visibleLines() + 1;

    QColor bgColor = palette().color(QPalette::Base);
    QColor textColor = palette().color(QPalette::Text);
    QColor addrColor(0x60, 0x80, 0xB0);
    QColor asciiColor(0x50, 0xA0, 0x50);
    QColor selColor(0x33, 0x66, 0xCC, 0x60);
    QColor hlColor(0xCC, 0x99, 0x33, 0x40);
    QColor cursorColor(0xFF, 0x66, 0x00, 0x80);
    QColor altRowColor = bgColor.darker(105);

    int64_t selLo = -1, selHi = -1;
    if (m_selStart >= 0 && m_selEnd >= 0) {
        selLo = std::min(m_selStart, m_selEnd);
        selHi = std::max(m_selStart, m_selEnd);
    }

    for (int i = 0; i < numLines; ++i) {
        int line = firstLine + i;
        int64_t lineOff = (int64_t)line * m_bytesPerLine;
        if (lineOff >= (int64_t)m_dataSize) break;

        int y = i * lh;
        int bytesInLine = std::min((int64_t)m_bytesPerLine, (int64_t)m_dataSize - lineOff);

        // Alternate row background
        if (line & 1) {
            p.fillRect(0, y, viewport()->width(), lh, altRowColor);
        }

        // Address
        p.setPen(addrColor);
        p.drawText(0, y, m_addrColW, lh, Qt::AlignLeft | Qt::AlignVCenter,
                   QString("%1").arg((uint32_t)lineOff, 8, 16, QChar('0')).toUpper());

        // Hex bytes
        for (int b = 0; b < bytesInLine; ++b) {
            int64_t byteOff = lineOff + b;
            int hx = m_hexColX + b * m_charW * 3;
            if (b >= 8) hx += m_charW; // extra space after 8th byte

            // Highlight background
            if (m_hlStart >= 0 && byteOff >= m_hlStart && byteOff < m_hlStart + m_hlLen)
                p.fillRect(hx - 1, y, m_charW * 2 + 2, lh, hlColor);

            // Selection background
            if (selLo >= 0 && byteOff >= selLo && byteOff <= selHi)
                p.fillRect(hx - 1, y, m_charW * 2 + 2, lh, selColor);

            // Cursor
            if (byteOff == m_cursorPos)
                p.fillRect(hx - 1, y, m_charW * 2 + 2, lh, cursorColor);

            uint8_t val = m_data[byteOff];
            p.setPen(val == 0 ? QColor(0x80, 0x80, 0x80) : textColor);
            p.drawText(hx, y, m_charW * 3, lh, Qt::AlignLeft | Qt::AlignVCenter,
                       QString("%1").arg(val, 2, 16, QChar('0')).toUpper());
        }

        // ASCII
        p.setPen(asciiColor);
        for (int b = 0; b < bytesInLine; ++b) {
            int64_t byteOff = lineOff + b;
            int ax = m_asciiColX + b * m_charW;

            if (selLo >= 0 && byteOff >= selLo && byteOff <= selHi)
                p.fillRect(ax, y, m_charW, lh, selColor);
            if (byteOff == m_cursorPos)
                p.fillRect(ax, y, m_charW, lh, cursorColor);

            uint8_t val = m_data[byteOff];
            QChar ch = (val >= 0x20 && val < 0x7F) ? QChar(val) : QChar('.');
            p.drawText(ax, y, m_charW, lh, Qt::AlignCenter, ch);
        }
    }

    // Column separator lines
    p.setPen(QColor(0x40, 0x40, 0x40));
    int sepX1 = m_hexColX - m_charW / 2;
    int sepX2 = m_asciiColX - m_charW / 2;
    p.drawLine(sepX1, 0, sepX1, viewport()->height());
    p.drawLine(sepX2, 0, sepX2, viewport()->height());
}
