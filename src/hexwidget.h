#pragma once
#include "theme.h"
#include <QAbstractScrollArea>
#include <QFont>
#include <QFontMetrics>
#include <QPaintEvent>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QWheelEvent>
#include <QScrollBar>
#include <QInputDialog>
#include <cstdint>
#include <functional>

class HexWidget : public QAbstractScrollArea {
    Q_OBJECT
public:
    explicit HexWidget(QWidget *parent = nullptr);

    void setData(const uint8_t *data, size_t size);
    void goToOffset(int64_t offset);
    void setHighlight(int64_t start, int64_t length);
    void clearHighlight();

    int64_t currentOffset() const { return m_cursorPos; }
    void setTheme(const Theme &theme);

signals:
    void offsetChanged(int64_t offset);
    void selectionChanged(int64_t start, int64_t end);
    void statusMessage(const QString &msg);

protected:
    void paintEvent(QPaintEvent *e) override;
    void keyPressEvent(QKeyEvent *e) override;
    void mousePressEvent(QMouseEvent *e) override;
    void mouseMoveEvent(QMouseEvent *e) override;
    void resizeEvent(QResizeEvent *e) override;

private:
    void recalcLayout();
    void updateScrollBar();
    int64_t posFromPoint(const QPoint &pt) const;
    int visibleLines() const;
    int lineHeight() const;
    int headerHeight() const;

    const uint8_t *m_data = nullptr;
    size_t   m_dataSize = 0;
    int64_t  m_cursorPos = 0;
    int64_t  m_selStart = -1;
    int64_t  m_selEnd = -1;
    int64_t  m_hlStart = -1;
    int64_t  m_hlLen = 0;
    int      m_bytesPerLine = 16;
    int      m_charW = 0;
    int      m_charH = 0;
    int      m_margin = 0;
    int      m_addrColW = 0;
    int      m_hexColX = 0;
    int      m_asciiColX = 0;
    QFont    m_font;
    Theme    m_theme;
};
