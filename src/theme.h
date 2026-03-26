#pragma once
#include <QColor>
#include <QString>

struct Theme {
    bool isDark;

    // Shared
    QColor bg, bgAlt, headerBg, headerFg, divider;
    QColor selection, selBorder;

    // Hex view
    QColor hexAddr, hexByteNorm, hexByteZero, hexByteHigh;
    QColor hexAscii, hexAsciiDot, hexHl, hexCursor, hexCursorBd;

    // Disasm view
    QColor disAddr, disBytes, disMnemonic, disOperands;
    QColor disCall, disJump, disRet, disNop;
    QColor disComment, disLabelBg, disLabelFg, disLabelLine;

    // Status bar (applied via stylesheet)
    QColor statusBg, statusFg;
};

inline Theme darkTheme() {
    Theme t{};
    t.isDark = true;

    t.bg         = {0x0C, 0x0C, 0x0C};
    t.bgAlt      = {0x11, 0x11, 0x11};
    t.headerBg   = {0x14, 0x14, 0x14};
    t.headerFg   = {0x6E, 0x6E, 0x6E};
    t.divider    = {0x2A, 0x2A, 0x2A};
    t.selection  = {0x1A, 0x3A, 0x56};
    t.selBorder  = {0x27, 0x5D, 0x8A};

    t.hexAddr     = {0x5A, 0x9E, 0xCF};
    t.hexByteNorm = {0xCC, 0xCC, 0xCC};
    t.hexByteZero = {0x40, 0x40, 0x40};
    t.hexByteHigh = {0xE0, 0x8E, 0x58};
    t.hexAscii    = {0x7E, 0xC6, 0x99};
    t.hexAsciiDot = {0x3A, 0x3A, 0x3A};
    t.hexHl       = {0x5A, 0x40, 0x10};
    t.hexCursor   = {0xDC, 0xDC, 0xAA, 0x50};
    t.hexCursorBd = {0xDC, 0xDC, 0xAA};

    t.disAddr      = {0x5A, 0x9E, 0xCF};
    t.disBytes     = {0x50, 0x50, 0x50};
    t.disMnemonic  = {0xD4, 0xD4, 0xD4};
    t.disOperands  = {0xB0, 0xB0, 0xB0};
    t.disCall      = {0x4E, 0xC9, 0xB0};
    t.disJump      = {0xC5, 0x86, 0xC0};
    t.disRet       = {0xCE, 0x91, 0x78};
    t.disNop       = {0x40, 0x40, 0x40};
    t.disComment   = {0x6A, 0x99, 0x55};
    t.disLabelBg   = {0x14, 0x14, 0x14};
    t.disLabelFg   = {0xDC, 0xDC, 0xAA};
    t.disLabelLine = {0x2A, 0x2A, 0x2A};

    t.statusBg = {0x0E, 0x63, 0x9C};
    t.statusFg = {0xFF, 0xFF, 0xFF};
    return t;
}

inline Theme lightTheme() {
    Theme t{};
    t.isDark = false;

    t.bg         = {0xFF, 0xFF, 0xFF};
    t.bgAlt      = {0xF8, 0xF8, 0xF8};
    t.headerBg   = {0xF3, 0xF3, 0xF3};
    t.headerFg   = {0x6E, 0x6E, 0x6E};
    t.divider    = {0xE0, 0xE0, 0xE0};
    t.selection  = {0xAD, 0xD6, 0xFF};
    t.selBorder  = {0x75, 0xB5, 0xEE};

    // VS Light hex colours
    t.hexAddr     = {0x2B, 0x91, 0xAF};
    t.hexByteNorm = {0x1E, 0x1E, 0x1E};
    t.hexByteZero = {0xC0, 0xC0, 0xC0};
    t.hexByteHigh = {0xA3, 0x15, 0x15};
    t.hexAscii    = {0x00, 0x80, 0x00};
    t.hexAsciiDot = {0xC8, 0xC8, 0xC8};
    t.hexHl       = {0xFF, 0xF0, 0xB0};
    t.hexCursor   = {0x00, 0x7A, 0xCC, 0x40};
    t.hexCursorBd = {0x00, 0x7A, 0xCC};

    // VS Light disasm colours — classic Visual Studio C++
    t.disAddr      = {0x2B, 0x91, 0xAF};   // teal addresses
    t.disBytes     = {0xA0, 0xA0, 0xA0};   // light grey raw bytes
    t.disMnemonic  = {0x00, 0x00, 0xFF};   // blue keywords
    t.disOperands  = {0x1E, 0x1E, 0x1E};   // black text
    t.disCall      = {0x79, 0x5E, 0x26};   // VS function-call brown
    t.disJump      = {0xAF, 0x00, 0xDB};   // VS magenta/purple
    t.disRet       = {0xA3, 0x15, 0x15};   // VS dark-red
    t.disNop       = {0xC0, 0xC0, 0xC0};   // faded grey
    t.disComment   = {0x00, 0x80, 0x00};   // green comments
    t.disLabelBg   = {0xF3, 0xF3, 0xF3};   // light grey bar
    t.disLabelFg   = {0x79, 0x5E, 0x26};   // VS function brown
    t.disLabelLine = {0xE0, 0xE0, 0xE0};

    t.statusBg = {0x00, 0x7A, 0xCC};
    t.statusFg = {0xFF, 0xFF, 0xFF};
    return t;
}

// ── Stylesheets ─────────────────────────────────────────────────────

inline QString darkStyleSheet() {
    return R"(
* { font-family: "Segoe UI", "Noto Sans", "Helvetica Neue", sans-serif; font-size: 13px; }
QMainWindow, QDialog { background: #181818; }
QMenuBar { background: #1b1b1b; color: #aaa; border-bottom: 1px solid #2a2a2a; padding: 2px 0; }
QMenuBar::item { padding: 4px 10px; }
QMenuBar::item:selected { background: #333; color: #ddd; border-radius: 3px; }
QMenu { background: #222; color: #ccc; border: 1px solid #333; padding: 4px 0; }
QMenu::item { padding: 5px 28px 5px 12px; }
QMenu::item:selected { background: #3d5a80; color: #fff; }
QMenu::separator { height: 1px; background: #333; margin: 4px 8px; }
QToolBar { background: #1b1b1b; border-bottom: 1px solid #2a2a2a; spacing: 6px; padding: 3px 6px; }
QToolBar QLabel { color: #888; }
QComboBox { background: #252525; color: #ccc; border: 1px solid #3a3a3a; border-radius: 3px; padding: 4px 10px; min-width: 280px; }
QComboBox:hover { border-color: #555; }
QComboBox::drop-down { border: none; width: 20px; }
QComboBox QAbstractItemView { background: #222; color: #ccc; border: 1px solid #3a3a3a; selection-background-color: #3d5a80; }
QTabWidget::pane { border: none; }
QTabBar { background: #1b1b1b; }
QTabBar::tab { background: transparent; color: #777; padding: 7px 18px; border: none; border-bottom: 2px solid transparent; }
QTabBar::tab:hover { color: #bbb; }
QTabBar::tab:selected { color: #ddd; border-bottom: 2px solid #5a9ecf; }
QDockWidget { color: #aaa; }
QDockWidget::title { background: #1b1b1b; padding: 6px 10px; border-bottom: 1px solid #2a2a2a; font-weight: bold; }
QTreeWidget, QTableWidget { background: #141414; alternate-background-color: #181818; color: #bbb; border: none; gridline-color: #222; outline: none; }
QTreeWidget::item, QTableWidget::item { padding: 3px 6px; }
QTreeWidget::item:selected, QTableWidget::item:selected { background: #1a3a56; color: #ddd; }
QTreeWidget::item:hover, QTableWidget::item:hover { background: #1e1e1e; }
QHeaderView::section { background: #1b1b1b; color: #777; border: none; border-right: 1px solid #2a2a2a; border-bottom: 1px solid #2a2a2a; padding: 5px 8px; font-weight: normal; }
QTreeWidget::branch { background: #141414; }
QTextEdit { background: #141414; color: #bbb; border: none; selection-background-color: #1a3a56; font-family: "Monospace", monospace; font-size: 12px; }
QLineEdit { background: #1e1e1e; color: #ccc; border: 1px solid #333; border-radius: 3px; padding: 5px 8px; selection-background-color: #3d5a80; }
QLineEdit:focus { border-color: #5a9ecf; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #3a3a3a; min-height: 30px; border-radius: 5px; margin: 2px; }
QScrollBar::handle:vertical:hover { background: #555; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 0; }
QScrollBar::handle:horizontal { background: #3a3a3a; min-width: 30px; border-radius: 5px; margin: 2px; }
QScrollBar::handle:horizontal:hover { background: #555; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }
QStatusBar { background: #0e639c; color: #fff; border: none; font-size: 12px; }
QStatusBar QLabel { color: #fff; padding: 0 8px; }
)";
}

inline QString lightStyleSheet() {
    return R"(
* { font-family: "Segoe UI", "Noto Sans", "Helvetica Neue", sans-serif; font-size: 13px; }
QMainWindow, QDialog { background: #f0f0f0; }
QMenuBar { background: #e8e8e8; color: #333; border-bottom: 1px solid #d0d0d0; padding: 2px 0; }
QMenuBar::item { padding: 4px 10px; }
QMenuBar::item:selected { background: #cde4f7; color: #000; border-radius: 3px; }
QMenu { background: #f6f6f6; color: #1e1e1e; border: 1px solid #ccc; padding: 4px 0; }
QMenu::item { padding: 5px 28px 5px 12px; }
QMenu::item:selected { background: #cde4f7; color: #000; }
QMenu::separator { height: 1px; background: #d8d8d8; margin: 4px 8px; }
QToolBar { background: #e8e8e8; border-bottom: 1px solid #d0d0d0; spacing: 6px; padding: 3px 6px; }
QToolBar QLabel { color: #555; }
QComboBox { background: #fff; color: #1e1e1e; border: 1px solid #c0c0c0; border-radius: 3px; padding: 4px 10px; min-width: 280px; }
QComboBox:hover { border-color: #888; }
QComboBox::drop-down { border: none; width: 20px; }
QComboBox QAbstractItemView { background: #fff; color: #1e1e1e; border: 1px solid #c0c0c0; selection-background-color: #cde4f7; }
QTabWidget::pane { border: none; }
QTabBar { background: #e8e8e8; }
QTabBar::tab { background: transparent; color: #666; padding: 7px 18px; border: none; border-bottom: 2px solid transparent; }
QTabBar::tab:hover { color: #333; }
QTabBar::tab:selected { color: #1e1e1e; border-bottom: 2px solid #007acc; }
QDockWidget { color: #333; }
QDockWidget::title { background: #e8e8e8; padding: 6px 10px; border-bottom: 1px solid #d0d0d0; font-weight: bold; }
QTreeWidget, QTableWidget { background: #fff; alternate-background-color: #f8f8f8; color: #1e1e1e; border: none; gridline-color: #eee; outline: none; }
QTreeWidget::item, QTableWidget::item { padding: 3px 6px; }
QTreeWidget::item:selected, QTableWidget::item:selected { background: #cde4f7; color: #000; }
QTreeWidget::item:hover, QTableWidget::item:hover { background: #e8f0f8; }
QHeaderView::section { background: #f3f3f3; color: #666; border: none; border-right: 1px solid #e0e0e0; border-bottom: 1px solid #e0e0e0; padding: 5px 8px; font-weight: normal; }
QTreeWidget::branch { background: #fff; }
QTextEdit { background: #fff; color: #1e1e1e; border: none; selection-background-color: #cde4f7; font-family: "Monospace", monospace; font-size: 12px; }
QLineEdit { background: #fff; color: #1e1e1e; border: 1px solid #c0c0c0; border-radius: 3px; padding: 5px 8px; selection-background-color: #cde4f7; }
QLineEdit:focus { border-color: #007acc; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #c0c0c0; min-height: 30px; border-radius: 5px; margin: 2px; }
QScrollBar::handle:vertical:hover { background: #999; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 0; }
QScrollBar::handle:horizontal { background: #c0c0c0; min-width: 30px; border-radius: 5px; margin: 2px; }
QScrollBar::handle:horizontal:hover { background: #999; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }
QStatusBar { background: #007acc; color: #fff; border: none; font-size: 12px; }
QStatusBar QLabel { color: #fff; padding: 0 8px; }
)";
}
