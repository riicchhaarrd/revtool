#include "mainwindow.h"
#include <QMenuBar>
#include <QMenu>
#include <QToolBar>
#include <QStatusBar>
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QApplication>
#include <QSplitter>

static const char *kStyleSheet = R"(
* {
    font-family: "Segoe UI", "Noto Sans", "Helvetica Neue", sans-serif;
    font-size: 13px;
}

QMainWindow, QDialog {
    background: #181818;
}

/* ── Menu bar ────────────────────────────────────────────────── */
QMenuBar {
    background: #1b1b1b;
    color: #aaa;
    border-bottom: 1px solid #2a2a2a;
    padding: 2px 0;
}
QMenuBar::item        { padding: 4px 10px; }
QMenuBar::item:selected { background: #333; color: #ddd; border-radius: 3px; }
QMenu {
    background: #222;
    color: #ccc;
    border: 1px solid #333;
    padding: 4px 0;
}
QMenu::item            { padding: 5px 28px 5px 12px; }
QMenu::item:selected   { background: #3d5a80; color: #fff; }
QMenu::separator       { height: 1px; background: #333; margin: 4px 8px; }

/* ── Toolbar ─────────────────────────────────────────────────── */
QToolBar {
    background: #1b1b1b;
    border-bottom: 1px solid #2a2a2a;
    spacing: 6px;
    padding: 3px 6px;
}
QToolBar QLabel { color: #888; }
QComboBox {
    background: #252525;
    color: #ccc;
    border: 1px solid #3a3a3a;
    border-radius: 3px;
    padding: 4px 10px;
    min-width: 280px;
}
QComboBox:hover         { border-color: #555; }
QComboBox::drop-down    { border: none; width: 20px; }
QComboBox QAbstractItemView {
    background: #222;
    color: #ccc;
    border: 1px solid #3a3a3a;
    selection-background-color: #3d5a80;
}

/* ── Tab bar ─────────────────────────────────────────────────── */
QTabWidget::pane { border: none; }
QTabBar {
    background: #1b1b1b;
}
QTabBar::tab {
    background: transparent;
    color: #777;
    padding: 7px 18px;
    border: none;
    border-bottom: 2px solid transparent;
}
QTabBar::tab:hover    { color: #bbb; }
QTabBar::tab:selected { color: #ddd; border-bottom: 2px solid #5a9ecf; }

/* ── Dock ────────────────────────────────────────────────────── */
QDockWidget {
    color: #aaa;
    titlebar-close-icon: none;
}
QDockWidget::title {
    background: #1b1b1b;
    padding: 6px 10px;
    border-bottom: 1px solid #2a2a2a;
    font-weight: bold;
}

/* ── Trees & Tables ──────────────────────────────────────────── */
QTreeWidget, QTableWidget {
    background: #141414;
    alternate-background-color: #181818;
    color: #bbb;
    border: none;
    gridline-color: #222;
    outline: none;
}
QTreeWidget::item, QTableWidget::item {
    padding: 3px 6px;
}
QTreeWidget::item:selected, QTableWidget::item:selected {
    background: #1a3a56;
    color: #ddd;
}
QTreeWidget::item:hover, QTableWidget::item:hover {
    background: #1e1e1e;
}
QHeaderView::section {
    background: #1b1b1b;
    color: #777;
    border: none;
    border-right: 1px solid #2a2a2a;
    border-bottom: 1px solid #2a2a2a;
    padding: 5px 8px;
    font-weight: normal;
}
QTreeWidget::branch { background: #141414; }
QTreeWidget::branch:has-children:!has-siblings:closed,
QTreeWidget::branch:closed:has-children:has-siblings {
    image: none;
    border-image: none;
}

/* ── Text edit (header info) ─────────────────────────────────── */
QTextEdit {
    background: #141414;
    color: #bbb;
    border: none;
    selection-background-color: #1a3a56;
    font-family: "Monospace", monospace;
    font-size: 12px;
}

/* ── Line edit (filter) ──────────────────────────────────────── */
QLineEdit {
    background: #1e1e1e;
    color: #ccc;
    border: 1px solid #333;
    border-radius: 3px;
    padding: 5px 8px;
    selection-background-color: #3d5a80;
}
QLineEdit:focus { border-color: #5a9ecf; }

/* ── Scrollbars ──────────────────────────────────────────────── */
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #3a3a3a;
    min-height: 30px;
    border-radius: 5px;
    margin: 2px;
}
QScrollBar::handle:vertical:hover { background: #555; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }

QScrollBar:horizontal {
    background: transparent;
    height: 10px;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background: #3a3a3a;
    min-width: 30px;
    border-radius: 5px;
    margin: 2px;
}
QScrollBar::handle:horizontal:hover { background: #555; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }

/* ── Status bar ──────────────────────────────────────────────── */
QStatusBar {
    background: #0e639c;
    color: #fff;
    border: none;
    font-size: 12px;
}
QStatusBar QLabel {
    color: #fff;
    padding: 0 8px;
}
)";

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("dis");
    resize(1400, 900);

    // Set dark palette as base, then layer stylesheet on top
    QPalette pal;
    pal.setColor(QPalette::Window,          QColor(0x18, 0x18, 0x18));
    pal.setColor(QPalette::WindowText,      QColor(0xCC, 0xCC, 0xCC));
    pal.setColor(QPalette::Base,            QColor(0x14, 0x14, 0x14));
    pal.setColor(QPalette::AlternateBase,   QColor(0x18, 0x18, 0x18));
    pal.setColor(QPalette::Text,            QColor(0xCC, 0xCC, 0xCC));
    pal.setColor(QPalette::Button,          QColor(0x25, 0x25, 0x25));
    pal.setColor(QPalette::ButtonText,      QColor(0xCC, 0xCC, 0xCC));
    pal.setColor(QPalette::Highlight,       QColor(0x1A, 0x3A, 0x56));
    pal.setColor(QPalette::HighlightedText, QColor(0xFF, 0xFF, 0xFF));
    QApplication::setPalette(pal);
    qApp->setStyleSheet(kStyleSheet);

    // Central: tabs for Disasm + Hex
    m_centralTabs = new QTabWidget;
    m_disasmWidget = new DisasmWidget;
    m_hexWidget = new HexWidget;
    m_centralTabs->addTab(m_disasmWidget, "Disassembly");
    m_centralTabs->addTab(m_hexWidget, "Hex Editor");
    setCentralWidget(m_centralTabs);

    // Info dock on the left
    m_infoWidget = new InfoWidget;
    auto *dock = new QDockWidget("Inspector", this);
    dock->setWidget(m_infoWidget);
    dock->setMinimumWidth(400);
    addDockWidget(Qt::LeftDockWidgetArea, dock);

    createMenus();
    createStatusBar();

    // ── Wire signals ────────────────────────────────────────────────
    connect(m_hexWidget, &HexWidget::offsetChanged, this, [this](int64_t off) {
        m_statusOffset->setText(QString("Offset: 0x%1").arg((uint32_t)off, 8, 16, QChar('0')).toUpper());
        int64_t addr = m_macho ? m_macho->addressForFileOffset(off) : -1;
        m_statusAddr->setText(addr >= 0
            ? QString("VM: 0x%1").arg((uint32_t)addr, 8, 16, QChar('0')).toUpper()
            : QString("VM: ---"));
    });

    connect(m_disasmWidget, &DisasmWidget::addressChanged, this, [this](uint32_t addr) {
        m_statusAddr->setText(QString("VM: 0x%1").arg(addr, 8, 16, QChar('0')).toUpper());
        int64_t off = m_macho ? m_macho->fileOffsetForAddress(addr) : -1;
        if (off >= 0)
            m_statusOffset->setText(QString("Offset: 0x%1").arg((uint32_t)off, 8, 16, QChar('0')).toUpper());
    });

    connect(m_disasmWidget, &DisasmWidget::goToHexOffset, this, [this](int64_t off) {
        m_hexWidget->goToOffset(off);
        m_centralTabs->setCurrentWidget(m_hexWidget);
    });

    connect(m_disasmWidget, &DisasmWidget::statusMessage, this, [this](const QString &msg) {
        m_statusInfo->setText(msg);
    });

    connect(m_infoWidget, &InfoWidget::sectionSelected, this,
        [this](uint32_t fileoff, uint32_t size, uint32_t vmaddr, const QString &name) {
            m_hexWidget->goToOffset(fileoff);
            m_hexWidget->setHighlight(fileoff, size);
            if (name.contains("text", Qt::CaseInsensitive) ||
                name.contains("stub", Qt::CaseInsensitive)) {
                for (auto &seg : m_macho->segments())
                    for (auto &sec : seg.sections)
                        if (sec.addr == vmaddr && sec.offset == fileoff) {
                            m_disasmWidget->disassembleSection(sec);
                            m_centralTabs->setCurrentWidget(m_disasmWidget);
                            return;
                        }
            }
        });

    connect(m_infoWidget, &InfoWidget::symbolSelected, this, [this](uint32_t addr) {
        m_disasmWidget->goToAddress(addr);
        m_centralTabs->setCurrentWidget(m_disasmWidget);
        int64_t off = m_macho ? m_macho->fileOffsetForAddress(addr) : -1;
        if (off >= 0) m_hexWidget->goToOffset(off);
    });

    connect(m_infoWidget, &InfoWidget::goToAddress, this, [this](uint32_t addr) {
        m_disasmWidget->goToAddress(addr);
        m_centralTabs->setCurrentWidget(m_disasmWidget);
    });
}

void MainWindow::createMenus() {
    auto *fileMenu = menuBar()->addMenu("&File");
    auto *openAct = fileMenu->addAction("&Open...");
    openAct->setShortcut(QKeySequence::Open);
    connect(openAct, &QAction::triggered, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Open Mach-O Binary", "", "All Files (*)");
        if (!path.isEmpty()) loadFile(path);
    });
    fileMenu->addSeparator();
    auto *quitAct = fileMenu->addAction("&Quit");
    quitAct->setShortcut(QKeySequence::Quit);
    connect(quitAct, &QAction::triggered, this, &QWidget::close);

    auto *navMenu = menuBar()->addMenu("&Navigate");
    auto *goAddrAct = navMenu->addAction("Go to &Address...");
    goAddrAct->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_G));
    connect(goAddrAct, &QAction::triggered, this, [this]() {
        bool ok;
        QString text = QInputDialog::getText(this, "Go to Address", "Virtual address (hex):", QLineEdit::Normal, "", &ok);
        if (ok && !text.isEmpty()) {
            bool c; uint32_t addr = text.toUInt(&c, 16);
            if (c) { m_disasmWidget->goToAddress(addr);
                int64_t off = m_macho ? m_macho->fileOffsetForAddress(addr) : -1;
                if (off >= 0) m_hexWidget->goToOffset(off); }
        }
    });
    auto *goOffAct = navMenu->addAction("Go to &Offset...");
    goOffAct->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_G));
    connect(goOffAct, &QAction::triggered, this, [this]() {
        bool ok;
        QString text = QInputDialog::getText(this, "Go to Offset", "File offset (hex):", QLineEdit::Normal, "", &ok);
        if (ok && !text.isEmpty()) { bool c; int64_t off = text.toLongLong(&c, 16); if (c) m_hexWidget->goToOffset(off); }
    });
    navMenu->addSeparator();
    auto *entryAct = navMenu->addAction("Go to &Entry Point");
    entryAct->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_E));
    connect(entryAct, &QAction::triggered, this, [this]() {
        if (m_macho) { m_disasmWidget->goToAddress(m_macho->entryPoint()); m_centralTabs->setCurrentWidget(m_disasmWidget); }
    });

    auto *viewMenu = menuBar()->addMenu("&View");
    auto *disasmAct = viewMenu->addAction("&Disassembly");
    disasmAct->setShortcut(QKeySequence(Qt::Key_1));
    connect(disasmAct, &QAction::triggered, this, [this]() { m_centralTabs->setCurrentWidget(m_disasmWidget); });
    auto *hexAct = viewMenu->addAction("&Hex Editor");
    hexAct->setShortcut(QKeySequence(Qt::Key_2));
    connect(hexAct, &QAction::triggered, this, [this]() { m_centralTabs->setCurrentWidget(m_hexWidget); });

    // Toolbar
    auto *toolbar = addToolBar("Sections");
    toolbar->setMovable(false);
    toolbar->addWidget(new QLabel("Section:"));
    m_sectionCombo = new QComboBox;
    toolbar->addWidget(m_sectionCombo);

    connect(m_sectionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int) { disassembleCurrentSection(); });
}

void MainWindow::createStatusBar() {
    m_statusOffset = new QLabel("Offset: ---");
    m_statusAddr   = new QLabel("VM: ---");
    m_statusInfo   = new QLabel("Ready");
    statusBar()->addWidget(m_statusOffset);
    statusBar()->addWidget(m_statusAddr);
    statusBar()->addPermanentWidget(m_statusInfo);
}

void MainWindow::loadFile(const QString &path) {
    m_macho = std::make_unique<MachOFile>();
    if (!m_macho->load(path.toStdString())) {
        QMessageBox::critical(this, "Error", "Failed to load Mach-O file.\nMake sure it's a valid Mach-O i386 binary.");
        m_macho.reset();
        return;
    }

    setWindowTitle(QString("dis  |  %1").arg(QFileInfo(path).fileName()));
    m_hexWidget->setData(m_macho->data(), m_macho->size());
    m_disasmWidget->setMachO(m_macho.get());
    m_infoWidget->setMachO(m_macho.get());
    populateSectionCombo();
    m_statusInfo->setText(QString("%1  |  %2 KB  |  Mach-O i386")
        .arg(QFileInfo(path).fileName()).arg(m_macho->size() / 1024));
}

void MainWindow::populateSectionCombo() {
    m_sectionCombo->blockSignals(true);
    m_sectionCombo->clear();
    m_codeSections.clear();

    for (auto &seg : m_macho->segments()) {
        for (auto &sec : seg.sections) {
            bool isCode = (sec.flags & 0x80000000) || (sec.flags & 0x00000400) ||
                          ((sec.flags & 0xFF) == 0 && sec.sectname.find("text") != std::string::npos);
            if (isCode && sec.size > 0) {
                m_codeSections.push_back(&sec);
                m_sectionCombo->addItem(
                    QString("%1,%2  (0x%3  %4 bytes)")
                        .arg(QString::fromStdString(sec.segname))
                        .arg(QString::fromStdString(sec.sectname))
                        .arg(sec.addr, 8, 16, QChar('0'))
                        .arg(sec.size));
            }
        }
    }
    m_sectionCombo->blockSignals(false);

    for (int i = 0; i < (int)m_codeSections.size(); ++i) {
        if (m_codeSections[i]->sectname == "__text" && m_codeSections[i]->segname == "__TEXT") {
            m_sectionCombo->setCurrentIndex(i);
            disassembleCurrentSection();
            break;
        }
    }
}

void MainWindow::disassembleCurrentSection() {
    int idx = m_sectionCombo->currentIndex();
    if (idx < 0 || idx >= (int)m_codeSections.size()) return;
    m_disasmWidget->disassembleSection(*m_codeSections[idx]);
    if (m_macho) {
        uint32_t ep = m_macho->entryPoint();
        auto &sec = *m_codeSections[idx];
        if (ep >= sec.addr && ep < sec.addr + sec.size)
            m_disasmWidget->goToAddress(ep);
    }
}
