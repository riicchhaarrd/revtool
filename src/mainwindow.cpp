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

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("dis — Mach-O Disassembler");
    resize(1400, 900);

    // Dark palette
    QPalette pal;
    pal.setColor(QPalette::Window,          QColor(0x1E, 0x1E, 0x2E));
    pal.setColor(QPalette::WindowText,      QColor(0xCD, 0xD6, 0xF4));
    pal.setColor(QPalette::Base,            QColor(0x18, 0x18, 0x25));
    pal.setColor(QPalette::AlternateBase,   QColor(0x20, 0x20, 0x30));
    pal.setColor(QPalette::Text,            QColor(0xCD, 0xD6, 0xF4));
    pal.setColor(QPalette::Button,          QColor(0x2A, 0x2A, 0x3A));
    pal.setColor(QPalette::ButtonText,      QColor(0xCD, 0xD6, 0xF4));
    pal.setColor(QPalette::Highlight,       QColor(0x45, 0x47, 0x5A));
    pal.setColor(QPalette::HighlightedText, QColor(0xFF, 0xFF, 0xFF));
    pal.setColor(QPalette::ToolTipBase,     QColor(0x30, 0x30, 0x40));
    pal.setColor(QPalette::ToolTipText,     QColor(0xCD, 0xD6, 0xF4));
    QApplication::setPalette(pal);

    setStyleSheet(
        "QMainWindow { background: #1e1e2e; }"
        "QTabWidget::pane { border: 1px solid #313244; }"
        "QTabBar::tab { background: #2a2a3a; color: #cdd6f4; padding: 6px 14px; }"
        "QTabBar::tab:selected { background: #45475a; }"
        "QHeaderView::section { background: #2a2a3a; color: #cdd6f4; padding: 3px; border: 1px solid #313244; }"
        "QTreeWidget, QTableWidget, QTextEdit { background: #181825; color: #cdd6f4; border: 1px solid #313244; }"
        "QLineEdit { background: #1e1e2e; color: #cdd6f4; border: 1px solid #45475a; padding: 3px; }"
        "QComboBox { background: #2a2a3a; color: #cdd6f4; border: 1px solid #45475a; padding: 3px 8px; }"
        "QComboBox QAbstractItemView { background: #1e1e2e; color: #cdd6f4; }"
        "QMenuBar { background: #1e1e2e; color: #cdd6f4; }"
        "QMenuBar::item:selected { background: #45475a; }"
        "QMenu { background: #1e1e2e; color: #cdd6f4; border: 1px solid #313244; }"
        "QMenu::item:selected { background: #45475a; }"
        "QToolBar { background: #1e1e2e; border: none; spacing: 4px; }"
        "QStatusBar { background: #181825; color: #a6adc8; }"
        "QDockWidget { color: #cdd6f4; }"
        "QDockWidget::title { background: #2a2a3a; padding: 4px; }"
        "QScrollBar:vertical { background: #181825; width: 12px; }"
        "QScrollBar::handle:vertical { background: #45475a; min-height: 20px; border-radius: 4px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }"
        "QScrollBar:horizontal { background: #181825; height: 12px; }"
        "QScrollBar::handle:horizontal { background: #45475a; min-width: 20px; border-radius: 4px; }"
        "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }"
    );

    // Central widget: tabs for Disasm and Hex
    m_centralTabs = new QTabWidget;
    m_disasmWidget = new DisasmWidget;
    m_hexWidget = new HexWidget;
    m_centralTabs->addTab(m_disasmWidget, "Disassembly");
    m_centralTabs->addTab(m_hexWidget, "Hex Editor");
    setCentralWidget(m_centralTabs);

    // Info dock
    m_infoWidget = new InfoWidget;
    auto *dock = new QDockWidget("Info", this);
    dock->setWidget(m_infoWidget);
    dock->setMinimumWidth(380);
    addDockWidget(Qt::LeftDockWidgetArea, dock);

    createMenus();
    createStatusBar();

    // Wire signals
    connect(m_hexWidget, &HexWidget::offsetChanged, this, [this](int64_t off) {
        m_statusOffset->setText(QString("  Offset: 0x%1").arg((uint32_t)off, 8, 16, QChar('0')).toUpper());
        int64_t addr = m_macho ? m_macho->addressForFileOffset(off) : -1;
        if (addr >= 0)
            m_statusAddr->setText(QString("  Addr: 0x%1").arg((uint32_t)addr, 8, 16, QChar('0')).toUpper());
        else
            m_statusAddr->setText("  Addr: N/A");
    });

    connect(m_disasmWidget, &DisasmWidget::addressChanged, this, [this](uint32_t addr) {
        m_statusAddr->setText(QString("  Addr: 0x%1").arg(addr, 8, 16, QChar('0')).toUpper());
        int64_t off = m_macho ? m_macho->fileOffsetForAddress(addr) : -1;
        if (off >= 0)
            m_statusOffset->setText(QString("  Offset: 0x%1").arg((uint32_t)off, 8, 16, QChar('0')).toUpper());
    });

    connect(m_disasmWidget, &DisasmWidget::goToHexOffset, this, [this](int64_t off) {
        m_hexWidget->goToOffset(off);
        m_centralTabs->setCurrentWidget(m_hexWidget);
    });

    connect(m_disasmWidget, &DisasmWidget::statusMessage, this, [this](const QString &msg) {
        m_statusInfo->setText("  " + msg);
    });

    connect(m_infoWidget, &InfoWidget::sectionSelected, this,
        [this](uint32_t fileoff, uint32_t size, uint32_t vmaddr, const QString &name) {
            m_hexWidget->goToOffset(fileoff);
            m_hexWidget->setHighlight(fileoff, size);

            // Check if this is a code section
            if (name.contains("text", Qt::CaseInsensitive) ||
                name.contains("stub", Qt::CaseInsensitive)) {
                // Find and disassemble this section
                for (auto &seg : m_macho->segments()) {
                    for (auto &sec : seg.sections) {
                        if (sec.addr == vmaddr && sec.offset == fileoff) {
                            m_disasmWidget->disassembleSection(sec);
                            m_centralTabs->setCurrentWidget(m_disasmWidget);
                            return;
                        }
                    }
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
    // File menu
    auto *fileMenu = menuBar()->addMenu("&File");

    auto *openAct = fileMenu->addAction("&Open...");
    openAct->setShortcut(QKeySequence::Open);
    connect(openAct, &QAction::triggered, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Open Mach-O Binary", "",
            "All Files (*)");
        if (!path.isEmpty()) loadFile(path);
    });

    fileMenu->addSeparator();
    auto *quitAct = fileMenu->addAction("&Quit");
    quitAct->setShortcut(QKeySequence::Quit);
    connect(quitAct, &QAction::triggered, this, &QWidget::close);

    // Navigate menu
    auto *navMenu = menuBar()->addMenu("&Navigate");

    auto *goAddrAct = navMenu->addAction("Go to &Address...");
    goAddrAct->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_G));
    connect(goAddrAct, &QAction::triggered, this, [this]() {
        bool ok;
        QString text = QInputDialog::getText(this, "Go to Address",
            "Virtual address (hex):", QLineEdit::Normal, "", &ok);
        if (ok && !text.isEmpty()) {
            bool convOk;
            uint32_t addr = text.toUInt(&convOk, 16);
            if (convOk) {
                m_disasmWidget->goToAddress(addr);
                int64_t off = m_macho ? m_macho->fileOffsetForAddress(addr) : -1;
                if (off >= 0) m_hexWidget->goToOffset(off);
            }
        }
    });

    auto *goOffAct = navMenu->addAction("Go to &Offset...");
    goOffAct->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_G));
    connect(goOffAct, &QAction::triggered, this, [this]() {
        bool ok;
        QString text = QInputDialog::getText(this, "Go to Offset",
            "File offset (hex):", QLineEdit::Normal, "", &ok);
        if (ok && !text.isEmpty()) {
            bool convOk;
            int64_t off = text.toLongLong(&convOk, 16);
            if (convOk) m_hexWidget->goToOffset(off);
        }
    });

    navMenu->addSeparator();
    auto *entryAct = navMenu->addAction("Go to &Entry Point");
    entryAct->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_E));
    connect(entryAct, &QAction::triggered, this, [this]() {
        if (m_macho) {
            m_disasmWidget->goToAddress(m_macho->entryPoint());
            m_centralTabs->setCurrentWidget(m_disasmWidget);
        }
    });

    // View menu
    auto *viewMenu = menuBar()->addMenu("&View");
    auto *disasmAct = viewMenu->addAction("&Disassembly");
    disasmAct->setShortcut(QKeySequence(Qt::Key_1));
    connect(disasmAct, &QAction::triggered, this, [this]() {
        m_centralTabs->setCurrentWidget(m_disasmWidget);
    });
    auto *hexAct = viewMenu->addAction("&Hex Editor");
    hexAct->setShortcut(QKeySequence(Qt::Key_2));
    connect(hexAct, &QAction::triggered, this, [this]() {
        m_centralTabs->setCurrentWidget(m_hexWidget);
    });

    // Disasm section selector in toolbar
    auto *toolbar = addToolBar("Sections");
    toolbar->addWidget(new QLabel("  Section: "));
    m_sectionCombo = new QComboBox;
    m_sectionCombo->setMinimumWidth(200);
    toolbar->addWidget(m_sectionCombo);

    connect(m_sectionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int) { disassembleCurrentSection(); });
}

void MainWindow::createStatusBar() {
    m_statusOffset = new QLabel("  Offset: 0x00000000");
    m_statusAddr   = new QLabel("  Addr: 0x00000000");
    m_statusInfo   = new QLabel;
    statusBar()->addWidget(m_statusOffset);
    statusBar()->addWidget(m_statusAddr);
    statusBar()->addPermanentWidget(m_statusInfo);
}

void MainWindow::loadFile(const QString &path) {
    m_macho = std::make_unique<MachOFile>();
    if (!m_macho->load(path.toStdString())) {
        QMessageBox::critical(this, "Error",
            "Failed to load Mach-O file.\nMake sure it's a valid Mach-O i386 binary.");
        m_macho.reset();
        return;
    }

    setWindowTitle(QString("dis — %1").arg(path));

    // Set up hex view with raw file data
    m_hexWidget->setData(m_macho->data(), m_macho->size());

    // Set up disassembler
    m_disasmWidget->setMachO(m_macho.get());

    // Set up info panel
    m_infoWidget->setMachO(m_macho.get());

    // Populate section combo with code sections
    populateSectionCombo();

    m_statusInfo->setText(QString("  Loaded: %1 (%2 KB)")
        .arg(path).arg(m_macho->size() / 1024));
}

void MainWindow::populateSectionCombo() {
    m_sectionCombo->blockSignals(true);
    m_sectionCombo->clear();
    m_codeSections.clear();

    for (auto &seg : m_macho->segments()) {
        for (auto &sec : seg.sections) {
            // Include code-like sections
            uint32_t stype = sec.flags & 0xFF;
            bool isCode = (stype == 0 && sec.sectname.find("text") != std::string::npos) ||
                          (sec.flags & 0x80000000) || // S_ATTR_PURE_INSTRUCTIONS
                          (sec.flags & 0x00000400);   // S_ATTR_SOME_INSTRUCTIONS
            if (isCode && sec.size > 0) {
                m_codeSections.push_back(&sec);
                m_sectionCombo->addItem(
                    QString("%1,%2 (0x%3, %4 bytes)")
                        .arg(QString::fromStdString(sec.segname))
                        .arg(QString::fromStdString(sec.sectname))
                        .arg(sec.addr, 8, 16, QChar('0'))
                        .arg(sec.size));
            }
        }
    }
    m_sectionCombo->blockSignals(false);

    // Auto-select __TEXT,__text
    for (int i = 0; i < (int)m_codeSections.size(); ++i) {
        if (m_codeSections[i]->sectname == "__text" &&
            m_codeSections[i]->segname == "__TEXT") {
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

    // Navigate to entry point if in this section
    if (m_macho) {
        uint32_t ep = m_macho->entryPoint();
        auto &sec = *m_codeSections[idx];
        if (ep >= sec.addr && ep < sec.addr + sec.size)
            m_disasmWidget->goToAddress(ep);
    }
}
