#include "mainwindow.h"
#include "decompiler.h"
#include "csyntax.h"

#include <QMenuBar>
#include <QMenu>
#include <QToolBar>
#include <QStatusBar>
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QApplication>
#include <QSplitter>
#include <QFileInfo>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("dis");
    resize(1400, 900);

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

    // Decompile dock on the right (hidden by default)
    m_decompView = new QTextEdit;
    m_decompView->setReadOnly(true);
    m_decompView->setFont(QFont("Monospace", 11));
    m_cHighlight = new CSyntaxHighlighter(m_decompView->document());
    m_decompDock = new QDockWidget("Pseudo-C", this);
    m_decompDock->setWidget(m_decompView);
    m_decompDock->setMinimumWidth(380);
    addDockWidget(Qt::RightDockWidgetArea, m_decompDock);
    m_decompDock->hide();

    createMenus();
    createStatusBar();

    // Apply dark theme by default
    applyTheme(true);

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

    connect(m_disasmWidget, &DisasmWidget::decompileRequested, this, &MainWindow::decompileFunction);

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
            if (name.contains("text", Qt::CaseInsensitive) || name.contains("stub", Qt::CaseInsensitive)) {
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

void MainWindow::applyTheme(bool dark) {
    m_darkTheme = dark;
    Theme t = dark ? darkTheme() : lightTheme();

    // QPalette base
    QPalette pal;
    pal.setColor(QPalette::Window,          t.bg);
    pal.setColor(QPalette::WindowText,      dark ? QColor(0xCC,0xCC,0xCC) : QColor(0x1E,0x1E,0x1E));
    pal.setColor(QPalette::Base,            t.bg);
    pal.setColor(QPalette::AlternateBase,   t.bgAlt);
    pal.setColor(QPalette::Text,            dark ? QColor(0xCC,0xCC,0xCC) : QColor(0x1E,0x1E,0x1E));
    pal.setColor(QPalette::Button,          t.headerBg);
    pal.setColor(QPalette::ButtonText,      dark ? QColor(0xCC,0xCC,0xCC) : QColor(0x1E,0x1E,0x1E));
    pal.setColor(QPalette::Highlight,       t.selection);
    pal.setColor(QPalette::HighlightedText, QColor(0xFF,0xFF,0xFF));
    QApplication::setPalette(pal);

    // Stylesheet
    qApp->setStyleSheet(dark ? darkStyleSheet() : lightStyleSheet());

    // Push theme to custom widgets
    m_hexWidget->setTheme(t);
    m_disasmWidget->setTheme(t);

    // Decompile view colors + highlighter
    if (m_decompView) {
        m_decompView->setStyleSheet(dark
            ? "QTextEdit { background: #1e1e1e; color: #d4d4d4; border: none; font-family: Monospace; font-size: 12px; }"
            : "QTextEdit { background: #fff; color: #1e1e1e; border: none; font-family: Monospace; font-size: 12px; }");
    }
    if (m_cHighlight) m_cHighlight->setDark(dark);

    // Update toggle text
    if (m_themeToggle)
        m_themeToggle->setText(dark ? "Switch to &Light Theme" : "Switch to &Dark Theme");
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

    // Navigate
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

    // View
    auto *viewMenu = menuBar()->addMenu("&View");
    auto *disasmAct = viewMenu->addAction("&Disassembly");
    disasmAct->setShortcut(QKeySequence(Qt::Key_1));
    connect(disasmAct, &QAction::triggered, this, [this]() { m_centralTabs->setCurrentWidget(m_disasmWidget); });
    auto *hexAct = viewMenu->addAction("&Hex Editor");
    hexAct->setShortcut(QKeySequence(Qt::Key_2));
    connect(hexAct, &QAction::triggered, this, [this]() { m_centralTabs->setCurrentWidget(m_hexWidget); });

    viewMenu->addSeparator();
    m_themeToggle = viewMenu->addAction("Switch to &Light Theme");
    m_themeToggle->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_T));
    connect(m_themeToggle, &QAction::triggered, this, [this]() {
        applyTheme(!m_darkTheme);
    });

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
        m_macho.reset(); return;
    }
    setWindowTitle(QString("dis  |  %1").arg(QFileInfo(path).fileName()));
    m_hexWidget->setData(m_macho->data(), m_macho->size());
    m_disasmWidget->setMachO(m_macho.get());
    m_infoWidget->setMachO(m_macho.get());
    populateSectionCombo();
    m_statusInfo->setText(QString("%1  |  %2 KB  |  Mach-O i386").arg(QFileInfo(path).fileName()).arg(m_macho->size() / 1024));
}

void MainWindow::populateSectionCombo() {
    m_sectionCombo->blockSignals(true);
    m_sectionCombo->clear();
    m_codeSections.clear();
    for (auto &seg : m_macho->segments())
        for (auto &sec : seg.sections) {
            bool isCode = (sec.flags & 0x80000000) || (sec.flags & 0x00000400) ||
                          ((sec.flags & 0xFF) == 0 && sec.sectname.find("text") != std::string::npos);
            if (isCode && sec.size > 0) {
                m_codeSections.push_back(&sec);
                m_sectionCombo->addItem(QString("%1,%2  (0x%3  %4 bytes)")
                    .arg(QString::fromStdString(sec.segname)).arg(QString::fromStdString(sec.sectname))
                    .arg(sec.addr, 8, 16, QChar('0')).arg(sec.size));
            }
        }
    m_sectionCombo->blockSignals(false);
    for (int i = 0; i < (int)m_codeSections.size(); ++i)
        if (m_codeSections[i]->sectname == "__text" && m_codeSections[i]->segname == "__TEXT") {
            m_sectionCombo->setCurrentIndex(i); disassembleCurrentSection(); break;
        }
}

void MainWindow::disassembleCurrentSection() {
    int idx = m_sectionCombo->currentIndex();
    if (idx < 0 || idx >= (int)m_codeSections.size()) return;
    m_disasmWidget->disassembleSection(*m_codeSections[idx]);
    if (m_macho) {
        uint32_t ep = m_macho->entryPoint();
        auto &sec = *m_codeSections[idx];
        if (ep >= sec.addr && ep < sec.addr + sec.size) m_disasmWidget->goToAddress(ep);
    }
}

void MainWindow::decompileFunction(uint32_t addr) {
    if (!m_macho) return;
    QString code = PseudoDecompiler::decompile(*m_macho, addr);
    m_decompView->setPlainText(code);
    m_decompDock->show();
    m_decompDock->raise();
}
