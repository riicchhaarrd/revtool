#include "infowidget.h"
#include "demangle.h"
#include <QRegularExpression>
#include <algorithm>
#include <set>

static QString hex32(uint32_t v) {
    return QString("0x%1").arg(v, 8, 16, QChar('0')).toUpper();
}

static void setupTable(QTableWidget *t) {
    t->setAlternatingRowColors(true);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->verticalHeader()->setDefaultSectionSize(22);
    t->horizontalHeader()->setStretchLastSection(true);
    t->setSortingEnabled(false);
}

// Classify a symbol into a human-readable kind
static QString classifySymbol(const NList &sym, const MachOFile *mf) {
    uint8_t ntype = sym.n_type & N_TYPE;
    if (ntype == N_UNDF) return "Import";
    if (ntype == N_ABS) return "Absolute";
    if (ntype == N_INDR) return "Indirect";
    if (ntype == N_SECT && sym.n_sect > 0) {
        auto secs = mf->allSections();
        int idx = sym.n_sect - 1; // 1-based
        if (idx >= 0 && idx < (int)secs.size()) {
            auto &sn = secs[idx]->sectname;
            auto &sg = secs[idx]->segname;
            if (sn == "__text" || sn == "__textcoal_nt") return "Function";
            if (sn.find("stub") != std::string::npos) return "Stub";
            if (sg == "__DATA" || sg == "__IMPORT") return "Data";
            if (sn == "__const" || sn == "__literal4" || sn == "__literal8" || sn == "__cstring")
                return "Const";
        }
        return "Symbol";
    }
    return "Other";
}

InfoWidget::InfoWidget(QWidget *parent) : QTabWidget(parent) {
    // Header tab
    m_headerInfo = new QTextEdit;
    m_headerInfo->setReadOnly(true);
    m_headerInfo->setFont(QFont("Monospace", 10));
    addTab(m_headerInfo, "Header");

    // Load Commands tab
    m_lcTable = new QTableWidget;
    addTab(m_lcTable, "Load Cmds");

    // Segments tab
    m_segTree = new QTreeWidget;
    m_segTree->setHeaderLabels({"Name", "VM Addr", "VM Size", "File Off", "File Size", "Flags"});
    m_segTree->setAlternatingRowColors(true);
    addTab(m_segTree, "Segments");

    // Source Tree tab
    {
        auto *w = new QWidget;
        auto *lay = new QVBoxLayout(w);
        lay->setContentsMargins(0,0,0,0);
        lay->setSpacing(2);

        // Toolbar row: filter + expand/collapse
        auto *toolbar = new QHBoxLayout;
        toolbar->setContentsMargins(4,4,4,2);
        m_srcFilter = new QLineEdit;
        m_srcFilter->setPlaceholderText("Filter...");
        toolbar->addWidget(m_srcFilter, 1);
        auto *expandBtn = new QPushButton("Expand All");
        expandBtn->setFixedWidth(80);
        auto *collapseBtn = new QPushButton("Collapse All");
        collapseBtn->setFixedWidth(85);
        toolbar->addWidget(expandBtn);
        toolbar->addWidget(collapseBtn);
        lay->addLayout(toolbar);

        m_sourceTree = new QTreeWidget;
        m_sourceTree->setHeaderLabels({"Name", "Address", "Info"});
        m_sourceTree->setAlternatingRowColors(true);
        m_sourceTree->setIndentation(16);
        m_sourceTree->setContextMenuPolicy(Qt::CustomContextMenu);
        lay->addWidget(m_sourceTree);
        addTab(w, "Source Tree");

        connect(expandBtn, &QPushButton::clicked, m_sourceTree, &QTreeWidget::expandAll);
        connect(collapseBtn, &QPushButton::clicked, m_sourceTree, &QTreeWidget::collapseAll);
    }

    // Functions tab (flat, filterable)
    {
        auto *w = new QWidget;
        auto *lay = new QVBoxLayout(w);
        lay->setContentsMargins(0,0,0,0);
        m_funcFilter = new QLineEdit;
        m_funcFilter->setPlaceholderText("Filter functions...");
        lay->addWidget(m_funcFilter);
        m_funcTable = new QTableWidget;
        lay->addWidget(m_funcTable);
        addTab(w, "Functions");
    }

    // Symbols tab (all non-STABS symbols)
    {
        auto *w = new QWidget;
        auto *lay = new QVBoxLayout(w);
        lay->setContentsMargins(0,0,0,0);

        auto *filterRow = new QHBoxLayout;
        m_symFilter = new QLineEdit;
        m_symFilter->setPlaceholderText("Filter symbols...");
        filterRow->addWidget(m_symFilter, 1);
        m_symKindCombo = new QComboBox;
        m_symKindCombo->addItems({"All", "Function", "Data", "Import", "Stub", "Const", "Other"});
        m_symKindCombo->setMinimumWidth(100);
        filterRow->addWidget(m_symKindCombo);
        lay->addLayout(filterRow);

        m_symTable = new QTableWidget;
        lay->addWidget(m_symTable);
        addTab(w, "Symbols");
    }

    // STABS tab
    m_stabsTree = new QTreeWidget;
    m_stabsTree->setHeaderLabels({"Name", "Address", "Size", "Details"});
    m_stabsTree->setAlternatingRowColors(true);
    addTab(m_stabsTree, "STABS");

    // Dylibs tab
    m_dylibTable = new QTableWidget;
    addTab(m_dylibTable, "Dylibs");
}

void InfoWidget::setMachO(MachOFile *macho) {
    m_macho = macho;
    if (!macho) return;
    buildHeaderTab();
    buildLoadCmdsTab();
    buildSegmentsTab();
    buildSourceTreeTab();
    buildFunctionsTab();
    buildSymbolsTab();
    buildStabsTab();
    buildDylibsTab();
}

void InfoWidget::buildHeaderTab() {
    auto &h = m_macho->header();
    QString info;
    info += QString("Magic:        0x%1\n").arg(h.magic, 8, 16, QChar('0')).toUpper();
    info += QString("CPU Type:     %1 (%2)\n")
                .arg(h.cputype == CPU_TYPE_I386 ? "i386" : "unknown").arg(h.cputype);
    info += QString("CPU Subtype:  %1\n").arg(h.cpusubtype);
    info += QString("File Type:    %1 (%2)\n")
                .arg(MachOFile::fileTypeName(h.filetype)).arg(h.filetype);
    info += QString("Load Cmds:    %1\n").arg(h.ncmds);
    info += QString("Cmds Size:    %1 bytes\n").arg(h.sizeofcmds);
    info += QString("Flags:        %1\n").arg(QString::fromStdString(MachOFile::flagsString(h.flags)));
    info += QString("Entry Point:  %1\n").arg(hex32(m_macho->entryPoint()));
    info += QString("File Size:    %1 bytes (%2 KB)\n").arg(m_macho->size()).arg(m_macho->size() / 1024);
    info += "\n── Segments ──\n";
    for (auto &seg : m_macho->segments()) {
        info += QString("  %-16s  vm=%1  size=%2  file=%3  sections=%4\n")
                    .arg(hex32(seg.vmaddr)).arg(hex32(seg.vmsize))
                    .arg(hex32(seg.fileoff)).arg(seg.nsects);
        info = info.replace("%-16s", QString::fromStdString(seg.segname).leftJustified(16));
    }
    info += QString("\n── Symbols ──\n");
    info += QString("  Total:     %1\n").arg(m_macho->symbols().size());
    int stabsCount = 0;
    for (auto &s : m_macho->symbols()) if (s.n_type & N_STAB) stabsCount++;
    info += QString("  STABS:     %1\n").arg(stabsCount);
    info += QString("  Regular:   %1\n").arg(m_macho->symbols().size() - stabsCount);
    info += QString("  Functions: %1\n").arg(m_macho->stabsFunctions().size());
    info += QString("  Sources:   %1\n").arg(m_macho->stabsSourceFiles().size());
    m_headerInfo->setPlainText(info);
}

void InfoWidget::buildLoadCmdsTab() {
    auto &cmds = m_macho->loadCommands();
    m_lcTable->setColumnCount(4);
    m_lcTable->setHorizontalHeaderLabels({"#", "Command", "Offset", "Size"});
    m_lcTable->setRowCount(cmds.size());
    setupTable(m_lcTable);
    for (int i = 0; i < (int)cmds.size(); ++i) {
        auto &lc = cmds[i];
        m_lcTable->setItem(i, 0, new QTableWidgetItem(QString::number(i)));
        m_lcTable->setItem(i, 1, new QTableWidgetItem(MachOFile::lcName(lc.cmd)));
        m_lcTable->setItem(i, 2, new QTableWidgetItem(hex32(lc.fileOffset)));
        m_lcTable->setItem(i, 3, new QTableWidgetItem(QString::number(lc.cmdsize)));
    }
    m_lcTable->resizeColumnsToContents();
}

void InfoWidget::buildSegmentsTab() {
    m_segTree->clear();
    for (auto &seg : m_macho->segments()) {
        auto *segItem = new QTreeWidgetItem(m_segTree);
        segItem->setText(0, QString::fromStdString(seg.segname));
        segItem->setText(1, hex32(seg.vmaddr));
        segItem->setText(2, hex32(seg.vmsize));
        segItem->setText(3, hex32(seg.fileoff));
        segItem->setText(4, hex32(seg.filesize));
        segItem->setText(5, QString("0x%1").arg(seg.flags, 8, 16, QChar('0')));
        for (auto &sec : seg.sections) {
            auto *secItem = new QTreeWidgetItem(segItem);
            secItem->setText(0, QString::fromStdString(sec.sectname));
            secItem->setText(1, hex32(sec.addr));
            secItem->setText(2, hex32(sec.size));
            secItem->setText(3, hex32(sec.offset));
            secItem->setText(4, hex32(sec.size));
            secItem->setText(5, QString("0x%1").arg(sec.flags, 8, 16, QChar('0')));
            secItem->setData(0, Qt::UserRole, sec.offset);
            secItem->setData(0, Qt::UserRole + 1, sec.size);
            secItem->setData(0, Qt::UserRole + 2, sec.addr);
        }
        segItem->setExpanded(true);
    }
    m_segTree->resizeColumnToContents(0);
    m_segTree->resizeColumnToContents(1);
    connect(m_segTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem *item, int) {
        if (item->parent()) {
            uint32_t foff = item->data(0, Qt::UserRole).toUInt();
            uint32_t sz   = item->data(0, Qt::UserRole + 1).toUInt();
            uint32_t addr = item->data(0, Qt::UserRole + 2).toUInt();
            emit sectionSelected(foff, sz, addr, item->text(0));
        }
    });
}

// ── Source Tree tab ─────────────────────────────────────────────────
// Node types stored in UserRole+10:
//   0 = directory, 1 = source file (UserRole+11 = stabs source index), 2 = function (UserRole = addr)
static const int ROLE_NODE_TYPE = Qt::UserRole + 10;
static const int ROLE_SRC_IDX  = Qt::UserRole + 11;

void InfoWidget::buildSourceTreeTab() {
    m_sourceTree->clear();

    auto splitPath = [](const std::string &path) -> std::vector<std::string> {
        std::vector<std::string> parts;
        std::string cur;
        for (char c : path) {
            if (c == '/') { if (!cur.empty()) parts.push_back(cur); cur.clear(); }
            else cur += c;
        }
        if (!cur.empty()) parts.push_back(cur);
        return parts;
    };

    auto findOrCreate = [](QTreeWidgetItem *parent, const QString &name, int nodeType) -> QTreeWidgetItem* {
        for (int i = 0; i < parent->childCount(); ++i)
            if (parent->child(i)->text(0) == name) return parent->child(i);
        auto *item = new QTreeWidgetItem(parent);
        item->setText(0, name);
        item->setData(0, ROLE_NODE_TYPE, nodeType);
        return item;
    };
    auto findOrCreateRoot = [&](const QString &name, int nodeType) -> QTreeWidgetItem* {
        for (int i = 0; i < m_sourceTree->topLevelItemCount(); ++i)
            if (m_sourceTree->topLevelItem(i)->text(0) == name) return m_sourceTree->topLevelItem(i);
        auto *item = new QTreeWidgetItem(m_sourceTree);
        item->setText(0, name);
        item->setData(0, ROLE_NODE_TYPE, nodeType);
        return item;
    };

    // Resolve full paths
    std::vector<std::string> allPaths;
    for (auto &sf : m_macho->stabsSourceFiles()) {
        QString dir = QString::fromStdString(sf.directory);
        QString fname = QString::fromStdString(sf.filename);
        allPaths.push_back((fname.startsWith(dir) ? fname : dir + fname).toStdString());
    }

    // Common prefix removal
    std::string prefix;
    if (allPaths.size() > 1) {
        auto p0 = splitPath(allPaths[0]);
        for (size_t d = 0; d < p0.size(); ++d) {
            bool ok = true;
            for (size_t j = 1; j < allPaths.size(); ++j) {
                auto pj = splitPath(allPaths[j]);
                if (d >= pj.size() || pj[d] != p0[d]) { ok = false; break; }
            }
            if (ok) prefix += "/" + p0[d]; else break;
        }
    }
    size_t prefixDepth = splitPath(prefix).size();

    // Build tree
    for (size_t si = 0; si < m_macho->stabsSourceFiles().size(); ++si) {
        auto &sf = m_macho->stabsSourceFiles()[si];
        auto parts = splitPath(allPaths[si]);
        std::vector<std::string> rel(parts.begin() + std::min(prefixDepth, parts.size()), parts.end());
        if (rel.empty()) rel.push_back(sf.filename);

        QTreeWidgetItem *parent = nullptr;
        for (size_t d = 0; d < rel.size(); ++d) {
            QString name = QString::fromStdString(rel[d]);
            bool isFile = (d == rel.size() - 1);
            QTreeWidgetItem *node = parent
                ? findOrCreate(parent, name, isFile ? 1 : 0)
                : findOrCreateRoot(name, isFile ? 1 : 0);

            if (isFile) {
                node->setData(0, ROLE_NODE_TYPE, 1);
                node->setData(0, ROLE_SRC_IDX, (int)si);
                int n = (int)sf.functionIndices.size();
                node->setText(2, QString("%1 func%2").arg(n).arg(n != 1 ? "s" : ""));

                for (size_t fi : sf.functionIndices) {
                    auto &fn = m_macho->stabsFunctions()[fi];
                    auto *fi2 = new QTreeWidgetItem(node);
                    fi2->setText(0, QString::fromStdString(fn.name));
                    fi2->setText(1, hex32(fn.address));
                    if (fn.size) fi2->setText(2, QString("%1 B").arg(fn.size));
                    fi2->setData(0, Qt::UserRole, fn.address);
                    fi2->setData(0, ROLE_NODE_TYPE, 2);
                }
            }
            parent = node;
        }
    }

    // [No Source] bucket
    std::set<uint32_t> covered;
    for (auto &sf : m_macho->stabsSourceFiles())
        for (size_t fi : sf.functionIndices)
            covered.insert(m_macho->stabsFunctions()[fi].address);

    auto *noSrc = new QTreeWidgetItem(m_sourceTree);
    noSrc->setText(0, "[No Source]");
    noSrc->setData(0, ROLE_NODE_TYPE, 0);
    int noSrcN = 0;

    for (auto &fn : m_macho->stabsFunctions()) {
        if (fn.sourceFileIdx >= 0) continue;
        auto *it = new QTreeWidgetItem(noSrc);
        it->setText(0, QString::fromStdString(fn.name));
        it->setText(1, hex32(fn.address));
        if (fn.size) it->setText(2, QString("%1 B").arg(fn.size));
        it->setData(0, Qt::UserRole, fn.address);
        it->setData(0, ROLE_NODE_TYPE, 2);
        covered.insert(fn.address);
        noSrcN++;
    }
    auto secs = m_macho->allSections();
    for (auto &sym : m_macho->symbols()) {
        if (sym.n_type & N_STAB) continue;
        if ((sym.n_type & N_TYPE) != N_SECT || sym.n_sect == 0) continue;
        int si = sym.n_sect - 1;
        if (si < 0 || si >= (int)secs.size()) continue;
        if (secs[si]->sectname != "__text" && secs[si]->sectname != "__textcoal_nt") continue;
        if (covered.count(sym.n_value)) continue;
        covered.insert(sym.n_value);
        auto *it = new QTreeWidgetItem(noSrc);
        it->setText(0, QString::fromStdString(demangle(sym.name)));
        it->setText(1, hex32(sym.n_value));
        it->setData(0, Qt::UserRole, sym.n_value);
        it->setData(0, ROLE_NODE_TYPE, 2);
        noSrcN++;
    }
    noSrc->setText(2, QString("%1 funcs").arg(noSrcN));

    // Directory function counts
    std::function<int(QTreeWidgetItem*)> countFn = [&](QTreeWidgetItem *item) -> int {
        int c = 0;
        for (int i = 0; i < item->childCount(); ++i) {
            if (item->child(i)->data(0, ROLE_NODE_TYPE).toInt() == 2) c++;
            else c += countFn(item->child(i));
        }
        if (item->data(0, ROLE_NODE_TYPE).toInt() == 0 && item->text(2).isEmpty())
            item->setText(2, QString("%1 funcs").arg(c));
        return c;
    };
    for (int i = 0; i < m_sourceTree->topLevelItemCount(); ++i)
        countFn(m_sourceTree->topLevelItem(i));

    m_sourceTree->resizeColumnToContents(0);
    m_sourceTree->resizeColumnToContents(1);

    // Start collapsed — user can expand what they want
    m_sourceTree->collapseAll();
    // Expand only top level
    for (int i = 0; i < m_sourceTree->topLevelItemCount(); ++i)
        m_sourceTree->topLevelItem(i)->setExpanded(true);

    // Double-click: function → navigate, file → decompile whole file
    connect(m_sourceTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem *item, int) {
        int nodeType = item->data(0, ROLE_NODE_TYPE).toInt();
        if (nodeType == 2) {
            // Function — navigate to disassembly
            uint32_t addr = item->data(0, Qt::UserRole).toUInt();
            if (addr) emit goToAddress(addr);
        } else if (nodeType == 1) {
            // Source file — decompile entire file
            int srcIdx = item->data(0, ROLE_SRC_IDX).toInt();
            emit decompileFileRequested(srcIdx);
        }
    });

    // Right-click context menu
    connect(m_sourceTree, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        auto *item = m_sourceTree->itemAt(pos);
        if (!item) return;
        int nodeType = item->data(0, ROLE_NODE_TYPE).toInt();
        QMenu menu;

        if (nodeType == 1) {
            auto *decompAct = menu.addAction("Decompile Entire File");
            connect(decompAct, &QAction::triggered, this, [this, item]() {
                emit decompileFileRequested(item->data(0, ROLE_SRC_IDX).toInt());
            });
            menu.addSeparator();
        }
        if (nodeType == 2) {
            auto *navAct = menu.addAction("Go to Disassembly");
            connect(navAct, &QAction::triggered, this, [this, item]() {
                emit goToAddress(item->data(0, Qt::UserRole).toUInt());
            });
            menu.addSeparator();
        }

        auto *expandAct = menu.addAction("Expand");
        connect(expandAct, &QAction::triggered, this, [item]() {
            std::function<void(QTreeWidgetItem*)> expandAll = [&](QTreeWidgetItem *it) {
                it->setExpanded(true);
                for (int i = 0; i < it->childCount(); ++i) expandAll(it->child(i));
            };
            expandAll(item);
        });
        auto *collapseAct = menu.addAction("Collapse");
        connect(collapseAct, &QAction::triggered, this, [item]() {
            std::function<void(QTreeWidgetItem*)> collapseAll = [&](QTreeWidgetItem *it) {
                it->setExpanded(false);
                for (int i = 0; i < it->childCount(); ++i) collapseAll(it->child(i));
            };
            collapseAll(item);
        });

        menu.exec(m_sourceTree->viewport()->mapToGlobal(pos));
    });

    // Filter
    connect(m_srcFilter, &QLineEdit::textChanged, this, [this](const QString &text) {
        QRegularExpression re(text, QRegularExpression::CaseInsensitiveOption);
        bool hasFilter = !text.isEmpty() && re.isValid();
        std::function<bool(QTreeWidgetItem*)> filter = [&](QTreeWidgetItem *item) -> bool {
            bool anyChild = false;
            for (int i = 0; i < item->childCount(); ++i)
                if (filter(item->child(i))) anyChild = true;
            bool self = !hasFilter || re.match(item->text(0)).hasMatch();
            bool vis = self || anyChild;
            item->setHidden(!vis);
            if (vis && hasFilter) item->setExpanded(true);
            return vis;
        };
        for (int i = 0; i < m_sourceTree->topLevelItemCount(); ++i)
            filter(m_sourceTree->topLevelItem(i));
    });
}

// ── Functions tab ───────────────────────────────────────────────────
void InfoWidget::buildFunctionsTab() {
    setupTable(m_funcTable);
    m_funcTable->setColumnCount(4);
    m_funcTable->setHorizontalHeaderLabels({"Name", "Address", "Size", "Source"});

    // Gather all functions: STABS functions + non-STABS code symbols
    struct FuncEntry {
        QString name;
        uint32_t addr;
        uint32_t size;
        QString source;
    };
    std::vector<FuncEntry> funcs;

    // From STABS
    for (auto &fn : m_macho->stabsFunctions()) {
        FuncEntry e;
        e.name = QString::fromStdString(fn.name);
        e.addr = fn.address;
        e.size = fn.size;
        if (fn.sourceFileIdx >= 0 && fn.sourceFileIdx < (int)m_macho->stabsSourceFiles().size())
            e.source = QString::fromStdString(m_macho->stabsSourceFiles()[fn.sourceFileIdx].filename);
        funcs.push_back(std::move(e));
    }

    // From regular symbols in __text that aren't already covered
    std::set<uint32_t> covered;
    for (auto &fn : m_macho->stabsFunctions()) covered.insert(fn.address);
    auto secs = m_macho->allSections();
    for (auto &sym : m_macho->symbols()) {
        if (sym.n_type & N_STAB) continue;
        if ((sym.n_type & N_TYPE) != N_SECT) continue;
        if (sym.n_sect == 0) continue;
        int si = sym.n_sect - 1;
        if (si >= 0 && si < (int)secs.size() &&
            (secs[si]->sectname == "__text" || secs[si]->sectname == "__textcoal_nt")) {
            if (covered.count(sym.n_value)) continue;
            covered.insert(sym.n_value);
            FuncEntry e;
            e.name = QString::fromStdString(demangle(sym.name));
            e.addr = sym.n_value;
            e.size = 0;
            funcs.push_back(std::move(e));
        }
    }

    // Sort by address
    std::sort(funcs.begin(), funcs.end(), [](auto &a, auto &b) { return a.addr < b.addr; });

    auto populateFuncs = [this, funcs](const QString &filter) {
        m_funcTable->setRowCount(0);
        QRegularExpression re(filter, QRegularExpression::CaseInsensitiveOption);
        bool hasFilter = !filter.isEmpty() && re.isValid();
        int row = 0;
        for (auto &f : funcs) {
            if (hasFilter && !re.match(f.name).hasMatch()) continue;
            m_funcTable->insertRow(row);
            m_funcTable->setItem(row, 0, new QTableWidgetItem(f.name));
            m_funcTable->setItem(row, 1, new QTableWidgetItem(hex32(f.addr)));
            m_funcTable->setItem(row, 2, new QTableWidgetItem(
                f.size > 0 ? QString::number(f.size) : ""));
            m_funcTable->setItem(row, 3, new QTableWidgetItem(f.source));
            row++;
        }
    };

    populateFuncs("");

    connect(m_funcFilter, &QLineEdit::textChanged, this, [populateFuncs](const QString &text) {
        populateFuncs(text);
    });

    connect(m_funcTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        auto *item = m_funcTable->item(row, 1);
        if (item) {
            bool ok;
            uint32_t addr = item->text().toUInt(&ok, 16);
            if (ok) emit goToAddress(addr);
        }
    });

    m_funcTable->resizeColumnsToContents();
}

// ── Symbols tab (all non-STABS, with kind filter + demangling) ──────
void InfoWidget::buildSymbolsTab() {
    setupTable(m_symTable);
    m_symTable->setColumnCount(5);
    m_symTable->setHorizontalHeaderLabels({"Name", "Address", "Kind", "Section", "Raw"});

    repopulateSymbols();

    connect(m_symFilter, &QLineEdit::textChanged, this, [this](const QString &) { repopulateSymbols(); });
    connect(m_symKindCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) { repopulateSymbols(); });

    connect(m_symTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        auto *item = m_symTable->item(row, 1);
        if (item) {
            bool ok;
            uint32_t addr = item->text().toUInt(&ok, 16);
            if (ok) emit symbolSelected(addr);
        }
    });
}

void InfoWidget::repopulateSymbols() {
    m_symTable->setRowCount(0);
    QString filter = m_symFilter->text();
    QRegularExpression re(filter, QRegularExpression::CaseInsensitiveOption);
    bool hasFilter = !filter.isEmpty() && re.isValid();
    QString kindFilter = m_symKindCombo->currentText();
    bool filterKind = (kindFilter != "All");

    int row = 0;
    int maxRows = 50000;
    for (auto &sym : m_macho->symbols()) {
        if (row >= maxRows) break;
        if (sym.n_type & N_STAB) continue;

        QString kind = classifySymbol(sym, m_macho);
        if (filterKind && kind != kindFilter) continue;

        QString demangled = QString::fromStdString(demangle(sym.name));
        if (hasFilter && !re.match(demangled).hasMatch()) continue;

        m_symTable->insertRow(row);
        m_symTable->setItem(row, 0, new QTableWidgetItem(demangled));
        m_symTable->setItem(row, 1, new QTableWidgetItem(hex32(sym.n_value)));
        m_symTable->setItem(row, 2, new QTableWidgetItem(kind));
        m_symTable->setItem(row, 3, new QTableWidgetItem(QString::number(sym.n_sect)));

        // Only show raw name if different from demangled
        QString raw = QString::fromStdString(sym.name);
        m_symTable->setItem(row, 4, new QTableWidgetItem(raw != demangled ? raw : ""));
        row++;
    }
    m_symTable->resizeColumnsToContents();
}

// ── STABS tab ───────────────────────────────────────────────────────
void InfoWidget::buildStabsTab() {
    m_stabsTree->clear();

    for (size_t si = 0; si < m_macho->stabsSourceFiles().size(); ++si) {
        auto &sf = m_macho->stabsSourceFiles()[si];
        auto *fileItem = new QTreeWidgetItem(m_stabsTree);
        QString dir = QString::fromStdString(sf.directory);
        QString fname = QString::fromStdString(sf.filename);
        QString path = fname.startsWith(dir) ? fname : dir + fname;
        fileItem->setText(0, path);
        fileItem->setText(1, hex32(sf.address));
        fileItem->setText(3, QString("%1 functions").arg(sf.functionIndices.size()));

        for (size_t fi : sf.functionIndices) {
            auto &fn = m_macho->stabsFunctions()[fi];
            auto *fnItem = new QTreeWidgetItem(fileItem);
            fnItem->setText(0, QString::fromStdString(fn.name));
            fnItem->setText(1, hex32(fn.address));
            fnItem->setText(2, fn.size > 0 ? QString::number(fn.size) + " bytes" : "");
            QString details;
            if (!fn.params.empty()) {
                details += "params: ";
                for (size_t p = 0; p < fn.params.size(); ++p) {
                    if (p) details += ", ";
                    details += QString::fromStdString(fn.params[p]);
                }
            }
            if (!fn.lineMap.empty()) {
                if (!details.isEmpty()) details += " | ";
                details += QString("lines: %1-%2").arg(fn.lineMap.front().second).arg(fn.lineMap.back().second);
            }
            fnItem->setText(3, details);
            fnItem->setData(0, Qt::UserRole, fn.address);
        }
    }

    auto *unattached = new QTreeWidgetItem(m_stabsTree);
    unattached->setText(0, "[No Source File]");
    int count = 0;
    for (auto &fn : m_macho->stabsFunctions()) {
        if (fn.sourceFileIdx >= 0) continue;
        auto *fnItem = new QTreeWidgetItem(unattached);
        fnItem->setText(0, QString::fromStdString(fn.name));
        fnItem->setText(1, hex32(fn.address));
        fnItem->setText(2, fn.size > 0 ? QString::number(fn.size) + " bytes" : "");
        fnItem->setData(0, Qt::UserRole, fn.address);
        count++;
    }
    unattached->setText(3, QString("%1 functions").arg(count));

    auto *summaryItem = new QTreeWidgetItem(m_stabsTree);
    summaryItem->setText(0, "[STABS Summary]");
    std::unordered_map<uint8_t, int> typeCounts;
    for (auto &sym : m_macho->symbols())
        if (sym.n_type & N_STAB) typeCounts[sym.n_type]++;
    std::vector<std::pair<uint8_t, int>> sorted(typeCounts.begin(), typeCounts.end());
    std::sort(sorted.begin(), sorted.end(), [](auto &a, auto &b) { return a.second > b.second; });
    for (auto &[type, cnt] : sorted) {
        auto *ti = new QTreeWidgetItem(summaryItem);
        ti->setText(0, MachOFile::stabsTypeName(type));
        ti->setText(1, QString("0x%1").arg(type, 2, 16, QChar('0')));
        ti->setText(3, QString::number(cnt));
    }

    m_stabsTree->resizeColumnToContents(0);
    m_stabsTree->resizeColumnToContents(1);
    connect(m_stabsTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem *item, int) {
        QVariant v = item->data(0, Qt::UserRole);
        if (v.isValid()) { uint32_t addr = v.toUInt(); if (addr) emit goToAddress(addr); }
    });
}

void InfoWidget::buildDylibsTab() {
    m_dylibTable->setColumnCount(3);
    m_dylibTable->setHorizontalHeaderLabels({"Name", "Current Version", "Compat Version"});
    m_dylibTable->setRowCount(m_macho->dylibs().size());
    setupTable(m_dylibTable);
    for (int i = 0; i < (int)m_macho->dylibs().size(); ++i) {
        auto &dl = m_macho->dylibs()[i];
        m_dylibTable->setItem(i, 0, new QTableWidgetItem(QString::fromStdString(dl.name)));
        auto fmtVer = [](uint32_t v) {
            return QString("%1.%2.%3").arg(v >> 16).arg((v >> 8) & 0xFF).arg(v & 0xFF);
        };
        m_dylibTable->setItem(i, 1, new QTableWidgetItem(fmtVer(dl.current_version)));
        m_dylibTable->setItem(i, 2, new QTableWidgetItem(fmtVer(dl.compat_version)));
    }
    m_dylibTable->resizeColumnsToContents();
}
