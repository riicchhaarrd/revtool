#include "infowidget.h"
#include <algorithm>

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

    // Symbols tab
    {
        auto *w = new QWidget;
        auto *lay = new QVBoxLayout(w);
        lay->setContentsMargins(0,0,0,0);
        m_symFilter = new QLineEdit;
        m_symFilter->setPlaceholderText("Filter symbols (regex supported)...");
        lay->addWidget(m_symFilter);
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
    buildSymbolsTab();
    buildStabsTab();
    buildDylibsTab();
}

void InfoWidget::buildHeaderTab() {
    auto &h = m_macho->header();
    QString info;
    info += QString("Magic:        0x%1\n").arg(h.magic, 8, 16, QChar('0')).toUpper();
    info += QString("CPU Type:     %1 (%2)\n")
                .arg(h.cputype == CPU_TYPE_I386 ? "i386" : "unknown")
                .arg(h.cputype);
    info += QString("CPU Subtype:  %1\n").arg(h.cpusubtype);
    info += QString("File Type:    %1 (%2)\n")
                .arg(MachOFile::fileTypeName(h.filetype))
                .arg(h.filetype);
    info += QString("Load Cmds:    %1\n").arg(h.ncmds);
    info += QString("Cmds Size:    %1 bytes\n").arg(h.sizeofcmds);
    info += QString("Flags:        %1\n").arg(QString::fromStdString(MachOFile::flagsString(h.flags)));
    info += QString("Entry Point:  %1\n").arg(hex32(m_macho->entryPoint()));
    info += QString("File Size:    %1 bytes (%2 KB)\n")
                .arg(m_macho->size())
                .arg(m_macho->size() / 1024);
    info += "\n── Segments ──\n";
    for (auto &seg : m_macho->segments()) {
        info += QString("  %-16s  vm=%1  size=%2  file=%3  sections=%4\n")
                    .arg(hex32(seg.vmaddr))
                    .arg(hex32(seg.vmsize))
                    .arg(hex32(seg.fileoff))
                    .arg(seg.nsects);
        info = info.replace("%-16s", QString::fromStdString(seg.segname).leftJustified(16));
    }
    info += QString("\n── Symbols ──\n");
    info += QString("  Total:     %1\n").arg(m_macho->symbols().size());
    int stabsCount = 0;
    for (auto &s : m_macho->symbols())
        if (s.n_type & N_STAB) stabsCount++;
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
            // Store section data for click handling
            secItem->setData(0, Qt::UserRole, sec.offset);
            secItem->setData(0, Qt::UserRole + 1, sec.size);
            secItem->setData(0, Qt::UserRole + 2, sec.addr);
        }
        segItem->setExpanded(true);
    }
    m_segTree->resizeColumnToContents(0);
    m_segTree->resizeColumnToContents(1);

    connect(m_segTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem *item, int) {
        if (item->parent()) { // It's a section
            uint32_t foff = item->data(0, Qt::UserRole).toUInt();
            uint32_t sz   = item->data(0, Qt::UserRole + 1).toUInt();
            uint32_t addr = item->data(0, Qt::UserRole + 2).toUInt();
            emit sectionSelected(foff, sz, addr, item->text(0));
        }
    });
}

void InfoWidget::buildSymbolsTab() {
    setupTable(m_symTable);
    m_symTable->setColumnCount(5);
    m_symTable->setHorizontalHeaderLabels({"Name", "Value", "Type", "Sect", "Desc"});

    auto populateSymbols = [this](const QString &filter) {
        m_symTable->setRowCount(0);
        QRegularExpression re(filter, QRegularExpression::CaseInsensitiveOption);
        bool hasFilter = !filter.isEmpty() && re.isValid();

        int row = 0;
        int maxRows = 50000; // cap for performance
        for (auto &sym : m_macho->symbols()) {
            if (row >= maxRows) break;
            if (sym.n_type & N_STAB) continue; // skip STABS in this view

            QString name = QString::fromStdString(sym.name);
            if (hasFilter && !re.match(name).hasMatch()) continue;

            m_symTable->insertRow(row);
            m_symTable->setItem(row, 0, new QTableWidgetItem(name));
            m_symTable->setItem(row, 1, new QTableWidgetItem(hex32(sym.n_value)));

            // Decode type
            QString typeStr;
            uint8_t ntype = sym.n_type & N_TYPE;
            if (ntype == N_UNDF) typeStr = "UNDEF";
            else if (ntype == N_ABS) typeStr = "ABS";
            else if (ntype == N_SECT) typeStr = "SECT";
            else if (ntype == N_PBUD) typeStr = "PBUD";
            else if (ntype == N_INDR) typeStr = "INDR";
            if (sym.n_type & N_EXT) typeStr += "|EXT";
            if (sym.n_type & N_PEXT) typeStr += "|PEXT";
            m_symTable->setItem(row, 2, new QTableWidgetItem(typeStr));
            m_symTable->setItem(row, 3, new QTableWidgetItem(QString::number(sym.n_sect)));
            m_symTable->setItem(row, 4, new QTableWidgetItem(QString::number(sym.n_desc)));
            row++;
        }
    };

    populateSymbols("");

    connect(m_symFilter, &QLineEdit::textChanged, this, [populateSymbols](const QString &text) {
        populateSymbols(text);
    });

    connect(m_symTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        auto *item = m_symTable->item(row, 1);
        if (item) {
            bool ok;
            uint32_t addr = item->text().toUInt(&ok, 16);
            if (ok) emit symbolSelected(addr);
        }
    });

    m_symTable->resizeColumnsToContents();
}

void InfoWidget::buildStabsTab() {
    m_stabsTree->clear();

    // Source files as top-level items, functions as children
    for (size_t si = 0; si < m_macho->stabsSourceFiles().size(); ++si) {
        auto &sf = m_macho->stabsSourceFiles()[si];
        auto *fileItem = new QTreeWidgetItem(m_stabsTree);
        // If filename already contains the directory as prefix, don't double it
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
                details += QString("lines: %1-%2")
                    .arg(fn.lineMap.front().second)
                    .arg(fn.lineMap.back().second);
            }
            fnItem->setText(3, details);
            fnItem->setData(0, Qt::UserRole, fn.address);
        }
    }

    // Functions without source files
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

    // STABS type summary
    auto *summaryItem = new QTreeWidgetItem(m_stabsTree);
    summaryItem->setText(0, "[STABS Summary]");
    std::unordered_map<uint8_t, int> typeCounts;
    for (auto &sym : m_macho->symbols()) {
        if (sym.n_type & N_STAB)
            typeCounts[sym.n_type]++;
    }
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
        if (v.isValid()) {
            uint32_t addr = v.toUInt();
            if (addr) emit goToAddress(addr);
        }
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
