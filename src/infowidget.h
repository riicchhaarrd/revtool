#pragma once
#include "macho.h"
#include <QTabWidget>
#include <QTreeWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <cstdint>

class InfoWidget : public QTabWidget {
    Q_OBJECT
public:
    explicit InfoWidget(QWidget *parent = nullptr);
    void setMachO(MachOFile *macho);

signals:
    void sectionSelected(uint32_t fileoff, uint32_t size, uint32_t vmaddr, const QString &name);
    void symbolSelected(uint32_t addr);
    void goToAddress(uint32_t addr);

private:
    void buildHeaderTab();
    void buildLoadCmdsTab();
    void buildSegmentsTab();
    void buildSourceTreeTab();
    void buildFunctionsTab();
    void buildSymbolsTab();
    void buildStabsTab();
    void buildDylibsTab();
    void repopulateSymbols();

    MachOFile *m_macho = nullptr;

    QTextEdit    *m_headerInfo    = nullptr;
    QTableWidget *m_lcTable       = nullptr;
    QTreeWidget  *m_segTree       = nullptr;
    QTreeWidget  *m_sourceTree    = nullptr;
    QLineEdit    *m_srcFilter     = nullptr;
    QTableWidget *m_funcTable     = nullptr;
    QLineEdit    *m_funcFilter    = nullptr;
    QTableWidget *m_symTable      = nullptr;
    QLineEdit    *m_symFilter     = nullptr;
    QComboBox    *m_symKindCombo  = nullptr;
    QTreeWidget  *m_stabsTree     = nullptr;
    QTableWidget *m_dylibTable    = nullptr;
};
