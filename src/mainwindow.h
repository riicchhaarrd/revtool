#pragma once
#include "theme.h"
#include "macho.h"
#include "hexwidget.h"
#include "disasmwidget.h"
#include "infowidget.h"
#include <QMainWindow>
#include <QDockWidget>
#include <QTabWidget>
#include <QLabel>
#include <QComboBox>
#include <QAction>
#include <memory>

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    void loadFile(const QString &path);

private:
    void createMenus();
    void createStatusBar();
    void populateSectionCombo();
    void disassembleCurrentSection();
    void applyTheme(bool dark);

    std::unique_ptr<MachOFile> m_macho;

    // Central area
    QTabWidget   *m_centralTabs = nullptr;
    HexWidget    *m_hexWidget   = nullptr;
    DisasmWidget *m_disasmWidget= nullptr;

    // Dock
    InfoWidget   *m_infoWidget  = nullptr;

    // Toolbar
    QComboBox    *m_sectionCombo = nullptr;

    // Status bar
    QLabel       *m_statusOffset = nullptr;
    QLabel       *m_statusAddr   = nullptr;
    QLabel       *m_statusInfo   = nullptr;

    // Section list for the combo
    std::vector<const Section*> m_codeSections;

    // Theme
    bool     m_darkTheme = true;
    QAction *m_themeToggle = nullptr;
};
