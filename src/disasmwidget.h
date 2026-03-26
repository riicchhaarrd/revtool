#pragma once
#include "macho.h"
#include <QAbstractScrollArea>
#include <QFont>
#include <QScrollBar>
#include <QInputDialog>
#include <capstone/capstone.h>
#include <vector>
#include <string>
#include <cstdint>

struct DisasmLine {
    uint32_t    address = 0;
    uint8_t     size    = 0;
    std::string bytes;
    std::string mnemonic;
    std::string operands;
    std::string label;
    std::string comment;
    bool        isCall = false;
    bool        isJump = false;
    bool        isRet  = false;
    bool        isNop  = false;
};

class DisasmWidget : public QAbstractScrollArea {
    Q_OBJECT
public:
    explicit DisasmWidget(QWidget *parent = nullptr);
    ~DisasmWidget();

    void setMachO(MachOFile *macho);
    void disassembleSection(const Section &sec);
    void goToAddress(uint32_t addr);
    void goToIndex(int idx);

    uint32_t currentAddress() const;
    const std::vector<DisasmLine>& lines() const { return m_lines; }

signals:
    void addressChanged(uint32_t addr);
    void statusMessage(const QString &msg);
    void goToHexOffset(int64_t offset);

protected:
    void paintEvent(QPaintEvent *e) override;
    void keyPressEvent(QKeyEvent *e) override;
    void mousePressEvent(QMouseEvent *e) override;
    void mouseDoubleClickEvent(QMouseEvent *e) override;
    void resizeEvent(QResizeEvent *e) override;

private:
    void updateScrollBar();
    int visibleLines() const;
    int lineHeight() const;
    int headerHeight() const;
    int indexFromY(int y) const;

    MachOFile *m_macho = nullptr;
    std::vector<DisasmLine> m_lines;
    int      m_currentLine = 0;
    csh      m_cs = 0;
    bool     m_csOk = false;
    QFont    m_font;
    int      m_charW = 0;
    int      m_charH = 0;

    int m_addrX    = 0;
    int m_bytesX   = 0;
    int m_mnemoX   = 0;
    int m_operX    = 0;
    int m_commentX = 0;
};
