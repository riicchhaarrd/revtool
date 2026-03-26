#include "csyntax.h"

CSyntaxHighlighter::CSyntaxHighlighter(QTextDocument *parent)
    : QSyntaxHighlighter(parent) { applyDark(); }

void CSyntaxHighlighter::setDark(bool dark) {
    dark ? applyDark() : applyLight();
    rehighlight();
}

void CSyntaxHighlighter::highlightBlock(const QString &text) {
    for (auto &rule : m_rules) {
        auto it = rule.pattern.globalMatch(text);
        while (it.hasNext()) {
            auto match = it.next();
            setFormat(match.capturedStart(), match.capturedLength(), rule.format);
        }
    }
}

void CSyntaxHighlighter::add(const char *pattern, QColor color) {
    QTextCharFormat fmt;
    fmt.setForeground(color);
    m_rules.append({QRegularExpression(pattern), fmt});
}

void CSyntaxHighlighter::applyDark() {
    m_rules.clear();
    add(R"(//[^\n]*)",                       QColor(0x6A, 0x99, 0x55)); // comments
    add(R"(\b(if|else|while|for|do|switch|case|break|continue|return|goto|int|void|unsigned|signed|char|short|long|float|double|struct|union|enum|const|static|extern|typedef|sizeof)\b)",
                                              QColor(0x56, 0x9C, 0xD6)); // keywords
    add(R"(\b[A-Za-z_]\w*(?=\s*\())",         QColor(0x4E, 0xC9, 0xB0)); // function calls
    add(R"(\b(?:0[xX][0-9a-fA-F]+|[0-9]+)\b)", QColor(0xB5, 0xCE, 0xA8)); // numbers
    add(R"("(?:[^"\\]|\\.)*")",               QColor(0xCE, 0x91, 0x78)); // strings
    add(R"(^[A-Za-z_]\w*:)",                  QColor(0xDC, 0xDC, 0xAA)); // labels
}

void CSyntaxHighlighter::applyLight() {
    m_rules.clear();
    add(R"(//[^\n]*)",                       QColor(0x00, 0x80, 0x00)); // comments
    add(R"(\b(if|else|while|for|do|switch|case|break|continue|return|goto|int|void|unsigned|signed|char|short|long|float|double|struct|union|enum|const|static|extern|typedef|sizeof)\b)",
                                              QColor(0x00, 0x00, 0xFF)); // keywords
    add(R"(\b[A-Za-z_]\w*(?=\s*\())",         QColor(0x79, 0x5E, 0x26)); // function calls
    add(R"(\b(?:0[xX][0-9a-fA-F]+|[0-9]+)\b)", QColor(0x09, 0x86, 0x58)); // numbers
    add(R"("(?:[^"\\]|\\.)*")",               QColor(0xA3, 0x15, 0x15)); // strings
    add(R"(^[A-Za-z_]\w*:)",                  QColor(0x79, 0x5E, 0x26)); // labels
}
