#pragma once
#include <QSyntaxHighlighter>
#include <QTextCharFormat>
#include <QRegularExpression>
#include <QColor>

class CSyntaxHighlighter : public QSyntaxHighlighter {
    Q_OBJECT
public:
    explicit CSyntaxHighlighter(QTextDocument *parent = nullptr);
    void setDark(bool dark);

protected:
    void highlightBlock(const QString &text) override;

private:
    struct Rule { QRegularExpression pattern; QTextCharFormat format; };
    QVector<Rule> m_rules;
    void add(const char *pattern, QColor color);
    void applyDark();
    void applyLight();
};
