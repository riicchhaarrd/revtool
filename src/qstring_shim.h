#pragma once
// Minimal QString / QStringList shim for Emscripten (WASM) builds.
// Provides only the API subset used by decompiler.h, backed by std::string.
#include <string>
#include <vector>
#include <cstring>
#include <cctype>

class QStringList;

class QString : public std::string {
public:
    QString() = default;
    QString(const char *s) : std::string(s ? s : "") {}
    QString(const std::string &s) : std::string(s) {}
    QString(std::string &&s) : std::string(std::move(s)) {}
    // Qt fill constructor: QString(int size, char ch)
    QString(int n, char ch) : std::string((size_t)(n > 0 ? n : 0), ch) {}

    static QString fromStdString(const std::string &s) { return QString(s); }
    std::string toStdString() const { return *this; }

    // toUtf8() returns *this so .constData() works via c_str()
    const QString &toUtf8() const { return *this; }
    const char *constData() const { return c_str(); }

    bool isEmpty() const { return empty(); }

    bool startsWith(const char *prefix) const { return find(prefix) == 0; }
    bool startsWith(const QString &prefix) const { return find(prefix) == 0; }

    bool endsWith(const char *suffix) const {
        size_t sl = strlen(suffix);
        return size() >= sl && compare(size() - sl, sl, suffix) == 0;
    }
    bool endsWith(const QString &suffix) const {
        return size() >= suffix.size() &&
               compare(size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    bool contains(const char *s) const { return find(s) != npos; }
    bool contains(const QString &s) const { return find(s) != npos; }
    bool contains(char c) const { return find(c) != npos; }

    int indexOf(char c, int from = 0) const {
        size_t pos = find(c, (size_t)from);
        return pos == npos ? -1 : (int)pos;
    }

    QString mid(int pos, int len = -1) const {
        if (pos < 0) pos = 0;
        if (pos >= (int)size()) return {};
        return len < 0 ? substr((size_t)pos) : substr((size_t)pos, (size_t)len);
    }

    QString trimmed() const {
        size_t s = 0, e = size();
        while (s < e && isspace((unsigned char)(*this)[s])) ++s;
        while (e > s && isspace((unsigned char)(*this)[e - 1])) --e;
        return substr(s, e - s);
    }

    // arg(string): replace first %1 with argument
    QString arg(const QString &a) const {
        QString r = *this;
        size_t p = r.find("%1");
        if (p != npos) r.replace(p, 2, a);
        return r;
    }
    // arg(int): replace first %1 with decimal integer
    QString arg(int n) const { return arg(QString(std::to_string(n))); }
    QString arg(long long n) const { return arg(QString(std::to_string(n))); }

    QStringList split(char sep) const;

    // Concatenation operators
    QString &operator+=(const QString &s) { std::string::operator+=(s); return *this; }
    QString &operator+=(const char *s)    { std::string::operator+=(s); return *this; }
    QString &operator+=(char c)           { push_back(c); return *this; }

    QString operator+(const QString &s) const { return QString(std::string(*this) + std::string(s)); }
    QString operator+(const char *s)    const { return QString(std::string(*this) + s); }
    friend QString operator+(const char *a, const QString &b) {
        return QString(std::string(a) + std::string(b));
    }
};

class QStringList : public std::vector<QString> {
public:
    void append(const QString &s) { push_back(s); }
    int size() const { return (int)std::vector<QString>::size(); }
    QString join(const QString &sep) const {
        QString r;
        for (int i = 0; i < (int)std::vector<QString>::size(); ++i) {
            if (i) r += sep;
            r += (*this)[(size_t)i];
        }
        return r;
    }
};

inline QStringList QString::split(char sep) const {
    QStringList result;
    size_t start = 0, pos;
    while ((pos = find(sep, start)) != npos) {
        result.push_back(substr(start, pos - start));
        start = pos + 1;
    }
    result.push_back(substr(start));
    return result;
}
