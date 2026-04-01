#pragma once
// Minimal QString / QStringList shim for Emscripten (WASM) builds.
// Provides only the API subset used by decompiler.h, backed by std::string.
#include <string>
#include <vector>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <cstdio>

class QStringList;

// Minimal QChar wrapper so that QString::operator[] can expose isLetterOrNumber().
class QChar {
    char c_;
public:
    QChar(char c = 0) : c_(c) {}
    operator char() const { return c_; }
    bool isLetterOrNumber() const { return isalnum((unsigned char)c_); }
    bool isDigit() const { return isdigit((unsigned char)c_); }
    bool isLower() const { return islower((unsigned char)c_); }
    bool operator==(char o)  const { return c_ == o; }
    bool operator==(QChar o) const { return c_ == o.c_; }
    bool operator!=(char o)  const { return c_ != o; }
    bool operator!=(QChar o) const { return c_ != o.c_; }
};

class QString : public std::string {
public:
    QString() = default;
    QString(const char *s) : std::string(s ? s : "") {}
    QString(const std::string &s) : std::string(s) {}
    QString(std::string &&s) : std::string(std::move(s)) {}
    // Qt fill constructor: QString(int size, char ch)
    QString(int n, char ch) : std::string((size_t)(n > 0 ? n : 0), ch) {}

    static QString fromStdString(const std::string &s) { return QString(s); }
    static QString fromUtf8(const char *s) { return QString(s ? s : ""); }
    std::string toStdString() const { return *this; }

    // toUtf8() returns *this so .constData() works via c_str()
    const QString &toUtf8() const { return *this; }
    const char *constData() const { return c_str(); }

    bool isEmpty() const { return empty(); }

    bool startsWith(const char *prefix) const { return find(prefix) == 0; }
    bool startsWith(const QString &prefix) const { return find(prefix) == 0; }
    bool startsWith(char c) const { return !empty() && front() == c; }

    bool endsWith(const char *suffix) const {
        size_t sl = strlen(suffix);
        return size() >= sl && compare(size() - sl, sl, suffix) == 0;
    }
    bool endsWith(const QString &suffix) const {
        return size() >= suffix.size() &&
               compare(size() - suffix.size(), suffix.size(), suffix) == 0;
    }
    bool endsWith(char c) const { return !empty() && back() == c; }

    bool contains(const char *s) const { return find(s) != npos; }
    bool contains(const QString &s) const { return find(s) != npos; }
    bool contains(char c) const { return find(c) != npos; }

    int lastIndexOf(char c, int from = -1) const {
        int start = (from < 0) ? (int)size() - 1 : std::min(from, (int)size() - 1);
        for (int i = start; i >= 0; --i)
            if (std::string::operator[]((size_t)i) == c) return i;
        return -1;
    }
    int lastIndexOf(const char *s, int from = -1) const {
        size_t sl = strlen(s);
        if (sl == 0) return from < 0 ? (int)size() : std::min(from, (int)size());
        int start = (from < 0) ? (int)size() - (int)sl
                                : std::min(from, (int)size() - (int)sl);
        for (int i = start; i >= 0; --i)
            if (compare((size_t)i, sl, s) == 0) return i;
        return -1;
    }
    int lastIndexOf(const QString &s, int from = -1) const {
        return lastIndexOf(s.c_str(), from);
    }

    int indexOf(char c, int from = 0) const {
        size_t pos = find(c, (size_t)(from < 0 ? 0 : from));
        return pos == npos ? -1 : (int)pos;
    }
    int indexOf(const char *s, int from = 0) const {
        size_t pos = find(s, (size_t)(from < 0 ? 0 : from));
        return pos == npos ? -1 : (int)pos;
    }
    int indexOf(const QString &s, int from = 0) const {
        size_t pos = find(s, (size_t)(from < 0 ? 0 : from));
        return pos == npos ? -1 : (int)pos;
    }

    QString mid(int pos, int len = -1) const {
        if (pos < 0) pos = 0;
        if (pos >= (int)size()) return {};
        return len < 0 ? substr((size_t)pos) : substr((size_t)pos, (size_t)len);
    }

    QString left(int n) const {
        if (n <= 0) return {};
        if ((size_t)n >= size()) return *this;
        return substr(0, (size_t)n);
    }

    QString chopped(int n) const {
        if (n <= 0) return *this;
        if ((size_t)n >= size()) return {};
        return substr(0, size() - (size_t)n);
    }

    void chop(int n) {
        if (n > 0) {
            if ((size_t)n >= size()) clear();
            else resize(size() - (size_t)n);
        }
    }

    int toInt(bool *ok = nullptr, int base = 10) const {
        if (empty()) { if (ok) *ok = false; return 0; }
        try {
            size_t pos = 0;
            int result = std::stoi(*this, &pos, base);
            if (ok) *ok = (pos == size());
            return result;
        } catch (...) {
            if (ok) *ok = false;
            return 0;
        }
    }
    unsigned int toUInt(bool *ok = nullptr, int base = 10) const {
        if (empty()) { if (ok) *ok = false; return 0; }
        try {
            size_t pos = 0;
            unsigned long result = std::stoul(*this, &pos, base);
            if (ok) *ok = (pos == size());
            return (unsigned int)result;
        } catch (...) {
            if (ok) *ok = false;
            return 0;
        }
    }

    void truncate(int n) {
        if (n >= 0 && (size_t)n < size()) resize((size_t)n);
    }

    int count(char c) const {
        return (int)std::count(begin(), end(), c);
    }

    static QString number(int n) { return QString(std::to_string(n)); }
    static QString number(long long n) { return QString(std::to_string(n)); }
    static QString number(double v, char fmt = 'g', int prec = 6) {
        char fmtbuf[16], buf[64];
        snprintf(fmtbuf, sizeof(fmtbuf), "%%.%d%c", prec, fmt);
        snprintf(buf, sizeof(buf), fmtbuf, v);
        return QString(buf);
    }

    QString trimmed() const {
        size_t s = 0, e = size();
        while (s < e && isspace((unsigned char)(*this)[s])) ++s;
        while (e > s && isspace((unsigned char)(*this)[e - 1])) --e;
        return substr(s, e - s);
    }

    // operator[] returning QChar so callers can use .isLetterOrNumber() etc.
    QChar operator[](size_t i) const { return QChar(std::string::operator[](i)); }
    QChar operator[](int i)    const { return operator[]((size_t)(i < 0 ? 0 : i)); }

    // replace(pos, len, str): positional replacement — expose the std::string overload
    // that our replace(const char*, const char*) would otherwise hide.
    QString &replace(int pos, int len, const QString &to) {
        if (pos >= 0 && len >= 0 && pos <= (int)size())
            std::string::replace((size_t)pos, (size_t)len, to);
        return *this;
    }

    // replace(from, to): replace all occurrences of substring
    QString &replace(const char *from, const char *to) {
        std::string &self = *this;
        std::string f(from), t(to);
        size_t pos = 0;
        while ((pos = self.find(f, pos)) != npos) {
            self.replace(pos, f.size(), t);
            pos += t.size();
        }
        return *this;
    }
    QString &replace(const QString &from, const QString &to) {
        return replace(from.c_str(), to.c_str());
    }

    // remove(pos, len): erase substring in-place
    QString &remove(int pos, int len) {
        if (pos >= 0 && pos < (int)size() && len > 0)
            erase((size_t)pos, (size_t)len);
        return *this;
    }
    // remove(char): remove all occurrences of character
    QString &remove(char c) {
        std::string &self = *this;
        self.erase(std::remove(self.begin(), self.end(), c), self.end());
        return *this;
    }

    // arg(string): replace first %1 with argument
    QString arg(const QString &a) const {
        QString r = *this;
        size_t p = r.find("%1");
        if (p != npos) r.std::string::replace(p, 2, a);
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
    bool isEmpty() const { return std::vector<QString>::empty(); }
    const QString &last() const { return back(); }
    QString &last() { return back(); }
    void removeAt(int i) {
        if (i >= 0 && (size_t)i < std::vector<QString>::size())
            erase(begin() + i);
    }
    QString join(const QString &sep) const {
        QString r;
        for (int i = 0; i < (int)std::vector<QString>::size(); ++i) {
            if (i) r += sep;
            r += (*this)[(size_t)i];
        }
        return r;
    }
    QString join(char sep) const { return join(QString(1, sep)); }
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
