#pragma once
// Minimal QString / QStringList shim for Emscripten (WASM) builds.
// Provides only the API subset used by decompiler.h, backed by std::string.
#include <string>
#include <vector>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstdio>

class QStringList;
class QRegularExpression;
class QRegularExpressionMatch;

// Minimal QChar wrapper so that QString::operator[] can expose isLetterOrNumber().
class QChar {
    char c_;
public:
    QChar(char c = 0) : c_(c) {}
    operator char() const { return c_; }
    bool isLetter() const { return isalpha((unsigned char)c_); }
    bool isLetterOrNumber() const { return isalnum((unsigned char)c_); }
    bool isDigit() const { return isdigit((unsigned char)c_); }
    bool isLower() const { return islower((unsigned char)c_); }
    bool isSpace() const { return isspace((unsigned char)c_); }
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
    int indexOf(const QRegularExpression &re, int from = 0,
                QRegularExpressionMatch *match = nullptr) const;

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
        errno = 0;
        char *end = nullptr;
        long result = std::strtol(c_str(), &end, base);
        bool parsed = end && end != c_str() && *end == '\0' && errno != ERANGE;
        if (ok) *ok = parsed;
        if (!parsed)
            return 0;
        return (int)result;
    }
    unsigned int toUInt(bool *ok = nullptr, int base = 10) const {
        if (empty()) { if (ok) *ok = false; return 0; }
        if ((*this)[0] == '-') {
            if (ok) *ok = false;
            return 0;
        }
        errno = 0;
        char *end = nullptr;
        unsigned long result = std::strtoul(c_str(), &end, base);
        bool parsed = end && end != c_str() && *end == '\0' && errno != ERANGE;
        if (ok) *ok = parsed;
        if (!parsed)
            return 0;
        return (unsigned int)result;
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
    QString &replace(const QRegularExpression &re, const QString &to);

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
    void insert(int i, const QString &s) {
        if (i >= 0 && (size_t)i <= std::vector<QString>::size())
            std::vector<QString>::insert(begin() + i, s);
    }
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

class QRegularExpressionMatch {
    friend class QRegularExpression;
    friend class QString;

    bool matched_ = false;
    int start_ = -1;
    std::vector<QString> captures_;
    std::vector<int> lengths_;

    void setMatch(int start, const std::vector<QString> &captures) {
        matched_ = true;
        start_ = start;
        captures_ = captures;
        lengths_.clear();
        lengths_.reserve(captures_.size());
        for (const auto &capture : captures_)
            lengths_.push_back((int)capture.size());
    }

public:
    bool hasMatch() const { return matched_; }
    QString captured(int idx) const {
        if (idx < 0 || (size_t)idx >= captures_.size()) return {};
        return captures_[(size_t)idx];
    }
    int capturedLength(int idx) const {
        if (idx < 0 || (size_t)idx >= lengths_.size()) return -1;
        return lengths_[(size_t)idx];
    }
};

class QRegularExpression {
    enum class Kind {
        Unknown,
        CharCastParen,
        CharCastBare,
        FramesAddr,
        NetchanAddr,
        SunParseAssign,
        SunLightColorAssign,
        PtrDecl,
        LocalDecl
    };

    QString pattern_;
    Kind kind_ = Kind::Unknown;

    static bool isIdentStart(char c) {
        return std::isalpha((unsigned char)c) || c == '_';
    }

    static bool isIdentChar(char c) {
        return std::isalnum((unsigned char)c) || c == '_';
    }

    static void skipSpaces(const QString &s, size_t &p) {
        while (p < s.size() && std::isspace((unsigned char)s[p]))
            ++p;
    }

    static bool onlySpacesToEnd(const QString &s, size_t p) {
        while (p < s.size()) {
            if (!std::isspace((unsigned char)s[p]))
                return false;
            ++p;
        }
        return true;
    }

    static bool readIdentifier(const QString &s, size_t &p, QString *out = nullptr) {
        if (p >= s.size() || !isIdentStart(s[p]))
            return false;
        size_t start = p++;
        while (p < s.size() && isIdentChar(s[p]))
            ++p;
        if (out)
            *out = s.substr(start, p - start);
        return true;
    }

    static Kind classify(const QString &pattern) {
        if (pattern == R"(\(\(char \*\)\((\w+)\)\))")
            return Kind::CharCastParen;
        if (pattern == R"(\(\(char \*\)(\w+)\))")
            return Kind::CharCastBare;
        if (pattern == R"(&([A-Za-z_][A-Za-z0-9_]*)->frames\[(\d+)\]\.ps)")
            return Kind::FramesAddr;
        if (pattern == R"(&([A-Za-z_][A-Za-z0-9_]*)->netchan\.remoteAddress\.type)")
            return Kind::NetchanAddr;
        if (pattern == R"(^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*&.*->sunParse\s*;)")
            return Kind::SunParseAssign;
        if (pattern == R"(^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*&.*->sunLight\.color\[0\]\s*;)")
            return Kind::SunLightColorAssign;
        if (pattern == R"(^(\s*)(?:char|int)\s*\*\s*(v\d+|var_[A-Za-z0-9_]+)\s*;)")
            return Kind::PtrDecl;
        return Kind::LocalDecl;
    }

    bool matchCharCastParen(const QString &s, size_t pos, QRegularExpressionMatch *match) const {
        const QString prefix = "((char *)(";
        if (s.compare(pos, prefix.size(), prefix) != 0)
            return false;
        size_t p = pos + prefix.size();
        QString name;
        if (!readIdentifier(s, p, &name))
            return false;
        if (p + 2 > s.size() || s.compare(p, 2, "))") != 0)
            return false;
        size_t end = p + 2;
        if (match)
            match->setMatch((int)pos, {s.substr(pos, end - pos), name});
        return true;
    }

    bool matchCharCastBare(const QString &s, size_t pos, QRegularExpressionMatch *match) const {
        const QString prefix = "((char *)";
        if (s.compare(pos, prefix.size(), prefix) != 0)
            return false;
        size_t p = pos + prefix.size();
        QString name;
        if (!readIdentifier(s, p, &name))
            return false;
        if (p >= s.size() || s[p] != ')')
            return false;
        size_t end = p + 1;
        if (match)
            match->setMatch((int)pos, {s.substr(pos, end - pos), name});
        return true;
    }

    bool matchFramesAddr(const QString &s, size_t pos, QRegularExpressionMatch *match) const {
        if (pos >= s.size() || s[pos] != '&')
            return false;
        size_t p = pos + 1;
        QString base;
        if (!readIdentifier(s, p, &base))
            return false;
        const QString mid = "->frames[";
        if (p + mid.size() > s.size() || s.compare(p, mid.size(), mid) != 0)
            return false;
        p += mid.size();
        size_t idxStart = p;
        while (p < s.size() && std::isdigit((unsigned char)s[p]))
            ++p;
        if (p == idxStart || p + 4 > s.size() || s.compare(p, 4, "].ps") != 0)
            return false;
        QString idx = s.substr(idxStart, p - idxStart);
        size_t end = p + 4;
        if (match)
            match->setMatch((int)pos, {s.substr(pos, end - pos), base, idx});
        return true;
    }

    bool matchNetchanAddr(const QString &s, size_t pos, QRegularExpressionMatch *match) const {
        if (pos >= s.size() || s[pos] != '&')
            return false;
        size_t p = pos + 1;
        QString base;
        if (!readIdentifier(s, p, &base))
            return false;
        const QString suffix = "->netchan.remoteAddress.type";
        if (p + suffix.size() > s.size() || s.compare(p, suffix.size(), suffix) != 0)
            return false;
        size_t end = p + suffix.size();
        if (match)
            match->setMatch((int)pos, {s.substr(pos, end - pos), base});
        return true;
    }

    bool matchSunAssign(const QString &s, const QString &member,
                        QRegularExpressionMatch *match) const {
        size_t p = 0;
        skipSpaces(s, p);
        size_t nameStart = p;
        QString name;
        if (!readIdentifier(s, p, &name))
            return false;
        skipSpaces(s, p);
        if (p >= s.size() || s[p] != '=')
            return false;
        ++p;
        skipSpaces(s, p);
        if (p >= s.size() || s[p] != '&')
            return false;

        size_t memberPos = s.find(member, p + 1);
        if (memberPos == QString::npos)
            return false;
        size_t semi = memberPos + member.size();
        skipSpaces(s, semi);
        if (semi >= s.size() || s[semi] != ';' || !onlySpacesToEnd(s, semi + 1))
            return false;
        if (match)
            match->setMatch(0, {s, name});
        (void)nameStart;
        return true;
    }

    bool matchPtrDecl(const QString &s, QRegularExpressionMatch *match) const {
        size_t p = 0;
        while (p < s.size() && (s[p] == ' ' || s[p] == '\t'))
            ++p;
        QString indent = s.substr(0, p);
        if (s.compare(p, 4, "char") == 0)
            p += 4;
        else if (s.compare(p, 3, "int") == 0)
            p += 3;
        else
            return false;
        if (p < s.size() && isIdentChar(s[p]))
            return false;
        skipSpaces(s, p);
        if (p >= s.size() || s[p] != '*')
            return false;
        ++p;
        skipSpaces(s, p);
        size_t nameStart = p;
        QString name;
        if (!readIdentifier(s, p, &name))
            return false;
        bool generatedName = (name.size() >= 2 && name[0] == 'v' &&
                              std::isdigit((unsigned char)name[1])) ||
                             name.rfind("var_", 0) == 0;
        if (!generatedName)
            return false;
        skipSpaces(s, p);
        if (p >= s.size() || s[p] != ';' || !onlySpacesToEnd(s, p + 1))
            return false;
        if (match)
            match->setMatch(0, {s.substr(0, p + 1), indent, s.substr(nameStart, name.size())});
        return true;
    }

    bool matchLocalDecl(const QString &s, QRegularExpressionMatch *match) const {
        QString t = s.trimmed();
        if (t.empty() || !t.endsWith(';'))
            return false;
        if (t.startsWith("return ") || t.startsWith("if ") || t.startsWith("while ") ||
            t.startsWith("for ") || t.startsWith("switch ") || t.startsWith("goto "))
            return false;

        size_t end = t.find('=');
        if (end == QString::npos)
            end = t.size() - 1;
        if (end == 0)
            return false;

        size_t p = end;
        while (p > 0 && std::isspace((unsigned char)t[p - 1]))
            --p;
        if (p > 0 && t[p - 1] == ']') {
            size_t bracket = t.rfind('[', p - 1);
            if (bracket == QString::npos)
                return false;
            p = bracket;
            while (p > 0 && std::isspace((unsigned char)t[p - 1]))
                --p;
        }

        size_t nameEnd = p;
        while (p > 0 && isIdentChar(t[p - 1]))
            --p;
        if (p == nameEnd || !isIdentStart(t[p]))
            return false;
        QString name = t.substr(p, nameEnd - p);
        QString before = QString(t.substr(0, p)).trimmed();
        if (before.empty())
            return false;
        bool hasTypeChar = false;
        for (char c : before) {
            if (std::isalpha((unsigned char)c) || c == '*') {
                hasTypeChar = true;
                break;
            }
        }
        if (!hasTypeChar)
            return false;
        if (match)
            match->setMatch(0, {t, name});
        return true;
    }

public:
    QRegularExpression(const char *pattern)
        : pattern_(pattern), kind_(classify(pattern_)) {}
    QRegularExpression(const QString &pattern)
        : pattern_(pattern), kind_(classify(pattern_)) {}

    QRegularExpressionMatch match(const QString &s) const {
        QRegularExpressionMatch out;
        findIn(s, 0, &out);
        return out;
    }

    int findIn(const QString &s, int from, QRegularExpressionMatch *match = nullptr) const {
        if (from < 0) from = 0;
        if ((size_t)from > s.size()) return -1;

        switch (kind_) {
        case Kind::SunParseAssign:
            return from == 0 && matchSunAssign(s, "->sunParse", match) ? 0 : -1;
        case Kind::SunLightColorAssign:
            return from == 0 && matchSunAssign(s, "->sunLight.color[0]", match) ? 0 : -1;
        case Kind::PtrDecl:
            return from == 0 && matchPtrDecl(s, match) ? 0 : -1;
        case Kind::LocalDecl:
            return from == 0 && matchLocalDecl(s, match) ? 0 : -1;
        case Kind::CharCastParen:
            for (size_t p = (size_t)from; p < s.size(); ++p)
                if (matchCharCastParen(s, p, match))
                    return (int)p;
            return -1;
        case Kind::CharCastBare:
            for (size_t p = (size_t)from; p < s.size(); ++p)
                if (matchCharCastBare(s, p, match))
                    return (int)p;
            return -1;
        case Kind::FramesAddr:
            for (size_t p = (size_t)from; p < s.size(); ++p)
                if (matchFramesAddr(s, p, match))
                    return (int)p;
            return -1;
        case Kind::NetchanAddr:
            for (size_t p = (size_t)from; p < s.size(); ++p)
                if (matchNetchanAddr(s, p, match))
                    return (int)p;
            return -1;
        case Kind::Unknown:
            break;
        }
        size_t pos = s.find(pattern_, (size_t)from);
        if (pos == QString::npos)
            return -1;
        if (match)
            match->setMatch((int)pos, {s.substr(pos, pattern_.size())});
        return (int)pos;
    }

    QString expandReplacement(const QString &replacement,
                              const QRegularExpressionMatch &match) const {
        QString out;
        for (size_t i = 0; i < replacement.size(); ++i) {
            if (replacement[i] == '\\' && i + 1 < replacement.size() &&
                replacement[i + 1].isDigit()) {
                int idx = replacement[i + 1] - '0';
                out += match.captured(idx);
                ++i;
            } else {
                out += replacement[i];
            }
        }
        return out;
    }
};

inline int QString::indexOf(const QRegularExpression &re, int from,
                            QRegularExpressionMatch *match) const {
    return re.findIn(*this, from, match);
}

inline QString &QString::replace(const QRegularExpression &re, const QString &to) {
    QString result;
    int pos = 0;
    QRegularExpressionMatch match;
    while (pos < (int)size()) {
        int found = re.findIn(*this, pos, &match);
        if (found < 0) {
            result += substr((size_t)pos);
            break;
        }
        result += substr((size_t)pos, (size_t)(found - pos));
        result += re.expandReplacement(to, match);
        int len = match.capturedLength(0);
        if (len <= 0) {
            result += std::string::operator[]((size_t)found);
            pos = found + 1;
        } else {
            pos = found + len;
        }
    }
    assign(result);
    return *this;
}
