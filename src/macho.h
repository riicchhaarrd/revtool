#pragma once
#include "demangle.h"
#include "stabs_types.h"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <unordered_map>

// ── Mach-O constants ────────────────────────────────────────────────
constexpr uint32_t MH_MAGIC_32    = 0xFEEDFACE;
constexpr uint32_t MH_MAGIC_64    = 0xFEEDFACF;

constexpr int CPU_TYPE_I386       = 7;
constexpr int CPU_TYPE_X86_64     = 0x01000007;

// File types
constexpr uint32_t MH_OBJECT      = 1;
constexpr uint32_t MH_EXECUTE     = 2;
constexpr uint32_t MH_DYLIB       = 6;
constexpr uint32_t MH_BUNDLE      = 8;

// Load command types
constexpr uint32_t LC_SEGMENT        = 0x01;
constexpr uint32_t LC_SYMTAB         = 0x02;
constexpr uint32_t LC_THREAD         = 0x04;
constexpr uint32_t LC_UNIXTHREAD     = 0x05;
constexpr uint32_t LC_DYSYMTAB       = 0x0B;
constexpr uint32_t LC_LOAD_DYLIB     = 0x0C;
constexpr uint32_t LC_ID_DYLIB       = 0x0D;
constexpr uint32_t LC_LOAD_DYLINKER  = 0x0E;
constexpr uint32_t LC_SEGMENT_64     = 0x19;
constexpr uint32_t LC_UUID           = 0x1B;
constexpr uint32_t LC_DYLD_INFO      = 0x22;
constexpr uint32_t LC_DYLD_INFO_ONLY = 0x80000022;
constexpr uint32_t LC_LOAD_WEAK_DYLIB= 0x80000018;
constexpr uint32_t LC_MAIN           = 0x80000028;
constexpr uint32_t LC_VERSION_MIN_MACOSX = 0x24;

// STABS symbol types (Apple mach-o/stab.h)
constexpr uint8_t N_GSYM   = 0x20;  // global symbol
constexpr uint8_t N_FNAME  = 0x22;  // F77 function name
constexpr uint8_t N_FUN    = 0x24;  // function
constexpr uint8_t N_STSYM  = 0x26;  // static data symbol
constexpr uint8_t N_LCSYM  = 0x28;  // .lcomm symbol
constexpr uint8_t N_BNSYM  = 0x2E;  // begin nsect sym
constexpr uint8_t N_AST    = 0x32;  // AST path
constexpr uint8_t N_OPT    = 0x3C;  // compiler option
constexpr uint8_t N_RSYM   = 0x40;  // register variable
constexpr uint8_t N_SLINE  = 0x44;  // source line
constexpr uint8_t N_ENSYM  = 0x4E;  // end nsect sym
constexpr uint8_t N_SSYM   = 0x60;  // struct/union element
constexpr uint8_t N_SO     = 0x64;  // source file
constexpr uint8_t N_OSO    = 0x66;  // object file
constexpr uint8_t N_LSYM   = 0x80;  // local sym / typedef
constexpr uint8_t N_BINCL  = 0x82;  // begin include
constexpr uint8_t N_SOL    = 0x84;  // included source file
constexpr uint8_t N_PARAMS = 0x86;  // compiler params
constexpr uint8_t N_VERSION= 0x88;  // compiler version
constexpr uint8_t N_OLEVEL = 0x8A;  // opt level
constexpr uint8_t N_PSYM   = 0xA0;  // parameter
constexpr uint8_t N_EINCL  = 0xA2;  // end include
constexpr uint8_t N_ENTRY  = 0xA4;  // alternate entry
constexpr uint8_t N_LBRAC  = 0xC0;  // left bracket (scope begin)
constexpr uint8_t N_EXCL   = 0xC2;  // deleted include
constexpr uint8_t N_RBRAC  = 0xE0;  // right bracket (scope end)
constexpr uint8_t N_BCOMM  = 0xE2;  // begin common
constexpr uint8_t N_ECOMM  = 0xE4;  // end common
constexpr uint8_t N_ECOML  = 0xE8;  // end common (local)
constexpr uint8_t N_LENG   = 0xFE;  // length of preceding entry

// nlist type masks
constexpr uint8_t N_STAB   = 0xE0;
constexpr uint8_t N_PEXT   = 0x10;
constexpr uint8_t N_TYPE   = 0x0E;
constexpr uint8_t N_EXT    = 0x01;

// N_TYPE values
constexpr uint8_t N_UNDF   = 0x00;
constexpr uint8_t N_ABS    = 0x02;
constexpr uint8_t N_SECT   = 0x0E;
constexpr uint8_t N_PBUD   = 0x0C;
constexpr uint8_t N_INDR   = 0x0A;

// ── Structures ──────────────────────────────────────────────────────

struct MachHeader {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

struct LoadCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t fileOffset; // offset within the file where this LC starts
};

struct Section {
    std::string sectname;
    std::string segname;
    uint32_t addr;
    uint32_t size;
    uint32_t offset;   // file offset
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
};

struct Segment {
    std::string segname;
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
    std::vector<Section> sections;
};

struct NList {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;   // 1-based section index
    int16_t  n_desc;
    uint32_t n_value;
    std::string name;
};

struct Dylib {
    std::string name;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compat_version;
};

struct StabsFunction {
    std::string name;
    std::string rawName;     // with type info
    uint32_t    address = 0;
    uint32_t    size = 0;
    bool        isGlobal = false;
    int         sourceFileIdx = -1;
    TypeRef     returnType = NullType;
    std::vector<std::pair<uint32_t, int>> lineMap; // addr -> line number
    std::vector<StabsTypedVar> params;
    std::vector<StabsTypedVar> locals;
};

struct StabsSourceFile {
    std::string directory;
    std::string filename;
    uint32_t    address = 0;
    std::vector<size_t> functionIndices;
};

// ── MachOFile ───────────────────────────────────────────────────────

class MachOFile {
public:
    bool load(const std::string &path) {
        std::ifstream ifs(path, std::ios::binary | std::ios::ate);
        if (!ifs) return false;
        m_size = ifs.tellg();
        ifs.seekg(0);
        m_data.resize(m_size);
        ifs.read(reinterpret_cast<char*>(m_data.data()), m_size);
        if (!ifs) return false;
        m_path = path;
        return parse();
    }

    // Accessors
    const std::string&       path()       const { return m_path; }
    const uint8_t*           data()       const { return m_data.data(); }
    size_t                   size()       const { return m_size; }
    const MachHeader&        header()     const { return m_header; }
    const std::vector<LoadCommand>& loadCommands() const { return m_loadCmds; }
    const std::vector<Segment>&     segments()     const { return m_segments; }
    const std::vector<NList>&       symbols()      const { return m_symbols; }
    const std::vector<Dylib>&       dylibs()       const { return m_dylibs; }
    const std::vector<StabsFunction>&   stabsFunctions()   const { return m_stabsFuncs; }
    const std::vector<StabsSourceFile>& stabsSourceFiles() const { return m_stabsSources; }
    const StabsTypeTable&               typeTable()        const { return m_typeTable; }
    uint32_t entryPoint() const { return m_entryPoint; }

    // Build a flat section list
    std::vector<const Section*> allSections() const {
        std::vector<const Section*> out;
        for (auto &seg : m_segments)
            for (auto &sec : seg.sections)
                out.push_back(&sec);
        return out;
    }

    // Find section containing a virtual address
    const Section* sectionForAddress(uint32_t addr) const {
        for (auto &seg : m_segments)
            for (auto &sec : seg.sections)
                if (addr >= sec.addr && addr < sec.addr + sec.size)
                    return &sec;
        return nullptr;
    }

    // Find segment containing a virtual address
    const Segment* segmentForAddress(uint32_t addr) const {
        for (auto &seg : m_segments)
            if (addr >= seg.vmaddr && addr < seg.vmaddr + seg.vmsize)
                return &seg;
        return nullptr;
    }

    // Convert virtual address to file offset
    int64_t fileOffsetForAddress(uint32_t addr) const {
        for (auto &seg : m_segments) {
            if (addr >= seg.vmaddr && addr < seg.vmaddr + seg.vmsize) {
                uint32_t off = addr - seg.vmaddr + seg.fileoff;
                if (off < m_size) return off;
            }
        }
        return -1;
    }

    // Convert file offset to virtual address
    int64_t addressForFileOffset(uint32_t off) const {
        for (auto &seg : m_segments) {
            if (off >= seg.fileoff && off < seg.fileoff + seg.filesize) {
                return off - seg.fileoff + seg.vmaddr;
            }
        }
        return -1;
    }

    // Read bytes at file offset
    const uint8_t* bytesAt(uint32_t fileOffset, uint32_t len) const {
        if (fileOffset + len <= m_size)
            return m_data.data() + fileOffset;
        return nullptr;
    }

    // Get string from string table
    std::string stringAt(uint32_t stroff, uint32_t idx) const {
        uint32_t pos = stroff + idx;
        if (pos >= m_size) return "";
        const char *s = reinterpret_cast<const char*>(m_data.data() + pos);
        size_t maxlen = m_size - pos;
        size_t len = strnlen(s, maxlen);
        return std::string(s, len);
    }

    // Build address -> function name map
    const std::unordered_map<uint32_t, std::string>& functionMap() const {
        return m_funcMap;
    }

    // LC name
    static const char* lcName(uint32_t cmd) {
        switch (cmd) {
        case LC_SEGMENT:        return "LC_SEGMENT";
        case LC_SYMTAB:         return "LC_SYMTAB";
        case LC_THREAD:         return "LC_THREAD";
        case LC_UNIXTHREAD:     return "LC_UNIXTHREAD";
        case LC_DYSYMTAB:       return "LC_DYSYMTAB";
        case LC_LOAD_DYLIB:     return "LC_LOAD_DYLIB";
        case LC_ID_DYLIB:       return "LC_ID_DYLIB";
        case LC_LOAD_DYLINKER:  return "LC_LOAD_DYLINKER";
        case LC_SEGMENT_64:     return "LC_SEGMENT_64";
        case LC_UUID:           return "LC_UUID";
        case LC_DYLD_INFO:      return "LC_DYLD_INFO";
        case LC_DYLD_INFO_ONLY: return "LC_DYLD_INFO_ONLY";
        case LC_LOAD_WEAK_DYLIB:return "LC_LOAD_WEAK_DYLIB";
        case LC_MAIN:           return "LC_MAIN";
        case LC_VERSION_MIN_MACOSX: return "LC_VERSION_MIN_MACOSX";
        default: return "LC_UNKNOWN";
        }
    }

    static const char* stabsTypeName(uint8_t type) {
        switch (type) {
        case N_GSYM:   return "N_GSYM";
        case N_FNAME:  return "N_FNAME";
        case N_FUN:    return "N_FUN";
        case N_STSYM:  return "N_STSYM";
        case N_LCSYM:  return "N_LCSYM";
        case N_BNSYM:  return "N_BNSYM";
        case N_AST:    return "N_AST";
        case N_OPT:    return "N_OPT";
        case N_RSYM:   return "N_RSYM";
        case N_SLINE:  return "N_SLINE";
        case N_ENSYM:  return "N_ENSYM";
        case N_SSYM:   return "N_SSYM";
        case N_SO:     return "N_SO";
        case N_OSO:    return "N_OSO";
        case N_LSYM:   return "N_LSYM";
        case N_BINCL:  return "N_BINCL";
        case N_SOL:    return "N_SOL";
        case N_PARAMS: return "N_PARAMS";
        case N_VERSION:return "N_VERSION";
        case N_OLEVEL: return "N_OLEVEL";
        case N_PSYM:   return "N_PSYM";
        case N_EINCL:  return "N_EINCL";
        case N_ENTRY:  return "N_ENTRY";
        case N_LBRAC:  return "N_LBRAC";
        case N_EXCL:   return "N_EXCL";
        case N_RBRAC:  return "N_RBRAC";
        case N_BCOMM:  return "N_BCOMM";
        case N_ECOMM:  return "N_ECOMM";
        case N_ECOML:  return "N_ECOML";
        case N_LENG:   return "N_LENG";
        default:       return "UNKNOWN";
        }
    }

    static const char* fileTypeName(uint32_t ft) {
        switch (ft) {
        case 1: return "MH_OBJECT";
        case 2: return "MH_EXECUTE";
        case 3: return "MH_FVMLIB";
        case 4: return "MH_CORE";
        case 5: return "MH_PRELOAD";
        case 6: return "MH_DYLIB";
        case 7: return "MH_DYLINKER";
        case 8: return "MH_BUNDLE";
        case 9: return "MH_DYLIB_STUB";
        case 10: return "MH_DSYM";
        case 11: return "MH_KEXT_BUNDLE";
        default: return "UNKNOWN";
        }
    }

    static std::string flagsString(uint32_t flags) {
        std::string out;
        auto add = [&](uint32_t bit, const char* name) {
            if (flags & bit) { if (!out.empty()) out += " | "; out += name; }
        };
        add(0x1, "NOUNDEFS"); add(0x2, "INCRLINK"); add(0x4, "DYLDLINK");
        add(0x8, "BINDATLOAD"); add(0x10, "PREBOUND"); add(0x20, "SPLIT_SEGS");
        add(0x40, "LAZY_INIT"); add(0x80, "TWOLEVEL"); add(0x100, "FORCE_FLAT");
        add(0x200, "NOMULTIDEFS"); add(0x400, "NOFIXPREBINDING");
        add(0x800, "PREBINDABLE"); add(0x1000, "ALLMODSBOUND");
        add(0x2000, "SUBSECTIONS_VIA_SYMBOLS"); add(0x4000, "CANONICAL");
        add(0x8000, "WEAK_DEFINES"); add(0x10000, "BINDS_TO_WEAK");
        add(0x20000, "ALLOW_STACK_EXECUTION"); add(0x40000, "ROOT_SAFE");
        add(0x80000, "SETUID_SAFE"); add(0x100000, "NO_REEXPORTED_DYLIBS");
        add(0x200000, "PIE");
        return out.empty() ? "NONE" : out;
    }

private:
    template<typename T>
    T readLE(size_t off) const {
        T val;
        memcpy(&val, m_data.data() + off, sizeof(T));
        return val;
    }

    std::string readString(size_t off) const {
        if (off >= m_size) return "";
        const char *s = reinterpret_cast<const char*>(m_data.data() + off);
        return std::string(s, strnlen(s, m_size - off));
    }

    std::string readFixedString(size_t off, size_t maxlen) const {
        if (off + maxlen > m_size) return "";
        const char *s = reinterpret_cast<const char*>(m_data.data() + off);
        return std::string(s, strnlen(s, maxlen));
    }

    bool parse() {
        if (m_size < 28) return false;
        m_header.magic      = readLE<uint32_t>(0);
        m_header.cputype    = readLE<int32_t>(4);
        m_header.cpusubtype = readLE<int32_t>(8);
        m_header.filetype   = readLE<uint32_t>(12);
        m_header.ncmds      = readLE<uint32_t>(16);
        m_header.sizeofcmds = readLE<uint32_t>(20);
        m_header.flags      = readLE<uint32_t>(24);

        if (m_header.magic != MH_MAGIC_32) return false; // Only 32-bit for now

        uint32_t headerSize = 28; // mach_header is 28 bytes for 32-bit
        uint32_t offset = headerSize;

        for (uint32_t i = 0; i < m_header.ncmds && offset + 8 <= m_size; ++i) {
            uint32_t cmd     = readLE<uint32_t>(offset);
            uint32_t cmdsize = readLE<uint32_t>(offset + 4);
            if (cmdsize < 8 || offset + cmdsize > m_size) break;

            LoadCommand lc{cmd, cmdsize, offset};
            m_loadCmds.push_back(lc);

            switch (cmd) {
            case LC_SEGMENT:    parseSegment(offset); break;
            case LC_SYMTAB:     parseSymtab(offset); break;
            case LC_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_ID_DYLIB:   parseDylib(offset); break;
            case LC_UNIXTHREAD: parseUnixThread(offset); break;
            }
            offset += cmdsize;
        }

        parseSTABS();
        buildFunctionMap();
        return true;
    }

    void parseSegment(uint32_t off) {
        Segment seg;
        seg.segname  = readFixedString(off + 8, 16);
        seg.vmaddr   = readLE<uint32_t>(off + 24);
        seg.vmsize   = readLE<uint32_t>(off + 28);
        seg.fileoff  = readLE<uint32_t>(off + 32);
        seg.filesize = readLE<uint32_t>(off + 36);
        seg.maxprot  = readLE<uint32_t>(off + 40);
        seg.initprot = readLE<uint32_t>(off + 44);
        seg.nsects   = readLE<uint32_t>(off + 48);
        seg.flags    = readLE<uint32_t>(off + 52);

        uint32_t secOff = off + 56; // segment_command is 56 bytes
        for (uint32_t i = 0; i < seg.nsects && secOff + 68 <= m_size; ++i) {
            Section sec;
            sec.sectname = readFixedString(secOff, 16);
            sec.segname  = readFixedString(secOff + 16, 16);
            sec.addr     = readLE<uint32_t>(secOff + 32);
            sec.size     = readLE<uint32_t>(secOff + 36);
            sec.offset   = readLE<uint32_t>(secOff + 40);
            sec.align    = readLE<uint32_t>(secOff + 44);
            sec.reloff   = readLE<uint32_t>(secOff + 48);
            sec.nreloc   = readLE<uint32_t>(secOff + 52);
            sec.flags    = readLE<uint32_t>(secOff + 56);
            seg.sections.push_back(sec);
            secOff += 68; // section is 68 bytes on 32-bit
        }
        m_segments.push_back(std::move(seg));
    }

    void parseSymtab(uint32_t off) {
        m_symoff  = readLE<uint32_t>(off + 8);
        m_nsyms   = readLE<uint32_t>(off + 12);
        m_stroff  = readLE<uint32_t>(off + 16);
        m_strsize = readLE<uint32_t>(off + 20);

        m_symbols.reserve(std::min(m_nsyms, (uint32_t)500000));
        uint32_t pos = m_symoff;
        for (uint32_t i = 0; i < m_nsyms && pos + 12 <= m_size; ++i) {
            NList nl;
            nl.n_strx  = readLE<uint32_t>(pos);
            nl.n_type  = readLE<uint8_t>(pos + 4);
            nl.n_sect  = readLE<uint8_t>(pos + 5);
            nl.n_desc  = readLE<int16_t>(pos + 6);
            nl.n_value = readLE<uint32_t>(pos + 8);
            nl.name    = stringAt(m_stroff, nl.n_strx);
            m_symbols.push_back(std::move(nl));
            pos += 12;
        }
    }

    void parseDylib(uint32_t off) {
        uint32_t nameOff = readLE<uint32_t>(off + 8);
        Dylib dl;
        dl.name            = readString(off + nameOff);
        dl.timestamp       = readLE<uint32_t>(off + 12);
        dl.current_version = readLE<uint32_t>(off + 16);
        dl.compat_version  = readLE<uint32_t>(off + 20);
        m_dylibs.push_back(std::move(dl));
    }

    void parseUnixThread(uint32_t off) {
        // LC_UNIXTHREAD for i386: flavor(4) + count(4) + i386_thread_state
        // EIP is at offset 10*4 = 40 bytes into the thread state (field 10)
        if (off + 16 + 40 + 4 <= m_size) {
            m_entryPoint = readLE<uint32_t>(off + 16 + 40);
        }
    }

    // Extract clean function name from STABS encoding like "_foo:F(0,1)"
    static std::string cleanStabsName(const std::string &raw) {
        auto colon = raw.find(':');
        if (colon == std::string::npos) return raw;
        return raw.substr(0, colon);
    }

    void parseSTABS() {
        int curSourceIdx = -1;
        std::string curDir;
        StabsFunction *curFunc = nullptr;

        for (size_t i = 0; i < m_symbols.size(); ++i) {
            auto &sym = m_symbols[i];
            if (!(sym.n_type & N_STAB)) continue;

            switch (sym.n_type) {
            case N_SO: {
                if (sym.name.empty()) {
                    curSourceIdx = -1;
                    curDir.clear();
                } else if (sym.name.back() == '/') {
                    curDir = sym.name;
                } else {
                    StabsSourceFile sf;
                    sf.directory = curDir;
                    sf.filename = sym.name;
                    sf.address = sym.n_value;
                    curSourceIdx = (int)m_stabsSources.size();
                    m_stabsSources.push_back(std::move(sf));
                    // Scope types per compilation unit
                    m_typeTable.setCompilationUnit(curSourceIdx);
                }
                break;
            }
            case N_FUN: {
                if (!sym.name.empty() && sym.n_sect != 0) {
                    StabsFunction fn;
                    fn.rawName = sym.name;
                    fn.name = demangleNameOnly(cleanStabsName(sym.name));
                    fn.address = sym.n_value;
                    fn.isGlobal = (sym.name.find(":F") != std::string::npos);
                    fn.sourceFileIdx = curSourceIdx;
                    // Parse return type from STABS encoding
                    auto parsed = m_typeTable.parseSymbol(sym.name);
                    fn.returnType = parsed.typeRef;
                    m_stabsFuncs.push_back(std::move(fn));
                    curFunc = &m_stabsFuncs.back();
                    if (curSourceIdx >= 0)
                        m_stabsSources[curSourceIdx].functionIndices.push_back(m_stabsFuncs.size()-1);
                } else if (sym.name.empty() || sym.n_sect == 0) {
                    if (curFunc) {
                        curFunc->size = sym.n_value;
                        curFunc = nullptr;
                    }
                }
                break;
            }
            case N_SLINE:
                if (curFunc)
                    curFunc->lineMap.push_back({sym.n_value, sym.n_desc});
                break;
            case N_PSYM: {
                auto parsed = m_typeTable.parseSymbol(sym.name);
                if (curFunc) {
                    StabsTypedVar tv;
                    tv.name = parsed.name;
                    tv.typeRef = parsed.typeRef;
                    tv.stackOffset = (int32_t)sym.n_value; // ebp-relative offset
                    curFunc->params.push_back(tv);
                }
                break;
            }
            case N_LSYM: {
                auto parsed = m_typeTable.parseSymbol(sym.name);
                if (parsed.isType || parsed.descriptor == 't' || parsed.descriptor == 'T') {
                    // Type definition — already registered in type table
                } else if (curFunc) {
                    // Local variable
                    StabsTypedVar tv;
                    tv.name = parsed.name;
                    tv.typeRef = parsed.typeRef;
                    tv.stackOffset = (int32_t)sym.n_value; // ebp-relative offset
                    curFunc->locals.push_back(tv);
                } else {
                    // File-scope type definition (no current function)
                    m_typeTable.parseSymbol(sym.name);
                }
                break;
            }
            case N_GSYM: {
                auto parsed = m_typeTable.parseSymbol(sym.name);
                if (parsed.descriptor == 'G') {
                    TypeRef useType = parsed.typeRef;
                    // Validate: skip mismatched struct types from CU-scoped refs
                    auto *rt = m_typeTable.resolveType(parsed.typeRef);
                    if (rt && (rt->kind == StabsTypeKind::Struct || rt->kind == StabsTypeKind::Union) &&
                        !rt->name.empty() && rt->name.find("$_") == std::string::npos &&
                        parsed.name.size() >= 4) {  // skip for short names (ri, rg, re, etc.)
                        std::string sn = rt->name, gn = parsed.name;
                        for (auto &c : sn) c = tolower(c);
                        for (auto &c : gn) c = tolower(c);
                        if (sn.size() > 2 && sn.substr(sn.size()-2) == "_t") sn = sn.substr(0, sn.size()-2);
                        bool related = (gn.find(sn) != std::string::npos || sn.find(gn) != std::string::npos);
                        if (!related && sn.size() >= 4) related = (gn.find(sn.substr(0,4)) != std::string::npos);
                        if (!related) useType = NullType;
                    }
                    m_typeTable.addGlobal(parsed.name, sym.n_value, useType, false);
                }
                break;
            }
            case N_STSYM:
            case N_LCSYM: {
                auto parsed = m_typeTable.parseSymbol(sym.name);
                m_typeTable.addGlobal(parsed.name, sym.n_value, parsed.typeRef, true);
                break;
            }
            case N_RSYM: {
                // Register variable or register parameter.
                // n_value = STABS register number (0=eax,1=ecx,2=edx,3=ebx,
                //           6=esi,7=edi, 21-28=xmm0-7)
                // Descriptor 'P' = register parameter, 'r' = register local
                auto parsed = m_typeTable.parseSymbol(sym.name);
                if (curFunc) {
                    StabsTypedVar tv;
                    tv.name = parsed.name;
                    tv.typeRef = parsed.typeRef;
                    tv.stackOffset = 0;
                    tv.regNum = (int)sym.n_value;
                    if (parsed.descriptor == 'P') {
                        // Register parameter — add as param if not already present
                        bool dup = false;
                        for (auto &p : curFunc->params)
                            if (p.name == tv.name) { p.regNum = tv.regNum; dup = true; break; }
                        if (!dup)
                            curFunc->params.push_back(tv);
                    } else {
                        // Register local — check if it matches an existing param
                        bool isParam = false;
                        for (auto &p : curFunc->params) {
                            if (p.name == tv.name && p.stackOffset == 0) {
                                p.regNum = tv.regNum;
                                isParam = true;
                                break;
                            }
                        }
                        if (!isParam)
                            curFunc->locals.push_back(tv);
                    }
                }
                break;
            }
            case N_BINCL:
                m_typeTable.addInclude(sym.name);
                break;
            case N_SOL:
                m_typeTable.addInclude(sym.name);
                break;
            default:
                break;
            }
        }

        // Fix parameter types using demangled function signatures.
        // N_PSYM entries use CU-scoped type refs that can resolve to wrong types
        // (e.g., int instead of struct WaveletDecode *). The mangled function name
        // encodes the correct parameter types. When a param's STABS type resolves
        // to a basic type (int) but the demangled name says it's a struct pointer,
        // search the type table for the struct and override the param's type.
        for (auto &fn : m_stabsFuncs) {
            if (fn.params.empty() || fn.rawName.empty()) continue;
            // Demangle to get full signature: "func(type1, type2, ...)"
            // rawName has STABS suffix (":F(0,1)") — strip it first
            std::string full = demangle(cleanStabsName(fn.rawName));
            // Only process if demangled name has parameter list
            size_t parenOpen = full.rfind('(');
            if (parenOpen == std::string::npos) continue;
            size_t parenClose = full.rfind(')');
            if (parenClose == std::string::npos || parenClose <= parenOpen) continue;
            std::string paramStr = full.substr(parenOpen + 1, parenClose - parenOpen - 1);
            // Split params by comma (simplified — doesn't handle nested templates)
            std::vector<std::string> paramTypes;
            {
                size_t start = 0;
                int depth = 0;
                for (size_t i = 0; i <= paramStr.size(); ++i) {
                    if (i < paramStr.size() && paramStr[i] == '<') depth++;
                    else if (i < paramStr.size() && paramStr[i] == '>') depth--;
                    else if ((i == paramStr.size() || paramStr[i] == ',') && depth == 0) {
                        std::string pt = paramStr.substr(start, i - start);
                        // Trim whitespace
                        while (!pt.empty() && pt.front() == ' ') pt.erase(pt.begin());
                        while (!pt.empty() && pt.back() == ' ') pt.pop_back();
                        if (!pt.empty()) paramTypes.push_back(pt);
                        start = i + 1;
                    }
                }
            }
            // Match params by position and fix types
            for (size_t pi = 0; pi < fn.params.size() && pi < paramTypes.size(); ++pi) {
                auto &param = fn.params[pi];
                auto *pt = m_typeTable.resolveType(param.typeRef);
                // Only fix if current type is a basic type (int, etc.)
                if (!pt || (pt->kind != StabsTypeKind::Int && pt->kind != StabsTypeKind::UInt))
                    continue;
                // Check if demangled type suggests a struct pointer
                std::string &dType = paramTypes[pi];
                bool isStructPtr = (dType.find('*') != std::string::npos);
                if (!isStructPtr) continue;
                // Extract struct name: "struct Foo *" or "Foo *" or "const Foo *"
                std::string structName;
                size_t starPos = dType.rfind('*');
                std::string before = dType.substr(0, starPos);
                while (!before.empty() && before.back() == ' ') before.pop_back();
                size_t lastSpace = before.rfind(' ');
                structName = (lastSpace != std::string::npos) ? before.substr(lastSpace + 1) : before;
                if (structName.empty() || structName == "char" || structName == "void" ||
                    structName == "int" || structName == "byte" || structName == "unsigned")
                    continue;
                // Search type table for a struct with this name
                if (structName == "float" || structName == "double" || structName == "long" ||
                    structName == "short" || structName == "const" || structName == "signed")
                    continue;
                for (auto &[tref, ti] : m_typeTable.allTypes()) {
                    if ((ti.kind == StabsTypeKind::Struct || ti.kind == StabsTypeKind::Union ||
                         ti.kind == StabsTypeKind::ForwardRef) &&
                        (ti.name == structName || ti.forwardTag == structName) &&
                        (ti.kind == StabsTypeKind::ForwardRef || !ti.fields.empty())) {
                        // Found the struct. Create a pointer type reference.
                        // Look for an existing pointer-to-struct type
                        for (auto &[pref, pti] : m_typeTable.allTypes()) {
                            if (pti.kind == StabsTypeKind::Pointer && pti.targetType == tref) {
                                param.typeRef = pref;
                                goto next_param;
                            }
                        }
                        // No pointer type found — use the struct type directly
                        // (the lifter handles struct types for field access)
                        param.typeRef = tref;
                        goto next_param;
                    }
                }
                next_param:;
            }
        }

        // Recover orphaned global type info: scan STABS strings for "name:G(CU,ID)"
        // patterns that weren't processed as N_GSYM entries. Match against nlist symbols
        // to get the address. This handles binaries where N_GSYM entries are missing.
        {   // Recover orphaned global type info from STABS string table
            // Build nlist symbol name → address map (strip leading underscore)
            std::map<std::string, uint32_t> nlSyms;
            for (auto &sym : m_symbols) {
                if (sym.n_type & N_STAB) continue;
                if ((sym.n_type & N_TYPE) == N_SECT || (sym.n_type & N_TYPE) == N_ABS) {
                    std::string name = sym.name;
                    if (!name.empty() && name[0] == '_') name = name.substr(1);
                    if (!name.empty()) nlSyms[name] = sym.n_value;
                }
            }
            // Scan the string table for "name:G(" or "name:S(" entries
            // Use m_stroff (string table start in file)
            for (uint32_t spos = 0; spos < m_strsize; ) {
                std::string entry = stringAt(m_stroff, spos);
                uint32_t slen = (uint32_t)entry.size();
                if (slen == 0) { spos++; continue; }
                // Check for "name:G(" or "name:S(" pattern
                auto gpos = entry.find(":G(");
                auto spos2 = entry.find(":S(");
                auto cpos = (gpos != std::string::npos) ? gpos :
                            (spos2 != std::string::npos) ? spos2 : std::string::npos;
                if (cpos != std::string::npos && cpos > 0 && cpos < 60) {
                    std::string gname = entry.substr(0, cpos);
                    auto it = nlSyms.find(gname);
                    if (it != nlSyms.end()) {
                        auto parsed = m_typeTable.parseSymbol(entry);
                        if (parsed.typeRef != NullType) {
                            // Validate: if the type resolves to a struct, check if
                            // the struct name is related to the global name.
                            // Mismatched struct types from CU-scoped refs cause
                            // compile errors ("not a structure or union").
                            TypeRef useType = parsed.typeRef;
                            auto *rt = m_typeTable.resolveType(parsed.typeRef);
                            if (rt && (rt->kind == StabsTypeKind::Struct ||
                                       rt->kind == StabsTypeKind::Union)) {
                                // Check if struct name relates to global name
                                std::string sn = rt->name;
                                std::string gn = gname;
                                // Convert both to lowercase for comparison
                                for (auto &c : sn) c = tolower(c);
                                for (auto &c : gn) c = tolower(c);
                                // Check if either contains the other (partial match)
                                bool related = false;
                                if (sn.size() >= 3 && gn.size() >= 4) {  // skip for short names
                                    // Strip common prefixes/suffixes
                                    std::string sn2 = sn;
                                    if (sn2.size() > 2 && sn2.substr(sn2.size()-2) == "_t")
                                        sn2 = sn2.substr(0, sn2.size()-2);
                                    if (gn.find(sn2) != std::string::npos ||
                                        sn2.find(gn) != std::string::npos)
                                        related = true;
                                    // Also check if the global name starts with a
                                    // common prefix of the struct name
                                    if (sn2.size() >= 4 && gn.find(sn2.substr(0,4)) != std::string::npos)
                                        related = true;
                                }
                                // Anonymous structs ($_NNNN) are always OK
                                if (rt->name.find("$_") != std::string::npos)
                                    related = true;
                                if (!related)
                                    useType = NullType;
                            }
                            m_typeTable.addGlobal(gname, it->second, useType, false);
                        }
                    }
                }
                spos += slen + 1;
            }
        }
    }

    void buildFunctionMap() {
        for (auto &fn : m_stabsFuncs) {
            if (fn.address)
                m_funcMap[fn.address] = fn.name;
        }
        // Also add non-STABS external symbols (demangled)
        for (auto &sym : m_symbols) {
            if (sym.n_type & N_STAB) continue;
            if ((sym.n_type & N_TYPE) == N_SECT && sym.n_value) {
                if (m_funcMap.find(sym.n_value) == m_funcMap.end())
                    m_funcMap[sym.n_value] = demangleNameOnly(sym.name);
            }
        }
        // Resolve import stubs via indirect symbol table
        resolveImportStubs();
    }

    void resolveImportStubs() {
        // Find LC_DYSYMTAB
        uint32_t indirectSymOff = 0, nIndirect = 0;
        for (auto &lc : m_loadCmds) {
            if (lc.cmd == LC_DYSYMTAB && lc.fileOffset + 64 <= m_size) {
                indirectSymOff = readLE<uint32_t>(lc.fileOffset + 56);
                nIndirect = readLE<uint32_t>(lc.fileOffset + 60);
                break;
            }
        }
        if (!indirectSymOff || !nIndirect) return;

        // For each section that has stubs (S_SYMBOL_STUBS = 0x08, S_LAZY_SYMBOL_POINTERS = 0x07,
        // S_NON_LAZY_SYMBOL_POINTERS = 0x06), resolve entries via indirect symbol table
        for (auto &seg : m_segments) {
            uint32_t secOff = 0;
            // Find the raw section offset to read reserved1/reserved2
            for (auto &lc : m_loadCmds) {
                if (lc.cmd != LC_SEGMENT) continue;
                std::string sn = readFixedString(lc.fileOffset + 8, 16);
                if (sn != seg.segname) continue;
                secOff = lc.fileOffset + 56;
                break;
            }
            if (!secOff) continue;

            for (uint32_t si = 0; si < seg.nsects && secOff + (si+1)*68 <= m_size; ++si) {
                uint32_t shOff = secOff + si * 68;
                uint32_t sflags = readLE<uint32_t>(shOff + 56);
                uint32_t reserved1 = readLE<uint32_t>(shOff + 60);
                uint32_t reserved2 = readLE<uint32_t>(shOff + 64);
                uint32_t saddr = readLE<uint32_t>(shOff + 32);
                uint32_t ssize = readLE<uint32_t>(shOff + 36);
                uint8_t secType = sflags & 0xFF;

                if (secType == 0x08 && reserved2 > 0) {
                    // S_SYMBOL_STUBS: each entry is reserved2 bytes
                    uint32_t nstubs = ssize / reserved2;
                    for (uint32_t j = 0; j < nstubs; ++j) {
                        uint32_t idx = reserved1 + j;
                        if (idx >= nIndirect) break;
                        if (indirectSymOff + (idx+1)*4 > m_size) break;
                        uint32_t symIdx = readLE<uint32_t>(indirectSymOff + idx * 4);
                        if (symIdx >= m_symbols.size()) continue;
                        uint32_t stubAddr = saddr + j * reserved2;
                        if (m_funcMap.find(stubAddr) == m_funcMap.end()) {
                            std::string name = demangleNameOnly(m_symbols[symIdx].name);
                            m_funcMap[stubAddr] = name;
                        }
                    }
                }
                if (secType == 0x07 || secType == 0x06) {
                    // Lazy/non-lazy symbol pointers: each entry is 4 bytes
                    uint32_t nptrs = ssize / 4;
                    for (uint32_t j = 0; j < nptrs; ++j) {
                        uint32_t idx = reserved1 + j;
                        if (idx >= nIndirect) break;
                        if (indirectSymOff + (idx+1)*4 > m_size) break;
                        uint32_t symIdx = readLE<uint32_t>(indirectSymOff + idx * 4);
                        if (symIdx >= m_symbols.size()) continue;
                        uint32_t ptrAddr = saddr + j * 4;
                        if (m_funcMap.find(ptrAddr) == m_funcMap.end()) {
                            std::string name = demangleNameOnly(m_symbols[symIdx].name);
                            m_funcMap[ptrAddr] = name;
                        }
                    }
                }
            }
        }
    }

    // Look up StabsFunction by address
    public:
    const StabsFunction* stabsFunctionAt(uint32_t addr) const {
        for (auto &fn : m_stabsFuncs)
            if (fn.address == addr) return &fn;
        return nullptr;
    }
    // Find a STABS function by demangled name (for cross-CU lookups when stub addr != real addr)
    const StabsFunction* stabsFunctionByName(const std::string &name) const {
        for (auto &fn : m_stabsFuncs)
            if (fn.name == name) return &fn;
        return nullptr;
    }
    // Find enclosing function for any address
    const StabsFunction* stabsFunctionContaining(uint32_t addr) const {
        const StabsFunction *best = nullptr;
        for (auto &fn : m_stabsFuncs) {
            if (addr >= fn.address && (fn.size == 0 || addr < fn.address + fn.size)) {
                if (!best || fn.address > best->address)
                    best = &fn;
            }
        }
        return best;
    }
    // Look up a data symbol name by address from the nlist symbol table
    std::string symbolNameAtAddress(uint32_t addr) const {
        if (m_dataSymMap.empty()) buildDataSymMap();
        auto it = m_dataSymMap.find(addr);
        return it != m_dataSymMap.end() ? it->second : "";
    }

    // Find nearest symbol below addr and return "symbol + 0xNN" for small offsets
    // Only works for addresses in data sections (not code)
    std::string nearestSymbolName(uint32_t addr) const {
        if (m_dataSymMap.empty()) buildDataSymMap();
        // Only resolve addresses that are actually in data sections
        const Section *sec = sectionForAddress(addr);
        if (!sec || (sec->segname != "__DATA" && sec->segname != "__IMPORT")) return "";
        auto it = m_dataSymMap.upper_bound(addr);
        if (it == m_dataSymMap.begin()) return "";
        --it;
        uint32_t diff = addr - it->first;
        if (diff > 0 && diff < 0x20000) {
            char buf[64];
            snprintf(buf, sizeof(buf), "(%s + 0x%X)", it->second.c_str(), diff);
            return buf;
        }
        return "";
    }

    private:

    void buildDataSymMap() const {
        for (auto &sym : m_symbols) {
            if (sym.n_value == 0 || sym.name.empty()) continue;
            if (sym.n_type & 0xE0) continue;  // Skip STABS
            if ((sym.n_type & 0x0E) != 0x0E) continue;  // Only N_SECT
            std::string name = sym.name;
            if (!name.empty() && name[0] == '_') name = name.substr(1);
            if (name.find(':') != std::string::npos) continue;
            // Demangle C++ names
            std::string demangled = demangleNameOnly(sym.name);
            if (!demangled.empty() && demangled != sym.name) name = demangled;
            m_dataSymMap[sym.n_value] = name;
        }
        // Also resolve import pointer targets: map import ptr address → target name
        for (auto &seg : m_segments) {
            if (seg.segname != "__IMPORT") continue;
            for (auto &sec : seg.sections) {
                if (sec.sectname != "__pointers") continue;
                uint32_t nptrs = sec.size / 4;
                for (uint32_t j = 0; j < nptrs; ++j) {
                    uint32_t ptrAddr = sec.addr + j * 4;
                    if (m_dataSymMap.count(ptrAddr)) continue; // already named
                    int64_t foff = fileOffsetForAddress(ptrAddr);
                    if (foff < 0 || foff + 4 > (int64_t)m_size) continue;
                    uint32_t targetAddr;
                    memcpy(&targetAddr, m_data.data() + foff, 4);
                    auto it = m_dataSymMap.find(targetAddr);
                    if (it != m_dataSymMap.end())
                        m_dataSymMap[ptrAddr] = it->second;
                }
            }
        }
    }

    std::string         m_path;
    std::vector<uint8_t> m_data;
    size_t              m_size = 0;
    MachHeader          m_header{};
    std::vector<LoadCommand> m_loadCmds;
    std::vector<Segment>     m_segments;
    std::vector<NList>       m_symbols;
    mutable std::map<uint32_t, std::string> m_dataSymMap;
    std::vector<Dylib>       m_dylibs;
    uint32_t m_symoff = 0, m_nsyms = 0, m_stroff = 0, m_strsize = 0;
    uint32_t m_entryPoint = 0;

    std::vector<StabsFunction>   m_stabsFuncs;
    std::vector<StabsSourceFile> m_stabsSources;
    std::unordered_map<uint32_t, std::string> m_funcMap;
    StabsTypeTable               m_typeTable;
};
