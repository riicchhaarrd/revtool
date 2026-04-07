#pragma once
#include "demangle.h"
#include "stabs_types.h"
#include <capstone/capstone.h>
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

enum class BinaryFormat {
    Unknown,
    MachO32,
    PE32,
};

struct DataDirectoryEntry {
    std::string name;
    uint32_t rva = 0;
    uint32_t size = 0;
};

struct PEHeader {
    uint32_t peOffset = 0;
    uint32_t signature = 0;
    uint16_t machine = 0;
    uint16_t numberOfSections = 0;
    uint32_t timeDateStamp = 0;
    uint32_t pointerToSymbolTable = 0;
    uint32_t numberOfSymbols = 0;
    uint16_t sizeOfOptionalHeader = 0;
    uint16_t characteristics = 0;
    uint16_t optionalMagic = 0;
    uint8_t  majorLinkerVersion = 0;
    uint8_t  minorLinkerVersion = 0;
    uint32_t sizeOfCode = 0;
    uint32_t sizeOfInitializedData = 0;
    uint32_t sizeOfUninitializedData = 0;
    uint32_t addressOfEntryPoint = 0;
    uint32_t baseOfCode = 0;
    uint32_t baseOfData = 0;
    uint32_t imageBase = 0;
    uint32_t sectionAlignment = 0;
    uint32_t fileAlignment = 0;
    uint16_t majorOSVersion = 0;
    uint16_t minorOSVersion = 0;
    uint16_t majorImageVersion = 0;
    uint16_t minorImageVersion = 0;
    uint16_t majorSubsystemVersion = 0;
    uint16_t minorSubsystemVersion = 0;
    uint32_t sizeOfImage = 0;
    uint32_t sizeOfHeaders = 0;
    uint32_t checksum = 0;
    uint16_t subsystem = 0;
    uint16_t dllCharacteristics = 0;
    uint32_t sizeOfStackReserve = 0;
    uint32_t sizeOfStackCommit = 0;
    uint32_t sizeOfHeapReserve = 0;
    uint32_t sizeOfHeapCommit = 0;
    uint32_t loaderFlags = 0;
    uint32_t numberOfRvaAndSizes = 0;
    std::vector<DataDirectoryEntry> dataDirectories;
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
        clear();
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
    BinaryFormat             format()     const { return m_format; }
    bool                     isMachO()    const { return m_format == BinaryFormat::MachO32; }
    bool                     isPE()       const { return m_format == BinaryFormat::PE32; }
    const PEHeader&          peHeader()   const { return m_peHeader; }
    const MachHeader&        header()     const { return m_header; }
    const std::vector<LoadCommand>& loadCommands() const { return m_loadCmds; }
    const std::vector<Segment>&     segments()     const { return m_segments; }
    const std::vector<NList>&       symbols()      const { return m_symbols; }
    const std::vector<Dylib>&       dylibs()       const { return m_dylibs; }
    const std::vector<StabsFunction>&   stabsFunctions()   const { return m_stabsFuncs; }
    const std::vector<StabsSourceFile>& stabsSourceFiles() const { return m_stabsSources; }
    const StabsTypeTable&               typeTable()        const { return m_typeTable; }
    uint32_t entryPoint() const { return m_entryPoint; }
    const std::vector<DataDirectoryEntry>& dataDirectories() const {
        return m_peHeader.dataDirectories;
    }

    const char* formatName() const {
        switch (m_format) {
        case BinaryFormat::MachO32: return "Mach-O i386";
        case BinaryFormat::PE32:    return "PE32 i386";
        default:                    return "Unknown";
        }
        return "Unknown";
    }

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
                if (addr >= sec.addr && addr < sec.addr + sectionAddressSpan(sec))
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
        for (auto &seg : m_segments)
            for (auto &sec : seg.sections)
                if (addr >= sec.addr && addr < sec.addr + sectionAddressSpan(sec)) {
                    uint32_t delta = addr - sec.addr;
                    if (delta >= sec.size || sec.size == 0) return -1;
                    uint32_t off = delta + sec.offset;
                    if (off < m_size) return off;
                }
        return -1;
    }

    // Convert file offset to virtual address
    int64_t addressForFileOffset(uint32_t off) const {
        for (auto &seg : m_segments)
            for (auto &sec : seg.sections)
                if (off >= sec.offset && off < sec.offset + sec.size) {
                    return off - sec.offset + sec.addr;
                }
        return -1;
    }

    bool isCodeSection(const Section &sec) const {
        if (isPE()) {
            return (sec.flags & 0x00000020) || (sec.flags & 0x20000000) ||
                   sec.sectname == ".text" || sec.sectname == ".code";
        }
        return (sec.flags & 0x80000000) || (sec.flags & 0x00000400) ||
               ((sec.flags & 0xFF) == 0 && sec.sectname.find("text") != std::string::npos);
    }

    bool isTextSection(const Section &sec) const {
        if (isPE()) return sec.sectname == ".text" || isCodeSection(sec);
        return sec.sectname == "__text" || sec.sectname == "__textcoal_nt" || isCodeSection(sec);
    }

    bool isImportSection(const Section &sec) const {
        if (isPE()) {
            return sec.sectname == ".idata" || sec.sectname == ".didat" ||
                   sec.sectname == ".rdata";
        }
        return sec.segname == "__IMPORT";
    }

    bool isCStringSection(const Section &sec) const {
        if (isPE())
            return sec.sectname == ".rdata" || sec.sectname == ".data" ||
                   sec.sectname == ".idata";
        return sec.sectname == "__cstring";
    }

    bool isDataSection(const Section &sec) const {
        if (isCodeSection(sec)) return false;
        if (isPE()) {
            return sec.sectname == ".data" || sec.sectname == ".rdata" ||
                   sec.sectname == ".idata" || sec.sectname == ".bss" ||
                   sec.sectname == ".tls" || sec.sectname == ".rsrc" ||
                   (sec.flags & 0x00000040) || (sec.flags & 0x00000080);
        }
        return sec.segname == "__DATA" || sec.segname == "__IMPORT";
    }

    std::string cStringAtAddress(uint32_t addr, size_t minLen = 1,
                                 size_t maxLen = 256) const {
        int64_t off = fileOffsetForAddress(addr);
        if (off < 0) return "";
        const Section *sec = sectionForAddress(addr);
        if (!sec || (!isCStringSection(*sec) && !isDataSection(*sec))) return "";
        uint32_t delta = addr - sec->addr;
        if (delta >= sec->size || sec->size == 0) return "";

        size_t limit = std::min<size_t>(maxLen, sec->size - delta);
        const uint8_t *p = bytesAt((uint32_t)off, (uint32_t)limit);
        if (!p || limit == 0) return "";

        std::string out;
        bool terminated = false;
        for (size_t i = 0; i < limit; ++i) {
            uint8_t c = p[i];
            if (c == 0) {
                terminated = true;
                break;
            }
            if (c < 0x20 || c >= 0x7F)
                return "";
            out += (char)c;
        }
        if (!terminated || out.size() < minLen) return "";
        return out;
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

    static const char* peMachineName(uint16_t machine) {
        switch (machine) {
        case 0x014c: return "i386";
        case 0x8664: return "x86_64";
        default:     return "unknown";
        }
    }

    static const char* peSubsystemName(uint16_t subsystem) {
        switch (subsystem) {
        case 1: return "Native";
        case 2: return "Windows GUI";
        case 3: return "Windows CUI";
        case 5: return "OS/2 CUI";
        case 7: return "POSIX CUI";
        case 9: return "Windows CE";
        case 10: return "EFI Application";
        case 11: return "EFI Boot Service Driver";
        case 12: return "EFI Runtime Driver";
        case 14: return "Xbox";
        default: return "Unknown";
        }
    }

    static std::string peCharacteristicsString(uint16_t chars) {
        std::string out;
        auto add = [&](uint16_t bit, const char *name) {
            if (chars & bit) { if (!out.empty()) out += " | "; out += name; }
        };
        add(0x0001, "RELOCS_STRIPPED");
        add(0x0002, "EXECUTABLE_IMAGE");
        add(0x0004, "LINE_NUMS_STRIPPED");
        add(0x0008, "LOCAL_SYMS_STRIPPED");
        add(0x0010, "AGGRESSIVE_WS_TRIM");
        add(0x0020, "LARGE_ADDRESS_AWARE");
        add(0x0100, "32BIT_MACHINE");
        add(0x0200, "DEBUG_STRIPPED");
        add(0x2000, "DLL");
        add(0x4000, "UP_SYSTEM_ONLY");
        return out.empty() ? "NONE" : out;
    }

private:
    uint32_t sectionAddressSpan(const Section &sec) const {
        if (isPE() && sec.segname == "IMAGE")
            return sec.align ? sec.align : sec.size;
        return sec.size;
    }

    void clear() {
        m_path.clear();
        m_data.clear();
        m_size = 0;
        m_format = BinaryFormat::Unknown;
        m_header = {};
        m_peHeader = {};
        m_loadCmds.clear();
        m_segments.clear();
        m_symbols.clear();
        m_dataSymMap.clear();
        m_dylibs.clear();
        m_symoff = m_nsyms = m_stroff = m_strsize = 0;
        m_entryPoint = 0;
        m_stabsFuncs.clear();
        m_stabsSources.clear();
        m_funcMap.clear();
        m_typeTable = StabsTypeTable();
    }

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
        if (m_size >= 0x40 && readLE<uint16_t>(0) == 0x5A4D)
            return parsePE();
        if (m_size < 28) return false;
        if (readLE<uint32_t>(0) == MH_MAGIC_32)
            return parseMachO();
        return false;
    }

    bool parseMachO() {
        m_format = BinaryFormat::MachO32;
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

    int sectionIndexForAddress(uint32_t addr) const {
        int idx = 0;
        for (auto &seg : m_segments)
            for (auto &sec : seg.sections) {
                if (addr >= sec.addr && addr < sec.addr + sectionAddressSpan(sec))
                    return idx;
                ++idx;
            }
        return -1;
    }

    int64_t peFileOffsetForRva(uint32_t rva) const {
        if (rva < m_peHeader.sizeOfHeaders && rva < m_size)
            return rva;
        for (auto &seg : m_segments) {
            for (auto &sec : seg.sections) {
                uint32_t secRva = sec.addr - m_peHeader.imageBase;
                uint32_t secSpan = sectionAddressSpan(sec);
                if (rva >= secRva && rva < secRva + secSpan) {
                    if (sec.size == 0 || rva - secRva >= sec.size) return -1;
                    uint32_t off = sec.offset + (rva - secRva);
                    if (off < m_size) return off;
                }
            }
        }
        return -1;
    }

    void addPESymbol(const std::string &name, uint32_t addr, uint8_t ntype, int secIdx) {
        if (name.empty()) return;
        for (auto &sym : m_symbols)
            if (sym.n_value == addr && sym.name == name && sym.n_type == ntype)
                return;
        NList sym{};
        sym.n_type = ntype;
        sym.n_sect = secIdx >= 0 ? (uint8_t)(secIdx + 1) : 0;
        sym.n_value = addr;
        sym.name = name;
        m_symbols.push_back(std::move(sym));
    }

    void parsePEImports(uint32_t dirRva, uint32_t dirSize) {
        if (!dirRva || !dirSize) return;
        int64_t dirOff = peFileOffsetForRva(dirRva);
        if (dirOff < 0) return;
        for (uint32_t off = (uint32_t)dirOff; off + 20 <= m_size; off += 20) {
            uint32_t origFirstThunk = readLE<uint32_t>(off + 0);
            uint32_t timeDateStamp  = readLE<uint32_t>(off + 4);
            uint32_t forwarderChain = readLE<uint32_t>(off + 8);
            uint32_t nameRva        = readLE<uint32_t>(off + 12);
            uint32_t firstThunk     = readLE<uint32_t>(off + 16);
            if (!origFirstThunk && !timeDateStamp && !forwarderChain &&
                !nameRva && !firstThunk)
                break;

            int64_t nameOff = peFileOffsetForRva(nameRva);
            std::string dllName = nameOff >= 0 ? readString((size_t)nameOff) : "";
            if (!dllName.empty())
                m_dylibs.push_back({dllName, 0, 0, 0});

            uint32_t thunkRva = origFirstThunk ? origFirstThunk : firstThunk;
            int64_t thunkOff = peFileOffsetForRva(thunkRva);
            int64_t iatOff = peFileOffsetForRva(firstThunk);
            if (thunkOff < 0 || iatOff < 0) continue;

            for (uint32_t idx = 0; ; ++idx) {
                uint32_t tOff = (uint32_t)thunkOff + idx * 4;
                uint32_t fOff = (uint32_t)iatOff + idx * 4;
                if (tOff + 4 > m_size || fOff + 4 > m_size) break;
                uint32_t thunkVal = readLE<uint32_t>(tOff);
                if (!thunkVal) break;

                std::string importName;
                if (thunkVal & 0x80000000) {
                    importName = dllName + "!#" + std::to_string(thunkVal & 0xFFFF);
                } else {
                    int64_t ibnOff = peFileOffsetForRva(thunkVal);
                    if (ibnOff < 0 || ibnOff + 2 > (int64_t)m_size) break;
                    importName = readString((size_t)ibnOff + 2);
                    if (!dllName.empty())
                        importName = dllName + "!" + importName;
                }

                uint32_t iatAddr = m_peHeader.imageBase + firstThunk + idx * 4;
                int secIdx = sectionIndexForAddress(iatAddr);
                addPESymbol(importName, iatAddr, N_UNDF, secIdx);
                m_funcMap[iatAddr] = importName;
            }
        }
    }

    void parsePEExports(uint32_t dirRva, uint32_t dirSize) {
        if (!dirRva || !dirSize) return;
        int64_t dirOff = peFileOffsetForRva(dirRva);
        if (dirOff < 0 || dirOff + 40 > (int64_t)m_size) return;

        uint32_t numberOfFunctions = readLE<uint32_t>(dirOff + 20);
        uint32_t numberOfNames = readLE<uint32_t>(dirOff + 24);
        uint32_t addressOfFunctions = readLE<uint32_t>(dirOff + 28);
        uint32_t addressOfNames = readLE<uint32_t>(dirOff + 32);
        uint32_t addressOfNameOrdinals = readLE<uint32_t>(dirOff + 36);

        int64_t funcsOff = peFileOffsetForRva(addressOfFunctions);
        int64_t namesOff = peFileOffsetForRva(addressOfNames);
        int64_t ordsOff = peFileOffsetForRva(addressOfNameOrdinals);
        if (funcsOff < 0 || namesOff < 0 || ordsOff < 0) return;

        for (uint32_t i = 0; i < numberOfNames; ++i) {
            if (namesOff + (i + 1) * 4 > (int64_t)m_size ||
                ordsOff + (i + 1) * 2 > (int64_t)m_size)
                break;
            uint32_t nameRva = readLE<uint32_t>(namesOff + i * 4);
            uint16_t ordinal = readLE<uint16_t>(ordsOff + i * 2);
            if (ordinal >= numberOfFunctions ||
                funcsOff + (ordinal + 1) * 4 > (int64_t)m_size)
                continue;
            int64_t nameOff = peFileOffsetForRva(nameRva);
            if (nameOff < 0) continue;
            std::string name = readString((size_t)nameOff);
            uint32_t funcRva = readLE<uint32_t>(funcsOff + ordinal * 4);
            if (!funcRva) continue;

            // Forwarded exports point back into the export directory.
            if (funcRva >= dirRva && funcRva < dirRva + dirSize)
                continue;

            uint32_t addr = m_peHeader.imageBase + funcRva;
            int secIdx = sectionIndexForAddress(addr);
            addPESymbol(name, addr, N_SECT, secIdx);
            if (secIdx >= 0 && m_funcMap.find(addr) == m_funcMap.end()) {
                auto secs = allSections();
                if (secIdx < (int)secs.size() && isCodeSection(*secs[secIdx]))
                    m_funcMap[addr] = demangleNameOnly(name);
            }
        }
    }

    bool parsePE() {
        if (m_size < 0x100 || readLE<uint16_t>(0) != 0x5A4D) return false;
        uint32_t peOff = readLE<uint32_t>(0x3C);
        if (peOff + 24 > m_size) return false;
        if (readLE<uint32_t>(peOff) != 0x00004550) return false;

        m_format = BinaryFormat::PE32;
        m_peHeader.peOffset = peOff;
        m_peHeader.signature = readLE<uint32_t>(peOff);
        m_peHeader.machine = readLE<uint16_t>(peOff + 4);
        m_peHeader.numberOfSections = readLE<uint16_t>(peOff + 6);
        m_peHeader.timeDateStamp = readLE<uint32_t>(peOff + 8);
        m_peHeader.pointerToSymbolTable = readLE<uint32_t>(peOff + 12);
        m_peHeader.numberOfSymbols = readLE<uint32_t>(peOff + 16);
        m_peHeader.sizeOfOptionalHeader = readLE<uint16_t>(peOff + 20);
        m_peHeader.characteristics = readLE<uint16_t>(peOff + 22);

        uint32_t optOff = peOff + 24;
        if (optOff + m_peHeader.sizeOfOptionalHeader > m_size ||
            m_peHeader.sizeOfOptionalHeader < 96)
            return false;

        m_peHeader.optionalMagic = readLE<uint16_t>(optOff + 0);
        if (m_peHeader.optionalMagic != 0x10B) return false;
        m_peHeader.majorLinkerVersion = readLE<uint8_t>(optOff + 2);
        m_peHeader.minorLinkerVersion = readLE<uint8_t>(optOff + 3);
        m_peHeader.sizeOfCode = readLE<uint32_t>(optOff + 4);
        m_peHeader.sizeOfInitializedData = readLE<uint32_t>(optOff + 8);
        m_peHeader.sizeOfUninitializedData = readLE<uint32_t>(optOff + 12);
        m_peHeader.addressOfEntryPoint = readLE<uint32_t>(optOff + 16);
        m_peHeader.baseOfCode = readLE<uint32_t>(optOff + 20);
        m_peHeader.baseOfData = readLE<uint32_t>(optOff + 24);
        m_peHeader.imageBase = readLE<uint32_t>(optOff + 28);
        m_peHeader.sectionAlignment = readLE<uint32_t>(optOff + 32);
        m_peHeader.fileAlignment = readLE<uint32_t>(optOff + 36);
        m_peHeader.majorOSVersion = readLE<uint16_t>(optOff + 40);
        m_peHeader.minorOSVersion = readLE<uint16_t>(optOff + 42);
        m_peHeader.majorImageVersion = readLE<uint16_t>(optOff + 44);
        m_peHeader.minorImageVersion = readLE<uint16_t>(optOff + 46);
        m_peHeader.majorSubsystemVersion = readLE<uint16_t>(optOff + 48);
        m_peHeader.minorSubsystemVersion = readLE<uint16_t>(optOff + 50);
        m_peHeader.sizeOfImage = readLE<uint32_t>(optOff + 56);
        m_peHeader.sizeOfHeaders = readLE<uint32_t>(optOff + 60);
        m_peHeader.checksum = readLE<uint32_t>(optOff + 64);
        m_peHeader.subsystem = readLE<uint16_t>(optOff + 68);
        m_peHeader.dllCharacteristics = readLE<uint16_t>(optOff + 70);
        m_peHeader.sizeOfStackReserve = readLE<uint32_t>(optOff + 72);
        m_peHeader.sizeOfStackCommit = readLE<uint32_t>(optOff + 76);
        m_peHeader.sizeOfHeapReserve = readLE<uint32_t>(optOff + 80);
        m_peHeader.sizeOfHeapCommit = readLE<uint32_t>(optOff + 84);
        m_peHeader.loaderFlags = readLE<uint32_t>(optOff + 88);
        m_peHeader.numberOfRvaAndSizes = readLE<uint32_t>(optOff + 92);
        m_entryPoint = m_peHeader.imageBase + m_peHeader.addressOfEntryPoint;

        static const char *kDirNames[] = {
            "Export", "Import", "Resource", "Exception",
            "Security", "Base Reloc", "Debug", "Architecture",
            "Global Ptr", "TLS", "Load Config", "Bound Import",
            "IAT", "Delay Import", "CLR", "Reserved"
        };
        uint32_t dirCount = std::min<uint32_t>(m_peHeader.numberOfRvaAndSizes, 16);
        for (uint32_t i = 0; i < dirCount && optOff + 96 + (i + 1) * 8 <= m_size; ++i) {
            DataDirectoryEntry dir;
            dir.name = kDirNames[i];
            dir.rva = readLE<uint32_t>(optOff + 96 + i * 8);
            dir.size = readLE<uint32_t>(optOff + 96 + i * 8 + 4);
            m_peHeader.dataDirectories.push_back(std::move(dir));
        }

        Segment imageSeg;
        imageSeg.segname = "IMAGE";
        imageSeg.vmaddr = m_peHeader.imageBase;
        imageSeg.vmsize = m_peHeader.sizeOfImage;
        imageSeg.fileoff = 0;
        imageSeg.filesize = (uint32_t)m_size;
        imageSeg.nsects = m_peHeader.numberOfSections;
        imageSeg.flags = m_peHeader.characteristics;

        uint32_t secOff = optOff + m_peHeader.sizeOfOptionalHeader;
        if (secOff + m_peHeader.numberOfSections * 40 > m_size) return false;
        for (uint32_t i = 0; i < m_peHeader.numberOfSections; ++i) {
            uint32_t shOff = secOff + i * 40;
            Section sec;
            sec.sectname = readFixedString(shOff + 0, 8);
            sec.segname = "IMAGE";
            uint32_t virtualSize = readLE<uint32_t>(shOff + 8);
            uint32_t virtualAddress = readLE<uint32_t>(shOff + 12);
            uint32_t sizeOfRawData = readLE<uint32_t>(shOff + 16);
            uint32_t pointerToRawData = readLE<uint32_t>(shOff + 20);
            sec.addr = m_peHeader.imageBase + virtualAddress;
            sec.size = sizeOfRawData;
            sec.align = virtualSize ? virtualSize : sizeOfRawData;
            sec.offset = pointerToRawData;
            sec.reloff = readLE<uint32_t>(shOff + 24);
            sec.nreloc = readLE<uint16_t>(shOff + 32);
            sec.flags = readLE<uint32_t>(shOff + 36);
            imageSeg.sections.push_back(std::move(sec));
        }
        m_segments.push_back(std::move(imageSeg));

        if (m_entryPoint && m_funcMap.find(m_entryPoint) == m_funcMap.end())
            m_funcMap[m_entryPoint] = "entry_point";

        if (!m_peHeader.dataDirectories.empty()) {
            if (m_peHeader.dataDirectories.size() > 0)
                parsePEExports(m_peHeader.dataDirectories[0].rva,
                               m_peHeader.dataDirectories[0].size);
            if (m_peHeader.dataDirectories.size() > 1)
                parsePEImports(m_peHeader.dataDirectories[1].rva,
                               m_peHeader.dataDirectories[1].size);
        }

        buildFunctionMap();
        if (m_entryPoint && m_funcMap.find(m_entryPoint) == m_funcMap.end())
            m_funcMap[m_entryPoint] = "entry_point";
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
                        parsed.name.size() >= 5) {  // skip for short names (ri, rg, re, tess, etc.)
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
                TypeRef useType = parsed.typeRef;
                // Validate struct types (same as N_GSYM)
                auto *rt2 = m_typeTable.resolveType(parsed.typeRef);
                if (rt2 && (rt2->kind == StabsTypeKind::Struct || rt2->kind == StabsTypeKind::Union) &&
                    !rt2->name.empty() && rt2->name.find("$_") == std::string::npos &&
                    parsed.name.size() >= 5) {
                    std::string sn = rt2->name, gn = parsed.name;
                    for (auto &c : sn) c = tolower(c);
                    for (auto &c : gn) c = tolower(c);
                    if (sn.size() > 2 && sn.substr(sn.size()-2) == "_t") sn = sn.substr(0, sn.size()-2);
                    bool related = (gn.find(sn) != std::string::npos || sn.find(gn) != std::string::npos);
                    if (!related && sn.size() >= 4) related = (gn.find(sn.substr(0,4)) != std::string::npos);
                    if (!related) useType = NullType;
                }
                m_typeTable.addGlobal(parsed.name, sym.n_value, useType, true);
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
            // Fix return type: if demangled name starts with "void " but
            // STABS says int, override to void
            if (full.substr(0, 5) == "void " && fn.returnType != NullType) {
                auto *rrt = m_typeTable.resolveType(fn.returnType);
                if (rrt && (rrt->kind == StabsTypeKind::Int || rrt->kind == StabsTypeKind::UInt)) {
                    // Find a void type in the table
                    for (auto &[tref, ti] : m_typeTable.allTypes()) {
                        if (ti.kind == StabsTypeKind::Void) {
                            fn.returnType = tref;
                            break;
                        }
                    }
                }
            }
            // Only process if demangled name has parameter list
            if (fn.params.empty()) continue;
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
                // Check if demangled type says float but STABS says int (CU type mismatch)
                std::string &dType = paramTypes[pi];
                {
                    std::string dt = dType;
                    if (dt.compare(0, 6, "const ") == 0) dt = dt.substr(6);
                    if (dt.compare(0, 9, "volatile ") == 0) dt = dt.substr(9);
                    if (dt == "float" || dt == "double") {
                        // Mark parameter as float by storing the demangled name info
                        // The decompiler's Call emission handles the actual cast
                        continue;
                    }
                }
                // Check if demangled type suggests a struct pointer
                if (dType.find('*') == std::string::npos) continue;
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
                                if (sn.size() >= 3 && gn.size() >= 5) {  // skip for short names
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
        auto secs = allSections();
        for (auto &sym : m_symbols) {
            if (sym.n_type & N_STAB) continue;
            if ((sym.n_type & N_TYPE) == N_SECT && sym.n_value) {
                int secIdx = sym.n_sect > 0 ? (int)sym.n_sect - 1 : -1;
                if (secIdx >= 0 && secIdx < (int)secs.size() &&
                    !isCodeSection(*secs[secIdx]))
                    continue;
                if (m_funcMap.find(sym.n_value) == m_funcMap.end())
                    m_funcMap[sym.n_value] = demangleNameOnly(sym.name);
            }
        }
        // Resolve import stubs via indirect symbol table
        if (isMachO())
            resolveImportStubs();
        if (isPE()) {
            discoverFunctionStartsFromCalls();
            discoverFunctionStartsFromPadding();
        }
    }

    void discoverFunctionStartsFromCalls() {
        csh cs = 0;
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs) != CS_ERR_OK) return;
        cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

        for (const Section *sec : allSections()) {
            if (!sec || !isCodeSection(*sec) || sec->size == 0) continue;
            const uint8_t *code = bytesAt(sec->offset, sec->size);
            if (!code) continue;

            cs_insn *insn = nullptr;
            size_t count = cs_disasm(cs, code, sec->size, sec->addr, 0, &insn);
            if (count == 0) continue;

            for (size_t i = 0; i < count; ++i) {
                if (!insn[i].detail) continue;
                if (std::string(insn[i].mnemonic) != "call") continue;
                if (insn[i].detail->x86.op_count == 0) continue;
                if (insn[i].detail->x86.operands[0].type != X86_OP_IMM) continue;
                uint32_t tgt = (uint32_t)insn[i].detail->x86.operands[0].imm;
                const Section *tsec = sectionForAddress(tgt);
                if (!tsec || !isCodeSection(*tsec)) continue;
                if (m_funcMap.count(tgt)) continue;
                char buf[32];
                snprintf(buf, sizeof(buf), "sub_%08X", tgt);
                m_funcMap[tgt] = buf;
            }

            cs_free(insn, count);
        }

        cs_close(&cs);
    }

    static bool isPaddingByte(uint8_t b) {
        return b == 0x90 || b == 0xCC || b == 0x00;
    }

    static bool isTerminatorByte(uint8_t b) {
        switch (b) {
        case 0xC2:
        case 0xC3:
        case 0xCA:
        case 0xCB:
        case 0xE9:
        case 0xEB:
            return true;
        default:
            return false;
        }
    }

    static bool looksLikeFunctionHead(const uint8_t *code, size_t len) {
        if (!code || len == 0) return false;
        if (len >= 5 &&
            code[0] == 0x8B && code[1] == 0xFF &&
            code[2] == 0x55 && code[3] == 0x8B && code[4] == 0xEC)
            return true;
        if (len >= 3 &&
            code[0] == 0x55 && code[1] == 0x8B && code[2] == 0xEC)
            return true;
        if (len >= 3 &&
            code[0] == 0x55 && code[1] == 0x89 && code[2] == 0xE5)
            return true;
        if (len >= 2 && code[0] == 0x81 && code[1] == 0xEC)
            return true;
        if (len >= 2 && code[0] == 0x83 && code[1] == 0xEC)
            return true;
        switch (code[0]) {
        case 0x51:
        case 0x52:
        case 0x53:
        case 0x55:
        case 0x56:
        case 0x57:
            return true;
        default:
            return false;
        }
    }

    void discoverFunctionStartsFromPadding() {
        for (const Section *sec : allSections()) {
            if (!sec || !isCodeSection(*sec) || sec->size == 0) continue;
            const uint8_t *code = bytesAt(sec->offset, sec->size);
            if (!code) continue;

            for (uint32_t i = 0; i < sec->size; ++i) {
                uint32_t addr = sec->addr + i;
                if (m_funcMap.count(addr)) continue;
                if (isPaddingByte(code[i])) continue;

                uint32_t padStart = i;
                while (padStart > 0 && isPaddingByte(code[padStart - 1]))
                    --padStart;

                uint32_t padLen = i - padStart;
                if (padLen < 4) continue;
                if (padStart > 0 && !isTerminatorByte(code[padStart - 1]))
                    continue;
                if (!looksLikeFunctionHead(code + i, sec->size - i))
                    continue;

                char buf[32];
                snprintf(buf, sizeof(buf), "sub_%08X", addr);
                m_funcMap[addr] = buf;
            }
        }
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
        if (!sec || !isDataSection(*sec)) return "";
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
        auto secs = allSections();
        for (auto &sym : m_symbols) {
            if (sym.n_value == 0 || sym.name.empty()) continue;
            if (sym.n_type & 0xE0) continue;  // Skip STABS
            if ((sym.n_type & 0x0E) == 0x0E) {
                int secIdx = sym.n_sect > 0 ? (int)sym.n_sect - 1 : -1;
                if (secIdx >= 0 && secIdx < (int)secs.size() &&
                    isCodeSection(*secs[secIdx]))
                    continue;
            } else if ((sym.n_type & N_TYPE) != N_UNDF || sym.n_value == 0) {
                continue;
            }
            std::string name = sym.name;
            if (!name.empty() && name[0] == '_') name = name.substr(1);
            if (name.find(':') != std::string::npos) continue;
            // Demangle C++ names
            std::string demangled = demangleNameOnly(sym.name);
            if (!demangled.empty() && demangled != sym.name) name = demangled;
            m_dataSymMap[sym.n_value] = name;
        }
        // Also resolve import pointer targets: map import ptr address → target name
        if (isPE()) return;
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
    BinaryFormat        m_format = BinaryFormat::Unknown;
    MachHeader          m_header{};
    PEHeader            m_peHeader{};
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
