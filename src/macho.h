#pragma once
#include "demangle.h"
#include "elf_dwarf.h"
#include "stabs_types.h"
#include <capstone/capstone.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <map>
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
    uint32_t n_size = 0;
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
    ELF32,
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
    bool isRegparm = false;  // true if function uses regparm(3) calling convention
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
    bool                     isELF()      const { return m_format == BinaryFormat::ELF32; }
    const PEHeader&          peHeader()   const { return m_peHeader; }
    const ELFHeader&         elfHeader()  const { return m_elfHeader; }
    const std::vector<ELFProgramHeader>& elfProgramHeaders() const { return m_elfProgramHeaders; }
    const MachHeader&        header()     const { return m_header; }
    const std::vector<LoadCommand>& loadCommands() const { return m_loadCmds; }
    const std::vector<Segment>&     segments()     const { return m_segments; }
    const std::vector<NList>&       symbols()      const { return m_symbols; }
    const std::vector<Dylib>&       dylibs()       const { return m_dylibs; }
    const std::vector<StabsFunction>&   stabsFunctions()   const { return m_stabsFuncs; }
    const std::vector<StabsSourceFile>& stabsSourceFiles() const { return m_stabsSources; }
    const StabsTypeTable&               typeTable()        const { return m_typeTable; }
    StabsTypeTable&                     mutableTypeTable()        { return m_typeTable; }
    uint32_t entryPoint() const { return m_entryPoint; }
    const std::vector<DataDirectoryEntry>& dataDirectories() const {
        return m_peHeader.dataDirectories;
    }

    const char* formatName() const {
        switch (m_format) {
        case BinaryFormat::MachO32: return "Mach-O i386";
        case BinaryFormat::PE32:    return "PE32 i386";
        case BinaryFormat::ELF32:   return "ELF32 i386";
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
        if (isELF()) {
            return (sec.flags & SHF_EXECINSTR) || sec.sectname == ".text" ||
                   sec.sectname == ".init" || sec.sectname == ".fini" ||
                   sec.sectname == ".plt" || sec.sectname == ".plt.sec";
        }
        return (sec.flags & 0x80000000) || (sec.flags & 0x00000400) ||
               ((sec.flags & 0xFF) == 0 && sec.sectname.find("text") != std::string::npos);
    }

    bool isTextSection(const Section &sec) const {
        if (isPE()) return sec.sectname == ".text" || isCodeSection(sec);
        if (isELF()) return sec.sectname == ".text" || isCodeSection(sec);
        return sec.sectname == "__text" || sec.sectname == "__textcoal_nt" || isCodeSection(sec);
    }

    bool isImportSection(const Section &sec) const {
        if (isPE()) {
            return sec.sectname == ".idata" || sec.sectname == ".didat" ||
                   sec.sectname == ".rdata";
        }
        if (isELF()) {
            return sec.sectname == ".plt" || sec.sectname == ".plt.sec" ||
                   sec.sectname == ".got" || sec.sectname == ".got.plt" ||
                   sec.sectname == ".dynamic" || sec.sectname == ".dynsym" ||
                   sec.sectname == ".dynstr";
        }
        return sec.segname == "__IMPORT";
    }

    bool isCStringSection(const Section &sec) const {
        if (isPE())
            return sec.sectname == ".rdata" || sec.sectname == ".data" ||
                   sec.sectname == ".idata";
        if (isELF())
            return sec.sectname == ".rodata" ||
                   sec.sectname.find(".rodata.") == 0 ||
                   sec.sectname == ".data.rel.ro" ||
                   sec.sectname.find(".data.rel.ro.") == 0 ||
                   sec.sectname == ".data";
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
        if (isELF()) {
            return (sec.flags & SHF_ALLOC) &&
                   (sec.sectname == ".data" || sec.sectname == ".rodata" ||
                    sec.sectname.find(".rodata.") == 0 ||
                    sec.sectname == ".data.rel.ro" ||
                    sec.sectname.find(".data.rel.ro.") == 0 ||
                    sec.sectname == ".bss" || sec.sectname == ".got" ||
                    sec.sectname == ".got.plt" || sec.sectname == ".dynamic" ||
                    sec.sectname == ".init_array" || sec.sectname == ".fini_array" ||
                    sec.sectname == ".ctors" || sec.sectname == ".dtors" ||
                    (sec.flags & SHF_WRITE));
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

    std::string symbolDisplayName(const std::string &name, bool nameOnly = true) const {
        if (isELF() && name.rfind("_Z", 0) != 0 && name.rfind("__Z", 0) != 0)
            return name;
        return nameOnly ? demangleNameOnly(name) : demangle(name);
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

    static const char* elfTypeName(uint16_t type) {
        switch (type) {
        case ET_REL:  return "ET_REL";
        case ET_EXEC: return "ET_EXEC";
        case ET_DYN:  return "ET_DYN";
        default:      return "UNKNOWN";
        }
    }

    static const char* elfMachineName(uint16_t machine) {
        switch (machine) {
        case EM_386: return "i386";
        default:     return "unknown";
        }
    }

    static const char* elfProgramTypeName(uint32_t type) {
        switch (type) {
        case PT_LOAD:    return "PT_LOAD";
        case PT_DYNAMIC: return "PT_DYNAMIC";
        case PT_INTERP:  return "PT_INTERP";
        case PT_NOTE:    return "PT_NOTE";
        case PT_PHDR:    return "PT_PHDR";
        default:         return "PT_UNKNOWN";
        }
    }

    static std::string elfProgramFlagsString(uint32_t flags) {
        std::string out;
        if (flags & PF_R) out += "R";
        if (flags & PF_W) out += "W";
        if (flags & PF_X) out += "X";
        return out.empty() ? "-" : out;
    }

private:
    uint32_t sectionAddressSpan(const Section &sec) const {
        if (isPE() && sec.segname == "IMAGE")
            return sec.align ? sec.align : sec.size;
        if (isELF())
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
        m_elfHeader = {};
        m_elfProgramHeaders.clear();
        m_loadCmds.clear();
        m_segments.clear();
        m_symbols.clear();
        m_dataSymMap.clear();
        m_dylibs.clear();
        m_symoff = m_nsyms = m_stroff = m_strsize = 0;
        m_elfSectionToFlat.clear();
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

    std::string stringAtBounded(uint32_t stroff, uint32_t strsize, uint32_t idx) const {
        if (idx >= strsize || stroff > m_size) return "";
        uint64_t pos64 = (uint64_t)stroff + idx;
        if (pos64 >= m_size) return "";
        size_t pos = (size_t)pos64;
        size_t maxlen = std::min<size_t>(strsize - idx, m_size - pos);
        const char *s = reinterpret_cast<const char*>(m_data.data() + pos);
        return std::string(s, strnlen(s, maxlen));
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
        if (m_size >= 52 && readLE<uint32_t>(0) == ELF_MAGIC_LE)
            return parseELF();
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
                    m_funcMap[addr] = symbolDisplayName(name);
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

    static uint8_t elfSymbolType(uint8_t info) {
        return info & 0x0F;
    }

    void addELFSymbol(const std::string &name, uint32_t nameIdx, uint8_t info,
                      uint16_t shndx, uint32_t value, uint32_t size) {
        uint8_t stype = elfSymbolType(info);
        if (stype == STT_FILE) return;
        if (name.empty() && stype != STT_SECTION) return;

        NList sym{};
        sym.n_strx = nameIdx;
        sym.n_desc = info;
        sym.n_value = value;
        sym.n_size = size;
        sym.name = name;

        if (shndx == SHN_UNDEF) {
            sym.n_type = N_UNDF;
            sym.n_sect = 0;
        } else if (shndx == SHN_ABS) {
            sym.n_type = N_ABS;
            sym.n_sect = 0;
        } else {
            sym.n_type = N_SECT;
            sym.n_sect = (shndx < m_elfSectionToFlat.size())
                ? m_elfSectionToFlat[shndx] : 0;
        }

        for (const auto &existing : m_symbols) {
            if (existing.n_type == sym.n_type && existing.n_sect == sym.n_sect &&
                existing.n_value == sym.n_value && existing.n_size == sym.n_size &&
                existing.name == sym.name)
                return;
        }
        m_symbols.push_back(std::move(sym));
    }

    std::string elfSymbolName(const std::vector<ELFSectionRecord> &sections,
                              uint32_t symtabIdx, uint32_t symIdx) const {
        if (symtabIdx >= sections.size()) return "";
        const auto &symtab = sections[symtabIdx];
        if (symtab.entsize < 16 || symtab.link >= sections.size()) return "";
        uint64_t symOff = (uint64_t)symtab.offset + (uint64_t)symIdx * symtab.entsize;
        if (symOff + 16 > m_size || symOff + 16 > (uint64_t)symtab.offset + symtab.size)
            return "";
        const auto &strtab = sections[symtab.link];
        uint32_t nameIdx = readLE<uint32_t>((size_t)symOff);
        return stringAtBounded(strtab.offset, strtab.size, nameIdx);
    }

    const ELFSectionRecord* findELFSection(const std::vector<ELFSectionRecord> &sections,
                                           const std::string &name) const {
        for (const auto &sec : sections)
            if (sec.name == name)
                return &sec;
        return nullptr;
    }

    uint64_t readULEB(size_t &pos, size_t end) const {
        uint64_t result = 0;
        unsigned shift = 0;
        while (pos < end && shift < 64) {
            uint8_t b = m_data[pos++];
            result |= (uint64_t)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        return result;
    }

    uint64_t readULEBFromBlock(const std::vector<uint8_t> &block, size_t &pos) const {
        uint64_t result = 0;
        unsigned shift = 0;
        while (pos < block.size() && shift < 64) {
            uint8_t b = block[pos++];
            result |= (uint64_t)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        return result;
    }

    int64_t readSLEB(size_t &pos, size_t end) const {
        int64_t result = 0;
        unsigned shift = 0;
        uint8_t b = 0;
        while (pos < end && shift < 64) {
            b = m_data[pos++];
            result |= (int64_t)(b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0) break;
        }
        if (shift < 64 && (b & 0x40))
            result |= -((int64_t)1 << shift);
        return result;
    }

    int64_t readSLEBFromBlock(const std::vector<uint8_t> &block, size_t &pos) const {
        int64_t result = 0;
        unsigned shift = 0;
        uint8_t b = 0;
        while (pos < block.size() && shift < 64) {
            b = block[pos++];
            result |= (int64_t)(b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0) break;
        }
        if (shift < 64 && (b & 0x40))
            result |= -((int64_t)1 << shift);
        return result;
    }

    uint64_t readUIntLE(size_t pos, size_t width) const {
        uint64_t value = 0;
        for (size_t i = 0; i < width && pos + i < m_size && i < 8; ++i)
            value |= (uint64_t)m_data[pos + i] << (i * 8);
        return value;
    }

    uint64_t readBlockUIntLE(const std::vector<uint8_t> &block, size_t pos, size_t width) const {
        uint64_t value = 0;
        for (size_t i = 0; i < width && pos + i < block.size() && i < 8; ++i)
            value |= (uint64_t)block[pos + i] << (i * 8);
        return value;
    }

    std::string stringFromSection(const ELFSectionRecord *sec, uint64_t off) const {
        if (!sec || off >= sec->size) return "";
        return stringAtBounded(sec->offset, sec->size, (uint32_t)off);
    }

    static bool isAbsolutePath(const std::string &path) {
        return !path.empty() && (path[0] == '/' || path[0] == '\\' ||
               (path.size() > 2 && path[1] == ':'));
    }

    static std::string joinPath(const std::string &dir, const std::string &name) {
        if (name.empty() || isAbsolutePath(name) || dir.empty())
            return name;
        if (dir.back() == '/' || dir.back() == '\\')
            return dir + name;
        return dir + "/" + name;
    }

    int sourceIndexForPath(const std::string &path, uint32_t address = 0) {
        std::string norm = path;
        for (char &c : norm) if (c == '\\') c = '/';
        std::string dir;
        std::string file = norm;
        size_t slash = norm.rfind('/');
        if (slash != std::string::npos) {
            dir = norm.substr(0, slash + 1);
            file = norm.substr(slash + 1);
        }
        for (size_t i = 0; i < m_stabsSources.size(); ++i) {
            if (m_stabsSources[i].directory == dir && m_stabsSources[i].filename == file)
                return (int)i;
        }
        StabsSourceFile sf;
        sf.directory = dir;
        sf.filename = file.empty() ? norm : file;
        sf.address = address;
        m_stabsSources.push_back(std::move(sf));
        return (int)m_stabsSources.size() - 1;
    }

    std::map<uint64_t, DwarfAbbrev> parseDwarfAbbrevs(const ELFSectionRecord *debugAbbrev,
                                                       uint32_t abbrevOffset) const {
        std::map<uint64_t, DwarfAbbrev> out;
        if (!debugAbbrev || abbrevOffset >= debugAbbrev->size) return out;
        size_t pos = debugAbbrev->offset + abbrevOffset;
        size_t end = debugAbbrev->offset + debugAbbrev->size;
        while (pos < end) {
            uint64_t code = readULEB(pos, end);
            if (code == 0) break;
            DwarfAbbrev abbr;
            abbr.code = code;
            abbr.tag = readULEB(pos, end);
            if (pos >= end) break;
            abbr.hasChildren = m_data[pos++] == DW_CHILDREN_yes;
            while (pos < end) {
                DwarfAbbrevAttr attr;
                attr.name = readULEB(pos, end);
                attr.form = readULEB(pos, end);
                if (attr.name == 0 && attr.form == 0)
                    break;
                if (attr.form == DW_FORM_implicit_const)
                    attr.implicitConst = readSLEB(pos, end);
                abbr.attrs.push_back(attr);
            }
            out[abbr.code] = std::move(abbr);
        }
        return out;
    }

    DwarfValue readDwarfFormValue(size_t &pos, size_t end, uint64_t form,
                                  int64_t implicitConst, uint8_t addressSize,
                                  const ELFSectionRecord *debugStr,
                                  const ELFSectionRecord *debugLineStr) const {
        DwarfValue value;
        value.form = form;
        value.present = true;
        if (form == DW_FORM_indirect) {
            uint64_t actual = readULEB(pos, end);
            return readDwarfFormValue(pos, end, actual, 0, addressSize, debugStr, debugLineStr);
        }

        auto need = [&](size_t n) -> bool {
            return pos + n <= end && pos + n <= m_size;
        };

        switch (form) {
        case DW_FORM_addr:
            if (need(addressSize)) {
                value.u = readUIntLE(pos, addressSize);
                value.s = (int64_t)value.u;
                pos += addressSize;
            }
            break;
        case DW_FORM_data1:
        case DW_FORM_flag:
        case DW_FORM_ref1:
        case DW_FORM_strx1:
        case DW_FORM_addrx1:
            if (need(1)) { value.u = readLE<uint8_t>(pos); value.s = (int64_t)value.u; pos += 1; }
            break;
        case DW_FORM_data2:
        case DW_FORM_ref2:
        case DW_FORM_strx2:
        case DW_FORM_addrx2:
            if (need(2)) { value.u = readLE<uint16_t>(pos); value.s = (int64_t)value.u; pos += 2; }
            break;
        case DW_FORM_data4:
        case DW_FORM_ref4:
        case DW_FORM_ref_addr:
        case DW_FORM_sec_offset:
        case DW_FORM_strp:
        case DW_FORM_line_strp:
        case DW_FORM_strx4:
        case DW_FORM_addrx4:
        case DW_FORM_ref_sup4:
        case DW_FORM_strp_sup:
            if (need(4)) { value.u = readLE<uint32_t>(pos); value.s = (int64_t)value.u; pos += 4; }
            if (form == DW_FORM_strp) {
                value.str = stringFromSection(debugStr, value.u);
                value.isString = true;
            } else if (form == DW_FORM_line_strp) {
                value.str = stringFromSection(debugLineStr, value.u);
                value.isString = true;
            }
            break;
        case DW_FORM_data8:
        case DW_FORM_ref8:
        case DW_FORM_ref_sig8:
        case DW_FORM_ref_sup8:
            if (need(8)) { value.u = readLE<uint64_t>(pos); value.s = (int64_t)value.u; pos += 8; }
            break;
        case DW_FORM_data16:
            if (need(16)) pos += 16;
            break;
        case DW_FORM_sdata:
            value.s = readSLEB(pos, end);
            value.u = (uint64_t)value.s;
            break;
        case DW_FORM_udata:
        case DW_FORM_ref_udata:
        case DW_FORM_strx:
        case DW_FORM_addrx:
        case DW_FORM_loclistx:
        case DW_FORM_rnglistx:
            value.u = readULEB(pos, end);
            value.s = (int64_t)value.u;
            break;
        case DW_FORM_string:
            if (pos < end && pos < m_size) {
                value.str = readString(pos);
                value.isString = true;
                pos += value.str.size() + 1;
            }
            break;
        case DW_FORM_flag_present:
            value.u = 1;
            value.s = 1;
            break;
        case DW_FORM_implicit_const:
            value.s = implicitConst;
            value.u = (uint64_t)implicitConst;
            break;
        case DW_FORM_block1:
            if (need(1)) {
                uint8_t n = readLE<uint8_t>(pos);
                pos += 1;
                size_t avail = std::min<size_t>(n, end > pos ? end - pos : 0);
                value.block.assign(m_data.begin() + pos, m_data.begin() + pos + avail);
                pos += avail;
            }
            break;
        case DW_FORM_block2:
            if (need(2)) {
                uint16_t n = readLE<uint16_t>(pos);
                pos += 2;
                size_t avail = std::min<size_t>(n, end > pos ? end - pos : 0);
                value.block.assign(m_data.begin() + pos, m_data.begin() + pos + avail);
                pos += avail;
            }
            break;
        case DW_FORM_block4:
            if (need(4)) {
                uint32_t n = readLE<uint32_t>(pos);
                pos += 4;
                size_t avail = std::min<size_t>(n, end > pos ? end - pos : 0);
                value.block.assign(m_data.begin() + pos, m_data.begin() + pos + avail);
                pos += avail;
            }
            break;
        case DW_FORM_block:
        case DW_FORM_exprloc: {
            uint64_t n = readULEB(pos, end);
            size_t avail = (size_t)std::min<uint64_t>(n, end > pos ? end - pos : 0);
            value.block.assign(m_data.begin() + pos, m_data.begin() + pos + avail);
            pos += avail;
            break;
        }
        case DW_FORM_strx3:
        case DW_FORM_addrx3:
            if (need(3)) {
                value.u = readUIntLE(pos, 3);
                value.s = (int64_t)value.u;
                pos += 3;
            }
            break;
        default:
            value.present = false;
            break;
        }
        if (pos > end) pos = end;
        return value;
    }

    std::string dwarfStringAttr(const std::map<uint64_t, DwarfValue> &attrs,
                                uint64_t attr) const {
        auto it = attrs.find(attr);
        if (it == attrs.end()) return "";
        if (it->second.isString) return it->second.str;
        return "";
    }

    uint64_t dwarfUnsignedAttr(const std::map<uint64_t, DwarfValue> &attrs,
                               uint64_t attr, uint64_t def = 0) const {
        auto it = attrs.find(attr);
        return it != attrs.end() && it->second.present ? it->second.u : def;
    }

    bool dwarfHasAttr(const std::map<uint64_t, DwarfValue> &attrs, uint64_t attr) const {
        auto it = attrs.find(attr);
        return it != attrs.end() && it->second.present;
    }

    TypeRef dwarfTypeRefForOffset(std::map<uint32_t, TypeRef> &typeRefs,
                                  uint32_t dieOffset) {
        auto it = typeRefs.find(dieOffset);
        if (it != typeRefs.end())
            return it->second;
        TypeRef ref = m_typeTable.createSyntheticType();
        typeRefs[dieOffset] = ref;
        return ref;
    }

    TypeRef dwarfBuiltinVoidType(std::map<uint32_t, TypeRef> &typeRefs) {
        constexpr uint32_t kVoidOffset = 0xFFFFFF00u;
        TypeRef ref = dwarfTypeRefForOffset(typeRefs, kVoidOffset);
        if (auto *ti = m_typeTable.getMutableType(ref)) {
            ti->kind = StabsTypeKind::Void;
            ti->name = "void";
            ti->sizeBytes = 0;
        }
        return ref;
    }

    uint32_t dwarfRefOffset(const DwarfUnit &unit, const DwarfValue &value) const {
        switch (value.form) {
        case DW_FORM_ref1:
        case DW_FORM_ref2:
        case DW_FORM_ref4:
        case DW_FORM_ref8:
        case DW_FORM_ref_udata:
            return unit.offset + (uint32_t)value.u;
        case DW_FORM_ref_addr:
            return (uint32_t)value.u;
        default:
            return unit.offset + (uint32_t)value.u;
        }
    }

    TypeRef dwarfTypeAttr(const DwarfUnit &unit,
                          const std::map<uint64_t, DwarfValue> &attrs,
                          uint64_t attr,
                          std::map<uint32_t, TypeRef> &typeRefs) {
        auto it = attrs.find(attr);
        if (it == attrs.end() || !it->second.present)
            return NullType;
        return dwarfTypeRefForOffset(typeRefs, dwarfRefOffset(unit, it->second));
    }

    StabsTypeKind dwarfBaseKind(uint64_t encoding, uint64_t sizeBytes,
                                const std::string &name) const {
        if (name == "void") return StabsTypeKind::Void;
        if (name == "bool" || name == "_Bool") return StabsTypeKind::Bool;
        if (name.find("long long") != std::string::npos)
            return encoding == DW_ATE_unsigned ? StabsTypeKind::ULongLong
                                                : StabsTypeKind::LongLong;
        if (name.find("long") != std::string::npos)
            return encoding == DW_ATE_unsigned ? StabsTypeKind::ULong
                                                : StabsTypeKind::Long;
        if (encoding == DW_ATE_float)
            return sizeBytes > 4 ? StabsTypeKind::Double : StabsTypeKind::Float;
        if (encoding == DW_ATE_boolean) return StabsTypeKind::Bool;
        if (encoding == DW_ATE_signed_char) return StabsTypeKind::Char;
        if (encoding == DW_ATE_unsigned_char) return StabsTypeKind::UChar;
        if (encoding == DW_ATE_unsigned) {
            if (sizeBytes <= 1) return StabsTypeKind::UChar;
            if (sizeBytes == 2) return StabsTypeKind::UShort;
            if (sizeBytes == 4) return StabsTypeKind::UInt;
            if (sizeBytes >= 8) return StabsTypeKind::ULongLong;
            return StabsTypeKind::UInt;
        }
        if (encoding == DW_ATE_signed || encoding == DW_ATE_address) {
            if (sizeBytes <= 1) return StabsTypeKind::Char;
            if (sizeBytes == 2) return StabsTypeKind::Short;
            if (sizeBytes == 4) return StabsTypeKind::Int;
            if (sizeBytes >= 8) return StabsTypeKind::LongLong;
            return StabsTypeKind::Int;
        }
        return StabsTypeKind::Unknown;
    }

    uint32_t dwarfLocationAddress(const DwarfValue &value, uint8_t addressSize) const {
        if (value.block.size() >= 1 + addressSize && value.block[0] == DW_OP_addr)
            return (uint32_t)readBlockUIntLE(value.block, 1, addressSize);
        return 0;
    }

    bool dwarfLocationFBReg(const DwarfValue &value, int &offset) const {
        if (value.block.empty() || value.block[0] != DW_OP_fbreg)
            return false;
        size_t pos = 1;
        offset = (int)readSLEBFromBlock(value.block, pos);
        return true;
    }

    bool dwarfBlockConstValue(const std::vector<uint8_t> &block,
                              int64_t &out) const {
        if (block.empty()) return false;
        size_t pos = 1;
        switch (block[0]) {
        case DW_OP_plus_uconst:
        case DW_OP_constu:
            out = (int64_t)readULEBFromBlock(block, pos);
            return true;
        case DW_OP_consts:
            out = readSLEBFromBlock(block, pos);
            return true;
        case DW_OP_const1u:
            if (block.size() >= 2) { out = block[1]; return true; }
            return false;
        case DW_OP_const1s:
            if (block.size() >= 2) { out = (int8_t)block[1]; return true; }
            return false;
        case DW_OP_const2u:
            if (block.size() >= 3) { out = (int64_t)readBlockUIntLE(block, 1, 2); return true; }
            return false;
        case DW_OP_const2s:
            if (block.size() >= 3) { out = (int16_t)readBlockUIntLE(block, 1, 2); return true; }
            return false;
        case DW_OP_const4u:
            if (block.size() >= 5) { out = (int64_t)readBlockUIntLE(block, 1, 4); return true; }
            return false;
        case DW_OP_const4s:
            if (block.size() >= 5) { out = (int32_t)readBlockUIntLE(block, 1, 4); return true; }
            return false;
        default:
            break;
        }

        // Some producers spell member offsets as "const, plus".
        if ((block[0] == DW_OP_constu || block[0] == DW_OP_consts ||
             block[0] == DW_OP_const1u || block[0] == DW_OP_const1s ||
             block[0] == DW_OP_const2u || block[0] == DW_OP_const2s ||
             block[0] == DW_OP_const4u || block[0] == DW_OP_const4s) &&
            block.back() == DW_OP_plus) {
            std::vector<uint8_t> prefix(block.begin(), block.end() - 1);
            return dwarfBlockConstValue(prefix, out);
        }
        return false;
    }

    bool dwarfDataMemberByteOffset(const DwarfValue &value, int &offset) const {
        if (!value.block.empty()) {
            int64_t v = 0;
            if (!dwarfBlockConstValue(value.block, v))
                return false;
            offset = (int)v;
            return true;
        }
        offset = (int)value.u;
        return true;
    }

    void fillDwarfType(uint32_t dieOffset, uint64_t tag,
                       const DwarfUnit &unit,
                       const std::map<uint64_t, DwarfValue> &attrs,
                       std::map<uint32_t, TypeRef> &typeRefs) {
        TypeRef ref = dwarfTypeRefForOffset(typeRefs, dieOffset);
        StabsTypeInfo *ti = m_typeTable.getMutableType(ref);
        if (!ti) return;

        std::string name = dwarfStringAttr(attrs, DW_AT_name);
        uint32_t sizeBytes = (uint32_t)dwarfUnsignedAttr(attrs, DW_AT_byte_size, ti->sizeBytes);

        switch (tag) {
        case DW_TAG_base_type: {
            uint64_t encoding = dwarfUnsignedAttr(attrs, DW_AT_encoding, 0);
            ti->kind = dwarfBaseKind(encoding, sizeBytes, name);
            ti->name = name;
            ti->sizeBytes = (int)sizeBytes;
            break;
        }
        case DW_TAG_pointer_type:
            ti->kind = StabsTypeKind::Pointer;
            ti->name.clear();
            ti->sizeBytes = unit.addressSize;
            ti->targetType = dwarfTypeAttr(unit, attrs, DW_AT_type, typeRefs);
            if (ti->targetType == NullType)
                ti->targetType = dwarfBuiltinVoidType(typeRefs);
            break;
        case DW_TAG_reference_type:
            ti->kind = StabsTypeKind::Reference;
            ti->sizeBytes = unit.addressSize;
            ti->targetType = dwarfTypeAttr(unit, attrs, DW_AT_type, typeRefs);
            break;
        case DW_TAG_const_type:
            ti->kind = StabsTypeKind::Const;
            ti->targetType = dwarfTypeAttr(unit, attrs, DW_AT_type, typeRefs);
            if (ti->targetType == NullType)
                ti->targetType = dwarfBuiltinVoidType(typeRefs);
            break;
        case DW_TAG_volatile_type:
            ti->kind = StabsTypeKind::Volatile;
            ti->targetType = dwarfTypeAttr(unit, attrs, DW_AT_type, typeRefs);
            break;
        case DW_TAG_typedef:
            ti->kind = StabsTypeKind::Typedef;
            ti->name = name;
            ti->targetType = dwarfTypeAttr(unit, attrs, DW_AT_type, typeRefs);
            break;
        case DW_TAG_structure_type:
        case DW_TAG_class_type:
            ti->kind = StabsTypeKind::Struct;
            ti->name = name;
            ti->sizeBytes = (int)sizeBytes;
            break;
        case DW_TAG_union_type:
            ti->kind = StabsTypeKind::Union;
            ti->name = name;
            ti->sizeBytes = (int)sizeBytes;
            break;
        case DW_TAG_enumeration_type:
            ti->kind = StabsTypeKind::Enum;
            ti->name = name;
            ti->sizeBytes = (int)sizeBytes;
            break;
        case DW_TAG_array_type:
            ti->kind = StabsTypeKind::Array;
            ti->targetType = dwarfTypeAttr(unit, attrs, DW_AT_type, typeRefs);
            ti->arrayLow = 0;
            ti->arrayHigh = -1;
            break;
        case DW_TAG_subroutine_type:
            ti->kind = StabsTypeKind::Function;
            ti->targetType = dwarfTypeAttr(unit, attrs, DW_AT_type, typeRefs);
            if (ti->targetType == NullType)
                ti->targetType = dwarfBuiltinVoidType(typeRefs);
            break;
        default:
            break;
        }
    }

    void addDwarfMember(TypeRef compositeType,
                        const DwarfUnit &unit,
                        const std::map<uint64_t, DwarfValue> &attrs,
                        std::map<uint32_t, TypeRef> &typeRefs) {
        if (compositeType == NullType) return;
        StabsTypeInfo *ti = m_typeTable.getMutableType(compositeType);
        if (!ti || (ti->kind != StabsTypeKind::Struct && ti->kind != StabsTypeKind::Union))
            return;
        StabsTypeField field;
        field.name = dwarfStringAttr(attrs, DW_AT_name);
        field.typeRef = dwarfTypeAttr(unit, attrs, DW_AT_type, typeRefs);
        if (ti->kind == StabsTypeKind::Union) {
            field.bitOffset = 0;
        } else {
            if (dwarfHasAttr(attrs, DW_AT_data_bit_offset)) {
                field.bitOffset = (int)dwarfUnsignedAttr(attrs, DW_AT_data_bit_offset);
            } else {
                auto it = attrs.find(DW_AT_data_member_location);
                if (it != attrs.end() && it->second.present) {
                    int byteOffset = 0;
                    if (dwarfDataMemberByteOffset(it->second, byteOffset))
                        field.bitOffset = byteOffset * 8;
                }
            }
        }
        if (dwarfHasAttr(attrs, DW_AT_bit_size))
            field.bitSize = (int)dwarfUnsignedAttr(attrs, DW_AT_bit_size);
        else if (auto *ft = m_typeTable.resolveType(field.typeRef))
            field.bitSize = ft->sizeBytes > 0 ? ft->sizeBytes * 8 : 0;

        if (!field.name.empty())
            ti->fields.push_back(std::move(field));
    }

    void addDwarfEnumerator(TypeRef enumType,
                            const std::map<uint64_t, DwarfValue> &attrs) {
        if (enumType == NullType) return;
        StabsTypeInfo *ti = m_typeTable.getMutableType(enumType);
        if (!ti || ti->kind != StabsTypeKind::Enum) return;
        StabsEnumVal ev;
        ev.name = dwarfStringAttr(attrs, DW_AT_name);
        auto it = attrs.find(DW_AT_const_value);
        if (it != attrs.end())
            ev.value = it->second.s;
        if (!ev.name.empty())
            ti->enumValues.push_back(std::move(ev));
    }

    void applyDwarfSubrange(TypeRef arrayType,
                            const std::map<uint64_t, DwarfValue> &attrs) {
        if (arrayType == NullType) return;
        StabsTypeInfo *ti = m_typeTable.getMutableType(arrayType);
        if (!ti || ti->kind != StabsTypeKind::Array) return;
        int low = (int)dwarfUnsignedAttr(attrs, DW_AT_lower_bound, 0);
        int high = -1;
        if (dwarfHasAttr(attrs, DW_AT_upper_bound)) {
            high = (int)dwarfUnsignedAttr(attrs, DW_AT_upper_bound);
        } else if (dwarfHasAttr(attrs, DW_AT_count)) {
            int count = (int)dwarfUnsignedAttr(attrs, DW_AT_count);
            high = low + count - 1;
        }
        ti->arrayLow = low;
        ti->arrayHigh = high;
        auto *elem = m_typeTable.resolveType(ti->targetType);
        int count = high >= low ? high - low + 1 : 0;
        if (elem && elem->sizeBytes > 0 && count > 0)
            ti->sizeBytes = elem->sizeBytes * count;
    }

    int dwarfTypeStorageSize(TypeRef ref, int depth = 0) const {
        if (ref == NullType || depth > 12)
            return 0;
        auto *ti = m_typeTable.resolveType(ref);
        if (!ti) return 0;
        if (ti->sizeBytes > 0)
            return ti->sizeBytes;
        if (ti->kind == StabsTypeKind::Array) {
            int elemSize = dwarfTypeStorageSize(ti->targetType, depth + 1);
            int count = ti->arrayHigh >= ti->arrayLow
                ? ti->arrayHigh - ti->arrayLow + 1 : 0;
            return elemSize > 0 && count > 0 ? elemSize * count : 0;
        }
        return 0;
    }

    void finalizeDwarfTypes(const std::map<uint32_t, TypeRef> &typeRefs) {
        for (int pass = 0; pass < 6; ++pass) {
            bool changed = false;
            for (const auto &kv : typeRefs) {
                StabsTypeInfo *ti = m_typeTable.getMutableType(kv.second);
                if (!ti) continue;
                if (ti->kind == StabsTypeKind::Array) {
                    int size = dwarfTypeStorageSize(kv.second);
                    if (size > 0 && ti->sizeBytes != size) {
                        ti->sizeBytes = size;
                        changed = true;
                    }
                } else if (ti->kind == StabsTypeKind::Struct ||
                           ti->kind == StabsTypeKind::Union) {
                    int maxBitEnd = 0;
                    for (auto &field : ti->fields) {
                        if (field.bitSize == 0) {
                            int fieldSize = dwarfTypeStorageSize(field.typeRef);
                            if (fieldSize > 0) {
                                field.bitSize = fieldSize * 8;
                                changed = true;
                            }
                        }
                        if (field.bitSize > 0)
                            maxBitEnd = std::max(maxBitEnd,
                                                 field.bitOffset + field.bitSize);
                    }
                    int byteSize = (maxBitEnd + 7) / 8;
                    if (ti->sizeBytes == 0 && byteSize > 0) {
                        ti->sizeBytes = byteSize;
                        changed = true;
                    }
                }
            }
            if (!changed)
                break;
        }
    }

    std::string readDwarfLineStringEntry(size_t &pos, size_t end,
                                         const std::vector<DwarfAbbrevAttr> &formats,
                                         uint64_t contentType,
                                         const ELFSectionRecord *debugLine,
                                         const ELFSectionRecord *debugLineStr,
                                         uint8_t addressSize,
                                         uint64_t &dirIndex) const {
        std::string text;
        dirIndex = 0;
        for (const auto &fmt : formats) {
            DwarfValue v = readDwarfFormValue(pos, end, fmt.form, fmt.implicitConst,
                                              addressSize, debugLine, debugLineStr);
            if (fmt.name == 0x01 || fmt.name == contentType) { // DW_LNCT_path
                if (v.isString) text = v.str;
                else if (v.form == DW_FORM_line_strp)
                    text = stringFromSection(debugLineStr, v.u);
            } else if (fmt.name == 0x02) { // DW_LNCT_directory_index
                dirIndex = v.u;
            }
        }
        return text;
    }

    DwarfLineTable parseDwarfLineTable(const std::vector<ELFSectionRecord> &sections,
                                       uint32_t offset,
                                       const std::string &compDir) const {
        DwarfLineTable table;
        table.compDir = compDir;
        const ELFSectionRecord *debugLine = findELFSection(sections, ".debug_line");
        const ELFSectionRecord *debugLineStr = findELFSection(sections, ".debug_line_str");
        const ELFSectionRecord *debugStr = findELFSection(sections, ".debug_str");
        if (!debugLine || offset >= debugLine->size) return table;

        size_t pos = debugLine->offset + offset;
        size_t secEnd = debugLine->offset + debugLine->size;
        if (pos + 10 > secEnd || pos + 10 > m_size) return table;

        uint32_t unitLength = readLE<uint32_t>(pos); pos += 4;
        if (unitLength == 0xFFFFFFFF) return table; // DWARF64 not supported here.
        size_t unitEnd = std::min<size_t>(pos + unitLength, secEnd);
        if (unitEnd > m_size || pos + 2 > unitEnd) return table;

        table.version = readLE<uint16_t>(pos); pos += 2;
        if (table.version < 2 || table.version > 5) return table;

        if (table.version >= 5) {
            if (pos + 2 > unitEnd) return table;
            table.addressSize = readLE<uint8_t>(pos); pos += 1;
            pos += 1; // segment selector size
        } else {
            table.addressSize = 4;
        }

        if (pos + 4 > unitEnd) return table;
        uint32_t headerLength = readLE<uint32_t>(pos); pos += 4;
        size_t headerEnd = std::min<size_t>(pos + headerLength, unitEnd);
        if (headerEnd > unitEnd) return table;
        if (pos + (table.version >= 4 ? 6 : 5) > headerEnd) return table;

        uint8_t minInstrLen = readLE<uint8_t>(pos); pos += 1;
        if (table.version >= 4) pos += 1; // max_ops_per_instruction
        uint8_t defaultIsStmt = readLE<uint8_t>(pos); pos += 1;
        int8_t lineBase = (int8_t)readLE<uint8_t>(pos); pos += 1;
        uint8_t lineRange = readLE<uint8_t>(pos); pos += 1;
        uint8_t opcodeBase = readLE<uint8_t>(pos); pos += 1;
        std::vector<uint8_t> stdOpLens(opcodeBase, 0);
        for (uint8_t i = 1; i < opcodeBase && pos < headerEnd; ++i)
            stdOpLens[i] = readLE<uint8_t>(pos++);

        if (table.version < 5) {
            while (pos < headerEnd) {
                std::string dir = readString(pos);
                pos += dir.size() + 1;
                if (dir.empty()) break;
                table.includeDirs.push_back(dir);
            }
            while (pos < headerEnd) {
                std::string name = readString(pos);
                pos += name.size() + 1;
                if (name.empty()) break;
                uint64_t dirIdx = readULEB(pos, headerEnd);
                (void)readULEB(pos, headerEnd); // mtime
                (void)readULEB(pos, headerEnd); // file length
                std::string dir = compDir;
                if (dirIdx > 0 && dirIdx - 1 < table.includeDirs.size())
                    dir = table.includeDirs[(size_t)dirIdx - 1];
                table.files.push_back(joinPath(dir, name));
            }
        } else {
            uint64_t dirFmtCount = readULEB(pos, headerEnd);
            std::vector<DwarfAbbrevAttr> dirFormats;
            for (uint64_t i = 0; i < dirFmtCount && pos < headerEnd; ++i) {
                DwarfAbbrevAttr fmt;
                fmt.name = readULEB(pos, headerEnd);
                fmt.form = readULEB(pos, headerEnd);
                dirFormats.push_back(fmt);
            }
            uint64_t dirCount = readULEB(pos, headerEnd);
            for (uint64_t i = 0; i < dirCount && pos < headerEnd; ++i) {
                uint64_t ignoredDirIndex = 0;
                std::string dir = readDwarfLineStringEntry(pos, headerEnd, dirFormats,
                                                           0x01, debugStr, debugLineStr,
                                                           table.addressSize, ignoredDirIndex);
                table.includeDirs.push_back(dir);
            }

            uint64_t fileFmtCount = readULEB(pos, headerEnd);
            std::vector<DwarfAbbrevAttr> fileFormats;
            for (uint64_t i = 0; i < fileFmtCount && pos < headerEnd; ++i) {
                DwarfAbbrevAttr fmt;
                fmt.name = readULEB(pos, headerEnd);
                fmt.form = readULEB(pos, headerEnd);
                fileFormats.push_back(fmt);
            }
            uint64_t fileCount = readULEB(pos, headerEnd);
            for (uint64_t i = 0; i < fileCount && pos < headerEnd; ++i) {
                uint64_t dirIdx = 0;
                std::string name = readDwarfLineStringEntry(pos, headerEnd, fileFormats,
                                                            0x01, debugStr, debugLineStr,
                                                            table.addressSize, dirIdx);
                std::string dir = compDir;
                if (dirIdx < table.includeDirs.size())
                    dir = table.includeDirs[(size_t)dirIdx];
                table.files.push_back(joinPath(dir, name));
            }
        }

        pos = headerEnd;
        struct LineState {
            uint32_t address = 0;
            uint32_t file = 1;
            uint32_t line = 1;
            bool isStmt = false;
            bool endSequence = false;
        } state;
        auto reset = [&]() {
            state.address = 0;
            state.file = table.version >= 5 ? 0 : 1;
            state.line = 1;
            state.isStmt = defaultIsStmt != 0;
            state.endSequence = false;
        };
        auto addRow = [&]() {
            DwarfLineRow row;
            row.address = state.address;
            row.file = state.file;
            row.line = state.line;
            row.endSequence = state.endSequence;
            table.rows.push_back(row);
        };
        reset();

        while (pos < unitEnd) {
            uint8_t op = readLE<uint8_t>(pos++);
            if (op >= opcodeBase) {
                uint8_t adjusted = op - opcodeBase;
                if (lineRange) {
                    state.address += (adjusted / lineRange) * minInstrLen;
                    state.line = (uint32_t)((int32_t)state.line + lineBase + (adjusted % lineRange));
                }
                addRow();
                state.endSequence = false;
                continue;
            }
            if (op == 0) {
                uint64_t extLen = readULEB(pos, unitEnd);
                size_t extEnd = std::min<size_t>(pos + extLen, unitEnd);
                if (pos >= extEnd) { pos = extEnd; continue; }
                uint8_t subop = readLE<uint8_t>(pos++);
                switch (subop) {
                case DW_LNE_end_sequence:
                    state.endSequence = true;
                    addRow();
                    reset();
                    break;
                case DW_LNE_set_address:
                    if (pos + table.addressSize <= extEnd) {
                        state.address = (uint32_t)readUIntLE(pos, table.addressSize);
                        pos += table.addressSize;
                    }
                    break;
                case DW_LNE_define_file:
                    // Rare in modern output; skip the payload.
                    break;
                default:
                    break;
                }
                pos = extEnd;
                continue;
            }

            switch (op) {
            case DW_LNS_copy:
                addRow();
                state.endSequence = false;
                break;
            case DW_LNS_advance_pc:
                state.address += (uint32_t)(readULEB(pos, unitEnd) * minInstrLen);
                break;
            case DW_LNS_advance_line:
                state.line = (uint32_t)((int32_t)state.line + readSLEB(pos, unitEnd));
                break;
            case DW_LNS_set_file:
                state.file = (uint32_t)readULEB(pos, unitEnd);
                break;
            case DW_LNS_set_column:
                (void)readULEB(pos, unitEnd);
                break;
            case DW_LNS_negate_stmt:
                state.isStmt = !state.isStmt;
                break;
            case DW_LNS_set_basic_block:
                break;
            case DW_LNS_const_add_pc: {
                uint8_t adjusted = 255 - opcodeBase;
                if (lineRange)
                    state.address += (adjusted / lineRange) * minInstrLen;
                break;
            }
            case DW_LNS_fixed_advance_pc:
                if (pos + 2 <= unitEnd) {
                    state.address += readLE<uint16_t>(pos);
                    pos += 2;
                }
                break;
            case DW_LNS_set_prologue_end:
            case DW_LNS_set_epilogue_begin:
                break;
            case DW_LNS_set_isa:
                (void)readULEB(pos, unitEnd);
                break;
            default:
                if (op < stdOpLens.size()) {
                    for (uint8_t i = 0; i < stdOpLens[op]; ++i)
                        (void)readULEB(pos, unitEnd);
                }
                break;
            }
        }

        std::sort(table.rows.begin(), table.rows.end(), [](const auto &a, const auto &b) {
            if (a.address != b.address) return a.address < b.address;
            if (a.file != b.file) return a.file < b.file;
            return a.line < b.line;
        });
        return table;
    }

    std::string dwarfFileForIndex(const DwarfUnit &unit, uint32_t fileIdx) const {
        if (!unit.lineTable) return "";
        const auto &files = unit.lineTable->files;
        if (files.empty()) return "";
        if (unit.lineTable->version >= 5) {
            if (fileIdx < files.size()) return files[(size_t)fileIdx];
        } else {
            if (fileIdx > 0 && fileIdx - 1 < files.size())
                return files[(size_t)fileIdx - 1];
        }
        return files.front();
    }

    std::string bestDwarfFileForRange(const DwarfUnit &unit, uint32_t low, uint32_t high) const {
        if (!unit.lineTable || unit.lineTable->files.empty()) return "";
        std::map<uint32_t, int> counts;
        for (const auto &row : unit.lineTable->rows) {
            if (row.endSequence || row.address < low || row.address >= high) continue;
            counts[row.file]++;
        }
        uint32_t bestFile = unit.lineTable->version >= 5 ? 0 : 1;
        int bestCount = -1;
        for (const auto &[file, count] : counts) {
            if (count > bestCount) {
                bestFile = file;
                bestCount = count;
            }
        }
        return dwarfFileForIndex(unit, bestFile);
    }

    uint32_t dwarfHighPC(uint32_t lowPc, const DwarfValue &highVal, uint16_t version) const {
        if (!highVal.present) return 0;
        if (highVal.form == DW_FORM_addr)
            return (uint32_t)highVal.u;
        // DWARF4+ defines constant-class high_pc as an offset from low_pc.
        if (version >= 4)
            return lowPc + (uint32_t)highVal.u;
        // Older producers were less consistent; prefer offset when the value
        // is not a plausible absolute address above low_pc.
        if (highVal.u <= lowPc)
            return lowPc + (uint32_t)highVal.u;
        return (uint32_t)highVal.u;
    }

    int dwarfSourceIndexForAttrs(const DwarfUnit &unit,
                                 const std::map<uint64_t, DwarfValue> &attrs,
                                 uint32_t address = 0) {
        std::string sourcePath;
        if (dwarfHasAttr(attrs, DW_AT_decl_file))
            sourcePath = dwarfFileForIndex(unit, (uint32_t)dwarfUnsignedAttr(attrs, DW_AT_decl_file));
        if (sourcePath.empty())
            sourcePath = joinPath(unit.compDir, unit.name);
        return sourcePath.empty() ? -1 : sourceIndexForPath(sourcePath, address);
    }

    int addDwarfFunction(const DwarfUnit &unit,
                         const std::map<uint64_t, DwarfValue> &attrs,
                         std::map<uint32_t, TypeRef> &typeRefs) {
        if (!dwarfHasAttr(attrs, DW_AT_low_pc)) return -1;
        uint32_t lowPc = (uint32_t)dwarfUnsignedAttr(attrs, DW_AT_low_pc);
        if (!lowPc || !sectionForAddress(lowPc)) return -1;
        const Section *sec = sectionForAddress(lowPc);
        if (!sec || !isCodeSection(*sec)) return -1;

        auto highIt = attrs.find(DW_AT_high_pc);
        uint32_t highPc = highIt != attrs.end()
            ? dwarfHighPC(lowPc, highIt->second, unit.version) : 0;
        if (highPc && highPc <= lowPc) highPc = 0;

        std::string rawName = dwarfStringAttr(attrs, DW_AT_linkage_name);
        if (rawName.empty()) rawName = dwarfStringAttr(attrs, DW_AT_MIPS_linkage_name);
        if (rawName.empty()) rawName = dwarfStringAttr(attrs, DW_AT_name);
        if (rawName.empty()) return -1;

        std::string sourcePath;
        if (dwarfHasAttr(attrs, DW_AT_decl_file))
            sourcePath = dwarfFileForIndex(unit, (uint32_t)dwarfUnsignedAttr(attrs, DW_AT_decl_file));
        if (sourcePath.empty() && highPc)
            sourcePath = bestDwarfFileForRange(unit, lowPc, highPc);
        if (sourcePath.empty())
            sourcePath = joinPath(unit.compDir, unit.name);

        int srcIdx = sourcePath.empty() ? -1 : sourceIndexForPath(sourcePath, lowPc);
        for (size_t i = 0; i < m_stabsFuncs.size(); ++i) {
            if (m_stabsFuncs[i].address == lowPc) {
                StabsFunction &existing = m_stabsFuncs[i];
                if (existing.name.empty() || existing.name.find("sub_") == 0)
                    existing.name = symbolDisplayName(rawName);
                if (existing.rawName.empty())
                    existing.rawName = rawName;
                if (existing.size == 0 && highPc)
                    existing.size = highPc - lowPc;
                if (existing.returnType == NullType) {
                    existing.returnType = dwarfTypeAttr(unit, attrs, DW_AT_type, typeRefs);
                    if (existing.returnType == NullType)
                        existing.returnType = dwarfBuiltinVoidType(typeRefs);
                }
                if (existing.sourceFileIdx < 0 && srcIdx >= 0) {
                    existing.sourceFileIdx = srcIdx;
                    m_stabsSources[srcIdx].functionIndices.push_back(i);
                }
                if (existing.lineMap.empty() && unit.lineTable && highPc) {
                    for (const auto &row : unit.lineTable->rows) {
                        if (row.endSequence || row.address < lowPc || row.address >= highPc)
                            continue;
                        existing.lineMap.push_back({row.address, (int)row.line});
                    }
                    std::sort(existing.lineMap.begin(), existing.lineMap.end(),
                              [](const auto &a, const auto &b) { return a.first < b.first; });
                }
                return (int)i;
            }
        }

        StabsFunction fn;
        fn.name = symbolDisplayName(rawName);
        fn.rawName = rawName;
        fn.address = lowPc;
        fn.size = highPc ? highPc - lowPc : 0;
        fn.isGlobal = dwarfUnsignedAttr(attrs, DW_AT_external, 0) != 0;
        fn.sourceFileIdx = srcIdx;
        fn.returnType = dwarfTypeAttr(unit, attrs, DW_AT_type, typeRefs);
        if (fn.returnType == NullType)
            fn.returnType = dwarfBuiltinVoidType(typeRefs);
        if (unit.lineTable) {
            for (const auto &row : unit.lineTable->rows) {
                if (row.endSequence) continue;
                if (row.address < lowPc) continue;
                if (highPc && row.address >= highPc) continue;
                if (!sourcePath.empty()) {
                    std::string rowPath = dwarfFileForIndex(unit, row.file);
                    if (!rowPath.empty() && rowPath != sourcePath) continue;
                }
                fn.lineMap.push_back({row.address, (int)row.line});
            }
            std::sort(fn.lineMap.begin(), fn.lineMap.end(), [](const auto &a, const auto &b) {
                return a.first < b.first;
            });
            fn.lineMap.erase(std::unique(fn.lineMap.begin(), fn.lineMap.end(),
                [](const auto &a, const auto &b) {
                    return a.first == b.first && a.second == b.second;
                }), fn.lineMap.end());
        }

        m_stabsFuncs.push_back(std::move(fn));
        int fnIdx = (int)m_stabsFuncs.size() - 1;
        if (srcIdx >= 0)
            m_stabsSources[srcIdx].functionIndices.push_back((size_t)fnIdx);
        return fnIdx;
    }

    void parseDwarfDIEs(size_t &pos, size_t end,
                        const std::map<uint64_t, DwarfAbbrev> &abbrevs,
                        DwarfUnit &unit,
                        const ELFSectionRecord *debugInfo,
                        const ELFSectionRecord *debugStr,
                        const ELFSectionRecord *debugLineStr,
                        std::map<uint32_t, TypeRef> &typeRefs,
                        int currentFuncIdx,
                        TypeRef currentCompositeType,
                        TypeRef currentArrayType,
                        TypeRef currentEnumType,
                        int depth) {
        if (depth > 64) return;
        while (pos < end) {
            uint32_t dieOffset = debugInfo ? (uint32_t)(pos - debugInfo->offset) : 0;
            uint64_t code = readULEB(pos, end);
            if (code == 0)
                return;
            auto ait = abbrevs.find(code);
            if (ait == abbrevs.end())
                return;
            const DwarfAbbrev &abbr = ait->second;
            std::map<uint64_t, DwarfValue> attrs;
            for (const auto &adef : abbr.attrs) {
                DwarfValue val = readDwarfFormValue(pos, end, adef.form, adef.implicitConst,
                                                    unit.addressSize, debugStr, debugLineStr);
                if (val.present)
                    attrs[adef.name] = std::move(val);
            }

            int childFuncIdx = currentFuncIdx;
            TypeRef childCompositeType = currentCompositeType;
            TypeRef childArrayType = currentArrayType;
            TypeRef childEnumType = currentEnumType;
            if (abbr.tag == DW_TAG_compile_unit) {
                unit.name = dwarfStringAttr(attrs, DW_AT_name);
                unit.compDir = dwarfStringAttr(attrs, DW_AT_comp_dir);
                if (dwarfHasAttr(attrs, DW_AT_stmt_list))
                    unit.stmtList = (uint32_t)dwarfUnsignedAttr(attrs, DW_AT_stmt_list);
            } else if (abbr.tag == DW_TAG_base_type ||
                       abbr.tag == DW_TAG_pointer_type ||
                       abbr.tag == DW_TAG_reference_type ||
                       abbr.tag == DW_TAG_const_type ||
                       abbr.tag == DW_TAG_volatile_type ||
                       abbr.tag == DW_TAG_typedef ||
                       abbr.tag == DW_TAG_structure_type ||
                       abbr.tag == DW_TAG_class_type ||
                       abbr.tag == DW_TAG_union_type ||
                       abbr.tag == DW_TAG_enumeration_type ||
                       abbr.tag == DW_TAG_array_type ||
                       abbr.tag == DW_TAG_subroutine_type) {
                fillDwarfType(dieOffset, abbr.tag, unit, attrs, typeRefs);
                TypeRef thisType = dwarfTypeRefForOffset(typeRefs, dieOffset);
                if (abbr.tag == DW_TAG_structure_type || abbr.tag == DW_TAG_class_type ||
                    abbr.tag == DW_TAG_union_type)
                    childCompositeType = thisType;
                if (abbr.tag == DW_TAG_array_type)
                    childArrayType = thisType;
                if (abbr.tag == DW_TAG_enumeration_type)
                    childEnumType = thisType;
            } else if (abbr.tag == DW_TAG_member) {
                addDwarfMember(currentCompositeType, unit, attrs, typeRefs);
            } else if (abbr.tag == DW_TAG_enumerator) {
                addDwarfEnumerator(currentEnumType, attrs);
            } else if (abbr.tag == DW_TAG_subrange_type) {
                applyDwarfSubrange(currentArrayType, attrs);
            } else if (abbr.tag == DW_TAG_subprogram) {
                int fnIdx = addDwarfFunction(unit, attrs, typeRefs);
                if (fnIdx >= 0)
                    childFuncIdx = fnIdx;
            } else if (abbr.tag == DW_TAG_formal_parameter && currentFuncIdx >= 0) {
                std::string pname = dwarfStringAttr(attrs, DW_AT_name);
                if (!pname.empty()) {
                    StabsFunction &fn = m_stabsFuncs[(size_t)currentFuncIdx];
                    StabsTypedVar *existingParam = nullptr;
                    for (auto &p : fn.params)
                        if (p.name == pname) { existingParam = &p; break; }
                    TypeRef ptype = dwarfTypeAttr(unit, attrs, DW_AT_type, typeRefs);
                    int stackOff = 0;
                    auto lit = attrs.find(DW_AT_location);
                    int fbreg = 0;
                    if (lit != attrs.end() && dwarfLocationFBReg(lit->second, fbreg))
                        stackOff = fbreg + 8;
                    if (existingParam) {
                        if (existingParam->typeRef == NullType)
                            existingParam->typeRef = ptype;
                        if (existingParam->stackOffset == 0)
                            existingParam->stackOffset = stackOff;
                    }
                    if (!existingParam) {
                        StabsTypedVar param;
                        param.name = pname;
                        param.typeRef = ptype;
                        param.stackOffset = stackOff;
                        fn.params.push_back(std::move(param));
                    }
                }
            } else if (abbr.tag == DW_TAG_variable) {
                std::string vname = dwarfStringAttr(attrs, DW_AT_name);
                if (!vname.empty()) {
                    TypeRef vtype = dwarfTypeAttr(unit, attrs, DW_AT_type, typeRefs);
                    auto lit = attrs.find(DW_AT_location);
                    if (currentFuncIdx >= 0) {
                        int fbreg = 0;
                        if (lit != attrs.end() && dwarfLocationFBReg(lit->second, fbreg)) {
                            StabsTypedVar local;
                            local.name = vname;
                            local.typeRef = vtype;
                            local.stackOffset = fbreg + 8;
                            m_stabsFuncs[(size_t)currentFuncIdx].locals.push_back(std::move(local));
                        }
                    } else if (lit != attrs.end()) {
                        uint32_t addr = dwarfLocationAddress(lit->second, unit.addressSize);
                        if (addr) {
                            bool isStatic = dwarfUnsignedAttr(attrs, DW_AT_external, 0) == 0;
                            int srcIdx = dwarfSourceIndexForAttrs(unit, attrs, addr);
                            m_typeTable.addGlobal(vname, addr, vtype, isStatic, srcIdx);
                        }
                    }
                }
            }

            if (abbr.hasChildren)
                parseDwarfDIEs(pos, end, abbrevs, unit, debugInfo, debugStr, debugLineStr,
                               typeRefs, childFuncIdx, childCompositeType,
                               childArrayType, childEnumType, depth + 1);
        }
    }

    void parseDWARF(const std::vector<ELFSectionRecord> &sections) {
        const ELFSectionRecord *debugInfo = findELFSection(sections, ".debug_info");
        const ELFSectionRecord *debugAbbrev = findELFSection(sections, ".debug_abbrev");
        const ELFSectionRecord *debugStr = findELFSection(sections, ".debug_str");
        const ELFSectionRecord *debugLineStr = findELFSection(sections, ".debug_line_str");
        if (!debugInfo || !debugAbbrev || debugInfo->size == 0 || debugAbbrev->size == 0)
            return;

        std::map<uint32_t, DwarfLineTable> lineCache;
        std::map<uint32_t, TypeRef> typeRefs;
        size_t pos = debugInfo->offset;
        size_t infoEnd = debugInfo->offset + debugInfo->size;
        while (pos + 11 <= infoEnd && pos + 11 <= m_size) {
            uint32_t unitStart = (uint32_t)(pos - debugInfo->offset);
            uint32_t unitLength = readLE<uint32_t>(pos); pos += 4;
            if (unitLength == 0xFFFFFFFF) break; // DWARF64 not supported.
            if (unitLength == 0) break;
            size_t unitEnd = std::min<size_t>(pos + unitLength, infoEnd);
            if (unitEnd > m_size || pos + 2 > unitEnd) break;

            DwarfUnit unit;
            unit.offset = unitStart;
            unit.end = (uint32_t)(unitEnd - debugInfo->offset);
            unit.version = readLE<uint16_t>(pos); pos += 2;
            if (unit.version < 2 || unit.version > 5) {
                pos = unitEnd;
                continue;
            }

            uint32_t abbrevOffset = 0;
            if (unit.version >= 5) {
                if (pos + 6 > unitEnd) break;
                uint8_t unitType = readLE<uint8_t>(pos); pos += 1;
                unit.addressSize = readLE<uint8_t>(pos); pos += 1;
                abbrevOffset = readLE<uint32_t>(pos); pos += 4;
                (void)unitType;
            } else {
                if (pos + 5 > unitEnd) break;
                abbrevOffset = readLE<uint32_t>(pos); pos += 4;
                unit.addressSize = readLE<uint8_t>(pos); pos += 1;
            }
            if (unit.addressSize == 0 || unit.addressSize > 8)
                unit.addressSize = 4;

            auto abbrevs = parseDwarfAbbrevs(debugAbbrev, abbrevOffset);
            if (abbrevs.empty()) {
                pos = unitEnd;
                continue;
            }

            // First pass over the root CU DIE to learn comp_dir/stmt_list before
            // subprogram DIEs need line-table paths.
            size_t dieStart = pos;
            size_t probe = pos;
            uint64_t rootCode = readULEB(probe, unitEnd);
            auto rootIt = abbrevs.find(rootCode);
            if (rootCode && rootIt != abbrevs.end()) {
                std::map<uint64_t, DwarfValue> rootAttrs;
                for (const auto &adef : rootIt->second.attrs) {
                    DwarfValue val = readDwarfFormValue(probe, unitEnd, adef.form,
                                                        adef.implicitConst, unit.addressSize,
                                                        debugStr, debugLineStr);
                    if (val.present)
                        rootAttrs[adef.name] = std::move(val);
                }
                unit.name = dwarfStringAttr(rootAttrs, DW_AT_name);
                unit.compDir = dwarfStringAttr(rootAttrs, DW_AT_comp_dir);
                if (dwarfHasAttr(rootAttrs, DW_AT_stmt_list))
                    unit.stmtList = (uint32_t)dwarfUnsignedAttr(rootAttrs, DW_AT_stmt_list);
            }
            if (unit.stmtList != UINT32_MAX) {
                auto lit = lineCache.find(unit.stmtList);
                if (lit == lineCache.end()) {
                    DwarfLineTable lt = parseDwarfLineTable(sections, unit.stmtList, unit.compDir);
                    lit = lineCache.emplace(unit.stmtList, std::move(lt)).first;
                }
                unit.lineTable = &lit->second;
            }

            pos = dieStart;
            parseDwarfDIEs(pos, unitEnd, abbrevs, unit, debugInfo, debugStr,
                           debugLineStr, typeRefs, -1, NullType, NullType,
                           NullType, 0);
            finalizeDwarfTypes(typeRefs);
            pos = unitEnd;
        }
    }

    void parseELFSymbolTable(const std::vector<ELFSectionRecord> &sections,
                             uint32_t symtabIdx) {
        if (symtabIdx >= sections.size()) return;
        const auto &symtab = sections[symtabIdx];
        if ((symtab.type != SHT_SYMTAB && symtab.type != SHT_DYNSYM) ||
            symtab.entsize < 16 || symtab.link >= sections.size() ||
            symtab.offset >= m_size)
            return;

        const auto &strtab = sections[symtab.link];
        uint32_t count = symtab.entsize ? symtab.size / symtab.entsize : 0;
        m_symbols.reserve(m_symbols.size() + std::min<uint32_t>(count, 500000));
        for (uint32_t i = 0; i < count; ++i) {
            uint64_t off = (uint64_t)symtab.offset + (uint64_t)i * symtab.entsize;
            if (off + 16 > m_size) break;
            uint32_t nameIdx = readLE<uint32_t>((size_t)off);
            uint32_t value = readLE<uint32_t>((size_t)off + 4);
            uint32_t size = readLE<uint32_t>((size_t)off + 8);
            uint8_t info = readLE<uint8_t>((size_t)off + 12);
            uint16_t shndx = readLE<uint16_t>((size_t)off + 14);
            std::string name = stringAtBounded(strtab.offset, strtab.size, nameIdx);
            addELFSymbol(name, nameIdx, info, shndx, value, size);
        }
    }

    void parseELFStabsSection(const ELFSectionRecord &stab,
                              const ELFSectionRecord &stabstr) {
        if (stab.offset >= m_size || stab.entsize == 0) return;
        uint32_t entsize = stab.entsize >= 12 ? stab.entsize : 12;
        uint32_t count = stab.size / entsize;
        m_symoff = stab.offset;
        m_nsyms = count;
        m_stroff = stabstr.offset;
        m_strsize = stabstr.size;

        m_symbols.reserve(m_symbols.size() + std::min<uint32_t>(count, 500000));
        for (uint32_t i = 0; i < count; ++i) {
            uint64_t off = (uint64_t)stab.offset + (uint64_t)i * entsize;
            if (off + 12 > m_size) break;
            NList nl{};
            nl.n_strx = readLE<uint32_t>((size_t)off);
            nl.n_type = readLE<uint8_t>((size_t)off + 4);
            nl.n_sect = readLE<uint8_t>((size_t)off + 5);
            nl.n_desc = readLE<int16_t>((size_t)off + 6);
            nl.n_value = readLE<uint32_t>((size_t)off + 8);
            nl.name = stringAtBounded(stabstr.offset, stabstr.size, nl.n_strx);
            m_symbols.push_back(std::move(nl));
        }
    }

    void parseELFDynamicNeeded(const std::vector<ELFSectionRecord> &sections) {
        for (const auto &sec : sections) {
            if (sec.type != SHT_DYNAMIC || sec.entsize < 8 ||
                sec.offset >= m_size || sec.link >= sections.size())
                continue;

            const auto &strtab = sections[sec.link];
            uint32_t count = sec.size / sec.entsize;
            for (uint32_t i = 0; i < count; ++i) {
                uint64_t off = (uint64_t)sec.offset + (uint64_t)i * sec.entsize;
                if (off + 8 > m_size) break;
                int32_t tag = readLE<int32_t>((size_t)off);
                uint32_t val = readLE<uint32_t>((size_t)off + 4);
                if (tag == 0) break;
                if (tag != DT_NEEDED) continue;
                std::string name = stringAtBounded(strtab.offset, strtab.size, val);
                if (name.empty()) continue;
                bool dup = false;
                for (const auto &dl : m_dylibs)
                    if (dl.name == name) { dup = true; break; }
                if (!dup)
                    m_dylibs.push_back({name, 0, 0, 0});
            }
        }
    }

    const Section* elfSectionByName(const std::string &name) const {
        for (const Section *sec : allSections())
            if (sec && sec->sectname == name)
                return sec;
        return nullptr;
    }

    void parseELFPltRelocations(const std::vector<ELFSectionRecord> &sections) {
        const Section *plt = elfSectionByName(".plt.sec");
        bool pltSec = plt != nullptr;
        if (!plt) {
            plt = elfSectionByName(".plt");
            pltSec = false;
        }
        if (!plt || plt->addr == 0) return;

        uint32_t pltEntrySize = 16;
        for (const auto &rel : sections) {
            if (rel.type != SHT_REL || rel.entsize < 8 || rel.offset >= m_size ||
                rel.link >= sections.size())
                continue;
            if (rel.name.find(".rel.plt") != 0 && rel.name.find(".rel.dyn") != 0)
                continue;

            uint32_t count = rel.size / rel.entsize;
            for (uint32_t i = 0; i < count; ++i) {
                uint64_t off = (uint64_t)rel.offset + (uint64_t)i * rel.entsize;
                if (off + 8 > m_size) break;
                uint32_t info = readLE<uint32_t>((size_t)off + 4);
                uint32_t symIdx = info >> 8;
                std::string name = elfSymbolName(sections, rel.link, symIdx);
                if (name.empty()) continue;

                uint32_t stubAddr = 0;
                if (rel.name.find(".rel.plt") == 0) {
                    stubAddr = plt->addr + pltEntrySize * (pltSec ? i : i + 1);
                }
                if (stubAddr && m_funcMap.find(stubAddr) == m_funcMap.end())
                    m_funcMap[stubAddr] = symbolDisplayName(name);
            }
        }
    }

    bool parseELF() {
        if (m_size < 52 || readLE<uint32_t>(0) != ELF_MAGIC_LE) return false;
        if (readLE<uint8_t>(4) != ELFCLASS32 || readLE<uint8_t>(5) != ELFDATA2LSB)
            return false;

        memcpy(m_elfHeader.ident, m_data.data(), 16);
        m_elfHeader.type = readLE<uint16_t>(16);
        m_elfHeader.machine = readLE<uint16_t>(18);
        m_elfHeader.version = readLE<uint32_t>(20);
        m_elfHeader.entry = readLE<uint32_t>(24);
        m_elfHeader.phoff = readLE<uint32_t>(28);
        m_elfHeader.shoff = readLE<uint32_t>(32);
        m_elfHeader.flags = readLE<uint32_t>(36);
        m_elfHeader.ehsize = readLE<uint16_t>(40);
        m_elfHeader.phentsize = readLE<uint16_t>(42);
        m_elfHeader.phnum = readLE<uint16_t>(44);
        m_elfHeader.shentsize = readLE<uint16_t>(46);
        m_elfHeader.shnum = readLE<uint16_t>(48);
        m_elfHeader.shstrndx = readLE<uint16_t>(50);

        if (m_elfHeader.machine != EM_386 || m_elfHeader.version != 1 ||
            (m_elfHeader.type != ET_EXEC && m_elfHeader.type != ET_DYN))
            return false;
        if (m_elfHeader.phnum && (m_elfHeader.phentsize < 32 ||
            (uint64_t)m_elfHeader.phoff + (uint64_t)m_elfHeader.phnum * m_elfHeader.phentsize > m_size))
            return false;
        if (m_elfHeader.shnum == 0 || m_elfHeader.shentsize < 40 ||
            (uint64_t)m_elfHeader.shoff + (uint64_t)m_elfHeader.shnum * m_elfHeader.shentsize > m_size)
            return false;

        m_format = BinaryFormat::ELF32;
        m_entryPoint = m_elfHeader.entry;

        for (uint32_t i = 0; i < m_elfHeader.phnum; ++i) {
            uint64_t off = (uint64_t)m_elfHeader.phoff + (uint64_t)i * m_elfHeader.phentsize;
            ELFProgramHeader ph{};
            ph.type = readLE<uint32_t>((size_t)off);
            ph.offset = readLE<uint32_t>((size_t)off + 4);
            ph.vaddr = readLE<uint32_t>((size_t)off + 8);
            ph.paddr = readLE<uint32_t>((size_t)off + 12);
            ph.filesz = readLE<uint32_t>((size_t)off + 16);
            ph.memsz = readLE<uint32_t>((size_t)off + 20);
            ph.flags = readLE<uint32_t>((size_t)off + 24);
            ph.align = readLE<uint32_t>((size_t)off + 28);
            m_elfProgramHeaders.push_back(ph);
        }

        std::vector<ELFSectionRecord> sections(m_elfHeader.shnum);
        for (uint32_t i = 0; i < m_elfHeader.shnum; ++i) {
            uint64_t off = (uint64_t)m_elfHeader.shoff + (uint64_t)i * m_elfHeader.shentsize;
            auto &sec = sections[i];
            sec.name = "";
            sec.type = readLE<uint32_t>((size_t)off + 4);
            sec.flags = readLE<uint32_t>((size_t)off + 8);
            sec.addr = readLE<uint32_t>((size_t)off + 12);
            sec.offset = readLE<uint32_t>((size_t)off + 16);
            sec.size = readLE<uint32_t>((size_t)off + 20);
            sec.link = readLE<uint32_t>((size_t)off + 24);
            sec.info = readLE<uint32_t>((size_t)off + 28);
            sec.addralign = readLE<uint32_t>((size_t)off + 32);
            sec.entsize = readLE<uint32_t>((size_t)off + 36);
        }

        if (m_elfHeader.shstrndx >= sections.size()) return false;
        const auto &shstr = sections[m_elfHeader.shstrndx];
        for (uint32_t i = 0; i < m_elfHeader.shnum; ++i) {
            uint64_t off = (uint64_t)m_elfHeader.shoff + (uint64_t)i * m_elfHeader.shentsize;
            uint32_t nameIdx = readLE<uint32_t>((size_t)off);
            sections[i].name = stringAtBounded(shstr.offset, shstr.size, nameIdx);
        }

        Segment imageSeg;
        imageSeg.segname = "ELF";
        imageSeg.vmaddr = UINT32_MAX;
        imageSeg.vmsize = 0;
        imageSeg.fileoff = 0;
        imageSeg.filesize = (uint32_t)m_size;
        imageSeg.flags = m_elfHeader.flags;

        m_elfSectionToFlat.assign(m_elfHeader.shnum, 0);
        uint32_t maxAddr = 0;
        for (uint32_t i = 0; i < sections.size(); ++i) {
            const auto &sh = sections[i];
            if (sh.type == SHT_NULL || !(sh.flags & SHF_ALLOC) || sh.size == 0)
                continue;

            Section sec{};
            sec.sectname = sh.name.empty() ? ("section_" + std::to_string(i)) : sh.name;
            sec.segname = "ELF";
            sec.addr = sh.addr;
            sec.align = sh.size; // ELF virtual span; file-backed bytes are in size.
            sec.offset = sh.offset;
            sec.size = sh.type == SHT_NOBITS ? 0 : sh.size;
            if (sec.offset > m_size) sec.size = 0;
            else if ((uint64_t)sec.offset + sec.size > m_size)
                sec.size = (uint32_t)(m_size - sec.offset);
            sec.reloff = 0;
            sec.nreloc = 0;
            sec.flags = sh.flags;

            m_elfSectionToFlat[i] = (uint8_t)(imageSeg.sections.size() + 1);
            imageSeg.sections.push_back(std::move(sec));
            imageSeg.vmaddr = std::min(imageSeg.vmaddr, sh.addr);
            if (sh.addr + sh.size > maxAddr) maxAddr = sh.addr + sh.size;
        }
        if (imageSeg.vmaddr == UINT32_MAX) imageSeg.vmaddr = 0;
        imageSeg.vmsize = maxAddr > imageSeg.vmaddr ? maxAddr - imageSeg.vmaddr : 0;
        imageSeg.nsects = (uint32_t)imageSeg.sections.size();
        m_segments.push_back(std::move(imageSeg));

        for (uint32_t i = 0; i < sections.size(); ++i) {
            if (sections[i].type == SHT_SYMTAB || sections[i].type == SHT_DYNSYM)
                parseELFSymbolTable(sections, i);
        }

        for (uint32_t i = 0; i < sections.size(); ++i) {
            if (sections[i].name != ".stab") continue;
            uint32_t strIdx = sections[i].link;
            if (strIdx >= sections.size()) {
                for (uint32_t j = 0; j < sections.size(); ++j)
                    if (sections[j].name == ".stabstr") { strIdx = j; break; }
            }
            if (strIdx < sections.size())
                parseELFStabsSection(sections[i], sections[strIdx]);
        }

        parseELFDynamicNeeded(sections);
        parseELFPltRelocations(sections);
        parseSTABS();
        parseDWARF(sections);
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
                if (!sym.name.empty()) {
                    StabsFunction fn;
                    fn.rawName = sym.name;
                    fn.name = symbolDisplayName(cleanStabsName(sym.name));
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
                } else {
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
                    // For ForwardRef: the ref tag matches the global name but the
                    if (rt && (rt->kind == StabsTypeKind::Struct || rt->kind == StabsTypeKind::Union) &&
                        !rt->name.empty() && rt->name.find("$_") == std::string::npos &&
                        parsed.name.size() >= 5) {
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
                // ForwardRef protection handled in parseTypeDef
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
                {
                    std::string gname = parsed.name;
                    // Strip C++ function scope from static locals:
                    // "FS_ShiftStr(char const*, int)::buf" → "buf"
                    auto scopePos = gname.rfind("::");
                    if (scopePos != std::string::npos && scopePos + 2 < gname.size()) {
                        // Only strip if there's a function-like pattern before ::
                        auto parenPos = gname.find('(');
                        if (parenPos != std::string::npos && parenPos < scopePos)
                            gname = gname.substr(scopePos + 2);
                    }
                    m_typeTable.addGlobal(gname, sym.n_value, useType, true);
                }
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
                    bool isStaticEntry = (entry.compare(cpos, 3, ":S(") == 0);
                    std::string gname = entry.substr(0, cpos);
                    auto it = nlSyms.find(gname);
                    if (it != nlSyms.end()) {
                        bool alreadyTyped = false;
                        for (auto &g : m_typeTable.globals()) {
                            if (g.isStatic == isStaticEntry &&
                                g.name == gname && g.address == it->second &&
                                g.typeRef != NullType) {
                                alreadyTyped = true;
                                break;
                            }
                        }
                        if (alreadyTyped) {
                            spos += slen + 1;
                            continue;
                        }
                        auto parsed = m_typeTable.parseSymbol(entry);
                        if (parsed.typeRef != NullType) {
                            // Validate: if the type resolves to a struct, check if
                            // the struct name is related to the global name.
                            // Mismatched struct types from CU-scoped refs cause
                            // compile errors ("not a structure or union").
                            TypeRef useType = parsed.typeRef;
                            auto *rt = m_typeTable.resolveType(parsed.typeRef);
                            // Reject ForwardRefs with unrelated tag names
                            if (rt && rt->kind == StabsTypeKind::ForwardRef &&
                                !rt->forwardTag.empty() && gname.size() >= 5) {
                                std::string tag = rt->forwardTag, lgn = gname;
                                for (auto &c : tag) c = tolower(c);
                                for (auto &c : lgn) c = tolower(c);
                                if (tag.size() > 2 && tag.substr(tag.size()-2) == "_t")
                                    tag = tag.substr(0, tag.size()-2);
                                bool related = (lgn.find(tag) != std::string::npos ||
                                               tag.find(lgn) != std::string::npos);
                                if (!related && tag.size() >= 4)
                                    related = (lgn.find(tag.substr(0,4)) != std::string::npos);
                                if (!related) useType = NullType;
                            }
                            if (rt && (rt->kind == StabsTypeKind::Struct ||
                                       rt->kind == StabsTypeKind::Union)) {
                                // Check if struct name relates to global name
                                std::string sn = rt->name;
                                std::string gn = gname;
                                // Convert both to lowercase for comparison
                                for (auto &c : sn) c = tolower(c);
                                for (auto &c : gn) c = tolower(c);
                                // Check if either contains the other (partial match)
                                bool related = gname.size() < 5;
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
                            m_typeTable.addGlobal(gname, it->second, useType, isStaticEntry);
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
                if (isELF()) {
                    uint8_t stype = elfSymbolType((uint8_t)sym.n_desc);
                    if (stype != STT_FUNC && stype != STT_NOTYPE)
                        continue;
                }
                if (m_funcMap.find(sym.n_value) == m_funcMap.end())
                    m_funcMap[sym.n_value] = symbolDisplayName(sym.name);
            }
        }
        // Resolve import stubs via indirect symbol table
        if (isMachO())
            resolveImportStubs();
        if (isPE() || isELF()) {
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
            if (!isELF() && !name.empty() && name[0] == '_') name = name.substr(1);
            if (name.find(':') != std::string::npos) continue;
            // Demangle C++ names
            std::string demangled = symbolDisplayName(sym.name);
            if (!demangled.empty() && demangled != sym.name) {
                name = demangled;
                // Strip function scope from static locals:
                // "FS_ShiftStr(char const*, int)::buf" → "buf"
                auto paren = name.find('(');
                auto scope = name.rfind("::");
                if (paren != std::string::npos && scope != std::string::npos &&
                    paren < scope && scope + 2 < name.size())
                    name = name.substr(scope + 2);
            }
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
    ELFHeader           m_elfHeader{};
    std::vector<ELFProgramHeader> m_elfProgramHeaders;
    std::vector<LoadCommand> m_loadCmds;
    std::vector<Segment>     m_segments;
    std::vector<NList>       m_symbols;
    mutable std::map<uint32_t, std::string> m_dataSymMap;
    std::vector<Dylib>       m_dylibs;
    uint32_t m_symoff = 0, m_nsyms = 0, m_stroff = 0, m_strsize = 0;
    std::vector<uint8_t> m_elfSectionToFlat;
    uint32_t m_entryPoint = 0;

    std::vector<StabsFunction>   m_stabsFuncs;
    std::vector<StabsSourceFile> m_stabsSources;
    std::unordered_map<uint32_t, std::string> m_funcMap;
    StabsTypeTable               m_typeTable;
};
