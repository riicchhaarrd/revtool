#pragma once

#include <cstdint>

// Mach-O constants
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
