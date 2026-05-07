#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class BinaryFormat {
    Unknown,
    MachO32,
    PE32,
    ELF32,
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
