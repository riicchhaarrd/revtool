#pragma once
#include <cstdint>
#include <string>
#include <vector>

// ── ELF constants ──────────────────────────────────────────────────
constexpr uint32_t ELF_MAGIC_LE = 0x464C457F; // "\x7FELF" read little-endian
constexpr uint8_t  ELFCLASS32   = 1;
constexpr uint8_t  ELFDATA2LSB  = 1;
constexpr uint16_t ET_REL       = 1;
constexpr uint16_t ET_EXEC      = 2;
constexpr uint16_t ET_DYN       = 3;
constexpr uint16_t EM_386       = 3;

constexpr uint32_t PT_LOAD      = 1;
constexpr uint32_t PT_DYNAMIC   = 2;
constexpr uint32_t PT_INTERP    = 3;
constexpr uint32_t PT_NOTE      = 4;
constexpr uint32_t PT_PHDR      = 6;

constexpr uint32_t PF_X         = 0x1;
constexpr uint32_t PF_W         = 0x2;
constexpr uint32_t PF_R         = 0x4;

constexpr uint32_t SHT_NULL     = 0;
constexpr uint32_t SHT_PROGBITS = 1;
constexpr uint32_t SHT_SYMTAB   = 2;
constexpr uint32_t SHT_STRTAB   = 3;
constexpr uint32_t SHT_RELA     = 4;
constexpr uint32_t SHT_DYNAMIC  = 6;
constexpr uint32_t SHT_NOBITS   = 8;
constexpr uint32_t SHT_REL      = 9;
constexpr uint32_t SHT_DYNSYM   = 11;

constexpr uint32_t SHF_WRITE     = 0x1;
constexpr uint32_t SHF_ALLOC     = 0x2;
constexpr uint32_t SHF_EXECINSTR = 0x4;

constexpr uint8_t STT_NOTYPE  = 0;
constexpr uint8_t STT_OBJECT  = 1;
constexpr uint8_t STT_FUNC    = 2;
constexpr uint8_t STT_SECTION = 3;
constexpr uint8_t STT_FILE    = 4;

constexpr uint32_t SHN_UNDEF = 0;
constexpr uint32_t SHN_ABS   = 0xFFF1;
constexpr int32_t  DT_NEEDED = 1;

struct ELFHeader {
    uint8_t  ident[16] = {};
    uint16_t type = 0;
    uint16_t machine = 0;
    uint32_t version = 0;
    uint32_t entry = 0;
    uint32_t phoff = 0;
    uint32_t shoff = 0;
    uint32_t flags = 0;
    uint16_t ehsize = 0;
    uint16_t phentsize = 0;
    uint16_t phnum = 0;
    uint16_t shentsize = 0;
    uint16_t shnum = 0;
    uint16_t shstrndx = 0;
};

struct ELFProgramHeader {
    uint32_t type = 0;
    uint32_t offset = 0;
    uint32_t vaddr = 0;
    uint32_t paddr = 0;
    uint32_t filesz = 0;
    uint32_t memsz = 0;
    uint32_t flags = 0;
    uint32_t align = 0;
};

struct ELFSectionRecord {
    std::string name;
    uint32_t type = 0;
    uint32_t flags = 0;
    uint32_t addr = 0;
    uint32_t offset = 0;
    uint32_t size = 0;
    uint32_t link = 0;
    uint32_t info = 0;
    uint32_t addralign = 0;
    uint32_t entsize = 0;
};

// ── DWARF constants ────────────────────────────────────────────────
constexpr uint64_t DW_TAG_array_type       = 0x01;
constexpr uint64_t DW_TAG_class_type       = 0x02;
constexpr uint64_t DW_TAG_enumeration_type = 0x04;
constexpr uint64_t DW_TAG_formal_parameter = 0x05;
constexpr uint64_t DW_TAG_member           = 0x0D;
constexpr uint64_t DW_TAG_pointer_type     = 0x0F;
constexpr uint64_t DW_TAG_reference_type   = 0x10;
constexpr uint64_t DW_TAG_compile_unit     = 0x11;
constexpr uint64_t DW_TAG_structure_type   = 0x13;
constexpr uint64_t DW_TAG_subroutine_type  = 0x15;
constexpr uint64_t DW_TAG_typedef          = 0x16;
constexpr uint64_t DW_TAG_union_type       = 0x17;
constexpr uint64_t DW_TAG_unspecified_parameters = 0x18;
constexpr uint64_t DW_TAG_subrange_type    = 0x21;
constexpr uint64_t DW_TAG_base_type        = 0x24;
constexpr uint64_t DW_TAG_const_type       = 0x26;
constexpr uint64_t DW_TAG_enumerator       = 0x28;
constexpr uint64_t DW_TAG_subprogram       = 0x2E;
constexpr uint64_t DW_TAG_variable         = 0x34;
constexpr uint64_t DW_TAG_volatile_type    = 0x35;
constexpr uint64_t DW_TAG_restrict_type    = 0x37;
constexpr uint64_t DW_TAG_rvalue_reference_type = 0x42;
constexpr uint64_t DW_TAG_atomic_type      = 0x47;

constexpr uint8_t DW_CHILDREN_no  = 0;
constexpr uint8_t DW_CHILDREN_yes = 1;

constexpr uint64_t DW_AT_location          = 0x02;
constexpr uint64_t DW_AT_name              = 0x03;
constexpr uint64_t DW_AT_byte_size         = 0x0B;
constexpr uint64_t DW_AT_bit_offset        = 0x0C;
constexpr uint64_t DW_AT_bit_size          = 0x0D;
constexpr uint64_t DW_AT_stmt_list         = 0x10;
constexpr uint64_t DW_AT_low_pc            = 0x11;
constexpr uint64_t DW_AT_high_pc           = 0x12;
constexpr uint64_t DW_AT_const_value       = 0x1C;
constexpr uint64_t DW_AT_comp_dir          = 0x1B;
constexpr uint64_t DW_AT_lower_bound       = 0x22;
constexpr uint64_t DW_AT_upper_bound       = 0x2F;
constexpr uint64_t DW_AT_external          = 0x3F;
constexpr uint64_t DW_AT_decl_file         = 0x3A;
constexpr uint64_t DW_AT_decl_line         = 0x3B;
constexpr uint64_t DW_AT_declaration       = 0x3C;
constexpr uint64_t DW_AT_encoding          = 0x3E;
constexpr uint64_t DW_AT_frame_base        = 0x40;
constexpr uint64_t DW_AT_abstract_origin   = 0x31;
constexpr uint64_t DW_AT_count             = 0x37;
constexpr uint64_t DW_AT_data_member_location = 0x38;
constexpr uint64_t DW_AT_specification     = 0x47;
constexpr uint64_t DW_AT_type              = 0x49;
constexpr uint64_t DW_AT_ranges            = 0x55;
constexpr uint64_t DW_AT_linkage_name      = 0x6E;
constexpr uint64_t DW_AT_data_bit_offset   = 0x6B;
constexpr uint64_t DW_AT_str_offsets_base  = 0x72;
constexpr uint64_t DW_AT_addr_base         = 0x73;
constexpr uint64_t DW_AT_rnglists_base     = 0x74;
constexpr uint64_t DW_AT_MIPS_linkage_name = 0x2007;

constexpr uint64_t DW_FORM_addr           = 0x01;
constexpr uint64_t DW_FORM_block2         = 0x03;
constexpr uint64_t DW_FORM_block4         = 0x04;
constexpr uint64_t DW_FORM_data2          = 0x05;
constexpr uint64_t DW_FORM_data4          = 0x06;
constexpr uint64_t DW_FORM_data8          = 0x07;
constexpr uint64_t DW_FORM_string         = 0x08;
constexpr uint64_t DW_FORM_block          = 0x09;
constexpr uint64_t DW_FORM_block1         = 0x0A;
constexpr uint64_t DW_FORM_data1          = 0x0B;
constexpr uint64_t DW_FORM_flag           = 0x0C;
constexpr uint64_t DW_FORM_sdata          = 0x0D;
constexpr uint64_t DW_FORM_strp           = 0x0E;
constexpr uint64_t DW_FORM_udata          = 0x0F;
constexpr uint64_t DW_FORM_ref_addr       = 0x10;
constexpr uint64_t DW_FORM_ref1           = 0x11;
constexpr uint64_t DW_FORM_ref2           = 0x12;
constexpr uint64_t DW_FORM_ref4           = 0x13;
constexpr uint64_t DW_FORM_ref8           = 0x14;
constexpr uint64_t DW_FORM_ref_udata      = 0x15;
constexpr uint64_t DW_FORM_indirect       = 0x16;
constexpr uint64_t DW_FORM_sec_offset     = 0x17;
constexpr uint64_t DW_FORM_exprloc        = 0x18;
constexpr uint64_t DW_FORM_flag_present   = 0x19;
constexpr uint64_t DW_FORM_strx           = 0x1A;
constexpr uint64_t DW_FORM_addrx          = 0x1B;
constexpr uint64_t DW_FORM_ref_sup4       = 0x1C;
constexpr uint64_t DW_FORM_strp_sup       = 0x1D;
constexpr uint64_t DW_FORM_data16         = 0x1E;
constexpr uint64_t DW_FORM_line_strp      = 0x1F;
constexpr uint64_t DW_FORM_ref_sig8       = 0x20;
constexpr uint64_t DW_FORM_implicit_const = 0x21;
constexpr uint64_t DW_FORM_loclistx       = 0x22;
constexpr uint64_t DW_FORM_rnglistx       = 0x23;
constexpr uint64_t DW_FORM_ref_sup8       = 0x24;
constexpr uint64_t DW_FORM_strx1          = 0x25;
constexpr uint64_t DW_FORM_strx2          = 0x26;
constexpr uint64_t DW_FORM_strx3          = 0x27;
constexpr uint64_t DW_FORM_strx4          = 0x28;
constexpr uint64_t DW_FORM_addrx1         = 0x29;
constexpr uint64_t DW_FORM_addrx2         = 0x2A;
constexpr uint64_t DW_FORM_addrx3         = 0x2B;
constexpr uint64_t DW_FORM_addrx4         = 0x2C;

constexpr uint8_t DW_LNS_copy              = 1;
constexpr uint8_t DW_LNS_advance_pc        = 2;
constexpr uint8_t DW_LNS_advance_line      = 3;
constexpr uint8_t DW_LNS_set_file          = 4;
constexpr uint8_t DW_LNS_set_column        = 5;
constexpr uint8_t DW_LNS_negate_stmt       = 6;
constexpr uint8_t DW_LNS_set_basic_block   = 7;
constexpr uint8_t DW_LNS_const_add_pc      = 8;
constexpr uint8_t DW_LNS_fixed_advance_pc  = 9;
constexpr uint8_t DW_LNS_set_prologue_end  = 10;
constexpr uint8_t DW_LNS_set_epilogue_begin= 11;
constexpr uint8_t DW_LNS_set_isa           = 12;
constexpr uint8_t DW_LNE_end_sequence      = 1;
constexpr uint8_t DW_LNE_set_address       = 2;
constexpr uint8_t DW_LNE_define_file       = 3;
constexpr uint8_t DW_LNE_set_discriminator = 4;

constexpr uint64_t DW_ATE_address          = 0x01;
constexpr uint64_t DW_ATE_boolean          = 0x02;
constexpr uint64_t DW_ATE_float            = 0x04;
constexpr uint64_t DW_ATE_signed           = 0x05;
constexpr uint64_t DW_ATE_signed_char      = 0x06;
constexpr uint64_t DW_ATE_unsigned         = 0x07;
constexpr uint64_t DW_ATE_unsigned_char    = 0x08;
constexpr uint8_t  DW_OP_addr              = 0x03;
constexpr uint8_t  DW_OP_const1u           = 0x08;
constexpr uint8_t  DW_OP_const1s           = 0x09;
constexpr uint8_t  DW_OP_const2u           = 0x0A;
constexpr uint8_t  DW_OP_const2s           = 0x0B;
constexpr uint8_t  DW_OP_const4u           = 0x0C;
constexpr uint8_t  DW_OP_const4s           = 0x0D;
constexpr uint8_t  DW_OP_constu            = 0x10;
constexpr uint8_t  DW_OP_consts            = 0x11;
constexpr uint8_t  DW_OP_plus              = 0x22;
constexpr uint8_t  DW_OP_plus_uconst       = 0x23;
constexpr uint8_t  DW_OP_reg0              = 0x50;
constexpr uint8_t  DW_OP_reg31             = 0x6F;
constexpr uint8_t  DW_OP_fbreg             = 0x91;
constexpr uint8_t  DW_OP_call_frame_cfa    = 0x9C;
constexpr uint8_t  DW_OP_addrx             = 0xA1;
constexpr uint8_t  DW_OP_constx            = 0xA2;

struct DwarfAbbrevAttr {
    uint64_t name = 0;
    uint64_t form = 0;
    int64_t implicitConst = 0;
};

struct DwarfAbbrev {
    uint64_t code = 0;
    uint64_t tag = 0;
    bool hasChildren = false;
    std::vector<DwarfAbbrevAttr> attrs;
};

struct DwarfValue {
    uint64_t u = 0;
    int64_t s = 0;
    std::string str;
    std::vector<uint8_t> block;
    uint64_t form = 0;
    bool present = false;
    bool isString = false;
};

struct DwarfLineRow {
    uint32_t address = 0;
    uint32_t file = 0;
    uint32_t line = 0;
    bool endSequence = false;
};

struct DwarfLineTable {
    uint16_t version = 0;
    uint8_t addressSize = 4;
    std::string compDir;
    std::vector<std::string> includeDirs;
    std::vector<std::string> files;
    std::vector<DwarfLineRow> rows;
};

struct DwarfUnit {
    uint32_t offset = 0;
    uint32_t end = 0;
    uint16_t version = 0;
    uint8_t addressSize = 4;
    std::string name;
    std::string compDir;
    uint32_t stmtList = UINT32_MAX;
    uint32_t strOffsetsBase = UINT32_MAX;
    uint32_t addrBase = UINT32_MAX;
    const DwarfLineTable *lineTable = nullptr;
};
