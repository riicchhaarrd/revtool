#!/usr/bin/env python3
"""
Check if a decompiled function recompiles to matching asm.

Usage:
  python3 asmcheck.py PM_ClipVelocity
  python3 asmcheck.py 0x6C054
  python3 asmcheck.py --all          # check all functions in regtest_funcs.txt
"""

import capstone, struct, subprocess, tempfile, os, re, sys

BINARY = ''
DECOMP = './build/decomp'
APPLE_GCC = '/tmp/apple-gcc-build/gcc/xgcc'
GCC_FLAGS = ['-B/tmp/apple-gcc-build/gcc/', '-m32', '-O2', '-mdynamic-no-pic',
             '-fno-schedule-insns', '-fno-schedule-insns2', '-mtune=pentium4',
             '-fno-if-conversion',
             '-std=c99', '-w']

TYPES_HEADER = 'stabs_types.h.gen'

# Minimal stubs so decompiled code compiles without system headers
STUBS = '''
typedef unsigned int size_t;
typedef int int32_t; typedef unsigned int uint32_t;
typedef short int16_t; typedef unsigned short uint16_t;
typedef signed char int8_t; typedef unsigned char uint8_t;
typedef long long int64_t; typedef unsigned long long uint64_t;
typedef int intptr_t; typedef unsigned int uintptr_t;
typedef __builtin_va_list va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)
#define va_end(ap) __builtin_va_end(ap)
#define va_arg(ap, type) __builtin_va_arg(ap, type)
typedef int BOOL; typedef int Bool; typedef int qboolean; typedef int bool;
typedef unsigned int DWORD; typedef unsigned int UINT;
typedef float vec_t; typedef vec_t vec3_t[3]; typedef vec_t vec2_t[2];
typedef unsigned char byte;
typedef int OSStatus; typedef short OSErr; typedef int Boolean;
typedef unsigned int OSType; typedef void *CursHandle;
typedef void *WindowRef; typedef void *MenuRef; typedef void *CGrafPtr;
typedef void *ControlRef;
typedef const char *LPCSTR; typedef const char *LPCTSTR;
typedef char *LPSTR; typedef void *LARGE_INTEGER;
typedef struct { short v; short h; } Point;
typedef void *ControlHandle; typedef void *DialogRef;
extern int CGRectZero;
typedef int HCURSOR; typedef int HWND; typedef int HINSTANCE;
typedef void *GDHandle; typedef void *CursPtr;
typedef unsigned int CGDirectDisplayID;
typedef unsigned char Str255[256];
typedef struct { float x, y; } CGPoint;
typedef struct { float w, h; } CGSize;
typedef struct { CGPoint origin; CGSize size; } CGRect;
#define NULL ((void*)0)
float floorf(float); float ceilf(float); float sqrtf(float);
float sinf(float); float cosf(float); float tanf(float);
float fabsf(float);
static inline float fminf(float a, float b) { return a < b ? a : b; }
static inline float fmaxf(float a, float b) { return a > b ? a : b; }
float acosf(float); float asinf(float); float atanf(float);
float atan2f(float,float); float fmodf(float,float); float powf(float,float);
double atan2(double,double); double floor(double); double ceil(double);
double sqrt(double); double fabs(double); double pow(double,double);
double sin(double); double cos(double); double log(double);
void *memset(void*,int,size_t); void *memcpy(void*,const void*,size_t);
size_t strlen(const char*); int strcmp(const char*,const char*);
char *strcpy(char*,const char*); int sprintf(char*,const char*,...);
int printf(const char*,...); int snprintf(char*,size_t,const char*,...);
int setjmp(void*); void exit(int); void *malloc(size_t); void free(void*);
int abs(int); int atoi(const char*);
typedef void *FILE;
typedef void *unzFile;
typedef int ControlPartCode;
typedef struct { short v; short h; } MacPoint;
typedef unsigned short UniChar;
typedef int Fixed;
typedef int TextEncoding;
typedef int ScriptCode;
typedef int RegionCode;
typedef unsigned int FourCharCode;
typedef unsigned int OptionBits;
typedef int EventKind;
typedef void *EventRef;
typedef int EventParamName;
typedef int EventParamType;
typedef void *EventHandlerRef;
typedef void *EventHandlerCallRef;
typedef void *EventHandlerUPP;
typedef int EventModifiers;
typedef void *AEDesc;
typedef void *AppleEvent;
typedef void *CFRunLoopTimerContext;
typedef int IOReturn;
/* zlib types */
typedef struct { int _[16]; } z_stream;
typedef struct { int _[4]; } unz_global_info;
typedef struct { int _[16]; } unz_file_info;
typedef unsigned long uLong;
typedef unsigned int uInt;
typedef void *voidpf;
typedef int SIZE_T;
typedef int INT32;
typedef unsigned int UINT32;
typedef short INT16;
typedef unsigned short UINT16;
typedef void *LPVOID;
typedef int LONG;
/* Win32 stubs */
typedef struct { int dwLowDateTime; int dwHighDateTime; } FILETIME;
typedef struct { int _[80]; } WIN32_FIND_DATAA;
typedef void *HANDLE;
typedef int HRESULT;
typedef unsigned long ULONG;
/* D3D9 opaque types */
typedef struct IDirect3D9 IDirect3D9;
typedef struct IDirect3DDevice9 IDirect3DDevice9;
typedef struct IDirect3DTexture9 IDirect3DTexture9;
typedef struct IDirect3DBaseTexture9 IDirect3DBaseTexture9;
typedef struct IDirect3DCubeTexture9 IDirect3DCubeTexture9;
typedef struct IDirect3DVolumeTexture9 IDirect3DVolumeTexture9;
typedef struct IDirect3DSurface9 IDirect3DSurface9;
typedef struct IDirect3DVolume9 IDirect3DVolume9;
typedef struct IDirect3DVertexBuffer9 IDirect3DVertexBuffer9;
typedef struct IDirect3DIndexBuffer9 IDirect3DIndexBuffer9;
typedef struct IDirect3DVertexShader9 IDirect3DVertexShader9;
typedef struct IDirect3DPixelShader9 IDirect3DPixelShader9;
typedef struct IDirect3DVertexDeclaration9 IDirect3DVertexDeclaration9;
typedef struct IDirect3DStateBlock9 IDirect3DStateBlock9;
typedef struct IDirect3DQuery9 IDirect3DQuery9;
typedef struct IDirect3DSwapChain9 IDirect3DSwapChain9;
typedef unsigned short ScriptString;
/* Wavelet types */
struct WaveletHuffmanDecode { short value; short bits; };
extern const struct WaveletHuffmanDecode waveletDecodeAlpha[4096];
extern const struct WaveletHuffmanDecode waveletDecodeRedGreen[4096];
extern const struct WaveletHuffmanDecode waveletDecodeBlue[4096];
typedef int D3DLOCKED_BOX; typedef int D3DBOX; typedef int D3DLOCKED_RECT;
typedef int D3DFORMAT; typedef int D3DPOOL; typedef int D3DSURFACE_DESC;
typedef int D3DVIEWPORT9; typedef int D3DGAMMARAMP;
typedef int D3DPRIMITIVETYPE; typedef int D3DCAPS9; typedef int D3DDISPLAYMODE;
typedef int D3DMULTISAMPLE_TYPE; typedef int D3DDEVTYPE; typedef int D3DADAPTER_IDENTIFIER9;
typedef int D3DRENDERSTATETYPE; typedef int D3DTEXTURESTAGESTATETYPE;
typedef int D3DTRANSFORMSTATETYPE; typedef int D3DSTATEBLOCKTYPE;
typedef int D3DTEXTUREFILTERTYPE; typedef int D3DSAMPLERSTATETYPE;
typedef int D3DLIGHT9; typedef int D3DRASTER_STATUS;
/* Game engine types */
typedef int scr_thread_t;
typedef void *scr_func_t;
typedef int TextureID;
typedef int MaterialHandle;
typedef int isNegative;
typedef struct { int _[4]; } GUID;
typedef unsigned long u_long;
typedef void *CFStringRef;
typedef void *CFMutableStringRef;
typedef void *CFURLRef;
typedef void *CFBundleRef;
typedef void *CFArrayRef;
typedef void *CFDictionaryRef;
typedef void *CFTypeRef;
typedef void *AudioConverterRef;
typedef unsigned int AudioUnitRenderActionFlags;
typedef struct { int _[8]; } AudioTimeStamp;
typedef struct { int mNumberBuffers; int _[32]; } AudioBufferList;
typedef struct { int _[4]; } AudioStreamPacketDescription;
typedef struct { int _[4]; } AudioStreamBasicDescription;
typedef struct { char _[80]; } FSRef;
typedef unsigned int UInt32;
typedef float Float32;
/* Network types */
typedef int SOCKET;
typedef struct { int _[4]; } fd_set;
typedef struct { int _[2]; } timeval;
/* JPEG types */
typedef struct { int _[256]; } jpeg_compress_struct;
typedef struct { int _[256]; } jpeg_decompress_struct;
typedef jpeg_decompress_struct* j_decompress_ptr;
typedef jpeg_compress_struct* j_compress_ptr;
typedef int JDIMENSION; typedef int JSAMPLE; typedef short JCOEF;
typedef unsigned short *histptr; typedef unsigned short histcell;
typedef int JMETHOD; typedef void *j_common_ptr;
typedef int boolean;
typedef short DCTELEM;
typedef int *JSAMPARRAY; typedef int *JSAMPROW; typedef int *JBLOCKROW;
/* Dvar struct types (needed for -> field access) */
union DvarValue { int enabled; int integer; float value; float *vector; const char *string; unsigned char color[4]; };
union DvarLimits { struct { int min; int max; } integer; struct { float min; float max; } value; int enumCount; };
struct dvar_s { const char *name; unsigned short flags; unsigned char type; unsigned char modified; union DvarValue current; union DvarValue latched; union DvarValue reset; union DvarLimits domain; struct dvar_s *next; struct dvar_s *hashNext; };
typedef struct dvar_s dvar_t;
/* Auto-generated typedefs for struct _s → _t patterns */
typedef struct archivedEntity_s archivedEntity_t;
typedef struct archivedSnapshot_s archivedSnapshot_t;
typedef struct cachedClient_s cachedClient_t;
typedef struct clientState_s clientState_t;
typedef struct displayContextDef_s displayContextDef_t;
typedef struct editFieldDef_s editFieldDef_t;
typedef struct fileData_s fileData_t;
typedef struct fileInPack_s fileInPack_t;
typedef struct game_hudelem_s game_hudelem_t;
typedef struct gitem_s gitem_t;
typedef struct indent_s indent_t;
typedef struct ipFilter_s ipFilter_t;
typedef struct itemDef_s itemDef_t;
typedef struct keywordHash_s keywordHash_t;
typedef struct listBoxDef_s listBoxDef_t;
typedef struct localEntity_s localEntity_t;
typedef struct multiDef_s multiDef_t;
typedef struct pc_token_s pc_token_t;
typedef struct punctuation_s punctuation_t;
typedef struct qtime_s qtime_t;
typedef struct refdef_s refdef_t;
typedef struct scr_anim_s scr_anim_t;
typedef struct scrollInfo_s scrollInfo_t;
typedef struct serverFilter_s serverFilter_t;
typedef struct statmonitor_s statmonitor_t;
typedef struct stringDef_s stringDef_t;
typedef struct turretInfo_s turretInfo_t;
typedef struct viewLerpWaypoint_s viewLerpWaypoint_t;
typedef struct weaponInfo_s weaponInfo_t;
/* Forward declarations for function pointer struct params */
typedef struct DObjAnimMat DObjAnimMat;
typedef struct XSurface_s XSurface_s;
/* Misc missing */
/* scr_anim_t handled by auto-generated typedef */
typedef struct { int _[32]; } SpeexBits;
typedef void *ogg_stream_state;
typedef struct { int _[64]; } inflate_state;
'''

# Dvar function prototypes with proper float parameter types
# (prevents default argument promotion from float to double)
DVAR_PROTOS = '''
#ifndef DVAR_PROTOS_DEFINED
#define DVAR_PROTOS_DEFINED
dvar_t *Dvar_RegisterBool(const char*,int,int);
dvar_t *Dvar_RegisterInt(const char*,int,int,int,int);
dvar_t *Dvar_RegisterFloat(const char*,float,float,float,int);
dvar_t *Dvar_RegisterString(const char*,const char*,int);
dvar_t *Dvar_RegisterEnum(const char*,const char**,int,int);
dvar_t *Dvar_RegisterColor(const char*,float,float,float,float,int);
dvar_t *Dvar_RegisterVec2(const char*,float,float,float,float,int);
dvar_t *Dvar_RegisterVec3(const char*,float,float,float,float,float,float,int);
dvar_t *Dvar_RegisterVec4(const char*,float,float,float,float,float,float,float,float,int);
int Scr_AddFloat(float);
int Dvar_SetInt(dvar_t*,int);
int Dvar_SetFloat(dvar_t*,float);
int Dvar_SetString(dvar_t*,const char*);
int Dvar_SetBool(dvar_t*,int);
#endif
'''


def load_binary():
    with open(BINARY, 'rb') as f:
        data = f.read()
    ncmds = struct.unpack_from('<I', data, 16)[0]
    off = 28
    text_addr = text_off = 0
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == 1:
            segname = data[off+8:off+24].rstrip(b'\x00').decode()
            if segname == '__TEXT':
                so = off + 56
                for _ in range(struct.unpack_from('<I', data, off+48)[0]):
                    if data[so:so+16].rstrip(b'\x00').decode() == '__text':
                        text_addr = struct.unpack_from('<I', data, so+32)[0]
                        text_off = struct.unpack_from('<I', data, so+40)[0]
                    so += 68
        off += size
    return data, text_addr, text_off


def disasm_original(data, text_addr, text_off, func_addr, func_size=0):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.syntax = capstone.CS_OPT_SYNTAX_ATT
    fo = text_off + (func_addr - text_addr)
    size = func_size if func_size > 0 else 4096
    all_insns = []
    all_addrs = []
    for i in md.disasm(data[fo:fo+size], func_addr):
        all_insns.append(f'{i.mnemonic} {i.op_str}'.strip())
        all_addrs.append(i.address)
    if not all_insns:
        return []
    # Find the last ret
    last_ret_idx = -1
    for idx in range(len(all_insns)):
        if all_insns[idx] in ('ret', 'retl'):
            last_ret_idx = idx
    # Find forward branch targets from BEFORE the last ret that land AFTER it
    # (these are code blocks like error handlers placed after the return)
    end_idx = last_ret_idx + 1 if last_ret_idx >= 0 else len(all_insns)
    for idx in range(end_idx):
        m = re.match(r'j\w+\s+(0x[0-9a-fA-F]+)', all_insns[idx])
        if m:
            target = int(m.group(1), 16)
            # Find the instruction index for this target
            for tidx in range(end_idx, len(all_insns)):
                if all_addrs[tidx] == target:
                    # Extend to include this block (until next ret/jmp/padding)
                    for bidx in range(tidx, len(all_insns)):
                        s = all_insns[bidx]
                        end_idx = max(end_idx, bidx + 1)
                        if s.startswith('ret') or s.startswith('jmp'):
                            break
                    break
    insns = all_insns[:end_idx]
    while insns and insns[-1] in ('nop', 'hlt', 'int3', 'ud2'):
        insns.pop()
    return insns


def compile_to_asm_raw(c_code):
    """Compile code as-is without stubs. Used for full source files."""
    basic = 'typedef unsigned int size_t;\ntypedef __builtin_va_list va_list;\n#define NULL ((void*)0)\n'
    full = basic + c_code
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(full)
        cpath = f.name
    try:
        r = subprocess.run([APPLE_GCC] + GCC_FLAGS + ['-S', '-o', '-', cpath],
                           capture_output=True, text=True, timeout=60)
        return r.returncode == 0, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return False, '', 'timeout'
    finally:
        os.unlink(cpath)


_types_header_cache = None

def _load_types_header():
    global _types_header_cache
    if _types_header_cache is None and os.path.exists(TYPES_HEADER):
        with open(TYPES_HEADER) as f:
            _types_header_cache = f.readlines()
    return _types_header_cache


def extract_struct_from_header(name):
    """Extract a specific struct/union/enum/typedef definition from the types header."""
    lines = _load_types_header()
    if not lines:
        return None

    # First pass: look for full definition (struct NAME { ... };)
    result = []
    in_block = False
    brace_depth = 0
    for line in lines:
        stripped = line.strip()
        if not in_block:
            if (stripped.startswith('struct ' + name + ' {') or
                stripped.startswith('union ' + name + ' {') or
                stripped.startswith('enum ' + name + ' {')):
                in_block = True
                brace_depth = stripped.count('{') - stripped.count('}')
                result.append(line)
                if brace_depth <= 0:
                    return ''.join(result)
                continue
        else:
            result.append(line)
            brace_depth += line.count('{') - line.count('}')
            if brace_depth <= 0:
                return ''.join(result)

    # Second pass: look for typedef
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('typedef ') and stripped.endswith(';'):
            if f' {name};' in stripped or f' {name}[' in stripped or f'*{name};' in stripped:
                result = line
                # If it's typedef struct X name, also extract struct X
                m = re.match(r'typedef\s+struct\s+(\w+)\s+' + re.escape(name), stripped)
                if m:
                    struct_def = extract_struct_from_header(m.group(1))
                    if struct_def:
                        result = struct_def + '\n' + result
                return result

    return None


def _try_compile(code, extra_flags=None):
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(code); cpath = f.name
    try:
        flags = GCC_FLAGS + (extra_flags or [])
        r = subprocess.run([APPLE_GCC] + flags + ['-S', '-o', '-', cpath],
                           capture_output=True, text=True, timeout=30)
        return r.returncode == 0, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return False, '', 'timeout'
    finally:
        os.unlink(cpath)


def compile_to_asm(c_code, orig_check=None, extra_flags=None):
    # Pre-extract all struct/typedef types referenced in the code from the types header
    extracted = {}  # name -> definition (ordered by dependency)
    # Find struct references AND typedef names (Type_t patterns used as pointer types)
    refs = set(re.findall(r'(?:struct|union)\s+([\w$]+)', c_code))
    # Also find typedef names used as pointer base types: "type_t *var"
    # Skip simple types already in STUBS (vec_t, qboolean, etc.)
    stubs_types = set(re.findall(r'typedef\s+\S+.*?\s+(\w+)\s*[;\[]', STUBS))
    # Find _t types used as pointer types: "type_t *var"
    for m in re.finditer(r'\b(\w+_t)\s*\*\s*\w+', c_code):
        name = m.group(1)
        if name not in stubs_types:
            refs.add(name)
    # Also find CamelCase/uppercase type names used as pointer types: "TypeName *var"
    for m in re.finditer(r'\b([A-Z]\w+)\s*\*\s*\w+', c_code):
        name = m.group(1)
        if name not in stubs_types and name not in ('NULL', 'BOOL', 'Bool', 'DWORD', 'UINT'):
            refs.add(name)
    # Find globals used with .field access and look up their struct types.
    # Pattern: "globalName.field" in code → find "extern struct X globalName;" in header
    global_externs = []
    lines_h = _load_types_header()
    if lines_h:
        # Build a map of global → struct type from extern declarations
        global_types = {}
        for line in lines_h:
            m = re.match(r'extern\s+(?:const\s+)?struct\s+(\w+)\s+\*?\s*(\w+)\s*(?:\[[\d]*\])?\s*;', line.strip())
            if m:
                global_types[m.group(2)] = m.group(1)
        # Find globals used with .field or ->field, extract their struct types
        # AND add extern declarations so the compiler knows the variable type
        global_externs = []
        # Also store the original extern lines for exact reproduction
        global_extern_lines = {}
        for line in lines_h:
            m2 = re.match(r'(extern\s+(?:const\s+)?struct\s+\w+\s+\*?\s*(\w+)\s*(?:\[[\d]*\])?\s*;)', line.strip())
            if m2:
                global_extern_lines[m2.group(2)] = m2.group(1)
        for m in re.finditer(r'\b(\w+)[.](\w+)', c_code):
            gname = m.group(1)
            if gname in global_types:
                stype = global_types[gname]
                refs.add(stype)
                # Only add extern if the struct is fully defined in the header
                if extract_struct_from_header(stype) and gname in global_extern_lines:
                    global_externs.append(global_extern_lines[gname])
        # Also handle ->field access on pointer globals
        for m in re.finditer(r'\b(\w+)->(\w+)', c_code):
            gname = m.group(1)
            if gname in global_types:
                stype = global_types[gname]
                refs.add(stype)
                if extract_struct_from_header(stype) and gname in global_extern_lines:
                    global_externs.append(global_extern_lines[gname])
    # Types already defined in STUBS — don't extract from header
    stubs_structs = {'DvarValue', 'DvarLimits', 'dvar_s', 'dvar_t', 'Point', 'MacPoint',
                     'CGPoint', 'CGSize', 'CGRect', 'MacRGBColor', 'WaveletHuffmanDecode',
                     'z_stream', 'unz_global_info', 'unz_file_info', 'FILETIME',
                     'WIN32_FIND_DATAA', 'fd_set', 'timeval', 'Rect',
                     'jpeg_compress_struct', 'jpeg_decompress_struct', 'SpeexBits', 'inflate_state'}
    queue = list(refs)
    visited = set()
    while queue:
        name = queue.pop(0)
        if name in visited: continue
        visited.add(name)
        if name in stubs_structs: continue
        defn = extract_struct_from_header(name)
        # If not found and name ends in _t, try _s (typedef → struct mapping)
        if not defn and name.endswith('_t'):
            s_name = name[:-2] + '_s'
            defn = extract_struct_from_header(s_name)
            if defn:
                # Add typedef only if not already in stubs
                if name not in stubs_types:
                    defn = defn.rstrip() + '\ntypedef struct ' + s_name + ' ' + name + ';\n'
        if defn:
            # Skip structs with invalid C (vtable pointers, C++ artifacts)
            # Note: $_NNNN anonymous types are valid GCC extensions, don't skip those
            if '::' in defn or '_vptr' in defn:
                continue
            # Fix self-referencing array fields: "TypeName field[N]" where TypeName
            # is the struct being defined → replace with "char field[N*4]" padding
            fixed_defn = defn
            # Find the struct name being defined
            sm = re.match(r'(?:struct|union)\s+(\w+)\s*\{', defn.strip())
            if sm:
                sname = sm.group(1)
                # Also get typedef aliases for this struct
                aliases = {sname, name}
                for line in defn.split('\n'):
                    tm = re.match(r'typedef\s+struct\s+\w+\s+(\w+)\s*;', line.strip())
                    if tm: aliases.add(tm.group(1))
                # Replace self-referencing array fields
                def fix_self_ref(m):
                    typename = m.group(1)
                    fname = m.group(2)
                    count = int(m.group(3)) if m.group(3) else 1
                    if typename in aliases:
                        return f'    char {fname}[{count * 4}];'
                    return m.group(0)
                fixed_defn = re.sub(
                    r'^\s+(\w+)\s+(\w+)\[(\d+)\]\s*;',
                    fix_self_ref, fixed_defn, flags=re.MULTILINE)
            extracted[name] = fixed_defn
            # Also register any struct tags defined in this block and queue for deps
            for m in re.finditer(r'struct\s+(\w+)\s*\{', defn):
                tag = m.group(1)
                if tag not in extracted:
                    extracted[tag] = defn
                    if tag not in visited:
                        queue.append(tag)
            # Extract dependencies: struct/union/enum fields AND typedef references
            for m in re.finditer(r'(?:struct|union|enum)\s+([\w$]+)\s+[\w$]+', defn):
                if m.group(1) not in visited:
                    queue.append(m.group(1))
            for m in re.finditer(r'\b(\w+_t)\s+\*?\s*\w+', defn):
                dep = m.group(1)
                if dep not in visited and dep not in stubs_types:
                    queue.append(dep)
            # Also follow CamelCase type names used as pointer or array types in fields
            for m in re.finditer(r'\b([A-Z]\w+)\s+(?:\*|\w+\s*\[)', defn):
                dep = m.group(1)
                if dep not in visited and dep not in stubs_types:
                    queue.append(dep)

    # Extract function prototypes for key functions that return typed pointers.
    # Only include prototypes whose return types AND param types are all defined.
    func_protos = ''
    lines = _load_types_header()
    if lines:
        in_protos = False
        # Functions called in the code whose return value is assigned
        assigned_calls = set()
        for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\(', c_code):
            assigned_calls.add(m.group(2))
        # Also capture functions used as arguments to other functions
        # (e.g., atanf(Scr_GetFloat(0)) — Scr_GetFloat's return type matters)
        for m in re.finditer(r'\(\s*(\w+)\s*\(', c_code):
            name = m.group(1)
            if name not in ('if', 'while', 'for', 'switch', 'return', 'sizeof', 'void', 'int', 'float', 'char'):
                assigned_calls.add(name)
        for line in lines:
            if '/* Function prototypes */' in line:
                in_protos = True
                continue
            if not in_protos:
                continue
            # Extract function name from prototype line
            m = re.match(r'(?:const\s+)?(?:struct\s+)?(?:\w[\w\s\*]*?)\s+\*?\s*(\w+)\s*\(', line.strip())
            if not m:
                continue
            if not m or m.group(1) not in assigned_calls:
                continue
            proto_name = m.group(1)
            # Don't add if function is defined in the code
            if re.search(r'\b' + re.escape(proto_name) + r'\s*\([^)]*\)\s*\{', c_code):
                continue
            # Skip known variadic functions
            if proto_name in ('va', 'Com_Printf', 'Com_Error', 'Com_DPrintf',
                              'Sys_Error', 'dprintf', 'Com_sprintf'):
                continue
            # Skip void-returning prototypes if the code assigns the return value
            stripped = line.strip()
            if (stripped.startswith('void ') or stripped.startswith('int void ')) and \
               proto_name in assigned_calls:
                continue
            # Only include if all types in the prototype are known
            # (check for struct/union references that aren't extracted)
            proto_types = re.findall(r'\b(struct|union)\s+(\w+)', line)
            all_known = True
            for kw, tname in proto_types:
                if tname not in extracted and tname + '_t' not in stubs_types and tname not in stubs_types:
                    all_known = False; break
            if not all_known:
                continue
            # Skip prototypes with unknown typedefs
            skip = False
            for word in re.findall(r'\b(\w+_t)\b', line):
                if word not in stubs_types and word not in extracted:
                    skip = True; break
            if skip:
                continue
            func_protos += line

    # Build: STUBS + extracted types (dependency-ordered) + prototypes + code
    # Topological sort: emit dependencies before dependents
    ordered = []
    emitted_set = set()
    def emit_type(name):
        if name in emitted_set or name not in extracted: return
        emitted_set.add(name)
        defn = extracted[name]
        # Mark struct tags defined in this block as emitted
        for m in re.finditer(r'struct\s+(\w+)\s*\{', defn):
            emitted_set.add(m.group(1))
        # Emit dependencies first (struct, union, enum)
        for m in re.finditer(r'(?:struct|union|enum)\s+([\w$]+)\s+[\w$]+', defn):
            emit_type(m.group(1))
        for m in re.finditer(r'\b(\w+_t)\s+\*?\s*\w+', defn):
            if m.group(1) not in emitted_set:
                emit_type(m.group(1))
        # Also follow CamelCase type references (pointer and array fields)
        for m in re.finditer(r'\b([A-Z]\w+)\s+(?:\*|\w+\s*\[)', defn):
            dep = m.group(1)
            if dep not in emitted_set and dep in extracted:
                emit_type(dep)
        ordered.append(defn)
    for name in extracted:
        emit_type(name)
    types_block = '\n'.join(ordered)
    # Remove extracted type lines that conflict with STUBS definitions
    for sname in stubs_structs:
        # Remove standalone typedef lines like "typedef struct { ... } Point;"
        types_block = re.sub(r'typedef\s+struct\s*\{[^}]*\}\s+' + re.escape(sname) + r'\s*;', '', types_block)
        # Remove "union Name { ... };" or "struct Name { ... };" blocks
        types_block = re.sub(r'(?:union|struct)\s+' + re.escape(sname) + r'\s*\{[^}]*\}\s*;', '', types_block)
    # Auto-generate typedefs: if the code uses "TypeName *" or "TypeName var"
    # and "struct TypeName" or "struct TypeName_s" is extracted, add typedef
    # Auto-typedef: when code uses CamelCase types that match a struct in
    # the types header, add "typedef struct X X;" so the type is known.
    # Only for types explicitly used as pointer types in the function code
    # (e.g., "TypeName *var") to avoid generating typedefs that conflict.
    auto_typedefs = []
    all_defined = set(re.findall(r'typedef\s+\S.*?\s+(\w+)\s*[\[;]', STUBS + types_block))
    for m in re.finditer(r'\b([A-Z]\w+)\s+\*', c_code):
        name = m.group(1)
        if name in all_defined or name in emitted_set: continue
        if name in ('NULL', 'BOOL', 'Bool', 'DWORD', 'UINT'): continue
        sname = name if name in extracted else (name + '_s' if name + '_s' in extracted else None)
        if not sname:
            for suffix in ('', '_s'):
                defn = extract_struct_from_header(name + suffix)
                if defn and '::' not in defn and '_vptr' not in defn:
                    sname = name + suffix
                    extracted[sname] = defn
                    emit_type(sname)
                    break
        if sname:
            # If the extracted block has the full struct+typedef, emit it directly
            ext_block = extracted.get(name, '') or extracted.get(sname, '')
            if ext_block and f'typedef struct' in ext_block and f' {name};' in ext_block:
                # Check if struct body isn't already in types_block
                if ext_block.strip() not in types_block:
                    types_block = ext_block + '\n' + types_block
                continue
            auto_typedefs.append(f'typedef struct {sname} {name};')
    if auto_typedefs:
        types_block += '\n' + '\n'.join(set(auto_typedefs))
    # Add extern declarations for globals with struct types
    if global_externs:
        types_block += '\n' + '\n'.join(set(global_externs))
    # Always include Dvar function prototypes.
    # Only include the 'typedef int dvar_t' stub if the real dvar_t isn't extracted.
    # dvar_t struct is defined in STUBS. Always include DVAR_PROTOS for
    # the Dvar function prototypes (the typedef was removed from DVAR_PROTOS).
    dvar_block = DVAR_PROTOS
    # Remove any Dvar function prototypes from types_block/func_protos to avoid conflicts
    func_protos = re.sub(r'^.*\bDvar_\w+\b.*\n', '', func_protos, flags=re.MULTILINE)
    full = STUBS + '\n' + dvar_block + '\n' + types_block + '\n' + func_protos + '\n' + c_code

    # Try compile with extracted types
    ok, stdout, stderr = _try_compile(full, extra_flags)
    if ok: return True, stdout, stderr

    # Retry: add simple stubs for remaining undeclared names
    q = r"[\x60\x27\u2018]"; cq = r"[\x27\u2019]"
    stubs_types = set()  # track what we've added as types
    for attempt in range(5):
        undeclared = set()
        for m in re.finditer(q + r"(\w+)" + cq + r" undeclared", stderr): undeclared.add(m.group(1))
        for m in re.finditer(r"syntax error before " + q + r"(\w+)" + cq, stderr):
            token = m.group(1)
            undeclared.add(token)
            # If the token is '*', look at the error line for the unknown type before it
            if token == '*':
                for em in re.finditer(r":(\d+):.*syntax error before.*\*", stderr):
                    eln = int(em.group(1))
                    code_lines = full.split('\n')
                    if eln <= len(code_lines):
                        eline = code_lines[eln-1].strip()
                        # Find words before * that look like type names
                        words = re.findall(r'\b(\w+)\b', eline)
                        for w in words:
                            if (w[0].isupper() or w.endswith('_t') or w.endswith('_s')) and len(w) > 2:
                                undeclared.add(w)
                    break
        # "dereferencing pointer to incomplete type" - add struct definition
        for m in re.finditer(r"dereferencing pointer to incomplete type", stderr):
            # Find the struct name from context
            pass  # handled below with struct stub generation
        # "invalid type argument of '->' / 'unary *'" - the variable needs pointer type
        # "invalid operands to binary" - type mismatch, try casting
        # These are harder to fix automatically
        # Handle "two or more data types": often C++ template return types
        for m in re.finditer(r':(\d+):.*two or more data types', stderr):
            lineno = int(m.group(1))
            code_lines = full.split('\n')
            if lineno <= len(code_lines):
                line_text = code_lines[lineno-1].strip()
                # C++ template return type: "struct __X<...> funcname(...)"
                # Replace with "int funcname(...)"
                if '<' in line_text:
                    cleaned = re.sub(r'^(?:struct\s+)?\w+<[^>]*>\s*', 'int ', line_text)
                    code_lines[lineno-1] = cleaned
                    full = '\n'.join(code_lines)
                    continue
                # First word(s) before the function name are the unknown return type
                # Try uppercase first, then any word that looks like a type
                words = re.findall(r'\b(\w+)\b', line_text)
                for w in words:
                    if w in ('static', 'void', 'int', 'char', 'float', 'double',
                             'unsigned', 'signed', 'const', 'struct', 'union',
                             'short', 'long', 'typedef', 'extern', 'inline',
                             'NULL', 'TRUE', 'FALSE', 'return', 'if', 'else',
                             'while', 'for', 'do', 'switch', 'case', 'break'):
                        continue
                    if len(w) > 1 and w not in already and w not in funcs:
                        undeclared.add(w)
                        break
        # Handle "storage size of 'X' isn't known" - add struct stub
        for m in re.finditer(r"storage size of " + q + r"(\w+)" + cq + r" isn.t known", stderr):
            vname = m.group(1)
            # Find the declaration line to get the type
            for line in full.split('\n'):
                if vname in line and ('struct ' in line or '_t ' in line):
                    tm = re.search(r'((?:struct\s+)?\w+)\s+' + re.escape(vname) + r'\s*[;\[]', line)
                    if tm:
                        tname = tm.group(1).strip()
                        if tname.startswith('struct '):
                            sname = tname.split()[1]
                            undeclared.add(sname)
                        elif tname.endswith('_t'):
                            # Try _t → _s struct extraction
                            s_name = tname[:-2] + '_s'
                            s_defn = extract_struct_from_header(s_name)
                            if s_defn and s_defn.strip() not in full:
                                idx = full.find(STUBS) + len(STUBS) if STUBS in full else 0
                                full = full[:idx] + s_defn + '\n' + full[idx:]
                    break
        # Handle "variable or field declared void" - the decompiler emitted void type
        for m in re.finditer(r"variable or field " + q + r"(\w+)" + cq + r" declared void", stderr):
            # Find the line and change 'void' to 'int'
            vname = m.group(1)
            full = re.sub(r'\bvoid\s+' + re.escape(vname) + r'\s*;',
                         'int ' + vname + ';', full)
            full = re.sub(r'\bvoid\s+' + re.escape(vname) + r'\s*=',
                         'int ' + vname + ' =', full)
        # Handle "assignment of read-only member" — strip const from pointer params
        # (aggregate value errors are fixed in the decompiler, not here)
        if 'read-only' in stderr:
            full = re.sub(r'\bconst\s+((?:struct\s+)?\w+\s*\*)', r'\1', full)
        # Handle "label at end of compound statement" - add empty statement after label
        if 'label at end of compound statement' in stderr:
            full = re.sub(r'(bb_\d+:)\s*\n(\s*\})', r'\1 ;\n\2', full)
            full = re.sub(r'(bb_\d+:)\s*\}', r'\1 ; }', full)
        # Handle "array type has incomplete element type" — replace array field with char padding
        for m in re.finditer(r':(\d+):.*array type has incomplete element type', stderr):
            lineno = int(m.group(1))
            code_lines = full.split('\n')
            if lineno <= len(code_lines):
                line_text = code_lines[lineno-1].strip()
                # Match: "TypeName field[N];" and replace with "char field[N*4];"
                am = re.match(r'\s*(\w+)\s+(\w+)\[(\d+)\]\s*;', code_lines[lineno-1])
                if am:
                    tname, fname, count = am.group(1), am.group(2), int(am.group(3))
                    indent = len(code_lines[lineno-1]) - len(code_lines[lineno-1].lstrip())
                    code_lines[lineno-1] = ' ' * indent + f'char {fname}[{count * 4}];'
                    full = '\n'.join(code_lines)
        # Handle "dereferencing pointer to incomplete type" - add struct definition
        for m in re.finditer(r"dereferencing pointer to incomplete type", stderr):
            pass  # extract struct name from the error line
        for m in re.finditer(r":(\d+):.*dereferencing pointer to incomplete type", stderr):
            lineno = int(m.group(1))
            code_lines = full.split('\n')
            if lineno <= len(code_lines):
                line_text = code_lines[lineno-1]
                # Look for struct X * patterns near this line
                for sm in re.finditer(r'struct\s+(\w+)\s*\*', full):
                    sname = sm.group(1)
                    # Check if this struct has a definition
                    if not re.search(r'struct\s+' + re.escape(sname) + r'\s*\{', full):
                        # Add a stub struct definition
                        stub = f'struct {sname} {{ int _[64]; }};\n'
                        if stub not in full:
                            idx = full.find(STUBS) + len(STUBS) if STUBS in full else 0
                            full = full[:idx] + stub + full[idx:]
                            break  # one at a time
        # Handle "switch quantity not an integer" - cast to int
        for m in re.finditer(r":(\d+):.*switch quantity not an integer", stderr):
            lineno = int(m.group(1))
            code_lines = full.split('\n')
            if lineno <= len(code_lines):
                line_text = code_lines[lineno-1]
                code_lines[lineno-1] = re.sub(r'switch\s*\((.+?)\)', r'switch ((int)(\1))', line_text)
                full = '\n'.join(code_lines)
        # Remove conflicting stubs
        for m in re.finditer(r"conflicting types for " + q + r"(\w+)" + cq, stderr):
            cname = re.escape(m.group(1))
            full = re.sub(r'^extern\s+\w+\s+\*?' + cname + r'\s*;.*\n', '', full, flags=re.MULTILINE)
            full = re.sub(r'^void\s+' + cname + r'\s*\(void\)\s*;.*\n', '', full, flags=re.MULTILINE)
            full = re.sub(r'^typedef\s+int\s+' + cname + r'\s*;.*\n', '', full, flags=re.MULTILINE)
        # Also handle "redefinition of 'struct/union X'" — remove the duplicate
        for m in re.finditer(r"redefinition of " + q + r"(?:struct|union)\s+(\w+)" + cq, stderr):
            cname = re.escape(m.group(1))
            # Remove the SECOND definition (keep the first from pre-extraction)
            # Find all occurrences and remove all but the first
            pattern = r'(?:struct|union) ' + cname + r' \{[^}]*\};\n'
            matches = list(re.finditer(pattern, full))
            if len(matches) > 1:
                # Remove from the end to preserve indices
                for match in reversed(matches[1:]):
                    full = full[:match.start()] + full[match.end():]
        for m in re.finditer(r"redeclared as different kind of symbol.*\n.*previous declaration of " + q + r"(\w+)" + cq, stderr):
            cname = re.escape(m.group(1))
            full = re.sub(r'^extern\s+\w+\s+\*?' + cname + r'\s*;.*\n', '', full, flags=re.MULTILINE)
            full = re.sub(r'^void\s+' + cname + r'\s*\(void\)\s*;.*\n', '', full, flags=re.MULTILINE)
            full = re.sub(r'^typedef\s+int\s+' + cname + r'\s*;.*\n', '', full, flags=re.MULTILINE)
        # Handle "incompatible types in assignment" — add (int) cast for simple RHS
        for m in re.finditer(r':(\d+):.*incompatible types in assignment', stderr):
            lineno = int(m.group(1))
            code_lines = full.split('\n')
            if lineno <= len(code_lines):
                line_text = code_lines[lineno-1].rstrip()
                # Only cast simple RHS: identifiers and function calls, not struct values
                rm = re.search(r'=\s*(\w[\w.>*()-]*)\s*;$', line_text)
                if rm and 'struct ' not in rm.group(1):
                    rhs = rm.group(1)
                    code_lines[lineno-1] = line_text[:rm.start()] + '= (int)(' + rhs + ');'
                    full = '\n'.join(code_lines)
        # Handle "incompatible types in return" — change return type to match
        if 'incompatible types in return' in stderr:
            # Find the function signature and change return type
            # Most common: function returns int but code returns a pointer, or vice versa
            func_m = re.search(r'^((?:static\s+)?)(int|void|float|char)\s+(\w+\s*\()', full, re.MULTILINE)
            if func_m:
                old_type = func_m.group(2)
                if old_type == 'int':
                    # Try void* (returning a pointer)
                    full = full[:func_m.start(2)] + 'void *' + full[func_m.end(2):]
                elif old_type == 'void':
                    full = full[:func_m.start(2)] + 'int' + full[func_m.end(2):]
        # Handle "void value not ignored" — change void func to int return
        for m in re.finditer(r"void value not ignored as it ought to be", stderr):
            # Find which void function is being used as a value
            for vm in re.finditer(r"(\w+)\s*=\s*(\w+)\s*\(", full):
                fname = vm.group(2)
                # If the function is declared as void, change to int
                old_proto = re.search(r'^void\s+' + re.escape(fname) + r'\s*\(', full, re.MULTILINE)
                if old_proto:
                    full = full[:old_proto.start()] + 'int ' + fname + full[old_proto.start()+5+len(fname):]
                    break
        # Handle "too few/many arguments to function" - fix prototype arg count
        for m in re.finditer(r"too (?:few|many) arguments to function " + q + r"(.+?)" + cq, stderr):
            fname_raw = m.group(1)
            # Extract function name (may be wrapped in expression)
            fm = re.search(r'\b(\w+)\s*$', fname_raw)
            if not fm: continue
            fname = fm.group(1)
            # Count actual arguments at the call site
            call_pat = re.escape(fname) + r'\s*\('
            cm = re.search(call_pat, full)
            if not cm: continue
            # Count args by tracking parens
            start = cm.end() - 1
            depth = 0; nargs = 0; i = start
            for i in range(start, min(start+500, len(full))):
                if full[i] == '(': depth += 1
                elif full[i] == ')':
                    depth -= 1
                    if depth == 0:
                        if i > start + 1: nargs += 1  # non-empty args
                        break
                elif full[i] == ',' and depth == 1: nargs += 1
            if nargs > 0:
                # Remove old prototype and add new one
                full = re.sub(r'^(?:int|void)\s+' + re.escape(fname) + r'\s*\([^)]*\)\s*;.*\n',
                             '', full, flags=re.MULTILINE)
                params = ', '.join(['int'] * nargs)
                new_proto = f'int {fname}({params});\n'
                idx = full.find(STUBS) + len(STUBS) if STUBS in full else 0
                full = full[:idx] + new_proto + full[idx:]
        # Handle "invalid operands to binary &/|/+" — pointer/struct used in bitwise ops
        for m in re.finditer(r':(\d+):.*invalid operands to binary ([&|+*\-])', stderr):
            lineno = int(m.group(1))
            code_lines = full.split('\n')
            if lineno <= len(code_lines):
                line_text = code_lines[lineno-1]
                # Cast pointer/struct expressions in binary ops to (int)
                op = m.group(2)
                # Try common patterns: (expr) OP N, var OP N, expr OP expr
                patched = re.sub(
                    r'\((.+?)\)\s*' + re.escape(op) + r'\s*(-?\d+)',
                    r'((int)(\1)) ' + op + r' \2', line_text, count=1)
                if patched == line_text:
                    # Try: var OP (expr) — cast the var
                    patched = re.sub(
                        r'\b(\w+)\s*' + re.escape(op) + r'\s*\(',
                        r'((int)\1) ' + op + ' (', line_text, count=1)
                code_lines[lineno-1] = patched
                full = '\n'.join(code_lines)
        # Handle "aggregate value used where an integer was expected"
        # — struct field assigned to int variable; cast RHS to (int)
        for m in re.finditer(r':(\d+):.*aggregate value used where an integer was expected', stderr):
            lineno = int(m.group(1))
            code_lines = full.split('\n')
            if lineno <= len(code_lines):
                line_text = code_lines[lineno-1]
                # Cast the RHS struct expression: "var = expr;" → "var = *(int*)&(expr);"
                code_lines[lineno-1] = re.sub(
                    r'(\w+\s*=\s*)(.+);$', r'\1*(int*)&(\2);', line_text.rstrip(), count=1)
                full = '\n'.join(code_lines)
        if not undeclared:
            # Even with no undeclared names, try recompiling if we patched the code
            ok, stdout, stderr = _try_compile(full, extra_flags)
            if ok: return True, stdout, stderr
            break
        already = set(re.findall(r'(?:typedef|struct|union|extern|enum)\s+\w+.*?\s+(\w+)\s*[;\{]', full))
        funcs = set(re.findall(r'\b(?:int|void|float|static)\s+(\w+)\s*\(', full))
        stubs = ''
        # Find names used in direct assignments (A = B; where B is a bare identifier)
        # These are function pointer assignments — declare B as void*
        assign_rhs = set()
        for m in re.finditer(r'^\s+\w+\s*=\s*(\w+)\s*;$', full, re.MULTILINE):
            rhs = m.group(1)
            if not rhs[0].isdigit() and rhs not in ('0', 'NULL', 'true', 'false'):
                assign_rhs.add(rhs)
        call_args = set()  # unused — kept for compatibility
        for name in sorted(undeclared):
            if name in already or name in funcs or name in extracted: continue
            # Use static for real globals to get direct addressing (no non_lazy_ptr).
            # Don't use static for decompiler-generated names (vN, varN, tN, gN)
            # which might shadow local variables.
            # Use static for read-only globals (direct addressing, no NLP).
            # But NOT for globals that are written to in the function
            # (static enables constant folding of initial value = 0).
            is_real_global = (not re.match(r'^(v\d|var_|t\d)', name) and
                              len(name) > 2 and name[0].islower())
            is_written = bool(re.search(re.escape(name) + r'\s*=\s*', full))
            # Written globals compared to 0 need 'static volatile' to prevent
            # constant folding (compiler folds static_var == 0 to true).
            # Other written globals use plain 'static'.
            is_zero_compared = is_written and re.search(
                re.escape(name) + r'\s*==\s*0\b', full)
            if is_real_global and is_zero_compared:
                qual = 'static volatile '
            elif is_real_global:
                qual = 'static '
            else:
                qual = ''
            if re.search(r'\*\s*\(' + re.escape(name) + r'\)|' +
                          re.escape(name) + r'\s*->|' +
                          re.escape(name) + r'\s*\[', full):
                # If used with -> and a field name, try to find the struct type
                arrow_field = re.search(re.escape(name) + r'\s*->\s*(\w+)', full)
                struct_type = None
                if arrow_field:
                    field_name = arrow_field.group(1)
                    # Search for this field in extracted types AND STUBS
                    # Check STUBS first (dvar_s is defined there)
                    for struct_m in re.finditer(r'struct\s+(\w+)\s*\{([^}]+)\}', STUBS):
                        if re.search(r'\b' + re.escape(field_name) + r'\b', struct_m.group(2)):
                            struct_type = 'struct ' + struct_m.group(1)
                            break
                    if not struct_type:
                        for tname, tdef in extracted.items():
                            if re.search(r'\b' + re.escape(field_name) + r'\b', tdef) and \
                               'struct' in tdef:
                                struct_type = tname
                                break
                if struct_type:
                    stubs += f'{qual}{struct_type} *{name};\n'
                else:
                    stubs += f'{qual}int *{name};\n'
            elif name.endswith('_f'):
                stubs += f'void {name}(void);\n'
            elif (name in assign_rhs and name not in stubs_types):
                if name not in already:
                    # Names starting with uppercase used as RHS of assignment are likely
                    # function names (function pointer assignment). Declare as function
                    # prototypes so the compiler uses the address as an immediate.
                    if name[0].isupper():
                        stubs += f'int {name}(void);\n'
                    else:
                        stubs += f'{qual}void *{name};\n'
            elif re.search(r'\(int\)\s*' + re.escape(name) + r'\b', full):
                # Used in (int)NAME — it's a function address, declare as function
                stubs += f'int {name}(void);\n'
            elif name[0].isupper() or name.endswith('_t'):
                stubs += f'typedef int {name};\n'
            else:
                stubs += f'{qual}int {name};\n'
        if not stubs: break
        idx = full.find(STUBS) + len(STUBS) if STUBS in full else 0
        full = full[:idx] + stubs + full[idx:]
        ok, stdout, stderr = _try_compile(full, extra_flags)
        if ok: return True, stdout, stderr

    return False, '', stderr


def extract_func_asm(asm_text, func_name):
    """Extract a function's instructions from gcc -S output (all basic blocks)."""
    insns = []
    in_func = False
    for line in asm_text.split('\n'):
        if f'_{func_name}:' in line:
            in_func = True
            continue
        if not in_func:
            continue
        stripped = line.strip()
        # Stop at next global function label or section directive
        # (skip L-labels and numeric labels like 0: 1: etc.)
        if stripped.endswith(':') and not stripped.startswith('L') and not stripped[0].isdigit():
            if not line.startswith('\t') and not line.startswith(' '):
                break
        if stripped.startswith('.section') or stripped.startswith('.subsections'):
            break
        if not stripped or stripped.startswith('.'):
            continue
        if (stripped.startswith('L') or stripped[0].isdigit()) and stripped.endswith(':'):
            continue  # skip local and numeric labels
        insns.append(stripped)
    # Strip trailing padding
    while insns and insns[-1] in ('hlt', 'nop', 'hlt ; hlt ; hlt ; hlt ; hlt'):
        insns.pop()
    return insns


def norm(s):
    """Normalize an instruction for comparison."""
    s = s.strip().replace('\t', ' ')
    # Hex offsets to decimal
    s = re.sub(r'0x([0-9a-fA-F]+)', lambda m: str(int(m.group(1), 16)), s)
    # Collapse whitespace and normalize comma spacing
    s = re.sub(r'\s+', ' ', s)
    s = re.sub(r',\s*', ', ', s)
    # Strip comments
    s = s.split('#')[0].strip()
    # retl -> ret, calll -> call, leave -> popl %ebp, cvtsi2ssl -> cvtsi2ss
    s = re.sub(r'^retl\b', 'ret', s)
    s = re.sub(r'^calll\b', 'call', s)
    s = re.sub(r'^jmpl\b', 'jmp', s)
    s = re.sub(r'^leave$', 'popl %ebp', s)
    s = re.sub(r'^cvtsi2ssl\b', 'cvtsi2ss', s)
    # sall/sarl → shll/shrl (same x86 encoding for shift)
    s = re.sub(r'^sall\b', 'shll', s)
    s = re.sub(r'^sarl\b', 'shrl', s)
    # xorl %reg, %reg → movl $0, %reg (both zero a register, same semantics)
    m = re.match(r'^xorl (%\w+), \1$', s)
    if m:
        s = f'movl $0, {m.group(1)}'
    # Normalize addl $-N → subl $N and subl $-N → addl $N
    m = re.match(r'^(addl|subl) \$-(\d+)(.*)', s)
    if m:
        op = 'subl' if m.group(1) == 'addl' else 'addl'
        s = f'{op} ${m.group(2)}{m.group(3)}'
    # Normalize leal with zero displacement: leal 0(,%reg,N) → leal (,%reg,N)
    s = re.sub(r'^(leal) 0\(,', r'\1 (,', s)
    # Normalize string ops: repe/repz and repne/repnz
    s = re.sub(r'^repe\b', 'repz', s)
    s = re.sub(r'^repne\b', 'repnz', s)
    # Strip implicit operands from string ops (esi/edi/al)
    s = re.sub(r'^(repz cmpsb).*', r'\1', s)
    s = re.sub(r'^(repnz scasb).*', r'\1', s)
    s = re.sub(r'^(rep movs[blwd]).*', r'\1', s)
    s = re.sub(r'^(rep stos[blwd]).*', r'\1', s)
    # testb %Xl, %Xl -> testl %eXx, %eXx (equivalent for zero-check)
    s = re.sub(r'^testb %([a-d])l, %\1l', r'testl %e\1x, %e\1x', s)
    # testw %Xx, %Xx -> testl %eXx, %eXx (equivalent for zero-check)
    s = re.sub(r'^testw %([a-d])x, %\1x', r'testl %e\1x, %e\1x', s)
    # testl %REG, %REG (self-test) → testl %<R>, %<R> (register doesn't matter)
    m = re.match(r'^testl (%(e[abcd]x|e[sd]i|ebx)), \1$', s)
    if m:
        s = 'testl %<R>, %<R>'
    # movzbl N(%reg), %eXx → movl N(%reg), %eXx for comparison purposes
    # (zero-extend byte load vs dword load — equivalent when source is byte-sized)
    s = re.sub(r'^movzbl\b', 'movl', s)
    # Normalize address constants, labels, and non_lazy_ptrs to <C>
    s = re.sub(r'L_\w+\$(?:non_lazy_ptr|stub)', '<C>', s)
    s = re.sub(r'LC\d+', '<C>', s)
    s = re.sub(r'-\d+\b', '<C>', s)  # negative numbers are always constants
    s = re.sub(r'\b\d{5,}\b', '<C>', s)  # large positive numbers too
    s = re.sub(r'\b0x[0-9a-fA-F]{5,}\b', '<C>', s)  # hex constants ≥5 digits
    # Normalize bare global symbol names (e.g., _sv_master, _com_sv_running)
    s = re.sub(r'\b_[a-zA-Z]\w{2,}\b', '<C>', s)
    # Collapse adjacent <C> patterns: <C>+<C> → <C>, <C>-<C> → <C>
    s = re.sub(r'<C>[+-]<C>', '<C>', s)
    # Strip $ before <C> (e.g., $<C> → <C>)
    s = re.sub(r'\$<C>', '<C>', s)
    # Normalize register choice in parameter loads and stores
    # Parameter loads: movl N(%ebp), %REG → movl N(%ebp), %<R>
    s = re.sub(r'^movl (\d+\(%ebp\)), %(eax|ecx|edx|esi|edi)',
               r'movl \1, %<R>', s)
    # (global load/store normalization removed — too aggressive for LCS matching)
    # Register-to-base-offset stores: movl %REG, N(%base)
    s = re.sub(r'^movl %(eax|ecx|edx|esi|edi), (\d+\(%e[bsd][xip]\))',
               r'movl %<R>, \2', s)
    # Normalize stack local offsets: -N(%ebp) → <S>(%ebp)
    # (stack frame layout varies between compilations)
    s = re.sub(r'-\d+\(%ebp\)', '<S>(%ebp)', s)
    # (struct field load normalization handled by existing patterns)
    # Normalize int↔float load variants into XMM registers
    # cvtsi2ss N(%reg), %xmm ≈ movss N(%reg), %xmm for matching purposes
    # (dvar values may be accessed as int or float depending on type info)
    s = re.sub(r'^cvtsi2ss (\d+\()', r'movss \1', s)
    # Normalize XMM register names (float register allocation varies)
    s = re.sub(r'%xmm[0-7]', '%xmm<N>', s)
    # Normalize ucomiss/comiss operand order (branch swaps compensate)
    # ucomiss %xmmA, %xmmB → ucomiss %xmm<N>, %xmm<N> (already normalized)
    # But also normalize ucomiss <C>, %xmm → ucomiss %xmm<N>, <C>
    # (canonical form: xmm operand first)
    m = re.match(r'^(u?comiss) (<C>), (%xmm<N>)', s)
    if m:
        s = f'{m.group(1)} {m.group(3)}, {m.group(2)}'
    # Normalize index register in indirect calls: call *TABLE(, %REG, N)
    s = re.sub(r'^call \*(<C>)\(, %(eax|ecx|edx|esi|edi), (\d+)\)',
               r'call *\1(, %<R>, \3)', s)
    # Normalize stack-offset stores: movl %REG, N(%esp) and movss ..., N(%esp)
    s = re.sub(r'^(movl|movss) %(eax|ecx|edx|esi|edi|xmm<N>), (\d+\(%esp\))',
               r'\1 %<R>, \3', s)
    s = re.sub(r'^(movl|movss) %(eax|ecx|edx|esi|edi|xmm<N>), \(%esp\)',
               r'\1 %<R>, (%esp)', s)
    # Normalize branch targets
    s = re.sub(r'^(j\w+) .*', r'\1 <T>', s)
    # Normalize padding instructions (nop, hlt sequences)
    if re.match(r'^(nop|hlt)', s):
        s = '<PAD>'
    return s


def norm_prologue(insns, other):
    """Normalize prologue differences:
    - Normalize sub esp,N value if sizes differ
    - Remove sub esp,N if only one stream has it."""
    result = list(insns)
    for i in range(min(5, len(result))):
        n = norm(result[i])
        if re.match(r'subl? \$?\d+, %esp', n):
            if i < len(other):
                on = norm(other[i])
                if re.match(r'subl? \$?\d+, %esp', on) and on != n:
                    result[i] = 'subl $<N>, %esp'
                    break
                elif not re.match(r'subl? \$?\d+, %esp', on):
                    result.pop(i)
                    break
            break
    return result


_callee_save_pats = [r'pushl %e[bsd][ix]', r'popl %e[bsd][ix]',
                     r'addl \$\d+, %esp', r'subl \$\d+, %esp']

def strip_callee_save(stream, other_stream):
    """Strip callee-save push/pop/addl that exist in one stream but not the other."""
    ns = [norm(x) for x in stream]
    no = set(norm(x) for x in other_stream)
    result = []
    for raw, n in zip(stream, ns):
        if n in no:
            result.append(raw)
            continue
        if any(re.match(p, n) for p in _callee_save_pats):
            continue
        result.append(raw)
    return result


def norm_stream(insns):
    """Normalize instruction stream — collapse indirect global access patterns."""
    result = []
    i = 0
    while i < len(insns):
        n = norm(insns[i])
        # Collapse: movl <C>, %reg; movl (%reg), %reg -> movl <C>, %reg
        # This is the non_lazy_ptr indirection pattern
        is_nlp = 'non_lazy_ptr' in insns[i]
        if (i + 1 < len(insns) and
            n.startswith('movl <C>, %') and is_nlp):
            reg = n.split(', ')[1]
            next_n = norm(insns[i+1])
            # Same register: movl (%reg), %reg
            if next_n == f'movl ({reg}), {reg}':
                result.append(n)
                i += 2
                continue
            # Different register: movl (%reg), %reg2 → movl <C>, %reg2
            m = re.match(r'movl \(' + re.escape(reg) + r'\), (%\w+)', next_n)
            if m:
                result.append(f'movl <C>, {m.group(1)}')
                i += 2
                continue
        # Collapse: movl <C>, %reg; movl val, (%reg) -> movl val, <C>
        # (store through non_lazy_ptr)
        if (i + 1 < len(insns) and
            n.startswith('movl <C>, %') and is_nlp):
            reg = n.split(', ')[1]
            next_n = norm(insns[i+1])
            m = re.match(r'movl (.+), \(' + re.escape(reg) + r'\)', next_n)
            if m:
                result.append(f'movl {m.group(1)}, <C>')
                i += 2
                continue
        # Collapse: movl <C>, %reg; addl $N, (%reg) -> addl $N, <C>
        if (i + 1 < len(insns) and
            n.startswith('movl <C>, %') and is_nlp):
            reg = n.split(', ')[1]
            next_n = norm(insns[i+1])
            m = re.match(r'(addl|subl|orl|andl|xorl) (.+), \(' + re.escape(reg) + r'\)', next_n)
            if m:
                result.append(f'{m.group(1)} {m.group(2)}, <C>')
                i += 2
                continue
        # Collapse 3-instruction NLP patterns: movl NLP, %r1; movl (%r1), %r2; OP N(%r2), ...
        # → movl <C>, %r2; OP N(%r2), ...
        # This handles: load NLP pointer, dereference, then access struct field
        if (i + 2 < len(insns) and
            n.startswith('movl <C>, %') and is_nlp):
            reg = n.split(', ')[1]
            next_n = norm(insns[i+1])
            m_deref = re.match(r'movl \(' + re.escape(reg) + r'\), (%\w+)', next_n)
            if m_deref:
                reg2 = m_deref.group(1)
                third_n = norm(insns[i+2])
                # movl N(%reg2), %dest → movl N(%<R>), %<R> (struct field load)
                m3 = re.match(r'(movl|movzbl|movb|movss) (\d+)\(' + re.escape(reg2) + r'\), (.+)', third_n)
                if m3:
                    result.append(f'movl <C>, {reg2}')
                    result.append(insns[i+2])
                    i += 3
                    continue
                # movl val, N(%reg2) → field store through NLP
                m3 = re.match(r'(movl|movb|movss) (.+), (\d+)\(' + re.escape(reg2) + r'\)', third_n)
                if m3:
                    result.append(f'movl <C>, {reg2}')
                    result.append(insns[i+2])
                    i += 3
                    continue
                # cmpb/testb etc on (%reg2) or N(%reg2)
                m3 = re.match(r'(cmpb|cmpw|cmpl|testb|testl) (.+), (\d*)\(' + re.escape(reg2) + r'\)', third_n)
                if m3:
                    result.append(f'movl <C>, {reg2}')
                    result.append(insns[i+2])
                    i += 3
                    continue
        # Collapse: movl <C>, %reg; movl %reg, <C> → movl <C>, <C>
        # (store-through-register for function pointers / globals)
        if (i + 1 < len(insns) and
            re.match(r'movl <C>, %e\w+', n)):
            reg = n.split(', ')[1]
            next_n = norm(insns[i+1])
            if re.match(r'movl ' + re.escape(reg) + r', <C>', next_n):
                result.append('movl <C>, <C>')
                i += 2
                continue
        # Collapse: movl <C>, %reg; movl %reg, N(%esp) → movl <C>, N(%esp)
        # (argument push through register vs direct push)
        if (i + 1 < len(insns) and
            re.match(r'movl <C>, %e\w+', n)):
            reg = n.split(', ')[1]  # e.g., '%eax'
            # Use raw instruction for register matching (norm may have replaced reg with %<R>)
            raw_next = insns[i+1].strip().replace('\t', ' ')
            m = re.match(r'movl?\s+' + re.escape(reg) + r',\s*(\d*\(%esp\))', raw_next)
            if m:
                esp_loc = m.group(1) or '(%esp)'
                result.append(f'movl <C>, {esp_loc}')
                i += 2
                continue
        # Normalize tail call: call X; leave; ret -> call X (drop leave+ret)
        if (i + 2 < len(insns) and
            n.startswith('call ') and
            norm(insns[i+1]) == 'popl %ebp' and
            norm(insns[i+2]).startswith('ret')):
            result.append(insns[i])  # keep the call
            i += 3  # skip leave+ret
            continue
        # Normalize original tail call: leave; jmp X -> call X (jmp = tail call)
        if (i + 1 < len(insns) and
            n == 'popl %ebp' and
            norm(insns[i+1]).startswith('jmp ')):
            next_n = norm(insns[i+1])
            # Convert jmp to call for comparison
            result.append('call ' + next_n.split(' ', 1)[1])
            i += 2
            continue
        result.append(insns[i])
        i += 1
    # Post-pass peephole: collapse patterns in result
    collapsed = []
    j = 0
    while j < len(result):
        rn = norm(result[j])
        # rep/repz + string op → combined (GCC emits prefix as separate instruction)
        if (j + 1 < len(result) and rn in ('repz', 'rep') and
            any(norm(result[j+1]).startswith(p) for p in ('cmps', 'movs', 'stos', 'scas', 'lods'))):
            collapsed.append(rn + ' ' + norm(result[j+1]))
            j += 2
            continue
        # movl <C>, %reg; movl %reg, <C> → movl <C>, <C>
        if (j + 1 < len(result) and
            re.match(r'movl <C>, %e\w+', rn)):
            reg = rn.split(', ')[1]
            next_rn = norm(result[j+1])
            if re.match(r'movl ' + re.escape(reg) + r', <C>', next_rn):
                collapsed.append('movl <C>, <C>')
                j += 2
                continue
            # movl <C>, %reg; movl %reg, N(%esp) → movl <C>, N(%esp)
            raw_next_r = result[j+1].strip().replace('\t', ' ')
            m = re.match(r'movl?\s+' + re.escape(reg) + r',\s*(\d*\(%esp\))', raw_next_r)
            if m:
                esp_loc = m.group(1) or '(%esp)'
                collapsed.append(f'movl <C>, {esp_loc}')
                j += 2
                continue
        collapsed.append(result[j])
        j += 1
    return collapsed


def get_func_addr(name):
    r = subprocess.run([DECOMP, BINARY, '-F'], capture_output=True, text=True)
    for line in r.stdout.split('\n'):
        # Exact name match
        m = re.match(r'\s+([0-9A-Fa-f]+)\s+\S+\s+(\S+)\(', line)
        if m:
            fname = m.group(2).replace('::', '_').replace('~', 'dtor_')
            if fname == name or m.group(2) == name:
                return int(m.group(1), 16), fname
    # Substring match
    for line in r.stdout.split('\n'):
        if name in line:
            m = re.match(r'\s+([0-9A-Fa-f]+)\s+.+\s+(\S+)\(', line)
            if m:
                fname = m.group(2).replace('::', '_').replace('~', 'dtor_').replace('*', '')
                if fname.startswith('*'): fname = fname[1:]
                return int(m.group(1), 16), fname
    return None, None


_func_addrs_cache = None
def _get_func_size(func_addr):
    global _func_addrs_cache
    if _func_addrs_cache is None:
        try:
            r = subprocess.run([DECOMP, BINARY, '-F'], capture_output=True, text=True, timeout=10)
            _func_addrs_cache = sorted(set(int(m.group(1), 16)
                for m in re.finditer(r'^\s+([0-9A-Fa-f]+)\s+', r.stdout, re.MULTILINE)))
        except:
            _func_addrs_cache = []
    for k, a in enumerate(_func_addrs_cache):
        if a == func_addr and k + 1 < len(_func_addrs_cache):
            return _func_addrs_cache[k+1] - a
    return 0

def find_source_for_addr(func_addr):
    """Find which source file index contains a function at the given address."""
    r = subprocess.run([DECOMP, BINARY, '--srcof', f'{func_addr:X}'],
                       capture_output=True, text=True, timeout=10)
    if r.returncode == 0 and r.stdout.strip().isdigit():
        return int(r.stdout.strip())
    return None


def check_function(name_or_addr, data, text_addr, text_off, verbose=True):
    # Resolve address
    if name_or_addr.startswith('0x') or name_or_addr.startswith('0X'):
        func_addr = int(name_or_addr, 16)
        _, func_name = get_func_addr(name_or_addr)
        if not func_name:
            func_name = f'sub_{func_addr:X}'
    else:
        func_addr, func_name = get_func_addr(name_or_addr)
        if func_addr is None:
            if verbose:
                print(f'Not found: {name_or_addr}')
            return None

    # Decompile
    r = subprocess.run([DECOMP, BINARY, '-f', f'{func_addr:X}'],
                       capture_output=True, text=True, timeout=30)
    c_code = r.stdout.strip()
    if not c_code:
        if verbose:
            print(f'{func_name}: decompilation failed')
        return None

    # Strip #include lines
    c_code = re.sub(r'#include\s*[<"].*?[>"]', '', c_code)

    # Detect regparm calling convention from original disassembly:
    # If function prologue saves %eax/%edx/%ecx to locals/regs (not loading from stack),
    # the function uses register parameters.
    use_regparm = False
    orig_check = disasm_original(data, text_addr, text_off, func_addr,
                                 _get_func_size(func_addr))
    # After push/mov-esp/push/sub, check if first data instruction uses %eax as source
    for inst in orig_check[2:8]:
        s = inst.strip()
        # movl %eax, %REG or movl %eax, N(%ebp) → saving register param
        if re.match(r'movl %eax, ', s) and '%ebp)' not in s.split(',')[1]:
            use_regparm = True
            break
        if re.match(r'movl %eax, -', s):
            use_regparm = True
            break
        # movl N(%ebp), %REG → loading stack param → NOT regparm
        if re.match(r'movl \d+\(%ebp\),', s):
            break
        if s.startswith('subl') or s.startswith('pushl'):
            continue
        break
    if use_regparm and c_code.startswith('static'):
        # Keep static + noinline so GCC's IPA passes float params in XMM registers.
        # Add a dummy caller to prevent the static function from being removed.
        c_code = re.sub(r'^static\s+', 'static __attribute__((noinline)) ', c_code)
        # Find the function name (after attribute, return type)
        # Pattern: static __attribute__(...) RETTYPE FNAME(
        m_fn = re.search(r'\)\s+\w+\s+(\w+)\s*\(', c_code)
        if m_fn:
            fname = m_fn.group(1)
            # Find the full param list
            ps = c_code.index('(', m_fn.end() - 1)
            depth = 0; pe = ps
            for ci in range(ps, len(c_code)):
                if c_code[ci] == '(': depth += 1
                if c_code[ci] == ')': depth -= 1
                if depth == 0: pe = ci; break
            params = re.sub(r'\s+', ' ', c_code[ps+1:pe])
            pnames = []
            for p in params.split(','):
                w = p.strip().replace('*', ' * ').split()
                if w: pnames.append(w[-1].strip('*'))
            c_code += f'\nvoid __dummy({params}) {{ {fname}({",".join(pnames)}); }}\n'
    elif c_code.startswith('static'):
        # Strip 'static' to prevent inlining/removal when compiling in isolation
        c_code = re.sub(r'^static\s+', '', c_code)

    # Try 1: compile the single function with stubs (structured mode)
    ok, asm_text, errors = compile_to_asm(c_code, orig_check=orig_check)

    # Try 2: source file fallback (disabled — source files have too many Carbon deps)
    # if not ok:
    #     src_idx = find_source_for_addr(func_addr)
    #     if src_idx is not None:
    #         r2 = subprocess.run([DECOMP, BINARY, '-s', str(src_idx)],
    #                             capture_output=True, text=True, timeout=60)
    #         if r2.stdout.strip():
    #             src_code = re.sub(r'#include\s*[<"].*?[>"]', '', r2.stdout)
    #             ok, asm_text, errors = compile_to_asm_raw(src_code)
    if not ok:
        if verbose:
            err_lines = [l for l in errors.split('\n') if ': error:' in l][:5]
            print(f'{func_name}: compile FAILED')
            for l in err_lines:
                print(f'  {l.strip()}')
        return None

    # Extract recompiled function
    recomp = extract_func_asm(asm_text, func_name)
    if not recomp:
        # Try with leading underscore stripped
        for line in asm_text.split('\n'):
            if ':' in line and not line.startswith('.') and not line.startswith('L'):
                label = line.split(':')[0].strip().lstrip('_')
                recomp = extract_func_asm(asm_text, label)
                if recomp:
                    break
    if not recomp:
        if verbose:
            print(f'{func_name}: no asm output (types missing?)')
        return None

    # Get function size from the function list (distance to next function)
    func_size = _get_func_size(func_addr)


    # Original disasm
    orig = disasm_original(data, text_addr, text_off, func_addr, func_size)

    # Try flat (goto-based) mode as alternative compilation
    # Use whichever produces a better LCS match
    if recomp:
        try:
            r_flat = subprocess.run([DECOMP, BINARY, '-f', f'{func_addr:X}', '--flat'],
                                   capture_output=True, text=True, timeout=30)
            flat_code = r_flat.stdout.strip()
            if flat_code and 'goto' in flat_code:
                flat_code = re.sub(r'#include\s*[<"].*?[>"]', '', flat_code)
                flat_code = re.sub(r'^static\s+', '', flat_code)
                ok_f, asm_f, _ = compile_to_asm(flat_code, orig_check=orig_check)
                if ok_f:
                    recomp_f = extract_func_asm(asm_f, func_name)
                    if not recomp_f:
                        for l2 in asm_f.split('\n'):
                            if ':' in l2 and not l2.startswith('.') and not l2.startswith('L'):
                                label = l2.split(':')[0].strip().lstrip('_')
                                recomp_f = extract_func_asm(asm_f, label)
                                if recomp_f: break
                    if recomp_f:
                        # Quick LCS for both versions
                        def quick_lcs(a, b):
                            na = [norm(x) for x in a]; nb = [norm(x) for x in b]
                            m2, n2 = len(na), len(nb); prev2 = [0]*(n2+1)
                            for ii in range(m2):
                                curr2 = [0]*(n2+1)
                                for jj in range(n2):
                                    curr2[jj+1] = prev2[jj]+1 if na[ii]==nb[jj] else max(curr2[jj],prev2[jj+1])
                                prev2 = curr2
                            return prev2[n2]
                        lcs_struct = quick_lcs(orig, recomp)
                        lcs_flat = quick_lcs(orig, recomp_f)
                        if lcs_flat > lcs_struct:
                            recomp = recomp_f
        except: pass

    # Normalize instruction streams
    orig = norm_stream(orig)
    recomp = norm_stream(recomp)
    # Normalize prologue: sub esp size differences
    orig = norm_prologue(orig, recomp)
    recomp = norm_prologue(recomp, orig)
    # Strip callee-save register differences
    orig = strip_callee_save(orig, recomp)
    recomp = strip_callee_save(recomp, orig)
    # Remove GCC's extra jp (NaN parity check) instructions when the original
    # doesn't have them. These are always after ucomiss and before a jcc.
    orig_has_jp = any(inst.strip().startswith('jp') for inst in orig)
    if not orig_has_jp:
        recomp = [inst for inst in recomp if not inst.strip().startswith('jp')]

    # Compare using LCS (longest common subsequence) for alignment-tolerant matching
    normed_o = [norm(x) for x in orig]
    normed_r = [norm(x) for x in recomp]
    m, n = len(normed_o), len(normed_r)
    total = max(m, n)

    # Compute LCS length
    # Use space-efficient 2-row DP
    prev = [0] * (n + 1)
    for i in range(m):
        curr = [0] * (n + 1)
        for j in range(n):
            if normed_o[i] == normed_r[j]:
                curr[j+1] = prev[j] + 1
            else:
                curr[j+1] = max(curr[j], prev[j+1])
        prev = curr
    matches = prev[n]

    pct = matches * 100 // total if total else 0

    if verbose:
        if pct == 100:
            print(f'{func_name}: {matches}/{total} PERFECT ({pct}%)')
        else:
            print(f'{func_name}: {matches}/{total} ({pct}%)')
            # Show diffs using position-by-position for readability
            for i in range(total):
                o = orig[i] if i < len(orig) else ''
                r = recomp[i] if i < len(recomp) else ''
                mk = ' ' if norm(o) == norm(r) else '|'
                print(f'  {mk} {o:42s} {r}')

    return pct


def main():
    if len(sys.argv) < 2:
        print('Usage: python3 asmcheck.py <func_name|0xaddr|--all>')
        sys.exit(1)

    data, text_addr, text_off = load_binary()

    if sys.argv[1] == '--all':
        if not os.path.exists('regtest_funcs.txt'):
            print('No regtest_funcs.txt')
            sys.exit(1)
        results = []
        with open('regtest_funcs.txt') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 1)
                addr = parts[0]
                name = parts[1] if len(parts) > 1 else addr
                pct = check_function(f'0x{addr}', data, text_addr, text_off, verbose=False)
                status = f'{pct}%' if pct is not None else 'FAIL'
                tag = 'PERFECT' if pct == 100 else ''
                print(f'  {name:45s} {status:>5s}  {tag}')
                results.append((name, pct))
        # Summary
        ok = sum(1 for _, p in results if p == 100)
        partial = sum(1 for _, p in results if p is not None and p < 100)
        fail = sum(1 for _, p in results if p is None)
        print(f'\n{ok} perfect, {partial} partial, {fail} failed out of {len(results)}')
    else:
        check_function(sys.argv[1], data, text_addr, text_off)


if __name__ == '__main__':
    main()
