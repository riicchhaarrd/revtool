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
typedef int BOOL; typedef int Bool; typedef int qboolean;
typedef unsigned int DWORD; typedef unsigned int UINT;
typedef float vec_t; typedef vec_t vec3_t[3]; typedef vec_t vec2_t[2];
typedef unsigned char byte;
#define NULL ((void*)0)
float floorf(float); float ceilf(float); float sqrtf(float);
float sinf(float); float cosf(float); float tanf(float);
float fabsf(float); float fminf(float,float); float fmaxf(float,float);
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


def disasm_original(data, text_addr, text_off, func_addr):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.syntax = capstone.CS_OPT_SYNTAX_ATT
    fo = text_off + (func_addr - text_addr)
    insns = []
    for i in md.disasm(data[fo:fo+4096], func_addr):
        insns.append(f'{i.mnemonic} {i.op_str}'.strip())
        if i.mnemonic in ('ret', 'retl'):
            break
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
            if f' {name};' in stripped or f' {name}[' in stripped:
                result = line
                # If it's typedef struct X name, also extract struct X
                m = re.match(r'typedef\s+struct\s+(\w+)\s+' + re.escape(name), stripped)
                if m:
                    struct_def = extract_struct_from_header(m.group(1))
                    if struct_def:
                        result = struct_def + '\n' + result
                return result

    return None


def _try_compile(code):
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(code); cpath = f.name
    try:
        r = subprocess.run([APPLE_GCC] + GCC_FLAGS + ['-S', '-o', '-', cpath],
                           capture_output=True, text=True, timeout=30)
        return r.returncode == 0, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return False, '', 'timeout'
    finally:
        os.unlink(cpath)


def compile_to_asm(c_code):
    # Pre-extract all struct/typedef types referenced in the code from the types header
    extracted = {}  # name -> definition (ordered by dependency)
    # Find struct references AND typedef names (Type_t patterns used as pointer types)
    refs = set(re.findall(r'struct\s+(\w+)', c_code))
    # Also find typedef names used as pointer base types: "type_t *var"
    # Skip simple types already in STUBS (vec_t, qboolean, etc.)
    stubs_types = set(re.findall(r'typedef\s+\S+.*?\s+(\w+)\s*[;\[]', STUBS))
    for m in re.finditer(r'\b(\w+_t)\s*\*\s*\w+', c_code):
        name = m.group(1)
        if name not in stubs_types:
            refs.add(name)
    queue = list(refs)
    visited = set()
    while queue:
        name = queue.pop(0)
        if name in visited: continue
        visited.add(name)
        defn = extract_struct_from_header(name)
        if defn:
            # Skip structs with invalid C (vtable pointers, C++ artifacts)
            if '$' in defn or '(*)()' in defn or '::' in defn:
                continue
            extracted[name] = defn
            # Also register any struct tags defined in this block
            for m in re.finditer(r'struct\s+(\w+)\s*\{', defn):
                extracted.setdefault(m.group(1), defn)
            # Extract dependencies: struct fields by value AND typedef references
            for m in re.finditer(r'(?:struct|union)\s+(\w+)\s+\w+', defn):
                if m.group(1) not in visited:
                    queue.append(m.group(1))
            for m in re.finditer(r'\b(\w+_t)\s+\*?\s*\w+', defn):
                dep = m.group(1)
                if dep not in visited and dep not in stubs_types:
                    queue.append(dep)

    # Build: STUBS + extracted types (dependency-ordered) + code
    # Topological sort: emit dependencies before dependents
    ordered = []
    emitted_set = set()
    def emit_type(name):
        if name in emitted_set or name not in extracted: return
        emitted_set.add(name)
        defn = extracted[name]
        # Mark ALL names defined in this block as emitted (struct tags + typedefs)
        for m in re.finditer(r'struct\s+(\w+)\s*\{', defn):
            emitted_set.add(m.group(1))
        for m in re.finditer(r'typedef\s+struct\s+\w+\s+(\w+)\s*;', defn):
            emitted_set.add(m.group(1))
        # Emit dependencies first
        for m in re.finditer(r'(?:struct|union)\s+(\w+)\s+\w+', defn):
            emit_type(m.group(1))
        for m in re.finditer(r'\b(\w+_t)\s+\*?\s*\w+', defn):
            if m.group(1) not in emitted_set:
                emit_type(m.group(1))
        ordered.append(defn)
    for name in extracted:
        emit_type(name)
    types_block = '\n'.join(ordered)
    full = STUBS + '\n' + types_block + '\n' + c_code

    # Try compile
    ok, stdout, stderr = _try_compile(full)
    if ok: return True, stdout, stderr

    # Retry: add simple stubs for remaining undeclared names
    q = r"[\x60\x27\u2018]"; cq = r"[\x27\u2019]"
    for attempt in range(5):
        undeclared = set()
        for m in re.finditer(q + r"(\w+)" + cq + r" undeclared", stderr): undeclared.add(m.group(1))
        for m in re.finditer(r"syntax error before " + q + r"(\w+)" + cq, stderr): undeclared.add(m.group(1))
        # Remove conflicting stubs
        for m in re.finditer(r"conflicting types for " + q + r"(\w+)" + cq, stderr):
            full = re.sub(r'^extern\s+\w+\s+\*?' + re.escape(m.group(1)) + r'\s*;.*\n', '', full, flags=re.MULTILINE)
        if not undeclared: break
        already = set(re.findall(r'(?:typedef|struct|extern)\s+\w+.*?\s+(\w+)\s*[;\{]', full))
        funcs = set(re.findall(r'\b(?:int|void|float|static)\s+(\w+)\s*\(', full))
        stubs = ''
        for name in sorted(undeclared):
            if name in already or name in funcs: continue
            if re.search(r'\*\s*\(' + re.escape(name) + r'\)|' + re.escape(name) + r'\s*->', full):
                stubs += f'extern void *{name};\n'
            elif name[0].isupper() or name.endswith('_t'):
                stubs += f'typedef int {name};\n'
            else:
                stubs += f'extern int {name};\n'
        if not stubs: break
        idx = full.find(STUBS) + len(STUBS) if STUBS in full else 0
        full = full[:idx] + stubs + full[idx:]
        ok, stdout, stderr = _try_compile(full)
        if ok: return True, stdout, stderr

    return False, '', stderr


def extract_func_asm(asm_text, func_name):
    """Extract a function's instructions from gcc -S output."""
    insns = []
    in_func = False
    for line in asm_text.split('\n'):
        if f'_{func_name}:' in line:
            in_func = True
            continue
        if not in_func:
            continue
        line = line.strip()
        if not line or line.startswith('.') or line.startswith('L'):
            continue
        insns.append(line)
        if line.startswith('ret'):
            break
    return insns


def norm(s):
    """Normalize an instruction for comparison."""
    s = s.strip().replace('\t', ' ')
    # Hex offsets to decimal
    s = re.sub(r'0x([0-9a-fA-F]+)', lambda m: str(int(m.group(1), 16)), s)
    # Collapse whitespace
    s = re.sub(r'\s+', ' ', s)
    # Strip comments
    s = s.split('#')[0].strip()
    # retl -> ret, calll -> call, leave -> popl %ebp
    s = re.sub(r'^retl\b', 'ret', s)
    s = re.sub(r'^calll\b', 'call', s)
    s = re.sub(r'^leave$', 'popl %ebp', s)
    # Normalize address constants, labels, and non_lazy_ptrs to <C>
    s = re.sub(r'L_\w+\$(?:non_lazy_ptr|stub)', '<C>', s)
    s = re.sub(r'LC\d+', '<C>', s)
    s = re.sub(r'\$<C>', '<C>', s)
    s = re.sub(r'\b\d{5,}\b', '<C>', s)
    # Normalize branch targets
    s = re.sub(r'^(j\w+) .*', r'\1 <T>', s)
    return s


def norm_prologue(insns, other):
    """Remove sub esp,N from prologue if the other stream has a different size or no sub esp.
    Also normalize leave;ret vs popl %ebp;ret in epilogue."""
    result = list(insns)
    # Check if first few instructions have sub esp
    for i in range(min(3, len(result))):
        n = norm(result[i])
        if re.match(r'subl? \$?\d+, %esp', n):
            # Check if other stream has a matching sub esp at same position
            if i < len(other):
                on = norm(other[i])
                if re.match(r'subl? \$?\d+, %esp', on) and on != n:
                    # Different sizes — normalize both to generic
                    result[i] = 'subl $<N>, %esp'
                    break
                elif not re.match(r'subl? \$?\d+, %esp', on):
                    # Other has no sub esp — remove ours
                    result.pop(i)
                    break
            break
    return result


def norm_stream(insns):
    """Normalize instruction stream — collapse indirect global access patterns."""
    result = []
    i = 0
    while i < len(insns):
        n = norm(insns[i])
        # Collapse: movl <C>, %reg; movl (%reg), %reg -> movl <C>, %reg
        # This is the non_lazy_ptr indirection pattern
        if (i + 1 < len(insns) and
            n.startswith('movl <C>, %') and
            'non_lazy_ptr' in insns[i]):
            reg = n.split(', ')[1]
            next_n = norm(insns[i+1])
            if next_n == f'movl ({reg}), {reg}':
                result.append(n)
                i += 2
                continue
        # Collapse: movl <C>, %reg; movl val, (%reg) -> movl val, <C>
        # (store through non_lazy_ptr)
        if (i + 1 < len(insns) and
            n.startswith('movl <C>, %') and
            'non_lazy_ptr' in insns[i]):
            reg = n.split(', ')[1]
            next_n = norm(insns[i+1])
            m = re.match(r'movl (.+), \(' + re.escape(reg) + r'\)', next_n)
            if m:
                result.append(f'movl {m.group(1)}, <C>')
                i += 2
                continue
        # Collapse: movl <C>, %reg; addl $N, (%reg) -> addl $N, <C>
        if (i + 1 < len(insns) and
            n.startswith('movl <C>, %') and
            'non_lazy_ptr' in insns[i]):
            reg = n.split(', ')[1]
            next_n = norm(insns[i+1])
            m = re.match(r'(addl|subl|orl|andl|xorl) (.+), \(' + re.escape(reg) + r'\)', next_n)
            if m:
                result.append(f'{m.group(1)} {m.group(2)}, <C>')
                i += 2
                continue
        result.append(insns[i])
        i += 1
    return result


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

    # Strip #include lines from decompiled code
    c_code = re.sub(r'#include\s*[<"].*?[>"]', '', c_code)

    # Try 1: compile the single function with stubs
    ok, asm_text, errors = compile_to_asm(c_code)

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

    # Original disasm
    orig = disasm_original(data, text_addr, text_off, func_addr)

    # Normalize recompiled stream (collapse non_lazy_ptr patterns)
    recomp = norm_stream(recomp)
    # Normalize both streams: remove sub esp from prologue if sizes differ
    # (compiler may add/omit stack frame based on alignment needs)
    orig = norm_prologue(orig, recomp)
    recomp = norm_prologue(recomp, orig)

    # Compare
    matches = 0
    total = max(len(orig), len(recomp))
    diffs = []
    for i in range(total):
        o = orig[i] if i < len(orig) else ''
        r = recomp[i] if i < len(recomp) else ''
        if norm(o) == norm(r):
            matches += 1
        else:
            diffs.append(i)

    pct = matches * 100 // total if total else 0

    if verbose:
        if pct == 100:
            print(f'{func_name}: {matches}/{total} PERFECT ({pct}%)')
        else:
            print(f'{func_name}: {matches}/{total} ({pct}%)')
            # Show diffs
            for i in range(total):
                o = orig[i] if i < len(orig) else ''
                r = recomp[i] if i < len(recomp) else ''
                m = norm(o) == norm(r)
                marker = ' ' if m else '|'
                print(f'  {marker} {o:42s} {r}')

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
