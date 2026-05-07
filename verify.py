#!/usr/bin/env python3
"""
Decompilation Verification Tool

Compares original binary disassembly against recompiled decompiler output.

Usage:
  python3 verify.py -n <func>        # verify a single function
  python3 verify.py -s <src_idx>     # verify all functions in a source file
  python3 verify.py --compile-test   # just test if decompiled code compiles
"""

import argparse
import struct
import subprocess
import tempfile
import os
import re
import sys
from difflib import unified_diff

# ── Mach-O parser (minimal, just enough to find __text and function boundaries) ──

class MachOReader:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        self.text_addr = 0
        self.text_size = 0
        self.text_offset = 0
        self._parse()

    def _parse(self):
        magic = struct.unpack_from('<I', self.data, 0)[0]
        if magic != 0xFEEDFACE:
            raise ValueError(f"Not a 32-bit Mach-O: {magic:#x}")
        ncmds = struct.unpack_from('<I', self.data, 16)[0]
        offset = 28
        for _ in range(ncmds):
            cmd, size = struct.unpack_from('<II', self.data, offset)
            if cmd == 1:  # LC_SEGMENT
                segname = self.data[offset+8:offset+24].rstrip(b'\x00').decode()
                if segname == '__TEXT':
                    nsects = struct.unpack_from('<I', self.data, offset+48)[0]
                    sect_off = offset + 56
                    for _ in range(nsects):
                        sname = self.data[sect_off:sect_off+16].rstrip(b'\x00').decode()
                        if sname == '__text':
                            self.text_addr = struct.unpack_from('<I', self.data, sect_off+32)[0]
                            self.text_size = struct.unpack_from('<I', self.data, sect_off+36)[0]
                            self.text_offset = struct.unpack_from('<I', self.data, sect_off+40)[0]
                            return
                        sect_off += 68
            offset += size

    def code_at(self, addr, size):
        """Get code bytes at a virtual address."""
        file_off = self.text_offset + (addr - self.text_addr)
        return self.data[file_off:file_off+size]


# ── Disassembly ──

def disasm_original(macho, addr, max_bytes=4096):
    """Disassemble original function from Mach-O binary using capstone."""
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    code = macho.code_at(addr, max_bytes)
    insns = []
    depth = 0
    for insn in md.disasm(code, addr):
        insns.append((insn.address, insn.mnemonic, insn.op_str))
        if insn.mnemonic == 'ret':
            if depth == 0:
                break
        # Track call depth for inlined returns
    return insns


def disasm_recompiled(obj_path, func_name):
    """Disassemble a function from a recompiled ELF .o using objdump."""
    result = subprocess.run(
        ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn', obj_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return []

    insns = []
    in_func = False
    # objdump format: "addr: mnemonic  operands"
    func_pattern = re.compile(rf'<{re.escape(func_name)}>:')
    insn_pattern = re.compile(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)?$')

    for line in result.stdout.split('\n'):
        if func_pattern.search(line):
            in_func = True
            continue
        if in_func:
            if line.strip() == '' or (line.strip() and not line.startswith(' ')):
                if insns:  # end of function
                    break
                continue
            m = insn_pattern.match(line)
            if m:
                addr = int(m.group(1), 16)
                mnemonic = m.group(2)
                operands = m.group(3).strip() if m.group(3) else ''
                insns.append((addr, mnemonic, operands))
    return insns


# ── Normalization for comparison ──


# Mnemonic aliases: different encodings for the same instruction
MNEMONIC_ALIASES = {
    # Conditional jump aliases
    'jnae': 'jb',   'jc': 'jb',
    'jnb': 'jae',   'jnc': 'jae',
    'jna': 'jbe',
    'jnbe': 'ja',
    'jnge': 'jl',
    'jnl': 'jge',
    'jng': 'jle',
    'jnle': 'jg',
    'je': 'jz',
    'jne': 'jnz',
    # SETcc aliases
    'setnae': 'setb',  'setc': 'setb',
    'setnb': 'setae',  'setnc': 'setae',
    'setna': 'setbe',
    'setnbe': 'seta',
    'setnge': 'setl',
    'setnl': 'setge',
    'setng': 'setle',
    'setnle': 'setg',
    'sete': 'setz',
    'setne': 'setnz',
    # CMOVcc aliases
    'cmovnae': 'cmovb',  'cmovc': 'cmovb',
    'cmovnb': 'cmovae',  'cmovnc': 'cmovae',
    'cmovna': 'cmovbe',
    'cmovnbe': 'cmova',
    'cmovnge': 'cmovl',
    'cmovnl': 'cmovge',
    'cmovng': 'cmovle',
    'cmovnle': 'cmovg',
    'cmove': 'cmovz',
    'cmovne': 'cmovnz',
}


def normalize_insn(mnemonic, operands):
    """Normalize an instruction for comparison (strip addresses, constants)."""
    # Normalize mnemonic aliases
    mn = mnemonic.lower()
    mn = MNEMONIC_ALIASES.get(mn, mn)

    # Normalize operands: replace absolute addresses with <addr>
    ops = operands
    # Replace hex constants (addresses) with symbolic placeholder
    ops = re.sub(r'0x[0-9a-fA-F]{4,}', '<addr>', ops)
    # Replace dword ptr [addr] patterns
    ops = re.sub(r'\[0x[0-9a-fA-F]+\]', '[<addr>]', ops)
    # Normalize register names
    ops = ops.lower()

    return mn, ops


def normalize_insn_stream(insns):
    """Normalize instruction stream for semantic equivalences.

    Handles multi-instruction patterns that are semantically identical:
      - test reg, reg  ->  cmp reg, 0
      - xor reg, reg   ->  mov reg, 0
      - mov esp, ebp; pop ebp  ->  leave
    """
    result = []
    i = 0
    while i < len(insns):
        addr, mn, ops = insns[i]
        mn_low = mn.lower()
        ops_parts = [x.strip() for x in ops.split(',')]

        # test reg, reg -> cmp reg, 0
        if mn_low == 'test' and len(ops_parts) == 2 and ops_parts[0] == ops_parts[1]:
            result.append((addr, 'cmp', f'{ops_parts[0]}, 0'))
            i += 1
            continue

        # xor reg, reg -> mov reg, 0
        if mn_low == 'xor' and len(ops_parts) == 2 and ops_parts[0] == ops_parts[1]:
            result.append((addr, 'mov', f'{ops_parts[0]}, 0'))
            i += 1
            continue

        # mov esp, ebp; pop ebp -> leave
        if (mn_low == 'mov' and
            ops.lower().replace(' ', '') in ('esp,ebp', '%esp,%ebp') and
            i + 1 < len(insns) and
            insns[i + 1][1].lower() == 'pop' and
            insns[i + 1][2].strip().lower() in ('ebp', '%ebp')):
            result.append((addr, 'leave', ''))
            i += 2
            continue

        result.append(insns[i])
        i += 1
    return result


def compare_functions(orig_insns, recomp_insns, func_name):
    """Compare two instruction streams and produce a report."""
    # Apply semantic normalization (multi-instruction patterns)
    orig_insns = normalize_insn_stream(orig_insns)
    recomp_insns = normalize_insn_stream(recomp_insns)

    # Normalize both (single-instruction aliases + operand normalization)
    orig_norm = [(normalize_insn(m, o)) for _, m, o in orig_insns]
    recomp_norm = [(normalize_insn(m, o)) for _, m, o in recomp_insns]

    # Mnemonic-only comparison (ignoring operand details)
    orig_mnemonics = [m for m, _ in orig_norm]
    recomp_mnemonics = [m for m, _ in recomp_norm]

    # Full comparison (mnemonic + normalized operands)
    orig_full = [f"{m} {o}" for m, o in orig_norm]
    recomp_full = [f"{m} {o}" for m, o in recomp_norm]

    # Count matching mnemonics (order-sensitive)
    match_count = 0
    for a, b in zip(orig_mnemonics, recomp_mnemonics):
        if a == b:
            match_count += 1

    total = max(len(orig_insns), len(recomp_insns))
    if total == 0:
        return 0.0, ""

    score = match_count / total * 100

    # Build side-by-side diff
    lines = []
    lines.append(f"{'─'*60}")
    lines.append(f"  {func_name}: {len(orig_insns)} insns (orig) vs {len(recomp_insns)} insns (recomp)")
    lines.append(f"  Mnemonic match: {match_count}/{total} ({score:.1f}%)")
    lines.append(f"{'─'*60}")

    # Side-by-side
    max_i = max(len(orig_insns), len(recomp_insns))
    for i in range(min(max_i, 60)):  # cap at 60 lines
        left = ""
        right = ""
        marker = " "
        if i < len(orig_insns):
            _, m, o = orig_insns[i]
            left = f"{m:8s} {o}"
        if i < len(recomp_insns):
            _, m, o = recomp_insns[i]
            right = f"{m:8s} {o}"

        # Compare normalized
        lnorm = normalize_insn(*orig_insns[i][1:3]) if i < len(orig_insns) else ("", "")
        rnorm = normalize_insn(*recomp_insns[i][1:3]) if i < len(recomp_insns) else ("", "")
        if lnorm == rnorm:
            marker = " "
        elif lnorm[0] == rnorm[0]:
            marker = "~"  # same mnemonic, different operands
        else:
            marker = "|"  # different instruction

        lines.append(f"  {left:40s} {marker} {right}")

    if max_i > 60:
        lines.append(f"  ... ({max_i - 60} more instructions)")

    return score, '\n'.join(lines)


# ── Compilation ──

def get_decomp_output(binary, flag, value):
    """Run decomp tool to get C output."""
    result = subprocess.run(
        ['./build/decomp', binary, flag, str(value)],
        capture_output=True, text=True
    )
    return result.stdout


def make_compilable(code):
    """Patch decompiled C to be compilable with the cross-compiler."""
    lines = code.split('\n')
    out = []

    # Provide minimal type stubs instead of system headers — works with any compiler
    out.append('/* minimal stubs for compilation */')
    out.append('typedef unsigned int size_t;')
    out.append('typedef int ssize_t;')
    out.append('typedef int int32_t;')
    out.append('typedef unsigned int uint32_t;')
    out.append('typedef short int16_t;')
    out.append('typedef unsigned short uint16_t;')
    out.append('typedef signed char int8_t;')
    out.append('typedef unsigned char uint8_t;')
    out.append('typedef long long int64_t;')
    out.append('typedef unsigned long long uint64_t;')
    out.append('typedef int intptr_t;')
    out.append('typedef unsigned int uintptr_t;')
    out.append('typedef int ptrdiff_t;')
    out.append('#define NULL ((void*)0)')
    out.append('float floorf(float); float ceilf(float); float sqrtf(float);')
    out.append('float sinf(float); float cosf(float); float tanf(float);')
    out.append('float fabsf(float); float fminf(float,float); float fmaxf(float,float);')
    out.append('float acosf(float); float asinf(float); float atanf(float);')
    out.append('double atan2(double,double); double floor(double); double ceil(double);')
    out.append('double sqrt(double); double fabs(double); double pow(double,double);')
    out.append('double sin(double); double cos(double); double log(double);')
    out.append('void *memset(void*,int,size_t); void *memcpy(void*,const void*,size_t);')
    out.append('size_t strlen(const char*); int strcmp(const char*,const char*);')
    out.append('char *strcpy(char*,const char*); char *strcat(char*,const char*);')
    out.append('int sprintf(char*,const char*,...); int printf(const char*,...);')
    out.append('int snprintf(char*,size_t,const char*,...);')
    out.append('int setjmp(void*); void longjmp(void*,int);')
    out.append('int atoi(const char*); void exit(int); void *malloc(size_t); void free(void*);')
    out.append('int abs(int);')
    out.append('')

    for line in lines:
        # Strip all #include directives — we provide stubs above
        if re.match(r'\s*#include\s', line):
            continue
        out.append(line)

    return '\n'.join(out)


APPLE_GCC = '/tmp/apple-gcc-build/gcc/xgcc'
APPLE_GCC_FLAGS = ['-B/tmp/apple-gcc-build/gcc/', '-m32', '-O2', '-mdynamic-no-pic',
                   '-fno-schedule-insns', '-fno-schedule-insns2', '-mtune=pentium4',
                   '-std=c99', '-w', '-fno-stack-protector']
SYSTEM_GCC_FLAGS = ['-m32', '-O2', '-std=c99', '-w', '-Wno-int-conversion',
                    '-fno-pic', '-fno-pie', '-fno-stack-protector', '-fno-omit-frame-pointer']

def _pick_compiler():
    """Use Apple GCC if available, else system gcc."""
    if os.path.exists(APPLE_GCC):
        return [APPLE_GCC] + APPLE_GCC_FLAGS
    return ['gcc'] + SYSTEM_GCC_FLAGS

def compile_to_obj(code, obj_path):
    """Compile C code to a 32-bit object file. Returns (success, errors)."""
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(code)
        c_path = f.name

    try:
        cmd = _pick_compiler() + ['-c', '-o', obj_path, c_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        errors = result.stderr
        return result.returncode == 0, errors
    except subprocess.TimeoutExpired:
        return False, "compilation timed out"
    finally:
        os.unlink(c_path)


def compile_to_asm(code):
    """Compile C code to assembly text. Returns (success, asm_text, errors)."""
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(code)
        c_path = f.name

    try:
        result = subprocess.run(
            _pick_compiler() + ['-S', '-o', '-', c_path],
            capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "compilation timed out"
    finally:
        os.unlink(c_path)


# ── Function address lookup ──

def get_func_addresses(binary):
    """Get function name -> address mapping from decomp -F."""
    result = subprocess.run(
        ['./build/decomp', binary, '-F', ''],
        capture_output=True, text=True
    )
    funcs = {}
    for line in result.stdout.split('\n'):
        m = re.match(r'\s+([0-9A-Fa-f]+)\s+\S+\s+(\S+)\(', line)
        if m:
            addr = int(m.group(1), 16)
            name = m.group(2)
            # Sanitize C++ names the same way the decompiler does
            cname = name.replace('::', '_').replace('~', 'dtor_').replace(' ', '_').replace('&', '')
            funcs[cname] = addr
    return funcs


# ── Main verification ──

def verify_function(binary, func_name, macho, func_addrs):
    """Verify a single function by comparing original vs recompiled asm."""
    # Get C code for the function
    c_code = get_decomp_output(binary, '-n', func_name)
    if not c_code.strip():
        return None, f"No output for {func_name}"

    # Get original disassembly
    addr = func_addrs.get(func_name)
    if not addr:
        # Try substring match
        for name, a in func_addrs.items():
            if func_name in name:
                addr = a
                func_name = name
                break
    if not addr:
        return None, f"Address not found for {func_name}"

    orig_insns = disasm_original(macho, addr)

    # Get the full source file for this function (we need type definitions)
    # For now, try compiling the function output directly with stubs
    code = make_compilable(c_code)

    # Try to compile to assembly
    success, asm_text, errors = compile_to_asm(code)
    if not success:
        # Count errors
        err_count = errors.count(': error:')
        return None, f"Compilation failed ({err_count} errors):\n{errors[:500]}"

    # Parse the gcc assembly output to extract instructions
    recomp_insns = []
    insn_pattern = re.compile(r'^\s+(\S+)\s+(.*)?$')
    in_text = False
    for line in asm_text.split('\n'):
        if '.text' in line:
            in_text = True
            continue
        if not in_text:
            continue
        if line.startswith('.') or line.strip().startswith('.'):
            continue
        if ':' in line and not line.strip().startswith(('mov', 'add', 'sub', 'push', 'pop',
                'call', 'ret', 'jmp', 'j', 'cmp', 'test', 'lea', 'xor', 'or', 'and',
                'shl', 'shr', 'sar', 'not', 'neg', 'imul', 'mul', 'div', 'inc', 'dec',
                'nop', 'cdq', 'fld', 'fst', 'movss', 'addss', 'subss', 'mulss', 'divss',
                'ucomiss', 'cvt')):
            continue  # label
        m = insn_pattern.match(line)
        if m:
            mn = m.group(1)
            ops = m.group(2).strip() if m.group(2) else ''
            if mn in ('ret', 'push', 'pop', 'mov', 'add', 'sub', 'call', 'jmp',
                       'cmp', 'test', 'lea', 'xor', 'or', 'and', 'je', 'jne',
                       'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe',
                       'movss', 'addss', 'subss', 'mulss', 'divss', 'ucomiss',
                       'shl', 'shr', 'imul', 'nop', 'cdq', 'inc', 'dec',
                       'jp', 'jnp', 'js', 'jns', 'neg', 'not'):
                recomp_insns.append((0, mn, ops))

    score, report = compare_functions(orig_insns, recomp_insns, func_name)
    return score, report


def verify_source(binary, src_idx):
    """Verify all functions in a source file."""
    macho = MachOReader(binary)
    func_addrs = get_func_addresses(binary)

    # Get full source file C output
    c_code = get_decomp_output(binary, '-s', str(src_idx))
    if not c_code.strip():
        print(f"No output for source {src_idx}")
        return

    code = make_compilable(c_code)

    # Try compilation first
    with tempfile.NamedTemporaryFile(suffix='.o', delete=False) as f:
        obj_path = f.name

    success, errors = compile_to_obj(code, obj_path)
    if not success:
        err_count = errors.count(': error:')
        print(f"Source {src_idx}: compilation FAILED ({err_count} errors)")
        # Show first few errors
        for line in errors.split('\n')[:10]:
            if ': error:' in line:
                print(f"  {line.strip()}")
        os.unlink(obj_path)
        return

    print(f"Source {src_idx}: compilation OK")

    # Get list of functions in this source file
    result = subprocess.run(
        ['./build/decomp', binary, '-F', ''],
        capture_output=True, text=True
    )

    # Disassemble the recompiled .o and compare each function
    total_score = 0
    num_funcs = 0

    # Extract function names from the decompiled output
    func_pattern = re.compile(r'^(?:static\s+)?(?:\w[\w\s\*]*?)\s+(\w+)\s*\(', re.MULTILINE)
    func_names = func_pattern.findall(c_code)

    for fname in func_names:
        if fname in ('if', 'while', 'for', 'switch', 'return', 'do', 'else'):
            continue

        recomp_insns = disasm_recompiled(obj_path, fname)
        if not recomp_insns:
            continue

        addr = func_addrs.get(fname)
        if not addr:
            continue

        orig_insns = disasm_original(macho, addr)
        if not orig_insns:
            continue

        score, report = compare_functions(orig_insns, recomp_insns, fname)
        print(report)
        total_score += score
        num_funcs += 1

    if num_funcs > 0:
        print(f"\n=== Average match: {total_score/num_funcs:.1f}% across {num_funcs} functions ===")

    os.unlink(obj_path)


def compile_test(binary, src_idx):
    """Just test if decompiled code compiles."""
    c_code = get_decomp_output(binary, '-s', str(src_idx))
    code = make_compilable(c_code)

    with tempfile.NamedTemporaryFile(suffix='.o', delete=False) as f:
        obj_path = f.name

    success, errors = compile_to_obj(code, obj_path)
    err_count = errors.count(': error:')
    os.unlink(obj_path)

    if success:
        print(f"Source {src_idx}: OK (compiles clean)")
    else:
        print(f"Source {src_idx}: FAIL ({err_count} errors)")
        for line in errors.split('\n')[:5]:
            if ': error:' in line:
                # Extract just the error message
                m = re.search(r': error: (.+)', line)
                if m:
                    print(f"  {m.group(1)}")
    return success


def main():
    parser = argparse.ArgumentParser(description='Decompilation verification tool')
    parser.add_argument('binary', nargs='?', default='binary.x86')
    parser.add_argument('-n', '--name', help='Verify function by name')
    parser.add_argument('-s', '--source', type=int, help='Verify source file by index')
    parser.add_argument('--compile-test', action='store_true', help='Test compilation only')
    parser.add_argument('--compile-all', action='store_true', help='Test all source files')
    args = parser.parse_args()

    if args.compile_all:
        # Test compilation of all source files
        ok = fail = 0
        for i in range(383):
            result = compile_test(args.binary, i)
            if result:
                ok += 1
            else:
                fail += 1
        print(f"\n=== {ok} OK, {fail} FAIL out of {ok+fail} source files ===")
        return

    if args.compile_test and args.source is not None:
        compile_test(args.binary, args.source)
        return

    if args.name:
        macho = MachOReader(args.binary)
        func_addrs = get_func_addresses(args.binary)
        score, report = verify_function(args.binary, args.name, macho, func_addrs)
        if score is not None:
            print(report)
        else:
            print(report)  # error message
        return

    if args.source is not None:
        verify_source(args.binary, args.source)
        return

    parser.print_help()


if __name__ == '__main__':
    main()
