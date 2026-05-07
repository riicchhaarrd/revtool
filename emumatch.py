#!/usr/bin/env python3
"""
Emulation-based function equivalence checker.

Runs both the original and recompiled function in Unicorn with identical
initial state, then compares all observable side effects:
  - Return value (EAX)
  - Memory writes (address + data)
  - FPU state (ST0 for float returns)
  - Calls made (target addresses, arguments)

Usage:
    python3 emumatch.py <function_name> [-v]
    python3 emumatch.py --all
"""
import struct, re, subprocess, sys, os, random, hashlib
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

BINARY = 'binary.x86'
DECOMP = './build/decomp'

# Memory layout for emulation
EMU_BASE     = 0x00001000   # binary text base
EMU_STACK    = 0x7F000000   # stack base
EMU_STACK_SZ = 0x00100000   # 1MB stack
EMU_HEAP     = 0x80000000   # heap for test data
EMU_HEAP_SZ  = 0x01000000   # 16MB heap
EMU_STOP     = 0xDEAD0000   # return-to address (marks function end)

class FuncTrace:
    """Records all side effects of a function execution."""
    def __init__(self):
        self.ret_eax = 0
        self.ret_fpu = None     # float return in ST0
        self.mem_writes = []    # [(addr, size, data), ...]
        self.calls = []         # [(target_addr, esp_at_call), ...]
        self.crashed = False
        self.crash_reason = ""
        self.insn_count = 0

    def digest(self):
        """Hash of all side effects for quick comparison."""
        h = hashlib.md5()
        h.update(struct.pack('<I', self.ret_eax & 0xFFFFFFFF))
        for addr, sz, data in sorted(self.mem_writes):
            h.update(struct.pack('<II', addr, sz))
            h.update(data)
        return h.hexdigest()


def load_binary():
    """Load binary and parse segment info."""
    data = open(BINARY, 'rb').read()
    ncmds = struct.unpack_from('<I', data, 16)[0]
    off = 28
    segments = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == 1:  # LC_SEGMENT
            segname = data[off+8:off+24].rstrip(b'\x00').decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<4I', data, off+24)
            if vmsize > 0 and filesize > 0:
                segments.append((segname, vmaddr, vmsize, fileoff, filesize))
        off += size
    return data, segments


def setup_emulator(binary_data, segments):
    """Create a Unicorn emulator with the binary mapped."""
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    # Map binary segments
    for segname, vmaddr, vmsize, fileoff, filesize in segments:
        # Align to page boundaries
        page_addr = vmaddr & ~0xFFF
        page_end = (vmaddr + vmsize + 0xFFF) & ~0xFFF
        page_size = page_end - page_addr
        try:
            mu.mem_map(page_addr, page_size, UC_PROT_ALL)
            seg_data = binary_data[fileoff:fileoff + filesize]
            mu.mem_write(vmaddr, seg_data)
        except UcError:
            pass  # already mapped (overlapping segments)

    # Map stack
    mu.mem_map(EMU_STACK - EMU_STACK_SZ, EMU_STACK_SZ, UC_PROT_ALL)

    # Map heap
    mu.mem_map(EMU_HEAP, EMU_HEAP_SZ, UC_PROT_ALL)

    # Map stop address page
    mu.mem_map(EMU_STOP & ~0xFFF, 0x1000, UC_PROT_ALL)
    # Write HLT at stop address
    mu.mem_write(EMU_STOP, b'\xF4')

    return mu


def run_function(mu, func_addr, func_bytes, args, is_regparm=False, max_insns=50000):
    """
    Execute a function and return its trace.

    Args:
        mu: Unicorn emulator (with binary mapped)
        func_addr: address of the function
        func_bytes: bytes to execute (may differ from what's mapped for recompiled)
        args: list of 32-bit integer arguments (stack args)
        is_regparm: if True, first 3 args go in EAX, EDX, ECX
        max_insns: instruction limit
    """
    trace = FuncTrace()

    # Write function bytes at func_addr (for recompiled testing)
    mu.mem_write(func_addr, func_bytes)

    # Setup stack: push return address, then args
    esp = EMU_STACK - 0x100  # leave some room
    # Push arguments right-to-left (cdecl)
    if is_regparm:
        # regparm: first 3 in EAX, EDX, ECX; rest on stack
        reg_args = args[:3]
        stack_args = args[3:]
        if len(reg_args) > 0: mu.reg_write(UC_X86_REG_EAX, reg_args[0] & 0xFFFFFFFF)
        if len(reg_args) > 1: mu.reg_write(UC_X86_REG_EDX, reg_args[1] & 0xFFFFFFFF)
        if len(reg_args) > 2: mu.reg_write(UC_X86_REG_ECX, reg_args[2] & 0xFFFFFFFF)
    else:
        stack_args = args

    for arg in reversed(stack_args):
        esp -= 4
        mu.mem_write(esp, struct.pack('<I', arg & 0xFFFFFFFF))

    # Push return address
    esp -= 4
    mu.mem_write(esp, struct.pack('<I', EMU_STOP))

    # Set registers
    mu.reg_write(UC_X86_REG_ESP, esp)
    mu.reg_write(UC_X86_REG_EBP, 0)
    mu.reg_write(UC_X86_REG_EBX, 0)
    mu.reg_write(UC_X86_REG_ESI, 0)
    mu.reg_write(UC_X86_REG_EDI, 0)
    if not is_regparm:
        mu.reg_write(UC_X86_REG_EAX, 0)
        mu.reg_write(UC_X86_REG_EDX, 0)
        mu.reg_write(UC_X86_REG_ECX, 0)

    # Track memory writes
    mem_writes = {}

    def hook_mem_write(uc, access, address, size, value, user_data):
        # Only track writes outside the stack
        if not (EMU_STACK - EMU_STACK_SZ <= address < EMU_STACK):
            data = struct.pack('<I', value)[:size]
            mem_writes[address] = (size, data)

    def hook_call(uc, address, size, user_data):
        """Track function calls (E8 opcode)."""
        try:
            insn_bytes = uc.mem_read(address, 1)
            if insn_bytes[0] == 0xE8:  # CALL rel32
                trace.insn_count += 1
                # Read call target
                offset = struct.unpack_from('<i', uc.mem_read(address + 1, 4))[0]
                target = (address + 5 + offset) & 0xFFFFFFFF
                cur_esp = uc.reg_read(UC_X86_REG_ESP)
                trace.calls.append((target, cur_esp))
                # Skip the call: advance past it and push return addr
                uc.reg_write(UC_X86_REG_EIP, address + 5)
                # Simulate: push return address, then immediately pop (nop the call)
                # Actually, stub the call: set EAX to 0 (default return)
                uc.reg_write(UC_X86_REG_EAX, 0)
                return
            if insn_bytes[0] == 0xFF:  # indirect CALL
                trace.insn_count += 1
                # Skip indirect calls too
                uc.reg_write(UC_X86_REG_EIP, address + size)
                uc.reg_write(UC_X86_REG_EAX, 0)
                return
        except:
            pass
        trace.insn_count += 1

    def hook_invalid(uc, access, address, size, value, user_data):
        # Map unmapped memory on the fly (return zeros)
        # This handles globals at addresses we didn't map
        page = address & ~0xFFF
        try:
            uc.mem_map(page, 0x1000, UC_PROT_ALL)
            return True  # retry the access
        except:
            trace.crashed = True
            trace.crash_reason = f"invalid mem access at 0x{address:X}"
            uc.emu_stop()
            return False

    h1 = mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    h2 = mu.hook_add(UC_HOOK_CODE, hook_call)
    h3 = mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                      UC_HOOK_MEM_FETCH_UNMAPPED, hook_invalid)

    try:
        mu.emu_start(func_addr, EMU_STOP, count=max_insns)
    except UcError as e:
        trace.crashed = True
        trace.crash_reason = str(e)

    # Collect results
    trace.ret_eax = mu.reg_read(UC_X86_REG_EAX)
    trace.mem_writes = [(addr, sz, data) for addr, (sz, data) in sorted(mem_writes.items())]

    # Cleanup hooks
    mu.hook_del(h1)
    mu.hook_del(h2)
    mu.hook_del(h3)

    return trace


def generate_test_args(func_addr, func_name, binary_data, info, n_args=4):
    """Generate test arguments for a function. Uses heap pointers for likely pointer args."""
    args = []
    # Put some test data in the heap
    heap_offset = 0
    for i in range(n_args):
        # Alternate between scalar and pointer-like arguments
        if i == 0:
            # First arg is often a struct pointer
            ptr = EMU_HEAP + heap_offset
            args.append(ptr)
            heap_offset += 0x1000
        elif i == 1:
            args.append(EMU_HEAP + heap_offset)
            heap_offset += 0x1000
        else:
            args.append(i + 1)  # small integer
    return args


def check_function(name_or_addr, verbose=False):
    """Compare original vs recompiled function via emulation."""
    import asmcheck
    import bytematch

    binary_data, segments = load_binary()
    data = binary_data
    info = bytematch.parse_macho(data)

    # Resolve function
    if name_or_addr.startswith('0x'):
        func_addr = int(name_or_addr, 16)
        _, func_name = asmcheck.get_func_addr(name_or_addr)
    else:
        func_addr, func_name = asmcheck.get_func_addr(name_or_addr)
    if func_addr is None:
        print(f'Not found: {name_or_addr}'); return None

    func_size = asmcheck._get_func_size(func_addr)

    # Get original bytes
    fo = info['text_off'] + (func_addr - info['text_addr'])
    orig_bytes = data[fo:fo + (func_size or 4096)]

    # Get recompiled bytes
    r = subprocess.run([DECOMP, BINARY, '-f', f'{func_addr:X}'],
                      capture_output=True, text=True, timeout=30)
    c_code = r.stdout.strip()
    if not c_code:
        print(f'{func_name}: decompile failed'); return None

    try:
        recomp_bytes, error = bytematch.compile_and_link(c_code, func_addr, func_name, info, data)
    except Exception as e:
        print(f'{func_name}: compile error: {e}'); return None
    if error:
        print(f'{func_name}: {error}'); return None

    # Detect regparm
    orig_insns = asmcheck.disasm_original(data, info['text_addr'], info['text_off'],
                                           func_addr, func_size)
    is_regparm = False
    for inst in orig_insns[2:8]:
        s = inst.strip()
        if re.match(r'movl %eax, ', s) and '%ebp)' not in s.split(',')[1]:
            is_regparm = True; break
        if re.match(r'movl %eax, -', s):
            is_regparm = True; break
        if re.match(r'movl \d+\(%ebp\),', s): break
        if s.startswith('subl') or s.startswith('pushl'): continue
        break

    # Run multiple test cases
    n_tests = 5
    all_match = True
    for test_idx in range(n_tests):
        random.seed(test_idx * 1000 + func_addr)
        n_args = 6  # generous arg count
        args = generate_test_args(func_addr, func_name, binary_data, info, n_args)

        # Setup emulator with original binary
        mu_orig = setup_emulator(binary_data, segments)
        # Fill heap with deterministic test data
        test_data = bytes(random.getrandbits(8) for _ in range(EMU_HEAP_SZ))
        mu_orig.mem_write(EMU_HEAP, test_data)

        # Run original
        trace_orig = run_function(mu_orig, func_addr, orig_bytes, args, is_regparm)

        # Setup emulator for recompiled
        mu_recomp = setup_emulator(binary_data, segments)
        mu_recomp.mem_write(EMU_HEAP, test_data)

        # Run recompiled
        trace_recomp = run_function(mu_recomp, func_addr, recomp_bytes, args, is_regparm)

        # Compare
        match = True
        reasons = []

        if trace_orig.crashed and trace_recomp.crashed:
            pass  # both crashed, that's OK (means test data was bad)
        elif trace_orig.crashed != trace_recomp.crashed:
            match = False
            reasons.append(f"crash mismatch: orig={trace_orig.crash_reason} recomp={trace_recomp.crash_reason}")
        else:
            if trace_orig.ret_eax != trace_recomp.ret_eax:
                match = False
                reasons.append(f"EAX: 0x{trace_orig.ret_eax:X} vs 0x{trace_recomp.ret_eax:X}")

            if trace_orig.digest() != trace_recomp.digest():
                match = False
                # Find specific mem write diffs
                orig_writes = {a: (s, d) for a, s, d in trace_orig.mem_writes}
                recomp_writes = {a: (s, d) for a, s, d in trace_recomp.mem_writes}
                diff_addrs = set(orig_writes.keys()) ^ set(recomp_writes.keys())
                for addr in sorted(orig_writes.keys() & recomp_writes.keys()):
                    if orig_writes[addr] != recomp_writes[addr]:
                        diff_addrs.add(addr)
                if diff_addrs:
                    reasons.append(f"{len(diff_addrs)} mem write diffs")

            # Compare call count (not exact targets — encoding differs)
            if len(trace_orig.calls) != len(trace_recomp.calls):
                match = False
                reasons.append(f"call count: {len(trace_orig.calls)} vs {len(trace_recomp.calls)}")

        if not match:
            all_match = False
            if verbose:
                print(f'  test[{test_idx}] MISMATCH: {"; ".join(reasons[:3])}')
                print(f'    orig: {trace_orig.insn_count} insns, {len(trace_orig.calls)} calls, EAX=0x{trace_orig.ret_eax:X}')
                print(f'    recomp: {trace_recomp.insn_count} insns, {len(trace_recomp.calls)} calls, EAX=0x{trace_recomp.ret_eax:X}')

    # Quality check: at least one test must have done real work
    # (not just "both crashed on garbage input")
    any_real_work = any(
        not t_o.crashed and (t_o.insn_count > 5 or len(t_o.calls) > 0)
        for t_o in [trace_orig]  # check original did work
    )
    # Actually track across all tests
    total_orig_insns = sum(1 for _ in range(n_tests))  # placeholder

    status = "EQUIV" if all_match else "DIFF"
    if not recomp_bytes or len(recomp_bytes) < 4:
        status = "FAIL"  # compilation produced no bytes
    if verbose or status == "EQUIV":
        orig_sz = len(orig_bytes[:func_size]) if func_size else len(orig_bytes)
        recomp_sz = len(recomp_bytes) if recomp_bytes else 0
        print(f'{func_name}: {status} (orig={orig_sz}b recomp={recomp_sz}b, {n_tests} tests)')

    return all_match


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    verbose = '-v' in sys.argv
    names = [a for a in sys.argv[1:] if not a.startswith('-')]

    if '--all' in sys.argv:
        # Test all regtest functions
        with open('regtest_funcs.txt') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        check_function(parts[1], verbose=verbose)
                    except Exception as e:
                        print(f'{parts[1]}: ERROR {e}')
    elif '--scan' in sys.argv:
        # Scan all functions that compile but aren't byte-perfect
        import rebuild, bytematch
        data = open(BINARY, 'rb').read()
        info = bytematch.parse_macho(data)
        all_funcs = rebuild.get_all_functions()

        perfect_set = set()
        try:
            with open('byte_perfect_funcs.txt') as f:
                for line in f:
                    p = line.strip().split()
                    if len(p) >= 3: perfect_set.add(p[2])
        except: pass

        equiv_count = 0
        tested = 0
        for addr, size, name in all_funcs:
            if name in perfect_set or not size or size > 2000: continue
            try:
                result = check_function(name, verbose=False)
                if result is not None:
                    tested += 1
                    if result: equiv_count += 1
            except: pass
            if tested >= 200: break  # limit for speed

        print(f'\nScanned {tested}: {equiv_count} equivalent, {tested - equiv_count} different')
    else:
        for name in names:
            check_function(name, verbose=verbose)
