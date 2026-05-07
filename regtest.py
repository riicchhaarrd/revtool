#!/usr/bin/env python3
"""
Regression test: decompile a list of functions, hash outputs, compare to baseline.

Usage:
  python3 regtest.py generate   # snapshot current output as baseline
  python3 regtest.py test       # compare current output to baseline
  python3 regtest.py add NAME   # add a function to the checklist
"""

import subprocess, hashlib, json, sys, os

BINARY = 'binary.x86'
DECOMP = './build/decomp'
BASELINE = 'regtest_baseline.json'
CHECKLIST = 'regtest_funcs.txt'

def decompile(addr):
    r = subprocess.run([DECOMP, BINARY, '-f', addr],
                       capture_output=True, text=True, timeout=30)
    return r.stdout.strip()

def load_checklist():
    if not os.path.exists(CHECKLIST):
        return []
    funcs = []
    with open(CHECKLIST) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(None, 1)
            addr = parts[0]
            name = parts[1] if len(parts) > 1 else addr
            funcs.append((addr, name))
    return funcs

def generate():
    funcs = load_checklist()
    if not funcs:
        print(f'No functions in {CHECKLIST}')
        return 1
    baseline = {}
    for addr, name in funcs:
        code = decompile(addr)
        h = hashlib.sha256(code.encode()).hexdigest()[:16]
        baseline[addr] = {'name': name, 'hash': h, 'lines': code.count('\n')}
        print(f'  {addr} {name}: {code.count(chr(10))} lines')
    with open(BASELINE, 'w') as f:
        json.dump(baseline, f, indent=2)
    print(f'Saved {len(baseline)} functions to {BASELINE}')
    return 0

def test():
    if not os.path.exists(BASELINE):
        print(f'No baseline. Run: python3 regtest.py generate')
        return 1
    with open(BASELINE) as f:
        baseline = json.load(f)
    ok = changed = fail = 0
    for addr, info in sorted(baseline.items(), key=lambda x: x[1]['name']):
        try:
            code = decompile(addr)
        except:
            print(f'  FAIL  {info["name"]}')
            fail += 1
            continue
        h = hashlib.sha256(code.encode()).hexdigest()[:16]
        if h == info['hash']:
            print(f'  ok    {info["name"]}')
            ok += 1
        else:
            print(f'  DIFF  {info["name"]} ({info["lines"]}→{code.count(chr(10))} lines)')
            changed += 1
    print(f'\n{ok} ok, {changed} changed, {fail} failed')
    return 1 if changed or fail else 0

def add(name):
    r = subprocess.run([DECOMP, BINARY, '-F'], capture_output=True, text=True)
    for line in r.stdout.split('\n'):
        if name in line:
            addr = line.strip().split()[0]
            fname = line.strip().split()[2].split('(')[0]
            with open(CHECKLIST, 'a') as f:
                f.write(f'{addr} {fname}\n')
            print(f'Added {addr} {fname}')
            return 0
    print(f'Not found: {name}')
    return 1

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 regtest.py [generate|test|add NAME]')
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'generate': sys.exit(generate())
    elif cmd == 'test': sys.exit(test())
    elif cmd == 'add' and len(sys.argv) > 2: sys.exit(add(sys.argv[2]))
    else: print(f'Unknown: {cmd}'); sys.exit(1)
