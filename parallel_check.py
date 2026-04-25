#!/usr/bin/env python3
"""Fast parallel asmcheck scanner. Uses multiprocessing for ~8x speedup."""
import subprocess, os, re, sys, time
from concurrent.futures import ProcessPoolExecutor, as_completed
from collections import Counter

BINARY = ''
DECOMP = './build/decomp'

def check_one(addr):
    """Check a single function, return (addr, status, name, pct, total, first_error)."""
    try:
        r = subprocess.run(['python3', 'asmcheck.py', addr],
                           capture_output=True, text=True, timeout=45)
        out = r.stdout.strip()
        if not out: return (addr, 'timeout', '', 0, 0, '')
        name = out.split(':')[0].strip()
        if 'PERFECT' in out:
            m = re.search(r'(\d+)/\1', out)
            cnt = int(m.group(1)) if m else 0
            return (addr, 'perfect', name, 100, cnt, '')
        if 'compile FAILED' in out:
            err = ''
            for line in out.split('\n'):
                if 'error:' in line:
                    err = re.search(r'error: (.+)', line).group(1).strip()
                    break
            return (addr, 'fail', name, 0, 0, err)
        m = re.search(r'(\d+)/(\d+)\s+\((\d+)%\)', out)
        if m:
            return (addr, 'partial', name, int(m.group(3)), int(m.group(2)), '')
        return (addr, 'unknown', name, 0, 0, '')
    except Exception as e:
        return (addr, 'error', '', 0, 0, str(e))

def main():
    os.chdir('/home/user/git/revtool')

    # Get function list
    r = subprocess.run([DECOMP, BINARY, '-F'], capture_output=True, text=True, timeout=30)
    all_funcs = [line.strip().split(None, 1)[0]
                 for line in r.stdout.strip().split('\n') if line.strip()]

    # Parse args
    stride = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 8

    sample = all_funcs[::stride][:limit]
    print(f"Checking {len(sample)} functions ({workers} workers)...")

    # Load existing regtest
    existing = set()
    if os.path.exists('regtest_funcs.txt'):
        with open('regtest_funcs.txt') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    existing.add(line.split()[0])

    start = time.time()
    results = []
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check_one, addr): addr for addr in sample}
        done = 0
        for future in as_completed(futures):
            done += 1
            results.append(future.result())
            if done % 50 == 0:
                print(f"  ...{done}/{len(sample)}", file=sys.stderr)

    elapsed = time.time() - start

    # Categorize
    perfect = [(a,n,t) for a,s,n,p,t,e in results if s == 'perfect']
    partial = [(a,n,p,t) for a,s,n,p,t,e in results if s == 'partial']
    failed = [(a,n,e) for a,s,n,p,t,e in results if s == 'fail']

    compiled = len(perfect) + len(partial)
    total = compiled + len(failed)

    print(f"\n=== Results ({elapsed:.0f}s) ===")
    print(f"Compiled: {compiled}/{total} ({100*compiled//total if total else 0}%)")
    print(f"Perfect:  {len(perfect)}/{total} ({100*len(perfect)//total if total else 0}%)")
    print(f"Failed:   {len(failed)}/{total}")

    # New perfects not in regtest
    new_perfect = [(a,n,t) for a,n,t in perfect if a not in existing and t >= 10]
    if new_perfect:
        print(f"\nNew PERFECT functions (10+ insns, not in regtest):")
        for a, n, t in sorted(new_perfect, key=lambda x: -x[2])[:20]:
            print(f"  {a} {n} ({t} insns)")

    # Near-perfect (85%+)
    near = [(a,n,p,t) for a,n,p,t in partial if p >= 85 and t >= 15]
    if near:
        print(f"\nNear-perfect (85%+, 15+ insns):")
        for a, n, p, t in sorted(near, key=lambda x: -x[2]):
            print(f"  {a} {n}: {p}% ({t} insns)")

    # Top error patterns
    err_counts = Counter()
    for a, n, e in failed:
        e2 = re.sub(r"'[^']*'", "'X'", e)
        err_counts[e2] += 1
    if err_counts:
        print(f"\nTop compile errors:")
        for err, count in err_counts.most_common(10):
            print(f"  {count:3d}  {err}")

if __name__ == '__main__':
    main()
