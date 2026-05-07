import rebuild, sys, time

funcs = rebuild.get_all_functions()
data = open('binary.x86', 'rb').read()
info = rebuild.parse_macho(data)

perfect = []
tested = 0
failed = 0
start = time.time()

with open('byte_perfect_funcs_new.txt', 'w') as out:
    for addr, size, name in funcs:
        if not size or size < 5:
            continue
        try:
            recomp, error = rebuild.compile_function(addr, name, info, data)
            if error or recomp is None:
                failed += 1
                continue
            tested += 1
            orig = rebuild.get_func_bytes(data, info, addr, size)
            pct, n_match, total, first_diff = rebuild.compare_bytes(orig, recomp)
            if pct == 100 and len(orig) == len(recomp):
                perfect.append((addr, size, name))
                out.write(f'{addr:08X} {size:5d} {name}\n')
                out.flush()
        except Exception:
            failed += 1
            continue

elapsed = time.time() - start
total_bytes = sum(s for _,s,_ in perfect)
print(f'Tested: {tested}, Failed: {failed}, Time: {elapsed:.0f}s')
print(f'PERFECT: {len(perfect)} ({total_bytes} bytes)')
