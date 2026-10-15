# sigcheck.py - scan CrimsonDesert.exe (as mapped image) for every AOB signature in the Trinity source.
import re, sys, struct, pathlib, json

def load_image(path):
    data = pathlib.Path(path).read_bytes()
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    nsec = struct.unpack_from('<H', data, pe + 6)[0]
    optsz = struct.unpack_from('<H', data, pe + 20)[0]
    base = struct.unpack_from('<Q', data, pe + 24 + 24)[0]
    secs = []
    off = pe + 24 + optsz
    for i in range(nsec):
        name = data[off:off+8].rstrip(b'\0').decode('latin1')
        vsize, va, rsize, raw = struct.unpack_from('<IIII', data, off + 8)
        chars = struct.unpack_from('<I', data, off + 36)[0]
        secs.append((name, va, vsize, raw, rsize, chars))
        off += 40
    return data, base, secs

def sig_regex(sig):
    out = b''
    for tok in sig.split():
        out += b'.' if tok in ('??', '?') else re.escape(bytes([int(tok, 16)]))
    return re.compile(out, re.S)

def main():
    exe, src = sys.argv[1], pathlib.Path(sys.argv[2])
    data, base, secs = load_image(exe)
    pat = re.compile(r'(?:(kSig_\w+)[^"\n]*?)?"((?:[0-9A-F]{2}|\?\?)(?: (?:[0-9A-F]{2}|\?\?)){5,})"')
    rows = []
    for f in src.rglob('*'):
        if f.suffix not in ('.h', '.cpp'): continue
        for ln, line in enumerate(f.read_text(errors='ignore').splitlines(), 1):
            for m in pat.finditer(line):
                rows.append((f.relative_to(src).as_posix(), ln, m.group(1) or '', m.group(2)))
    results = []
    for path, ln, name, sig in rows:
        rx = sig_regex(sig)
        hits = []
        for (sname, va, vsize, raw, rsize, chars) in secs:
            if not chars & 0x20000000: continue  # executable sections only
            blob = data[raw:raw+rsize]
            for m in rx.finditer(blob):
                hits.append(base + va + m.start())
                if len(hits) > 5: break
        results.append({'file': path, 'line': ln, 'name': name, 'hits': len(hits), 'va': [hex(h) for h in hits[:3]]})
        print(f"{len(hits):>2}  {path}:{ln}  {name}  {' '.join(hex(h) for h in hits[:2])}")
    json.dump(results, open(sys.argv[3], 'w'), indent=1)

main()
