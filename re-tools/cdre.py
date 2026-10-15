# cdre.py - small static-analysis kit for CrimsonDesert.exe (mapped-image view, RTTI, rip-relative xrefs, disasm).
import struct, re, pathlib, functools
import numpy as np
import capstone

EXE = r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert\bin64\CrimsonDesert.exe"


class Image:
    def __init__(self, path=EXE):
        raw = pathlib.Path(path).read_bytes()
        pe = struct.unpack_from('<I', raw, 0x3c)[0]
        nsec = struct.unpack_from('<H', raw, pe + 6)[0]
        optsz = struct.unpack_from('<H', raw, pe + 20)[0]
        opt = pe + 24
        self.base = struct.unpack_from('<Q', raw, opt + 24)[0]
        self.size = struct.unpack_from('<I', raw, opt + 56)[0]
        self.sections = []
        img = bytearray(self.size)
        off = opt + optsz
        for _ in range(nsec):
            name = raw[off:off + 8].rstrip(b'\0').decode('latin1')
            vsize, va, rsize, rawp = struct.unpack_from('<IIII', raw, off + 8)
            chars = struct.unpack_from('<I', raw, off + 36)[0]
            n = min(rsize, vsize) if vsize else rsize
            img[va:va + n] = raw[rawp:rawp + n]
            self.sections.append((name, va, max(vsize, rsize), chars))
            off += 40
        hdr = min(s[1] for s in self.sections)
        img[0:hdr] = raw[0:hdr]
        self.img = bytes(img)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = False

    # --- address helpers -------------------------------------------------------
    def rva(self, va): return va - self.base
    def va(self, rva): return rva + self.base
    def exec_ranges(self):
        return [(va, va + sz) for (n, va, sz, ch) in self.sections if ch & 0x20000000]
    def data_ranges(self):
        return [(va, va + sz) for (n, va, sz, ch) in self.sections if not ch & 0x20000000]
    def u8(self, va): return self.img[self.rva(va)]
    def u16(self, va): return struct.unpack_from('<H', self.img, self.rva(va))[0]
    def u32(self, va): return struct.unpack_from('<I', self.img, self.rva(va))[0]
    def i32(self, va): return struct.unpack_from('<i', self.img, self.rva(va))[0]
    def u64(self, va): return struct.unpack_from('<Q', self.img, self.rva(va))[0]
    def cstr(self, va, n=200):
        r = self.rva(va); e = self.img.find(b'\0', r, r + n)
        return self.img[r:e if e >= 0 else r + n].decode('latin1')
    def in_image(self, va): return self.base <= va < self.base + self.size

    # --- searching -------------------------------------------------------------
    def find_all(self, needle, ranges=None, limit=100000):
        out = []
        for lo, hi in (ranges or [(0, self.size)]):
            s = 0 if ranges is None else lo
            e = self.size if ranges is None else hi
            i = self.img.find(needle, s, e)
            while i >= 0 and len(out) < limit:
                out.append(self.va(i)); i = self.img.find(needle, i + 1, e)
        return out

    def find_sig(self, sig, ranges=None, limit=50):
        rx = re.compile(b''.join(b'.' if t in ('?', '??') else re.escape(bytes([int(t, 16)])) for t in sig.split()), re.S)
        out = []
        for lo, hi in (ranges or self.exec_ranges()):
            for m in rx.finditer(self.img, lo, hi):
                out.append(self.va(m.start()))
                if len(out) >= limit: return out
        return out

    def xrefs_rip(self, target_va, ranges=None, tails=(0, 1, 4)):
        """Offsets of rel32 fields that resolve to target (disp field address, tail = imm bytes after disp)."""
        target_rva = self.rva(target_va)
        out = []
        buf = np.frombuffer(self.img, dtype=np.uint8)
        for lo, hi in (ranges or self.exec_ranges()):
            lo_r, hi_r = lo, min(hi, self.size - 4)
            CH = 1 << 25
            for s in range(lo_r, hi_r, CH):
                e = min(s + CH, hi_r)
                b = buf[s:e + 3].astype(np.uint32)
                d = b[:-3] | (b[1:-2] << 8) | (b[2:-1] << 16) | (b[3:] << 24)
                idx = np.arange(e - s, dtype=np.uint32)
                for t in tails:
                    want = np.uint32((target_rva - s - 4 - t) & 0xffffffff)
                    hits = np.nonzero((d + idx) == want)[0]
                    out += [(self.va(s + int(h)), t) for h in hits]
        return out

    def xrefs_abs64(self, target_va, ranges=None):
        needle = struct.pack('<Q', target_va)
        return self.find_all(needle, ranges or self.data_ranges())

    # --- RTTI ------------------------------------------------------------------
    @functools.lru_cache(maxsize=None)
    def rtti(self, mangled):
        """mangled like '.?AVTrocTrLearnSkillReq@pa@@' -> dict(td, col, vtable)"""
        hits = self.find_all(mangled.encode() + b'\0', self.data_ranges())
        res = []
        for s in hits:
            td = s - 0x10
            td_rva = struct.pack('<I', self.rva(td))
            for p in self.find_all(td_rva, self.data_ranges()):
                col = p - 0xC
                if self.u32(col) != 1 or self.u32(col + 0x14) != self.rva(col):
                    continue
                for q in self.xrefs_abs64(col):
                    res.append({'td': td, 'col': col, 'offset': self.u32(col + 4), 'vtable': q + 8})
        return res

    def vtable_funcs(self, vt, maxn=64):
        out = []
        for i in range(maxn):
            f = self.u64(vt + 8 * i)
            if not any(lo <= self.rva(f) < hi for lo, hi in self.exec_ranges()): break
            out.append(f)
        return out

    # --- disassembly -----------------------------------------------------------
    def dis(self, va, n=40, stop_ret=True):
        r = self.rva(va)
        lines = []
        for ins in self.md.disasm(self.img[r:r + n * 15], va):
            lines.append(f"{ins.address:#x}: {ins.mnemonic} {ins.op_str}")
            if len(lines) >= n or (stop_ret and ins.mnemonic in ('ret', 'int3')): break
        return lines

    def func_start(self, va, back=0x4000):
        """Heuristic: walk back to the previous int3/cc padding boundary."""
        r = self.rva(va)
        lo = max(0, r - back)
        k = self.img.rfind(b'\xcc\xcc', lo, r)
        return self.va(k + 2) if k >= 0 else None


@functools.lru_cache(maxsize=1)
def load():
    return Image()


def rip_target(im, ins_va):
    """Resolve the rip-relative operand of the instruction at ins_va."""
    r = im.rva(ins_va)
    ins = next(im.md.disasm(im.img[r:r + 16], ins_va))
    m = re.search(r'\[rip ([+-]) (0x[0-9a-f]+|\d+)\]', ins.op_str)
    if not m: return None
    d = int(m.group(2), 0) * (1 if m.group(1) == '+' else -1)
    return ins_va + ins.size + d


def dis2(im, va, n=40, stop_ret=True):
    """Disassembly with rip targets resolved and printable strings annotated."""
    r = im.rva(va)
    out = []
    for ins in im.md.disasm(im.img[r:r + n * 15], va):
        s = f"{ins.address:#x}: {ins.mnemonic} {ins.op_str}"
        m = re.search(r'\[rip ([+-]) (0x[0-9a-f]+|\d+)\]', ins.op_str)
        if m:
            t = ins.address + ins.size + int(m.group(2), 0) * (1 if m.group(1) == '+' else -1)
            s += f"   ; -> {t:#x}"
            if im.in_image(t):
                txt = im.cstr(t, 80)
                if len(txt) >= 4 and all(32 <= ord(c) < 127 for c in txt): s += f' "{txt}"'
        out.append(s)
        if len(out) >= n or (stop_ret and ins.mnemonic in ('ret', 'int3')): break
    return out


def troc_handler(im, name):
    """Static handler object for a Troc message: (vtable, obj, init_site)."""
    res = im.rtti(f'.?AV{name}@pa@@')
    if not res: return None
    vt = res[0]['vtable']
    for a, t in im.xrefs_rip(vt, tails=(0,)):
        ins = a - 3
        # pattern: lea rax,[vt] ; mov [rip+obj], rax
        nxt = ins + 7
        tgt = rip_target(im, nxt)
        if tgt and im.u8(nxt) == 0x48 and im.u8(nxt + 1) == 0x89:
            return {'vtable': vt, 'obj': tgt, 'init': ins, 'handle': im.vtable_funcs(vt)[-1]}
    return {'vtable': vt, 'obj': None}


def field_map(im, table, max_fn=0x3000):
    """Map '<table> _field' deserializer error strings to row offsets (best effort)."""
    import collections
    d = im.img
    rx = re.compile(re.escape(table.encode()) + rb'[^\x00]{0,6}?(_[A-Za-z0-9_]+)')
    strs = {}
    for lo, hi in im.data_ranges():
        for m in rx.finditer(d, lo, hi):
            if d[m.start() - 1] == 0:
                strs[im.va(m.start())] = m.group(1).decode()
    if not strs: return {}
    # locate deserializer(s) via xrefs of the strings
    sites = {}
    for s in strs:
        for a, t in im.xrefs_rip(s, tails=(0,)):
            sites[a - 3] = s
    if not sites: return {}
    fstart = im.func_start(min(sites))
    end = max(sites) + 0x40
    r0 = im.rva(fstart)
    ins = list(im.md.disasm(d[r0:im.rva(end)], fstart))
    addr_i = {x.address: i for i, x in enumerate(ins)}
    # most common base register in "lea rdx, [reg + off]"
    cnt = collections.Counter(re.match(r'rdx, \[(\w+) \+', x.op_str).group(1) for x in ins
                              if x.mnemonic == 'lea' and re.match(r'rdx, \[(\w+) \+ ', x.op_str)
                              and not x.op_str.startswith('rdx, [rsp') and not x.op_str.startswith('rdx, [rbp'))
    base = cnt.most_common(1)[0][0] if cnt else 'rdi'
    def dest_before(i):
        for j in range(i - 1, max(i - 14, 0), -1):
            m = re.match(r'rdx, \[(\w+) \+ (0x[0-9a-f]+|\d+)\]', ins[j].op_str)
            if ins[j].mnemonic == 'lea' and m:
                if m.group(1) == base: return int(m.group(2), 0), None
                return None, j
            if ins[j].mnemonic == 'lea' and ins[j].op_str == f'rdx, [{base}]': return 0, None
        return None, None
    jumps_to = collections.defaultdict(list)
    for i, x in enumerate(ins):
        if x.mnemonic.startswith('j') and x.op_str.startswith('0x'):
            jumps_to[int(x.op_str, 16)].append(i)
    out = {}
    for i, x in enumerate(ins):
        if x.address not in sites: continue
        name = strs[sites[x.address]]
        cands = []
        if i > 0 and ins[i - 1].mnemonic in ('jne', 'je'):
            cands.append(i - 1)
        cands += jumps_to.get(x.address, [])
        for c in cands:
            off, tmp = dest_before(c)
            if off is None and tmp is not None:
                # read into a temp, then stored: look for mov [base+X], e?ax after the branch
                for k in range(c + 1, min(c + 6, len(ins))):
                    m = re.search(rf'\[{base} \+ (0x[0-9a-f]+|\d+)\], [re]?[a-d]x', ins[k].op_str)
                    if ins[k].mnemonic == 'mov' and m: off = int(m.group(1), 0); break
            if off is not None:
                out[name] = off; break
        out.setdefault(name, None)
    return dict(sorted(out.items(), key=lambda kv: (kv[1] is None, kv[1] or 0)))


def field_map_fast(im, table, anchor_field='_key', span=0x8000):
    """Like field_map, but only one xref scan: disassemble the deserializer once."""
    import collections
    d = im.img
    rx = re.compile(re.escape(table.encode()) + rb'[^\x00]{0,6}?(_[A-Za-z0-9_]+)')
    strs = {}
    for lo, hi in im.data_ranges():
        for m in rx.finditer(d, lo, hi):
            if d[m.start() - 1] == 0:
                strs.setdefault(im.va(m.start()), m.group(1).decode())
    anchor = next((a for a, n in strs.items() if n == anchor_field), None)
    if anchor is None: return {}
    xr = im.xrefs_rip(anchor, tails=(0,))
    if not xr: return {}
    center = xr[0][0]
    lo = center - span; hi = center + span
    k = d.find(b'\xcc\xcc'.decode('unicode_escape').encode('latin1'), im.rva(lo))
    lo = im.va(k + 2) if k >= 0 else lo
    while d[im.rva(lo)] == 0xcc: lo += 1
    r0 = im.rva(lo)
    ins = list(im.md.disasm(d[r0:im.rva(hi)], lo))
    def tgt(x):
        m = re.search(r'\[rip ([+-]) (0x[0-9a-f]+|\d+)\]', x.op_str)
        if not m: return None
        return x.address + x.size + int(m.group(2), 0) * (1 if m.group(1) == '+' else -1)
    sites = {}
    for i, x in enumerate(ins):
        if x.mnemonic == 'lea' and (x.op_str.startswith('rcx,') or x.op_str.startswith('ecx,')):
            t = tgt(x)
            if t in strs: sites[x.address] = (i, strs[t])
    cnt = collections.Counter(re.match(r'rdx, \[(\w+) \+', x.op_str).group(1) for x in ins
                              if x.mnemonic == 'lea' and re.match(r'rdx, \[(\w+) \+ ', x.op_str)
                              and not x.op_str.startswith('rdx, [rsp') and not x.op_str.startswith('rdx, [rbp'))
    base = cnt.most_common(1)[0][0] if cnt else 'rdi'
    jumps_to = collections.defaultdict(list)
    for i, x in enumerate(ins):
        if x.mnemonic.startswith('j') and x.op_str.startswith('0x'):
            jumps_to[int(x.op_str, 16)].append(i)
    def dest_before(i):
        for j in range(i - 1, max(i - 14, 0), -1):
            m = re.match(r'rdx, \[(\w+) \+ (0x[0-9a-f]+|\d+)\]', ins[j].op_str)
            if ins[j].mnemonic == 'lea' and m:
                return (int(m.group(2), 0), None) if m.group(1) not in ('rsp', 'rbp') else (None, j)
            if ins[j].mnemonic == 'lea' and re.match(r'rdx, \[(r[a-z0-9]+)\]$', ins[j].op_str) and 'rsp' not in ins[j].op_str: return 0, None
        return None, None
    out = {}
    for addr, (i, name) in sites.items():
        cands = ([i - 1] if i > 0 and ins[i - 1].mnemonic in ('jne', 'je') else []) + jumps_to.get(addr, [])
        for c in cands:
            off, tmp = dest_before(c)
            if off is None and tmp is not None:
                for k in range(c + 1, min(c + 6, len(ins))):
                    m = re.search(r'\[(?!rsp|rbp)r\w+ \+ (0x[0-9a-f]+|\d+)\], [re]?[a-d]x', ins[k].op_str)
                    if ins[k].mnemonic == 'mov' and m: off = int(m.group(1), 0); break
            if off is not None: out[name] = off; break
        out.setdefault(name, None)
    for n in strs.values(): out.setdefault(n, None)
    return out
