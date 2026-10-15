# errname.py - map an engine error code value to its eErrNo* name (live globals + static initializer).
import sys, struct
sys.path.insert(0, '.')
from livemem import Proc
import cdre


def find_globals(p, value, lo=0x146c00000, hi=0x146e00000):
    raw = p.read(lo, hi - lo)
    return [lo + i for i in range(0, len(raw) - 3, 4) if struct.unpack_from('<I', raw, i)[0] == value]


def name_for(im, g):
    # static init: ... lea rcx,"eErrNo..." ; call hash ; mov [rip+g], eax
    for a, t in im.xrefs_rip(g, tails=(0,)):
        L = cdre.dis2(im, a - 2 - 0x30, 14, stop_ret=False)
        for l in L:
            if '"eErr' in l or '"Err' in l:
                return l.split('"')[1]
    return None


if __name__ == '__main__':
    v = int(sys.argv[1], 16); p = Proc(); im = cdre.load()
    for g in find_globals(p, v):
        print(hex(g), name_for(im, g))
