# memwalk.py - annotate a live object: every qword that points at an RTTI object, a vector, or a string.
import sys, struct
sys.path.insert(0, '.')
from livemem import Proc

BASE = 0x140000000


def rtti(p, obj):
    try:
        vt = p.u64(obj)
        if not (BASE <= vt < BASE + 0x20000000): return None
        col = p.u64(vt - 8)
        if not (BASE <= col < BASE + 0x20000000) or p.u32(col) != 1: return None
        return p.cstr(BASE + p.u32(col + 0xC) + 0x10)
    except OSError:
        return None


def walk(p, obj, size=0x200):
    raw = p.read(obj, size)
    print(f"{obj:#x}: {rtti(p, obj)}")
    for off in range(0, size - 7, 8):
        q = struct.unpack_from('<Q', raw, off)[0]
        note = ''
        if 0x10000000 < q < 0x7fffffffffff:
            c = rtti(p, q)
            if c: note = c
            elif BASE <= q < BASE + 0x20000000: note = 'image'
            else:
                n = struct.unpack_from('<I', raw, off + 8)[0] if off + 12 <= size else 0
                cap = struct.unpack_from('<I', raw, off + 12)[0] if off + 16 <= size else 0
                if 0 < n <= cap < 100000: note = f'vector? n={n} cap={cap}'
                else: note = 'heap'
        elif q:
            note = f'val {q:#x} ({q & 0xffffffff})'
        if note: print(f"  +{off:#05x}: {q:#018x}  {note}")


if __name__ == '__main__':
    p = Proc()
    walk(p, int(sys.argv[1], 16), int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x200)
