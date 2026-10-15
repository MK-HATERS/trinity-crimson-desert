# find_actor.py - list server actors whose CharacterInfo key matches (status+0x30 = characterinfo row).
import sys, struct
sys.path.insert(0, '.')
from livemem import Proc


def actor_rows(p):
    mgr = p.u64(p.u64(0x146D696B8)); d = p.u64(mgr + 0xB8); n = p.u32(mgr + 0xC0)
    ct = p.u64(0x146D69A48); rows = p.u64(ct + 0x58)
    for i in range(n):
        o = p.u64(d + 8 * i)
        try:
            st = p.u64(p.u64(o + 0x68) + 0x20); idx = p.u16(st + 0x30)
            r = p.u64(rows + 8 * idx); yield o, p.u32(o + 0x50), idx, p.u32(r), p.cstr(p.u64(p.u64(r + 8)))
        except OSError:
            continue


if __name__ == '__main__':
    p = Proc(); want = {int(a) for a in sys.argv[1:]}
    for o, aid, idx, key, sk in actor_rows(p):
        if not want or key in want: print(hex(o), 'id', hex(aid), 'row', idx, 'key', key, sk)
