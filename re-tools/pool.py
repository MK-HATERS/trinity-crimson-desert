# pool.py - child-actor pool on the ServerUserActor (sub+0x18 CommonChildContainerActorComponent).
import sys, struct
sys.path.insert(0, '.')
from livemem import Proc


def pool(p):
    mgr = p.u64(p.u64(0x146D696B8)); user = p.u64(p.u64(mgr + 0xB8)); c = p.u64(p.u64(user + 0x68) + 0x18)
    arr = p.u64(c + 0x18); n = p.u32(c + 0x20)
    ct = p.u64(0x146D69A48); rows = p.u64(ct + 0x58)
    out = []
    for i in range(n):
        a = p.u64(arr + 16 * i); used = p.read(arr + 16 * i + 8, 1)[0]
        if not used: continue
        name = '?'
        try:
            st = p.u64(p.u64(a + 0x68) + 0x20); idx = p.u16(st + 0x30); r = p.u64(rows + 8 * idx)
            name = f'{p.u32(r)} {p.cstr(p.u64(p.u64(r + 8)))}'
        except OSError:
            pass
        out.append((i, a, p.u32(a + 0x50), name))
    return out


if __name__ == '__main__':
    for row in pool(Proc()): print(row[0], hex(row[1]), 'id', hex(row[2]), row[3])
