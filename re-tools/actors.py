# actors.py - list characters in the client character manager with id and CharacterInfo key.
import sys, struct, json
sys.path.insert(0, '.')
from livemem import Proc
from memwalk import rtti

CAT = {c['character_key']: c['display_name'] for c in json.load(open(
    r'..\refs\CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS\CrimsonGameMods\data\character_catalog.json',
    encoding='utf-8'))['characters']}


def char_key(p, owner):
    try:
        sub = p.u64(owner + 0x68); st = p.u64(sub + 0x20); row = p.u64(st + 0x30)
        return p.u32(row), p.cstr(p.u64(p.u64(row + 8)))
    except OSError:
        return None, None


def actors(p, mgr):
    data = p.u64(mgr + 0xB8); n = p.u32(mgr + 0xC0)
    out = []
    for i in range(n):
        o = p.u64(data + 8 * i)
        if not o: continue
        k, sk = char_key(p, o)
        out.append((i, o, rtti(p, o), p.u32(o + 0x50), k, sk))
    return out


if __name__ == '__main__':
    p = Proc(); mgr = int(sys.argv[1], 16)
    flt = sys.argv[2] if len(sys.argv) > 2 else None
    rows = actors(p, mgr)
    print('count', len(rows))
    for i, o, cls, aid, k, sk in rows:
        if flt and flt.lower() not in f'{cls} {sk} {CAT.get(k)}'.lower(): continue
        print(i, hex(o), cls, 'id', hex(aid), 'key', k, sk, '|', CAT.get(k))
