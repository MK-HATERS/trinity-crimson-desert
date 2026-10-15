# probe.py - send commands to Trinity's dev probe and print the reply.
# usage: python probe.py "owners" "table skillinfo"   (or pipe lines on stdin)
import sys, time, pathlib

BIN = pathlib.Path(r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert\bin64")
IN, OUT = BIN / "Trinity_probe.in", BIN / "Trinity_probe.out"


def run(lines, timeout=20.0):
    start = OUT.stat().st_size if OUT.exists() else 0
    IN.write_text("\n".join(lines) + "\n", encoding="utf-8")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if OUT.exists() and OUT.stat().st_size > start:
            data = OUT.read_bytes()[start:].decode("utf-8", "replace")
            if "=== done" in data:
                return data
        time.sleep(0.2)
    return "TIMEOUT (is a save loaded? the probe runs on the game-thread tick)\n"


if __name__ == "__main__":
    cmds = sys.argv[1:] or [l.rstrip("\n") for l in sys.stdin if l.strip()]
    sys.stdout.write(run(cmds))
