# livemem.py - read-only access to the running CrimsonDesert.exe (ReadProcessMemory).
import ctypes, ctypes.wintypes as wt, struct, subprocess

PROCESS_VM_READ, PROCESS_QUERY_INFORMATION = 0x10, 0x400
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


def pid_of(name="CrimsonDesert.exe"):
    out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if parts and parts[0].lower() == name.lower():
            return int(parts[1])
    raise RuntimeError("game not running")


class Proc:
    def __init__(self, pid=None):
        self.h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid or pid_of())
        if not self.h:
            raise ctypes.WinError(ctypes.get_last_error())

    def read(self, addr, n):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t()
        if not k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
            raise OSError(f"read failed at {addr:#x}")
        return buf.raw[:got.value]

    def u16(self, a): return struct.unpack('<H', self.read(a, 2))[0]
    def u32(self, a): return struct.unpack('<I', self.read(a, 4))[0]
    def u64(self, a): return struct.unpack('<Q', self.read(a, 8))[0]

    def cstr(self, a, n=128):
        b = self.read(a, n)
        return b.split(b'\0', 1)[0].decode('utf-8', 'replace')


# --- write access (VM_WRITE | VM_OPERATION) for test scaffolding only --------
PROCESS_VM_WRITE, PROCESS_VM_OPERATION = 0x20, 0x8
MEM_COMMIT_RESERVE, PAGE_READWRITE = 0x3000, 0x04
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD]
k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


class RwProc(Proc):
    def __init__(self, pid=None):
        self.h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                                 False, pid or pid_of())
        if not self.h:
            raise ctypes.WinError(ctypes.get_last_error())

    def alloc(self, n=0x1000):
        a = k32.VirtualAllocEx(self.h, None, n, MEM_COMMIT_RESERVE, PAGE_READWRITE)
        if not a: raise ctypes.WinError(ctypes.get_last_error())
        return a

    def write(self, addr, data):
        n = ctypes.c_size_t()
        if not k32.WriteProcessMemory(self.h, ctypes.c_void_p(addr), data, len(data), ctypes.byref(n)) or n.value != len(data):
            raise OSError(f"write failed at {addr:#x}")
