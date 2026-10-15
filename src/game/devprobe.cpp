#include "devprobe.h"

#include <Windows.h>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "inventory.h"
#include "mercenary.h"
#include "player.h"
#include "offsets.h"
#include "troc.h"
#include "teleport.h"
#include "../core/logger.h"
#include "../mem/safe_memory.h"

namespace trinity::game
{
    namespace
    {
        constexpr uintptr_t kIdbBase = 0x140000000ULL;

        std::wstring g_inPath;
        std::wstring g_outPath;
        ULONGLONG    g_nextPoll = 0;

        bool InitPaths()
        {
            if (!g_inPath.empty()) return true;
            HMODULE self = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    reinterpret_cast<LPCWSTR>(&InitPaths), &self))
                return false;
            wchar_t buf[MAX_PATH];
            const DWORD n = GetModuleFileNameW(self, buf, MAX_PATH);
            if (!n || n >= MAX_PATH) return false;
            std::wstring dir(buf, n);
            dir.resize(dir.find_last_of(L"\\/") + 1);
            g_inPath = dir + L"Trinity_probe.in";
            g_outPath = dir + L"Trinity_probe.out";
            return true;
        }

        uintptr_t Rebase(uintptr_t idbVa)
        {
            const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
            return idbVa - kIdbBase + base;
        }

        // Parses "0x..."/decimal; '=' prefix keeps the value absolute, otherwise
        // values inside the IDB image range are rebased to the live module.
        uintptr_t ParseAddr(const char* s)
        {
            const bool absolute = *s == '=';
            const uintptr_t v = std::strtoull(absolute ? s + 1 : s, nullptr, 0);
            if (!absolute && v >= kIdbBase && v < kIdbBase + 0x20000000ULL)
                return Rebase(v);
            return v;
        }

        void Out(std::string& o, const char* fmt, ...)
        {
            char line[1024];
            va_list ap;
            va_start(ap, fmt);
            vsnprintf(line, sizeof(line), fmt, ap);
            va_end(ap);
            o += line;
        }

        void HexDump(std::string& o, uintptr_t addr, size_t len)
        {
            for (size_t off = 0; off < len; off += 16)
            {
                Out(o, "  %016llX:", static_cast<unsigned long long>(addr + off));
                char ascii[17] = {};
                for (size_t i = 0; i < 16; ++i)
                {
                    uint8_t b = 0;
                    if (off + i < len && mem::Read8(addr + off + i, &b))
                    {
                        Out(o, " %02X", b);
                        ascii[i] = (b >= 32 && b < 127) ? static_cast<char>(b) : '.';
                    }
                    else
                    {
                        Out(o, " ??");
                        ascii[i] = ' ';
                    }
                }
                Out(o, "  %s\n", ascii);
            }
        }

        uintptr_t Deref(uintptr_t p, uintptr_t off)
        {
            uintptr_t v = 0;
            return mem::ReadPtr(p + off, &v) ? v : 0;
        }

        void DescribeOwner(std::string& o, const char* label, uintptr_t owner)
        {
            const uintptr_t sub = owner ? Deref(owner, 0x68) : 0;
            Out(o, "%s owner=%p sub(+68)=%p equip(+38)=%p skill(+F0)=%p knowledge(+150)=%p inv(+B8)=%p\n",
                label, reinterpret_cast<void*>(owner), reinterpret_cast<void*>(sub),
                reinterpret_cast<void*>(sub ? Deref(sub, 0x38) : 0),
                reinterpret_cast<void*>(sub ? Deref(sub, 0xF0) : 0),
                reinterpret_cast<void*>(sub ? Deref(sub, 0x150) : 0),
                reinterpret_cast<void*>(sub ? Deref(sub, 0xB8) : 0));
        }

        struct RealmSwitch
        {
            uintptr_t addr = 0;
            uint8_t previous = 0;
            bool active = false;
            explicit RealmSwitch(int realm)
            {
                if (realm < 0) return;
                addr = Inventory::RealmFlagAddress(&previous);
                active = addr && mem::Write8(addr, static_cast<uint8_t>(realm));
            }
            ~RealmSwitch() { if (active) mem::Write8(addr, previous); }
        };

        using Native7 = uint64_t(__fastcall*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                              uint64_t, uint64_t, uint64_t);

        // Separate function: __try cannot share a frame with C++ objects.
        bool GuardedCall(uintptr_t fn, const uint64_t* a, uint64_t* ret, DWORD* code)
        {
            __try
            {
                *ret = reinterpret_cast<Native7>(fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
                return true;
            }
            __except (*code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        struct Scratch
        {
            std::vector<uint8_t> bytes;
            std::string label;
        };

        void CmdCall(std::string& o, char** tok, int n)
        {
            if (n < 3) { Out(o, "usage: call <addr> <c|s|-> [args]\n"); return; }
            const uintptr_t fn = ParseAddr(tok[1]);
            const int realm = tok[2][0] == 's' ? 1 : tok[2][0] == 'c' ? 0 : -1;
            uint64_t args[7] = {};
            std::vector<Scratch> scratch;
            scratch.reserve(8);
            for (int i = 3; i < n && i - 3 < 7; ++i)
            {
                const char* t = tok[i];
                uint64_t v = 0;
                if (!std::strcmp(t, "@srv")) v = Inventory::ServerCharacterAddr();
                else if (!std::strcmp(t, "@cli")) v = Inventory::ClientCharacterAddr();
                else if (!std::strcmp(t, "@srvsub")) v = Deref(Inventory::ServerCharacterAddr(), 0x68);
                else if (!std::strcmp(t, "@clisub")) v = Deref(Inventory::ClientCharacterAddr(), 0x68);
                else if (!std::strncmp(t, "buf", 3) || !std::strncmp(t, "u16:", 4) ||
                         !std::strncmp(t, "u32:", 4) || !std::strncmp(t, "u64:", 4))
                {
                    Scratch s;
                    s.label = t;
                    if (t[0] == 'b')
                    {
                        const size_t len = std::strtoull(t + 3, nullptr, 0);
                        s.bytes.assign(len ? (len > 4096 ? 4096 : len) : 64, 0);
                    }
                    else
                    {
                        const uint64_t val = std::strtoull(t + 4, nullptr, 0);
                        s.bytes.assign(16, 0);
                        std::memcpy(s.bytes.data(), &val, sizeof(val));
                    }
                    scratch.push_back(std::move(s));
                    v = reinterpret_cast<uint64_t>(scratch.back().bytes.data());
                }
                else v = ParseAddr(t);
                args[i - 3] = v;
            }
            Out(o, "call %p realm=%d args=", reinterpret_cast<void*>(fn), realm);
            for (uint64_t a : args) Out(o, " %llX", static_cast<unsigned long long>(a));
            Out(o, "\n");
            uint64_t ret = 0;
            DWORD code = 0;
            bool ok;
            {
                RealmSwitch guard(realm);
                ok = GuardedCall(fn, args, &ret, &code);
            }
            if (ok) Out(o, "  -> rax=%llX\n", static_cast<unsigned long long>(ret));
            else Out(o, "  -> EXCEPTION %08lX\n", code);
            for (const Scratch& s : scratch)
            {
                Out(o, "  %s @%p:\n", s.label.c_str(), static_cast<const void*>(s.bytes.data()));
                HexDump(o, reinterpret_cast<uintptr_t>(s.bytes.data()), s.bytes.size() > 128 ? 128 : s.bytes.size());
            }
        }

        void Execute(std::string& o, char* line)
        {
            char* tok[16];
            int n = 0;
            for (char* t = std::strtok(line, " \t\r\n"); t && n < 16; t = std::strtok(nullptr, " \t\r\n"))
                tok[n++] = t;
            if (!n || tok[0][0] == '#') return;
            Out(o, "> %s", tok[0]);
            for (int i = 1; i < n; ++i) Out(o, " %s", tok[i]);
            Out(o, "\n");

            if (!std::strcmp(tok[0], "owners"))
            {
                Out(o, "module base=%p\n", reinterpret_cast<void*>(GetModuleHandleW(nullptr)));
                DescribeOwner(o, "controlled", Player::GetControlledOwner());
                DescribeOwner(o, "client    ", Inventory::ClientCharacterAddr());
                DescribeOwner(o, "server    ", Inventory::ServerCharacterAddr());
                for (int i = 0; i < Player::GetTrackedMountCount() && i < 4; ++i)
                    DescribeOwner(o, "mount     ", Player::GetMountOwner(i));
            }
            else if (!std::strcmp(tok[0], "table") && n >= 2)
            {
                const uintptr_t g = Inventory::FindTableGlobal(tok[1], n >= 3);
                const uintptr_t t = g ? Deref(g, 0) : 0;
                uint32_t count = 0;
                if (t) mem::Read32(t + 0x08, &count);
                Out(o, "table %s global=%p table=%p count=%u defs50=%p defs58=%p\n", tok[1],
                    reinterpret_cast<void*>(g), reinterpret_cast<void*>(t), count,
                    reinterpret_cast<void*>(t ? Deref(t, 0x50) : 0),
                    reinterpret_cast<void*>(t ? Deref(t, 0x58) : 0));
                if (t) HexDump(o, t, 0x80);
            }
            else if (!std::strcmp(tok[0], "read") && n >= 3)
            {
                size_t len = std::strtoull(tok[2], nullptr, 0);
                if (len > 4096) len = 4096;
                HexDump(o, ParseAddr(tok[1]), len);
            }
            else if (!std::strcmp(tok[0], "readp") && n >= 3)
            {
                uintptr_t p = ParseAddr(tok[1]);
                Out(o, "  start %p\n", reinterpret_cast<void*>(p));
                for (char* t = std::strtok(tok[2], ","); t && p; t = std::strtok(nullptr, ","))
                {
                    const uintptr_t off = std::strtoull(t, nullptr, 0);
                    p = Deref(p, off);
                    Out(o, "  [+%llX] -> %p\n", static_cast<unsigned long long>(off), reinterpret_cast<void*>(p));
                }
            }
            else if (!std::strcmp(tok[0], "pos"))
            {
                float x = 0, y = 0, z = 0;
                const bool ok = Teleport::GetLastPosition(&x, &y, &z);
                Out(o, "pos %s %.3f %.3f %.3f\n", ok ? "ok" : "unknown", x, y, z);
            }
            else if (!std::strcmp(tok[0], "post") && n >= 2)
            {
                // post <TrocTrName> [hex payload] - runs inside the server pump
                uint8_t payload[0x200];
                size_t len = 0;
                for (int i = 2; i < n; ++i)
                    for (const char* c = tok[i]; c[0] && c[1] && len < sizeof(payload); c += 2)
                    {
                        char byte[3] = { c[0], c[1], 0 };
                        payload[len++] = static_cast<uint8_t>(std::strtoul(byte, nullptr, 16));
                    }
                const uint32_t ticket = troc::Post(tok[1], payload, static_cast<uint16_t>(len));
                Out(o, "posted %s len=%zu ticket=%u pump=%d pending=%zu\n", tok[1], len, ticket,
                    troc::ServerPumpReady() ? 1 : 0, troc::Pending());
            }
            else if (!std::strcmp(tok[0], "spawn") && n >= 2)
            {
                // spawn <characterinfo row> [adopt 0|1]
                const uint16_t row = static_cast<uint16_t>(std::strtoul(tok[1], nullptr, 0));
                const bool adopt = n >= 3 && tok[2][0] == '1';
                Mercenary::SpawnCreature(row, adopt);
                Out(o, "spawn row %u adopt=%d queued\n", row, adopt ? 1 : 0);
            }
            else if (!std::strcmp(tok[0], "results"))
            {
                troc::Completion done[32];
                size_t count = 0;
                troc::TakeCompletions(done, 32, &count);
                for (size_t i = 0; i < count; ++i)
                    Out(o, "ticket %u -> %s err=0x%08X\n", done[i].ticket, done[i].ran ? "returned" : "FAULTED", done[i].err);
                Out(o, "pending=%zu\n", troc::Pending());
            }
            else if (!std::strcmp(tok[0], "charmgr"))
            {
                const uintptr_t g = Player::GetCharMgrGlobal();
                Out(o, "charmgr global=%p mgr=%p\n", reinterpret_cast<void*>(g),
                    reinterpret_cast<void*>(g ? Deref(g, 0) : 0));
            }
            else if (!std::strcmp(tok[0], "troc") && n >= 3)
            {
                // troc <TrocTrName> <sender> [hex payload bytes]
                TrocHandler h{};
                if (!troc::Find(tok[1], &h)) { Out(o, "handler not found\n"); return; }
                Out(o, "handler obj=%p handle=%p id=%u\n", reinterpret_cast<void*>(h.obj),
                    reinterpret_cast<void*>(h.handle), h.msgId);
                uintptr_t sender = 0;
                if (!std::strcmp(tok[2], "@srv")) sender = Inventory::ServerCharacterAddr();
                else if (!std::strcmp(tok[2], "@cli")) sender = Inventory::ClientCharacterAddr();
                else if (!std::strcmp(tok[2], "@ctl")) sender = Player::GetControlledOwner();
                else sender = ParseAddr(tok[2]);
                uint8_t payload[0x200];
                size_t len = 0;
                for (int i = 3; i < n; ++i)
                    for (const char* c = tok[i]; c[0] && c[1] && len < sizeof(payload); c += 2)
                    {
                        char byte[3] = { c[0], c[1], 0 };
                        payload[len++] = static_cast<uint8_t>(std::strtoul(byte, nullptr, 16));
                    }
                uint32_t err = 0;
                const bool ok = troc::Send(h, sender, payload, static_cast<uint16_t>(len), &err);
                Out(o, "sender=%p len=%zu -> %s err=0x%08X\n", reinterpret_cast<void*>(sender), len,
                    ok ? "returned" : "FAULTED", err);
            }
            else if (!std::strcmp(tok[0], "call"))
            {
                CmdCall(o, tok, n);
            }
            else
            {
                Out(o, "unknown command\n");
            }
        }
    }

    void DevProbe::Tick()
    {
        const ULONGLONG now = GetTickCount64();
        if (now < g_nextPoll) return;
        g_nextPoll = now + 250;
        if (!InitPaths()) return;
        if (GetFileAttributesW(g_inPath.c_str()) == INVALID_FILE_ATTRIBUTES) return;

        // Claim the file first so an editor writing it cannot race the read.
        const std::wstring claimed = g_inPath + L".run";
        DeleteFileW(claimed.c_str());
        if (!MoveFileW(g_inPath.c_str(), claimed.c_str())) return;

        std::string input;
        if (FILE* f = _wfopen(claimed.c_str(), L"rb"))
        {
            char buf[4096];
            size_t r;
            while ((r = std::fread(buf, 1, sizeof(buf), f)) > 0) input.append(buf, r);
            std::fclose(f);
        }
        DeleteFileW(claimed.c_str());

        std::string out;
        size_t pos = 0;
        while (pos < input.size())
        {
            size_t end = input.find('\n', pos);
            if (end == std::string::npos) end = input.size();
            std::string line = input.substr(pos, end - pos);
            pos = end + 1;
            std::vector<char> mutableLine(line.begin(), line.end());
            mutableLine.push_back('\0');
            Execute(out, mutableLine.data());
        }
        char tid[64];
        snprintf(tid, sizeof(tid), "=== done (tid %lu)\n", GetCurrentThreadId());
        out += tid;

        if (FILE* f = _wfopen(g_outPath.c_str(), L"ab"))
        {
            std::fwrite(out.data(), 1, out.size(), f);
            std::fclose(f);
        }
    }
}
