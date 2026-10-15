#include "scanner.h"

#include <vector>

#include "../core/logger.h"

namespace trinity::mem
{
    const ModuleRegion& GameModule()
    {
        static const ModuleRegion region = []
        {
            ModuleRegion r{};
            const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
            if (!base)
                return r;

            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return r;

            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return r;

            r.base = base;
            r.size = nt->OptionalHeader.SizeOfImage;
            return r;
        }();
        return region;
    }

    namespace
    {
        struct ParsedPattern
        {
            std::vector<uint8_t> bytes; // value at each position (0 where wildcard)
            std::vector<bool>    mask;  // true = must match, false = wildcard
        };

        int HexNibble(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        ParsedPattern Parse(std::string_view p)
        {
            ParsedPattern out;
            for (size_t i = 0; i < p.size();)
            {
                const char c = p[i];
                if (c == ' ' || c == '\t') { ++i; continue; }
                if (c == '?')
                {
                    out.bytes.push_back(0);
                    out.mask.push_back(false);
                    ++i;
                    if (i < p.size() && p[i] == '?') ++i;
                    continue;
                }
                const int hi = HexNibble(c);
                if (hi < 0) { ++i; continue; }
                int lo = hi;
                if (i + 1 < p.size() && HexNibble(p[i + 1]) >= 0) { lo = HexNibble(p[i + 1]); i += 2; }
                else                                              { i += 1; }
                out.bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
                out.mask.push_back(true);
            }
            return out;
        }

        bool IsReadable(DWORD protect)
        {
            if (protect & PAGE_GUARD) return false;
            if (protect == PAGE_NOACCESS || protect == PAGE_EXECUTE) return false;
            const DWORD readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                   PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
            return (protect & readable) != 0;
        }

        // Merged, contiguous, committed+readable spans within the module image.
        // Uses VirtualQuery to accurately scan live committed memory pages (MEM_COMMIT)
        // while bypassing uncommitted gaps and guarded pages, with PE header fallback.
        std::vector<std::pair<uintptr_t, uintptr_t>> ReadableSpans(const ModuleRegion& mod)
        {
            std::vector<std::pair<uintptr_t, uintptr_t>> spans;
            const auto base = mod.base;
            const auto size = mod.size;
            if (!base || !size) return spans;

            uintptr_t curr = base;
            const uintptr_t end = base + size;

            while (curr < end)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(curr), &mbi, sizeof(mbi)))
                    break;

                const uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                const uintptr_t regionEnd   = regionStart + mbi.RegionSize;

                if ((mbi.State == MEM_COMMIT) && IsReadable(mbi.Protect))
                {
                    const uintptr_t spanBegin = (regionStart > base) ? regionStart : base;
                    const uintptr_t spanEnd   = (regionEnd < end) ? regionEnd : end;
                    if (spanBegin < spanEnd)
                    {
                        if (!spans.empty() && spans.back().second == spanBegin)
                            spans.back().second = spanEnd;
                        else
                            spans.emplace_back(spanBegin, spanEnd);
                    }
                }

                if (regionEnd <= curr)
                    break;
                curr = regionEnd;
            }

            // Fallback: If VirtualQuery produced no spans, query PE section headers directly
            if (spans.empty())
            {
                const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
                if (dos->e_magic == IMAGE_DOS_SIGNATURE)
                {
                    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
                    if (nt->Signature == IMAGE_NT_SIGNATURE)
                    {
                        auto* sec = IMAGE_FIRST_SECTION(nt);
                        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
                        {
                            if (!(sec->Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE)))
                                continue;

                            const uintptr_t begin = base + sec->VirtualAddress;
                            const uintptr_t vsz   = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
                            const uintptr_t regEnd = begin + vsz;
                            if (!spans.empty() && spans.back().second == begin)
                                spans.back().second = regEnd;
                            else
                                spans.emplace_back(begin, regEnd);
                        }
                    }
                }
            }

            return spans;
        }

        // Scan [begin,end) for the pattern, appending up to maxResults hits.
        void ScanSpan(uintptr_t begin, uintptr_t end, const ParsedPattern& pat,
                      size_t firstFixed, uint8_t anchor, bool haveAnchor,
                      std::vector<uintptr_t>& out, size_t maxResults)
        {
            const size_t patLen = pat.bytes.size();
            if (end < begin || (end - begin) < patLen) return;

            const auto* const start = reinterpret_cast<const uint8_t*>(begin);
            const uint8_t* const last = reinterpret_cast<const uint8_t*>(end - patLen);

            for (const uint8_t* p = start; p <= last; ++p)
            {
                if (haveAnchor && p[firstFixed] != anchor)
                    continue;
                bool hit = true;
                for (size_t i = 0; i < patLen; ++i)
                {
                    if (pat.mask[i] && p[i] != pat.bytes[i]) { hit = false; break; }
                }
                if (hit)
                {
                    out.push_back(reinterpret_cast<uintptr_t>(p));
                    if (out.size() >= maxResults) return;
                }
            }
        }

        std::vector<uintptr_t> Scan(std::string_view pattern, const ModuleRegion& mod, size_t maxResults)
        {
            std::vector<uintptr_t> results;
            if (!mod) return results;

            const ParsedPattern pat = Parse(pattern);
            const size_t patLen = pat.bytes.size();
            if (patLen == 0) return results;

            size_t firstFixed = 0;
            while (firstFixed < patLen && !pat.mask[firstFixed]) ++firstFixed;
            const bool    haveAnchor = firstFixed < patLen;
            const uint8_t anchor     = haveAnchor ? pat.bytes[firstFixed] : 0;

            for (const auto& [begin, end] : ReadableSpans(mod))
            {
                ScanSpan(begin, end, pat, firstFixed, anchor, haveAnchor, results, maxResults);
                if (results.size() >= maxResults) break;
            }
            return results;
        }
    }

    uintptr_t FindPattern(std::string_view pattern, const ModuleRegion& mod)
    {
        const auto hits = Scan(pattern, mod, 1);
        return hits.empty() ? 0 : hits.front();
    }

    std::vector<uintptr_t> FindAllMatches(std::string_view pattern, const ModuleRegion& mod, size_t maxCount)
    {
        return Scan(pattern, mod, maxCount);
    }

    uintptr_t FindPatternIf(std::string_view pattern, const ModuleRegion& mod,
                            bool (*visit)(uintptr_t match, void* ctx), void* ctx)
    {
        if (!mod || !visit) return 0;

        const ParsedPattern pat = Parse(pattern);
        const size_t patLen = pat.bytes.size();
        if (patLen == 0) return 0;

        size_t firstFixed = 0;
        while (firstFixed < patLen && !pat.mask[firstFixed]) ++firstFixed;
        const bool    haveAnchor = firstFixed < patLen;
        const uint8_t anchor     = haveAnchor ? pat.bytes[firstFixed] : 0;

        for (const auto& [begin, end] : ReadableSpans(mod))
        {
            if (end < begin || (end - begin) < patLen) continue;
            const auto* const start = reinterpret_cast<const uint8_t*>(begin);
            const uint8_t* const last = reinterpret_cast<const uint8_t*>(end - patLen);
            for (const uint8_t* p = start; p <= last; ++p)
            {
                if (haveAnchor && p[firstFixed] != anchor)
                    continue;
                bool hit = true;
                for (size_t i = 0; i < patLen; ++i)
                {
                    if (pat.mask[i] && p[i] != pat.bytes[i]) { hit = false; break; }
                }
                if (hit && visit(reinterpret_cast<uintptr_t>(p), ctx))
                    return reinterpret_cast<uintptr_t>(p);
            }
        }
        return 0;
    }

    size_t CountMatches(std::string_view pattern, const ModuleRegion& mod, size_t maxCount)
    {
        return Scan(pattern, mod, maxCount).size();
    }

    namespace
    {
        // Scans [data, data+len) for up to 2 hits. Kept free of C++ objects
        // so the mapped-file reads can sit under SEH (a disk read error on a
        // mapped view raises EXCEPTION_IN_PAGE_ERROR).
        int ScanRaw(const uint8_t* data, size_t len, const uint8_t* bytes, const bool* mask,
                    size_t patLen, size_t* hits)
        {
            int count = 0;
            __try
            {
                if (len < patLen) return 0;
                for (size_t off = 0; off + patLen <= len; ++off)
                {
                    size_t i = 0;
                    while (i < patLen && (!mask[i] || data[off + i] == bytes[i])) ++i;
                    if (i == patLen)
                    {
                        hits[count++] = off;
                        if (count == 2) break;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return -1;
            }
            return count;
        }

        // Unique RVA of `pattern` in the on-disk image of the running exe, or 0.
        uint32_t FindRvaOnDisk(std::string_view pattern, const ModuleRegion& mod)
        {
            wchar_t path[MAX_PATH];
            if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return 0;

            HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) return 0;
            HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
            CloseHandle(file);
            if (!mapping) return 0;
            const auto* view = static_cast<const uint8_t*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
            CloseHandle(mapping);
            if (!view) return 0;

            const ParsedPattern pat = Parse(pattern);
            std::vector<uint8_t> maskBytes(pat.mask.begin(), pat.mask.end());
            uint32_t found = 0;
            int total = 0;

            const auto* liveNt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                mod.base + reinterpret_cast<const IMAGE_DOS_HEADER*>(mod.base)->e_lfanew);
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(view);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(view + dos->e_lfanew);
            // Same build as the running image, or the RVAs mean nothing.
            if (dos->e_magic == IMAGE_DOS_SIGNATURE && nt->Signature == IMAGE_NT_SIGNATURE &&
                nt->FileHeader.TimeDateStamp == liveNt->FileHeader.TimeDateStamp &&
                nt->OptionalHeader.SizeOfImage == liveNt->OptionalHeader.SizeOfImage && !pat.bytes.empty())
            {
                const auto* sec = IMAGE_FIRST_SECTION(nt);
                for (WORD s = 0; s < nt->FileHeader.NumberOfSections && total < 2; ++s, ++sec)
                {
                    if (!sec->PointerToRawData || !sec->SizeOfRawData) continue;
                    size_t len = sec->SizeOfRawData;
                    if (sec->Misc.VirtualSize && sec->Misc.VirtualSize < len) len = sec->Misc.VirtualSize;
                    size_t hits[2] = {};
                    const int n = ScanRaw(view + sec->PointerToRawData, len, pat.bytes.data(),
                                          reinterpret_cast<const bool*>(maskBytes.data()), pat.bytes.size(), hits);
                    if (n < 0) { total = 0; break; }
                    for (int h = 0; h < n && total < 2; ++h, ++total)
                        found = sec->VirtualAddress + static_cast<uint32_t>(hits[h]);
                }
            }
            UnmapViewOfFile(view);
            return (total == 1 && found < mod.size) ? found : 0;
        }

        // Destination of a detour jump at `addr` (jmp rel32, jmp [rip+0] / qword,
        // mov rax,imm64; jmp rax), or 0.
        uintptr_t DetourDestination(uintptr_t addr)
        {
            const auto* b = reinterpret_cast<const uint8_t*>(addr);
            if (b[0] == 0xE9)
                return addr + 5 + *reinterpret_cast<const int32_t*>(b + 1);
            if (b[0] == 0xFF && b[1] == 0x25)
                return *reinterpret_cast<const uintptr_t*>(addr + 6 + *reinterpret_cast<const int32_t*>(b + 2));
            if (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0)
                return *reinterpret_cast<const uintptr_t*>(b + 2);
            return 0;
        }

        uintptr_t SafeDetourDestination(uintptr_t addr)
        {
            __try { return DetourDestination(addr); }
            __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
        }
    }

    uintptr_t FindPatternOrHooked(std::string_view pattern, const char* context)
    {
        if (const uintptr_t live = FindPattern(pattern))
            return live;

        const ModuleRegion& mod = GameModule();
        if (!mod) return 0;
        const uint32_t rva = FindRvaOnDisk(pattern, mod);
        if (!rva) return 0;
        const uintptr_t addr = mod.base + rva;

        // Follow up to a few chained jumps to name the mod that hooked it
        // (MinHook-style detours land in a relay page first, then the mod).
        char owner[MAX_PATH] = "unknown module";
        uintptr_t dest = addr;
        for (int hop = 0; hop < 4; ++hop)
        {
            dest = SafeDetourDestination(dest);
            if (!dest) break;
            HMODULE m = nullptr;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   reinterpret_cast<LPCSTR>(dest), &m) && m)
            {
                char p[MAX_PATH];
                if (GetModuleFileNameA(m, p, MAX_PATH))
                {
                    const char* name = strrchr(p, '\\');
                    lstrcpynA(owner, name ? name + 1 : p, MAX_PATH);
                }
                break;
            }
        }

        LOG_WARN("%s: live bytes were patched (hooked by %s); resolved from the on-disk exe @ %p - chaining.",
                 context, owner, reinterpret_cast<void*>(addr));
        return addr;
    }

    void LogModuleLayout()
    {
        const ModuleRegion& mod = GameModule();
        if (!mod)
        {
            LOG_ERR("scanner: game module not resolved.");
            return;
        }

        size_t spanCount = 0, execBytes = 0, readBytes = 0;
        const uintptr_t end = mod.base + mod.size;
        uintptr_t addr = mod.base;
        MEMORY_BASIC_INFORMATION mbi{};
        while (addr < end && VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi))
        {
            if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
            {
                ++spanCount;
                size_t rs = mbi.RegionSize;
                readBytes += rs;
                if (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                    execBytes += rs;
            }
            addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (mbi.RegionSize == 0) break;
        }
        LOG("scanner: module base=0x%p size=0x%zX readable-regions=%zu readable=0x%zX exec=0x%zX",
            reinterpret_cast<void*>(mod.base), mod.size, spanCount, readBytes, execBytes);
    }
}
