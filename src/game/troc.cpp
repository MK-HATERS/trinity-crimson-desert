#include "troc.h"

#include <Windows.h>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <MinHook.h>

#include "inventory.h"
#include "../core/logger.h"
#include "../mem/safe_memory.h"
#include "../mem/scanner.h"

namespace trinity::game
{
    namespace
    {
        struct Section
        {
            uintptr_t begin = 0;
            uintptr_t end = 0;
            bool exec = false;
            bool write = false;
        };

        int ImageSections(Section* out, int cap)
        {
            const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            const IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
            int n = 0;
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections && n < cap; ++i, ++s)
            {
                // Section names are scrambled in this binary; only flags are trustworthy.
                const DWORD size = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
                out[n].begin = base + s->VirtualAddress;
                out[n].end = out[n].begin + size;
                out[n].exec = (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                out[n].write = (s->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                ++n;
            }
            return n;
        }

        bool Readable(uintptr_t p, size_t len)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<void*>(p), &mbi, sizeof(mbi))) return false;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) return false;
            return p + len <= reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }

        // Scans [begin,end) page-region by page-region, skipping uncommitted
        // ranges (the Denuvo section is only partly mapped).
        template <class F>
        uintptr_t ScanRegions(uintptr_t begin, uintptr_t end, F&& match)
        {
            uintptr_t p = begin;
            while (p < end)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<void*>(p), &mbi, sizeof(mbi))) break;
                const uintptr_t rEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                const uintptr_t stop = rEnd < end ? rEnd : end;
                if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
                {
                    if (const uintptr_t hit = match(p, stop)) return hit;
                }
                p = rEnd;
            }
            return 0;
        }

        uintptr_t FindBytes(const Section* secs, int n, bool wantExec, const void* needle, size_t len)
        {
            for (int i = 0; i < n; ++i)
            {
                if (secs[i].exec != wantExec) continue;
                const uintptr_t hit = ScanRegions(secs[i].begin, secs[i].end, [&](uintptr_t a, uintptr_t b) -> uintptr_t {
                    for (uintptr_t q = a; q + len <= b; ++q)
                        if (*reinterpret_cast<const uint8_t*>(q) == *static_cast<const uint8_t*>(needle) &&
                            std::memcmp(reinterpret_cast<const void*>(q), needle, len) == 0)
                            return q;
                    return 0;
                });
                if (hit) return hit;
            }
            return 0;
        }

        template <class T>
        uintptr_t FindAligned(const Section* secs, int n, bool writable, T value, uintptr_t (*accept)(uintptr_t, T))
        {
            for (int i = 0; i < n; ++i)
            {
                if (secs[i].exec || (writable && !secs[i].write)) continue;
                const uintptr_t hit = ScanRegions(secs[i].begin, secs[i].end, [&](uintptr_t a, uintptr_t b) -> uintptr_t {
                    for (uintptr_t q = (a + alignof(T) - 1) & ~(uintptr_t)(alignof(T) - 1); q + sizeof(T) <= b; q += alignof(T))
                        if (*reinterpret_cast<const T*>(q) == value)
                            if (const uintptr_t r = accept(q, value)) return r;
                    return 0;
                });
                if (hit) return hit;
            }
            return 0;
        }

        uintptr_t ResolveHandler(const char* name, TrocHandler* out)
        {
            Section secs[32];
            const int n = ImageSections(secs, 32);
            const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

            const std::string mangled = std::string(".?AV") + name + "@pa@@";
            const uintptr_t str = FindBytes(secs, n, false, mangled.c_str(), mangled.size() + 1);
            if (!str) return 0;
            const uint32_t tdRva = static_cast<uint32_t>(str - 0x10 - base);

            // COL: signature 1, +0x0C type-descriptor rva, +0x14 self rva.
            static uintptr_t s_base;
            s_base = base;
            const uintptr_t col = FindAligned<uint32_t>(secs, n, false, tdRva, [](uintptr_t q, uint32_t) -> uintptr_t {
                const uintptr_t c = q - 0x0C;
                if (*reinterpret_cast<const uint32_t*>(c) != 1) return 0;
                if (*reinterpret_cast<const uint32_t*>(c + 0x14) != static_cast<uint32_t>(c - s_base)) return 0;
                return c;
            });
            if (!col) return 0;

            const uintptr_t colRef = FindAligned<uint64_t>(secs, n, false, col, [](uintptr_t q, uint64_t) -> uintptr_t { return q; });
            if (!colRef) return 0;
            const uintptr_t vtable = colRef + 8;

            // The handler object is a static: its first qword is the vtable.
            const uintptr_t obj = FindAligned<uint64_t>(secs, n, true, vtable, [](uintptr_t q, uint64_t) -> uintptr_t { return q; });
            if (!obj) return 0;

            uintptr_t handle = 0;
            uint16_t id = 0;
            if (!mem::ReadPtr(vtable + 2 * sizeof(uintptr_t), &handle) || !mem::Read16(obj + 0x0C, &id))
                return 0;
            out->obj = obj;
            out->handle = handle;
            out->msgId = id;
            return obj;
        }

        std::mutex g_cacheLock;
        std::unordered_map<std::string, TrocHandler> g_cache;

        using HandleFn = uint32_t*(__fastcall*)(uintptr_t obj, uint32_t* err, void* packet);

        bool GuardedHandle(uintptr_t fn, uintptr_t obj, uint32_t* err, void* packet)
        {
            __try
            {
                reinterpret_cast<HandleFn>(fn)(obj, err, packet);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }
    }

    bool troc::Find(const char* name, TrocHandler* out)
    {
        {
            std::lock_guard<std::mutex> lock(g_cacheLock);
            const auto it = g_cache.find(name);
            if (it != g_cache.end()) { *out = it->second; return out->obj != 0; }
        }
        TrocHandler h{};
        ResolveHandler(name, &h);
        if (h.obj)
            LOG_OK("troc: %s handler=%p handle=%p id=%u", name, reinterpret_cast<void*>(h.obj),
                   reinterpret_cast<void*>(h.handle), h.msgId);
        else
            LOG_WARN("troc: %s handler not found", name);
        std::lock_guard<std::mutex> lock(g_cacheLock);
        g_cache[name] = h;
        *out = h;
        return h.obj != 0;
    }

    bool troc::Send(const TrocHandler& h, uintptr_t sender, const void* payload,
                    uint16_t payloadLen, uint32_t* outErr)
    {
        if (!h.obj || !h.handle || !sender || payloadLen > 0x7F00) return false;

        uint8_t bytes[5 + 0x200] = {};
        if (payloadLen > sizeof(bytes) - 5) return false;
        std::memcpy(bytes, &h.msgId, 2);
        std::memcpy(bytes + 3, &payloadLen, 2);
        if (payloadLen) std::memcpy(bytes + 5, payload, payloadLen);

        alignas(16) uint8_t packet[0x60] = {};
        const uint16_t total = static_cast<uint16_t>(5 + payloadLen);
        std::memcpy(packet + 0x00, &sender, 8);
        std::memcpy(packet + 0x10, &total, 2);
        const uintptr_t bytesPtr = reinterpret_cast<uintptr_t>(bytes);
        std::memcpy(packet + 0x18, &bytesPtr, 8);

        uint8_t previous = 0;
        const uintptr_t realm = Inventory::RealmFlagAddress(&previous);
        if (realm) mem::Write8(realm, 1);
        uint32_t err = 0xFFFFFFFFu;
        const bool ok = GuardedHandle(h.handle, h.obj, &err, packet);
        if (realm) mem::Write8(realm, previous);
        if (outErr) *outErr = err;
        return ok;
    }

    namespace
    {
        struct Posted
        {
            uint32_t ticket = 0;
            TrocHandler handler{};
            std::vector<uint8_t> payload;
            bool mainLoop = false;   // run on the main dispatch loop (PostMain)
            uintptr_t sender = 0;    // packet +0x00 override (0 = template's)
        };

        std::mutex              g_postLock;
        std::vector<Posted>     g_posted;
        std::vector<std::function<void()>> g_tasks;   // PostMainTask, guarded by g_postLock
        std::vector<troc::Completion> g_done;
        uint32_t                g_nextTicket = 1;
        HandleFn                g_moveActorOriginal = nullptr;

        // Server -> client reply sender. Handlers report a refusal by sending the
        // generic error reply (type 0x3F5) whose body is [u8 ?][u32 code at +3]
        // [u16 request id at +7]; the handler's own result stays 0. While posted
        // requests run, the hook records that code so a refusal is visible.
        constexpr const char* kSig_ServerReplyCall =
            "48 8B 0D ?? ?? ?? ?? 4C 8D 44 24 ?? 48 89 44 24 30 41 B9 11 00 00 00 8B D6 C6 44 24 20 00 E8";
        using ReplyFn = uint64_t(__fastcall*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        ReplyFn                 g_replyOriginal = nullptr;
        thread_local uint32_t   t_lastRefusal = 0;
        thread_local bool       t_inPump = false;

        // Every refusal path looks its error code up in the engine's error table
        // (most of them only send a reply when that entry says so), so this is
        // where a silent refusal becomes visible.
        constexpr const char* kSig_ErrorLookupCall =
            "E8 ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8B C8 E8";
        using ErrorLookupFn = void*(__fastcall*)(void* table, const uint32_t* code);
        ErrorLookupFn           g_errorLookupOriginal = nullptr;

        void* __fastcall hkErrorLookup(void* table, const uint32_t* code)
        {
            if (t_inPump && !t_lastRefusal && code)
            {
                uint32_t v = 0;
                if (mem::Read32(reinterpret_cast<uintptr_t>(code), &v) && v) t_lastRefusal = v;
            }
            return g_errorLookupOriginal(table, code);
        }
        uintptr_t               g_moveActorTarget = 0;
        bool                    g_pumpReady = false;

        // Main dispatch loop (PE 2976: loop 0x1427731C0 calls the dispatcher
        // 0x142774730 for each request, on the thread spawning works from).
        constexpr const char* kSig_MainDispatchCall =
            "4C 8D 8C 24 90 00 00 00 48 8B 5C 24 38 48 8B D3 E8";   // unique; stops before
        // 0x14277331E, which DesertLink Mod Menu patches with its own completion hook.
        constexpr size_t kOff_MainDispatchCall = 16;
        using DispatchFn = uint64_t(__fastcall*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        DispatchFn              g_dispatchOriginal = nullptr;
        bool                    g_mainReady = false;
        alignas(16) uint8_t     g_lastTemplate[0x60] = {};
        bool                    g_haveTemplate = false;   // guarded by g_postLock

        bool RunWithTemplate(const Posted& req, const uint8_t* templ, uint32_t* err)
        {
            uint8_t bytes[5 + 0x200] = {};
            const uint16_t len = static_cast<uint16_t>(req.payload.size());
            std::memcpy(bytes, &req.handler.msgId, 2);
            // byte 2 (channel) is not read by server handlers; leave it 0.
            std::memcpy(bytes + 3, &len, 2);
            if (len) std::memcpy(bytes + 5, req.payload.data(), len);

            alignas(16) uint8_t packet[0x60] = {};
            std::memcpy(packet, templ, sizeof(packet));   // same sender / connection context
            if (req.sender) std::memcpy(packet, &req.sender, 8);
            const uint16_t total = static_cast<uint16_t>(5 + len);
            std::memcpy(packet + 0x10, &total, 2);
            const uintptr_t bytesPtr = reinterpret_cast<uintptr_t>(bytes);
            std::memcpy(packet + 0x18, &bytesPtr, 8);
            *err = 0xFFFFFFFFu;
            return GuardedHandle(req.handler.handle, req.handler.obj, err, packet);
        }

        bool CopyTemplate(void* packet, uint8_t* out)
        {
            __try { std::memcpy(out, packet, 0x60); return true; }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }

        uint64_t __fastcall hkServerReply(uint64_t a1, uint64_t type, uint64_t body, uint64_t a4,
                                          uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8)
        {
            if (t_inPump && static_cast<uint16_t>(type) == 0x3F5 && body)
            {
                uint32_t code = 0;
                if (mem::Read32(body + 3, &code) && code) t_lastRefusal = code;
            }
            return g_replyOriginal(a1, type, body, a4, a5, a6, a7, a8);
        }

        uint32_t* __fastcall hkMoveActorHandle(uintptr_t obj, uint32_t* err, void* packet)
        {
            uint32_t* r = g_moveActorOriginal(obj, err, packet);
            if (t_inPump) return r;

            std::vector<Posted> work;
            {
                std::lock_guard<std::mutex> lock(g_postLock);
                if (g_posted.empty()) return r;
                std::vector<Posted> keep;
                for (Posted& p : g_posted) (p.mainLoop ? keep : work).push_back(std::move(p));
                g_posted.swap(keep);
            }
            uint8_t templ[0x60];
            if (!CopyTemplate(packet, templ)) return r;
            {
                std::lock_guard<std::mutex> lock(g_postLock);
                std::memcpy(g_lastTemplate, templ, sizeof(templ));
                g_haveTemplate = true;
            }

            t_inPump = true;
            std::vector<troc::Completion> results;
            for (const Posted& req : work)
            {
                troc::Completion c{};
                c.ticket = req.ticket;
                t_lastRefusal = 0;
                c.ran = RunWithTemplate(req, templ, &c.err);
                if (c.ran && c.err == 0 && t_lastRefusal) c.err = t_lastRefusal; // refusal sent as a reply
                LOG("troc: ran posted #%u (id %u, %zu bytes) -> %s err=0x%08X", req.ticket, req.handler.msgId,
                    req.payload.size(), c.ran ? "returned" : "FAULTED", c.err);
                results.push_back(c);
            }
            t_inPump = false;

            std::lock_guard<std::mutex> lock(g_postLock);
            g_done.insert(g_done.end(), results.begin(), results.end());
            if (g_done.size() > 64) g_done.erase(g_done.begin(), g_done.end() - 64);
            return r;
        }
    }

    namespace
    {
        uint64_t __fastcall hkMainDispatch(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                                           uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8)
        {
            const uint64_t r = g_dispatchOriginal(a1, a2, a3, a4, a5, a6, a7, a8);
            if (t_inPump) return r;

            std::vector<Posted> work;
            std::vector<std::function<void()>> tasks;
            alignas(16) uint8_t templ[0x60];
            {
                std::lock_guard<std::mutex> lock(g_postLock);
                tasks.swap(g_tasks);
                if (!g_posted.empty() && g_haveTemplate)
                {
                    std::vector<Posted> keep;
                    for (Posted& p : g_posted) (p.mainLoop ? work : keep).push_back(std::move(p));
                    g_posted.swap(keep);
                    std::memcpy(templ, g_lastTemplate, sizeof(templ));
                }
                if (work.empty() && tasks.empty()) return r;
            }

            t_inPump = true;
            for (auto& task : tasks) task();
            std::vector<troc::Completion> results;
            for (const Posted& req : work)
            {
                troc::Completion c{};
                c.ticket = req.ticket;
                t_lastRefusal = 0;
                c.ran = RunWithTemplate(req, templ, &c.err);
                if (c.ran && c.err == 0 && t_lastRefusal) c.err = t_lastRefusal;
                LOG("troc: ran main-loop #%u (id %u, %zu bytes) -> %s err=0x%08X", req.ticket, req.handler.msgId,
                    req.payload.size(), c.ran ? "returned" : "FAULTED", c.err);
                results.push_back(c);
            }
            t_inPump = false;

            std::lock_guard<std::mutex> lock(g_postLock);
            g_done.insert(g_done.end(), results.begin(), results.end());
            if (g_done.size() > 64) g_done.erase(g_done.begin(), g_done.end() - 64);
            return r;
        }
    }

    bool troc::InstallServerPump()
    {
        TrocHandler h{};
        if (!Find("TrocTrMoveActorReq", &h) || !h.handle) return false;
        g_moveActorTarget = h.handle;
        if (MH_CreateHook(reinterpret_cast<void*>(h.handle), reinterpret_cast<void*>(&hkMoveActorHandle),
                          reinterpret_cast<void**>(&g_moveActorOriginal)) != MH_OK ||
            MH_EnableHook(reinterpret_cast<void*>(h.handle)) != MH_OK)
        {
            LOG_WARN("troc: server pump hook failed @ %p", reinterpret_cast<void*>(h.handle));
            return false;
        }
        if (const uintptr_t site = mem::FindPattern(kSig_ServerReplyCall))
        {
            void* reply = reinterpret_cast<void*>(mem::ResolveCall(site + 30));
            if (MH_CreateHook(reply, reinterpret_cast<void*>(&hkServerReply), reinterpret_cast<void**>(&g_replyOriginal)) == MH_OK &&
                MH_EnableHook(reply) == MH_OK)
                LOG_OK("troc: server reply hook @ %p", reply);
        }
        if (const uintptr_t site = mem::FindPattern(kSig_ErrorLookupCall))
        {
            void* lookup = reinterpret_cast<void*>(mem::ResolveCall(site + 21));
            if (MH_CreateHook(lookup, reinterpret_cast<void*>(&hkErrorLookup), reinterpret_cast<void**>(&g_errorLookupOriginal)) == MH_OK &&
                MH_EnableHook(lookup) == MH_OK)
                LOG_OK("troc: error lookup hook @ %p", lookup);
        }
        if (const uintptr_t site = mem::FindPattern(kSig_MainDispatchCall))
        {
            void* dispatch = reinterpret_cast<void*>(mem::ResolveCall(site + kOff_MainDispatchCall));
            if (MH_CreateHook(dispatch, reinterpret_cast<void*>(&hkMainDispatch), reinterpret_cast<void**>(&g_dispatchOriginal)) == MH_OK &&
                MH_EnableHook(dispatch) == MH_OK)
            {
                g_mainReady = true;
                LOG_OK("troc: main-loop pump on dispatcher @ %p", dispatch);
            }
        }
        if (!g_mainReady) LOG_WARN("troc: main-loop dispatcher not found - spawning unavailable");
        g_pumpReady = true;
        LOG_OK("troc: server pump installed on TrocTrMoveActorReq @ %p", reinterpret_cast<void*>(h.handle));
        return true;
    }

    bool troc::ServerPumpReady() { return g_pumpReady; }

    uint32_t troc::Post(const char* name, const void* payload, uint16_t payloadLen)
    {
        TrocHandler h{};
        if (!g_pumpReady || payloadLen > 0x200 || !Find(name, &h)) return 0;
        Posted p;
        p.handler = h;
        p.payload.assign(static_cast<const uint8_t*>(payload), static_cast<const uint8_t*>(payload) + payloadLen);
        std::lock_guard<std::mutex> lock(g_postLock);
        p.ticket = g_nextTicket++;
        g_posted.push_back(std::move(p));
        return g_posted.back().ticket;
    }

    uint32_t troc::PostMain(const char* name, const void* payload, uint16_t payloadLen)
    {
        return PostMainAs(name, payload, payloadLen, 0);
    }

    uint32_t troc::PostMainAs(const char* name, const void* payload, uint16_t payloadLen, uintptr_t sender)
    {
        TrocHandler h{};
        if (!g_mainReady || payloadLen > 0x200 || !Find(name, &h)) return 0;
        Posted p;
        p.handler = h;
        p.mainLoop = true;
        p.sender = sender;
        p.payload.assign(static_cast<const uint8_t*>(payload), static_cast<const uint8_t*>(payload) + payloadLen);
        std::lock_guard<std::mutex> lock(g_postLock);
        p.ticket = g_nextTicket++;
        g_posted.push_back(std::move(p));
        return g_posted.back().ticket;
    }

    bool troc::PostMainTask(std::function<void()> fn)
    {
        if (!g_mainReady || !fn) return false;
        std::lock_guard<std::mutex> lock(g_postLock);
        g_tasks.push_back(std::move(fn));
        return true;
    }

    void troc::TakeCompletions(Completion* out, size_t cap, size_t* count)
    {
        std::lock_guard<std::mutex> lock(g_postLock);
        const size_t n = g_done.size() < cap ? g_done.size() : cap;
        for (size_t i = 0; i < n; ++i) out[i] = g_done[i];
        g_done.erase(g_done.begin(), g_done.begin() + n);
        *count = n;
    }

    size_t troc::Pending()
    {
        std::lock_guard<std::mutex> lock(g_postLock);
        return g_posted.size();
    }
}
