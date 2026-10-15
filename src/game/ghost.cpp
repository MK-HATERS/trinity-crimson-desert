#include "ghost.h"

#include <Windows.h>
#include <atomic>
#include <cstring>
#include <iterator>
#include <MinHook.h>

#include "inventory.h"
#include "player.h"
#include "../core/logger.h"
#include "../core/state.h"
#include "../mem/safe_memory.h"
#include "../mem/scanner.h"

namespace trinity::game
{
    namespace
    {
        // Actor layout (PE 2976): +0x60 u32 handle, +0x68 component block,
        // +0x88 -> {?, u8 kind} (1 = player body; NPC kinds 3,4,5,6,8,9),
        // +0x94 u8 player-controlled, +0x96 u8 server player, +0xA0 user actor.
        constexpr uintptr_t kOff_Actor_Handle     = 0x60;
        constexpr uintptr_t kOff_Actor_Sub        = 0x68;
        constexpr uintptr_t kOff_Actor_KindInfo   = 0x88;
        constexpr uintptr_t kOff_Actor_Controlled = 0x94;
        constexpr uintptr_t kOff_Actor_ServerSide = 0x96;
        constexpr uintptr_t kOff_Actor_User       = 0xA0;
        // Component block slots; every component keeps its actor at +0x08.
        constexpr uintptr_t kOff_Sub_Status = 0x20;
        constexpr uintptr_t kOff_Sub_Hide   = 0x40;
        constexpr uintptr_t kOff_Sub_Detect = 0x50;
        constexpr uintptr_t kOff_Sub_Target = 0x90;
        constexpr uintptr_t kOff_Comp_Owner = 0x08;
        // DetectActorComponent: two 0x38-byte slots from +0x38 (u32 handle first).
        constexpr uintptr_t kOff_Detect_Slots = 0x38;
        constexpr uintptr_t kSizeof_DetectSlot = 0x38;
        // TargetActorComponent: 4 engage lists {data, u32 n} at +0x98 step 0x10
        // (8-byte entries), hate lists at +0x120 / +0x130 (0x14-byte entries),
        // current target handle at +0x178.
        constexpr uintptr_t kOff_Target_Engage  = 0x98;
        constexpr uintptr_t kOff_Target_Hate0   = 0x120;
        constexpr uintptr_t kOff_Target_Hate1   = 0x130;
        constexpr uintptr_t kOff_Target_Current = 0x178;
        constexpr uint8_t   kRelation_Enemy = 0;   // {"Enemy","Neutral","Ally","Ignore","Exclusive"} @0x14597C8B0
        constexpr uint8_t   kRelation_Neutral = 1, kRelation_Ally = 2;

        // Hooked game functions (unique signatures, verified on PE 2976).
        constexpr const char* kSig_IsHiding       = "40 53 48 83 EC 20 48 8B D9 48 8B 09 48 8B 01 FF 90 D8 01 00 00";
        constexpr const char* kSig_BuildCandidate = "48 8B C4 48 89 58 20 89 50 10 48 89 48 08 55 56 57 41 54 41 55 41 56 41 57";
        constexpr const char* kSig_SenseTest      = "48 89 5C 24 08 48 89 6C 24 10 56 57 41 54 41 56 41 57 48 81 EC 80 00 00 00 C5 F8 29 74 24 70";
        constexpr const char* kSig_CanTarget      = "48 89 5C 24 10 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 20 45 0F B6 F9";
        constexpr const char* kSig_SetSlot        = "48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 20 4C 89 44 24 18 55 41 54 41 55 41 56 41 57 48 8D 6C 24 D9";
        constexpr const char* kSig_SetCurTarget   = "48 8B C4 4C 89 48 20 44 89 40 18 48 89 50 10 55 53 56 57 41 54";
        constexpr const char* kSig_AddHate        = "48 89 5C 24 10 44 88 44 24 18 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D9 48 81 EC A0 00 00 00 45 0F B6 E1";
        constexpr const char* kSig_DetectUpdate   = "4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 49 89 7B 20 41 54 41 56 41 57 48 83 EC 60 48 8B 01";
        constexpr const char* kSig_SetEngaged     = "48 89 5C 24 18 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 30 41 0F B7 F9";
        // ApplyDetect's entry is a jmp into Denuvo code: found through its caller.
        constexpr const char* kSig_ApplyDetectCall =
            "C6 44 24 38 01 48 8D 45 A8 48 89 44 24 30 44 89 64 24 28 C6 44 24 20 03 45 0F B6 CE 4C 8B C3 48 8B D6 48 8B CF E8";
        constexpr size_t      kOff_ApplyDetectCall = 0x25;
        // Helpers.
        constexpr const char* kSig_RelQuery =
            "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 41 54 41 55 41 56 41 57 48 8D 6C 24 C9 48 81 EC A0 00 00 00 45 0F B6 E8";
        constexpr const char* kSig_ClientLookup =
            "48 89 5C 24 08 48 89 54 24 10 55 56 57 41 56 41 57 48 83 EC 30 41 8B F8 48 8B F2 48 8B E9 45 33 FF 44 89 7C 24 20 45 85 C0 75 2A 48 8D 0D";
        constexpr const char* kSig_LeaseRelease =
            "48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20 48 8B F1 80 79 10 00 74 ?? 48 8B 79 08 80 79 11 00 75";
        constexpr const char* kSig_RemoveHate =
            "48 89 5C 24 10 44 88 44 24 18 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D9 48 81 EC 90 00 00 00 41 0F B6 C0";
        constexpr const char* kSig_RefreshSlots =
            "48 8B C4 48 89 48 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 68 A1 48 81 EC D8 00 00 00 C5 F8 29 70 A8 C5 F8 29 78 98 "
            "C5 78 29 40 88 C5 78 29 88 78 FF FF FF C5 78 29 90 68 FF FF FF C5 78 29 5C 24 70";
        // Manager globals: server = **g (ServerActorManager, lookup = vtable slot 5),
        // client = *(*g + 0x38) (ClientActorManager).
        constexpr const char* kSig_ServerMgrLoad = "48 8B 0D ?? ?? ?? ?? 48 8B 09 E8";
        constexpr const char* kSig_ClientMgrLoad = "48 8B 0D ?? ?? ?? ?? 48 8B 49 38";

        using Fn1 = uint64_t(__fastcall*)(uint64_t);
        using Fn4 = uint64_t(__fastcall*)(uint64_t, uint64_t, uint64_t, uint64_t);
        using Fn5 = uint64_t(__fastcall*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        using Fn7 = uint64_t(__fastcall*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        using Fn8 = uint64_t(__fastcall*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

        struct alignas(8) Lease
        {
            uintptr_t vt = 0;
            uintptr_t actor = 0;
            uint8_t   valid = 0;   // the lookup pinned the actor
            uint8_t   flag = 0;
            uint8_t   pad[6] = {};
            uintptr_t extra = 0;
        };
        using ServerLookupFn = void*(__fastcall*)(uintptr_t mgr, Lease* out, uint32_t handle);
        using ClientLookupFn = void*(__fastcall*)(uintptr_t mgr, Lease* out, uint32_t handle, uint32_t flags);
        using ReleaseFn      = void(__fastcall*)(Lease* lease);
        using RelQueryFn     = uint8_t(__fastcall*)(uintptr_t self, uintptr_t other, uint8_t flag);
        // The game returns the relation zero-extended in eax (movzx eax, dil).
        using RelQuery64     = uint64_t(__fastcall*)(uint64_t self, uint64_t other, uint64_t flag);
        using RemoveHateFn   = void(__fastcall*)(uintptr_t targetComp, const uint32_t* handle, uint8_t flag);
        using RefreshSlotsFn = void(__fastcall*)(uintptr_t detectComp);

        Fn1 oIsHiding = nullptr;
        Fn8 oBuildCandidate = nullptr, oSenseTest = nullptr, oApplyDetect = nullptr;
        Fn4 oCanTarget = nullptr, oSetSlot = nullptr, oAddHate = nullptr;
        Fn7 oSetCurTarget = nullptr;
        Fn5 oDetectUpdate = nullptr, oSetEngaged = nullptr;
        RelQuery64 oRelQuery = nullptr;

        RelQueryFn     g_relQuery = nullptr;   // the hooked entry: answers include allegiance
        ClientLookupFn g_clientLookup = nullptr;
        ReleaseFn      g_release = nullptr;
        RemoveHateFn   g_removeHate = nullptr;
        RefreshSlotsFn g_refreshSlots = nullptr;
        uintptr_t      g_serverMgrGlobal = 0, g_clientMgrGlobal = 0;

        std::atomic<bool>     g_enabled{ false };
        std::atomic<uint32_t> g_playerHandle{ 0 };     // last local player body seen by a pointer check
        std::atomic<uint32_t> g_controlledHandle{ 0 }; // controlled body, refreshed by Tick
        std::atomic<uintptr_t> g_clientUser{ 0 };      // the local ClientUserActor
        std::atomic<uint32_t> g_characterHandle{ 0 };  // the player character (the controlled body may be a mount)
        bool g_installed = false, g_failed = false;
        thread_local bool t_inPurge = false;

        // --- Spawn allegiance table ---------------------------------------------------
        // Written on the game thread only; read by RelQuery and the detours on any
        // thread. A handle is the same on the server body and its client twin.
        enum : uint8_t { kSideNone = 0, kSideAlly = 1, kSideEnemy = 2, kSideNeutral = 3 };
        struct AllyEntry
        {
            std::atomic<uint32_t>  handle{ 0 };
            std::atomic<uint8_t>   side{ kSideNone };
            std::atomic<uint8_t>   logged{ 0 };       // bit 0: its view of the player logged, bit 1: the player's view
            std::atomic<ULONGLONG> purgeUntil{ 0 };   // Neutral: old aggro on the player is dropped until then
        };
        constexpr size_t      kAllyCap = 64;
        constexpr ULONGLONG   kNeutralPurgeMs = 3000;
        AllyEntry             g_ally[kAllyCap];
        std::atomic<uint64_t> g_allyFilter[64];       // bit (handle & 0xFFF) set: the handle may be in the table
        std::atomic<uint32_t> g_allyCount{ 0 };
        std::atomic<bool>     g_allyWanted{ false };  // a side was requested: install the hooks

        AllyEntry* FindAlly(uint32_t h)
        {
            if (!h || !(g_allyFilter[(h >> 6) & 63].load(std::memory_order_relaxed) & (1ull << (h & 63))))
                return nullptr;
            for (AllyEntry& e : g_ally)
                if (e.handle.load(std::memory_order_acquire) == h) return &e;
            return nullptr;
        }

        uint8_t SideOf(const AllyEntry* e) { return e ? e->side.load(std::memory_order_relaxed) : kSideNone; }

        // The detours treat the player as invisible to this body: an Ally always,
        // a Neutral for a moment after it gets its side (old aggro is dropped).
        bool AllegianceSuppresses(uint32_t h)
        {
            const AllyEntry* e = FindAlly(h);
            const uint8_t side = SideOf(e);
            return side == kSideAlly ||
                   (side == kSideNeutral && GetTickCount64() < e->purgeUntil.load(std::memory_order_relaxed));
        }

        // Ghost Mode on, or at least one body with a side: the detours do work.
        bool Active()
        {
            return g_enabled.load(std::memory_order_relaxed) || g_allyCount.load(std::memory_order_relaxed);
        }

        // --- Guarded reads + RTTI ------------------------------------------------
        uintptr_t Rd(uintptr_t a)
        {
            uintptr_t v = 0;
            return mem::ReadPtr(a, &v) ? v : 0;
        }
        uint32_t Rd32(uintptr_t a)
        {
            uint32_t v = 0;
            return mem::Read32(a, &v) ? v : 0;
        }
        uint8_t Rd8(uintptr_t a)
        {
            uint8_t v = 0;
            return mem::Read8(a, &v) ? v : 0;
        }

        enum Cls { kSrvNormal, kSrvChild, kCliNormal, kCliChild, kSrvUser, kCliUser, kSrvActorMgr, kCliActorMgr, kClsCount };
        constexpr const char* kClsNames[kClsCount] = {
            ".?AVServerNormalInGameActor@pa@@", ".?AVServerChildOnlyInGameActor@pa@@",
            ".?AVClientNormalInGameActor@pa@@", ".?AVClientChildOnlyInGameActor@pa@@",
            ".?AVServerUserActor@pa@@",         ".?AVClientUserActor@pa@@",
            ".?AVServerActorManager@pa@@",      ".?AVClientActorManager@pa@@",
        };
        std::atomic<uintptr_t> g_vt[kClsCount];   // each class has one vtable: cached on first match

        bool VtIs(uintptr_t vt, Cls c)
        {
            if (!vt) return false;
            const uintptr_t known = g_vt[c].load(std::memory_order_relaxed);
            if (known) return vt == known;
            const uintptr_t col = Rd(vt - 8);
            uint32_t tdRva = 0;
            char name[48] = {};
            if (!col || !mem::Read32(col + 0x0C, &tdRva) ||
                !mem::ReadCString(reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)) + tdRva + 0x10, name, sizeof(name)) ||
                std::strcmp(name, kClsNames[c]) != 0)
                return false;
            g_vt[c].store(vt, std::memory_order_relaxed);
            return true;
        }

        bool IsServerActor(uintptr_t a)
        {
            const uintptr_t vt = Rd(a);
            return VtIs(vt, kSrvNormal) || VtIs(vt, kSrvChild);
        }

        // An in-game actor whose status component points back at it.
        bool IsValidActor(uintptr_t a)
        {
            const uintptr_t vt = Rd(a);
            if (!(VtIs(vt, kSrvNormal) || VtIs(vt, kSrvChild) || VtIs(vt, kCliNormal) || VtIs(vt, kCliChild))) return false;
            const uintptr_t status = Rd(Rd(a + kOff_Actor_Sub) + kOff_Sub_Status);
            return Rd32(a + kOff_Actor_Handle) && status && Rd(status + kOff_Comp_Owner) == a;
        }

        bool IsLocalPlayer(uintptr_t a)
        {
            if (!IsValidActor(a) || !Rd8(a + kOff_Actor_Controlled)) return false;
            const uintptr_t user = Rd(a + kOff_Actor_User);
            if (!user) return false;
            if (IsServerActor(a)) return Rd8(a + kOff_Actor_ServerSide) && VtIs(Rd(user), kSrvUser);
            const uintptr_t mine = g_clientUser.load(std::memory_order_relaxed);
            return VtIs(Rd(user), kCliUser) && (!mine || user == mine);
        }

        bool IsNpcKind(uintptr_t a)
        {
            if (!IsValidActor(a)) return false;
            const uint8_t k = Rd8(Rd(a + kOff_Actor_KindInfo) + 1);
            return k == 3 || k == 4 || k == 5 || k == 6 || k == 8 || k == 9;
        }

        bool IsComponentOf(uintptr_t comp, uintptr_t a, uintptr_t off)
        {
            return comp && IsValidActor(a) && Rd(comp + kOff_Comp_Owner) == a && Rd(Rd(a + kOff_Actor_Sub) + off) == comp;
        }

        bool IsNpcComp(uintptr_t comp, uintptr_t off)
        {
            const uintptr_t a = Rd(comp + kOff_Comp_Owner);
            return IsNpcKind(a) && IsComponentOf(comp, a, off);
        }

        uint8_t Relation(uintptr_t self, uintptr_t other)
        {
            __try { return g_relQuery(self, other, 0); }
            __except (EXCEPTION_EXECUTE_HANDLER) { return 5; }   // 5 = undetermined
        }

        // comp (DetectActorComponent at off 0x50, TargetActorComponent at 0x90)
        // belongs to an NPC that sees the local player `target` as Enemy (Ghost
        // Mode), or to a body whose side keeps it off the player.
        bool ShouldSuppress(uintptr_t comp, uintptr_t target, uintptr_t off)
        {
            const bool ghost = g_enabled.load(std::memory_order_relaxed);
            if ((!ghost && !g_allyCount.load(std::memory_order_relaxed)) || !IsLocalPlayer(target)) return false;
            g_playerHandle.store(Rd32(target + kOff_Actor_Handle), std::memory_order_relaxed);
            const uintptr_t self = Rd(comp + kOff_Comp_Owner);
            if (self == target || !IsNpcKind(self) || !IsComponentOf(comp, self, off)) return false;
            if (AllegianceSuppresses(Rd32(self + kOff_Actor_Handle))) return true;
            return ghost && Relation(self, target) == kRelation_Enemy;
        }

        // Pins the actor of `handle` on the same side (server/client) as `self`.
        uintptr_t LeaseByHandle(Lease* lease, uintptr_t self, uint32_t handle)
        {
            __try
            {
                if (IsServerActor(self))
                {
                    const uintptr_t mgr = Rd(Rd(g_serverMgrGlobal));
                    const uintptr_t vt = Rd(mgr);
                    const uintptr_t lookup = vt && VtIs(vt, kSrvActorMgr) ? Rd(vt + 5 * 8) : 0;
                    if (!lookup) return 0;
                    reinterpret_cast<ServerLookupFn>(lookup)(mgr, lease, handle);
                }
                else
                {
                    const uintptr_t mgr = Rd(Rd(g_clientMgrGlobal) + 0x38);
                    if (!mgr || !VtIs(Rd(mgr), kCliActorMgr)) return 0;
                    g_clientLookup(mgr, lease, handle, 0);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
            return lease->valid && lease->actor && Rd32(lease->actor + kOff_Actor_Handle) == handle ? lease->actor : 0;
        }

        void ReleaseLease(Lease* lease)
        {
            if (!lease->vt) return;
            __try { g_release(lease); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        bool IsPlayerHandle(uint32_t h)
        {
            return h && (h == g_playerHandle.load(std::memory_order_relaxed) ||
                         h == g_controlledHandle.load(std::memory_order_relaxed) ||
                         h == g_characterHandle.load(std::memory_order_relaxed));
        }

        bool ShouldSuppressHandle(uintptr_t comp, uint32_t handle, uintptr_t off)
        {
            // Only the player's handle can be suppressed: everything else is
            // rejected before any lookup.
            if (!Active() || !IsPlayerHandle(handle) || !IsNpcComp(comp, off))
                return false;
            Lease lease;
            const uintptr_t target = LeaseByHandle(&lease, Rd(comp + kOff_Comp_Owner), handle);
            const bool suppress = target && ShouldSuppress(comp, target, off);
            ReleaseLease(&lease);
            return suppress;
        }

        // Hate / engage entry `handle` on TargetActorComponent `c90`: drop it when
        // it links a hostile NPC and the player, from either side.
        bool ShouldDropEntry(uintptr_t c90, uint32_t handle)
        {
            if (!handle || !Active()) return false;
            const uintptr_t self = Rd(c90 + kOff_Comp_Owner);
            if (!IsComponentOf(c90, self, kOff_Sub_Target)) return false;
            if (IsNpcKind(self)) return ShouldSuppressHandle(c90, handle, kOff_Sub_Target);
            if (!IsLocalPlayer(self)) return false;
            Lease lease;
            const uintptr_t npc = LeaseByHandle(&lease, self, handle);
            const bool drop = npc && ShouldSuppress(Rd(Rd(npc + kOff_Actor_Sub) + kOff_Sub_Target), self, kOff_Sub_Target);
            ReleaseLease(&lease);
            return drop;
        }

        bool IsLocalPlayerHideObj(uintptr_t o)
        {
            const uintptr_t a = Rd(o);
            if (!IsLocalPlayer(a)) return false;
            const uintptr_t hide = Rd(Rd(a + kOff_Actor_Sub) + kOff_Sub_Hide);
            return hide && Rd(hide + kOff_Comp_Owner) == a && Rd(hide + 0x40) == o;
        }

        // The game's own "empty" detect slot (0x1420B0FF0): handle 0, 1.0f, 0x40.
        struct alignas(8) DetectSlot { uint8_t bytes[kSizeof_DetectSlot]; };
        const DetectSlot& EmptySlot()
        {
            static const DetectSlot slot = [] {
                DetectSlot s{};
                const float one = 1.0f;
                const uint32_t flags = 0x40;
                std::memcpy(s.bytes + 0x14, &one, 4);
                std::memcpy(s.bytes + 0x18, &flags, 4);
                return s;
            }();
            return slot;
        }

        // Drops whatever aggro the NPC owning `det` already has on the player
        // (detect slots, engage and hate lists, current target) and the
        // player's matching entries. Calls the originals, so no detour re-enters.
        void PurgeBody(uintptr_t det)
        {
            const uintptr_t self = Rd(det + kOff_Comp_Owner);
            const uintptr_t c90 = Rd(Rd(self + kOff_Actor_Sub) + kOff_Sub_Target);
            if (!IsComponentOf(c90, self, kOff_Sub_Target)) return;

            bool cleared = false;
            for (uint64_t slot = 0; slot < 2; ++slot)
            {
                const uint32_t h = Rd32(det + kOff_Detect_Slots + kSizeof_DetectSlot * slot);
                if (!ShouldSuppressHandle(det, h, kOff_Sub_Detect)) continue;
                oSetSlot(det, slot, 0, reinterpret_cast<uint64_t>(&EmptySlot()));
                cleared = true;
            }
            if (cleared) g_refreshSlots(det);

            // Every handle the target component refers to; only the player's
            // can pass ShouldSuppressHandle, so one is enough.
            uint32_t player = 0;
            auto consider = [&](uint32_t h) { if (!player && IsPlayerHandle(h)) player = h; };
            consider(Rd32(c90 + kOff_Target_Current));
            for (uintptr_t l = 0; l < 4; ++l)
            {
                const uintptr_t data = Rd(c90 + kOff_Target_Engage + 0x10 * l);
                const uint32_t n = Rd32(c90 + kOff_Target_Engage + 0x10 * l + 8);
                for (uint32_t i = 0; data && i < n && i < 64; ++i) consider(Rd32(data + 8ull * i));
            }
            for (const uintptr_t list : { kOff_Target_Hate0, kOff_Target_Hate1 })
            {
                const uintptr_t data = Rd(c90 + list);
                const uint32_t n = Rd32(c90 + list + 8);
                for (uint32_t i = 0; data && i < n && i < 64; ++i) consider(Rd32(data + 0x14ull * i));
            }
            if (!player || !ShouldSuppressHandle(c90, player, kOff_Sub_Target)) return;

            Lease lease;
            const uintptr_t body = LeaseByHandle(&lease, self, player);
            if (body)
            {
                uint32_t h = player;
                oSetEngaged(c90, 0, h, 0xFFFF, 4);
                g_removeHate(c90, &h, 0);
                if (Rd32(c90 + kOff_Target_Current) == h)
                {
                    uint32_t key = 0xFFFFFFFF;
                    uint64_t zero = 0;
                    uint8_t flag = 0;
                    oSetCurTarget(c90, reinterpret_cast<uint64_t>(&key), 0, reinterpret_cast<uint64_t>(&zero), 0, 1,
                                  reinterpret_cast<uint64_t>(&flag));
                }
                const uintptr_t pc90 = Rd(Rd(body + kOff_Actor_Sub) + kOff_Sub_Target);
                if (IsComponentOf(pc90, body, kOff_Sub_Target))
                {
                    uint32_t npc = Rd32(self + kOff_Actor_Handle);
                    oSetEngaged(pc90, 0, npc, 0xFFFF, 4);
                    g_removeHate(pc90, &npc, 0);
                }
            }
            ReleaseLease(&lease);
        }

        void Purge(uintptr_t det)
        {
            if (t_inPurge || !Active() || !IsNpcComp(det, kOff_Sub_Detect)) return;
            t_inPurge = true;
            __try { PurgeBody(det); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            t_inPurge = false;
        }

        // Decision helpers wrapped so a bad pointer can never take a hook down.
        bool SafeSuppress(uintptr_t comp, uintptr_t target, uintptr_t off)
        {
            __try { return ShouldSuppress(comp, target, off); }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }
        bool SafeSuppressHandle(uintptr_t comp, uint32_t handle, uintptr_t off)
        {
            __try { return ShouldSuppressHandle(comp, handle, off); }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }
        bool SafeDropEntry(uintptr_t c90, uint32_t handle)
        {
            __try { return ShouldDropEntry(c90, handle); }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }
        bool SafeHideObj(uintptr_t o)
        {
            __try { return IsLocalPlayerHideObj(o); }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }

        // The game reads GetLastError around some of these calls.
        struct LastErrorGuard
        {
            DWORD saved = GetLastError();
            ~LastErrorGuard() { SetLastError(saved); }
        };

        // --- Allegiance relations -----------------------------------------------------
        const char* RelationName(uint8_t r)
        {
            static const char* const kNames[] = { "Enemy", "Neutral", "Ally", "Ignore", "Exclusive", "none" };
            return r < 6 ? kNames[r] : "?";
        }

        const char* SideName(uint8_t side)
        {
            return side == kSideAlly ? "Ally" : side == kSideEnemy ? "Enemy" : side == kSideNeutral ? "Neutral" : "none";
        }

        uint8_t GameRelation(uintptr_t self, uintptr_t other, uint64_t flag)
        {
            return static_cast<uint8_t>(oRelQuery(self, other, flag));
        }

        // The player hurt this body: one of its hate lists holds the player.
        bool HatesPlayer(uintptr_t a)
        {
            const uintptr_t c90 = Rd(Rd(a + kOff_Actor_Sub) + kOff_Sub_Target);
            if (!c90 || Rd(c90 + kOff_Comp_Owner) != a) return false;
            for (const uintptr_t list : { kOff_Target_Hate0, kOff_Target_Hate1 })
            {
                const uintptr_t data = Rd(c90 + list);
                const uint32_t n = Rd32(c90 + list + 8);
                for (uint32_t i = 0; data && i < n && i < 64; ++i)
                    if (IsPlayerHandle(Rd32(data + 0x14ull * i))) return true;
            }
            return false;
        }

        // The game's own relation between the player character and `x`:
        // RelQuery(player, x) or RelQuery(x, player). The player's body is looked
        // up in the realm of `body` (the body with a side in this query, always
        // an in-game actor; `x` shares its realm). False when it is not loaded.
        bool PlayerRelation(uintptr_t x, uintptr_t body, bool playerFirst, uint64_t flag, uint8_t* out)
        {
            uint32_t ph = g_characterHandle.load(std::memory_order_relaxed);
            if (!ph) ph = g_controlledHandle.load(std::memory_order_relaxed);
            if (!ph || !IsValidActor(body)) return false;
            Lease lease;
            const uintptr_t p = LeaseByHandle(&lease, body, ph);
            if (p) *out = playerFirst ? GameRelation(p, x, flag) : GameRelation(x, p, flag);
            ReleaseLease(&lease);
            return p != 0;
        }

        // How the player sees `x` (whose side is `side`). `player` is the
        // player's body when it is part of this query, else 0 (looked up in the
        // realm of `body`). Falls back to the game's answer for (self, other).
        uint8_t PlayerView(uintptr_t x, uint8_t side, uintptr_t player, uintptr_t body, uint64_t flag, uintptr_t self,
                           uintptr_t other)
        {
            if (side == kSideAlly) return kRelation_Ally;
            if (side == kSideEnemy) return kRelation_Enemy;
            if (side == kSideNeutral && !HatesPlayer(x)) return kRelation_Neutral;
            if (player) return GameRelation(player, x, flag);
            uint8_t r = 0;
            return PlayerRelation(x, body, true, flag, &r) ? r : GameRelation(self, other, flag);
        }

        // How `x` sees the player.
        uint8_t ViewOfPlayer(uintptr_t x, uint8_t side, uintptr_t player, uintptr_t body, uint64_t flag, uintptr_t self,
                             uintptr_t other)
        {
            if (side == kSideAlly) return kRelation_Ally;
            if (side == kSideEnemy) return kRelation_Enemy;
            if (side == kSideNeutral && !HatesPlayer(x)) return kRelation_Neutral;
            if (player) return GameRelation(x, player, flag);
            uint8_t r = 0;
            return PlayerRelation(x, body, false, flag, &r) ? r : GameRelation(self, other, flag);
        }

        // RelQuery(self, other) when either body has a side; false = the game decides.
        //  - Ally: sees everyone the way the player does, and everyone sees it the
        //    way they see the player (so the player's enemies fight it).
        //  - Enemy: hostile to the player and to whatever the player calls Ally.
        //  - Neutral: Neutral to the player's side until the player hurts it.
        //  - Two bodies outside the player's side: the game decides.
        bool AllegianceRelation(uintptr_t self, uintptr_t other, uint64_t flag, uint8_t* out)
        {
            const uint32_t hs = Rd32(self + kOff_Actor_Handle), ho = Rd32(other + kOff_Actor_Handle);
            AllyEntry* es = FindAlly(hs);
            AllyEntry* eo = FindAlly(ho);
            const uint8_t a = SideOf(es), b = SideOf(eo);
            if (a == kSideNone && b == kSideNone) return false;
            const bool selfPlayer = IsPlayerHandle(hs), otherPlayer = IsPlayerHandle(ho);
            uint8_t r;
            if (a == kSideAlly)
                r = otherPlayer || b == kSideAlly ? kRelation_Ally : PlayerView(other, b, 0, self, flag, self, other);
            else if (b == kSideAlly)
                r = selfPlayer ? kRelation_Ally : ViewOfPlayer(self, a, 0, other, flag, self, other);
            else if (otherPlayer)
                r = ViewOfPlayer(self, a, other, self, flag, self, other);
            else if (selfPlayer)
                r = PlayerView(other, b, self, other, flag, self, other);
            else
            {
                const bool selfHasSide = a != kSideNone;
                const uint8_t side = selfHasSide ? a : b;
                const uint8_t thirdSide = selfHasSide ? b : a;
                uint8_t pr = 0;
                const bool thirdIsPlayerSide = thirdSide == kSideNone &&
                                               PlayerRelation(selfHasSide ? other : self, selfHasSide ? self : other,
                                                              true, flag, &pr) &&
                                               pr == kRelation_Ally;
                r = !thirdIsPlayerSide ? GameRelation(self, other, flag)
                                       : side == kSideEnemy ? kRelation_Enemy : kRelation_Neutral;
            }
            // First answer between a body with a side and the player, each way.
            if (otherPlayer && es && !(es->logged.fetch_or(1) & 1))
                LOG("allegiance: 0x%08X (%s) sees the player as %s (the game said %s)", hs, SideName(a), RelationName(r),
                    RelationName(GameRelation(self, other, flag)));
            if (selfPlayer && eo && !(eo->logged.fetch_or(2) & 2))
                LOG("allegiance: the player sees 0x%08X (%s) as %s (the game said %s)", ho, SideName(b), RelationName(r),
                    RelationName(GameRelation(self, other, flag)));
            *out = r;
            return true;
        }

        bool SafeAllegianceRelation(uint64_t self, uint64_t other, uint64_t flag, uint8_t* out)
        {
            __try { return AllegianceRelation(self, other, flag, out); }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }

        // --- Detours ----------------------------------------------------------------
        // Hook 0: the "actor is hidden" predicate (bush / stealth AI conditions).
        uint64_t __fastcall hkIsHiding(uint64_t o)
        {
            const uint64_t r = oIsHiding(o);
            if (!g_enabled.load(std::memory_order_relaxed)) return r;
            LastErrorGuard keep;
            return SafeHideObj(o) ? ((r & ~0xFFull) | 1) : r;
        }

        // Hook 1: building a detection candidate (target in r8).
        uint64_t __fastcall hkBuildCandidate(uint64_t c, uint64_t a2, uint64_t t, uint64_t a4, uint64_t a5, uint64_t a6,
                                             uint64_t a7, uint64_t a8)
        {
            if (Active())
            {
                LastErrorGuard keep;
                if (SafeSuppress(c, t, kOff_Sub_Detect)) return 0;
            }
            return oBuildCandidate(c, a2, t, a4, a5, a6, a7, a8);
        }

        // Hook 2: range / view cone / line-of-sight test (target in rdx).
        uint64_t __fastcall hkSenseTest(uint64_t c, uint64_t t, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                                        uint64_t a7, uint64_t a8)
        {
            if (Active())
            {
                LastErrorGuard keep;
                if (SafeSuppress(c, t, kOff_Sub_Detect)) return 0;
            }
            return oSenseTest(c, t, a3, a4, a5, a6, a7, a8);
        }

        // Hook 3: TargetActorComponent "can target" (vtable slot 43).
        uint64_t __fastcall hkCanTarget(uint64_t c, uint64_t t, uint64_t filter, uint64_t a4)
        {
            if (Active())
            {
                LastErrorGuard keep;
                if (SafeSuppress(c, t, kOff_Sub_Target)) return 0;
            }
            return oCanTarget(c, t, filter, a4);
        }

        // Hook 4: storing a detect slot: the player's handle becomes an empty slot.
        uint64_t __fastcall hkSetSlot(uint64_t c, uint64_t slot, uint64_t a3, uint64_t s)
        {
            if (Active() && (slot & 0xFF) < 2 && s)
            {
                LastErrorGuard keep;
                if (SafeSuppressHandle(c, Rd32(s), kOff_Sub_Detect)) s = reinterpret_cast<uint64_t>(&EmptySlot());
            }
            return oSetSlot(c, slot, a3, s);
        }

        // Hook 5: setting the current target (+0x178): the player becomes "none".
        uint64_t __fastcall hkSetCurTarget(uint64_t c, uint64_t key, uint64_t handle, uint64_t a4, uint64_t a5,
                                           uint64_t a6, uint64_t a7)
        {
            if (Active())
            {
                LastErrorGuard keep;
                if (SafeSuppressHandle(c, static_cast<uint32_t>(handle), kOff_Sub_Target)) { handle = 0; a6 = 1; }
            }
            return oSetCurTarget(c, key, handle, a4, a5, a6, a7);
        }

        // Hook 6: adding hate entries (mirrored onto every listed actor).
        struct GameArray { uintptr_t data; uint32_t count; uint32_t cap; };
        struct HateEntry { uint8_t bytes[0x14]; };   // u32 handle first

        // Copies `list` without the entries ShouldDropEntry rejects; returns how
        // many were dropped (0 = keep the original list).
        uint32_t FilterHate(uint64_t c, uint64_t list, HateEntry* kept, uint32_t* keptCount)
        {
            *keptCount = 0;
            __try
            {
                const GameArray src = *reinterpret_cast<const GameArray*>(list);
                if (src.count == 0 || src.count > 64 || !src.data) return 0;
                uint32_t dropped = 0;
                for (uint32_t i = 0; i < src.count; ++i)
                {
                    const HateEntry& e = reinterpret_cast<const HateEntry*>(src.data)[i];
                    uint32_t h = 0;
                    std::memcpy(&h, e.bytes, 4);
                    if (SafeDropEntry(c, h)) ++dropped;
                    else kept[(*keptCount)++] = e;
                }
                return dropped;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { *keptCount = 0; return 0; }
        }

        uint64_t __fastcall hkAddHate(uint64_t c, uint64_t list, uint64_t a3, uint64_t kind)
        {
            if (!Active() || !list) return oAddHate(c, list, a3, kind);
            HateEntry kept[64];
            uint32_t keptCount = 0, dropped = 0;
            {
                LastErrorGuard keep;
                dropped = FilterHate(c, list, kept, &keptCount);
            }
            if (!dropped) return oAddHate(c, list, a3, kind);
            if (!keptCount) return 0;   // every entry linked the player to a hostile NPC
            GameArray filtered{ reinterpret_cast<uintptr_t>(kept), keptCount, keptCount };
            return oAddHate(c, reinterpret_cast<uint64_t>(&filtered), a3, kind);
        }

        // Hook 7: each detect component's update: purge existing aggro first.
        uint64_t __fastcall hkDetectUpdate(uint64_t c, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
        {
            if (Active())
            {
                LastErrorGuard keep;
                Purge(c);
            }
            return oDetectUpdate(c, a2, a3, a4, a5);
        }

        // Hook 8: engage lists: an "add" of the player becomes a remove from all four.
        uint64_t __fastcall hkSetEngaged(uint64_t c, uint64_t add, uint64_t handle, uint64_t tag, uint64_t list)
        {
            if (Active() && (add & 0xFF))
            {
                LastErrorGuard keep;
                if (SafeDropEntry(c, static_cast<uint32_t>(handle))) return oSetEngaged(c, 0, handle, 0xFFFF, 4);
            }
            return oSetEngaged(c, add, handle, tag, list);
        }

        // Hook 9: forced detection after an attack, a hit or contact (source in rdx).
        uint64_t __fastcall hkApplyDetect(uint64_t c, uint64_t src, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                                          uint64_t a7, uint64_t a8)
        {
            if (Active())
            {
                LastErrorGuard keep;
                if (SafeSuppress(c, src, kOff_Sub_Detect)) return 0;
            }
            return oApplyDetect(c, src, a3, a4, a5, a6, a7, a8);
        }

        // Hook 10: the engine's relationship query, answered here for bodies with a side.
        uint64_t __fastcall hkRelQuery(uint64_t self, uint64_t other, uint64_t flag)
        {
            if (!g_allyCount.load(std::memory_order_relaxed)) return oRelQuery(self, other, flag);
            uint8_t r = 0;
            bool mine;
            {
                LastErrorGuard keep;
                mine = SafeAllegianceRelation(self, other, flag, &r);
            }
            return mine ? r : oRelQuery(self, other, flag);
        }

        // --- Installation -------------------------------------------------------------
        // First "48 8B 0D g ..." site whose global leads to an object of class `cls`
        // (`deref38`: the object sits at *(*g + 0x38)).
        uintptr_t FindManagerGlobal(const char* sig, Cls cls, bool deref38)
        {
            for (const uintptr_t site : mem::FindAllMatches(sig, 200000))
            {
                const uintptr_t g = mem::ResolveRipAt(site, 7);
                const uintptr_t obj = deref38 ? Rd(Rd(g) + 0x38) : Rd(Rd(g));
                if (obj && VtIs(Rd(obj), cls)) return g;
            }
            return 0;
        }

        bool Install()
        {
            const ULONGLONG t0 = GetTickCount64();
            struct Target { const char* name; uintptr_t addr; void* detour; void** original; };
            uintptr_t applyDetect = 0;
            if (const uintptr_t site = mem::FindPattern(kSig_ApplyDetectCall))
                applyDetect = mem::ResolveCall(site + kOff_ApplyDetectCall);
            // Calls through g_relQuery enter hkRelQuery once the hooks are on.
            g_relQuery = reinterpret_cast<RelQueryFn>(mem::FindPattern(kSig_RelQuery));
            Target targets[] = {
                { "IsHiding",         mem::FindPattern(kSig_IsHiding),       &hkIsHiding,       reinterpret_cast<void**>(&oIsHiding) },
                { "BuildCandidate",   mem::FindPattern(kSig_BuildCandidate), &hkBuildCandidate, reinterpret_cast<void**>(&oBuildCandidate) },
                { "SenseTest",        mem::FindPattern(kSig_SenseTest),      &hkSenseTest,      reinterpret_cast<void**>(&oSenseTest) },
                { "CanTarget",        mem::FindPattern(kSig_CanTarget),      &hkCanTarget,      reinterpret_cast<void**>(&oCanTarget) },
                { "SetSlot",          mem::FindPattern(kSig_SetSlot),        &hkSetSlot,        reinterpret_cast<void**>(&oSetSlot) },
                { "SetCurrentTarget", mem::FindPattern(kSig_SetCurTarget),   &hkSetCurTarget,   reinterpret_cast<void**>(&oSetCurTarget) },
                { "AddHateEntries",   mem::FindPattern(kSig_AddHate),        &hkAddHate,        reinterpret_cast<void**>(&oAddHate) },
                { "DetectUpdate",     mem::FindPattern(kSig_DetectUpdate),   &hkDetectUpdate,   reinterpret_cast<void**>(&oDetectUpdate) },
                { "SetEngaged",       mem::FindPattern(kSig_SetEngaged),     &hkSetEngaged,     reinterpret_cast<void**>(&oSetEngaged) },
                { "ApplyDetect",      applyDetect,                            &hkApplyDetect,    reinterpret_cast<void**>(&oApplyDetect) },
                { "RelQuery",         reinterpret_cast<uintptr_t>(g_relQuery), &hkRelQuery,      reinterpret_cast<void**>(&oRelQuery) },
            };
            g_clientLookup = reinterpret_cast<ClientLookupFn>(mem::FindPattern(kSig_ClientLookup));
            g_release = reinterpret_cast<ReleaseFn>(mem::FindPattern(kSig_LeaseRelease));
            g_removeHate = reinterpret_cast<RemoveHateFn>(mem::FindPattern(kSig_RemoveHate));
            g_refreshSlots = reinterpret_cast<RefreshSlotsFn>(mem::FindPattern(kSig_RefreshSlots));
            g_serverMgrGlobal = FindManagerGlobal(kSig_ServerMgrLoad, kSrvActorMgr, false);
            g_clientMgrGlobal = FindManagerGlobal(kSig_ClientMgrLoad, kCliActorMgr, true);

            bool ok = g_relQuery && g_clientLookup && g_release && g_removeHate && g_refreshSlots &&
                      g_serverMgrGlobal && g_clientMgrGlobal;
            if (!ok)
                LOG_WARN("ghost: helpers missing (relQuery=%p clientLookup=%p release=%p removeHate=%p refresh=%p "
                         "serverMgr=%p clientMgr=%p)", reinterpret_cast<void*>(g_relQuery),
                         reinterpret_cast<void*>(g_clientLookup), reinterpret_cast<void*>(g_release),
                         reinterpret_cast<void*>(g_removeHate), reinterpret_cast<void*>(g_refreshSlots),
                         reinterpret_cast<void*>(g_serverMgrGlobal), reinterpret_cast<void*>(g_clientMgrGlobal));
            for (const Target& t : targets)
                if (!t.addr) { LOG_WARN("ghost: %s not found", t.name); ok = false; }
            if (!ok) return false;

            int created = 0;
            for (const Target& t : targets)
            {
                if (MH_CreateHook(reinterpret_cast<void*>(t.addr), t.detour, t.original) != MH_OK)
                {
                    LOG_WARN("ghost: hook %s @ %p failed", t.name, reinterpret_cast<void*>(t.addr));
                    break;
                }
                ++created;
            }
            if (created != static_cast<int>(std::size(targets)))
            {
                for (int i = 0; i < created; ++i) MH_RemoveHook(reinterpret_cast<void*>(targets[i].addr));
                return false;
            }
            for (const Target& t : targets) MH_QueueEnableHook(reinterpret_cast<void*>(t.addr));
            if (MH_ApplyQueued() != MH_OK)
            {
                for (const Target& t : targets) MH_RemoveHook(reinterpret_cast<void*>(t.addr));
                LOG_WARN("ghost: enabling hooks failed");
                return false;
            }
            LOG_OK("ghost: %d hooks installed (relQuery %p, server mgr global %p, client mgr global %p, %llu ms)",
                   static_cast<int>(std::size(targets)), reinterpret_cast<void*>(g_relQuery),
                   reinterpret_cast<void*>(g_serverMgrGlobal), reinterpret_cast<void*>(g_clientMgrGlobal),
                   GetTickCount64() - t0);
            return true;
        }
    }

    void Ghost::Tick()
    {
        const bool want = State::Get().ghostMode;
        if ((want || g_allyWanted.load(std::memory_order_relaxed)) && !g_installed && !g_failed)
        {
            // The manager objects exist only in a loaded world.
            if (!Player::Ready()) return;
            g_installed = Install();
            g_failed = !g_installed;
            if (g_failed) LOG_WARN("ghost: unavailable on this build - Ghost Mode and spawn sides stay off.");
        }
        if (!g_installed)
        {
            g_enabled.store(false);
            return;
        }
        const uintptr_t owner = Player::GetControlledOwner();
        g_controlledHandle.store(owner ? Rd32(owner + kOff_Actor_Handle) : 0, std::memory_order_relaxed);
        const uintptr_t character = Inventory::ServerCharacterAddr();
        g_characterHandle.store(character ? Rd32(character + kOff_Actor_Handle) : 0, std::memory_order_relaxed);
        const uintptr_t client = Inventory::ClientActorAddr();
        const uintptr_t user = client ? Rd(client + kOff_Actor_User) : 0;
        if (user && VtIs(Rd(user), kCliUser)) g_clientUser.store(user, std::memory_order_relaxed);
        if (g_enabled.load() != want)
        {
            g_enabled.store(want);
            LOG("ghost: %s", want ? "on - hostile NPCs lose track of the player on their next detect update" : "off");
        }
    }

    bool Ghost::Installed() { return g_installed; }
    bool Ghost::Failed() { return g_failed; }

    void Ghost::PrepareAllegiance() { g_allyWanted.store(true, std::memory_order_relaxed); }

    bool Ghost::SetAllegiance(uint32_t handle, Allegiance side)
    {
        if (!handle) return false;
        if (side == Allegiance::None)
        {
            ClearAllegiance(handle);
            return true;
        }
        g_allyWanted.store(true, std::memory_order_relaxed);
        if (!g_installed) return false;
        const uint8_t s = side == Allegiance::Ally ? kSideAlly : side == Allegiance::Enemy ? kSideEnemy : kSideNeutral;
        AllyEntry* e = FindAlly(handle);
        const bool fresh = !e;
        if (fresh)
        {
            for (AllyEntry& f : g_ally)
                if (!f.handle.load(std::memory_order_relaxed)) { e = &f; break; }
            if (!e) return false;
        }
        e->side.store(s, std::memory_order_relaxed);
        e->logged.store(0, std::memory_order_relaxed);
        e->purgeUntil.store(GetTickCount64() + kNeutralPurgeMs, std::memory_order_relaxed);
        if (fresh)
        {
            // Filter bit first: a reader that finds the handle must pass the filter.
            g_allyFilter[(handle >> 6) & 63].fetch_or(1ull << (handle & 63), std::memory_order_relaxed);
            e->handle.store(handle, std::memory_order_release);
            g_allyCount.fetch_add(1, std::memory_order_relaxed);
        }
        LOG("allegiance: 0x%08X is now %s", handle, SideName(s));
        return true;
    }

    void Ghost::ClearAllegiance(uint32_t handle)
    {
        AllyEntry* e = FindAlly(handle);
        if (!e) return;
        e->side.store(kSideNone, std::memory_order_relaxed);
        e->handle.store(0, std::memory_order_release);
        if (g_allyCount.fetch_sub(1, std::memory_order_relaxed) == 1)
            for (std::atomic<uint64_t>& bits : g_allyFilter) bits.store(0, std::memory_order_relaxed);
    }
}
