#include "mercenary.h"

#include <Windows.h>
#include <algorithm>
#include <cmath>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

#include "ghost.h"
#include "inventory.h"
#include "offsets.h"
#include "player.h"
#include "troc.h"
#include "character_names.h"
#include "../core/logger.h"
#include "../core/state.h"
#include "../core/mod.h"
#include "../mem/safe_memory.h"
#include "../mem/scanner.h"

namespace trinity::game
{
    namespace
    {
        constexpr uintptr_t kOff_Table_Count = 0x08;
        constexpr uintptr_t kOff_Table_Rows  = 0x58;
        constexpr uintptr_t kOff_Row_Key     = 0x00;
        constexpr uintptr_t kOff_Row_String  = 0x08;   // -> string obj -> char*

        constexpr uintptr_t kOff_Char_MercenaryInfo = 0xBE; // u16 mercenaryinfo row
        constexpr uintptr_t kOff_Char_VehicleInfo   = 0x6E; // u16 vehicleinfo row (0xFFFF = not rideable)

        constexpr uintptr_t kOff_Merc_Type        = 0x20; // u8 _mercenaryType
        constexpr uintptr_t kOff_Merc_SummonLimit = 0x14; // u32 _defaultLimitSummonCount
        constexpr uintptr_t kOff_Merc_HireLimit   = 0x18; // u32 _defaultLimitHireCount

        constexpr uintptr_t kOff_Owner_Sub   = 0x68;
        constexpr uintptr_t kOff_Sub_Clan    = 0x110;
        constexpr uintptr_t kOff_Clan_Vector = 0x18;  // record*[]
        constexpr uintptr_t kOff_Clan_Count  = 0x20;  // u32
        constexpr uintptr_t kOff_Rec_CharRow = 0x20;  // u16
        constexpr uintptr_t kOff_Rec_Number  = 0x28;  // u32
        constexpr uintptr_t kOff_Rec_Actor   = 0x50;  // u32 handle of the summoned body, 0 = not summoned

        constexpr uint8_t kType_Main = 1, kType_Vehicle = 2, kType_Wagon = 3, kType_Pet = 4;
        constexpr uint8_t kType_Observer = 10, kType_RecoveryItem = 11; // engine bookkeeping, not shown

        uintptr_t g_charGlobal = 0;
        uintptr_t g_mercGlobal = 0;
        bool      g_installed = false;

        std::mutex                     g_lock;
        std::vector<Mercenary::Entry>  g_entries;
        bool                           g_ready = false;
        char                           g_status[160] = {};
        ULONGLONG                      g_nextSnapshot = 0;

        // Limits: original table values, captured once, restored when off.
        uintptr_t g_petRow = 0;
        uint32_t  g_petHireOriginal = 0, g_petSummonOriginal = 0;
        bool      g_petOriginalsKnown = false;
        std::atomic<int> g_petSummonLimit{ 0 };

        // Nearby scan (actor manager list: data +0xB8, count +0xC0).
        constexpr uintptr_t kOff_ActorMgr_List  = 0xB8;
        constexpr uintptr_t kOff_ActorMgr_Count = 0xC0;
        constexpr uintptr_t kOff_Actor_Handle   = 0x60;  // u32 request handle (not the +0x50 index)
        constexpr uintptr_t kOff_Sub_Status     = 0x20;
        constexpr uintptr_t kOff_Status_CharRow = 0x30;  // u16 characterinfo row
        constexpr uintptr_t kOff_Sub_Transform  = 0x1A0; // ServerTransformSyncActorComponent
        constexpr uintptr_t kOff_Transform_Pos  = 0xB4;  // float3, local to the 1 km sector
        constexpr uintptr_t kOff_Transform_Sector = 0xC0; // s16 x, s16 z (game 0x1421A1950: world = local + sector * 1000)
        constexpr float     kSectorSize         = 1000.0f;
        constexpr float     kNearbyRadius       = 40.0f;
        constexpr size_t    kNearbyMax          = 48;

        std::atomic<bool>               g_nearbyRequested{ false };
        std::atomic<bool>               g_tameRequested{ false };

        // Add-any-creature state (game thread).
        struct SpawnRequest
        {
            uint16_t row = 0xFFFF; bool adopt = false; bool pending = false; int count = 1;
            Mercenary::SpawnSide side = Mercenary::SpawnSide::Default;
        };
        // One spawn order, run body by body as DesertLink does (PE 2976): send
        // one TrocTrSpawnCharacterCheatReq, wait until the actor table shows a
        // new body of that row, then send the next. Back-to-back orders lose
        // bodies, and the handler reports 0 whether or not one was created, so
        // the actor table is the only proof.
        struct SpawnJob
        {
            bool                  active = false;
            uint16_t              row = 0xFFFF;
            uint32_t              key = 0;
            bool                  adopt = false;
            Mercenary::SpawnSide  side = Mercenary::SpawnSide::Default;
            int                   total = 0, sent = 0, made = 0;
            float                 origin[3] = {};   // player world position when ordered
            float                 target[3] = {};   // requested position of the body in flight
            float                 nearest = -1.0f;  // closest confirmed body to the player
            float                 farDist = -1.0f;  // a new body of the row, but far from the target
            ULONGLONG             deadline = 0;
            std::vector<uint32_t> known;            // handles of the row before the body in flight
            char                  name[64] = {};
        };
        SpawnRequest                    g_spawnReq;
        SpawnJob                        g_spawnJob;
        ULONGLONG                       g_nextSpawnPump = 0;
        std::vector<uint32_t>           g_adoptedHandles;  // never hire the same body twice
        std::vector<uint32_t>           g_spawnedHandles;  // bodies Trinity spawned this session
        constexpr ULONGLONG             kSpawnWaitMs      = 6000;    // DesertLink waits 5 s
        constexpr ULONGLONG             kSpawnPumpMs      = 100;
        constexpr float                 kSpawnDistance    = 5.0f;    // DesertLink "Near"
        constexpr float                 kSpawnAngleStep   = 0.65f;   // body i at i * 0.65 rad
        constexpr float                 kSpawnMatchRadius = 15.0f;   // DesertLink accepts 10 m
        std::atomic<int>                g_catalogReq{ -1 };
        std::vector<Mercenary::Species> g_catalog;

        // characterinfo +0x68 = native actor type (1 player, 3 npc, 4 unique
        // companion, 5 vehicle/mount, 6 animal/pet, 7 object). 1 and 7 cannot be
        // spawned; 4 allows one body per character (DesertLink's rules).
        constexpr uintptr_t kOff_Char_NativeType = 0x68;
        constexpr uint8_t   kNative_Player = 1, kNative_Companion = 4, kNative_Object = 7;

        // Spawned bodies Trinity tracks for the Spawned NPCs page (game thread).
        struct SpawnedNpc
        {
            uint32_t             handle = 0;
            uint16_t             row = 0xFFFF;
            Mercenary::SpawnSide side = Mercenary::SpawnSide::Default;
            bool                 despawnQueued = false; // removal task posted to the server thread
            bool                 removing = false;      // removal accepted, waiting for the body to go
            ULONGLONG            removeUntil = 0;
            char                 name[64] = {};
        };
        struct DespawnResult { uint32_t handle; uint32_t status; };
        std::vector<SpawnedNpc>              g_spawned;
        std::vector<Mercenary::SpawnedInfo>  g_spawnedView;     // menu copy, g_lock
        std::vector<uint32_t>                g_despawnReq;      // menu -> game thread, g_lock (0 = all)
        std::mutex                           g_despawnLock;
        std::vector<DespawnResult>           g_despawnResults;  // server thread -> game thread
        ULONGLONG                            g_nextTrackPump = 0;
        constexpr size_t                     kMaxSpawned = 64;  // DesertLink's session cap
        constexpr uint32_t                   kDespawnNotFound = 0xFFFFFFFE, kDespawnFault = 0xFFFFFFFD;

        // Mount stat overrides by mercenary number (applied on the game thread).
        // Value indices verified live on 2.03 (Herspia: 18 / 51 / 3 / 2 / 2 / 2).
        constexpr int       kVal_Attack = 0, kVal_Defense = 1;
        constexpr int       kVal_Speed = 42, kVal_Accel = 43, kVal_Turn = 44, kVal_Jump = 45;
        constexpr uintptr_t kOff_StatusComp_Data = 0x18;
        constexpr uintptr_t kOff_StatusData_Vals = 0x18;  // i64 x4 per value
        constexpr uintptr_t kOff_StatusData_Count = 0x20;
        constexpr uintptr_t kOff_StatusData_Gauges = 0x58;
        constexpr uintptr_t kSizeof_StatusVal = 0x20;
        constexpr int       kGauge_Hp = 0, kGauge_Vigor = 22;
        std::mutex                                   g_statsLock;
        std::vector<std::pair<uint32_t, Mercenary::MountStats>> g_statOverrides;

        // A tamed mount whose family is not callable, waiting for its record.
        struct Remap { uint16_t fromRow = 0xFFFF; uint16_t toRow = 0xFFFF; ULONGLONG until = 0; };
        Remap                           g_remap;

        // Species change requests (handled on the game thread).
        struct SpeciesRequest { uint32_t number = 0; bool anyFamily = false; bool pending = false; };
        struct ChangeRequest  { uint32_t number = 0; uint16_t row = 0; bool pending = false; };
        SpeciesRequest                  g_speciesReq;
        ChangeRequest                   g_changeReq;
        std::vector<Mercenary::Species> g_species;
        constexpr uint8_t kType_Domestic = 5;
        std::vector<Mercenary::Nearby>  g_nearby;

        uintptr_t Ptr(uintptr_t a)
        {
            uintptr_t v = 0;
            return mem::ReadPtr(a, &v) ? v : 0;
        }

        bool ReadCString(uintptr_t p, char* out, size_t cap)
        {
            out[0] = 0;
            if (!p) return false;
            __try
            {
                const char* s = reinterpret_cast<const char*>(p);
                size_t i = 0;
                for (; i + 1 < cap && s[i]; ++i) out[i] = s[i];
                out[i] = 0;
                return i > 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { out[0] = 0; return false; }
        }

        bool IsClass(uintptr_t obj, const char* mangled)
        {
            const uintptr_t vt = Ptr(obj);
            const uintptr_t col = vt ? Ptr(vt - 8) : 0;
            uint32_t tdRva = 0;
            if (!col || !mem::Read32(col + 0x0C, &tdRva)) return false;
            const char* name = reinterpret_cast<const char*>(
                reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)) + tdRva + 0x10);
            __try { return std::strcmp(name, mangled) == 0; }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }

        uintptr_t RowPtr(uintptr_t global, uint32_t index)
        {
            const uintptr_t table = Ptr(global);
            uint32_t count = 0;
            if (!table || !mem::Read32(table + kOff_Table_Count, &count) || index >= count) return 0;
            return Ptr(Ptr(table + kOff_Table_Rows) + 8ull * index);
        }

        // mercenaryinfo has no table-name anchor the string resolver can use,
        // but its global sits in the same block as the other "*info" table
        // globals. Pick the neighbour whose first row is "Mercenary_Main".
        uintptr_t FindMercenaryInfoGlobal(uintptr_t anchorGlobal)
        {
            for (uintptr_t g = anchorGlobal - 0x400; g < anchorGlobal + 0x400; g += 8)
            {
                const uintptr_t table = Ptr(g);
                uint32_t count = 0;
                if (!table || !mem::Read32(table + kOff_Table_Count, &count) || count < 8 || count > 64) continue;
                char key[32];
                if (ReadCString(Ptr(Ptr(RowPtr(g, 0) + kOff_Row_String)), key, sizeof(key)) &&
                    std::strcmp(key, "Mercenary_Main") == 0)
                    return g;
            }
            return 0;
        }

        const char* EnglishName(uint32_t key)
        {
            const auto* b = character_names::kNames;
            const auto* e = b + character_names::kCount;
            const auto* it = std::lower_bound(b, e, key,
                [](const character_names::Entry& x, uint32_t k) { return x.key < k; });
            return (it != e && it->key == key) ? it->name : nullptr;
        }

        Mercenary::Kind KindOf(uint8_t type)
        {
            switch (type)
            {
            case kType_Vehicle: case kType_Wagon: return Mercenary::Kind::Mount;
            case kType_Pet:                       return Mercenary::Kind::Pet;
            case kType_Main:                      return Mercenary::Kind::Companion;
            case 6: case 7: case 8: case 9: case 12: return Mercenary::Kind::Mercenary; // melee/range/worker/shop/guest
            default:                              return Mercenary::Kind::Other;
            }
        }

        uintptr_t PlayerClan()
        {
            const uintptr_t owner = Player::GetControlledOwner();
            const uintptr_t sub = owner ? Ptr(owner + kOff_Owner_Sub) : 0;
            const uintptr_t clan = sub ? Ptr(sub + kOff_Sub_Clan) : 0;
            return clan && IsClass(clan, ".?AVServerMercenaryClanActorComponent@pa@@") ? clan : 0;
        }

        void BuildSnapshot()
        {
            const uintptr_t clan = PlayerClan();
            std::vector<Mercenary::Entry> entries;
            if (clan)
            {
                const uintptr_t vec = Ptr(clan + kOff_Clan_Vector);
                uint32_t count = 0;
                mem::Read32(clan + kOff_Clan_Count, &count);
                for (uint32_t i = 0; vec && i < count && i < 512; ++i)
                {
                    const uintptr_t rec = Ptr(vec + 8ull * i);
                    uint16_t charRow = 0xFFFF;
                    Mercenary::Entry e{};
                    if (!rec || !mem::Read16(rec + kOff_Rec_CharRow, &charRow) || !mem::Read32(rec + kOff_Rec_Number, &e.number))
                        continue;
                    const uintptr_t crow = RowPtr(g_charGlobal, charRow);
                    if (!crow) continue;
                    mem::Read32(crow + kOff_Row_Key, &e.characterKey);
                    char key[64];
                    ReadCString(Ptr(Ptr(crow + kOff_Row_String)), key, sizeof(key));
                    if (const char* en = EnglishName(e.characterKey)) snprintf(e.name, sizeof(e.name), "%s", en);
                    else snprintf(e.name, sizeof(e.name), "%s", key);

                    uint16_t mercRow = 0xFFFF;
                    mem::Read16(crow + kOff_Char_MercenaryInfo, &mercRow);
                    if (const uintptr_t mrow = mercRow != 0xFFFF ? RowPtr(g_mercGlobal, mercRow) : 0)
                    {
                        uint8_t type = 0;
                        mem::Read8(mrow + kOff_Merc_Type, &type);
                        if (type == kType_Observer || type == kType_RecoveryItem) continue;
                        e.kind = KindOf(type);
                        ReadCString(Ptr(Ptr(mrow + kOff_Row_String)), e.typeKey, sizeof(e.typeKey));
                    }
                    entries.push_back(e);
                }
                std::sort(entries.begin(), entries.end(), [](const Mercenary::Entry& a, const Mercenary::Entry& b) {
                    if (a.kind != b.kind) return a.kind < b.kind;
                    return std::strcmp(a.name, b.name) < 0;
                });
            }
            std::lock_guard<std::mutex> lock(g_lock);
            g_entries.swap(entries);
            g_ready = clan != 0;
        }

        uintptr_t FindMercRow(const char* key)
        {
            const uintptr_t table = Ptr(g_mercGlobal);
            uint32_t count = 0;
            if (!table || !mem::Read32(table + kOff_Table_Count, &count)) return 0;
            for (uint32_t i = 0; i < count; ++i)
            {
                const uintptr_t row = RowPtr(g_mercGlobal, i);
                char k[40];
                if (row && ReadCString(Ptr(Ptr(row + kOff_Row_String)), k, sizeof(k)) && std::strcmp(k, key) == 0)
                    return row;
            }
            return 0;
        }

        // Keeps the Pet row's limits at the requested values (or the captured
        // originals). Table rows are shared data, so this is a write only when
        // the value differs.
        void ApplyLimits()
        {
            if (!g_petRow) g_petRow = FindMercRow("Pet");
            if (!g_petRow) return;
            if (!g_petOriginalsKnown)
            {
                if (!mem::Read32(g_petRow + kOff_Merc_HireLimit, &g_petHireOriginal) ||
                    !mem::Read32(g_petRow + kOff_Merc_SummonLimit, &g_petSummonOriginal))
                    return;
                g_petOriginalsKnown = true;
                LOG("mercenary: Pet limits hire=%u summon=%u", g_petHireOriginal, g_petSummonOriginal);
            }
            const State& st = State::Get();
            const uint32_t hire = st.petSlotLimit ? static_cast<uint32_t>(st.petSlotLimitVal) : g_petHireOriginal;
            const int summonReq = g_petSummonLimit.load();
            const uint32_t summon = summonReq > 0 ? static_cast<uint32_t>(summonReq) : g_petSummonOriginal;
            uint32_t cur = 0;
            if (mem::Read32(g_petRow + kOff_Merc_HireLimit, &cur) && cur != hire) mem::Write32(g_petRow + kOff_Merc_HireLimit, hire);
            if (mem::Read32(g_petRow + kOff_Merc_SummonLimit, &cur) && cur != summon) mem::Write32(g_petRow + kOff_Merc_SummonLimit, summon);
        }

        bool ReadPos(uintptr_t owner, float* out3)
        {
            const uintptr_t sub = owner ? Ptr(owner + kOff_Owner_Sub) : 0;
            const uintptr_t tf = sub ? Ptr(sub + kOff_Sub_Transform) : 0;
            if (!tf || !IsClass(tf, ".?AVServerTransformSyncActorComponent@pa@@")) return false;
            for (int i = 0; i < 3; ++i)
            {
                uint32_t bits = 0;
                if (!mem::Read32(tf + kOff_Transform_Pos + 4 * i, &bits)) return false;
                std::memcpy(&out3[i], &bits, 4);
            }
            // World position, as the spawn cheat expects it. The raw float3 is
            // sector-local: sending it spawned bodies in sector (0,0), which only
            // matched the player's spot by chance.
            uint16_t sx = 0, sz = 0;
            if (!mem::Read16(tf + kOff_Transform_Sector, &sx) || !mem::Read16(tf + kOff_Transform_Sector + 2, &sz))
                return false;
            out3[0] += static_cast<float>(static_cast<int16_t>(sx)) * kSectorSize;
            out3[2] += static_cast<float>(static_cast<int16_t>(sz)) * kSectorSize;
            return std::isfinite(out3[0]) && std::isfinite(out3[1]) && std::isfinite(out3[2]);
        }

        void BuildNearby()
        {
            std::vector<Mercenary::Nearby> list;
            float me[3];
            const uintptr_t mgr = Ptr(Ptr(Player::GetCharMgrGlobal()));
            if (mgr && ReadPos(Player::GetControlledOwner(), me))
            {
                const uintptr_t data = Ptr(mgr + kOff_ActorMgr_List);
                uint32_t count = 0;
                mem::Read32(mgr + kOff_ActorMgr_Count, &count);
                for (uint32_t i = 0; data && i < count && i < 8192; ++i)
                {
                    const uintptr_t actor = Ptr(data + 8ull * i);
                    // Party members / already-owned mercenaries live in the child pool.
                    if (!actor || !IsClass(actor, ".?AVServerNormalInGameActor@pa@@")) continue;
                    float pos[3];
                    if (!ReadPos(actor, pos)) continue;
                    const float dx = pos[0] - me[0], dz = pos[2] - me[2];
                    const float dist = sqrtf(dx * dx + dz * dz);
                    if (dist > kNearbyRadius) continue;

                    const uintptr_t status = Ptr(Ptr(actor + kOff_Owner_Sub) + kOff_Sub_Status);
                    uint16_t charRow = 0xFFFF;
                    if (!status || !mem::Read16(status + kOff_Status_CharRow, &charRow)) continue;
                    const uintptr_t crow = RowPtr(g_charGlobal, charRow);
                    uint16_t mercRow = 0xFFFF;
                    if (!crow || !mem::Read16(crow + kOff_Char_MercenaryInfo, &mercRow) || mercRow == 0xFFFF) continue;
                    const uintptr_t mrow = RowPtr(g_mercGlobal, mercRow);
                    uint8_t type = 0;
                    if (!mrow || !mem::Read8(mrow + kOff_Merc_Type, &type) ||
                        type == kType_Observer || type == kType_RecoveryItem)
                        continue;

                    Mercenary::Nearby n{};
                    if (!mem::Read32(actor + kOff_Actor_Handle, &n.handle) || !n.handle) continue;
                    n.charRow = charRow;
                    n.distance = dist;
                    n.kind = KindOf(type);
                    mem::Read32(crow + kOff_Row_Key, &n.characterKey);
                    char key[64];
                    ReadCString(Ptr(Ptr(crow + kOff_Row_String)), key, sizeof(key));
                    if (const char* en = EnglishName(n.characterKey)) snprintf(n.name, sizeof(n.name), "%s", en);
                    else snprintf(n.name, sizeof(n.name), "%s", key);
                    ReadCString(Ptr(Ptr(mrow + kOff_Row_String)), n.typeKey, sizeof(n.typeKey));
                    list.push_back(n);
                }
                std::sort(list.begin(), list.end(), [](const Mercenary::Nearby& a, const Mercenary::Nearby& b) {
                    return a.distance < b.distance;
                });
                if (list.size() > kNearbyMax) list.resize(kNearbyMax);
            }
            std::lock_guard<std::mutex> lock(g_lock);
            g_nearby.swap(list);
        }

        uintptr_t ClientClan()
        {
            const uintptr_t actor = Inventory::ClientActorAddr();
            const uintptr_t sub = actor ? Ptr(actor + kOff_Owner_Sub) : 0;
            const uintptr_t clan = sub ? Ptr(sub + kOff_Sub_Clan) : 0;
            return clan && IsClass(clan, ".?AVClientMercenaryClanActorComponent@pa@@") ? clan : 0;
        }

        uintptr_t FindRecord(uintptr_t clan, uint32_t number)
        {
            if (!clan) return 0;
            const uintptr_t vec = Ptr(clan + kOff_Clan_Vector);
            uint32_t count = 0;
            mem::Read32(clan + kOff_Clan_Count, &count);
            for (uint32_t i = 0; vec && i < count && i < 512; ++i)
            {
                const uintptr_t rec = Ptr(vec + 8ull * i);
                uint32_t no = 0;
                if (rec && mem::Read32(rec + kOff_Rec_Number, &no) && no == number) return rec;
            }
            return 0;
        }

        uint16_t MercRowOf(uint16_t charRow)
        {
            uint16_t merc = 0xFFFF;
            const uintptr_t crow = RowPtr(g_charGlobal, charRow);
            if (crow) mem::Read16(crow + kOff_Char_MercenaryInfo, &merc);
            return merc;
        }

        void BuildSpecies(uint32_t number, bool anyFamily)
        {
            std::vector<Mercenary::Species> list;
            const uintptr_t rec = FindRecord(PlayerClan(), number);
            uint16_t srcRow = 0xFFFF;
            const uint16_t family = rec && mem::Read16(rec + kOff_Rec_CharRow, &srcRow) ? MercRowOf(srcRow) : 0xFFFF;
            // A mount only becomes rideable rows (any vehicle family: horse, dragon,
            // special, war machine); verified live: deer -> Riding_Dragon_1 summons a
            // dragon that rides and flies like the native one.
            uint8_t srcType = 0;
            if (const uintptr_t m = family != 0xFFFF ? RowPtr(g_mercGlobal, family) : 0) mem::Read8(m + kOff_Merc_Type, &srcType);
            const uintptr_t table = Ptr(g_charGlobal);
            uint32_t count = 0;
            if (family != 0xFFFF && table && mem::Read32(table + kOff_Table_Count, &count))
            {
                for (uint32_t r = 0; r < count && r < 0x10000; ++r)
                {
                    if (r == srcRow) continue;
                    const uintptr_t crow = RowPtr(g_charGlobal, r);
                    uint16_t merc = 0xFFFF;
                    if (!crow || !mem::Read16(crow + kOff_Char_MercenaryInfo, &merc) || merc == 0xFFFF) continue;
                    const uintptr_t mrow = RowPtr(g_mercGlobal, merc);
                    uint8_t type = 0;
                    if (!mrow || !mem::Read8(mrow + kOff_Merc_Type, &type)) continue;
                    if (anyFamily)
                    {
                        // Creatures only: vehicles, wagons, pets, domestic animals.
                        if (srcType == kType_Vehicle)
                        {
                            uint16_t vehicle = 0xFFFF;
                            if (type != kType_Vehicle || !mem::Read16(crow + kOff_Char_VehicleInfo, &vehicle) || vehicle == 0xFFFF) continue;
                            // The plain "Vehicle" family (wild wyverns, elephant, camels...) is
                            // never listed by the game's summon menus: a mount swapped into it
                            // vanishes (verified live with Animal_Wyvern_30507 / Riding_Elephant_1).
                            // Horse, Dragon, Special and WarMachine families are callable.
                            char family[40];
                            if (!ReadCString(Ptr(Ptr(mrow + kOff_Row_String)), family, sizeof(family)) ||
                                std::strcmp(family, "Vehicle") == 0) continue;
                        }
                        else if (type != kType_Vehicle && type != kType_Wagon && type != kType_Pet && type != kType_Domestic) continue;
                    }
                    else if (merc != family) continue;

                    Mercenary::Species sp{};
                    sp.row = static_cast<uint16_t>(r);
                    mem::Read32(crow + kOff_Row_Key, &sp.key);
                    char key[64];
                    if (!ReadCString(Ptr(Ptr(crow + kOff_Row_String)), key, sizeof(key))) continue;
                    // Show the internal key too: several rows share an English name
                    // ("Wyvern" is both the wild enemy and the rideable mount).
                    if (const char* en = EnglishName(sp.key)) snprintf(sp.name, sizeof(sp.name), "%s (%s)", en, key);
                    else snprintf(sp.name, sizeof(sp.name), "%s", key);
                    ReadCString(Ptr(Ptr(mrow + kOff_Row_String)), sp.typeKey, sizeof(sp.typeKey));
                    list.push_back(sp);
                }
                std::sort(list.begin(), list.end(), [](const Mercenary::Species& a, const Mercenary::Species& b) {
                    const int c = std::strcmp(a.name, b.name);
                    return c != 0 ? c < 0 : a.key < b.key;
                });
            }
            std::lock_guard<std::mutex> lock(g_lock);
            g_species.swap(list);
        }

        void ApplyChange(uint32_t number, uint16_t row)
        {
            if (MercRowOf(row) == 0xFFFF) return;
            const uintptr_t server = FindRecord(PlayerClan(), number);
            const uintptr_t client = FindRecord(ClientClan(), number);
            // A summoned mercenary keeps its spawned body (and the icon built from it)
            // until it is unsummoned, so the swap would only show after a reload.
            // Verified live: swapping while unsummoned updates the menus at once and
            // the next summon spawns the new species.
            uint32_t actor = 0;
            if (server && mem::Read32(server + kOff_Rec_Actor, &actor) && actor)
            {
                std::lock_guard<std::mutex> lock(g_lock);
                snprintf(g_status, sizeof(g_status), "It is summoned: unsummon it first, then change it.");
                return;
            }
            const bool ok = server && mem::Write16(server + kOff_Rec_CharRow, row);
            if (ok && client) mem::Write16(client + kOff_Rec_CharRow, row);
            LOG("mercenary: species #%u -> row %u (server=%d client=%d)", number, row, ok ? 1 : 0, client ? 1 : 0);
            std::lock_guard<std::mutex> lock(g_lock);
            snprintf(g_status, sizeof(g_status), ok ? "Species changed. Summon it to see the new body."
                                                    : "Species change failed: mercenary not found.");
        }

        void SetStatus(const char* fmt, const char* arg)
        {
            std::lock_guard<std::mutex> lock(g_lock);
            snprintf(g_status, sizeof(g_status), fmt, arg);
        }

        // Families the game's summon menus list. The plain "Vehicle" family
        // (wild wyverns, elephant, camels) is never listed: verified live.
        bool CallableMountFamily(uint16_t mercRow)
        {
            const uintptr_t mrow = mercRow != 0xFFFF ? RowPtr(g_mercGlobal, mercRow) : 0;
            uint8_t type = 0;
            char family[40];
            return mrow && mem::Read8(mrow + kOff_Merc_Type, &type) && type == kType_Vehicle &&
                   ReadCString(Ptr(Ptr(mrow + kOff_Row_String)), family, sizeof(family)) &&
                   std::strcmp(family, "Vehicle") != 0;
        }

        uint16_t VehicleRowOf(uint16_t charRow)
        {
            const uintptr_t crow = RowPtr(g_charGlobal, charRow);
            uint16_t vehicle = 0xFFFF;
            return crow && mem::Read16(crow + kOff_Char_VehicleInfo, &vehicle) ? vehicle : 0xFFFF;
        }

        // Rideable row with the same vehicle type in a callable family,
        // preferring the player-mount rows ("Riding_*").
        uint16_t CallableEquivalent(uint16_t charRow)
        {
            const uint16_t vehicle = VehicleRowOf(charRow);
            const uintptr_t table = Ptr(g_charGlobal);
            uint32_t count = 0;
            if (vehicle == 0xFFFF || !table || !mem::Read32(table + kOff_Table_Count, &count)) return 0xFFFF;
            uint16_t best = 0xFFFF;
            for (uint32_t r = 0; r < count && r < 0x10000; ++r)
            {
                if (VehicleRowOf(static_cast<uint16_t>(r)) != vehicle || !CallableMountFamily(MercRowOf(static_cast<uint16_t>(r))))
                    continue;
                char key[64];
                if (!ReadCString(Ptr(Ptr(RowPtr(g_charGlobal, r) + kOff_Row_String)), key, sizeof(key))) continue;
                if (std::strncmp(key, "Riding_", 7) == 0) return static_cast<uint16_t>(r);
                if (best == 0xFFFF) best = static_cast<uint16_t>(r);
            }
            return best;
        }

        uintptr_t StatusDataOf(uintptr_t owner)
        {
            const uintptr_t comp = owner ? Ptr(Ptr(owner + kOff_Owner_Sub) + kOff_Sub_Status) : 0;
            const uintptr_t data = comp ? Ptr(comp + kOff_StatusComp_Data) : 0;
            // The block points back at its component: cheap sanity check.
            return data && Ptr(data) == comp ? data : 0;
        }

        uintptr_t ValueSlot(uintptr_t data, int index)
        {
            uint32_t count = 0;
            const uintptr_t vals = Ptr(data + kOff_StatusData_Vals);
            if (!vals || !mem::Read32(data + kOff_StatusData_Count, &count) || static_cast<uint32_t>(index) >= count || count > 256)
                return 0;
            return vals + kSizeof_StatusVal * index;
        }

        uintptr_t GaugeSlot(uintptr_t data, int type)
        {
            const uintptr_t arr = Ptr(data + kOff_StatusData_Gauges);
            for (int i = 0; arr && i < 32; ++i)
            {
                int32_t t = -1;
                if (mem::Read32(arr + kSizeof_StatEntry * i, reinterpret_cast<uint32_t*>(&t)) && t == type)
                    return arr + kSizeof_StatEntry * i;
            }
            return 0;
        }

        // Summoned body of a mercenary on both sides (server actor list, client
        // tracked mounts); either may be 0.
        void MountBodies(uint32_t number, uintptr_t* serverOwner, uintptr_t* clientOwner)
        {
            *serverOwner = *clientOwner = 0;
            const uintptr_t rec = FindRecord(PlayerClan(), number);
            uint32_t handle = 0;
            if (!rec || !mem::Read32(rec + kOff_Rec_Actor, &handle) || !handle) return;
            const uintptr_t mgr = Ptr(Ptr(Player::GetCharMgrGlobal()));
            const uintptr_t data = mgr ? Ptr(mgr + kOff_ActorMgr_List) : 0;
            uint32_t count = 0;
            if (data) mem::Read32(mgr + kOff_ActorMgr_Count, &count);
            for (uint32_t i = 0; i < count && i < 8192 && !*serverOwner; ++i)
            {
                const uintptr_t a = Ptr(data + 8ull * i);
                uint32_t h = 0;
                if (a && mem::Read32(a + kOff_Actor_Handle, &h) && h == handle) *serverOwner = a;
            }
            // Client side: the player's ClientChildContainerActorComponent (sub+0x18)
            // keeps every summoned mercenary in +0x18 = 100 x {actor*, u8 inUse},
            // with the same handle as the server body (verified live).
            const uintptr_t player = Inventory::ClientActorAddr();
            const uintptr_t container = player ? Ptr(Ptr(player + kOff_Owner_Sub) + 0x18) : 0;
            const uintptr_t slots = container ? Ptr(container + 0x18) : 0;
            for (uint32_t i = 0; slots && i < 100 && !*clientOwner; ++i)
            {
                const uintptr_t a = Ptr(slots + 0x10ull * i);
                uint32_t h = 0;
                if (a && a != *serverOwner && mem::Read32(a + kOff_Actor_Handle, &h) && h == handle) *clientOwner = a;
            }
        }

        void WriteValue(uintptr_t data, int index, int units)
        {
            const uintptr_t slot = units >= 0 && data ? ValueSlot(data, index) : 0;
            int64_t cur = 0;
            const int64_t want = int64_t{units} * 1000;
            if (slot && mem::Read64(slot, reinterpret_cast<uint64_t*>(&cur)) && cur != want)
                mem::Write64(slot, static_cast<uint64_t>(want));
        }

        void WriteGaugeMax(uintptr_t data, int type, int units)
        {
            const uintptr_t e = units > 0 && data ? GaugeSlot(data, type) : 0;
            int64_t base = 0;
            const int64_t want = int64_t{units} * 1000;
            if (!e || !mem::Read64(e + kOff_StatEntry_Base, reinterpret_cast<uint64_t*>(&base)) || base == want) return;
            mem::Write64(e + kOff_StatEntry_Base, static_cast<uint64_t>(want));
            mem::Write64(e + kOff_StatEntry_Current, static_cast<uint64_t>(want));
            mem::Write64(e + kOff_StatEntry_Norm, 0);
        }

        // Overrides persist in Trinity_mounts.ini next to Trinity.asi, one line per
        // mercenary number: number=attack,defense,maxHp,maxVigor,speed,accel,turn,jump
        // (-1 = game value). Numbers are per save, so another save's mount with the
        // same number would pick the line up too.
        bool OverridesPath(char* buf, size_t cap)
        {
            const DWORD n = GetModuleFileNameA(Mod::Get().Module(), buf, static_cast<DWORD>(cap));
            char* slash = n && n < cap ? strrchr(buf, '\\') : nullptr;
            if (!slash) return false;
            const size_t left = cap - static_cast<size_t>(slash + 1 - buf);
            return snprintf(slash + 1, left, "Trinity_mounts.ini") < static_cast<int>(left);
        }

        void SaveOverrides()   // caller holds g_statsLock
        {
            char path[MAX_PATH];
            FILE* f = nullptr;
            if (!OverridesPath(path, sizeof(path)) || fopen_s(&f, path, "w") != 0 || !f) return;
            fprintf(f, "; Trinity mount stat overrides: number=attack,defense,maxHp,maxVigor,speed,accel,turn,jump\n");
            for (const auto& [n, s] : g_statOverrides)
                fprintf(f, "%u=%d,%d,%d,%d,%d,%d,%d,%d\n", n, s.attack, s.defense, s.maxHp, s.maxVigor,
                        s.speed, s.accel, s.turn, s.jump);
            fclose(f);
        }

        void LoadOverrides()
        {
            char path[MAX_PATH];
            FILE* f = nullptr;
            if (!OverridesPath(path, sizeof(path)) || fopen_s(&f, path, "r") != 0 || !f) return;
            std::lock_guard<std::mutex> lock(g_statsLock);
            char line[160];
            while (fgets(line, sizeof(line), f))
            {
                uint32_t n = 0;
                Mercenary::MountStats s;
                if (sscanf_s(line, "%u=%d,%d,%d,%d,%d,%d,%d,%d", &n, &s.attack, &s.defense, &s.maxHp, &s.maxVigor,
                             &s.speed, &s.accel, &s.turn, &s.jump) == 9 && n)
                    g_statOverrides.emplace_back(n, s);
            }
            fclose(f);
            if (!g_statOverrides.empty())
                LOG("mercenary: loaded %zu mount stat override(s)", g_statOverrides.size());
        }

        void ApplyStatOverrides()
        {
            std::vector<std::pair<uint32_t, Mercenary::MountStats>> list;
            {
                std::lock_guard<std::mutex> lock(g_statsLock);
                list = g_statOverrides;
            }
            for (const auto& [number, s] : list)
            {
                uintptr_t so = 0, co = 0;
                MountBodies(number, &so, &co);
                for (const uintptr_t owner : { so, co })
                {
                    const uintptr_t data = StatusDataOf(owner);
                    if (!data) continue;
                    WriteValue(data, kVal_Attack, s.attack);
                    WriteValue(data, kVal_Defense, s.defense);
                    WriteValue(data, kVal_Speed, s.speed);
                    WriteValue(data, kVal_Accel, s.accel);
                    WriteValue(data, kVal_Turn, s.turn);
                    WriteValue(data, kVal_Jump, s.jump);
                    WriteGaugeMax(data, kGauge_Hp, s.maxHp);
                    WriteGaugeMax(data, kGauge_Vigor, s.maxVigor);
                }
            }
        }

        // Rows that are the player, the party or engine actors: spawning them
        // duplicates the controlled character or a world singleton.
        bool IsSystemCharacterKey(const char* key)
        {
            static const char* const kSkip[] = { "Kliff", "Damian", "Oongka", "PlayerAll", "WorldObserver",
                                                 "MainVehicle", "Object_", "Wall", "Docking" };
            for (const char* p : kSkip)
                if (!_strnicmp(key, p, strlen(p))) return true;
            return false;
        }

        Mercenary::CatalogKind ClassifyCharacterKey(const char* key)
        {
            using K = Mercenary::CatalogKind;
            if (strstr(key, "Boss")) return K::Bosses;
            if (!_strnicmp(key, "MON_", 4) || !_strnicmp(key, "NatureCreature", 14) || !_strnicmp(key, "Marionette", 10))
                return K::Monsters;
            if (!_strnicmp(key, "Animal_", 7)) return K::Animals;
            // NPC keys: N + 1..3 capitals + '_' (NHM_, NHW_, NGM_, NDEM_...) or Marni_.
            if (key[0] == 'N')
            {
                int caps = 0;
                while (caps < 4 && key[1 + caps] >= 'A' && key[1 + caps] <= 'Z') ++caps;
                if (caps >= 1 && caps <= 3 && key[1 + caps] == '_') return K::People;
            }
            if (!_strnicmp(key, "Marni_", 6)) return K::People;
            return K::Others;
        }

        const char* CatalogKindLabel(Mercenary::CatalogKind k)
        {
            switch (k)
            {
            case Mercenary::CatalogKind::Bosses:   return "Boss";
            case Mercenary::CatalogKind::Monsters: return "Monster";
            case Mercenary::CatalogKind::Animals:  return "Animal";
            case Mercenary::CatalogKind::People:   return "Person";
            default:                               return "Other";
            }
        }

        void BuildCharacterCatalog(Mercenary::CatalogKind kind, std::vector<Mercenary::Species>* list)
        {
            const uintptr_t table = Ptr(g_charGlobal);
            uint32_t count = 0;
            if (!table || !mem::Read32(table + kOff_Table_Count, &count)) return;
            for (uint32_t r = 0; r < count && r < 0x10000; ++r)
            {
                const uintptr_t crow = RowPtr(g_charGlobal, r);
                char key[96];
                if (!crow || !ReadCString(Ptr(Ptr(crow + kOff_Row_String)), key, sizeof(key)) || !key[0]) continue;
                uint8_t native = 0;
                mem::Read8(crow + kOff_Char_NativeType, &native);
                if (native == kNative_Player || native == kNative_Object) continue;
                if (IsSystemCharacterKey(key) || ClassifyCharacterKey(key) != kind) continue;
                Mercenary::Species sp{};
                sp.row = static_cast<uint16_t>(r);
                mem::Read32(crow + kOff_Row_Key, &sp.key);
                if (const char* en = EnglishName(sp.key)) snprintf(sp.name, sizeof(sp.name), "%s (%s)", en, key);
                else snprintf(sp.name, sizeof(sp.name), "%s", key);
                snprintf(sp.typeKey, sizeof(sp.typeKey), "%s", CatalogKindLabel(kind));
                list->push_back(sp);
            }
        }

        void BuildCatalog(Mercenary::CatalogKind kind)
        {
            std::vector<Mercenary::Species> list;
            const uintptr_t table = Ptr(g_charGlobal);
            uint32_t count = 0;
            if (kind != Mercenary::CatalogKind::Mounts && kind != Mercenary::CatalogKind::Pets)
            {
                BuildCharacterCatalog(kind, &list);
                std::sort(list.begin(), list.end(), [](const Mercenary::Species& a, const Mercenary::Species& b) {
                    const int c = std::strcmp(a.name, b.name);
                    return c != 0 ? c < 0 : a.key < b.key;
                });
            }
            else if (table && mem::Read32(table + kOff_Table_Count, &count))
            {
                for (uint32_t r = 0; r < count && r < 0x10000; ++r)
                {
                    const uintptr_t crow = RowPtr(g_charGlobal, r);
                    uint16_t merc = 0xFFFF;
                    if (!crow || !mem::Read16(crow + kOff_Char_MercenaryInfo, &merc) || merc == 0xFFFF) continue;
                    const uintptr_t mrow = RowPtr(g_mercGlobal, merc);
                    uint8_t type = 0;
                    if (!mrow || !mem::Read8(mrow + kOff_Merc_Type, &type)) continue;
                    if (kind == Mercenary::CatalogKind::Mounts)
                    {
                        // Only what the summon menus can call (see CallableMountFamily).
                        if (VehicleRowOf(static_cast<uint16_t>(r)) == 0xFFFF || !CallableMountFamily(merc)) continue;
                    }
                    else if (type != kType_Pet && type != kType_Domestic) continue;

                    Mercenary::Species sp{};
                    sp.row = static_cast<uint16_t>(r);
                    mem::Read32(crow + kOff_Row_Key, &sp.key);
                    char key[64];
                    if (!ReadCString(Ptr(Ptr(crow + kOff_Row_String)), key, sizeof(key))) continue;
                    if (const char* en = EnglishName(sp.key)) snprintf(sp.name, sizeof(sp.name), "%s (%s)", en, key);
                    else snprintf(sp.name, sizeof(sp.name), "%s", key);
                    ReadCString(Ptr(Ptr(mrow + kOff_Row_String)), sp.typeKey, sizeof(sp.typeKey));
                    list.push_back(sp);
                }
                std::sort(list.begin(), list.end(), [](const Mercenary::Species& a, const Mercenary::Species& b) {
                    const int c = std::strcmp(a.name, b.name);
                    return c != 0 ? c < 0 : a.key < b.key;
                });
            }
            std::lock_guard<std::mutex> lock(g_lock);
            g_catalog.swap(list);
        }

        // RTTI class name of an engine object (".?AVServerNormalInGameActor@pa@@").
        bool ClassName(uintptr_t obj, char* out, size_t cap)
        {
            const uintptr_t vt = Ptr(obj);
            const uintptr_t col = vt ? Ptr(vt - 8) : 0;
            uint32_t tdRva = 0;
            if (!col || !mem::Read32(col + 0x0C, &tdRva)) return false;
            return ReadCString(reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)) + tdRva + 0x10, out, cap);
        }

        // Server status component of an actor (characterinfo row +0x30,
        // faction +0x342), 0 if it is not one.
        uintptr_t ServerStatusOf(uintptr_t actor)
        {
            const uintptr_t status = actor ? Ptr(Ptr(actor + kOff_Owner_Sub) + kOff_Sub_Status) : 0;
            return status && IsClass(status, ".?AVServerStatusActorComponent@pa@@") ? status : 0;
        }

        // Every server actor with a status component: visit(actor, handle, row).
        template <class F>
        void ForEachServerActor(F&& visit)
        {
            const uintptr_t mgr = Ptr(Ptr(Player::GetCharMgrGlobal()));
            const uintptr_t data = mgr ? Ptr(mgr + kOff_ActorMgr_List) : 0;
            uint32_t count = 0;
            if (!data || !mem::Read32(mgr + kOff_ActorMgr_Count, &count)) return;
            for (uint32_t i = 0; i < count && i < 8192; ++i)
            {
                const uintptr_t actor = Ptr(data + 8ull * i);
                const uintptr_t status = actor ? Ptr(Ptr(actor + kOff_Owner_Sub) + kOff_Sub_Status) : 0;
                uint16_t r = 0xFFFF;
                uint32_t handle = 0;
                if (!status || !mem::Read16(status + kOff_Status_CharRow, &r) ||
                    !mem::Read32(actor + kOff_Actor_Handle, &handle) || !handle ||
                    !IsClass(status, ".?AVServerStatusActorComponent@pa@@"))
                    continue;
                visit(actor, handle, r);
            }
        }

        Allegiance AllegianceOf(Mercenary::SpawnSide side)
        {
            using S = Mercenary::SpawnSide;
            return side == S::Ally ? Allegiance::Ally : side == S::Enemy ? Allegiance::Enemy
                 : side == S::Neutral ? Allegiance::Neutral : Allegiance::None;
        }

        // Every server actor of a characterinfo row, any actor class.
        template <class F>
        void ForEachActorOfRow(uint16_t row, F&& visit)
        {
            ForEachServerActor([&](uintptr_t actor, uint32_t handle, uint16_t r) {
                if (r == row) visit(actor, handle);
            });
        }

        // --- Despawn ------------------------------------------------------------
        // The engine removes a child actor with 0x142068340(actor, &status, 7,
        // *(u32*)0x146CDB940) (Denuvo-virtualized; called per child by the
        // container's remove-all, vtable slot 6 = 0x142119F10), holding a lease
        // from the ServerActorManager handle lookup (0x142A82370, released by
        // 0x141434880). DesertLink's despawn is that same call on one actor.
        // Runs on the server thread through troc::PostMainTask.
        constexpr const char* kSig_RemoveChildCall =
            "44 8B 0D ?? ?? ?? ?? 41 B0 07 48 8D 94 24 98 00 00 00 48 8B CB E8";
        constexpr const char* kSig_LeaseRelease =
            "48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20 48 8B F1 80 79 10 00 74 ?? 48 8B 79 08 80 79 11 00 75";
        // mov rcx,[rip+mgrGlobal]; mov rcx,[rcx]; call lookup - every manager uses
        // one of five byte-identical lookup instances; the ServerActorManager
        // global is the one whose object carries that RTTI.
        constexpr const char* kSig_ManagerLookupCall = "48 8B 0D ?? ?? ?? ?? 48 8B 09 E8";
        constexpr uint8_t kLookupPrologue[] = { 0x44, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10,
                                                0x53, 0x55, 0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x30 };

        struct alignas(8) ActorLease
        {
            uintptr_t vt = 0;
            uintptr_t actor = 0;
            uint8_t   valid = 0;   // the lookup pinned the actor
            uint8_t   flag = 0;
            uint8_t   pad[6] = {};
            uintptr_t extra = 0;
        };
        using LeaseAcquireFn = void*(__fastcall*)(uintptr_t mgr, ActorLease* out, uint32_t handle);
        using LeaseReleaseFn = void(__fastcall*)(ActorLease* lease);
        using RemoveActorFn  = void(__fastcall*)(uintptr_t actor, uint32_t* status, uint8_t reason, uint32_t code);
        LeaseAcquireFn g_leaseAcquire = nullptr;
        LeaseReleaseFn g_leaseRelease = nullptr;
        RemoveActorFn  g_removeActor = nullptr;
        uintptr_t      g_actorMgrGlobal = 0, g_removeCodeGlobal = 0;
        bool           g_removeSigsTried = false;

        bool BytesEqual(uintptr_t at, const uint8_t* want, size_t n)
        {
            for (size_t i = 0; i < n; ++i)
            {
                uint8_t b = 0;
                if (!mem::Read8(at + i, &b) || b != want[i]) return false;
            }
            return true;
        }

        bool ResolveDespawn()
        {
            if (g_leaseAcquire && g_leaseRelease && g_removeActor) return true;
            if (!g_removeSigsTried)
            {
                g_removeSigsTried = true;
                if (const uintptr_t site = mem::FindPattern(kSig_RemoveChildCall))
                {
                    g_removeCodeGlobal = mem::ResolveRipAt(site, 7);
                    g_removeActor = reinterpret_cast<RemoveActorFn>(mem::ResolveCall(site + 21));
                }
                g_leaseRelease = reinterpret_cast<LeaseReleaseFn>(mem::FindPattern(kSig_LeaseRelease));
                if (!g_removeActor || !g_leaseRelease)
                    LOG_WARN("mercenary: despawn signatures not found (remove=%p release=%p)",
                             reinterpret_cast<void*>(g_removeActor), reinterpret_cast<void*>(g_leaseRelease));
            }
            if (!g_removeActor || !g_leaseRelease) return false;
            // The manager object only exists in a loaded world; retried per request.
            const ULONGLONG t0 = GetTickCount64();
            const auto sites = mem::FindAllMatches(kSig_ManagerLookupCall, 200000);
            std::unordered_set<uintptr_t> notManager;   // globals already rejected
            for (const uintptr_t site : sites)
            {
                const uintptr_t g = mem::ResolveRipAt(site, 7);
                const uintptr_t fn = mem::ResolveCall(site + 10);
                if (notManager.count(g) || !BytesEqual(fn, kLookupPrologue, sizeof(kLookupPrologue))) continue;
                const uintptr_t mgr = Ptr(Ptr(g));
                if (!mgr || !IsClass(mgr, ".?AVServerActorManager@pa@@"))
                {
                    notManager.insert(g);
                    continue;
                }
                g_actorMgrGlobal = g;
                g_leaseAcquire = reinterpret_cast<LeaseAcquireFn>(fn);
                break;
            }
            LOG("mercenary: despawn backend %s (manager global %p, lookup %p, remove %p, %zu sites, %llu ms)",
                g_leaseAcquire ? "ready" : "NOT found", reinterpret_cast<void*>(g_actorMgrGlobal),
                reinterpret_cast<void*>(g_leaseAcquire), reinterpret_cast<void*>(g_removeActor), sites.size(),
                GetTickCount64() - t0);
            return g_leaseAcquire != nullptr;
        }

        // Server thread. Returns the engine status (0 = removed), kDespawnNotFound
        // when the handle no longer names that body, kDespawnFault on a fault.
        uint32_t DespawnOnServer(uint32_t handle, uint16_t row)
        {
            const uintptr_t mgr = Ptr(Ptr(g_actorMgrGlobal));
            if (!mgr || !g_leaseAcquire || !g_leaseRelease || !g_removeActor) return kDespawnFault;
            ActorLease lease;
            __try { g_leaseAcquire(mgr, &lease, handle); }
            __except (EXCEPTION_EXECUTE_HANDLER) { return kDespawnFault; }
            uint32_t status = kDespawnNotFound;
            if (lease.valid && lease.actor)
            {
                uint32_t h = 0;
                uint16_t r = 0xFFFF;
                const uintptr_t st = ServerStatusOf(lease.actor);
                if (mem::Read32(lease.actor + kOff_Actor_Handle, &h) && h == handle && st &&
                    mem::Read16(st + kOff_Status_CharRow, &r) && r == row)
                {
                    uint32_t code = 0;
                    mem::Read32(g_removeCodeGlobal, &code);
                    status = 0xFFFFFFFF;
                    __try { g_removeActor(lease.actor, &status, 7, code); }
                    __except (EXCEPTION_EXECUTE_HANDLER) { status = kDespawnFault; }
                }
            }
            __try { g_leaseRelease(&lease); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            return status;
        }

        void RowDisplayName(uint16_t row, char* out, size_t cap)
        {
            const uintptr_t crow = RowPtr(g_charGlobal, row);
            uint32_t key = 0;
            char internal[64] = {};
            if (crow) mem::Read32(crow + kOff_Row_Key, &key);
            if (const char* en = key ? EnglishName(key) : nullptr) snprintf(out, cap, "%s", en);
            else if (crow && ReadCString(Ptr(Ptr(crow + kOff_Row_String)), internal, sizeof(internal)))
                snprintf(out, cap, "%s", internal);
            else snprintf(out, cap, "row %u", row);
        }

        // Spawned bodies join the player's child-actor pool: controlled actor
        // +0xA0 = ServerUserActor, its sub+0x18 = CommonChildContainerActorComponent
        // (+0x08 owner, +0x18 slots of {actor*, u8 inUse at +8}, +0x20 u32 capacity).
        // A full pool makes the spawn cheat create nothing, silently.
        bool ChildPoolUsage(int* used, int* capacity)
        {
            const uintptr_t owner = Player::GetControlledOwner();
            const uintptr_t user = owner ? Ptr(owner + 0xA0) : 0;
            if (!user || !IsClass(user, ".?AVServerUserActor@pa@@")) return false;
            const uintptr_t comp = Ptr(Ptr(user + kOff_Owner_Sub) + 0x18);
            uint32_t cap = 0;
            if (!comp || !IsClass(comp, ".?AVCommonChildContainerActorComponent@pa@@") || Ptr(comp + 0x08) != user ||
                !mem::Read32(comp + 0x20, &cap) || cap == 0 || cap > 0x1000)
                return false;
            const uintptr_t slots = Ptr(comp + 0x18);
            if (!slots) return false;
            int n = 0;
            for (uint32_t i = 0; i < cap; ++i)
            {
                uint8_t inUse = 0;
                if (mem::Read8(slots + 0x10ull * i + 8, &inUse) && inUse) ++n;
            }
            *used = n;
            *capacity = static_cast<int>(cap);
            return true;
        }

        // [actor+0x88]+1 == 1 marks player-controlled bodies (never a spawn).
        bool IsPlayerKind(uintptr_t actor)
        {
            const uintptr_t info = Ptr(actor + 0x88);
            uint8_t kind = 0;
            return info && mem::Read8(info + 1, &kind) && kind == 1;
        }

        void FinishSpawnJob(const char* msg)
        {
            LOG("mercenary: spawn %s (row %u): %d of %d made - %s", g_spawnJob.name, g_spawnJob.row, g_spawnJob.made,
                g_spawnJob.total, msg[0] ? msg : "adopting");
            if (msg[0]) SetStatus("%s", msg);
            g_spawnJob.active = false;
            g_spawnJob.known.clear();
        }

        bool SendNextBody()
        {
            SpawnJob& job = g_spawnJob;
            const float a = kSpawnAngleStep * static_cast<float>(job.sent);
            job.target[0] = job.origin[0] + kSpawnDistance * std::cos(a);
            job.target[1] = job.origin[1];                // DesertLink keeps the player's height too
            job.target[2] = job.origin[2] + kSpawnDistance * std::sin(a);
            job.known.clear();
            ForEachActorOfRow(job.row, [&](uintptr_t, uint32_t handle) { job.known.push_back(handle); });

            uint8_t payload[21] = {};
            std::memcpy(payload + 0, &job.key, 4);       // characterinfo key
            std::memcpy(payload + 8, job.target, 12);    // +4 stays 0
            payload[20] = 1;
            // The spawning character: the controlled server body, as DesertLink
            // sends it (0 = keep the MoveActorReq sender).
            uintptr_t sender = Player::GetControlledOwner();
            if (sender && !IsClass(sender, ".?AVServerNormalInGameActor@pa@@") &&
                !IsClass(sender, ".?AVServerChildOnlyInGameActor@pa@@"))
                sender = 0;
            if (!troc::PostMainAs("TrocTrSpawnCharacterCheatReq", payload, sizeof(payload), sender)) return false;
            ++job.sent;
            job.deadline = GetTickCount64() + kSpawnWaitMs;
            LOG("mercenary: spawn %s row %u key %u body %d/%d at %.1f %.1f %.1f (sender %s, adopt=%d)", job.name, job.row,
                job.key, job.sent, job.total, job.target[0], job.target[1], job.target[2], sender ? "player" : "template",
                job.adopt ? 1 : 0);
            char msg[128];
            if (job.total == 1) snprintf(msg, sizeof(msg), "Spawning %s...", job.name);
            else snprintf(msg, sizeof(msg), "Spawning %s (%d of %d)...", job.name, job.sent, job.total);
            SetStatus("%s", msg);
            return true;
        }

        void StartSpawnJob(const SpawnRequest& req)
        {
            SpawnJob& job = g_spawnJob;
            job = SpawnJob{};
            const uintptr_t crow = RowPtr(g_charGlobal, req.row);
            uint8_t native = 0;
            if (!crow || !mem::Read32(crow + kOff_Row_Key, &job.key) || !job.key)
            {
                SetStatus("%s", "Spawn unavailable: character not found.");
                return;
            }
            mem::Read8(crow + kOff_Char_NativeType, &native);
            job.row = req.row;
            job.adopt = req.adopt;
            job.side = req.side;
            job.total = req.count < 1 ? 1 : (req.count > 10 ? 10 : req.count);
            if (!req.adopt)
            {
                if (g_spawned.size() >= kMaxSpawned)
                {
                    SetStatus("%s", "64 spawned NPCs are alive. Despawn some (Spawned NPCs) before adding more.");
                    return;
                }
                if (job.total > static_cast<int>(kMaxSpawned - g_spawned.size()))
                    job.total = static_cast<int>(kMaxSpawned - g_spawned.size());
            }
            RowDisplayName(req.row, job.name, sizeof(job.name));
            char msg[160];
            if (native == kNative_Player || native == kNative_Object)
            {
                snprintf(msg, sizeof(msg), "%s is a player/system actor and cannot be spawned.", job.name);
                SetStatus("%s", msg);
                return;
            }
            if (native == kNative_Companion)
            {
                bool exists = false;
                ForEachActorOfRow(req.row, [&](uintptr_t, uint32_t) { exists = true; });
                if (exists)
                {
                    snprintf(msg, sizeof(msg), "%s already exists in the world (one body per companion).", job.name);
                    SetStatus("%s", msg);
                    return;
                }
                job.total = 1;
            }
            int used = 0, cap = 0;
            if (ChildPoolUsage(&used, &cap))
            {
                LOG("mercenary: child-actor pool %d/%d before spawning %s", used, cap, job.name);
                if (used >= cap)
                {
                    snprintf(msg, sizeof(msg), "The game's NPC pool is full (%d/%d). Reload the save to clear spawned NPCs.",
                             used, cap);
                    SetStatus("%s", msg);
                    return;
                }
                if (job.total > cap - used) job.total = cap - used;
            }
            if (!ReadPos(Player::GetControlledOwner(), job.origin))
            {
                SetStatus("%s", "Spawn unavailable: player position not found.");
                return;
            }
            job.active = true;
            if (!SendNextBody()) FinishSpawnJob("Spawn unavailable (server pump not ready).");
        }

        // Accepts the new body of the row nearest the requested spot, hires it for
        // Add Any Mount / Pet, then sends the next one; stops at the first body
        // that never shows up.
        void PumpSpawnJob()
        {
            SpawnJob& job = g_spawnJob;
            if (!job.active) return;
            uintptr_t found = 0;
            uint32_t foundHandle = 0;
            float foundDist = 0.0f;
            ForEachActorOfRow(job.row, [&](uintptr_t actor, uint32_t handle) {
                if (std::find(job.known.begin(), job.known.end(), handle) != job.known.end() ||
                    std::find(g_spawnedHandles.begin(), g_spawnedHandles.end(), handle) != g_spawnedHandles.end() ||
                    IsPlayerKind(actor))
                    return;
                float pos[3];
                if (!ReadPos(actor, pos)) return;
                const float dx = pos[0] - job.target[0], dz = pos[2] - job.target[2];
                const float d = sqrtf(dx * dx + dz * dz);
                if (d > kSpawnMatchRadius)
                {
                    if (job.farDist < 0.0f || d < job.farDist) job.farDist = d;
                    return;
                }
                if (!found || d < foundDist) { found = actor; foundHandle = handle; foundDist = d; }
            });
            char msg[160];
            if (found)
            {
                g_spawnedHandles.push_back(foundHandle);
                if (g_spawnedHandles.size() > 512) g_spawnedHandles.erase(g_spawnedHandles.begin());
                ++job.made;
                float pos[3] = {};
                ReadPos(found, pos);
                const float px = pos[0] - job.origin[0], pz = pos[2] - job.origin[2];
                const float fromPlayer = sqrtf(px * px + pz * pz);
                if (job.nearest < 0.0f || fromPlayer < job.nearest) job.nearest = fromPlayer;
                char cls[96] = {};
                ClassName(found, cls, sizeof(cls));
                LOG("mercenary: spawned %s appeared (handle 0x%08X, %s, %.1f m from target)", job.name, foundHandle, cls,
                    foundDist);
                if (job.adopt &&
                    std::find(g_adoptedHandles.begin(), g_adoptedHandles.end(), foundHandle) == g_adoptedHandles.end())
                {
                    g_adoptedHandles.push_back(foundHandle);
                    if (g_adoptedHandles.size() > 256) g_adoptedHandles.erase(g_adoptedHandles.begin());
                    Mercenary::Hire(foundHandle, job.name);
                }
                else if (!job.adopt)
                {
                    SpawnedNpc npc;
                    npc.handle = foundHandle;
                    npc.row = job.row;
                    npc.side = job.side;
                    snprintf(npc.name, sizeof(npc.name), "%s", job.name);
                    if (job.side != Mercenary::SpawnSide::Default &&
                        !Ghost::SetAllegiance(foundHandle, AllegianceOf(job.side)))
                        LOG_WARN("mercenary: %s (0x%08X) keeps its own side - the AI hooks are unavailable", job.name,
                                 foundHandle);
                    g_spawned.push_back(npc);
                }
                if (job.sent < job.total)
                {
                    if (!SendNextBody())
                    {
                        snprintf(msg, sizeof(msg), "Only %d of %d x %s spawned (server pump stopped).", job.made, job.total,
                                 job.name);
                        FinishSpawnJob(msg);
                    }
                    return;
                }
                if (job.adopt) msg[0] = 0;   // Hire() set the status
                else if (job.total > 1) snprintf(msg, sizeof(msg), "Spawned %d x %s.", job.made, job.name);
                else snprintf(msg, sizeof(msg), "%s spawned (%.0f m away).", job.name, job.nearest);
                FinishSpawnJob(msg);
                return;
            }
            if (GetTickCount64() < job.deadline) return;
            if (job.made > 0)
                snprintf(msg, sizeof(msg), "Only %d of %d x %s spawned; the game stopped creating them.", job.made,
                         job.total, job.name);
            else if (job.farDist >= 0.0f)
                snprintf(msg, sizeof(msg), "%s appeared %.0f m from the spot, not beside you.", job.name, job.farDist);
            else
                snprintf(msg, sizeof(msg), "The game did not create %s. Try open, flat ground or another character.",
                         job.name);
            FinishSpawnJob(msg);
        }

        // Despawn requests and results, and dropping bodies that left the world
        // (with their side). Game thread, every 250 ms.
        void PumpTracked(ULONGLONG now)
        {
            if (now < g_nextTrackPump) return;
            g_nextTrackPump = now + 250;
            char msg[160];

            std::vector<DespawnResult> results;
            {
                std::lock_guard<std::mutex> lock(g_despawnLock);
                results.swap(g_despawnResults);
            }
            for (const DespawnResult& r : results)
                for (SpawnedNpc& npc : g_spawned)
                {
                    if (npc.handle != r.handle) continue;
                    npc.despawnQueued = false;
                    LOG("mercenary: despawn %s (0x%08X) -> status 0x%08X", npc.name, npc.handle, r.status);
                    if (r.status == 0)
                    {
                        npc.removing = true;
                        npc.removeUntil = now + 5000;
                    }
                    else
                    {
                        snprintf(msg, sizeof(msg), r.status == kDespawnNotFound ? "%s already left the world."
                                                                                : "The game refused to despawn %s.",
                                 npc.name);
                        SetStatus("%s", msg);
                    }
                }

            std::vector<uint32_t> requests;
            {
                std::lock_guard<std::mutex> lock(g_lock);
                requests.swap(g_despawnReq);
            }
            if (!requests.empty())
            {
                if (!ResolveDespawn())
                    SetStatus("%s", "Despawn unavailable: the game's removal call was not found.");
                else
                {
                    int queued = 0;
                    for (SpawnedNpc& npc : g_spawned)
                    {
                        const bool wanted = std::find(requests.begin(), requests.end(), 0u) != requests.end() ||
                                            std::find(requests.begin(), requests.end(), npc.handle) != requests.end();
                        if (!wanted || npc.removing || npc.despawnQueued) continue;
                        const uint32_t handle = npc.handle;
                        const uint16_t row = npc.row;
                        if (!troc::PostMainTask([handle, row] {
                                const uint32_t status = DespawnOnServer(handle, row);
                                std::lock_guard<std::mutex> lock(g_despawnLock);
                                g_despawnResults.push_back({ handle, status });
                            }))
                            break;
                        npc.despawnQueued = true;
                        ++queued;
                    }
                    if (queued)
                    {
                        snprintf(msg, sizeof(msg), "Despawning %d NPC%s...", queued, queued == 1 ? "" : "s");
                        SetStatus("%s", msg);
                    }
                }
            }

            if (g_spawned.empty())
            {
                std::lock_guard<std::mutex> lock(g_lock);
                g_spawnedView.clear();
                return;
            }
            // One pass over the actor table: which bodies are still there, and where.
            std::unordered_map<uint32_t, uintptr_t> present;
            ForEachServerActor([&](uintptr_t actor, uint32_t handle, uint16_t) { present.emplace(handle, actor); });
            float me[3] = {};
            const bool haveMe = ReadPos(Player::GetControlledOwner(), me);
            int gone = 0;
            const char* lastGone = nullptr;
            static char goneName[64];
            std::vector<Mercenary::SpawnedInfo> view;
            for (size_t i = 0; i < g_spawned.size();)
            {
                SpawnedNpc& npc = g_spawned[i];
                // An empty actor table means the world is changing: keep the list.
                const auto it = present.find(npc.handle);
                if (!present.empty() && it == present.end())
                {
                    if (npc.removing)
                    {
                        ++gone;
                        snprintf(goneName, sizeof(goneName), "%s", npc.name);
                        lastGone = goneName;
                    }
                    Ghost::ClearAllegiance(npc.handle);
                    g_spawned.erase(g_spawned.begin() + i);
                    continue;
                }
                if (npc.removing && now > npc.removeUntil)
                {
                    npc.removing = false;
                    snprintf(msg, sizeof(msg), "%s is still in the world; try Despawn again.", npc.name);
                    SetStatus("%s", msg);
                }
                Mercenary::SpawnedInfo info;
                info.handle = npc.handle;
                snprintf(info.name, sizeof(info.name), "%s", npc.name);
                info.side = npc.side;
                info.removing = npc.removing || npc.despawnQueued;
                float pos[3];
                if (it != present.end() && haveMe && ReadPos(it->second, pos))
                {
                    const float dx = pos[0] - me[0], dz = pos[2] - me[2];
                    info.distance = sqrtf(dx * dx + dz * dz);
                }
                view.push_back(info);
                ++i;
            }
            if (gone == 1) { snprintf(msg, sizeof(msg), "%s despawned.", lastGone); SetStatus("%s", msg); }
            else if (gone > 1) { snprintf(msg, sizeof(msg), "Despawned %d NPCs.", gone); SetStatus("%s", msg); }
            std::lock_guard<std::mutex> lock(g_lock);
            g_spawnedView.swap(view);
        }

        void PumpSpawns(ULONGLONG now)
        {
            PumpTracked(now);
            if (now < g_nextSpawnPump) return;
            g_nextSpawnPump = now + kSpawnPumpMs;
            if (!g_spawnJob.active)
            {
                // A side needs the AI hooks before the first body exists, or the
                // body can engage the player in the meantime (Ghost::Tick installs
                // them on the next frame).
                const bool waitForHooks = !Ghost::Installed() && !Ghost::Failed();
                SpawnRequest sp;
                {
                    std::lock_guard<std::mutex> lock(g_lock);
                    sp = g_spawnReq;
                    if (sp.pending && !(waitForHooks && sp.side != Mercenary::SpawnSide::Default && !sp.adopt))
                        g_spawnReq.pending = false;
                    else
                        sp.pending = false;
                }
                if (sp.pending) StartSpawnJob(sp);
            }
            PumpSpawnJob();
        }

        void TameNearest()
        {
            BuildNearby();
            std::vector<Mercenary::Nearby> list;
            {
                std::lock_guard<std::mutex> lock(g_lock);
                list = g_nearby;
            }
            for (const Mercenary::Nearby& n : list)   // sorted by distance
            {
                if (n.kind != Mercenary::Kind::Mount || VehicleRowOf(n.charRow) == 0xFFFF) continue;
                const uint16_t merc = MercRowOf(n.charRow);
                uint16_t target = n.charRow;
                if (!CallableMountFamily(merc))
                {
                    target = CallableEquivalent(n.charRow);
                    if (target == 0xFFFF) continue;   // no rideable version of this creature
                }
                if (!Mercenary::Hire(n.handle, n.name)) return;
                if (target != n.charRow)
                    g_remap = { n.charRow, target, GetTickCount64() + 15000 };
                LOG("mercenary: taming %s (row %u -> %u, %.0f m)", n.name, n.charRow, target, n.distance);
                return;
            }
            SetStatus("%s", "No tameable mount within 40 m.");
        }

        // Points the freshly hired record at the callable row (server + client).
        void ApplyRemap()
        {
            if (g_remap.toRow == 0xFFFF) return;
            if (GetTickCount64() > g_remap.until) { g_remap = {}; return; }
            const uintptr_t clans[2] = { PlayerClan(), ClientClan() };
            bool done = false;
            for (const uintptr_t clan : clans)
            {
                const uintptr_t vec = clan ? Ptr(clan + kOff_Clan_Vector) : 0;
                uint32_t count = 0;
                if (!vec || !mem::Read32(clan + kOff_Clan_Count, &count)) continue;
                for (uint32_t i = 0; i < count && i < 512; ++i)
                {
                    const uintptr_t rec = Ptr(vec + 8ull * i);
                    uint16_t row = 0xFFFF;
                    if (rec && mem::Read16(rec + kOff_Rec_CharRow, &row) && row == g_remap.fromRow &&
                        mem::Write16(rec + kOff_Rec_CharRow, g_remap.toRow))
                        done = true;
                }
            }
            if (!done) return;
            LOG("mercenary: tamed mount remapped to callable row %u", g_remap.toRow);
            g_remap = {};
            std::lock_guard<std::mutex> lock(g_lock);
            snprintf(g_status, sizeof(g_status), "Tamed. It joins your special mounts once it is dismissed and called again.");
        }
    }

    bool Mercenary::Install()
    {
        g_charGlobal = Inventory::FindTableGlobal("characterinfo");
        // The table rows only exist once data is loaded; the mercenaryinfo
        // global is located lazily in Tick.
        g_installed = g_charGlobal != 0;
        if (g_installed) LoadOverrides();
        if (!g_installed) LOG_WARN("mercenary: characterinfo table not found - Mounts & Pets list disabled");
        return g_installed;
    }

    void Mercenary::Tick()
    {
        if (!g_installed) return;
        const ULONGLONG now = GetTickCount64();
        if (g_mercGlobal) PumpSpawns(now);
        if (now < g_nextSnapshot) return;
        g_nextSnapshot = now + 1000;
        if (!g_mercGlobal)
        {
            g_mercGlobal = FindMercenaryInfoGlobal(g_charGlobal);
            if (!g_mercGlobal) return;
            LOG_OK("mercenary: mercenaryinfo table @ %p", reinterpret_cast<void*>(g_mercGlobal));
        }
        ApplyLimits();
        BuildSnapshot();
        if (g_nearbyRequested.exchange(false)) BuildNearby();
        if (g_tameRequested.exchange(false)) TameNearest();
        if (const int kind = g_catalogReq.exchange(-1); kind >= 0)
            BuildCatalog(static_cast<Mercenary::CatalogKind>(kind));
        ApplyRemap();
        ApplyStatOverrides();

        SpeciesRequest sreq;
        ChangeRequest creq;
        {
            std::lock_guard<std::mutex> lock(g_lock);
            sreq = g_speciesReq; g_speciesReq.pending = false;
            creq = g_changeReq;  g_changeReq.pending = false;
        }
        if (creq.pending) ApplyChange(creq.number, creq.row);
        if (sreq.pending) BuildSpecies(sreq.number, sreq.anyFamily);
    }

    bool Mercenary::Snapshot(std::vector<Entry>* out)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        *out = g_entries;
        return g_ready;
    }

    bool Mercenary::Rename(uint32_t number, const char* name)
    {
        wchar_t wide[16] = {};
        const int n = MultiByteToWideChar(CP_UTF8, 0, name, -1, wide, 16);
        if (n <= 1 || n > 16) { SetStatus("%s", "Name must be 1-15 characters."); return false; }
        const uint32_t chars = static_cast<uint32_t>(n - 1);

        uint8_t payload[8 + 4 + 32] = {};
        const uint64_t number64 = number;
        std::memcpy(payload, &number64, 8);
        std::memcpy(payload + 8, &chars, 4);
        std::memcpy(payload + 12, wide, (chars + 1) * 2);   // includes the terminator the server checks
        const uint16_t len = static_cast<uint16_t>(12 + (chars + 1) * 2);
        if (!troc::Post("TrocTrChangeMercenaryNameReq", payload, len))
        {
            SetStatus("%s", "Rename unavailable (server pump not ready).");
            return false;
        }
        SetStatus("Rename to \"%s\" sent - move a step to apply.", name);
        g_nextSnapshot = 0;
        return true;
    }

    bool Mercenary::Dismiss(uint32_t number)
    {
        const uint64_t number64 = number;
        if (!troc::Post("TrocTrFireMercenaryReq", &number64, 8))
        {
            SetStatus("%s", "Dismiss unavailable (server pump not ready).");
            return false;
        }
        SetStatus("%s", "Dismiss sent - move a step to apply.");
        g_nextSnapshot = 0;
        return true;
    }

    void Mercenary::RequestNearbyScan()
    {
        g_nearbyRequested.store(true);
        g_nextSnapshot = 0;
    }

    bool Mercenary::NearbySnapshot(std::vector<Nearby>* out)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        *out = g_nearby;
        return g_ready;
    }

    bool Mercenary::Hire(uint32_t handle, const char* name)
    {
        uint8_t payload[5] = {};
        std::memcpy(payload, &handle, 4);   // byte 4: hire mode 0 (as the game's own taming)
        if (!troc::Post("TrocTrHireMercenaryToTargetReq", payload, sizeof(payload)))
        {
            SetStatus("%s", "Adding unavailable (server pump not ready).");
            return false;
        }
        SetStatus("Adding %s - move a step to apply.", name);
        g_nextSnapshot = 0;
        return true;
    }

    bool Mercenary::ReadMountStats(uint32_t number, MountStats* out)
    {
        uintptr_t so = 0, co = 0;
        MountBodies(number, &so, &co);
        const uintptr_t data = StatusDataOf(so ? so : co);
        if (!data) return false;
        auto val = [&](int index) {
            int64_t v = 0;
            const uintptr_t slot = ValueSlot(data, index);
            return slot && mem::Read64(slot, reinterpret_cast<uint64_t*>(&v)) ? static_cast<int>(v / 1000) : -1;
        };
        auto gauge = [&](int type) {
            int64_t v = 0;
            const uintptr_t e = GaugeSlot(data, type);
            return e && mem::Read64(e + kOff_StatEntry_Base, reinterpret_cast<uint64_t*>(&v)) ? static_cast<int>(v / 1000) : -1;
        };
        out->attack = val(kVal_Attack);   out->defense = val(kVal_Defense);
        out->speed = val(kVal_Speed);     out->accel = val(kVal_Accel);
        out->turn = val(kVal_Turn);       out->jump = val(kVal_Jump);
        out->maxHp = gauge(kGauge_Hp);    out->maxVigor = gauge(kGauge_Vigor);
        return true;
    }

    void Mercenary::SetMountStats(uint32_t number, const MountStats& stats)
    {
        std::lock_guard<std::mutex> lock(g_statsLock);
        for (auto& [n, s] : g_statOverrides)
            if (n == number) { s = stats; SaveOverrides(); return; }
        g_statOverrides.emplace_back(number, stats);
        SaveOverrides();
    }

    void Mercenary::ClearMountStats(uint32_t number)
    {
        std::lock_guard<std::mutex> lock(g_statsLock);
        g_statOverrides.erase(std::remove_if(g_statOverrides.begin(), g_statOverrides.end(),
                                             [&](const auto& e) { return e.first == number; }),
                              g_statOverrides.end());
        SaveOverrides();
    }

    bool Mercenary::HasMountStats(uint32_t number)
    {
        std::lock_guard<std::mutex> lock(g_statsLock);
        for (const auto& e : g_statOverrides) if (e.first == number) return true;
        return false;
    }

    namespace
    {
        constexpr uintptr_t kOff_Rec_Evolution = 0x120;   // -> {u32 level, pad, u32 exp}
        constexpr uintptr_t kOff_Evo_Exp       = 0x08;
    }

    int Mercenary::GetEvolutionLevel(uint32_t number)
    {
        const uintptr_t block = Ptr(FindRecord(PlayerClan(), number) + kOff_Rec_Evolution);
        uint32_t level = 0;
        return block && mem::Read32(block, &level) && level < 1000 ? static_cast<int>(level) : -1;
    }

    bool Mercenary::SetEvolutionLevel(uint32_t number, int level)
    {
        if (level < 1 || level > 999) return false;
        bool ok = false;
        for (const uintptr_t clan : { PlayerClan(), ClientClan() })
        {
            const uintptr_t rec = FindRecord(clan, number);
            const uintptr_t block = rec ? Ptr(rec + kOff_Rec_Evolution) : 0;
            if (block && mem::Write32(block, static_cast<uint32_t>(level)))
            {
                mem::Write32(block + kOff_Evo_Exp, 0);
                ok = true;
            }
        }
        LOG("mercenary: evolution #%u -> %d (%s)", number, level, ok ? "ok" : "no record");
        return ok;
    }

    void Mercenary::RequestCatalog(CatalogKind kind)
    {
        {
            std::lock_guard<std::mutex> lock(g_lock);
            g_catalog.clear();
        }
        g_catalogReq = static_cast<int>(kind);
        g_nextSnapshot = 0;
    }

    bool Mercenary::CatalogSnapshot(std::vector<Species>* out)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        *out = g_catalog;
        return !g_catalog.empty();
    }

    bool Mercenary::SpawnCreature(uint16_t row, bool adopt, int count, SpawnSide side)
    {
        if (side != SpawnSide::Default && !adopt) Ghost::PrepareAllegiance();
        std::lock_guard<std::mutex> lock(g_lock);
        g_spawnReq = { row, adopt, true, count, side };
        g_nextSnapshot = 0;
        return true;
    }

    void Mercenary::SpawnedSnapshot(std::vector<SpawnedInfo>* out)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        *out = g_spawnedView;
    }

    void Mercenary::Despawn(uint32_t handle)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        g_despawnReq.push_back(handle);
    }

    void Mercenary::TameNearestMount()
    {
        g_tameRequested = true;
        g_nextSnapshot = 0;
    }

    void Mercenary::RequestSpecies(uint32_t number, bool anyFamily)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        g_species.clear();
        g_speciesReq = { number, anyFamily, true };
        g_nextSnapshot = 0;
    }

    bool Mercenary::SpeciesSnapshot(std::vector<Species>* out)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        *out = g_species;
        return !g_species.empty();
    }

    bool Mercenary::ChangeSpecies(uint32_t number, uint16_t row, const char* name)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        g_changeReq = { number, row, true };
        snprintf(g_status, sizeof(g_status), "Changing species to %s...", name);
        g_nextSnapshot = 0;
        return true;
    }

    void Mercenary::SetPetSummonLimit(int value) { g_petSummonLimit.store(value < 0 ? 0 : value); }
    int  Mercenary::GetPetSummonLimit() { return g_petSummonLimit.load(); }
    int  Mercenary::DefaultPetSummonLimit() { return g_petOriginalsKnown ? static_cast<int>(g_petSummonOriginal) : 3; }

    void Mercenary::LastStatus(char* buf, size_t cap)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        snprintf(buf, cap, "%s", g_status);
    }
}
