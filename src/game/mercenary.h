#pragma once

#include <cstdint>
#include <vector>

namespace trinity::game
{
    // Mounts & pets ("mercenaries" in the engine): list the player's own,
    // rename or dismiss them, and raise the registration / summon limits.
    //
    // Engine facts (PE 1.0.0.2976, verified live):
    //  - Player owner+0x68 -> +0x110 is the ServerMercenaryClanActorComponent.
    //    Its +0x18 vector (count at +0x20) holds one record per mercenary:
    //    +0x20 u16 = characterinfo row, +0x28 u32 = mercenary number.
    //  - CharacterInfo row +0xBE u16 = mercenaryinfo row (0xFFFF = not a
    //    mercenary). The mercenaryinfo table names the kind (Vehicle_Horse,
    //    Pet, Mercenary_Main...) and carries the limits: +0x14 u32 summon
    //    count, +0x18 u32 registration (hire) count.
    //  - Rename / dismiss are the game's own requests (TrocTrChangeMercenaryNameReq,
    //    TrocTrFireMercenaryReq) run through the server pump (troc.h), so they
    //    persist like the in-game buttons.
    class Mercenary
    {
    public:
        enum class Kind : uint8_t { Mount, Pet, Companion, Mercenary, Other };

        struct Entry
        {
            uint32_t number = 0;          // mercenary number (request key)
            uint32_t characterKey = 0;
            Kind     kind = Kind::Other;
            char     name[64] = {};       // English character name or readable key
            char     typeKey[40] = {};    // mercenaryinfo key, e.g. "Vehicle_Horse"
        };

        static bool Install();
        static void Tick();               // game thread

        static bool Snapshot(std::vector<Entry>* out);

        // Requests (game's own; applied by the server on the next pump).
        // `name` is UTF-8, at most 15 characters.
        static bool Rename(uint32_t number, const char* name);
        static bool Dismiss(uint32_t number);

        // --- Adding: hire a live animal / mount near the player ----------------
        // The game's own hire request (TrocTrHireMercenaryToTargetReq) accepts
        // any live actor whose character has a mercenary type, addressed by its
        // actor handle (owner+0x60). The server refuses targets that are not
        // loaded around the player, so the list is limited to nearby actors.
        struct Nearby
        {
            uint32_t handle = 0;
            uint32_t characterKey = 0;
            uint16_t charRow = 0xFFFF;
            Kind     kind = Kind::Other;
            float    distance = 0.0f;
            char     name[64] = {};
            char     typeKey[40] = {};
        };
        static void RequestNearbyScan();            // refreshed on the game thread
        static bool NearbySnapshot(std::vector<Nearby>* out);
        static bool Hire(uint32_t handle, const char* name);

        // One-shot taming: hires the closest rideable mount (horse, wild wyvern,
        // bear...). Mounts of the plain "Vehicle" family never show in the game's
        // summon menus, so the new record is pointed at the rideable row of the
        // same vehicle type (e.g. Animal_Wyvern -> Riding_Wyvern_1000).
        static void TameNearestMount();

        // --- Species change: the save editors' "charKey swap", done live -------
        // Rewrites the character a mercenary record points at (record +0x20) in
        // both the server record (saved) and the client mirror (what the menus
        // and summoning read), so the change shows without reloading. Same
        // family = targets that share the record's mercenaryinfo row; other
        // families are experimental (the record layout can differ per family).
        // Refused while the mercenary is summoned (record +0x50 = live body):
        // the spawned body would stay the old species until a reload.
        struct Species
        {
            uint16_t row = 0;
            uint32_t key = 0;
            char     name[128] = {};
            char     typeKey[40] = {};
        };
        // --- Add any creature: spawn it beside the player, then adopt it -------
        // TrocTrSpawnCharacterCheatReq {u32 characterKey, u32 0, float3 pos, u8 1}
        // run through the server pump; the position must be the server
        // TransformSync one (the teleport module's position is another space and
        // spawns the body far away). Layout learned from DesertLink Spawn Any NPC
        // (PE 2976). The new body is then hired like a tamed animal.
        // Mounts / Pets = adoptable families. The rest is every character the
        // game defines, split by its internal key (no faction data needed):
        // Bosses ("Boss" anywhere), Monsters (MON_/NatureCreature/Marionette),
        // Animals (Animal_), People (N??_ npc prefixes, Marni_), Others.
        // Player/party/system rows (Kliff, WorldObserver, Object_...) are left out.
        enum class CatalogKind : uint8_t { Mounts, Pets, Bosses, Monsters, Animals, People, Others };
        static void RequestCatalog(CatalogKind kind);
        static bool CatalogSnapshot(std::vector<Species>* out);
        // Side of a spawned body: Default keeps its own faction; Ally takes the
        // player's, Enemy "Faction_Bandit", Neutral "Faction_Empty_Misc" (u16
        // factioninfo row at Server/ClientStatusActorComponent +0x342, the
        // write DesertLink uses for its faction battles).
        enum class SpawnSide : uint8_t { Default, Ally, Enemy, Neutral };
        // count > 1 spawns bodies one after another around the player (adopt
        // applies to each).
        static bool SpawnCreature(uint16_t row, bool adopt, int count = 1, SpawnSide side = SpawnSide::Default);

        // Bodies spawned this session that are still in the world (not adopted
        // ones). Despawn removes them with the engine's own child-removal call.
        struct SpawnedInfo
        {
            uint32_t  handle = 0;
            char      name[64] = {};
            float     distance = -1.0f;
            SpawnSide side = SpawnSide::Default;
            bool      removing = false;
        };
        static void SpawnedSnapshot(std::vector<SpawnedInfo>* out);
        static void Despawn(uint32_t handle);   // 0 = every tracked body

        static void RequestSpecies(uint32_t number, bool anyFamily);
        static bool SpeciesSnapshot(std::vector<Species>* out);
        static bool ChangeSpecies(uint32_t number, uint16_t row, const char* name);

        // --- Mount stats -------------------------------------------------------
        // A summoned mount's status component (sub+0x20) holds, at +0x18, a
        // status block: +0x18 = 46 x 0x20 values {i64 value, i64 min, i64 max,
        // i64 flag} (x1000 fixed point) and +0x58 = the 0x90-stride gauge array
        // (Hp type 0, Vigor type 22). Server and client keep separate copies and
        // the server does not push them to the client, so both are written.
        // The engine rebuilds them on every summon, so edits are kept as a
        // per-mount override (saved to Trinity_mounts.ini) and re-applied
        // whenever that mount is out.
        // -1 = leave the game's value.
        struct MountStats
        {
            int attack = -1, defense = -1, maxHp = -1, maxVigor = -1;
            int speed = -1, accel = -1, turn = -1, jump = -1;   // levels 1..5
        };
        static bool ReadMountStats(uint32_t number, MountStats* out);   // false if not summoned
        static void SetMountStats(uint32_t number, const MountStats& stats);
        static void ClearMountStats(uint32_t number);
        static bool HasMountStats(uint32_t number);

        // Evolution level ("Evolucao Nv.N" on the mount page). Record +0x120
        // points at an evolution block in both the server record (saved) and
        // the client mirror (UI): +0x00 u32 level, +0x08 u32 exp inside the
        // level. Found by diffing memory across a real level-up (3 -> 4).
        // The mount's skills follow the level (verified: they lit up at Nv.5).
        static int  GetEvolutionLevel(uint32_t number);            // -1 if unknown
        static bool SetEvolutionLevel(uint32_t number, int level);

        // Session-only summon limit for pets (0 = game default).
        static void SetPetSummonLimit(int value);
        static int  GetPetSummonLimit();
        static int  DefaultPetSummonLimit();

        static void LastStatus(char* buf, size_t cap);
    };
}
