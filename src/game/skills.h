#pragma once

#include <cstdint>
#include <vector>

namespace trinity::game
{
    // Skills and Knowledge - list and learn what a character has not unlocked.
    //
    // How the engine models it (PE 1.0.0.2976, verified in game):
    //  - A skill is unlocked by its KNOWLEDGE. SkillInfo row +0xA0
    //    (_learnKnowledgeInfo) is a u16 row index into the "knowledgeinfo"
    //    table; 0xFFFF means the skill is not knowledge-gated.
    //  - Each character's ServerKnowledgeActorComponent (owner+0x68 -> +0x150)
    //    holds one 0x18-byte state per knowledgeinfo row (+0x18 array, +0x20
    //    count). Byte 0 of a state is the learned level (0 = not learned).
    //  - Learning goes through the engine's own knowledge-apply function
    //    (Denuvo-virtualized body, called through its thunk) in the server
    //    realm: apply(comp, u32* err, const u16* row, u32 level, u32 0,
    //    u8 source, void* 0) - one row per call, the fourth argument is the
    //    level to reach (the game's list path passes each entry's level).
    //    Source 0x19 is what the game uses for knowledge granted by events.
    //    The result persists in the save like any other knowledge.
    //  - The skill tree's own request (TrocTrLearnSkillReq) reports success but
    //    does not apply anything when sent this way, and the knowledge cheat
    //    requests (TrocTrLearnKnowledge[Group]ByCheatReq) are empty stubs in
    //    retail, so neither is used.
    //  - The journal (Journal > Knowledge) is the KnowledgeGroupInfo tree:
    //    every group row lists its knowledgeinfo rows (+0x80) and its parent
    //    (+0xA0); +0xA3 says whether the journal shows it.
    //  - Elemental magic needs, per character: Spirit (Knowledge_Mp), the four
    //    elements (Knowledge_MpFire/MpIce/MpLightning/MpWind, normally learned
    //    by meditating at fixed spots), the character's four Mp spells and
    //    Imbue Element. The elements are not skills, so the skill list never
    //    shows them: spells learned without them stay unusable.
    //
    // Everything is located by signature; snapshots and every request run on
    // the game thread (Tick). The UI only reads the published copies.
    class Skills
    {
    public:
        struct Entry
        {
            uint32_t skillKey = 0;
            uint16_t knowledgeRow = 0;
            uint32_t knowledgeKey = 0;
            uint8_t  level = 0;
            int8_t   owner = 0;       // 0 Kliff, 1 Damiane, 2 Oongka (from the skill's key name)
            char     key[64] = {};    // SkillInfo _stringKey, e.g. "Skill_EvadeAttack_Kick"
            char     name[64] = {};   // display name (English) or a readable form of `key`
        };

        // A journal category or one of its groups.
        struct KnowledgeGroup
        {
            uint16_t index = 0xFFFF;  // KnowledgeGroupInfo row
            int      learned = 0;     // rows under it the character has
            int      total = 0;       // rows under it
            char     name[64] = {};
        };

        // One journal entry (a knowledgeinfo row) and the character's level.
        struct KnowledgeEntry
        {
            uint16_t row = 0;
            uint8_t  level = 0;
            char     name[64] = {};   // English name, or a readable form of `key`
            char     key[64] = {};    // internal name, e.g. "Knowledge_Crow"
            char     group[64] = {};  // the group that lists it
        };

        static bool Install();
        static void Tick();           // game thread

        // Character whose knowledge the lists show and learn into
        // (0 Kliff, 1 Damiane, 2 Oongka).
        static void SetCharacter(int index);
        static int  GetCharacter();

        static bool Ready();
        // Copies the latest snapshot. Returns false while nothing is available.
        static bool Snapshot(std::vector<Entry>* out, int* learned, int* total);

        // Queue requests; executed on the following ticks.
        static void RequestLearn(uint16_t knowledgeRow);
        static void RequestLearnAllMissing();

        // --- Journal -------------------------------------------------------------
        // Categories (parent 0xFFFF) or the groups of a category, only those the
        // journal shows. False until the tree and the character are loaded.
        static bool KnowledgeGroups(uint16_t parent, std::vector<KnowledgeGroup>* out);
        // Every entry under `group`, missing first.
        static bool KnowledgeEntries(uint16_t group, std::vector<KnowledgeEntry>* out);
        // KnowledgeGroupInfo row of an internal group name, 0xFFFF when absent.
        static uint16_t FindKnowledgeGroup(const char* internalName);
        static void RequestLearnGroup(uint16_t group);   // every missing entry under it
        static void RequestLearnJournal();               // every shown category but Quests

        // --- Elemental magic -------------------------------------------------------
        // Spirit, the four elements, the character's four elemental spells and
        // Imbue Element with its elemental moves, prerequisites first.
        static void RequestLearnElementalMagic();
        // Pieces of that set the character is missing (-1 = not loaded yet).
        static int  ElementalMissing();

        // Unlocks still queued, and dropping them.
        static int  Pending();
        static void CancelPending();

        // Last result line for the UI (empty when nothing happened yet).
        static void LastStatus(char* buf, size_t cap);
    };
}
