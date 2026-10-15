#include "skills.h"

#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

#include "inventory.h"
#include "player.h"
#include "offsets.h"
#include "knowledge_names.h"
#include "../core/logger.h"
#include "../mem/scanner.h"
#include "../mem/safe_memory.h"

namespace trinity::game
{
    namespace
    {
        // SkillInfo row lookup is called right before the skill-tree UI tests
        // the row's _learnKnowledgeInfo (+0xA0) against 0xFFFF; the lookup's
        // third instruction loads the SkillInfo table global.
        constexpr const char* kSig_SkillRowLookupCall = "E8 ?? ?? ?? ?? 66 39 98 A0 00 00 00";
        constexpr uintptr_t   kOff_SkillLookup_MovGlobal = 0x15; // mov rbx, cs:SkillInfo

        // The one call site that applies a knowledge with source 0x19 and level 1
        // (knowledge reward path). The call lands on the knowledge-apply thunk.
        constexpr const char* kSig_KnowledgeApplySite =
            "C6 44 24 28 19 C7 44 24 20 00 00 00 00 41 B9 01 00 00 00 "
            "4C 8D 83 ?? ?? ?? ?? 48 8D 94 24 ?? ?? ?? ?? 48 8B 89 50 01 00 00 E8";
        constexpr uintptr_t kOff_KnowledgeApplySite_Call = 0x29;

        // Every static-info table has a key -> row lookup that starts by loading
        // its manager into r10; the KnowledgeGroupInfo one is picked by the
        // manager's RTTI (FindTableGlobal cannot: its first string anchor is the
        // loader, which never loads the global).
        constexpr const char* kSig_TableKeyLookup = "4C 8B 15 ?? ?? ?? ?? 48 89 5C 24 38 41 83 7A 6C 00";
        constexpr const char* kCls_KnowledgeGroupManager = ".?AVKnowledgeGroupInfoManager@pa@@";

        constexpr uintptr_t kOff_Table_Count = 0x08;   // u32
        constexpr uintptr_t kOff_Table_Rows  = 0x58;   // row ptr[]
        constexpr uintptr_t kOff_Skill_Key        = 0x00; // u32 _key
        constexpr uintptr_t kOff_Skill_StringKey  = 0x08; // -> string obj -> char*
        constexpr uintptr_t kOff_Skill_Knowledge  = 0xA0; // u16 _learnKnowledgeInfo (knowledgeinfo row)
        constexpr uintptr_t kOff_Knowledge_Key    = 0x00; // u32 _key
        constexpr uintptr_t kOff_Knowledge_Name   = 0x08; // -> string obj -> char* ("Knowledge_MpFire")

        // KnowledgeGroupInfo row (ctor 0x141813460).
        constexpr uintptr_t kOff_Group_Name     = 0x08;  // -> string obj -> char* ("KnowledgeGroup_Quest")
        constexpr uintptr_t kOff_Group_Rows     = 0x80;  // u16* knowledgeinfo rows of this group
        constexpr uintptr_t kOff_Group_RowCount = 0x88;  // u32
        constexpr uintptr_t kOff_Group_Parent   = 0xA0;  // u16 group row, 0xFFFF = category
        constexpr uintptr_t kOff_Group_Shown    = 0xA3;  // u8, 0 = not shown in the journal
        constexpr uint16_t  kNoGroup = 0xFFFF;

        constexpr uintptr_t kOff_Owner_Sub        = 0x68;
        constexpr uintptr_t kOff_Sub_Knowledge    = 0x150; // ServerKnowledgeActorComponent
        constexpr uintptr_t kOff_KComp_States     = 0x18;  // 0x18-byte state per knowledgeinfo row
        constexpr uintptr_t kOff_KComp_Count      = 0x20;  // u32
        constexpr uintptr_t kKnowledgeStateStride = 0x18;

        constexpr uint8_t   kSourceEventGrant = 0x19;
        constexpr int       kMaxLearnsPerPump = 8;
        constexpr ULONGLONG kLearnPumpMs = 100;     // both game-thread ticks call Tick; the clock paces it

        using KnowledgeApply_t = uint32_t*(__fastcall*)(uintptr_t comp, uint32_t* err, const uint16_t* row,
                                                        uint32_t level, uint32_t zero, uint8_t source, void* extra);

        uintptr_t        g_skillGlobal = 0;
        uintptr_t        g_knowledgeGlobal = 0;
        uintptr_t        g_groupGlobal = 0;
        KnowledgeApply_t g_apply = nullptr;
        bool             g_installed = false;
        ULONGLONG        g_nextGroupScan = 0;

        std::atomic<int> g_character{ 0 };
        ULONGLONG        g_nextSnapshot = 0;
        ULONGLONG        g_nextLearn = 0;

        // Journal tree (game thread builds it once; the published copies below
        // are what the UI reads).
        struct GroupNode
        {
            bool                  loaded = false;
            bool                  shown = false;
            uint16_t              parent = kNoGroup;
            char                  internal[80] = {};
            char                  name[64] = {};
            std::vector<uint16_t> own;        // rows the group itself lists
            std::vector<uint16_t> children;   // shown child groups
            std::vector<uint16_t> rows;       // every row under it through shown groups, no duplicates
        };
        std::vector<GroupNode>                    g_tree;
        std::vector<std::string>                  g_rowInternal;   // knowledgeinfo row -> internal name
        std::unordered_map<std::string, uint16_t> g_rowByName;
        std::atomic<bool>                         g_namesBuilt{ false };  // g_rowInternal / g_rowByName final
        std::atomic<bool>                         g_treeBuilt{ false };   // g_tree final once set

        struct LearnItem { uint16_t row; int8_t character; };

        std::mutex                  g_lock; // guards everything below
        std::vector<Skills::Entry>  g_entries;
        int                         g_learned = 0;
        int                         g_total = 0;
        bool                        g_ready = false;
        std::vector<uint8_t>        g_levels;        // selected character, per knowledgeinfo row
        std::vector<int>            g_groupLearned;  // per group, through shown groups
        int                         g_elementalMissing = -1;
        std::deque<LearnItem>       g_queue;
        std::vector<uint8_t>        g_queued;        // row already waiting in g_queue
        std::vector<uint16_t>       g_groupRequests;
        bool                        g_learnAll = false;
        bool                        g_learnJournal = false;
        bool                        g_learnElemental = false;
        bool                        g_jobActive = false;
        int                         g_jobOk = 0, g_jobFailed = 0, g_jobRefusalLogs = 0;
        char                        g_status[160] = {};

        uintptr_t Ptr(uintptr_t a)
        {
            uintptr_t v = 0;
            return mem::ReadPtr(a, &v) ? v : 0;
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

        const char* EnglishName(uint32_t knowledgeKey)
        {
            const auto* b = knowledge_names::kNames;
            const auto* e = b + knowledge_names::kCount;
            const auto* it = std::lower_bound(b, e, knowledgeKey,
                [](const knowledge_names::Entry& x, uint32_t k) { return x.key < k; });
            return (it != e && it->key == knowledgeKey) ? it->name : nullptr;
        }

        // "Skill_EvadeAttack_Kick" -> "EvadeAttack Kick"
        void Readable(const char* key, char* out, size_t cap)
        {
            const char* s = std::strncmp(key, "Skill_", 6) == 0 ? key + 6 : key;
            size_t i = 0;
            for (; *s && i + 1 < cap; ++s) out[i++] = (*s == '_') ? ' ' : *s;
            out[i] = 0;
        }

        // "Knowledge_SyrrhaptesParadoxus" -> "Syrrhaptes Paradoxus"
        void ReadableKnowledge(const char* key, char* out, size_t cap)
        {
            const char* s = std::strncmp(key, "Knowledge_", 10) == 0 ? key + 10 : key;
            size_t i = 0;
            for (char prev = 0; *s && i + 1 < cap; prev = *s++)
            {
                const bool camel = *s >= 'A' && *s <= 'Z' && prev >= 'a' && prev <= 'z';
                if ((*s == '_' || camel) && i && out[i - 1] != ' ') out[i++] = ' ';
                if (*s != '_' && i + 1 < cap) out[i++] = *s;
            }
            out[i] = 0;
        }

        // Journal category / group title from its internal name:
        // "KnowledgeGroup_Character_GrayMane_Temp" -> "Gray Mane".
        void GroupTitle(const char* internal, char* out, size_t cap)
        {
            static const struct { const char* internal; const char* title; } kKnown[] = {
                { "KnowledgeGroup_Character",            "Characters" },
                { "KnowledgeGroup_Character_Faction",    "Factions" },
                { "KnowledgeGroup_Topography",           "Regions" },
                { "KnowledgeGroup_Character_Animal",     "Animals & Creatures" },
                { "KnowledgeGroup_Character_NonAnimal",  "Notable Enemies" },
                { "KnowledgeGroup_Character_Riding",     "Mounts & Vehicles" },
                { "KnowledgeGroup_Discover",             "Discoveries" },
                { "KnowledgeGroup_Item",                 "Materials" },
                { "KnowledgeGroup_Item_Collection",      "Collections" },
                { "KnowledgeGroup_CraftingRecipe",       "Recipes & Blueprints" },
                { "KnowledgeGroup_CraftingRecipe_Kuku",  "Kuku Blueprints" },
                { "KnowledgeGroup_Quest",                "Quests & Research" },
                { "KnowledgeGroup_Reserch",              "Institute Research" },
            };
            for (const auto& k : kKnown)
                if (!std::strcmp(internal, k.internal)) { snprintf(out, cap, "%s", k.title); return; }

            const char* s = std::strncmp(internal, "KnowledgeGroup_", 15) == 0 ? internal + 15 : internal;
            char tokens[8][40] = {};
            int n = 0;
            while (*s && n < 8)
            {
                size_t len = 0;
                while (s[len] && s[len] != '_') ++len;
                if (len && len < sizeof(tokens[0]))
                {
                    std::memcpy(tokens[n], s, len);
                    tokens[n][len] = 0;
                    static const char* const kFiller[] = { "Temp", "Temp2", "Temp3", "wsseTemp", "Tmep" };
                    bool filler = false;
                    for (const char* f : kFiller) filler |= !std::strcmp(tokens[n], f);
                    if (!filler) ++n;
                }
                s += len;
                if (*s == '_') ++s;
            }
            static const char* const kNoise[] = { "Character", "Faction", "Topography", "Discover", "Item",
                                                  "CraftingRecipe", "Craft" };
            int first = 0;
            if (n > 1)
                for (const char* w : kNoise)
                    if (!std::strcmp(tokens[0], w)) { first = 1; break; }
            size_t i = 0;
            for (int t = first; t < n; ++t)
            {
                const char* w = !std::strcmp(tokens[t], "Reserch") ? "Research" : tokens[t];
                if (i && i + 1 < cap) out[i++] = ' ';
                for (char prev = 0; *w && i + 1 < cap; prev = *w++)
                {
                    if (*w >= 'A' && *w <= 'Z' && prev >= 'a' && prev <= 'z' && i + 1 < cap) out[i++] = ' ';
                    if (i + 1 < cap) out[i++] = *w;
                }
            }
            out[i] = 0;
            if (!i) snprintf(out, cap, "%s", internal);
        }

        int8_t OwnerFromKey(const char* key)
        {
            if (std::strstr(key, "Damian")) return 1;
            if (std::strstr(key, "Oongka")) return 2;
            return 0;
        }

        uintptr_t OwnerFor(int character)
        {
            uintptr_t owner = Player::GetOwner(character);
            if (!owner && Player::GetActiveCharacterIdx() == character)
                owner = Player::GetControlledOwner();
            return owner;
        }

        uint32_t KnowledgeCount()
        {
            uint32_t count = 0;
            const uintptr_t table = Ptr(g_knowledgeGlobal);
            return table && mem::Read32(table + kOff_Table_Count, &count) ? count : 0;
        }

        // The character's ServerKnowledgeActorComponent, or 0 when it is not
        // loaded / not the expected class / sized for another table.
        uintptr_t KnowledgeComp(int character, uint32_t knowledgeCount, uintptr_t* states)
        {
            const uintptr_t owner = OwnerFor(character);
            const uintptr_t sub = owner ? Ptr(owner + kOff_Owner_Sub) : 0;
            const uintptr_t comp = sub ? Ptr(sub + kOff_Sub_Knowledge) : 0;
            if (!comp || !IsClass(comp, ".?AVServerKnowledgeActorComponent@pa@@")) return 0;
            uint32_t count = 0;
            if (!mem::Read32(comp + kOff_KComp_Count, &count) || count != knowledgeCount) return 0;
            *states = Ptr(comp + kOff_KComp_States);
            return *states ? comp : 0;
        }

        bool GuardedApply(uintptr_t comp, uint16_t row, uint32_t* err)
        {
            __try
            {
                g_apply(comp, err, &row, 1, 0, kSourceEventGrant, nullptr);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }

        // Runs one apply in the server realm. The engine commits the new level a
        // moment later (the in-game "skill acquired" notice follows), so an
        // immediate readback of 0 is not a failure - only a fault or a non-zero
        // engine result is. The next snapshot shows the confirmed level.
        bool Learn(uintptr_t comp, uint16_t row)
        {
            uint8_t previous = 0;
            const uintptr_t realm = Inventory::RealmFlagAddress(&previous);
            if (!realm) return false;
            mem::Write8(realm, 1);
            uint32_t err = 0xFFFFFFFFu;
            const bool called = GuardedApply(comp, row, &err);
            mem::Write8(realm, previous);
            const bool ok = called && err == 0;
            if (!ok && g_jobRefusalLogs++ < 10)
            {
                if (!called) LOG_WARN("skills: knowledge apply faulted for row %u", row);
                else LOG_WARN("skills: knowledge apply refused row %u (err 0x%08X)", row, err);
            }
            return ok;
        }

        // --- Journal tree ---------------------------------------------------------------
        uintptr_t FindGroupGlobal()
        {
            for (const uintptr_t site : mem::FindAllMatches(kSig_TableKeyLookup, 512))
            {
                const uintptr_t g = mem::ResolveRipAt(site, 7);
                const uintptr_t mgr = g ? Ptr(g) : 0;
                if (mgr && IsClass(mgr, kCls_KnowledgeGroupManager)) return g;
            }
            return 0;
        }

        // Collects every row under `index` through shown groups into node.rows.
        void CollectRows(uint16_t index, std::vector<uint16_t>* out, std::vector<uint32_t>* seenStamp, uint32_t stamp,
                         int depth)
        {
            if (index >= g_tree.size() || depth > 16) return;
            const GroupNode& node = g_tree[index];
            for (const uint16_t r : node.own)
                if ((*seenStamp)[r] != stamp) { (*seenStamp)[r] = stamp; out->push_back(r); }
            for (const uint16_t c : node.children) CollectRows(c, out, seenStamp, stamp, depth + 1);
        }

        // Every knowledgeinfo row's internal name ("Knowledge_MpFire"). Once per
        // session: the table is static data.
        bool BuildNames()
        {
            const uint32_t knowCount = KnowledgeCount();
            const uintptr_t knowRows = knowCount ? Ptr(Ptr(g_knowledgeGlobal) + kOff_Table_Rows) : 0;
            if (!knowRows || knowCount > 0xFFFF) return false;
            std::vector<std::string> internal(knowCount);
            std::unordered_map<std::string, uint16_t> byName;
            byName.reserve(knowCount * 2);
            int named = 0;
            for (uint32_t r = 0; r < knowCount; ++r)
            {
                char name[80];
                if (ReadCString(Ptr(Ptr(Ptr(knowRows + 8ull * r) + kOff_Knowledge_Name)), name, sizeof(name)))
                {
                    internal[r] = name;
                    byName.emplace(name, static_cast<uint16_t>(r));
                    ++named;
                }
            }
            if (!named) return false;
            g_rowInternal.swap(internal);
            g_rowByName.swap(byName);
            g_namesBuilt.store(true, std::memory_order_release);
            return true;
        }

        // Reads the KnowledgeGroupInfo tree. Once per session: static data.
        bool BuildTree()
        {
            if (!g_groupGlobal)
            {
                const ULONGLONG now = GetTickCount64();
                if (now < g_nextGroupScan) return false;
                g_nextGroupScan = now + 10000;
                g_groupGlobal = FindGroupGlobal();
                if (!g_groupGlobal)
                {
                    static bool warned = false;
                    if (!warned) LOG_WARN("skills: KnowledgeGroupInfo manager not found - journal unavailable");
                    warned = true;
                    return false;
                }
                LOG_OK("skills: KnowledgeGroupInfo global %p", reinterpret_cast<void*>(g_groupGlobal));
            }
            const uint32_t knowCount = KnowledgeCount();
            const uintptr_t mgr = Ptr(g_groupGlobal);
            uint32_t count = 0;
            const uintptr_t groupRows = mgr ? Ptr(mgr + kOff_Table_Rows) : 0;
            if (!knowCount || !groupRows || !mem::Read32(mgr + kOff_Table_Count, &count) || !count || count > 0x4000 ||
                knowCount > 0xFFFF)
                return false;

            std::vector<GroupNode> tree(count);
            int loaded = 0;
            for (uint32_t i = 0; i < count; ++i)
            {
                const uintptr_t row = Ptr(groupRows + 8ull * i);
                if (!row) continue;   // never looked up by the game yet (none of the journal's)
                GroupNode& node = tree[i];
                node.loaded = true;
                ++loaded;
                uint8_t shown = 0;
                mem::Read16(row + kOff_Group_Parent, &node.parent);
                mem::Read8(row + kOff_Group_Shown, &shown);
                node.shown = shown != 0;
                ReadCString(Ptr(Ptr(row + kOff_Group_Name)), node.internal, sizeof(node.internal));
                GroupTitle(node.internal, node.name, sizeof(node.name));
                const uintptr_t data = Ptr(row + kOff_Group_Rows);
                uint32_t n = 0;
                if (data && mem::Read32(row + kOff_Group_RowCount, &n) && n <= 4096)
                    for (uint32_t k = 0; k < n; ++k)
                    {
                        uint16_t r = 0xFFFF;
                        if (mem::Read16(data + 2ull * k, &r) && r < knowCount) node.own.push_back(r);
                    }
            }
            for (uint32_t i = 0; i < count; ++i)
                if (tree[i].loaded && tree[i].shown && tree[i].parent < count && tree[tree[i].parent].loaded)
                    tree[tree[i].parent].children.push_back(static_cast<uint16_t>(i));

            g_tree.swap(tree);
            std::vector<uint32_t> seen(knowCount, 0);
            int journalRows = 0;
            for (uint32_t i = 0; i < count; ++i)
            {
                if (!g_tree[i].loaded) continue;
                CollectRows(static_cast<uint16_t>(i), &g_tree[i].rows, &seen, i + 1, 0);
                if (g_tree[i].parent == kNoGroup && g_tree[i].shown) journalRows += static_cast<int>(g_tree[i].rows.size());
            }
            g_treeBuilt.store(true, std::memory_order_release);
            LOG("skills: journal tree read - %u groups (%d loaded), %d entries in shown categories", count, loaded,
                journalRows);
            return true;
        }

        // The rows "Unlock Elemental Magic" learns for a character, in learning
        // order: Spirit, the elements, the spells, Imbue Element and its
        // elemental moves.
        std::vector<uint16_t> ElementalRows(int character)
        {
            std::vector<uint16_t> rows;
            auto add = [&](const std::string& name) {
                const auto it = g_rowByName.find(name);
                if (it != g_rowByName.end() && std::find(rows.begin(), rows.end(), it->second) == rows.end())
                    rows.push_back(it->second);
            };
            static const char* const kElements[] = { "MpFire", "MpIce", "MpLightning", "MpWind" };
            add("Knowledge_Mp");
            for (const char* e : kElements) add(std::string("Knowledge_") + e);
            const std::string prefix = character == 1 ? "Knowledge_Damian_" : character == 2 ? "Knowledge_Oongka_"
                                                                                               : "Knowledge_Kliff_";
            for (const char* e : kElements) add(prefix + e);
            const std::string imbue = character == 0 ? "Knowledge_ElementalReinforce" : prefix + "ElementalReinforce";
            add(imbue);
            for (size_t r = 0; r < g_rowInternal.size(); ++r)
                if (!g_rowInternal[r].compare(0, imbue.size() + 1, imbue + "_")) add(g_rowInternal[r]);
            if (character == 0)
                for (const char* extra : { "Knowledge_RotationBash_Fire", "Knowledge_RotationBash_Ice",
                                           "Knowledge_RotationBash_Lightning", "Knowledge_ElementalArrow" })
                    add(extra);
            return rows;
        }

        void BuildSnapshot()
        {
            const uintptr_t skillTable = Ptr(g_skillGlobal);
            const uintptr_t knowTable = Ptr(g_knowledgeGlobal);
            uint32_t skillCount = 0, knowCount = 0;
            if (!skillTable || !knowTable || !mem::Read32(skillTable + kOff_Table_Count, &skillCount) ||
                !mem::Read32(knowTable + kOff_Table_Count, &knowCount) || !skillCount || !knowCount)
                return;
            const uintptr_t skillRows = Ptr(skillTable + kOff_Table_Rows);
            const uintptr_t knowRows = Ptr(knowTable + kOff_Table_Rows);

            const int character = g_character.load();
            uintptr_t states = 0;
            const uintptr_t comp = KnowledgeComp(character, knowCount, &states);

            std::vector<uint8_t> levels(knowCount, 0);
            if (comp)
                for (uint32_t r = 0; r < knowCount; ++r) mem::Read8(states + r * kKnowledgeStateStride, &levels[r]);

            std::vector<Skills::Entry> entries;
            entries.reserve(512);
            std::vector<uint8_t> seen(knowCount, 0);
            int learned = 0;
            for (uint32_t i = 0; i < skillCount; ++i)
            {
                const uintptr_t row = Ptr(skillRows + 8ull * i);
                if (!row) continue;
                uint16_t kRow = 0xFFFF;
                if (!mem::Read16(row + kOff_Skill_Knowledge, &kRow) || kRow >= knowCount || seen[kRow]) continue;
                seen[kRow] = 1;

                Skills::Entry e{};
                e.knowledgeRow = kRow;
                mem::Read32(row + kOff_Skill_Key, &e.skillKey);
                ReadCString(Ptr(Ptr(row + kOff_Skill_StringKey)), e.key, sizeof(e.key));
                e.owner = OwnerFromKey(e.key);
                if (e.owner != character) continue;

                const uintptr_t kr = Ptr(knowRows + 8ull * kRow);
                if (kr) mem::Read32(kr + kOff_Knowledge_Key, &e.knowledgeKey);
                if (const char* en = EnglishName(e.knowledgeKey))
                    snprintf(e.name, sizeof(e.name), "%s", en);
                else
                    Readable(e.key, e.name, sizeof(e.name));
                e.level = levels[kRow];
                if (e.level) ++learned;
                entries.push_back(e);
            }
            std::sort(entries.begin(), entries.end(), [](const Skills::Entry& a, const Skills::Entry& b) {
                if ((a.level == 0) != (b.level == 0)) return a.level == 0; // missing first
                return std::strcmp(a.name, b.name) < 0;
            });

            if (Player::Ready())
            {
                if (!g_namesBuilt.load(std::memory_order_acquire)) BuildNames();
                if (!g_treeBuilt.load(std::memory_order_acquire)) BuildTree();
            }
            std::vector<int> groupLearned(g_tree.size(), 0);
            for (size_t i = 0; i < g_tree.size(); ++i)
                for (const uint16_t r : g_tree[i].rows)
                    if (r < knowCount && levels[r]) ++groupLearned[i];
            int elementalMissing = -1;
            if (comp && g_namesBuilt)
            {
                elementalMissing = 0;
                for (const uint16_t r : ElementalRows(character))
                    if (!levels[r]) ++elementalMissing;
            }

            std::lock_guard<std::mutex> lock(g_lock);
            g_entries.swap(entries);
            g_learned = learned;
            g_total = static_cast<int>(g_entries.size());
            g_ready = comp != 0;
            g_levels.swap(levels);
            g_groupLearned.swap(groupLearned);
            g_elementalMissing = elementalMissing;
        }

        // Queues a missing row for `character` once (g_lock held).
        void QueueRow(uint16_t row, int character)
        {
            if (g_queued.size() < g_levels.size()) g_queued.resize(g_levels.size(), 0);
            if (row >= g_levels.size() || g_levels[row] || g_queued[row]) return;
            g_queued[row] = 1;
            g_queue.push_back({ row, static_cast<int8_t>(character) });
            if (!g_jobActive)
            {
                g_jobActive = true;
                g_jobOk = g_jobFailed = g_jobRefusalLogs = 0;
            }
        }

        // Turns the pending "learn this set" requests into queued rows (g_lock held).
        void ExpandRequests(int character)
        {
            if (g_learnAll)
                for (const Skills::Entry& e : g_entries) QueueRow(e.knowledgeRow, character);
            if (g_learnElemental && g_namesBuilt)
                for (const uint16_t r : ElementalRows(character)) QueueRow(r, character);
            if (g_learnJournal && g_treeBuilt)
                for (size_t i = 0; i < g_tree.size(); ++i)
                {
                    const GroupNode& node = g_tree[i];
                    if (node.loaded && node.shown && node.parent == kNoGroup &&
                        std::strcmp(node.internal, "KnowledgeGroup_Quest"))
                        for (const uint16_t r : node.rows) QueueRow(r, character);
                }
            if (g_treeBuilt)
                for (const uint16_t gIdx : g_groupRequests)
                    if (gIdx < g_tree.size())
                        for (const uint16_t r : g_tree[gIdx].rows) QueueRow(r, character);
            g_learnAll = g_learnElemental = g_learnJournal = false;
            g_groupRequests.clear();
        }

        void RunQueue()
        {
            const ULONGLONG now = GetTickCount64();
            if (now < g_nextLearn) return;
            g_nextLearn = now + kLearnPumpMs;

            std::vector<LearnItem> work;
            {
                std::lock_guard<std::mutex> lock(g_lock);
                ExpandRequests(g_character.load());
                if (g_queue.empty()) return;
                while (!g_queue.empty() && static_cast<int>(work.size()) < kMaxLearnsPerPump)
                {
                    work.push_back(g_queue.front());
                    g_queue.pop_front();
                }
            }

            const uint32_t knowCount = KnowledgeCount();
            int ok = 0, failed = 0, unloaded = 0;
            for (const LearnItem& item : work)
            {
                uintptr_t states = 0;
                const uintptr_t comp = g_apply ? KnowledgeComp(item.character, knowCount, &states) : 0;
                if (!comp) { ++unloaded; continue; }
                uint8_t level = 0;
                mem::Read8(states + item.row * kKnowledgeStateStride, &level);
                if (level || Learn(comp, item.row)) ++ok;
                else ++failed;
            }

            std::lock_guard<std::mutex> lock(g_lock);
            for (const LearnItem& item : work)
                if (item.row < g_queued.size()) g_queued[item.row] = 0;
            g_jobOk += ok;
            g_jobFailed += failed;
            if (unloaded)
            {
                // The character left the world (or was never loaded): drop the job.
                for (const LearnItem& item : g_queue)
                    if (item.row < g_queued.size()) g_queued[item.row] = 0;
                g_queue.clear();
                g_jobActive = false;
                snprintf(g_status, sizeof(g_status), "Character not loaded - stopped after %d unlocks.", g_jobOk);
            }
            else if (!g_queue.empty())
                snprintf(g_status, sizeof(g_status), "Unlocking... %d done, %zu left.", g_jobOk, g_queue.size());
            else
            {
                g_jobActive = false;
                snprintf(g_status, sizeof(g_status), g_jobFailed ? "Unlocked %d, %d refused by the game." : "Unlocked %d.",
                         g_jobOk, g_jobFailed);
                LOG("skills: unlock job finished - %d unlocked, %d refused", g_jobOk, g_jobFailed);
            }
            g_nextSnapshot = GetTickCount64() + 300;
        }
    }

    bool Skills::Install()
    {
        if (const uintptr_t site = mem::FindPattern(kSig_SkillRowLookupCall))
        {
            const uintptr_t fn = mem::ResolveCall(site);
            uint8_t b[3] = {};
            if (fn && mem::Read8(fn + kOff_SkillLookup_MovGlobal, &b[0]) && mem::Read8(fn + kOff_SkillLookup_MovGlobal + 1, &b[1]) &&
                mem::Read8(fn + kOff_SkillLookup_MovGlobal + 2, &b[2]) && b[0] == 0x48 && b[1] == 0x8B && b[2] == 0x1D)
                g_skillGlobal = mem::ResolveRipAt(fn + kOff_SkillLookup_MovGlobal, 7);
        }
        if (const uintptr_t site = mem::FindPattern(kSig_KnowledgeApplySite))
            g_apply = reinterpret_cast<KnowledgeApply_t>(mem::ResolveCall(site + kOff_KnowledgeApplySite_Call));
        g_knowledgeGlobal = Inventory::FindTableGlobal("knowledgeinfo");

        g_installed = g_skillGlobal && g_apply && g_knowledgeGlobal;
        if (g_installed)
            LOG_OK("skills: SkillInfo=%p knowledgeinfo=%p apply=%p", reinterpret_cast<void*>(g_skillGlobal),
                   reinterpret_cast<void*>(g_knowledgeGlobal), reinterpret_cast<void*>(g_apply));
        else
            LOG_WARN("skills: unavailable (SkillInfo=%p knowledgeinfo=%p apply=%p)", reinterpret_cast<void*>(g_skillGlobal),
                     reinterpret_cast<void*>(g_knowledgeGlobal), reinterpret_cast<void*>(g_apply));
        return g_installed;
    }

    void Skills::Tick()
    {
        if (!g_installed) return;
        RunQueue();
        const ULONGLONG now = GetTickCount64();
        if (now < g_nextSnapshot) return;
        g_nextSnapshot = now + 750;
        BuildSnapshot();
    }

    void Skills::SetCharacter(int index)
    {
        if (index < 0 || index > 2) return;
        if (g_character.exchange(index) != index)
        {
            std::lock_guard<std::mutex> lock(g_lock);
            g_entries.clear();
            g_levels.clear();
            g_groupLearned.clear();
            g_elementalMissing = -1;
            g_ready = false;
            g_nextSnapshot = 0;
        }
    }

    int Skills::GetCharacter() { return g_character.load(); }

    bool Skills::Ready()
    {
        std::lock_guard<std::mutex> lock(g_lock);
        return g_installed && g_ready;
    }

    bool Skills::Snapshot(std::vector<Entry>* out, int* learned, int* total)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        *out = g_entries;
        *learned = g_learned;
        *total = g_total;
        return g_installed && g_ready;
    }

    void Skills::RequestLearn(uint16_t knowledgeRow)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        QueueRow(knowledgeRow, g_character.load());
    }

    void Skills::RequestLearnAllMissing()
    {
        std::lock_guard<std::mutex> lock(g_lock);
        g_learnAll = true;
    }

    // The tree is written once, before g_treeBuilt flips, on the thread that
    // snapshots; afterwards it is only read, so the UI reads it under g_lock
    // together with the per-character counts.
    bool Skills::KnowledgeGroups(uint16_t parent, std::vector<KnowledgeGroup>* out)
    {
        out->clear();
        std::lock_guard<std::mutex> lock(g_lock);
        if (!g_installed || !g_ready || !g_treeBuilt || g_groupLearned.size() != g_tree.size()) return false;
        for (size_t i = 0; i < g_tree.size(); ++i)
        {
            const GroupNode& node = g_tree[i];
            if (!node.loaded || !node.shown || node.parent != parent || node.rows.empty()) continue;
            KnowledgeGroup g;
            g.index = static_cast<uint16_t>(i);
            g.learned = g_groupLearned[i];
            g.total = static_cast<int>(node.rows.size());
            snprintf(g.name, sizeof(g.name), "%s", node.name);
            out->push_back(g);
        }
        return true;
    }

    bool Skills::KnowledgeEntries(uint16_t group, std::vector<KnowledgeEntry>* out)
    {
        out->clear();
        std::lock_guard<std::mutex> lock(g_lock);
        if (!g_installed || !g_ready || !g_treeBuilt || group >= g_tree.size()) return false;
        const uintptr_t knowRows = Ptr(Ptr(g_knowledgeGlobal) + kOff_Table_Rows);
        // The group that lists each row, for the description line.
        std::unordered_map<uint16_t, uint16_t> lister;
        std::vector<uint16_t> stack{ group };
        while (!stack.empty())
        {
            const uint16_t gi = stack.back();
            stack.pop_back();
            if (gi >= g_tree.size()) continue;
            for (const uint16_t r : g_tree[gi].own) lister.emplace(r, gi);
            for (const uint16_t c : g_tree[gi].children) stack.push_back(c);
        }
        for (const uint16_t r : g_tree[group].rows)
        {
            KnowledgeEntry e;
            e.row = r;
            e.level = r < g_levels.size() ? g_levels[r] : 0;
            if (r < g_rowInternal.size()) snprintf(e.key, sizeof(e.key), "%s", g_rowInternal[r].c_str());
            uint32_t key = 0;
            const char* en = knowRows && mem::Read32(Ptr(knowRows + 8ull * r) + kOff_Knowledge_Key, &key) ? EnglishName(key)
                                                                                                          : nullptr;
            if (en) snprintf(e.name, sizeof(e.name), "%s", en);
            else ReadableKnowledge(e.key, e.name, sizeof(e.name));
            const auto it = lister.find(r);
            if (it != lister.end()) snprintf(e.group, sizeof(e.group), "%s", g_tree[it->second].name);
            out->push_back(e);
        }
        std::sort(out->begin(), out->end(), [](const KnowledgeEntry& a, const KnowledgeEntry& b) {
            if ((a.level == 0) != (b.level == 0)) return a.level == 0;
            return std::strcmp(a.name, b.name) < 0;
        });
        return true;
    }

    uint16_t Skills::FindKnowledgeGroup(const char* internalName)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        if (!g_treeBuilt) return kNoGroup;
        for (size_t i = 0; i < g_tree.size(); ++i)
            if (g_tree[i].loaded && !std::strcmp(g_tree[i].internal, internalName)) return static_cast<uint16_t>(i);
        return kNoGroup;
    }

    void Skills::RequestLearnGroup(uint16_t group)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        if (group != kNoGroup) g_groupRequests.push_back(group);
    }

    void Skills::RequestLearnJournal()
    {
        std::lock_guard<std::mutex> lock(g_lock);
        g_learnJournal = true;
    }

    void Skills::RequestLearnElementalMagic()
    {
        std::lock_guard<std::mutex> lock(g_lock);
        g_learnElemental = true;
    }

    int Skills::ElementalMissing()
    {
        std::lock_guard<std::mutex> lock(g_lock);
        return g_elementalMissing;
    }

    int Skills::Pending()
    {
        std::lock_guard<std::mutex> lock(g_lock);
        return static_cast<int>(g_queue.size());
    }

    void Skills::CancelPending()
    {
        std::lock_guard<std::mutex> lock(g_lock);
        const size_t dropped = g_queue.size();
        for (const LearnItem& item : g_queue)
            if (item.row < g_queued.size()) g_queued[item.row] = 0;
        g_queue.clear();
        g_jobActive = false;
        g_learnAll = g_learnElemental = g_learnJournal = false;
        g_groupRequests.clear();
        if (dropped)
            snprintf(g_status, sizeof(g_status), "Stopped - %d unlocked, %zu skipped.", g_jobOk, dropped);
    }

    void Skills::LastStatus(char* buf, size_t cap)
    {
        std::lock_guard<std::mutex> lock(g_lock);
        snprintf(buf, cap, "%s", g_status);
    }
}
