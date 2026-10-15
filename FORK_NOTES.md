# Fork additions — Trinity 1.5.0 (Crimson Desert 2.03.02, PE 1.0.0.2976)

This fork of Trinity (MIT, by XeTrinityz, vTweak maintenance by Lian) adds mounts and pets, NPC spawning
with sides, Ghost Mode, journal knowledge and elemental magic unlocks, combat options and a set of crash and
correctness fixes. Everything below was reverse-engineered on PE 1.0.0.2976 and tested in game, except
Max Health, Stamina Use, Damage Numbers and the journal (Knowledge page) unlocks, which are not verified in
game yet — report problems in the issues.

## Install

1. Install an ASI loader for Crimson Desert (`winmm.dll` or `dinput8.dll` in `bin64`).
2. Copy `Trinity.asi` and the `languages` folder from the release zip into `bin64` (the folder with
   `CrimsonDesert.exe`). Close the game before replacing the ASI.
3. Launch, load a save, press **Insert** (keyboard) or **LB + D-pad Down** (controller).

## New in 1.5.0

**WORLD → Spawn Characters**
- Any character from the game's own list: bosses, monsters and creatures, animals, people, everything else.
  Search, 1–10 at a time in a ring around you.
- **Side**: Default, **Ally** (never attacks you or your companions, fights your enemies), **Enemy**
  (hostile to you and your allies), **Neutral** (ignores you until you hurt it). Mix Ally and Enemy spawns
  for a battle.
- **Spawned NPCs**: every body you spawned, with distance and side; despawn one or all of them.

**COMBAT**
- **Ghost Mode**: enemies cannot detect or target you, even after you attack them; enemies already fighting
  you lose track within a moment.
- **Max Health** 2x / 5x / 10x, **Stamina Use** 50 / 20 / 10 %, **Damage Numbers** (dealt yellow, taken red).

**PLAYER → Skills**
- **Unlock Elemental Magic**: Spirit, the four elements (Flame, Frost, Lightning, Wind), the character's
  four elemental spells and Imbue Element. The game teaches the elements by meditating at fixed spots, so
  spells learned without them stay unusable — this unlocks the whole chain in the right order.

**PLAYER → Knowledge**
- The journal's own categories (characters, factions, regions, animals and creatures, discoveries,
  materials, collections, recipes and blueprints, quests and research) with counts per character.
- Unlock a whole category, one group or single entries; **Unlock All Journal Knowledge** (everything but
  Quests & Research); **Finish Institute Research** (83 projects); **Unlock Kuku Blueprints** (31).
- Unlocks are queued and can be stopped at any time. Quest knowledge can skip or lock quest steps, so it is
  never part of the "all" button.

**Mounts & pets** (PLAYER → Mount & Pet Options)
- My Mounts & Pets: change species (same family or any rideable family), edit stats (evolution level,
  attack, defense, health, vigor, speed, acceleration, turning, jump), rename, dismiss.
- **Add Any Mount / Add Any Pet**: spawned beside you and adopted. Tame Nearest Mount (F9), Add Nearby
  Mount / Pet, pet registration slots and pets summoned at once.

**Inventory**: Short Item Cooldowns (≤ 1 s) and 99 Item Charges, restored when turned off.

## Fixes

- Crash when changing graphics options (frame generation, resolution): the overlay now releases the swap
  chain's buffers before the game recreates it.
- Crash in the weapon wheel after refining gear past its enchant list; refine levels are clamped per item
  and saves with an out-of-range level are repaired.
- Money, stacking, durability, weather (wind) and thread-safety fixes from a code audit.
- Spawned characters appear beside you (world position = sector-local position + sector × 1000).

## How it works (short)

- **Troc requests.** Client and server run in one process. `troc.cpp` finds the game's request handlers
  (`TrocTr*Req`) by RTTI and runs them on the server thread right after the main dispatcher returns, with
  the player's controlled actor as sender (spawning uses the game's own `TrocTrSpawnCharacterCheatReq`).
- **Relations.** `ghost.cpp` hooks the perception and targeting code; NPC sides answer the engine's single
  relationship query (`RelQuery`) for the spawned bodies, so detection, targeting, hate and damage agree.
- **Knowledge.** Skills, elements and journal entries are knowledge rows learned through the game's own
  knowledge-apply function in the server realm, so they persist in the save. The journal tree is the game's
  `KnowledgeGroupInfo` table.
- **Mercenary records.** Mounts and pets are mercenaries (server clan `sub+0x110`, 0x1C0-byte records:
  `+0x20` characterinfo row, `+0x28` number, `+0x50` summoned body, `+0x120` evolution).

## Build

- **Release:** `Build_Trinity.ps1 -Configuration Release -BuildOnly` → `build-clean/Trinity.asi`.
- **With the developer probe** (file command channel used during RE): `re-tools/build_dev.ps1`
  (`-DENABLE_DEVPROBE=ON`). Never ship that build.

## Credits

- **Trinity:** XeTrinityz (original) and Lian (vTweak maintenance). MIT.
- **DesertLink Mod Menu** (DesertLink, Nexus 3638): Ghost Mode, NPC sides and despawn, Max Health,
  Stamina Use, Damage Numbers and the cooldown/charge options were developed by studying how DesertLink
  implements them. The code in this repository is our own and works against the game directly.
- **Character and knowledge names:** generated from NattKh's *CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS*
  data (MPL-2.0; see the headers).
- **Built by:** Claude (Anthropic, Claude Code) working with Matheus Lima, with live memory reads, capstone
  disassembly and in-game tests.

Single-player only. Not affiliated with or endorsed by Pearl Abyss.
