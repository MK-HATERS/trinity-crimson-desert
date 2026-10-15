# Fork additions — Trinity 1.5.2 (Crimson Desert 2.03.02, PE 1.0.0.2976)

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

## 1.5.2 — modifier hotkeys, weather mods

**New: Ctrl / Shift / Alt hotkeys.** The Menu, Marker Teleport and Tame Nearest Mount keys can be bound to a
combination such as **Ctrl+F9**: in SYSTEM → Keybinds, select the row, hold the modifier and press the key. A
bind fires only with exactly its modifiers, so plain F9 can be left to another mod (KliffWings opens on F9,
CalmerDynamicWind toggles on F10). Fly and menu-navigation keys stay single keys, because Ctrl is Fly Down.
In `Trinity.ini` a modifier adds to the key code: Ctrl +256, Shift +512, Alt +1024 (Ctrl+F9 = `376`).

**Fixed: CalmerDynamicWind did nothing with Trinity installed.** Trinity hooked the rain, snow, dust and wind
functions at startup even when its weather options were never used; CalmerDynamicWind refuses to hook a
function another mod already holds, so it installed nothing. Those four hooks are now installed only the first
time a weather option leaves its default.

## 1.5.1 — works alongside other ASI mods

**Fixed: Inventory, Teleport, Game Speed and most queued features did nothing when other ASI mods were
installed.** ASI loaders load mods alphabetically, so Trinity usually loads last. Mods that hook the same game
functions first (for example KliffWings and DesertLinkDyeStudio) overwrite the start of those functions with a
jump, so Trinity's byte signatures no longer matched in memory. `Trinity.log` showed:

```text
teleport: movement-update signature NOT FOUND - position tracking disabled.
inventory: holder resolver signature NOT FOUND - inventory disabled.
world: FrameTimerUpdate signature not found - Game Speed disabled.
```

The movement-update and frame-timer hooks also drive the per-frame work for Player, Inventory, Dye,
Equipment, Skills, Mounts & Pets and Ghost Mode, so losing them broke far more than the three features named.

When a signature misses in memory, Trinity now looks it up in the unmodified `CrimsonDesert.exe` on disk
(same build only, unique match required), hooks the live function on top of the other mod's detour, and both
mods run. The log names the mod that got there first:

```text
teleport: movement-update: live bytes were patched (hooked by KliffWings.asi); resolved from the on-disk exe @ ... - chaining.
```

**Changed: `Trinity_Crash.txt` no longer reports other mods' handled errors as crashes.** The exception logger
sees every fault in the process before the faulting module's own handler runs, so a mod that catches its own
errors (CrimsonInvEditor does every 5 seconds) filled the file with false "crash reports". Entries are now
labelled first-chance exceptions with the module named; it was only a crash if the game closed at that time.

If two mods offer the same feature (inventory editing, dyes, damage numbers, teleport), both now run. If one
misbehaves, disable the duplicate first.

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
