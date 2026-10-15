#pragma once

#include <cstdint>

namespace trinity::game
{
    // Side forced on a body Trinity spawned (Spawn Characters > Side).
    enum class Allegiance : uint8_t { None, Ally, Enemy, Neutral };

    // Ghost Mode: hostile NPCs cannot detect, target or keep aggro on the
    // player, even after attacks or contact. Port of DesertLink Mod Menu's
    // GhostModule (PE 1.0.0.2976): ten MinHooks on the
    // shared detect / target code (server, client and worker threads all run
    // it), each asking the engine's own relationship query whether the
    // perceiver treats the player as Enemy (0) before suppressing anything.
    //  - detection: candidate build, sense test, forced detect, detect slots;
    //  - targeting: CanTarget, SetCurrentTarget, engage lists, hate lists;
    //  - "hidden" predicate forced true for the player;
    //  - each NPC's detect update purges aggro it already had on the player.
    // Hooks are created on the first enable and stay installed; off makes every
    // detour a pass-through. Allies, neutrals and the player's mount are not
    // affected.
    //
    // The same hooks carry spawn allegiance: an eleventh hook on the engine's
    // relationship query (RelQuery, the only relation API: detection,
    // targeting, hate and damage all call it) answers for bodies given a side.
    //  - Ally: the player's side. Never hostile to the player or to anything on
    //    the player's side; sees everyone else the way the player is seen.
    //  - Enemy: hostile to the player and to the player's side.
    //  - Neutral: ignores the player's side until the player hurts it.
    // Writing the faction at status+0x342 does not change any of this (live
    // test 2026-10-15), so no faction is written.
    class Ghost
    {
    public:
        // Game thread: installs on first need, refreshes the player handles.
        static void Tick();
        // Hooks resolved and installed (false until the first need).
        static bool Installed();
        // True when installation was attempted and failed (feature unavailable).
        static bool Failed();

        // Any thread: a side is about to be used; the next Tick installs the hooks.
        static void PrepareAllegiance();
        // Game thread. False when the hooks are unavailable or 64 bodies already
        // have a side.
        static bool SetAllegiance(uint32_t handle, Allegiance side);
        static void ClearAllegiance(uint32_t handle);
    };
}
