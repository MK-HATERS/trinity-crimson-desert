#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

namespace trinity::game
{
    // Troc ("TrocTr*Req") is the engine's in-process client->server request
    // system. Every request type has ONE static handler object:
    //   obj+0x00  vtable (RTTI ".?AV<Name>@pa@@"), slot 2 = Handle(obj, int* err, Packet*)
    //   obj+0x0C  u16 message id      obj+0x21 u8 disabled      obj+0x22 char name[0x65]
    // Handle() parses the packet payload and runs the server logic for the
    // sender, exactly as when the game's own UI sends the request. Locating the
    // handler through its RTTI name keeps this independent of addresses that
    // move between title updates.
    //
    // Packet (only the fields Handle() reads):
    //   +0x00 sender owner (server-realm character the request acts for)
    //   +0x10 u16 total byte count (5-byte header + payload)
    //   +0x18 ptr  bytes: [u16 msgId][u8 0][u16 payloadLen][payload...]
    //   +0x38 u8  "trusted" flag (0 = enforce payload <= 0x7FC1)
    struct TrocHandler
    {
        uintptr_t obj = 0;
        uintptr_t handle = 0;
        uint16_t  msgId = 0;
    };

    namespace troc
    {
        // Resolves (and caches) the static handler for e.g. "TrocTrLearnSkillReq".
        bool Find(const char* name, TrocHandler* out);

        // Runs the request in the server realm on the game thread. Returns false
        // if the call faulted; *outErr receives the engine's result code
        // (0 = accepted). The payload layout is the request's own.
        bool Send(const TrocHandler& h, uintptr_t sender, const void* payload,
                  uint16_t payloadLen, uint32_t* outErr);

        // --- Server pump ------------------------------------------------------
        // Some requests (spawning, hiring) only work while the server is
        // already processing a message: they rely on per-thread server state
        // that a call from anywhere else does not have. InstallServerPump()
        // hooks the handler of TrocTrMoveActorReq - which the server runs
        // whenever the player moves - and, right after the original, runs every
        // posted request with a copy of that real packet (same sender, same
        // context), only the message bytes replaced.
        bool InstallServerPump();
        bool ServerPumpReady();

        struct Completion
        {
            uint32_t ticket = 0;
            bool     ran = false;    // handler returned (false: faulted / handler missing)
            uint32_t err = 0;        // handler result code
        };

        // Queues a request; returns a ticket (0 when the name does not resolve).
        uint32_t Post(const char* name, const void* payload, uint16_t payloadLen);

        // Same, but run on the server's MAIN dispatch loop, right after it has
        // finished a request (the point DesertLink Spawn Any NPC uses). Spawning
        // needs this: TrocTrSpawnCharacterCheatReq run inside MoveActorReq (the
        // movement loop, another thread) returns 0 but no body ever appears.
        // Uses the sender of the last MoveActorReq packet.
        uint32_t PostMain(const char* name, const void* payload, uint16_t payloadLen);
        // PostMain with an explicit packet sender (+0x00). The spawn logic reads
        // the sender as the spawning character (vt+0x160 user, kind byte
        // [+0x88]+1 == 1 -> recorded in the spawn descriptor); DesertLink passes
        // the player's controlled SERVER actor here, not the MoveActorReq one.
        uint32_t PostMainAs(const char* name, const void* payload, uint16_t payloadLen, uintptr_t sender);
        // Runs fn on the server thread at the same point as PostMain (right
        // after the main dispatcher returns), for direct engine calls that must
        // not race the server (actor removal). fn must not throw.
        bool PostMainTask(std::function<void()> fn);
        // Completions not yet collected (oldest first); clears them.
        void TakeCompletions(Completion* out, size_t cap, size_t* count);
        size_t Pending();
    }
}
