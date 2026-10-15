#pragma once

namespace trinity::game
{
    // Developer probe - a file-driven command channel for live reverse
    // engineering. While "Trinity_probe.in" exists beside Trinity.asi, Tick()
    // (game thread) consumes it line by line, executes each command and appends
    // the results to "Trinity_probe.out". With no input file it costs one
    // throttled GetFileAttributes per 250 ms and does nothing else.
    //
    // Commands (addresses are static VAs as in the IDB, 0x140000000 base; they
    // are rebased to the live module automatically. Prefix with '=' for an
    // absolute runtime address):
    //   owners                         client/server player owners + component chain
    //   table <name> [indirect]        resolve a "*info" table global (string anchor)
    //   read <addr> <len>              guarded hex dump (len <= 4096)
    //   readp <addr> <off,off,...>     follow a pointer chain, printing each hop
    //   call <addr> <realm> [args...]  call a native function (up to 7 args),
    //                                  realm = c | s | - (client / server / leave)
    //     arg forms: 0x.. / decimal, @srv @cli (owners), @srvsub @clisub (+0x68),
    //                buf<N> (zeroed N-byte scratch, dumped after the call),
    //                u16:<v> u32:<v> u64:<v> (pointer to a scratch value)
    class DevProbe
    {
    public:
        static void Tick();
    };
}
