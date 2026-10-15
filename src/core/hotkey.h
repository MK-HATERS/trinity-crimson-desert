#pragma once
#include <Windows.h>

// Keyboard binds for the global hotkeys (menu, marker teleport, tame) carry
// optional modifiers above the virtual-key byte, so one int still persists
// each bind in Trinity.ini: Ctrl+F9 = 0x100 | VK_F9 = 376.
namespace trinity::hotkey
{
    inline constexpr int kVkMask = 0xFF;
    inline constexpr int kCtrl   = 0x100;
    inline constexpr int kShift  = 0x200;
    inline constexpr int kAlt    = 0x400;
    inline constexpr int kModMask = kCtrl | kShift | kAlt;

    inline bool IsModifierVk(int vk)
    {
        return vk == VK_SHIFT || vk == VK_CONTROL || vk == VK_MENU ||
               (vk >= VK_LSHIFT && vk <= VK_RMENU);
    }

    inline int HeldModifiers()
    {
        int mods = 0;
        if (GetAsyncKeyState(VK_CONTROL) & 0x8000) mods |= kCtrl;
        if (GetAsyncKeyState(VK_SHIFT)   & 0x8000) mods |= kShift;
        if (GetAsyncKeyState(VK_MENU)    & 0x8000) mods |= kAlt;
        return mods;
    }

    // The bind's key is held with exactly its modifiers, so plain F9 and
    // Ctrl+F9 can be bound to different things (or left to other mods).
    inline bool Down(int bind)
    {
        const int vk = bind & kVkMask;
        if (vk == 0 || !(GetAsyncKeyState(vk) & 0x8000))
            return false;
        return HeldModifiers() == (bind & kModMask);
    }

    // Accepted range for a persisted bind: a key byte plus modifier bits.
    inline bool Valid(int bind)
    {
        return bind >= 0 && (bind & ~(kVkMask | kModMask)) == 0 &&
               !((bind & kModMask) && (bind & kVkMask) == 0);
    }
}
