#include <windows.h>
#include <string.h>

#define PATCH_RVA   0x2154F0
#define PATCH_SIZE  15

static const BYTE expected[PATCH_SIZE] = {
    0x6A, 0x01,
    0xFF, 0x15, 0x58, 0x81, 0x63, 0x00,
    0x50,
    0xFF, 0x15, 0xB4, 0x81, 0x63, 0x00
};

static void ApplyPatch(void)
{
    HMODULE hExe = GetModuleHandle(NULL);
    if (!hExe)
        return;

    BYTE* target = (BYTE*)hExe + PATCH_RVA;

    /* Guard against a different exe build/version being loaded: only patch
       if the bytes at this location are exactly what we expect. */
    __try {
        if (memcmp(target, expected, PATCH_SIZE) != 0)
            return;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return; /* target not mapped / access violation -- bail out safely */
    }

    DWORD oldProtect;
    if (!VirtualProtect(target, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect))
        return;

    memset(target, 0x90, PATCH_SIZE);

    VirtualProtect(target, PATCH_SIZE, oldProtect, &oldProtect);
    FlushInstructionCache(hExe, target, PATCH_SIZE);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            ApplyPatch();
            break;
    }
    return TRUE;
}
