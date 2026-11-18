#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>

#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif

#pragma runtime_checks("", off)
#pragma optimize("", off)

// Sentinel values are compiled into the shellcode as 64-bit immediates and
// patched by the injector before it is written to the target. Keeping them as
// named constants means the scan pattern is generated from the same value.
static constexpr uintptr_t kHookBaseSentinel = 0x15846254168ull;
static constexpr uintptr_t kHookFlagSentinel = 0x24856841253ull;

static void __stdcall HookShellcode()
{
    uintptr_t base      = kHookBaseSentinel;
    uintptr_t flag_addr = kHookFlagSentinel;

    *(volatile BYTE*)flag_addr = 0x69;

    BYTE* pBase = (BYTE*)base;
    auto* pDos  = (IMAGE_DOS_HEADER*)pBase;
    auto* pNt   = (IMAGE_NT_HEADERS64*)(pBase + pDos->e_lfanew);
    auto* pOpt  = &pNt->OptionalHeader;

    using fn_LoadLibraryA    = HMODULE(WINAPI*)(const char*);
    using fn_GetProcAddress  = FARPROC(WINAPI*)(HMODULE, const char*);
    using fn_RtlAddFuncTable = BOOL(WINAPI*)(void*, DWORD, DWORD64);

    auto getPEB = []() -> BYTE* {
#ifdef _WIN64
        return (BYTE*)__readgsqword(0x60);
#else
        return (BYTE*)__readfsdword(0x30);
#endif
    };

    auto hashStr = [](const wchar_t* s) -> ULONG {
        ULONG h = 0;
        for (; *s; s++) h = h * 31 + (*s | 0x20);
        return h;
    };

    auto findModule = [&](ULONG nameHash) -> BYTE* {
        BYTE* peb = getPEB();
        BYTE* ldr = *(BYTE**)(peb + 0x18);
        LIST_ENTRY* head = (LIST_ENTRY*)(ldr + 0x10);
        for (LIST_ENTRY* e = head->Flink; e != head; e = e->Flink) {
            BYTE* entry = (BYTE*)e;
            UNICODE_STRING* name = (UNICODE_STRING*)(entry + 0x58);
            if (!name->Buffer) continue;
            if (hashStr(name->Buffer) == nameHash)
                return *(BYTE**)(entry + 0x30);
        }
        return nullptr;
    };

    auto findExport = [](BYTE* modBase, const char* funcName) -> void* {
        auto* dos = (IMAGE_DOS_HEADER*)modBase;
        auto* nt  = (IMAGE_NT_HEADERS64*)(modBase + dos->e_lfanew);
        ULONG expRva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG expSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!expRva) return nullptr;
        auto* exp     = (IMAGE_EXPORT_DIRECTORY*)(modBase + expRva);
        auto* names   = (ULONG*)(modBase + exp->AddressOfNames);
        auto* ords    = (USHORT*)(modBase + exp->AddressOfNameOrdinals);
        auto* funcs   = (ULONG*)(modBase + exp->AddressOfFunctions);
        for (ULONG i = 0; i < exp->NumberOfNames; i++) {
            const char* n = (const char*)(modBase + names[i]);
            const char* a = n, *b = funcName;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a != *b) continue;
            ULONG rva = funcs[ords[i]];
            if (rva >= expRva && rva < expRva + expSize) continue;
            return modBase + rva;
        }
        return nullptr;
    };

    // Hash with the same routine defined above; baked-in ROR13 hashes belong
    // to a different algorithm and never matched this loader.
    BYTE* k32  = findModule(hashStr(L"kernel32.dll"));
    BYTE* ntdl = findModule(hashStr(L"ntdll.dll"));

    auto _LoadLibraryA    = (fn_LoadLibraryA)   findExport(k32,  "LoadLibraryA");
    auto _GetProcAddress  = (fn_GetProcAddress)  findExport(k32,  "GetProcAddress");
    auto _RtlAddFuncTable = (fn_RtlAddFuncTable) findExport(ntdl, "RtlAddFunctionTable");

    if (!_LoadLibraryA || !_GetProcAddress) return;

    ptrdiff_t Delta = pBase - (BYTE*)(uintptr_t)pOpt->ImageBase;
    if (Delta && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* reloc    = (IMAGE_BASE_RELOCATION*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        auto* relocEnd = (IMAGE_BASE_RELOCATION*)((uintptr_t)reloc + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
        while (reloc < relocEnd && reloc->SizeOfBlock) {
            WORD* entry = (WORD*)(reloc + 1);
            UINT  count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (UINT i = 0; i < count; i++, entry++)
                if ((*entry >> 0xC) == IMAGE_REL_BASED_DIR64)
                    *(uintptr_t*)(pBase + reloc->VirtualAddress + (*entry & 0xFFF)) += (uintptr_t)Delta;
            reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; imp->Name; imp++) {
            HMODULE hMod = _LoadLibraryA((char*)(pBase + imp->Name));
            auto* orig   = (uintptr_t*)(pBase + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            auto* iat    = (uintptr_t*)(pBase + imp->FirstThunk);
            for (; *orig; orig++, iat++) {
                if (IMAGE_SNAP_BY_ORDINAL(*orig))
                    *iat = (uintptr_t)_GetProcAddress(hMod, (char*)(*orig & 0xFFFF));
                else
                    *iat = (uintptr_t)_GetProcAddress(hMod, ((IMAGE_IMPORT_BY_NAME*)(pBase + *orig))->Name);
            }
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* tls = (IMAGE_TLS_DIRECTORY64*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* cb  = (PIMAGE_TLS_CALLBACK*)(tls->AddressOfCallBacks);
        for (; cb && *cb; cb++)
            (*cb)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    if (_RtlAddFuncTable && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size)
        _RtlAddFuncTable(
            pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress,
            pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
            (DWORD64)pBase
        );

    auto _DllMain = (BOOL(WINAPI*)(void*, DWORD, void*))(pBase + pOpt->AddressOfEntryPoint);
    _DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);
}

#pragma optimize("", off)
#pragma runtime_checks("", off)
static void HookShellcode_End() { __nop(); }
#pragma runtime_checks("", restore)
#pragma optimize("", on)
#pragma runtime_checks("", restore)

static inline PBYTE ScanPattern(PVOID imageBase, SIZE_T imageSize, const char* pat, const char* mask)
{
    SIZE_T mlen = strlen(mask);
    for (SIZE_T i = 0; i < imageSize - mlen; i++) {
        PBYTE addr = (PBYTE)imageBase + i;
        bool match = true;
        for (SIZE_T j = 0; j < mlen; j++) {
            if (mask[j] == 'x' && addr[j] != (BYTE)pat[j]) { match = false; break; }
        }
        if (match) return addr;
    }
    return nullptr;
}

template <uintptr_t Sentinel>
static inline bool PatchSentinel(BYTE* code, SIZE_T len, uintptr_t value)
{
    BYTE pat[sizeof(value)];
    for (SIZE_T i = 0; i < sizeof(value); ++i)
        pat[i] = (BYTE)(Sentinel >> (i * 8));

    BYTE* at = ScanPattern(code, len, reinterpret_cast<const char*>(pat), "xxxxxxxx");
    if (!at) return false;
    memcpy(at, &value, sizeof(value));
    return true;
}

static inline int ScFunctionLength(const void* fn) {
    // Explicit casts avoid the MSVC "pointer-to-function -> pointer-to-object"
    // extension warning while measuring the compiled shellcode body.
    return (int)((const BYTE*)reinterpret_cast<const void*>(&HookShellcode_End)
               - (const BYTE*)fn);
}

static inline void ApplySectionProtections(HANDLE hProc, BYTE* remoteBase, IMAGE_NT_HEADERS64* nt)
{
    auto* secs = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        auto* s = secs + i;
        DWORD chars   = s->Characteristics;
        BOOL  isExec  = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL  isRead  = (chars & IMAGE_SCN_MEM_READ)    != 0;
        BOOL  isWrite = (chars & IMAGE_SCN_MEM_WRITE)   != 0;

        DWORD prot = PAGE_NOACCESS;
        if      (isExec && isRead && isWrite) prot = PAGE_EXECUTE_READWRITE;
        else if (isExec && isRead)            prot = PAGE_EXECUTE_READ;
        else if (isExec)                      prot = PAGE_EXECUTE;
        else if (isRead && isWrite)           prot = PAGE_READWRITE;
        else if (isRead)                      prot = PAGE_READONLY;

        SIZE_T secSize = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
        if (!secSize) continue;

        DWORD old;
        VirtualProtectEx(hProc, remoteBase + s->VirtualAddress, secSize, prot, &old);
    }
}

struct HookInjector {
    static bool inject(DWORD pid, const wchar_t* dllPath)
    {
        DWORD threadId = 0;
        {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            THREADENTRY32 te = { sizeof(te) };
            if (Thread32First(snap, &te)) do {
                if (te.th32OwnerProcessID == pid) { threadId = te.th32ThreadID; break; }
            } while (Thread32Next(snap, &te));
            CloseHandle(snap);
        }
        if (!threadId) return false;

        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProc) return false;

        HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) { CloseHandle(hProc); return false; }
        DWORD fileSize = GetFileSize(hFile, NULL);
        BYTE* fileData = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        DWORD read = 0;
        ReadFile(hFile, fileData, fileSize, &read, NULL);
        CloseHandle(hFile);

        auto* dos = (IMAGE_DOS_HEADER*)fileData;
        auto* nt  = (IMAGE_NT_HEADERS64*)(fileData + dos->e_lfanew);

        BYTE* remoteBase = (BYTE*)VirtualAllocEx(hProc, NULL, nt->OptionalHeader.SizeOfImage,
                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteBase) { VirtualFree(fileData, 0, MEM_RELEASE); CloseHandle(hProc); return false; }

        WriteProcessMemory(hProc, remoteBase, fileData, nt->OptionalHeader.SizeOfHeaders, NULL);
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            if (sec->SizeOfRawData)
                WriteProcessMemory(hProc, remoteBase + sec->VirtualAddress,
                                   fileData + sec->PointerToRawData, sec->SizeOfRawData, NULL);
        }

        BYTE* flagBase = (BYTE*)VirtualAllocEx(hProc, NULL, sizeof(DWORD), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        BYTE* scRemote = (BYTE*)VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!flagBase || !scRemote) {
            if (flagBase) VirtualFreeEx(hProc, flagBase, 0, MEM_RELEASE);
            if (scRemote) VirtualFreeEx(hProc, scRemote, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
            VirtualFree(fileData, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }

        int scLen = ScFunctionLength(reinterpret_cast<const void*>(&HookShellcode));
        BYTE* scLocal = (BYTE*)VirtualAlloc(NULL, scLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        memcpy(scLocal, reinterpret_cast<const void*>(&HookShellcode), scLen);

        bool patched = PatchSentinel<kHookBaseSentinel>(scLocal, scLen, (uintptr_t)remoteBase)
                    && PatchSentinel<kHookFlagSentinel>(scLocal, scLen, (uintptr_t)flagBase);

        if (!patched) {
            VirtualFree(scLocal, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, scRemote, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, flagBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
            VirtualFree(fileData, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }

        WriteProcessMemory(hProc, scRemote, scLocal, scLen, NULL);
        VirtualFree(scLocal, 0, MEM_RELEASE);

        DWORD old;
        VirtualProtectEx(hProc, scRemote, 0x1000, PAGE_EXECUTE_READ, &old);

        HMODULE ntdll = LoadLibraryA("ntdll.dll");
        HWINEVENTHOOK hook = SetWinEventHook(
            EVENT_MIN, EVENT_MAX,
            ntdll,
            (WINEVENTPROC)scRemote,
            pid, threadId,
            WINEVENT_INCONTEXT
        );

        if (!hook) {
            VirtualFreeEx(hProc, scRemote, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, flagBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
            VirtualFree(fileData, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }

        BYTE  flag    = 0;
        DWORD timeout = 10000;
        while (flag != 0x69 && timeout > 0) {
            ReadProcessMemory(hProc, flagBase, &flag, 1, NULL);
            Sleep(10);
            timeout -= 10;
        }

        UnhookWinEvent(hook);

        if (flag == 0x69)
            ApplySectionProtections(hProc, remoteBase, nt);

        VirtualFreeEx(hProc, scRemote, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, flagBase, 0, MEM_RELEASE);
        VirtualFree(fileData, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (flag == 0x69);
    }
};
