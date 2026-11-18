#include <windows.h>
#include <objbase.h>
#include <dia2.h>
#include <diacreate.h>
#include <cstdio>
#include <cwchar>
#include <cstring>

#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

struct Req { const wchar_t* type; const wchar_t* field; const char* macro; };

static const Req kReqs[] = {
    { L"_EPROCESS", L"UniqueProcessId",     "OFFSET_EPROCESS_UNIQUEPROCESSID" },
    { L"_EPROCESS", L"ActiveProcessLinks",  "OFFSET_EPROCESS_ACTIVEPROCESSLINKS" },
    { L"_EPROCESS", L"ImageFileName",       "OFFSET_EPROCESS_IMAGEFILENAME" },
    { L"_EPROCESS", L"DebugPort",           "OFFSET_EPROCESS_DEBUGPORT" },
    { L"_EPROCESS", L"ThreadListHead",      "OFFSET_EPROCESS_THREADLISTHEAD" },
    { L"_EPROCESS", L"Pcb",                 "OFFSET_EPROCESS_PCB" },
    { L"_EPROCESS", L"VadRoot",             "OFFSET_EPROCESS_VADROOT" },
    { L"_KTHREAD",  L"StackBase",           "OFFSET_KTHREAD_STACKBASE" },
    { L"_KTHREAD",  L"StackLimit",          "OFFSET_KTHREAD_STACKLIMIT" },
    { L"_KTHREAD",  L"Teb",                 "OFFSET_KTHREAD_TEB" },
    { L"_KTHREAD",  L"Process",             "OFFSET_KTHREAD_PROCESS" },
    { L"_KTHREAD",  L"State",               "OFFSET_KTHREAD_STATE" },
    // MM_AVL_TABLE is RTL_AVL_TABLE on modern kernels; there is no Root field.
    // The tree root is BalancedRoot.Right, resolved below.
    { L"_RTL_AVL_TABLE", L"BalancedRoot",   "OFFSET_MM_AVL_TABLE_ROOT" },
    { L"_MMVAD_SHORT", L"StartingVpn",      "OFFSET_MMVAD_STARTINGVPN" },
    { L"_MMVAD_SHORT", L"EndingVpn",        "OFFSET_MMVAD_ENDINGVPN" },
    { L"_MMVAD_SHORT", L"StartingVpnHigh",  "OFFSET_MMVAD_STARTINGVPNHIGH" },
    { L"_MMVAD_SHORT", L"EndingVpnHigh",    "OFFSET_MMVAD_ENDINGVPNHIGH" },
};

static bool FindUdt(IDiaSession* session, const wchar_t* name, IDiaSymbol** out) {
    IDiaSymbol* global = nullptr;
    if (FAILED(session->get_globalScope(&global))) return false;
    IDiaEnumSymbols* en = nullptr;
    HRESULT hr = global->findChildren(SymTagUDT, name, nsNone, &en);
    global->Release();
    if (FAILED(hr) || !en) return false;
    IDiaSymbol* sym = nullptr;
    ULONG got = 0;
    hr = en->Next(1, &sym, &got);
    en->Release();
    if (FAILED(hr) || !sym) return false;
    *out = sym;
    return true;
}

static bool FindField(IDiaSymbol* udt, const wchar_t* field, ULONG* offset) {
    IDiaEnumSymbols* en = nullptr;
    if (FAILED(udt->findChildren(SymTagData, field, nsNone, &en)) || !en) return false;
    IDiaSymbol* sym = nullptr;
    ULONG got = 0;
    HRESULT hr = en->Next(1, &sym, &got);
    en->Release();
    if (FAILED(hr) || !sym) return false;
    DWORD kind = 0;
    sym->get_locationType(&kind);
    LONG off = 0;
    bool ok = (kind == LocIsThisRel || kind == LocIsNull) && SUCCEEDED(sym->get_offset(&off));
    sym->Release();
    if (ok) *offset = (ULONG)off;
    return ok;
}

static bool FieldOffset(IDiaSession* session, const wchar_t* type,
                        const wchar_t* field, ULONG* offset) {
    IDiaSymbol* udt = nullptr;
    if (!FindUdt(session, type, &udt)) return false;
    bool ok = FindField(udt, field, offset);
    udt->Release();
    return ok;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::fwprintf(stderr, L"usage: dia_offsets <pdb>\n");
        return 2;
    }
    CoInitialize(nullptr);
    wchar_t dllBuf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"NANAHIRA_DIA_DLL", dllBuf, MAX_PATH);
    const wchar_t* dll = (n > 0 && n < MAX_PATH)
        ? dllBuf
        : L"C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\DIA SDK\\bin\\amd64\\msdia140.dll";
    IDiaDataSource* src = nullptr;
    HRESULT hr = NoRegCoCreate(dll, CLSID_DiaSource, IID_IDiaDataSource, (void**)&src);
    if (FAILED(hr) || !src) {
        std::fwprintf(stderr, L"NoRegCoCreate failed: 0x%08X\n", hr);
        return 3;
    }
    hr = src->loadDataFromPdb(argv[1]);
    if (FAILED(hr)) {
        std::fwprintf(stderr, L"loadDataFromPdb failed: 0x%08X\n", hr);
        return 4;
    }
    IDiaSession* session = nullptr;
    if (FAILED(src->openSession(&session)) || !session) {
        std::fwprintf(stderr, L"openSession failed\n");
        return 5;
    }

    if (argc >= 3 && wcscmp(argv[2], L"--list") == 0) {
        IDiaSymbol* global = nullptr;
        session->get_globalScope(&global);
        IDiaEnumSymbols* en = nullptr;
        global->findChildren(SymTagUDT, L".*(VAD|AVL_TABLE).*",
                             (NameSearchOptions)(nsfRegularExpression | nsfCaseSensitive), &en);
        global->Release();
        if (en) {
            IDiaSymbol* sym = nullptr;
            ULONG got = 0;
            while (SUCCEEDED(en->Next(1, &sym, &got)) && got) {
                BSTR n = nullptr; sym->get_name(&n);
                std::wprintf(L"%s\n", n ? n : L"?");
                if (n) SysFreeString(n);
                sym->Release();
            }
            en->Release();
        }
        session->Release(); src->Release(); CoUninitialize();
        return 0;
    }
    if (argc >= 3 && wcscmp(argv[2], L"--fields") == 0 && argc >= 4) {
        IDiaSymbol* udt = nullptr;
        if (!FindUdt(session, argv[3], &udt)) {
            std::fwprintf(stderr, L"no such UDT: %s\n", argv[3]);
            return 6;
        }
        IDiaEnumSymbols* en = nullptr;
        udt->findChildren(SymTagData, nullptr, nsNone, &en);
        if (en) {
            IDiaSymbol* sym = nullptr; ULONG got = 0;
            while (SUCCEEDED(en->Next(1, &sym, &got)) && got) {
                BSTR n = nullptr; sym->get_name(&n);
                DWORD kind = 0; sym->get_locationType(&kind);
                LONG off = 0; sym->get_offset(&off);
                if (kind == LocIsThisRel || kind == LocIsNull)
                    std::wprintf(L"%-32s 0x%04X\n", n ? n : L"?", (ULONG)off);
                if (n) SysFreeString(n);
                sym->Release();
            }
            en->Release();
        }
        udt->Release(); session->Release(); src->Release(); CoUninitialize();
        return 0;
    }

    int missing = 0, found = 0;
    std::printf("#pragma once\n\n// Generated from the kernel PDB that matches this host. Do not hand-edit.\n\n");
    for (const auto& r : kReqs) {
        IDiaSymbol* udt = nullptr;
        if (!FindUdt(session, r.type, &udt)) {
            std::fwprintf(stderr, L"MISSING UDT: %s\n", r.type);
            std::printf("// MISSING UDT %s\n", r.macro);
            ++missing;
            continue;
        }
        ULONG off = 0;
        if (!FindField(udt, r.field, &off)) {
            BSTR n = nullptr; udt->get_name(&n);
            std::fwprintf(stderr, L"MISSING FIELD: %s :: %s (as %hs)\n",
                          n ? n : r.type, r.field, r.macro);
            if (n) SysFreeString(n);
            std::printf("// MISSING FIELD %s\n", r.macro);
            ++missing;
        } else {
            ULONG value = off;
            if (std::strcmp(r.macro, "OFFSET_MM_AVL_TABLE_ROOT") == 0) {
                ULONG right = 0;
                if (!FieldOffset(session, L"_RTL_BALANCED_NODE", L"Right", &right)) {
                    std::fwprintf(stderr, L"MISSING FIELD: _RTL_BALANCED_NODE.Right\n");
                    std::printf("// MISSING FIELD _RTL_BALANCED_NODE.Right\n");
                    ++missing;
                    udt->Release();
                    continue;
                }
                value += right;
            }
            std::printf("#define %-45s 0x%04X\n", r.macro, value);
            ++found;
        }
        udt->Release();
    }
    std::fwprintf(stderr, L"found=%d missing=%d\n", found, missing);
    session->Release();
    src->Release();
    CoUninitialize();
    return missing ? 1 : 0;
}
