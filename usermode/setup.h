#pragma once

// Preflight only. Loading is performed by the external mapper, so this file
// deliberately never touches bcdedit, the service database, or the registry.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "nanahira.h"

static const char* SetupEnvOr(const char* name, const char* fallback, char* buf, DWORD sz)
{
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) == 0 && value && *value) {
        strncpy_s(buf, sz, value, sz - 1);
        free(value);
    } else {
        strncpy_s(buf, sz, fallback, sz - 1);
    }
    return buf;
}

static const char* SetupMapperPath()
{
    static char buf[MAX_PATH];
    return SetupEnvOr("NANAHIRA_MAPPER",
                      "D:\\Ameger\\Mapper\\Build\\Release\\Mapper.exe", buf, MAX_PATH);
}

static const char* SetupPdbPath()
{
    static char buf[MAX_PATH];
    return SetupEnvOr("PDB_PATH",
                      "D:\\Ameger\\Mapper\\Build\\Symbols\\ntkrnlmp.pdb", buf, MAX_PATH);
}

static bool SetupIsAdmin()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION elev = {};
    DWORD sz = sizeof(elev);
    BOOL ok = GetTokenInformation(tok, TokenElevation, &elev, sz, &sz);
    CloseHandle(tok);
    return ok && elev.TokenIsElevated;
}

static bool SetupValidDriver(const char* path)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    IMAGE_DOS_HEADER dos = {};
    DWORD read = 0;
    bool ok = ReadFile(h, &dos, sizeof(dos), &read, nullptr)
           && dos.e_magic == IMAGE_DOS_SIGNATURE;

    if (ok) {
        ok = SetFilePointer(h, dos.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER;
    }
    if (ok) {
        IMAGE_NT_HEADERS64 nt = {};
        ok = ReadFile(h, &nt, sizeof(nt), &read, nullptr)
          && nt.Signature == IMAGE_NT_SIGNATURE
          && nt.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
    }
    CloseHandle(h);
    return ok;
}

static void SetupRow(const char* label, bool ok)
{
    printf("  %s  %-28s\n", ok ? CLR_GREEN "[OK]" CLR_RESET
                               : CLR_RED  "[!!]" CLR_RESET, label);
}

static void SetupPreflight()
{
    char exe[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    char* slash = strrchr(exe, '\\');
    if (slash) *(slash + 1) = '\0';

    char sys[MAX_PATH];
    snprintf(sys, sizeof(sys), "%sdriver.sys", exe);
    char stamp[MAX_PATH];
    snprintf(stamp, sizeof(stamp), "%soffsets.buildinfo", exe);

    printf(CLR_PURPLE CLR_BOLD "  N A N A H I R A" CLR_RESET
           "  preflight  v%d.%d.%d\n\n",
           PROTO_VER_MAJOR, PROTO_VER_MINOR, PROTO_VER_PATCH);

    SetupRow("elevated operator", SetupIsAdmin());
    SetupRow("driver.sys present", GetFileAttributesA(sys) != INVALID_FILE_ATTRIBUTES);
    SetupRow("driver.sys valid x64", SetupValidDriver(sys));
    SetupRow("offsets stamp present", GetFileAttributesA(stamp) != INVALID_FILE_ATTRIBUTES);
    SetupRow("kernel PDB present", GetFileAttributesA(SetupPdbPath()) != INVALID_FILE_ATTRIBUTES);
    SetupRow("mapper present", GetFileAttributesA(SetupMapperPath()) != INVALID_FILE_ATTRIBUTES);

    printf(CLR_GRAY "\n  map: %s\n  pdb: %s\n\n" CLR_RESET,
           SetupMapperPath(), SetupPdbPath());
    printf(CLR_GRAY "  No system settings changed. Mapper handles driver loading.\n\n" CLR_RESET);
}

// Kept as the public entry point for compatibility with older callers.
static void RunSetupWizard() { SetupPreflight(); }
