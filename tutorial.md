# Nanahira Usage Tutorial

This guide walks you through building, loading, and using the Nanahira kernel manual mapping injector.

---

## Order of Operations

```
  1. Build  →  2. Load driver  →  3. Start target  →  4. Inject
```

---

## 1. Build

### Prerequisites
* **Visual Studio 2026 Build Tools:** MSVC v145 (14.51) with the "Desktop development with C++" workload.
* **WDK & SDK:** Windows Driver Kit / SDK 10.0.28000.0 (must match `WindowsTargetPlatformVersion` in both `.vcxproj` files).
* **Kernel PDB:** `D:\Ameger\Mapper\Build\Symbols\ntkrnlmp.pdb` by default, or set `PDB_PATH`. `build_release.bat` verifies its GUID against the live `ntoskrnl.exe` before generating `driver\offsets.h`. Rust/Cargo is not required.

To build the project automatically:

```batch
build_release.bat
```

This verifies the kernel PDB GUID, regenerates `driver\offsets.h`, applies source mutation, compiles both projects with MSVC v145, restores the source files, and applies 10 binary PE mutations. Outputs land in `output/`, alongside `offsets.buildinfo`.

For a manual build, open `nanahira.sln` in Visual Studio 2026 Build Tools, select `Release | x64`, run `tools\dia-offsetgen\build_and_run.bat` first, then build, then run `quick_spoof.bat`.

---

The driver (`driver.sys`) needs to be loaded into the kernel.

### Option A: Test Signing (legacy — not used on this host)

This path is retained for other machines. On this host VBS/HVCI/WDAC were disabled and the external mapper (Option B) is used instead.

1. **One-time setup:** Run the following commands as Administrator and reboot your PC:
   ```batch
   bcdedit /set testsigning on
   bcdedit /set nointegritychecks on
   ```

2. **Self-sign the driver:** Run this PowerShell block as Administrator to generate a local cert and sign the binary:
   ```powershell
   # Self-sign the driver
   $cert = New-SelfSignedCertificate -Subject "CN=Nanahira" -Type CodeSigningCert -CertStoreLocation "Cert:\LocalMachine\My"
   $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
   $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
   $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher","LocalMachine")
   $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
   Set-AuthenticodeSignature -FilePath "output\driver.sys" -Certificate $cert
   ```

3. **Register and Start the Service:**
   ```batch
   sc create nanahira type= kernel binPath= "C:\path\to\output\driver.sys"
   sc start nanahira
   ```

### Option B: External mapper (used on this host)

Test signing is not used. The driver is manually mapped with the mapper already staged at `D:\Ameger\Mapper`.

1. **Build** with `build_release.bat` (elevated). Output: `output\driver.sys`.
2. **Map**, from an elevated shell:
   ```batch
   D:\Ameger\Mapper\Build\Release\Mapper.exe D:\Ameger\Nanahira\output\driver.sys
   ```
3. **Verify** with `output\nanahira.exe`.

Do not run the mapper from this workspace shell; it requires elevation and is executed by the operator.

---

## 3. Inject

Once the driver is active, you can launch the injector. Specify your target process and DLL path:

```batch
:: Default kernel manual mapping mode
output\nanahira.exe target.exe C:\path\to\dll.dll

:: Thread hijack mode (hijacks an existing thread; no new threads created)
output\nanahira.exe target.exe C:\path\to\dll.dll --hijack

:: WinEventHook injection mode (no CreateRemoteThread)
output\nanahira.exe target.exe C:\path\to\dll.dll --mode=hook

:: Usermode fallback injection mode (no driver required)
output\nanahira.exe target.exe C:\path\to\dll.dll --mode=usermode

:: GUI/CLI Mode
output\nanahira.exe
```

---

## 4. Re-spoof Binaries

To apply fresh PE binary mutations without recompiling the source code:

```batch
quick_spoof.bat
```
*(Make sure to re-sign `driver.sys` after running this).*

---

## Unload Driver

To stop and remove the registered kernel service safely:

```batch
sc stop nanahira
sc delete nanahira
```

---

## Injection Flags

Per-injection behavior can be controlled via flags defined in `shared/protocol.h`:

| Flag | Effect |
|:---|:---|
| `INJ_FLAG_ERASE_HEADERS` | Zero out PE headers in the target process after mapping |
| `INJ_FLAG_STOMP_HEADERS` | Overwrite PE headers with LFSR junk instead of zeros |
| `INJ_FLAG_SKIP_TLS` | Skip execution of TLS callbacks |
| `INJ_FLAG_SKIP_EXCEPTIONS` | Skip `RtlAddFunctionTable` exception directory call |
| `INJ_FLAG_THREAD_HIJACK` | Hijack an existing thread to execute the entry point |
