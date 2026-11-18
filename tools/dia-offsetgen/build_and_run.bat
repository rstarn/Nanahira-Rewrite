@echo off
setlocal enabledelayedexpansion

rem Regenerate driver\offsets.h from the kernel PDB that matches the running
rem ntoskrnl.exe. Uses the DIA SDK already shipped with VS 2026 Build Tools.
rem No cargo, no registry writes, no symbol-server downloads.

set "ROOT=%~dp0..\.."
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "DIAINC=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\DIA SDK\include"
set "DIALIB=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\DIA SDK\lib\amd64"
if defined NANAHIRA_VCVARS set "VCVARS=%NANAHIRA_VCVARS%"
if defined NANAHIRA_DIAINC set "DIAINC=%NANAHIRA_DIAINC%"
if defined NANAHIRA_DIALIB set "DIALIB=%NANAHIRA_DIALIB%"
set "PDB=%PDB_PATH%"
if not defined PDB set "PDB=D:\Ameger\Mapper\Build\Symbols\ntkrnlmp.pdb"
set "WORK=%TEMP%\nanahira_dia"
set "OUT=%ROOT%\driver\offsets.h"

if not exist "%VCVARS%" (
    echo  [x] vcvars64.bat not found: !VCVARS!
    exit /b 1
)
if not exist "%PDB%" (
    echo  [x] Kernel PDB not found: %PDB%
    echo      Set PDB_PATH to the ntkrnlmp.pdb matching this Windows build.
    exit /b 1
)

echo  [1/3] Verifying PDB GUID against live ntoskrnl.exe...
python "%~dp0verify_pdb.py" "%PDB%"
if errorlevel 1 (
    echo  [x] PDB mismatch - refusing to write offsets.h
    exit /b 1
)

echo  [2/3] Building DIA offset generator...
if not exist "%WORK%" mkdir "%WORK%"
call "%VCVARS%" >nul 2>&1
cl /nologo /EHsc /O2 /I"%DIAINC%" /Fo"%WORK%\dia_offsets.obj" "%~dp0dia_offsets.cpp" /link /LIBPATH:"%DIALIB%" ole32.lib oleaut32.lib advapi32.lib /OUT:"%WORK%\dia_offsets.exe" >nul 2>&1
if errorlevel 1 (
    echo  [x] Failed to build DIA offset generator
    exit /b 1
)

echo  [3/3] Extracting offsets from %PDB%...
"%WORK%\dia_offsets.exe" "%PDB%" > "%WORK%\offsets.h"
if errorlevel 1 (
    echo  [x] One or more required symbols were not found in the PDB
    type "%WORK%\offsets.h"
    exit /b 1
)

move /Y "%WORK%\offsets.h" "%OUT%" >nul
if not exist "%ROOT%\output" mkdir "%ROOT%\output"
> "%ROOT%\output\offsets.buildinfo" echo kernel=ntoskrnl.exe
>> "%ROOT%\output\offsets.buildinfo" echo pdb=%PDB%
>> "%ROOT%\output\offsets.buildinfo" echo generated=%DATE% %TIME%
echo  [+] Wrote %OUT%
exit /b 0
