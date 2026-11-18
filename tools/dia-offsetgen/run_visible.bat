@echo off
chcp 65001 >nul
title Nanahira offset generator

call "%~dp0build_and_run.bat"
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo  [+] Offset generation succeeded.
) else (
    echo  [x] Offset generation FAILED with code %RC%.
)
echo.
pause
exit /b %RC%
