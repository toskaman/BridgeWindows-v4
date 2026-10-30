@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo  BridgeWindows Agent v4 - Legacy Build (XP SP3 / Win7 x86)
echo  AGENT_LEGACY_XP: CryptoAPI instead of CNG, no Vista+ API
echo =======================================================

set LMINGW=E:\toolchains\llvm-mingw-20261020-msvcrt-i686\bin\i686-w64-mingw32-gcc.exe
if not exist "%LMINGW%" ( echo [ERROR] llvm-mingw msvcrt-i686 not found at E:\toolchains. & exit /b 1 )

:: MSVCRT (XP inbox) instead of UCRT; subsystem/OS 5.01 for the XP loader.
:: -mwindows: GUI subsystem, no console window (the status window has a Show console button).
:: NOTE: a -mwindows binary detaches from cmd instantly with no stdout -- this is
:: expected. Verify via the daemon /status (or the status window), not console output.
"%LMINGW%" -DAGENT_LEGACY_XP -O2 -s -mwindows ^
    agent.c gui.c -o agent-legacy-x86.exe ^
    -lws2_32 -ladvapi32 -luser32 -lgdi32 -lpsapi -lcomctl32 -lshell32 ^
    -Wl,--major-os-version,5 -Wl,--minor-os-version,1 ^
    -Wl,--major-subsystem-version,5 -Wl,--minor-subsystem-version,1
if errorlevel 1 ( echo [ERROR] legacy build failed. & exit /b 1 )

for %%I in (agent-legacy-x86.exe) do echo [SUCCESS] agent-legacy-x86.exe (x86 legacy, %%~zI bytes)

if not exist agents mkdir agents
copy /y agent-legacy-x86.exe agents\agent-win-x86-legacy.exe >nul
echo [SUCCESS] staged agents\agent-win-x86-legacy.exe
echo =======================================================
