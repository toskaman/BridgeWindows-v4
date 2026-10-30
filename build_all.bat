@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo  BridgeWindows Agent v4 - Full Build Matrix
echo  win-x86, win-x64, win-arm64, linux-x64, linux-arm64
echo =======================================================

set ZIG="%USERPROFILE%\scoop\shims\zig.exe"
set FAIL=0

:: 1. Windows x86 + x64 (native MinGW)
call build.bat all
if errorlevel 1 set FAIL=1

:: 2. Windows ARM64 (zig cross)
echo [BUILD] win-arm64: agent.c + gui.c -^> agent_arm64.exe
if not exist %ZIG% ( echo [WARN] zig not found, skipping arm64. ) else (
    %ZIG% cc -target aarch64-windows -O2 -s -Wl,--subsystem,windows agent.c gui.c -o agent_arm64.exe -lws2_32 -ladvapi32 -luser32 -lgdi32 -lpsapi -lbcrypt -lcomctl32 -lshell32 2>nul
    if errorlevel 1 ( echo [ERROR] win-arm64 failed. & set FAIL=1 ) else (
        for %%I in (agent_arm64.exe) do echo [SUCCESS] agent_arm64.exe win-arm64 %%~zI bytes
    )
)

:: 3. Linux x86_64 + aarch64 (zig cross, static musl)
if not exist %ZIG% ( echo [WARN] zig not found, skipping linux. ) else (
    echo [BUILD] linux-x64: agent_linux.c -^> agent-linux-x64
    %ZIG% cc -target x86_64-linux-musl -O2 -s agent_linux.c -o agent-linux-x64 -lpthread -lm 2>nul
    if errorlevel 1 ( echo [ERROR] linux-x64 failed. & set FAIL=1 ) else (
        for %%I in (agent-linux-x64) do echo [SUCCESS] agent-linux-x64 %%~zI bytes
    )
    echo [BUILD] linux-arm64: agent_linux.c -^> agent-linux-arm64
    %ZIG% cc -target aarch64-linux-musl -O2 -s agent_linux.c -o agent-linux-arm64 -lpthread -lm 2>nul
    if errorlevel 1 ( echo [ERROR] linux-arm64 failed. & set FAIL=1 ) else (
        for %%I in (agent-linux-arm64) do echo [SUCCESS] agent-linux-arm64 %%~zI bytes
    )
)

if "%FAIL%"=="1" ( echo [BUILD] MATRIX FAILED. & exit /b 1 )

:: 4. Stage canonical names into agents/ + manifest
if not exist agents mkdir agents
copy /y agent.exe agents\agent-win-x86.exe >nul
copy /y agent_x64.exe agents\agent-win-x64.exe >nul
copy /y agent_arm64.exe agents\agent-win-arm64.exe >nul
copy /y agent-linux-x64 agents\agent-linux-x64 >nul
copy /y agent-linux-arm64 agents\agent-linux-arm64 >nul
del agents\SHA256SUMS 2>nul
for %%F in (agent-win-x86.exe agent-win-x64.exe agent-win-arm64.exe agent-linux-x64 agent-linux-arm64) do (
    for /f "skip=1 tokens=1" %%H in ('certutil -hashfile agents\%%F SHA256 ^| findstr /v "CertUtil"') do (
        echo %%H  %%F>> agents\SHA256SUMS
    )
)
echo [SUCCESS] agents/ staged + SHA256SUMS
echo =======================================================
