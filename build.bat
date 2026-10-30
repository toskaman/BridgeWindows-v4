@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo  BridgeWindows Agent v4 - Native Build Script
echo =======================================================

:: Usage: build.bat [x86^|x64^|all]   (default: x86, output agent.exe)
set TARGET=%1
if "%TARGET%"=="" set TARGET=x86

set GCC32="%USERPROFILE%\scoop\apps\mingw-winlibs\current\bin\gcc.exe"
set WINDRES32="%USERPROFILE%\scoop\apps\mingw-winlibs\current\bin\windres.exe"
set GCC64="%USERPROFILE%\scoop\apps\gcc\current\bin\gcc.exe"
set WINDRES64="%USERPROFILE%\scoop\apps\gcc\current\bin\windres.exe"

set COMMON_SRCS=agent.c gui.c
set COMMON_LIBS=-lws2_32 -ladvapi32 -luser32 -lgdi32 -lpsapi -lbcrypt -lcomctl32 -lshell32
:: GUI subsystem: no console window; the status window has a Show console button.
:: --headless still attaches/allocates a console at runtime.
set GUI_FLAGS=-mwindows

if "%TARGET%"=="x64" goto :do_x64
if "%TARGET%"=="all" goto :do_all
call :build_x86
if errorlevel 1 exit /b 1
goto :usage

:do_x64
call :build_x64
if errorlevel 1 exit /b 1
goto :usage

:do_all
call :build_x86
if errorlevel 1 exit /b 1
call :build_x64
if errorlevel 1 exit /b 1
goto :usage

:build_x86
echo [BUILD] x86: agent.c + gui.c -^> agent.exe
if not exist %GCC32% ( echo [ERROR] 32-bit GCC not found. & exit /b 1 )
:: NOTE: no agent.rc on x86 - the i686 toolchain already embeds a comctl32 v6
:: manifest; adding ours fails the link with "multiple non-default manifests".
%GCC32% -O2 -s -static %GUI_FLAGS% %COMMON_SRCS% -o agent.exe %COMMON_LIBS%
if errorlevel 1 ( echo [ERROR] Compilation x86 failed. & exit /b 1 )
for %%I in (agent.exe) do echo [SUCCESS] agent.exe (x86, %%~zI bytes)
exit /b 0

:build_x64
echo [BUILD] x64: agent.c + gui.c -^> agent_x64.exe
if not exist %GCC64% ( echo [ERROR] 64-bit GCC not found. & exit /b 1 )
%WINDRES64% agent.rc agent_x64_res.o
if errorlevel 1 ( echo [ERROR] windres x64 failed. & exit /b 1 )
%GCC64% -O2 -s -static %GUI_FLAGS% %COMMON_SRCS% agent_x64_res.o -o agent_x64.exe %COMMON_LIBS%
if errorlevel 1 ( echo [ERROR] Compilation x64 failed. & exit /b 1 )
del agent_x64_res.o
for %%I in (agent_x64.exe) do echo [SUCCESS] agent_x64.exe (x64, %%~zI bytes)
exit /b 0

:usage
echo.
echo Usage on Remote PC:
echo   agent.exe --host ^<MASTER_IP^> --port 9876 --token ^<YOUR_PSK^> --agent-id ^<PC_NAME^>
echo   (add --headless to run without the status window)
echo =======================================================
