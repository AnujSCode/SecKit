@echo off
REM ============================================================
REM  SecKit launcher - double-click to build and run SecKit.
REM ============================================================
title SecKit
cd /d "%~dp0"

where dotnet >nul 2>nul
if errorlevel 1 (
    echo [ERROR] The .NET 8 SDK was not found on your PATH.
    echo Install it from https://dotnet.microsoft.com/download and try again.
    echo.
    pause
    exit /b 1
)

echo Building SecKit (first run may take a minute)...
dotnet build -c Release -v quiet
if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. See the messages above.
    pause
    exit /b 1
)

echo.
dotnet run -c Release --no-build

echo.
echo SecKit exited. Press any key to close.
pause >nul
