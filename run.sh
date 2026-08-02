#!/usr/bin/env bash
# ============================================================
#  SecKit launcher - build and run SecKit on macOS/Linux.
# ============================================================
set -e
cd "$(dirname "$0")"

if ! command -v dotnet >/dev/null 2>&1; then
    echo "[ERROR] The .NET 8 SDK was not found on your PATH."
    echo "Install it from https://dotnet.microsoft.com/download and try again."
    exit 1
fi

echo "Building SecKit (first run may take a minute)..."
dotnet build -c Release -v quiet

echo
dotnet run -c Release --no-build
