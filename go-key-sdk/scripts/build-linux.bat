@echo off
setlocal enabledelayedexpansion
REM ============================================================
REM  Build Linux binaries from Windows (pure Go, CGO disabled)
REM
REM    scripts\build-linux.bat            -> linux/amd64
REM    scripts\build-linux.bat arm64      -> linux/arm64
REM
REM  Output: dist\linux-<arch>\
REM ============================================================

set "ARCH=%~1"
if "%ARCH%"=="" set "ARCH=amd64"

if /I "%ARCH%"=="amd64" (
  set "GOARCH=amd64"
) else if /I "%ARCH%"=="arm64" (
  set "GOARCH=arm64"
) else (
  echo usage: build-linux.bat [amd64^|arm64]
  exit /b 2
)

where go >nul 2>nul
if errorlevel 1 (
  if exist "C:\Program Files\Go\bin\go.exe" (
    set "GO=C:\Program Files\Go\bin\go.exe"
  ) else (
    echo [ERROR] go not found in PATH
    exit /b 1
  )
) else (
  set "GO=go"
)

cd /d "%~dp0.."

set "CGO_ENABLED=0"
set "GOOS=linux"
set "GOARCH=%GOARCH%"
set "OUT=dist\linux-%GOARCH%"

if not exist "%OUT%" mkdir "%OUT%"

set "LDFLAGS=-s -w -X example.com/key-sdk/keyclient.Version=1.0.0"

echo.
echo === building for linux/%GOARCH% ===
echo output: %OUT%
echo.

for %%B in (central devca dbsetup smoke vectorcheck) do (
  echo [build] %%B
  "%GO%" build -trimpath -buildvcs=false -ldflags "%LDFLAGS%" -o "%OUT%\%%B" ./cmd/%%B
  if errorlevel 1 (
    echo [ERROR] build failed: %%B
    exit /b 1
  )
)

"%GO%" build -trimpath -buildvcs=false -ldflags "%LDFLAGS%" -o "%OUT%\goclient" ./examples/goclient
if errorlevel 1 (
  echo [ERROR] build failed: goclient
  exit /b 1
)

echo.
echo === result ===
dir /b "%OUT%"
echo.
echo Copy the whole folder to the Linux host, e.g.:
echo   scp -r %OUT% user@server:/opt/central-key-service/bin
echo.
echo On the server:
echo   chmod +x bin/*
echo   ./bin/central -config /etc/central-key/config.json
echo.

endlocal
