# Start a local test environment for the central key service.
#   .\scripts\dev.ps1
#   .\scripts\dev.ps1 -Port 9443
#   .\scripts\dev.ps1 -Memory
# ASCII only on purpose: works in both Windows PowerShell 5.1 and PowerShell 7,
# regardless of the file encoding.
param(
    [int]$Port = 8443,
    [string]$Config = "",
    [switch]$Memory,
    [switch]$SkipCerts
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

# Config resolution: explicit -Config > config.local.json > config.example.json
if (-not $Config) {
    if (Test-Path "config.local.json") { $Config = "config.local.json" } else { $Config = "config.example.json" }
}

$go = "go"
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    $candidate = "C:\Program Files\Go\bin\go.exe"
    if (Test-Path $candidate) {
        $go = $candidate
    } else {
        throw "go not found. Add Go to PATH or install it."
    }
}

if (-not $SkipCerts -and -not (Test-Path "certs/ca.crt")) {
    Write-Host "== generating dev CA and client certificates =="
    & $go run ./cmd/devca -out ./certs -systems SYS-A,SYS-B
}

New-Item -ItemType Directory -Force data | Out-Null
if (-not $env:KEY_KEK) {
    if (Test-Path "data/kek.hex") {
        $env:KEY_KEK = (Get-Content "data/kek.hex" -Raw).Trim()
    } else {
        $bytes = New-Object byte[] 32
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($bytes)
        $rng.Dispose()
        $hex = -join ($bytes | ForEach-Object { $_.ToString("x2") })
        Set-Content -Path "data/kek.hex" -Value $hex -NoNewline
        $env:KEY_KEK = $hex
        Write-Host "== generated data/kek.hex (do not commit) =="
    }
}

$argsList = @("-config", $Config, "-addr", "127.0.0.1:$Port")
if ($Memory) {
    $argsList += @("-data", "", "-audit", "")
}

Write-Host ""
Write-Host "  config  : $Config"
Write-Host "  service : https://127.0.0.1:$Port"
Write-Host "  admin   : https://127.0.0.1:$Port/admin   (user: admin, password: admin token)"
Write-Host "  smoke   : go run ./cmd/smoke -base https://127.0.0.1:$Port"
Write-Host ""

& $go run ./cmd/central @argsList
