# Compile and run the vector tests (ASCII only, encoding independent).
$ErrorActionPreference = "Stop"

$javac = "javac"
$java = "java"
if ($env:JAVA_HOME) {
    $javac = Join-Path $env:JAVA_HOME "bin\javac.exe"
    $java = Join-Path $env:JAVA_HOME "bin\java.exe"
} elseif (-not (Get-Command javac -ErrorAction SilentlyContinue)) {
    $root = "C:\Program Files\Eclipse Adoptium"
    if (Test-Path $root) {
        $jdk = Get-ChildItem $root -Directory | Select-Object -First 1
        if ($jdk) {
            $javac = Join-Path $jdk.FullName "bin\javac.exe"
            $java = Join-Path $jdk.FullName "bin\java.exe"
        }
    }
}

Set-Location $PSScriptRoot
New-Item -ItemType Directory -Force out | Out-Null
& $javac -encoding UTF-8 -d out (Get-ChildItem -Recurse -Filter *.java src).FullName
& $javac -encoding UTF-8 -cp out -d out test/VectorTest.java
& $java "-Dfile.encoding=UTF-8" -cp out VectorTest @args
exit $LASTEXITCODE
