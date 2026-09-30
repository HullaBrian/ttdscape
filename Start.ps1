# Builds the analyzer and the viewer (if needed) and starts the local TTDscape server.
#   powershell -ExecutionPolicy Bypass -File .\Start.ps1 [-Port 5177] [-Rebuild] [-SymbolPath "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"]
param(
    [int]$Port = 5177,
    [switch]$Rebuild,
    [string]$SymbolPath = ""
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Find-CMake {
    $c = Get-Command cmake -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath
    $p = Join-Path $vs "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    if (Test-Path $p) { return $p }
    throw "CMake not found. Install Visual Studio with the C++ workload (includes CMake)."
}

$analyzer = Join-Path $PSScriptRoot "build\analyzer\RelWithDebInfo\ttdscape-analyzer.exe"
if ($Rebuild -or -not (Test-Path $analyzer)) {
    $cmake = Find-CMake
    $vsMajor = (& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property catalog_productLineVersion)
    $preset = if ($vsMajor -eq "2022") { "vs2022-x64" } else { "x64" }
    & $cmake -S analyzer --preset $preset
    & $cmake --build build/analyzer --config RelWithDebInfo
    if ($LASTEXITCODE -ne 0) { throw "analyzer build failed" }
}

$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    if (Test-Path "$env:ProgramFiles\nodejs\node.exe") { $env:Path = "$env:ProgramFiles\nodejs;$env:Path" }
    else { throw "Node.js 22.12+ is required." }
}
if (-not (Test-Path "node_modules")) { npm install; if ($LASTEXITCODE -ne 0) { throw "npm install failed" } }
if ($Rebuild -or -not (Test-Path "client\dist\index.html")) { npm run build; if ($LASTEXITCODE -ne 0) { throw "viewer build failed" } }

$env:TTDSCAPE_PORT = "$Port"
if ($SymbolPath) { $env:TTDSCAPE_SYMBOL_PATH = $SymbolPath }
Write-Host "Open http://127.0.0.1:$Port"
node server/index.mjs
