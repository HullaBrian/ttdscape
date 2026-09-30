# Records the TTDscape fixture with TTD. Requires elevation (TTD's recorder needs admin);
# re-launches itself elevated if necessary (you will see a UAC prompt).
#   powershell -ExecutionPolicy Bypass -File fixtures\record-fixture.ps1 [-Arch x64|x86] [-Name fixture01]
# Output: fixtures\traces\<Name>.run and <Name>.truth.json
param(
    [ValidateSet("x64", "x86")] [string]$Arch = "x64",
    [string]$Name = "",
    [string]$Exe = ""
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $Name) { $Name = if ($Arch -eq "x86") { "fixture86" } else { "fixture01" } }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $Exe) {
    if ($Arch -eq "x86") {
        $Exe = Join-Path $root "build\fixture-x86\RelWithDebInfo\ttdscape-fixture.exe"
        if (-not $isAdmin -and -not (Test-Path $Exe)) {
            $cmake = Get-Command cmake -ErrorAction SilentlyContinue
            $cmakeExe = if ($cmake) { $cmake.Source } else {
                $vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath
                Join-Path $vs "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" }
            & $cmakeExe -S (Join-Path $PSScriptRoot "app") -B (Join-Path $root "build\fixture-x86") -A Win32 | Out-Null
            & $cmakeExe --build (Join-Path $root "build\fixture-x86") --config RelWithDebInfo | Out-Null
        }
    } else {
        $Exe = Join-Path $root "build\analyzer\fixtures\RelWithDebInfo\ttdscape-fixture.exe"
    }
}
if (-not (Test-Path $Exe)) { throw "fixture executable not found: $Exe (build the analyzer first)" }
$Exe = (Resolve-Path $Exe).Path

if (-not $isAdmin) {
    $shell = (Get-Process -Id $PID).Path
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"", "-Arch", $Arch, "-Name", $Name, "-Exe", "`"$Exe`"")
    $p = Start-Process -FilePath $shell -ArgumentList $argList -Verb RunAs -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "elevated recording failed with exit code $($p.ExitCode)" }
    Write-Host "recorded $(Join-Path $PSScriptRoot "traces\$Name.run")"
    exit 0
}

$outDir = Join-Path $PSScriptRoot "traces"
New-Item -ItemType Directory -Force $outDir | Out-Null
$run = Join-Path $outDir "$Name.run"
$truth = Join-Path $outDir "$Name.truth.json"
Remove-Item -ErrorAction SilentlyContinue $run, (Join-Path $outDir "$Name.idx"), (Join-Path $outDir "$Name.out"), $truth
ttd.exe -acceptEula -noUI -out $run $Exe $truth | Out-Host
if (-not (Test-Path $run)) {
    # Some TTD versions append a sequence number to the requested name.
    $made = Get-ChildItem $outDir -Filter "$Name*.run" | Sort-Object LastWriteTime | Select-Object -Last 1
    if ($made) { Move-Item $made.FullName $run -Force }
}
if (-not (Test-Path $run) -or -not (Test-Path $truth)) { throw "recording failed: $run / $truth missing" }
Write-Host "recorded $run"
