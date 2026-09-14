# build-release.ps1 — Builds, tests and packages AMA Network Analyzer for GitHub Releases
# Usage: .\build-release.ps1

$ErrorActionPreference = "Stop"

$Version     = "2.1.0"
$Solution    = "AMANetworkAnalyzer.sln"
$ProjectPath = "src\AMANetworkAnalyzer\AMANetworkAnalyzer.csproj"
$Runtime     = "win-x64"
$OutputDir   = "release"
$ZipName     = "AMANetworkAnalyzer-v$Version-$Runtime.zip"

Write-Host "Building AMA Network Analyzer v$Version..." -ForegroundColor Cyan

if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutputDir | Out-Null

# A release must never ship code that fails its own tests.
Write-Host "Running tests..." -ForegroundColor Cyan
dotnet test $Solution -c Release --nologo
if ($LASTEXITCODE -ne 0) { Write-Error "Tests failed - release aborted."; exit 1 }

Write-Host "Publishing..." -ForegroundColor Cyan
dotnet publish $ProjectPath -c Release -r $Runtime --self-contained false -o "$OutputDir\app"
if ($LASTEXITCODE -ne 0) { Write-Error "Publish failed"; exit 1 }

Write-Host "Creating $ZipName..." -ForegroundColor Cyan
Compress-Archive -Path "$OutputDir\app\*" -DestinationPath "$OutputDir\$ZipName"

$exe = Get-Item "$OutputDir\app\AMANetworkAnalyzer.exe"
$zip = Get-Item "$OutputDir\$ZipName"

# Publish the hashes so users can verify what they downloaded.
$exeHash = (Get-FileHash $exe.FullName -Algorithm SHA256).Hash
$zipHash = (Get-FileHash $zip.FullName -Algorithm SHA256).Hash
"SHA256 ($($exe.Name)) = $exeHash`nSHA256 ($($zip.Name)) = $zipHash" |
    Set-Content "$OutputDir\SHA256SUMS.txt" -Encoding utf8

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "  EXE: $($exe.FullName) ($([math]::Round($exe.Length / 1KB)) KB)"
Write-Host "  ZIP: $($zip.FullName) ($([math]::Round($zip.Length / 1KB)) KB)"
Write-Host "  SHA256 (zip): $zipHash"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Go to https://github.com/el-bakkali/AMANetworkAnalyzer/releases/new"
Write-Host "  2. Choose tag: v$Version"
Write-Host "  3. Title: AMA Network Analyzer v$Version"
Write-Host "  4. Attach: $OutputDir\$ZipName and $OutputDir\SHA256SUMS.txt"
Write-Host "  5. Publish release"
