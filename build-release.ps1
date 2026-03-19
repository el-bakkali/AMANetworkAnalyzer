# build-release.ps1 — Builds and packages AMA Network Analyzer for GitHub Releases
# Usage: .\build-release.ps1

$ErrorActionPreference = "Stop"
$Version = "1.0.0"
$ProjectPath = "src\AMANetworkAnalyzer\AMANetworkAnalyzer.csproj"
$OutputDir = "release"
$ZipName = "AMANetworkAnalyzer-v$Version-win-x64.zip"

Write-Host "Building AMA Network Analyzer v$Version..." -ForegroundColor Cyan

# Clean
if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutputDir | Out-Null

# Build
dotnet publish $ProjectPath -c Debug -o "$OutputDir\app"
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

# Create zip for GitHub Release
Write-Host "Creating $ZipName..." -ForegroundColor Cyan
Compress-Archive -Path "$OutputDir\app\*" -DestinationPath "$OutputDir\$ZipName"

# Summary
$exe = Get-Item "$OutputDir\app\AMANetworkAnalyzer.exe"
$zip = Get-Item "$OutputDir\$ZipName"
Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "  EXE: $($exe.FullName) ($([math]::Round($exe.Length / 1KB)) KB)"
Write-Host "  ZIP: $($zip.FullName) ($([math]::Round($zip.Length / 1KB)) KB)"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Go to https://github.com/el-bakkali/AMANetworkAnalyzer/releases/new"
Write-Host "  2. Choose tag: v$Version"
Write-Host "  3. Title: AMA Network Analyzer v$Version"
Write-Host "  4. Attach: $OutputDir\$ZipName"
Write-Host "  5. Publish release"
