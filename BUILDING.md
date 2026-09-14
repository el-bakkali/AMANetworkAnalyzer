# Building AMA Network Analyzer

Run everything from the repository root.

## Prerequisites

Windows 10 or 11, and the .NET 10 SDK. Nothing else.

```powershell
dotnet --version
```

## Run it

```powershell
dotnet run --project src/AMANetworkAnalyzer
```

The window opens straight away. Drop a `.pcap`, `.pcapng`, `.etl`, or `.cab` file on it, or use Open Capture.

## Build and test

```powershell
dotnet build AMANetworkAnalyzer.sln -c Release
dotnet test AMANetworkAnalyzer.sln -c Release
```

The build treats warnings as errors, so anything the analyzers flag will fail it. The test project covers the parsers and the diagnostic rules. Run it before opening a pull request.

Build output lands in `src\AMANetworkAnalyzer\bin\Release\net10.0-windows\AMANetworkAnalyzer.exe`.

## Publish

Framework-dependent, which needs the .NET 10 Desktop Runtime on the target machine:

```powershell
dotnet publish src/AMANetworkAnalyzer -c Release -r win-x64 --self-contained false -o publish
```

Self-contained, which does not:

```powershell
dotnet publish src/AMANetworkAnalyzer -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o publish
```

For anything you intend to hand to someone else, use `build-release.ps1`. It builds Release, runs the tests, publishes, zips the output, and writes `SHA256SUMS.txt` so recipients can verify what they got.

## Targeting an older .NET

Change `TargetFramework` in both project files together:

- `src\AMANetworkAnalyzer\AMANetworkAnalyzer.csproj` to `net8.0-windows`
- `src\AMANetworkAnalyzer.Core\AMANetworkAnalyzer.Core.csproj` to `net8.0`

They have to move together, or the project reference will not resolve.

---

## ETL and CAB support

`.etl` files from `netsh trace` are converted to pcapng by Microsoft's etl2pcapng (MIT). The app fetches v1.11.0 on first use and verifies it against a pinned SHA-256.

It looks in three absolute locations, in order:

1. `%LOCALAPPDATA%\AMANetworkAnalyzer\tools\etl2pcapng.exe`, where downloads are cached
2. `tools\etl2pcapng.exe` next to the app
3. `etl2pcapng.exe` next to the app

The working directory and `PATH` are deliberately not searched. An attacker can influence both, and this binary gets executed (CWE-426). The hash is re-checked on every launch, so a copy you supply yourself has to match the pinned one exactly.

### Air-gapped machines

Download `etl2pcapng.exe` from the v1.11.0 release on a connected machine and put it in any of the three locations above. A different build will be rejected, including a newer one.

### Upgrading etl2pcapng

Update `PinnedVersion`, `DownloadUrl`, `ExpectedSha256` and `ExpectedSizeBytes` together at the top of `EtlConverter.cs`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `dotnet` not recognised | Install the .NET SDK from https://dotnet.microsoft.com |
| Build fails on a warning | Intentional. `TreatWarningsAsErrors` is on, so fix the warning |
| `NU1100: Unable to resolve` on publish | Drop `--self-contained` and publish framework-dependent |
| Window opens blank | Check display scaling and try 100% |
| ETL download fails | No connectivity. Put a hash-matching `etl2pcapng.exe` in `%LOCALAPPDATA%\AMANetworkAnalyzer\tools\` |
| "SHA-256 verification FAILED" | The file does not match the pinned hash. Re-download from the official release rather than working around it |

