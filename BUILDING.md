# Building & Running AMA Network Analyzer

## Prerequisites

- **Windows 10/11**
- **.NET 10 SDK** (or .NET 8/9 — change `TargetFramework` in the `.csproj` to `net8.0-windows` or `net9.0-windows`)
- No other dependencies required

Check your SDK version:

```powershell
dotnet --version
```

---

## Option 1: Run Directly (Development)

This compiles and launches the app in one step. No `.exe` is produced in a publish folder — it runs from the build output.

```powershell
dotnet run --project "C:\Source\AMANetworkAnalyzer\src\AMANetworkAnalyzer\AMANetworkAnalyzer.csproj"
```

The WPF window will open immediately. Drop a `.pcap`, `.pcapng`, or `.etl` file to start analysis.

---

## Option 2: Build Only (No Run)

Compiles the project and produces output in the `bin\` folder:

```powershell
dotnet build "C:\Source\AMANetworkAnalyzer\src\AMANetworkAnalyzer\AMANetworkAnalyzer.csproj"
```

The compiled exe will be at:

```
src\AMANetworkAnalyzer\bin\Debug\net10.0-windows\AMANetworkAnalyzer.exe
```

To build Release:

```powershell
dotnet build "C:\Source\AMANetworkAnalyzer\src\AMANetworkAnalyzer\AMANetworkAnalyzer.csproj" -c Release
```

---

## Option 3: Publish an .exe (For Distribution)

### Framework-dependent (small exe, requires .NET runtime on target machine)

```powershell
dotnet publish "C:\Source\AMANetworkAnalyzer\src\AMANetworkAnalyzer\AMANetworkAnalyzer.csproj" -c Debug -o C:\Source\AMANetworkAnalyzer\publish
```

Output: `C:\Source\AMANetworkAnalyzer\publish\AMANetworkAnalyzer.exe` (~160 KB)

> The target machine needs the .NET 10 Desktop Runtime installed.
> Download from: https://dotnet.microsoft.com/download/dotnet/10.0

### Self-contained single file (large exe, no runtime needed)

> **Note:** This requires the .NET runtime packages to be available in your NuGet cache. With .NET 10 preview SDKs, this may fail. Use .NET 8 or .NET 9 GA for reliable self-contained builds.

```powershell
dotnet publish "C:\Source\AMANetworkAnalyzer\src\AMANetworkAnalyzer\AMANetworkAnalyzer.csproj" -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o C:\Source\AMANetworkAnalyzer\publish
```

Output: `publish\AMANetworkAnalyzer.exe` (~60 MB, fully self-contained, no installer)

---

## Switching .NET Version

If you need to target .NET 8 or 9 instead of 10, edit the `.csproj`:

```xml
<!-- Change this line in AMANetworkAnalyzer.csproj -->
<TargetFramework>net8.0-windows</TargetFramework>
```

Then all build/publish commands work the same way.

---

## ETL File Support

For `.etl` files (from `netsh trace start`), the app uses Microsoft's open-source `etl2pcapng.exe` (MIT license).

**It downloads automatically with integrity verification.** When you drop an `.etl` file:
1. The app checks for `etl2pcapng.exe` locally (same folder, `tools\` subfolder, or system PATH)
2. If not found, downloads **v1.11.0** from https://github.com/microsoft/etl2pcapng/releases/tag/v1.11.0
3. Verifies integrity before use
4. Saves verified binary to `tools\` folder (one-time download, ~160 KB)

### Offline / air-gapped machines

If the machine has no internet access, manually download `etl2pcapng.exe` from the v1.11.0 release and place it:
- Same folder as `AMANetworkAnalyzer.exe`, or
- In a `tools\` subfolder next to the exe, or
- Anywhere on the system `PATH`

### Upgrading etl2pcapng

To pin to a newer version, update the constants at the top of `EtlConverter.cs` (version, URL, and hash).

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `dotnet` not recognized | Install .NET SDK from https://dotnet.microsoft.com |
| `NU1100: Unable to resolve` on publish | Use `-c Debug` without `-r win-x64 --self-contained`, or switch to .NET 8/9 GA |
| App launches but window is blank | Check Windows display scaling; try running at 100% |
| ETL files show download error | Check internet connectivity; or manually place `etl2pcapng.exe` in the `tools\` subfolder |
