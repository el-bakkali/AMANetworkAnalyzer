# AMA Network Analyzer

A Windows desktop tool for novice engineers to diagnose Azure Monitor Agent (AMA) network connectivity issues by analyzing packet capture files.

**Drop a `.pcap`, `.pcapng`, or `.etl` file → get an instant diagnostic report.**

## Features

- **Drag-and-drop** `.pcap`, `.pcapng`, and `.etl` capture files
- **7 automated diagnostic rules** based on the AMA Network Troubleshooting Guide:
  1. **Endpoint Connectivity** — Verifies traffic to all required AMA endpoints
  2. **DNS Resolution** — Checks DNS queries/responses for AMA domains (NXDOMAIN, SERVFAIL)
  3. **Firewall Blocking** — Detects TCP RST packets and SYN retransmissions
  4. **Proxy Detection** — Finds HTTP CONNECT, proxy auth (407), and common proxy ports
  5. **TLS/SSL Analysis** — Detects TLS alerts, handshake failures, and version issues
  6. **TLS Cipher Compliance** — Validates offered/selected ciphers against AMA requirements:
     - TLS 1.3: `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`
     - TLS 1.2: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
  7. **Private Link / AMPLS Detection** — Detects when AMA endpoints resolve to private IPs, indicates AMPLS usage, and flags mixed public/private DNS misconfigurations
- **Sovereign cloud support** — Azure Commercial (`.com`), Azure Government (`.us`), and Azure China 21Vianet (`.cn`)
- **Wireshark filter suggestions** — Each finding includes a clickable Wireshark display filter (copies to clipboard)
- **Export reports** to text or Markdown
- **Dark-themed WPF UI** with pass/warn/error severity badges

## Zero Dependencies

- No NuGet packages
- No Wireshark/tshark installation required
- No Npcap/WinPcap
- No manual ETL tool setup — `etl2pcapng` is auto-downloaded on first ETL use
- Pure managed .NET — pcap/pcapng parsing, packet dissection, DNS/TLS/HTTP parsing all built-in

## Quick Start

See [BUILDING.md](BUILDING.md) for full build, run, and publish instructions.

```powershell
# Run directly (requires .NET 10 SDK)
dotnet run --project "C:\Source\AMANetworkAnalyzer\src\AMANetworkAnalyzer\AMANetworkAnalyzer.csproj"

# Build the exe
dotnet publish "C:\Source\AMANetworkAnalyzer\src\AMANetworkAnalyzer\AMANetworkAnalyzer.csproj" -c Debug -o publish
# Output: publish\AMANetworkAnalyzer.exe
```

## ETL Support

For Microsoft `.etl` network traces (from `netsh trace`), the tool uses Microsoft's open-source [etl2pcapng](https://github.com/microsoft/etl2pcapng) converter (MIT license).

**No setup required.** Just drop an `.etl` file. The app will:
1. Check if `etl2pcapng.exe` is already available locally
2. If not found, **download v1.11.0** from [GitHub releases](https://github.com/microsoft/etl2pcapng/releases/tag/v1.11.0)
3. **Verify integrity** before execution
4. Convert the ETL to pcapng and analyze it

The download happens once and is cached for future use. For offline/air-gapped machines, manually place `etl2pcapng.exe` next to the app or in a `tools\` subfolder.

## AMA Endpoints Checked

All endpoints checked for Azure Commercial (`.com`), Azure Government (`.us`), and Azure China 21Vianet (`.cn`).

| Endpoint | Purpose |
|---|---|
| `global.handler.control.monitor.azure.com` | Control service |
| `<region>.handler.control.monitor.azure.com` | DCR fetch |
| `<workspace-id>.ods.opinsights.azure.com` | Log data ingestion (ODS) |
| `<dce>.<region>.ingest.monitor.azure.com` | DCE data ingestion |
| `management.azure.com` | ARM (custom metrics) |
| `<region>.monitoring.azure.com` | Custom metrics ingestion |
| `global.prod.microsoftmetrics.com` | Metrics service |

> Endpoints resolving to private IPs (10.x, 172.16-31.x, 192.168.x) are flagged as Private Link / AMPLS usage.

## Project Structure

```
src/AMANetworkAnalyzer/
├── Models/Models.cs          # RawPacket, ParsedPacket, DnsInfo, TlsInfo, Findings, AMA endpoints/ciphers
├── Parsers/
│   ├── PcapReader.cs         # Reads pcap (classic + nanosecond) and pcapng files
│   ├── PacketParser.cs       # Dissects Ethernet/IP/TCP/UDP/DNS/TLS/HTTP
│   └── EtlConverter.cs       # ETL → pcapng conversion via etl2pcapng.exe
├── Analysis/
│   ├── IAnalysisRule.cs      # Rule interface
│   ├── AnalysisEngine.cs     # Orchestrates all rules
│   └── Rules/
│       ├── EndpointConnectivityRule.cs
│       ├── DnsResolutionRule.cs
│       ├── FirewallBlockRule.cs
│       ├── ProxyDetectionRule.cs
│       ├── TlsAnalysisRule.cs
│       ├── TlsCipherComplianceRule.cs
│       └── PrivateLinkDetectionRule.cs
├── ViewModels/
│   ├── MainViewModel.cs      # MVVM binding, file loading, analysis orchestration
│   └── RelayCommand.cs       # ICommand implementation
├── Converters/Converters.cs  # WPF value converters (severity → color/icon)
├── Themes/Dark.xaml          # Dark color palette and control styles
├── MainWindow.xaml/cs        # Main UI with drag-drop
├── App.xaml/cs               # Application entry point
└── GlobalUsings.cs           # Shared using directives
```

## How It Works

1. **File Loading** — PcapReader detects the format (pcap vs pcapng via magic bytes) and extracts raw packets
2. **Packet Parsing** — PacketParser dissects each packet: Ethernet → IPv4 → TCP/UDP → DNS/TLS/HTTP
3. **Analysis** — Seven rules run against the parsed packets, each producing findings with severity levels
4. **Display** — Results are grouped by category with color-coded severity, actionable recommendations, and Wireshark filters

## Supported Capture Formats

| Format | Extension | Notes |
|---|---|---|
| pcap (libpcap) | `.pcap`, `.cap` | Classic and nanosecond variants, both byte orders |
| pcapng | `.pcapng` | Section/Interface/Enhanced Packet blocks |
| ETL | `.etl` | Requires etl2pcapng.exe for conversion |

## Security & Privacy

- **100% offline analysis** — Your capture files are processed locally on your machine. No data is sent to the cloud, no telemetry, no phone-home
- **No external dependencies** — Zero third-party libraries. Built entirely on .NET standard libraries
- **Standalone executable** — No installer, no registry changes, no background services
- **Verified ETL converter** — The optional `etl2pcapng.exe` download is integrity-checked before use
- **HTTPS only** — The single outbound network call (ETL tool download) uses HTTPS exclusively

## Link Layer Support

- Ethernet (type 1)
- Linux cooked capture v1 (type 113)
- Raw IP (type 101)
