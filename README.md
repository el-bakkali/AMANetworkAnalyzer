# AMA Network Analyzer

A Windows desktop tool for novice engineers to diagnose Azure Monitor Agent (AMA) network connectivity issues by analyzing packet capture files.

**Drop a `.pcap`, `.pcapng`, `.etl`, or `.cab` file → get an instant diagnostic report. Click any finding to drill down to the exact packets.**

## Features

- **Drag-and-drop** `.pcap`, `.pcapng`, `.etl`, and `.cab` capture files
- **Drill-down packet detail panel** — Click any finding or severity badge to view the exact affected packets with timestamps, IPs, ports, DNS/TLS/HTTP details
- **Streaming pcap reader** — Memory-efficient file processing (supports files up to 2 GB without loading into memory)
- **.cab file support** — Windows `netsh trace` `.cab` archives are automatically extracted and converted
- **Security compliance tags** — Findings tagged with OWASP ASVS, NIST CSF, and CIS Controls references
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
- **File integrity warnings** — Detects truncated/corrupted pcap files and surfaces parse warnings
- **Input validation** — File extension validation with magic-number fallback, path traversal protection
- **Sovereign cloud support** — Azure Commercial (`.com`), Azure Government (`.us`), and Azure China 21Vianet (`.cn`)
- **Wireshark filter suggestions** — Each finding includes a clickable Wireshark display filter (copies to clipboard)
- **Async export** — Non-blocking report export to text or Markdown
- **Finding deduplication** — Identical findings are merged instead of shown multiple times
- **Dark-themed WPF UI** with pass/warn/error severity badges and split-pane drill-down

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

## ETL and CAB Support

For Microsoft `.etl` network traces (from `netsh trace`), the tool uses Microsoft's open-source [etl2pcapng](https://github.com/microsoft/etl2pcapng) converter (MIT license).

For `.cab` archives (also produced by `netsh trace`), the tool automatically extracts the `.etl` file using Windows' built-in `expand.exe`, then converts it.

**No setup required.** Just drop an `.etl` or `.cab` file. The app will:
1. If `.cab` → extract `.etl` from the archive
2. Check if `etl2pcapng.exe` is already available locally
3. If not found, **download v1.11.0** from [GitHub releases](https://github.com/microsoft/etl2pcapng/releases/tag/v1.11.0)
4. **Verify SHA-256 integrity** before execution
5. Convert the ETL to pcapng and analyze it

The download happens once and is cached for future use. For offline/air-gapped machines, manually place `etl2pcapng.exe` next to the app or in a `tools\` subfolder.

## What's New in v2.0

- **Drill-down UI** — Click any finding → see the exact affected packets (IPs, ports, DNS, TLS, HTTP) in a detail panel. Click severity badges (PASS/INFO/WARN/ERROR) to filter.
- **.cab file support** — Windows `netsh trace` `.cab` archives are automatically extracted and analyzed.
- **Streaming pcap reader** — Files streamed from disk instead of loaded into memory. Supports up to 2 GB.
- **Truncation warnings** — Truncated/corrupted pcap files are detected and surfaced as warnings.
- **Security compliance tags** — Findings include OWASP, NIST CSF, and CIS Controls references.
- **Input validation** — File extension + magic-number validation, path traversal protection.
- **Async export** — Report export runs asynchronously so it doesn't block the UI.
- **Finding deduplication** — Identical findings are merged instead of shown multiple times.

## Security & Privacy

- **100% offline analysis** — Your files are processed locally. No data is sent to the cloud, no telemetry, no phone-home
- **No external dependencies** — Zero third-party libraries. Built entirely on .NET standard libraries
- **Input validation** — File extension allowlisting, magic-number verification, path traversal protection (OWASP ASVS)
- **SHA-256 integrity verification** — `etl2pcapng` downloads are verified against a pinned hash before execution
- **Compliance-aware findings** — Tagged with OWASP ASVS, NIST CSF, and CIS Controls references

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
