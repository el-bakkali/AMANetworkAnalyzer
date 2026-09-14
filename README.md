# AMA Network Analyzer

Drop a network capture on it and find out why the Azure Monitor Agent cannot reach Azure.

Hand it a `.pcap`, `.pcapng`, `.etl`, or `.cab` and it reports what is broken. Click any finding to see the packets behind it.

A Windows desktop app (WPF, .NET 10), written for engineers who need an answer out of a capture without first learning Wireshark display filters.

## What it checks

Seven rules run against every capture, based on the AMA network troubleshooting guide.

| Rule | Looks for |
|---|---|
| Endpoint connectivity | Traffic to each AMA endpoint required by the cloud the capture belongs to |
| DNS resolution | NXDOMAIN and SERVFAIL responses for AMA domains |
| Firewall blocking | TCP resets and SYN retransmissions |
| Proxy detection | HTTP CONNECT, 407 proxy auth, common proxy ports |
| TLS analysis | Alerts, handshake failures, version problems |
| TLS cipher compliance | Offered and selected ciphers against what AMA requires |
| Private Link / AMPLS | AMA endpoints resolving to private IPs, and mixed public/private DNS |

The cipher rule wants `TLS_AES_256_GCM_SHA384` or `TLS_AES_128_GCM_SHA256` on TLS 1.3, and `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` or `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` on TLS 1.2.

Every finding carries a severity, a recommendation, and a Wireshark display filter you can copy. Findings are deduplicated, so a problem that shows up in four hundred packets is reported once. Truncated or corrupt captures are flagged rather than silently half-parsed.

## Dependencies

The application pulls no NuGet packages. Pcap and pcapng reading, packet dissection, and the DNS, TLS and HTTP decoders are hand-written against the .NET base class library. You do not need Wireshark, tshark, Npcap or WinPcap.

Two exceptions. The test project uses xUnit. And ETL conversion shells out to Microsoft's [etl2pcapng](https://github.com/microsoft/etl2pcapng) (MIT), which is fetched on first use and hash-checked every time it runs.

## Quick start

You need the .NET 10 SDK.

```powershell
# Run it
dotnet run --project src/AMANetworkAnalyzer

# Test it
dotnet test

# Publish an exe
dotnet publish src/AMANetworkAnalyzer -c Release -r win-x64 --self-contained false -o publish
```

[BUILDING.md](BUILDING.md) covers self-contained builds and air-gapped setup.

## ETL and CAB files

`netsh trace` produces `.etl` files, and sometimes wraps them in a `.cab`. Both work.

A `.cab` is expanded using the `expand.exe` that ships with Windows, resolved from the system directory. The extracted `.etl` is then re-checked to confirm it genuinely sits inside the extraction folder before anything opens it.

An `.etl` is converted to pcapng by etl2pcapng. On first use the app fetches v1.11.0 from the GitHub release over HTTPS, verifies it against a pinned SHA-256, and caches it under `%LOCALAPPDATA%\AMANetworkAnalyzer\tools\`. The hash is re-checked on every launch, not only after the download.

On an air-gapped machine, put `etl2pcapng.exe` in that folder yourself, or next to the exe, or in a `tools\` subfolder beside it. It still has to match the pinned hash, so copy it from the official release.

## Security

Captures never leave the machine. No telemetry, no phone-home. The only outbound request the app can make is the etl2pcapng download.

The parser eats attacker-controlled binary input, so that is where most of the effort went.

- Managed, bounds-checked parsing. `AllowUnsafeBlocks` is off and warnings are errors.
- Input is validated by extension allowlist with a magic-number fallback, and anything over 2 GB is refused.
- etl2pcapng is only ever located by absolute path. The working directory and `PATH` are never consulted, because an attacker can influence both (CWE-426).
- The file handle used for hash verification stays open across process start, so the bytes that were hashed are the bytes that execute (CWE-367).
- Files extracted from a `.cab` are re-resolved against the extraction root, and reparse points are skipped (CWE-22).
- Hostnames and other capture-derived strings are escaped before they are written into an exported report.

Findings carry OWASP ASVS, NIST CSF, and CIS Controls tags.

CI runs the tests, CodeQL with `security-extended`, and gitleaks over the full history on every push.

## AMA endpoints checked

The table lists the Azure Commercial names. Government (`.us`) and China 21Vianet (`.cn`) have equivalents for all but the metrics service.

A machine talks to one cloud, so the analyzer works out which one the capture belongs to and only checks that set. Reporting the other two as unreachable would add a dozen guaranteed false errors and bury the real ones.

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

## Project layout

All the parsing and analysis lives in a library with no WPF dependency, which is what makes it testable.

```
src/AMANetworkAnalyzer.Core/
├── Models/
│   ├── Models.cs             # Packets, findings, AMA endpoints and cipher suites
│   └── SafeText.cs           # Escaping for capture-derived strings
├── Parsers/
│   ├── PcapReader.cs         # pcap (classic + nanosecond) and pcapng, both byte orders
│   ├── PacketParser.cs       # Ethernet, IPv4, TCP, UDP, DNS, TLS, HTTP
│   ├── EtlConverter.cs       # etl2pcapng download, verification and invocation
│   └── CabExtractor.cs       # .cab expansion with containment checks
└── Analysis/
    ├── IAnalysisRule.cs
    ├── AnalysisEngine.cs     # Runs the rules, deduplicates findings
    └── Rules/                # The seven diagnostic rules

src/AMANetworkAnalyzer/       # WPF shell
├── ViewModels/               # Binding, file loading, cancellation
├── Converters/               # Severity to colour and icon
├── Themes/Dark.xaml
└── MainWindow.xaml           # Drag-and-drop target, split-pane drill-down

tests/AMANetworkAnalyzer.Core.Tests/
├── CaptureBuilder.cs         # Builds real pcap and pcapng bytes in both byte orders
└── *Tests.cs                 # 91 tests
```

## How it works

The reader identifies the format from the magic bytes, then walks the file once, dissecting each packet as it is read. Ethernet or Linux cooked or raw IP, then IPv4, then TCP or UDP, then DNS, TLS or HTTP. The seven rules run over the parsed result and each emits findings with a severity. The UI groups those by category and lets you click through to the packets that produced them.

Reading and parsing happen in a single pass. Earlier versions read the whole file twice, once for the report and once for drill-down, which is now fixed. On a synthetic 200,000-packet capture that made analysis about 1.27 times faster, cut allocation churn by roughly 30 percent, and lowered peak working set by about 16 percent.

## Supported capture formats

| Format | Extension | Notes |
|---|---|---|
| pcap (libpcap) | `.pcap`, `.cap` | Classic and nanosecond variants, both byte orders |
| pcapng | `.pcapng` | Section, interface and enhanced packet blocks |
| ETL | `.etl` | Converted by etl2pcapng |
| CAB | `.cab` | Expanded, then the `.etl` inside is converted |

Link layers: Ethernet (1), Linux cooked capture v1 (113), and raw IP (101).

## Limitations

Worth knowing before you file a bug.

- IPv4 only. IPv6 packets are skipped.
- TCP streams are not reassembled, so a TLS handshake split across segments can be missed.
- Memory tracks packet count rather than file size. A synthetic 24 MB capture holding 200,000 packets settles around 134 MB. The 2 GB ceiling is a refusal threshold, not a promise that a 2 GB capture will fit in RAM.
- Windows only, and it needs a desktop session. There is no command-line mode.
- The app is not code-signed. If you did not build it yourself, check it against the `SHA256SUMS.txt` published with the release.

## Contributing

Run `dotnet test` before opening a pull request. The build treats warnings as errors, so a warning will fail CI.

If you touch `PcapReader` or `PacketParser`, add a test. `CaptureBuilder` constructs real capture bytes, including deliberately malformed ones, so there is no need to check binary fixtures into the repo.

Licensed under MIT.
