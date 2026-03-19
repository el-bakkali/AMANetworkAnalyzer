namespace AMANetworkAnalyzer.Analysis.Rules;

using AMANetworkAnalyzer.Models;

/// <summary>
/// Rule 5 — Detects TLS handshake failures, alerts, and potential HTTPS inspection.
/// Maps to TSG Step 5: "Check TLS/SSL Issues".
/// </summary>
public sealed class TlsAnalysisRule : IAnalysisRule
{
    public string Name => "TLS / SSL Analysis";
    public string Category => "TLS / SSL";

    public List<AnalysisFinding> Analyze(List<ParsedPacket> packets)
    {
        var findings = new List<AnalysisFinding>();

        // ── TLS handshakes to AMA endpoints ──────────────────────────
        var amaClientHellos = packets
            .Where(p => p.Tls?.Handshake is { HandshakeType: 1, ServerName: not null } hs &&
                        AmaEndpoints.IsAmaEndpoint(hs.ServerName))
            .ToList();

        var amaServerHellos = packets
            .Where(p => p.Tls?.Handshake is { HandshakeType: 2 })
            .ToList();

        if (amaClientHellos.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Pass,
                Title = $"TLS handshakes initiated to AMA endpoints ({amaClientHellos.Count} Client Hellos)",
                Detail = $"SNI hostnames: {string.Join(", ", amaClientHellos.Select(p => p.Tls!.Handshake!.ServerName).Distinct()!)}",
                WiresharkFilter = "tls.handshake.extensions_server_name contains \"opinsights.azure.com\" || tls.handshake.extensions_server_name contains \"monitor.azure.com\"",
                RelatedPacketIndices = amaClientHellos.Select(p => p.Index).ToList()
            });
        }

        // ── TLS Alerts ───────────────────────────────────────────────
        var alertPackets = packets
            .Where(p => p.Tls?.Alert is not null && (p.SourcePort == 443 || p.DestPort == 443))
            .ToList();

        if (alertPackets.Count > 0)
        {
            var alertGroups = alertPackets
                .GroupBy(p => p.Tls!.Alert!.Description)
                .OrderByDescending(g => g.Count());

            foreach (var group in alertGroups)
            {
                var sample = group.First().Tls!.Alert!;
                string desc = sample.DescriptionName;
                string level = sample.LevelName;

                Severity severity;
                string recommendation;

                switch (sample.Description)
                {
                    case 40: // handshake_failure
                        severity = Severity.Error;
                        recommendation = "Certificate mismatch or HTTPS inspection may be interfering. Disable HTTPS inspection for AMA endpoints.";
                        break;
                    case 46: // certificate_unknown
                        severity = Severity.Error;
                        recommendation = "A proxy or inspection device may be injecting its own certificate. Bypass proxy/inspection for AMA endpoints.";
                        break;
                    case 42: // bad_certificate
                    case 43: // unsupported_certificate
                    case 44: // certificate_revoked
                    case 45: // certificate_expired
                    case 48: // unknown_ca
                        severity = Severity.Error;
                        recommendation = "Certificate trust issue detected. If using HTTPS inspection, ensure AMA endpoints are excluded.";
                        break;
                    case 70: // protocol_version
                    case 71: // insufficient_security
                        severity = Severity.Error;
                        recommendation = "TLS version or cipher negotiation failed. Ensure TLS 1.2+ is supported on the network path.";
                        break;
                    case 0: // close_notify
                        severity = Severity.Info;
                        recommendation = "Normal connection closure.";
                        break;
                    default:
                        severity = Severity.Warning;
                        recommendation = "Investigate the TLS alert and network path.";
                        break;
                }

                findings.Add(new AnalysisFinding
                {
                    RuleName = Name,
                    Category = Category,
                    Severity = severity,
                    Title = $"TLS Alert: {desc} ({level}) × {group.Count()}",
                    Detail = $"TLS alert '{desc}' (level={level}, code={sample.Description}) seen {group.Count()} times on port 443.",
                    Recommendation = recommendation,
                    WiresharkFilter = "tls.alert_message",
                    RelatedPacketIndices = group.Select(p => p.Index).ToList()
                });
            }
        }

        // ── TLS version check ────────────────────────────────────────
        foreach (var ch in amaClientHellos)
        {
            var hs = ch.Tls!.Handshake!;
            var supportedVersions = hs.SupportedVersions;
            bool supportsTls13 = supportedVersions.Contains(0x0304);
            bool supportsTls12 = supportedVersions.Contains(0x0303);

            // If supported_versions extension is present
            if (supportedVersions.Count > 0)
            {
                if (!supportsTls12 && !supportsTls13)
                {
                    findings.Add(new AnalysisFinding
                    {
                        RuleName = Name,
                        Category = Category,
                        Severity = Severity.Error,
                        Title = $"Client Hello to {hs.ServerName} does not offer TLS 1.2 or 1.3",
                        Detail = $"Supported versions offered: {string.Join(", ", supportedVersions.Select(v => $"0x{v:X4}"))}. AMA requires TLS 1.2 or 1.3.",
                        Recommendation = "Ensure the client supports TLS 1.2 (0x0303) or TLS 1.3 (0x0304).",
                        RelatedPacketIndices = [ch.Index]
                    });
                }
            }
            else
            {
                // Fall back to ClientVersion field
                if (hs.ClientVersion < 0x0303)
                {
                    findings.Add(new AnalysisFinding
                    {
                        RuleName = Name,
                        Category = Category,
                        Severity = Severity.Error,
                        Title = $"Client Hello to {hs.ServerName} uses TLS version < 1.2",
                        Detail = $"Client version: 0x{hs.ClientVersion:X4}. AMA requires TLS 1.2 or higher.",
                        Recommendation = "Configure the system to use TLS 1.2 or later.",
                        RelatedPacketIndices = [ch.Index]
                    });
                }
            }
        }

        // ── No TLS issues ────────────────────────────────────────────
        if (alertPackets.Count == 0 && findings.All(f => f.Severity == Severity.Pass || f.Severity == Severity.Info))
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Pass,
                Title = "No TLS/SSL issues detected",
                Detail = "No TLS alerts or handshake failures were detected on port 443.",
                WiresharkFilter = "tls.alert_message"
            });
        }

        return findings;
    }
}
