namespace AMANetworkAnalyzer.Analysis.Rules;

using AMANetworkAnalyzer.Models;

/// <summary>
/// Rule 6 — Validates that TLS cipher suites offered/selected match AMA requirements.
/// Required ciphers:
///   TLS 1.3: TLS_AES_256_GCM_SHA384 (0x1302), TLS_AES_128_GCM_SHA256 (0x1301)
///   TLS 1.2: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030), TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
/// </summary>
public sealed class TlsCipherComplianceRule : IAnalysisRule
{
    public string Name => "TLS Cipher Compliance";
    public string Category => "TLS Cipher Compliance";

    public List<AnalysisFinding> Analyze(List<ParsedPacket> packets)
    {
        var findings = new List<AnalysisFinding>();

        // ── Client Hello analysis (offered ciphers) ──────────────────
        var amaClientHellos = packets
            .Where(p => p.Tls?.Handshake is { HandshakeType: 1, ServerName: not null } hs &&
                        AmaEndpoints.IsAmaEndpoint(hs.ServerName) &&
                        p.Tls.Handshake.OfferedCipherSuites.Count > 0)
            .ToList();

        foreach (var pkt in amaClientHellos)
        {
            var hs = pkt.Tls!.Handshake!;
            var offered = new HashSet<ushort>(hs.OfferedCipherSuites);

            var presentRequired = AmaCipherSuites.Required
                .Where(r => offered.Contains(r.Key))
                .ToList();

            var missingRequired = AmaCipherSuites.Required
                .Where(r => !offered.Contains(r.Key))
                .ToList();

            if (missingRequired.Count == 0)
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name,
                    Category = Category,
                    Severity = Severity.Pass,
                    Title = $"All required ciphers offered to {hs.ServerName}",
                    Detail = $"Client Hello offers all {AmaCipherSuites.Required.Count} required cipher suites: {string.Join(", ", presentRequired.Select(r => r.Value))}",
                    WiresharkFilter = $"tls.handshake.extensions_server_name contains \"{hs.ServerName}\"",
                    RelatedPacketIndices = [pkt.Index]
                });
            }
            else
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name,
                    Category = Category,
                    Severity = missingRequired.Count == AmaCipherSuites.Required.Count ? Severity.Error : Severity.Warning,
                    Title = $"Missing {missingRequired.Count} required cipher(s) in Client Hello to {hs.ServerName}",
                    Detail = $"Missing: {string.Join(", ", missingRequired.Select(r => $"{r.Value} (0x{r.Key:X4})"))}. " +
                             $"Present: {string.Join(", ", presentRequired.Select(r => r.Value))}. " +
                             $"Total offered: {offered.Count} cipher suites.",
                    Recommendation = "Ensure the operating system or TLS library supports the required cipher suites. Check Group Policy or registry settings that may restrict cipher suites.",
                    WiresharkFilter = $"tls.handshake.extensions_server_name contains \"{hs.ServerName}\"",
                    RelatedPacketIndices = [pkt.Index]
                });
            }
        }

        // ── Server Hello analysis (selected cipher) ──────────────────
        // We need to correlate Server Hellos to AMA connections.
        // In a capture, Server Hellos come from port 443 and the dest is the client.
        // We check if the source IP matches a known AMA IP.
        var amaIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pkt in packets)
        {
            if (pkt.Dns is { IsResponse: true, ResponseCode: 0 } && pkt.Dns.QueryNames.Any(AmaEndpoints.IsAmaEndpoint))
            {
                foreach (var ans in pkt.Dns.Answers.Where(a => a.Type is 1 or 28))
                    amaIps.Add(ans.Data);
            }
            if (pkt.Tls?.Handshake?.ServerName is { } sni && AmaEndpoints.IsAmaEndpoint(sni) && pkt.DestIp is not null)
                amaIps.Add(pkt.DestIp);
        }

        var amaServerHellos = packets
            .Where(p => p.Tls?.Handshake is { HandshakeType: 2 } &&
                        p.SourcePort == 443 &&
                        p.SourceIp is not null &&
                        amaIps.Contains(p.SourceIp))
            .ToList();

        foreach (var pkt in amaServerHellos)
        {
            var hs = pkt.Tls!.Handshake!;
            ushort selected = hs.SelectedCipherSuite;
            string cipherName = AmaCipherSuites.GetName(selected);

            if (AmaCipherSuites.Required.ContainsKey(selected))
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name,
                    Category = Category,
                    Severity = Severity.Pass,
                    Title = $"Server selected compliant cipher: {cipherName}",
                    Detail = $"Server at {pkt.SourceIp}:443 selected {cipherName} (0x{selected:X4}), which is in the required list.",
                    RelatedPacketIndices = [pkt.Index]
                });
            }
            else
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name,
                    Category = Category,
                    Severity = Severity.Warning,
                    Title = $"Server selected non-standard cipher: {cipherName}",
                    Detail = $"Server at {pkt.SourceIp}:443 selected cipher 0x{selected:X4} ({cipherName}), which is NOT in the AMA required cipher list. " +
                             "This may indicate an HTTPS inspection device is terminating the TLS connection.",
                    Recommendation = "If an HTTPS inspection device is in the path, disable inspection for AMA endpoints.",
                    RelatedPacketIndices = [pkt.Index]
                });
            }
        }

        // ── Summary if no TLS handshakes to AMA endpoints ───────────
        if (amaClientHellos.Count == 0 && amaServerHellos.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Warning,
                Title = "No TLS handshakes to AMA endpoints found for cipher analysis",
                Detail = "Could not locate any TLS Client Hello or Server Hello messages targeting AMA endpoints. Cipher compliance could not be verified.",
                Recommendation = "Ensure the capture includes the TLS handshake (capture from the start of the connection)."
            });
        }

        return findings;
    }
}
