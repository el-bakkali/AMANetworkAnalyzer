namespace AMANetworkAnalyzer.Analysis.Rules;

using AMANetworkAnalyzer.Models;

/// <summary>
/// Rule 7 — Detects Private Link / Azure Monitor Private Link Scope (AMPLS) usage.
/// When private links are in use, AMA endpoints resolve to private IP addresses
/// (10.x, 172.16-31.x, 192.168.x) instead of public IPs.
/// Different firewall and DNS rules apply in this scenario.
/// See: https://learn.microsoft.com/azure/azure-monitor/logs/private-link-security
/// </summary>
public sealed class PrivateLinkDetectionRule : IAnalysisRule
{
    public string Name => "Private Link / AMPLS Detection";
    public string Category => "Private Link";

    public List<AnalysisFinding> Analyze(List<ParsedPacket> packets)
    {
        var findings = new List<AnalysisFinding>();

        // Collect DNS answers for AMA endpoints and check if they resolve to private IPs
        var privateResolutions = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var publicResolutions = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var relatedIndices = new List<int>();

        foreach (var pkt in packets)
        {
            if (pkt.Dns is not { IsResponse: true, ResponseCode: 0 })
                continue;

            foreach (var qname in pkt.Dns.QueryNames)
            {
                if (!AmaEndpoints.IsAmaEndpoint(qname))
                    continue;

                foreach (var ans in pkt.Dns.Answers.Where(a => a.Type is 1 or 28)) // A or AAAA
                {
                    if (IsPrivateIp(ans.Data))
                    {
                        if (!privateResolutions.ContainsKey(qname))
                            privateResolutions[qname] = [];
                        privateResolutions[qname].Add(ans.Data);
                        relatedIndices.Add(pkt.Index);
                    }
                    else
                    {
                        if (!publicResolutions.ContainsKey(qname))
                            publicResolutions[qname] = [];
                        publicResolutions[qname].Add(ans.Data);
                    }
                }
            }
        }

        if (privateResolutions.Count > 0)
        {
            var details = privateResolutions
                .Select(kv => $"{kv.Key} → {string.Join(", ", kv.Value.Distinct())}")
                .ToList();

            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Info,
                Title = $"Private Link / AMPLS detected ({privateResolutions.Count} endpoints resolve to private IPs)",
                Detail = $"The following AMA endpoints resolve to private IP addresses, indicating Azure Monitor Private Link Scope (AMPLS) is in use:\n{string.Join("\n", details)}",
                Recommendation = "When using Private Link, ensure all DCRs use DCEs and that DCEs are added to the AMPLS configuration. Public endpoint firewall rules do not apply — private DNS zones must be configured correctly instead. See: https://learn.microsoft.com/azure/azure-monitor/logs/private-link-security",
                WiresharkFilter = "dns.qry.name contains \"monitor.azure.com\" || dns.qry.name contains \"opinsights.azure.com\"",
                RelatedPacketIndices = relatedIndices.Distinct().ToList()
            });

            // Check for mixed resolution (some private, some public) which is a misconfiguration
            var mixedEndpoints = privateResolutions.Keys
                .Where(k => publicResolutions.ContainsKey(k))
                .ToList();

            if (mixedEndpoints.Count > 0)
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name,
                    Category = Category,
                    Severity = Severity.Warning,
                    Title = $"Mixed DNS resolution: {mixedEndpoints.Count} endpoints resolve to BOTH private and public IPs",
                    Detail = $"Endpoints with mixed resolution: {string.Join(", ", mixedEndpoints)}. This may indicate a DNS configuration issue — split-brain DNS or conditional forwarders may not be fully applied.",
                    Recommendation = "Verify private DNS zones are configured for all required zones. See: https://learn.microsoft.com/azure/azure-monitor/logs/private-link-security"
                });
            }
        }

        // Also check if any TLS connections to AMA endpoints go to private IPs
        var privateTlsConnections = packets
            .Where(p => p.Tls?.Handshake is { HandshakeType: 1, ServerName: not null } hs &&
                        AmaEndpoints.IsAmaEndpoint(hs.ServerName) &&
                        p.DestIp is not null && IsPrivateIp(p.DestIp))
            .ToList();

        if (privateTlsConnections.Count > 0 && privateResolutions.Count == 0)
        {
            // TLS to private IPs but no DNS evidence — might have missed the DNS
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Info,
                Title = $"TLS connections to private IPs for AMA endpoints ({privateTlsConnections.Count} connections)",
                Detail = "AMA endpoint TLS handshakes are directed to private IP addresses, suggesting Private Link is in use. DNS resolution was not captured but the connection pattern confirms AMPLS.",
                Recommendation = "Ensure AMPLS and private DNS zones are fully configured.",
                RelatedPacketIndices = privateTlsConnections.Select(p => p.Index).ToList()
            });
        }

        if (findings.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Pass,
                Title = "No Private Link detected — using public endpoints",
                Detail = "AMA endpoints resolve to public IP addresses. Standard firewall rules apply (port 443 outbound to AMA endpoints)."
            });
        }

        return findings;
    }

    private static bool IsPrivateIp(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var addr))
            return false;

        byte[] bytes = addr.GetAddressBytes();
        if (bytes.Length != 4) // IPv4 only for this check
            return false;

        // RFC 1918 private ranges
        return bytes[0] == 10 ||                                    // 10.0.0.0/8
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || // 172.16.0.0/12
               (bytes[0] == 192 && bytes[1] == 168);                // 192.168.0.0/16
    }
}
