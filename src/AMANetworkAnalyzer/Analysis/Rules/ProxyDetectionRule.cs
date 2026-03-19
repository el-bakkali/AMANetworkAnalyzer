namespace AMANetworkAnalyzer.Analysis.Rules;

using AMANetworkAnalyzer.Models;

/// <summary>
/// Rule 4 — Detects proxy usage (HTTP CONNECT, proxy auth, common proxy ports).
/// Maps to TSG Step 3: "Check for Proxy Usage".
/// </summary>
public sealed class ProxyDetectionRule : IAnalysisRule
{
    public string Name => "Proxy Detection";
    public string Category => "Proxy Detection";

    private static readonly HashSet<ushort> CommonProxyPorts = [3128, 8080, 8443, 8888, 9090];

    public List<AnalysisFinding> Analyze(List<ParsedPacket> packets)
    {
        var findings = new List<AnalysisFinding>();

        // ── HTTP CONNECT requests ────────────────────────────────────
        var connectPackets = packets
            .Where(p => p.Http is { Method: "CONNECT" })
            .ToList();

        var amaConnectPackets = connectPackets
            .Where(p => p.Http?.RequestUri is { } uri &&
                        AmaEndpoints.IsAmaEndpoint(uri.Contains(':') ? uri[..uri.IndexOf(':')] : uri))
            .ToList();

        if (amaConnectPackets.Count > 0)
        {
            var targets = amaConnectPackets
                .Select(p => p.Http?.RequestUri)
                .Where(u => u is not null)
                .Distinct()
                .ToList();

            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Warning,
                Title = $"Proxy CONNECT detected for AMA endpoints ({amaConnectPackets.Count} requests)",
                Detail = $"HTTP CONNECT tunnel requests to AMA endpoints via proxy: {string.Join(", ", targets!)}",
                Recommendation = "Verify AMA is configured with matching proxy settings. See proxy configuration section in AMA docs.",
                WiresharkFilter = "http.request.method == \"CONNECT\" && (frame contains \"opinsights\" || frame contains \"monitor.azure.com\")",
                RelatedPacketIndices = amaConnectPackets.Select(p => p.Index).ToList()
            });
        }
        else if (connectPackets.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Info,
                Title = $"Proxy CONNECT traffic present ({connectPackets.Count} requests, not AMA-targeted)",
                Detail = "HTTP CONNECT requests were found in the capture but none target AMA endpoints.",
                WiresharkFilter = "http.request.method == \"CONNECT\"",
                RelatedPacketIndices = connectPackets.Select(p => p.Index).ToList()
            });
        }

        // ── HTTP 407 Proxy Authentication Required ───────────────────
        var proxyAuthPackets = packets
            .Where(p => p.Http is { StatusCode: 407 })
            .ToList();

        if (proxyAuthPackets.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Error,
                Title = $"Proxy authentication required (HTTP 407 × {proxyAuthPackets.Count})",
                Detail = "The proxy is rejecting requests because authentication credentials are missing or incorrect.",
                Recommendation = "Configure AMA with proxy authentication credentials using Set-AzVMExtension or New-AzConnectedMachineExtension with auth=true.",
                WiresharkFilter = "http.response.code == 407",
                RelatedPacketIndices = proxyAuthPackets.Select(p => p.Index).ToList()
            });
        }

        // ── Proxy-Authorization / Proxy-Authenticate headers ─────────
        var proxyHeaderPackets = packets
            .Where(p => p.Http is not null &&
                        (p.Http.Headers.ContainsKey("Proxy-Authorization") ||
                         p.Http.Headers.ContainsKey("Proxy-Authenticate")))
            .ToList();

        if (proxyHeaderPackets.Count > 0 && proxyAuthPackets.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Info,
                Title = "Proxy authentication headers detected",
                Detail = $"Found {proxyHeaderPackets.Count} packets with Proxy-Authorization or Proxy-Authenticate headers.",
                WiresharkFilter = "http.proxy_authorization || http.proxy_authenticate",
                RelatedPacketIndices = proxyHeaderPackets.Select(p => p.Index).ToList()
            });
        }

        // ── Traffic to common proxy ports ────────────────────────────
        var proxyPortPackets = packets
            .Where(p => CommonProxyPorts.Contains(p.DestPort) && p.Protocol == IpProtocol.Tcp)
            .ToList();

        if (proxyPortPackets.Count > 0)
        {
            var ports = proxyPortPackets.Select(p => p.DestPort).Distinct().OrderBy(p => p).ToList();
            var destIps = proxyPortPackets.Select(p => p.DestIp).Where(ip => ip is not null).Distinct().Take(5).ToList();

            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Info,
                Title = $"Traffic to common proxy ports: {string.Join(", ", ports)}",
                Detail = $"{proxyPortPackets.Count} packets sent to common proxy ports. Destination IPs: {string.Join(", ", destIps)}. This may indicate a transparent or explicit proxy.",
                Recommendation = "If a proxy is in use, ensure AMA proxy settings are configured to match.",
                WiresharkFilter = $"tcp.port == {string.Join(" || tcp.port == ", ports)}"
            });
        }

        // ── Via header ───────────────────────────────────────────────
        var viaPackets = packets
            .Where(p => p.Http is not null && p.Http.Headers.ContainsKey("Via"))
            .ToList();

        if (viaPackets.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Info,
                Title = "HTTP Via header detected (proxy indicator)",
                Detail = $"{viaPackets.Count} packets contain a Via header, indicating traffic passed through a proxy.",
                WiresharkFilter = "http.via"
            });
        }

        // ── No proxy detected ────────────────────────────────────────
        if (findings.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Pass,
                Title = "No proxy activity detected",
                Detail = "No HTTP CONNECT requests, proxy authentication headers, or traffic to common proxy ports found.",
                WiresharkFilter = "http.request.method == \"CONNECT\""
            });
        }

        return findings;
    }
}
