namespace AMANetworkAnalyzer.Analysis.Rules;

using AMANetworkAnalyzer.Models;

/// <summary>
/// Rule 1 — Checks whether traffic to each AMA endpoint appears in the capture.
/// Maps to TSG Step 1: "Verify AMA Endpoint Connectivity".
/// </summary>
public sealed class EndpointConnectivityRule : IAnalysisRule
{
    public string Name => "Endpoint Connectivity";
    public string Category => "Endpoint Connectivity";

    public List<AnalysisFinding> Analyze(List<ParsedPacket> packets)
    {
        var findings = new List<AnalysisFinding>();

        // Collect all hostnames seen via DNS queries and TLS SNI
        var seenHostnames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pkt in packets)
        {
            if (pkt.Dns is not null)
            {
                foreach (var qname in pkt.Dns.QueryNames)
                    seenHostnames.Add(qname);
            }
            if (pkt.Tls?.Handshake?.ServerName is { } sni)
                seenHostnames.Add(sni);
            if (pkt.Http?.RequestUri is { } uri)
            {
                // CONNECT host:port
                string host = uri.Contains(':') ? uri[..uri.IndexOf(':')] : uri;
                seenHostnames.Add(host);
            }
        }

        // A capture belongs to exactly one cloud. Checking all three would emit a dozen
        // unreachable-endpoint errors that are guaranteed false and bury the real ones.
        var clouds = AmaEndpoints.DetectClouds(seenHostnames);

        if (clouds.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Error,
                Title = "No AMA traffic detected in capture",
                Detail = "The capture does not contain any traffic to Azure Monitor Agent endpoints. The AMA extension may not be installed, not running, or the capture was taken on the wrong interface.",
                Recommendation = "Verify AMA extension status. Ensure the capture includes the network interface used by AMA."
            });
            return findings;
        }

        findings.Add(new AnalysisFinding
        {
            RuleName = Name,
            Category = Category,
            Severity = Severity.Info,
            Title = $"Capture targets {string.Join(", ", clouds.Select(AmaEndpoints.DisplayName).Order())}",
            Detail = "Endpoint checks below are limited to this cloud. Endpoints belonging to the other sovereign clouds are not expected here and are not reported."
        });

        foreach (var (pattern, description, cloud) in AmaEndpoints.All)
        {
            if (!clouds.Contains(cloud))
                continue;

            var matchingHosts = seenHostnames
                .Where(h => AmaEndpoints.Matches(h, pattern))
                .ToList();

            if (matchingHosts.Count > 0)
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name,
                    Category = Category,
                    Severity = Severity.Pass,
                    Title = $"Traffic found for {pattern}",
                    Detail = $"{description}. Hostnames seen: {string.Join(", ", matchingHosts)}",
                    WiresharkFilter = $"frame contains \"{pattern}\""
                });
            }
            else
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name,
                    Category = Category,
                    Severity = Severity.Error,
                    Title = $"No traffic found for {pattern}",
                    Detail = $"No DNS queries, TLS connections, or HTTP requests to {description} ({pattern}) were detected.",
                    Recommendation = "Verify AMA extension is installed and running. Check that the VM can reach this endpoint on port 443.",
                    WiresharkFilter = $"frame contains \"{pattern}\""
                });
            }
        }

        return findings;
    }
}
