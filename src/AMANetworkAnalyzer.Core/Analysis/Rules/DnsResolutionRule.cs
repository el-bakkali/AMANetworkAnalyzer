namespace AMANetworkAnalyzer.Analysis.Rules;

using AMANetworkAnalyzer.Models;

/// <summary>
/// Rule 2 — Validates DNS resolution for AMA endpoints.
/// Maps to TSG Step 4: "Check DNS Resolution".
/// </summary>
public sealed class DnsResolutionRule : IAnalysisRule
{
    public string Name => "DNS Resolution";
    public string Category => "DNS Resolution";

    public List<AnalysisFinding> Analyze(List<ParsedPacket> packets)
    {
        var findings = new List<AnalysisFinding>();

        // Collect DNS queries and responses keyed by query name
        var queries = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);     // name → packet indices
        var responses = new Dictionary<string, List<DnsResponseInfo>>(StringComparer.OrdinalIgnoreCase);

        foreach (var pkt in packets)
        {
            if (pkt.Dns is null) continue;

            foreach (var qname in pkt.Dns.QueryNames)
            {
                if (!AmaEndpoints.IsAmaEndpoint(qname))
                    continue;

                if (!pkt.Dns.IsResponse)
                {
                    if (!queries.ContainsKey(qname))
                        queries[qname] = [];
                    queries[qname].Add(pkt.Index);
                }
                else
                {
                    if (!responses.ContainsKey(qname))
                        responses[qname] = [];
                    responses[qname].Add(new DnsResponseInfo(
                        pkt.Dns.ResponseCode,
                        pkt.Dns.Answers.Where(a => a.Type is 1 or 28).Select(a => a.Data).ToList(),
                        pkt.Index
                    ));
                }
            }
        }

        // No DNS queries for AMA endpoints
        if (queries.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Warning,
                Title = "No DNS queries for AMA endpoints found",
                Detail = "The capture contains no DNS lookups for Azure Monitor Agent endpoints. This could mean DNS is cached, AMA is not running, or DNS traffic was not captured.",
                Recommendation = "Flush DNS cache (ipconfig /flushdns) and recapture, or verify AMA extension is running.",
                WiresharkFilter = "dns.qry.name contains \"opinsights.azure.com\" || dns.qry.name contains \"monitor.azure.com\""
            });
            return findings;
        }

        // Analyze each queried AMA endpoint
        foreach (var (hostname, queryIndices) in queries)
        {
            if (responses.TryGetValue(hostname, out var resps) && resps.Count > 0)
            {
                foreach (var resp in resps)
                {
                    if (resp.ResponseCode == 0)
                    {
                        string ips = resp.ResolvedAddresses.Count > 0
                            ? string.Join(", ", resp.ResolvedAddresses)
                            : "(no A/AAAA records)";

                        findings.Add(new AnalysisFinding
                        {
                            RuleName = Name,
                            Category = Category,
                            Severity = Severity.Pass,
                            Title = $"DNS resolved: {hostname}",
                            Detail = $"Resolved to: {ips}",
                            WiresharkFilter = $"dns.qry.name contains \"{hostname}\"",
                            RelatedPacketIndices = [.. queryIndices, resp.PacketIndex]
                        });
                    }
                    else
                    {
                        string rcName = resp.ResponseCode switch
                        {
                            2 => "SERVFAIL",
                            3 => "NXDOMAIN",
                            _ => $"Error code {resp.ResponseCode}"
                        };

                        string rec = resp.ResponseCode switch
                        {
                            3 => "Check DNS server configuration, conditional forwarders, and private DNS zones.",
                            2 => "DNS server encountered a failure. Check DNS server health and connectivity.",
                            _ => "Investigate DNS server logs."
                        };

                        findings.Add(new AnalysisFinding
                        {
                            RuleName = Name,
                            Category = Category,
                            Severity = Severity.Error,
                            Title = $"DNS failure for {hostname}: {rcName}",
                            Detail = $"DNS response code {resp.ResponseCode} ({rcName}). The endpoint cannot be resolved.",
                            Recommendation = rec,
                            WiresharkFilter = $"dns.flags.rcode != 0 && dns.qry.name contains \"{hostname}\"",
                            RelatedPacketIndices = [.. queryIndices, resp.PacketIndex]
                        });
                    }
                }
            }
            else
            {
                // Query sent but no response received
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name,
                    Category = Category,
                    Severity = Severity.Warning,
                    Title = $"DNS query unanswered: {hostname}",
                    Detail = $"A DNS query was sent for {hostname} but no response was captured. The DNS server may be unreachable.",
                    Recommendation = "Check DNS server connectivity (port 53 UDP/TCP). Verify DNS server address in network configuration.",
                    WiresharkFilter = $"dns.qry.name contains \"{hostname}\"",
                    RelatedPacketIndices = queryIndices
                });
            }
        }

        return findings;
    }

    private sealed record DnsResponseInfo(ushort ResponseCode, List<string> ResolvedAddresses, int PacketIndex);
}
