namespace AMANetworkAnalyzer.Analysis.Rules;

using AMANetworkAnalyzer.Models;

/// <summary>
/// Rule 3 — Detects firewall blocking via TCP RST packets and SYN retransmissions.
/// Maps to TSG Step 2: "Check for Firewall Blocking (RST Analysis)".
/// </summary>
public sealed class FirewallBlockRule : IAnalysisRule
{
    public string Name => "Firewall / RST Analysis";
    public string Category => "Firewall Blocking";

    public List<AnalysisFinding> Analyze(List<ParsedPacket> packets)
    {
        var findings = new List<AnalysisFinding>();

        // ── Collect AMA endpoint IPs (from DNS answers) ──────────────
        var amaIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pkt in packets)
        {
            if (pkt.Dns is { IsResponse: true, ResponseCode: 0 })
            {
                bool isAma = pkt.Dns.QueryNames.Any(AmaEndpoints.IsAmaEndpoint);
                if (isAma)
                {
                    foreach (var ans in pkt.Dns.Answers.Where(a => a.Type is 1 or 28))
                        amaIps.Add(ans.Data);
                }
            }
        }

        // Also match any TLS SNI to AMA endpoints → record the dest IP
        foreach (var pkt in packets)
        {
            if (pkt.Tls?.Handshake?.ServerName is { } sni && AmaEndpoints.IsAmaEndpoint(sni) && pkt.DestIp is not null)
                amaIps.Add(pkt.DestIp);
        }

        // ── RST packets on port 443 ─────────────────────────────────
        var rstPackets = packets
            .Where(p => p.HasFlag(TcpFlags.RST) && (p.SourcePort == 443 || p.DestPort == 443))
            .ToList();

        var amaRstPackets = rstPackets
            .Where(p => (p.DestIp is not null && amaIps.Contains(p.DestIp)) ||
                        (p.SourceIp is not null && amaIps.Contains(p.SourceIp)))
            .ToList();

        if (amaRstPackets.Count > 0)
        {
            // Determine RST pattern
            var rstAfterSyn = new List<ParsedPacket>();
            var rstAfterTls = new List<ParsedPacket>();

            foreach (var rst in amaRstPackets)
            {
                // Look at surrounding packets to determine context
                var prevPackets = packets
                    .Where(p => p.Index < rst.Index && p.Index >= rst.Index - 5)
                    .Where(p => (p.DestIp == rst.SourceIp || p.DestIp == rst.DestIp) &&
                                (p.SourceIp == rst.SourceIp || p.SourceIp == rst.DestIp))
                    .ToList();

                bool hadTls = prevPackets.Any(p => p.Tls is not null);
                bool hadSynOnly = prevPackets.Any(p => p.HasFlag(TcpFlags.SYN) && !p.HasFlag(TcpFlags.ACK));

                if (hadTls)
                    rstAfterTls.Add(rst);
                else if (hadSynOnly)
                    rstAfterSyn.Add(rst);
            }

            if (rstAfterSyn.Count > 0)
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name,
                    Category = Category,
                    Severity = Severity.Error,
                    Title = $"Firewall blocking: {rstAfterSyn.Count} RST after SYN to AMA endpoints",
                    Detail = $"TCP RST packets received immediately after SYN to AMA endpoint IPs ({string.Join(", ", amaIps.Take(5))}). A firewall or network device is actively rejecting connections.",
                    Recommendation = "Add AMA endpoints to the firewall allow list for outbound port 443.",
                    WiresharkFilter = "tcp.flags.reset == 1 && tcp.port == 443",
                    RelatedPacketIndices = rstAfterSyn.Select(p => p.Index).ToList()
                });
            }

            if (rstAfterTls.Count > 0)
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name,
                    Category = Category,
                    Severity = Severity.Error,
                    Title = $"HTTPS inspection blocking: {rstAfterTls.Count} RST after TLS handshake",
                    Detail = "TCP RST received after TLS Client Hello. An HTTPS inspection device or SSL policy may be terminating the connection.",
                    Recommendation = "Disable HTTPS inspection for AMA endpoints. See: https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-network-configuration",
                    WiresharkFilter = "(tls.alert_message || tcp.flags.reset == 1) && tcp.port == 443",
                    RelatedPacketIndices = rstAfterTls.Select(p => p.Index).ToList()
                });
            }

            // General RST count
            if (rstAfterSyn.Count == 0 && rstAfterTls.Count == 0)
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name,
                    Category = Category,
                    Severity = Severity.Warning,
                    Title = $"{amaRstPackets.Count} RST packets to/from AMA endpoint IPs",
                    Detail = $"RST packets detected on connections to AMA endpoints. IPs: {string.Join(", ", amaIps.Take(5))}",
                    Recommendation = "Investigate whether a firewall, proxy, or load balancer is resetting connections.",
                    WiresharkFilter = "tcp.flags.reset == 1 && tcp.port == 443",
                    RelatedPacketIndices = amaRstPackets.Select(p => p.Index).ToList()
                });
            }
        }
        else if (rstPackets.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Info,
                Title = $"{rstPackets.Count} RST packets on port 443 (not targeting AMA IPs)",
                Detail = "RST packets exist on port 443 but none are associated with known AMA endpoint IPs.",
                WiresharkFilter = "tcp.flags.reset == 1 && tcp.port == 443"
            });
        }

        // ── SYN retransmissions (silent drops) ───────────────────────
        var synPackets = packets
            .Where(p => p.HasFlag(TcpFlags.SYN) && !p.HasFlag(TcpFlags.ACK) &&
                        p.DestPort == 443 && p.DestIp is not null)
            .ToList();

        // Group by destination IP and check for multiple SYNs (retransmissions)
        var synGroups = synPackets
            .GroupBy(p => $"{p.SourceIp}:{p.SourcePort}->{p.DestIp}:{p.DestPort}")
            .Where(g => g.Count() > 1) // retransmission = same 4-tuple SYN sent >1 time
            .ToList();

        var amaSynRetrans = synGroups
            .Where(g => g.Any(p => p.DestIp is not null && amaIps.Contains(p.DestIp)))
            .ToList();

        if (amaSynRetrans.Count > 0)
        {
            int totalRetrans = amaSynRetrans.Sum(g => g.Count() - 1);
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Error,
                Title = $"SYN retransmissions to AMA endpoints ({totalRetrans} retries)",
                Detail = $"SYN packets to AMA endpoint IPs were retransmitted without receiving SYN-ACK. Traffic is being silently dropped by a firewall, NSG, or routing issue.",
                Recommendation = "Check NSG rules, route tables, and firewall drop logs. Verify no UDR is sending traffic to a black hole.",
                WiresharkFilter = "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.analysis.retransmission",
                RelatedPacketIndices = amaSynRetrans.SelectMany(g => g.Select(p => p.Index)).ToList()
            });
        }

        // ── No issues found ──────────────────────────────────────────
        if (findings.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name,
                Category = Category,
                Severity = Severity.Pass,
                Title = "No firewall blocking detected",
                Detail = "No TCP RST packets or SYN retransmissions were found targeting AMA endpoint IPs on port 443.",
                WiresharkFilter = "tcp.flags.reset == 1 && tcp.port == 443"
            });
        }

        return findings;
    }
}
