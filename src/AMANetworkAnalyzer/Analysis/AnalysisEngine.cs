namespace AMANetworkAnalyzer.Analysis;

using AMANetworkAnalyzer.Analysis.Rules;
using AMANetworkAnalyzer.Models;
using AMANetworkAnalyzer.Parsers;

/// <summary>
/// Orchestrates reading a capture file, parsing packets, and running all diagnostic rules.
/// </summary>
public sealed class AnalysisEngine
{
    private readonly List<IAnalysisRule> _rules =
    [
        new EndpointConnectivityRule(),
        new DnsResolutionRule(),
        new FirewallBlockRule(),
        new ProxyDetectionRule(),
        new TlsAnalysisRule(),
        new TlsCipherComplianceRule(),
        new PrivateLinkDetectionRule(),
    ];

    /// <summary>
    /// Runs the full analysis pipeline on raw packets already loaded from a file.
    /// </summary>
    public AnalysisReport Analyze(string fileName, List<RawPacket> rawPackets)
    {
        var parsed = PacketParser.ParseAll(rawPackets);

        var report = new AnalysisReport
        {
            FileName = Path.GetFileName(fileName),
            AnalyzedAt = DateTime.UtcNow,
            TotalPackets = parsed.Count
        };

        if (parsed.Count > 1)
        {
            var ts = parsed.Select(p => p.Timestamp).Where(t => t > DateTime.MinValue).ToList();
            if (ts.Count > 1)
                report.CaptureDuration = ts.Max() - ts.Min();
        }

        foreach (var rule in _rules)
        {
            try
            {
                var findings = rule.Analyze(parsed);
                report.Findings.AddRange(findings);
            }
            catch (Exception ex)
            {
                report.Findings.Add(new AnalysisFinding
                {
                    RuleName = rule.Name,
                    Category = rule.Category,
                    Severity = Severity.Warning,
                    Title = $"Rule '{rule.Name}' encountered an error",
                    Detail = ex.Message,
                    Recommendation = "This rule could not complete. The capture file may be incomplete."
                });
            }
        }

        return report;
    }
}
