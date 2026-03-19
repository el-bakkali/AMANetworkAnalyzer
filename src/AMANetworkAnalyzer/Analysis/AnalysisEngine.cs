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
    public AnalysisReport Analyze(string fileName, List<RawPacket> rawPackets, List<string>? parseWarnings = null)
    {
        var parsed = PacketParser.ParseAll(rawPackets);

        var report = new AnalysisReport
        {
            FileName = Path.GetFileName(fileName),
            AnalyzedAt = DateTime.UtcNow,
            TotalPackets = parsed.Count,
            ParseWarnings = parseWarnings ?? []
        };

        if (parsed.Count > 1)
        {
            var ts = parsed.Select(p => p.Timestamp).Where(t => t > DateTime.MinValue).ToList();
            if (ts.Count > 1)
                report.CaptureDuration = ts.Max() - ts.Min();
        }

        // Surface parse warnings as findings
        if (parseWarnings is { Count: > 0 })
        {
            report.Findings.Add(new AnalysisFinding
            {
                RuleName = "File Integrity",
                Category = "File Integrity",
                Severity = Severity.Warning,
                Title = $"{parseWarnings.Count} parser warning(s) detected",
                Detail = string.Join("\n", parseWarnings.Select(w => $"  • {w}")),
                Recommendation = "The capture file may be truncated or corrupted. Re-capture or obtain a complete copy.",
                ComplianceTag = "NIST-DE.AE-3 | CIS-8.2"
            });
        }

        foreach (var rule in _rules)
        {
            try
            {
                var findings = rule.Analyze(parsed);
                // Deduplicate findings with identical title+category
                foreach (var finding in findings)
                {
                    bool isDuplicate = report.Findings.Any(f =>
                        f.Title == finding.Title && f.Category == finding.Category);
                    if (!isDuplicate)
                        report.Findings.Add(finding);
                }
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
