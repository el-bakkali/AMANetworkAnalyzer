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
        ArgumentNullException.ThrowIfNull(rawPackets);
        return AnalyzeParsed(fileName, PacketParser.ParseAll(rawPackets), parseWarnings);
    }

    /// <summary>
    /// Runs the diagnostic rules against packets that have already been dissected.
    /// </summary>
    public AnalysisReport AnalyzeParsed(
        string fileName, List<ParsedPacket> parsed, List<string>? parseWarnings = null)
    {
        ArgumentNullException.ThrowIfNull(parsed);

        var report = new AnalysisReport
        {
            FileName = Path.GetFileName(fileName),
            AnalyzedAt = DateTime.UtcNow,
            TotalPackets = parsed.Count,
            ParseWarnings = parseWarnings ?? []
        };

        report.CaptureDuration = MeasureDuration(parsed);

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

        var seen = new HashSet<(string Category, string Title)>();
        foreach (var finding in report.Findings)
            seen.Add((finding.Category, finding.Title));

        foreach (var rule in _rules)
        {
            try
            {
                foreach (var finding in rule.Analyze(parsed))
                {
                    if (seen.Add((finding.Category, finding.Title)))
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

    private static TimeSpan MeasureDuration(List<ParsedPacket> parsed)
    {
        DateTime earliest = DateTime.MaxValue;
        DateTime latest = DateTime.MinValue;
        int counted = 0;

        foreach (var packet in parsed)
        {
            if (packet.Timestamp == DateTime.MinValue) continue;

            if (packet.Timestamp < earliest) earliest = packet.Timestamp;
            if (packet.Timestamp > latest) latest = packet.Timestamp;
            counted++;
        }

        return counted > 1 ? latest - earliest : TimeSpan.Zero;
    }
}
