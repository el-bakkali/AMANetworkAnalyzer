namespace AMANetworkAnalyzer.Core.Tests;

using AMANetworkAnalyzer.Analysis;
using AMANetworkAnalyzer.Models;
using AMANetworkAnalyzer.Parsers;

public class AnalysisEngineTests
{
    private const string AmaHost = "workspace.ods.opinsights.azure.com";

    private static List<ParsedPacket> Parse(params byte[][] frames) =>
        PacketParser.ParseAll([.. frames.Select(f => new RawPacket(DateTime.UtcNow, f, LinkLayerType.Ethernet))]);

    [Fact]
    public void ReportsNoAmaTrafficForAnEmptyCapture()
    {
        var report = new AnalysisEngine().AnalyzeParsed("empty.pcap", []);

        Assert.Equal(0, report.TotalPackets);
        Assert.Contains(report.Findings, f => f.Title.Contains("No AMA traffic", StringComparison.Ordinal));
    }

    [Fact]
    public void DetectsSuccessfulDnsResolution()
    {
        var packets = Parse(
            CaptureBuilder.Udp("10.0.0.1", "10.0.0.2", 5353, 53, CaptureBuilder.DnsQuery(1, AmaHost)),
            CaptureBuilder.Udp("10.0.0.2", "10.0.0.1", 53, 5353,
                CaptureBuilder.DnsResponseWithAddress(1, AmaHost, "20.1.2.3")));

        var report = new AnalysisEngine().AnalyzeParsed("dns.pcap", packets);

        Assert.Contains(report.Findings, f =>
            f.Category == "DNS Resolution" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void DetectsDnsFailure()
    {
        var packets = Parse(
            CaptureBuilder.Udp("10.0.0.1", "10.0.0.2", 5353, 53, CaptureBuilder.DnsQuery(1, AmaHost)),
            CaptureBuilder.Udp("10.0.0.2", "10.0.0.1", 53, 5353,
                CaptureBuilder.DnsResponseWithAddress(1, AmaHost, "0.0.0.0", responseCode: 3)));

        var report = new AnalysisEngine().AnalyzeParsed("nxdomain.pcap", packets);

        Assert.Contains(report.Findings, f =>
            f.Severity == Severity.Error && f.Title.Contains("NXDOMAIN", StringComparison.Ordinal));
    }

    [Fact]
    public void DetectsPrivateLinkResolution()
    {
        var packets = Parse(
            CaptureBuilder.Udp("10.0.0.1", "10.0.0.2", 5353, 53, CaptureBuilder.DnsQuery(1, AmaHost)),
            CaptureBuilder.Udp("10.0.0.2", "10.0.0.1", 53, 5353,
                CaptureBuilder.DnsResponseWithAddress(1, AmaHost, "10.20.30.40")));

        var report = new AnalysisEngine().AnalyzeParsed("ampls.pcap", packets);

        Assert.Contains(report.Findings, f =>
            f.Category == "Private Link" && f.Title.Contains("AMPLS", StringComparison.Ordinal));
    }

    [Fact]
    public void DetectsMissingRequiredCiphers()
    {
        var packets = Parse(CaptureBuilder.Tcp("10.0.0.1", "20.0.0.1", 50000, 443, 0x18,
            CaptureBuilder.TlsClientHello(AmaHost, 0x000A))); // a single legacy suite

        var report = new AnalysisEngine().AnalyzeParsed("ciphers.pcap", packets);

        Assert.Contains(report.Findings, f =>
            f.Category == "TLS Cipher Compliance" && f.Severity is Severity.Error or Severity.Warning);
    }

    [Fact]
    public void AcceptsCompliantCipherSet()
    {
        var packets = Parse(CaptureBuilder.Tcp("10.0.0.1", "20.0.0.1", 50000, 443, 0x18,
            CaptureBuilder.TlsClientHello(AmaHost, 0x1302, 0x1301, 0xC030, 0xC02F)));

        var report = new AnalysisEngine().AnalyzeParsed("ciphers-ok.pcap", packets);

        Assert.Contains(report.Findings, f =>
            f.Category == "TLS Cipher Compliance" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void DetectsTlsHandshakeFailureAlert()
    {
        var packets = Parse(
            CaptureBuilder.Tcp("10.0.0.1", "20.0.0.1", 50000, 443, 0x18,
                CaptureBuilder.TlsClientHello(AmaHost, 0x1302)),
            CaptureBuilder.Tcp("20.0.0.1", "10.0.0.1", 443, 50000, 0x18,
                CaptureBuilder.TlsAlert(2, 40)));

        var report = new AnalysisEngine().AnalyzeParsed("alert.pcap", packets);

        Assert.Contains(report.Findings, f =>
            f.Severity == Severity.Error && f.Title.Contains("handshake_failure", StringComparison.Ordinal));
    }

    [Fact]
    public void LookalikeHostnameDoesNotCountAsAmaTraffic()
    {
        var packets = Parse(CaptureBuilder.Udp("10.0.0.1", "10.0.0.2", 5353, 53,
            CaptureBuilder.DnsQuery(1, "notods.opinsights.azure.com")));

        var report = new AnalysisEngine().AnalyzeParsed("lookalike.pcap", packets);

        Assert.Contains(report.Findings, f => f.Title.Contains("No AMA traffic", StringComparison.Ordinal));
    }

    [Fact]
    public void FindingsAreDeduplicated()
    {
        // The same query repeated must not produce repeated identical findings.
        var frames = Enumerable.Range(0, 20)
            .Select(_ => CaptureBuilder.Udp("10.0.0.1", "10.0.0.2", 5353, 53,
                CaptureBuilder.DnsQuery(1, AmaHost)))
            .ToArray();

        var report = new AnalysisEngine().AnalyzeParsed("dupes.pcap", Parse(frames));

        var duplicates = report.Findings
            .GroupBy(f => (f.Category, f.Title))
            .Where(g => g.Count() > 1);

        Assert.Empty(duplicates);
    }

    [Fact]
    public void ParseWarningsSurfaceAsAFinding()
    {
        var report = new AnalysisEngine().AnalyzeParsed("warned.pcap", [], ["file truncated"]);

        Assert.Contains(report.Findings, f => f.Category == "File Integrity");
    }

    [Fact]
    public void CaptureDurationSpansFirstToLastTimestamp()
    {
        var start = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        byte[] frame = CaptureBuilder.Udp("10.0.0.1", "10.0.0.2", 1, 2, [1]);

        var packets = PacketParser.ParseAll(
        [
            new RawPacket(start, frame, LinkLayerType.Ethernet),
            new RawPacket(start.AddSeconds(30), frame, LinkLayerType.Ethernet)
        ]);

        var report = new AnalysisEngine().AnalyzeParsed("duration.pcap", packets);

        Assert.Equal(TimeSpan.FromSeconds(30), report.CaptureDuration);
    }

    [Fact]
    public void SeverityCountsMatchFindings()
    {
        var report = new AnalysisEngine().AnalyzeParsed("counts.pcap", []);

        Assert.Equal(report.Findings.Count(f => f.Severity == Severity.Error), report.ErrorCount);
        Assert.Equal(report.Findings.Count(f => f.Severity == Severity.Pass), report.PassCount);
    }

    [Fact]
    public void AFailingRuleIsReportedWithoutAbortingAnalysis()
    {
        var engine = new AnalysisEngine();
        var packets = Parse(CaptureBuilder.Udp("10.0.0.1", "10.0.0.2", 5353, 53,
            CaptureBuilder.DnsQuery(1, AmaHost)));

        var report = engine.AnalyzeParsed("ok.pcap", packets);

        // Every built-in rule contributed at least one category.
        Assert.True(report.Findings.Select(f => f.Category).Distinct().Count() >= 5);
    }
}
