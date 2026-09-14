namespace AMANetworkAnalyzer.Core.Tests;

using AMANetworkAnalyzer.Models;

public class AmaEndpointsTests
{
    [Theory]
    [InlineData("ods.opinsights.azure.com")]
    [InlineData("ODS.OPINSIGHTS.AZURE.COM")]
    [InlineData("workspace-id.ods.opinsights.azure.com")]
    [InlineData("ods.opinsights.azure.com.")]           // trailing root dot
    [InlineData("global.handler.control.monitor.azure.com")]
    [InlineData("westeurope.handler.control.monitor.azure.com")]
    [InlineData("management.azure.us")]
    [InlineData("dce-x.westeurope.ingest.monitor.azure.cn")]
    public void RecognisesAmaEndpoints(string hostname) =>
        Assert.True(AmaEndpoints.IsAmaEndpoint(hostname));

    /// <summary>
    /// Regression: a plain suffix comparison matched any hostname merely ending in the
    /// pattern, so lookalike domains were reported as genuine AMA traffic.
    /// </summary>
    [Theory]
    [InlineData("notods.opinsights.azure.com")]
    [InlineData("evilods.opinsights.azure.com")]
    [InlineData("xmanagement.azure.com")]
    [InlineData("fakeglobal.prod.microsoftmetrics.com")]
    public void RejectsLookalikeHostnames(string hostname) =>
        Assert.False(AmaEndpoints.IsAmaEndpoint(hostname));

    [Theory]
    [InlineData("example.com")]
    [InlineData("opinsights.azure.com.evil.net")]
    [InlineData("")]
    [InlineData(null)]
    public void RejectsUnrelatedHostnames(string? hostname) =>
        Assert.False(AmaEndpoints.IsAmaEndpoint(hostname));

    [Fact]
    public void MatchesRequiresALabelBoundary()
    {
        Assert.True(AmaEndpoints.Matches("a.management.azure.com", "management.azure.com"));
        Assert.True(AmaEndpoints.Matches("management.azure.com", "management.azure.com"));
        Assert.False(AmaEndpoints.Matches("amanagement.azure.com", "management.azure.com"));
    }

    [Fact]
    public void MatchEndpointReturnsDescription()
    {
        Assert.NotNull(AmaEndpoints.MatchEndpoint("w1.ods.opinsights.azure.com"));
        Assert.Null(AmaEndpoints.MatchEndpoint("contoso.example.com"));
    }
}

public class SafeTextTests
{
    [Fact]
    public void HostNameStripsControlAndNonHostCharacters()
    {
        byte[] raw = [(byte)'a', 0x00, (byte)'b', 0x0A, (byte)'-', (byte)'c', 0xFF];
        Assert.Equal("ab-c", SafeText.HostName(raw));
    }

    [Fact]
    public void HostNameReturnsNullWhenNothingUsableRemains()
    {
        Assert.Null(SafeText.HostName([0x00, 0x01, 0x02]));
        Assert.Null(SafeText.HostName([]));
    }

    [Fact]
    public void HostNameIsLengthCapped()
    {
        byte[] raw = Enumerable.Repeat((byte)'a', 5000).ToArray();
        Assert.Equal(SafeText.MaxHostNameLength, SafeText.HostName(raw)!.Length);
    }

    [Fact]
    public void SingleLineRemovesNewlines()
    {
        Assert.Equal("abc", SafeText.SingleLine("a\r\nb\tc"));
    }

    [Fact]
    public void SingleLineIsLengthCapped()
    {
        Assert.Equal(10, SafeText.SingleLine(new string('x', 100), 10).Length);
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a*b", @"a\*b")]
    [InlineData("[link](x)", @"\[link\]\(x\)")]
    [InlineData("back`tick", @"back\`tick")]
    public void MarkdownEscapeNeutralisesSyntax(string input, string expected) =>
        Assert.Equal(expected, SafeText.MarkdownEscape(input));

    [Fact]
    public void MarkdownEscapePreservesNewlines() =>
        Assert.Contains("\n", SafeText.MarkdownEscape("a\nb"), StringComparison.Ordinal);

    [Fact]
    public void PlainTextDropsControlCharactersButKeepsWhitespace()
    {
        string result = SafeText.PlainText("a\u0007b\nc\td");
        Assert.DoesNotContain('\u0007', result);
        Assert.Contains("\n", result, StringComparison.Ordinal);
        Assert.Contains("\t", result, StringComparison.Ordinal);
    }

    [Fact]
    public void PrintableAsciiReplacesNonPrintableBytes() =>
        Assert.Equal("a.b", SafeText.PrintableAscii([(byte)'a', 0x00, (byte)'b'], 10));
}
