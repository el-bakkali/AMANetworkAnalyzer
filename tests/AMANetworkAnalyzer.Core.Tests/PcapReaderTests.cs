namespace AMANetworkAnalyzer.Core.Tests;

using AMANetworkAnalyzer.Models;
using AMANetworkAnalyzer.Parsers;

public class PcapReaderTests
{
    private static byte[] SampleFrame() =>
        CaptureBuilder.Udp("10.0.0.1", "10.0.0.2", 12345, 53,
            CaptureBuilder.DnsQuery(0x1234, "ods.opinsights.azure.com"));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReadsPcapInBothByteOrders(bool bigEndian)
    {
        byte[] bytes = CaptureBuilder.Pcap([SampleFrame(), SampleFrame()], bigEndian);
        using var file = CaptureBuilder.ToTempFile(bytes);

        var (packets, warnings) = PcapReader.ReadFile(file.Path);

        Assert.Equal(2, packets.Count);
        Assert.Empty(warnings);
        Assert.All(packets, p => Assert.Equal(LinkLayerType.Ethernet, p.LinkType));
    }

    /// <summary>
    /// Regression: the block length used to be read before the section header revealed the
    /// byte order, so a big-endian file produced a nonsense length and the parse aborted.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReadsPcapngInBothByteOrders(bool bigEndian)
    {
        byte[] bytes = CaptureBuilder.Pcapng([SampleFrame(), SampleFrame(), SampleFrame()], bigEndian);
        using var file = CaptureBuilder.ToTempFile(bytes, ".pcapng");

        var (packets, warnings) = PcapReader.ReadFile(file.Path);

        Assert.Equal(3, packets.Count);
        Assert.Empty(warnings);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PcapngTimestampsAreOrderedAndPlausible(bool bigEndian)
    {
        byte[] bytes = CaptureBuilder.Pcapng([SampleFrame(), SampleFrame()], bigEndian);
        using var file = CaptureBuilder.ToTempFile(bytes, ".pcapng");

        var (packets, _) = PcapReader.ReadFile(file.Path);

        Assert.True(packets[1].Timestamp > packets[0].Timestamp);
        Assert.InRange(packets[0].Timestamp.Year, 2023, 2030);
    }

    [Fact]
    public void RejectsUnknownMagic()
    {
        using var file = CaptureBuilder.ToTempFile([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);

        var exception = Assert.Throws<InvalidDataException>(() => PcapReader.ReadFile(file.Path));
        Assert.Contains("Unsupported file format", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsFileTooSmall()
    {
        using var file = CaptureBuilder.ToTempFile([0x01, 0x02]);
        Assert.Throws<InvalidDataException>(() => PcapReader.ReadFile(file.Path));
    }

    [Fact]
    public void ReportsTruncatedPacketData()
    {
        byte[] bytes = CaptureBuilder.Pcap([SampleFrame()]);
        using var file = CaptureBuilder.ToTempFile(bytes[..^20]); // cut into the packet body

        var (_, warnings) = PcapReader.ReadFile(file.Path);

        Assert.NotEmpty(warnings);
        Assert.Contains(warnings, w => w.Contains("truncated", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void TruncatedPcapngBlockDoesNotThrow()
    {
        byte[] bytes = CaptureBuilder.Pcapng([SampleFrame(), SampleFrame()]);
        using var file = CaptureBuilder.ToTempFile(bytes[..^12], ".pcapng");

        var (packets, warnings) = PcapReader.ReadFile(file.Path);

        Assert.Single(packets);
        Assert.NotEmpty(warnings);
    }

    [Fact]
    public void EmptyCaptureYieldsNoPackets()
    {
        byte[] bytes = CaptureBuilder.Pcap([]);
        using var file = CaptureBuilder.ToTempFile(bytes);

        var (packets, warnings) = PcapReader.ReadFile(file.Path);

        Assert.Empty(packets);
        Assert.Empty(warnings);
    }

    [Fact]
    public void ReadAndParseMatchesReadThenParse()
    {
        byte[] bytes = CaptureBuilder.Pcap([SampleFrame(), SampleFrame()]);
        using var file = CaptureBuilder.ToTempFile(bytes);

        var (raw, _) = PcapReader.ReadFile(file.Path);
        var expected = PacketParser.ParseAll(raw);
        var (actual, _) = PcapReader.ReadAndParse(file.Path);

        Assert.Equal(expected.Count, actual.Count);
        Assert.Equal(
            expected.Select(p => p.Dns?.QueryNames.FirstOrDefault()),
            actual.Select(p => p.Dns?.QueryNames.FirstOrDefault()));
    }

    [Fact]
    public void ReadAndParseHonoursCancellation()
    {
        byte[] bytes = CaptureBuilder.Pcap(Enumerable.Range(0, 50).Select(_ => SampleFrame()));
        using var file = CaptureBuilder.ToTempFile(bytes);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.Throws<OperationCanceledException>(() => PcapReader.ReadAndParse(file.Path, cts.Token));
    }

    [Fact]
    public void MissingFileThrowsFileNotFound()
    {
        string path = Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid():N}.pcap");
        Assert.Throws<FileNotFoundException>(() => PcapReader.ReadFile(path));
    }

    [Fact]
    public void IsKnownMagicAcceptsEverySupportedFormat()
    {
        Assert.True(PcapReader.IsKnownMagic(0xA1B2C3D4));
        Assert.True(PcapReader.IsKnownMagic(0xD4C3B2A1));
        Assert.True(PcapReader.IsKnownMagic(0xA1B23C4D));
        Assert.True(PcapReader.IsKnownMagic(0x4D3CB2A1));
        Assert.True(PcapReader.IsKnownMagic(0x0A0D0D0A));
        Assert.False(PcapReader.IsKnownMagic(0xDEADBEEF));
    }
}
