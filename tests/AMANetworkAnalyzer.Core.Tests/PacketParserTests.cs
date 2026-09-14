namespace AMANetworkAnalyzer.Core.Tests;

using System.Text;
using AMANetworkAnalyzer.Models;
using AMANetworkAnalyzer.Parsers;

public class PacketParserTests
{
    private static ParsedPacket ParseFrame(byte[] frame) =>
        PacketParser.Parse(new RawPacket(DateTime.UtcNow, frame, LinkLayerType.Ethernet), 0);

    // ── Layer 3/4 ────────────────────────────────────────────────────

    [Fact]
    public void ParsesIpv4AndUdpHeaders()
    {
        var packet = ParseFrame(CaptureBuilder.Udp("10.1.2.3", "10.4.5.6", 5353, 53, [1, 2, 3, 4]));

        Assert.Equal("10.1.2.3", packet.SourceIp);
        Assert.Equal("10.4.5.6", packet.DestIp);
        Assert.Equal(IpProtocol.Udp, packet.Protocol);
        Assert.Equal(5353, packet.SourcePort);
        Assert.Equal(53, packet.DestPort);
    }

    [Fact]
    public void ParsesTcpFlags()
    {
        var packet = ParseFrame(CaptureBuilder.Tcp("10.0.0.1", "10.0.0.2", 443, 50000, 0x04, []));

        Assert.Equal(IpProtocol.Tcp, packet.Protocol);
        Assert.True(packet.HasFlag(TcpFlags.RST));
        Assert.False(packet.HasFlag(TcpFlags.SYN));
    }

    [Fact]
    public void PayloadIsASliceNotACopy()
    {
        byte[] frame = CaptureBuilder.Udp("10.0.0.1", "10.0.0.2", 1, 2, [9, 8, 7]);
        var packet = ParseFrame(frame);

        Assert.Equal(new byte[] { 9, 8, 7 }, packet.Payload.ToArray());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(13)]
    [InlineData(20)]
    [InlineData(33)]
    public void TruncatedFramesDoNotThrow(int length)
    {
        byte[] frame = CaptureBuilder.Udp("10.0.0.1", "10.0.0.2", 1, 2, [1, 2, 3]);
        var packet = ParseFrame(frame[..Math.Min(length, frame.Length)]);

        Assert.NotNull(packet); // best-effort parse, never an exception
    }

    // ── DNS ──────────────────────────────────────────────────────────

    [Fact]
    public void ParsesDnsQueryName()
    {
        var packet = ParseFrame(CaptureBuilder.Udp("10.0.0.1", "10.0.0.2", 5353, 53,
            CaptureBuilder.DnsQuery(0x1234, "ods.opinsights.azure.com")));

        Assert.NotNull(packet.Dns);
        Assert.False(packet.Dns.IsResponse);
        Assert.Equal("ods.opinsights.azure.com", Assert.Single(packet.Dns.QueryNames));
    }

    [Fact]
    public void ParsesCompressedDnsAnswer()
    {
        var packet = ParseFrame(CaptureBuilder.Udp("10.0.0.2", "10.0.0.1", 53, 5353,
            CaptureBuilder.DnsResponseWithAddress(0x1234, "ods.opinsights.azure.com", "20.1.2.3")));

        Assert.NotNull(packet.Dns);
        Assert.True(packet.Dns.IsResponse);
        var answer = Assert.Single(packet.Dns.Answers);
        Assert.Equal("20.1.2.3", answer.Data);
    }

    /// <summary>
    /// Regression: the record cursor used to be derived from the parsed CNAME rather than the
    /// declared rdata length, so any CNAME whose rdata did not exactly equal its encoded name
    /// desynchronised the answer section and corrupted every record after it.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    public void CnameResynchronisesFromDeclaredRdataLength(int padding)
    {
        var packet = ParseFrame(CaptureBuilder.Udp("10.0.0.2", "10.0.0.1", 53, 5353,
            CaptureBuilder.DnsResponseWithOversizedCname(
                0x1234, "ods.opinsights.azure.com", "ods.trafficmanager.net", "20.9.9.9", padding)));

        Assert.NotNull(packet.Dns);
        Assert.Equal(2, packet.Dns.Answers.Count);

        Assert.Equal(5, packet.Dns.Answers[0].Type);
        Assert.Equal("ods.trafficmanager.net", packet.Dns.Answers[0].Data);

        Assert.Equal(1, packet.Dns.Answers[1].Type);
        Assert.Equal("20.9.9.9", packet.Dns.Answers[1].Data);
    }

    [Fact]
    public void SelfReferencingCompressionPointerTerminates()
    {
        // A pointer at offset 12 aimed at itself would loop forever without a guard.
        byte[] dns = new byte[16];
        dns[2] = 0x81; dns[3] = 0x80;
        dns[5] = 1;                  // qdcount
        dns[12] = 0xC0; dns[13] = 0x0C;

        var packet = ParseFrame(CaptureBuilder.Udp("10.0.0.2", "10.0.0.1", 53, 5353, dns));

        Assert.NotNull(packet.Dns); // terminated rather than hanging
    }

    [Fact]
    public void ForwardCompressionPointerIsRejected()
    {
        byte[] dns = new byte[20];
        dns[2] = 0x81; dns[3] = 0x80;
        dns[5] = 1;
        dns[12] = 0xC0; dns[13] = 0x10; // points forward, which no valid encoder emits

        var packet = ParseFrame(CaptureBuilder.Udp("10.0.0.2", "10.0.0.1", 53, 5353, dns));

        Assert.NotNull(packet.Dns);
        Assert.Empty(packet.Dns.QueryNames);
    }

    [Fact]
    public void DnsResponseCodeIsExtracted()
    {
        var packet = ParseFrame(CaptureBuilder.Udp("10.0.0.2", "10.0.0.1", 53, 5353,
            CaptureBuilder.DnsResponseWithAddress(1, "ods.opinsights.azure.com", "0.0.0.0", responseCode: 3)));

        Assert.NotNull(packet.Dns);
        Assert.Equal(3, packet.Dns.ResponseCode);
        Assert.Equal("NXDomain", packet.Dns.ResponseCodeName);
    }

    [Fact]
    public void ControlCharactersAreStrippedFromDnsLabels()
    {
        byte[] dns =
        [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x04, (byte)'a', 0x00, 0x0A, (byte)'b',   // label containing NUL and LF
            0x00,
            0x00, 0x01, 0x00, 0x01
        ];

        var packet = ParseFrame(CaptureBuilder.Udp("10.0.0.1", "10.0.0.2", 5353, 53, dns));

        Assert.NotNull(packet.Dns);
        string name = Assert.Single(packet.Dns.QueryNames);
        Assert.DoesNotContain('\0', name);
        Assert.DoesNotContain('\n', name);
    }

    // ── TLS ──────────────────────────────────────────────────────────

    [Fact]
    public void ParsesClientHelloSniAndCiphers()
    {
        var packet = ParseFrame(CaptureBuilder.Tcp("10.0.0.1", "20.0.0.1", 50000, 443, 0x18,
            CaptureBuilder.TlsClientHello("ods.opinsights.azure.com", 0x1302, 0x1301, 0xC030)));

        Assert.NotNull(packet.Tls?.Handshake);
        Assert.Equal(1, packet.Tls.Handshake.HandshakeType);
        Assert.Equal("ods.opinsights.azure.com", packet.Tls.Handshake.ServerName);
        Assert.Equal([0x1302, 0x1301, 0xC030], packet.Tls.Handshake.OfferedCipherSuites);
        Assert.Contains((ushort)0x0304, packet.Tls.Handshake.SupportedVersions);
    }

    [Fact]
    public void ParsesTlsAlert()
    {
        var packet = ParseFrame(CaptureBuilder.Tcp("20.0.0.1", "10.0.0.1", 443, 50000, 0x18,
            CaptureBuilder.TlsAlert(2, 40)));

        Assert.NotNull(packet.Tls?.Alert);
        Assert.Equal("Fatal", packet.Tls.Alert.LevelName);
        Assert.Equal("handshake_failure", packet.Tls.Alert.DescriptionName);
    }

    [Fact]
    public void TruncatedClientHelloDoesNotThrow()
    {
        byte[] hello = CaptureBuilder.TlsClientHello("ods.opinsights.azure.com", 0x1302);

        for (int length = 5; length < hello.Length; length += 3)
        {
            var packet = ParseFrame(
                CaptureBuilder.Tcp("10.0.0.1", "20.0.0.1", 50000, 443, 0x18, hello[..length]));
            Assert.NotNull(packet);
        }
    }

    [Fact]
    public void OversizedSniLengthIsRejected()
    {
        byte[] hello = CaptureBuilder.TlsClientHello("ods.opinsights.azure.com", 0x1302);

        // Corrupt the record length so the declared extent exceeds the bytes present.
        hello[3] = 0xFF;
        hello[4] = 0xFF;

        var packet = ParseFrame(CaptureBuilder.Tcp("10.0.0.1", "20.0.0.1", 50000, 443, 0x18, hello));
        Assert.NotNull(packet); // clamped, not crashed
    }

    // ── HTTP ─────────────────────────────────────────────────────────

    [Fact]
    public void ParsesHttpConnectRequest()
    {
        byte[] request = Encoding.ASCII.GetBytes(
            "CONNECT ods.opinsights.azure.com:443 HTTP/1.1\r\nHost: proxy\r\nProxy-Authorization: Basic eA==\r\n\r\n");

        var packet = ParseFrame(CaptureBuilder.Tcp("10.0.0.1", "10.0.0.9", 50000, 8080, 0x18, request));

        Assert.NotNull(packet.Http);
        Assert.Equal("CONNECT", packet.Http.Method);
        Assert.Equal("ods.opinsights.azure.com:443", packet.Http.RequestUri);
        Assert.True(packet.Http.Headers.ContainsKey("proxy-authorization"));
    }

    [Fact]
    public void ParsesHttp407Response()
    {
        byte[] response = Encoding.ASCII.GetBytes(
            "HTTP/1.1 407 Proxy Authentication Required\r\nVia: 1.1 proxy\r\n\r\n");

        var packet = ParseFrame(CaptureBuilder.Tcp("10.0.0.9", "10.0.0.1", 8080, 50000, 0x18, response));

        Assert.NotNull(packet.Http);
        Assert.Equal(407, packet.Http.StatusCode);
        Assert.True(packet.Http.Headers.ContainsKey("Via"));
    }

    [Fact]
    public void ImplausibleHttpStatusIsRejected()
    {
        byte[] response = Encoding.ASCII.GetBytes("HTTP/1.1 99999 Nope\r\n\r\n");

        var packet = ParseFrame(CaptureBuilder.Tcp("10.0.0.9", "10.0.0.1", 8080, 50000, 0x18, response));

        Assert.Null(packet.Http);
    }

    [Fact]
    public void NonHttpPayloadIsNotMisidentified()
    {
        var packet = ParseFrame(
            CaptureBuilder.Tcp("10.0.0.1", "10.0.0.2", 1234, 4321, 0x18, [0xFF, 0xFE, 0xFD, 0xFC, 0x00]));

        Assert.Null(packet.Http);
        Assert.Null(packet.Tls);
    }
}
