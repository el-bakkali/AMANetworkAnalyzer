namespace AMANetworkAnalyzer.Parsers;

using System.Buffers.Binary;
using System.Net;
using System.Text;
using AMANetworkAnalyzer.Models;

/// <summary>
/// Dissects raw packet bytes into structured <see cref="ParsedPacket"/> objects.
/// Supports Ethernet, IPv4, TCP, UDP, DNS, TLS (Client/Server Hello + Alerts), and basic HTTP.
/// </summary>
public static class PacketParser
{
    public static List<ParsedPacket> ParseAll(List<RawPacket> rawPackets)
    {
        var parsed = new List<ParsedPacket>(rawPackets.Count);
        for (int i = 0; i < rawPackets.Count; i++)
        {
            var pkt = Parse(rawPackets[i], i);
            if (pkt is not null)
                parsed.Add(pkt);
        }
        return parsed;
    }

    public static ParsedPacket? Parse(RawPacket raw, int index)
    {
        var pkt = new ParsedPacket { Index = index, Timestamp = raw.Timestamp };
        var data = raw.Data;

        int ipOffset = raw.LinkType switch
        {
            LinkLayerType.Ethernet => ParseEthernet(data, pkt),
            LinkLayerType.LinuxSll => ParseLinuxSll(data, pkt),
            LinkLayerType.Raw => 0,  // starts at IP header
            _ => -1
        };

        if (ipOffset < 0 || ipOffset >= data.Length)
            return pkt; // link layer only

        int transportOffset = ParseIPv4(data, ipOffset, pkt);
        if (transportOffset < 0)
            return pkt;

        int payloadOffset;
        if (pkt.Protocol == IpProtocol.Tcp)
            payloadOffset = ParseTcp(data, transportOffset, pkt);
        else if (pkt.Protocol == IpProtocol.Udp)
            payloadOffset = ParseUdp(data, transportOffset, pkt);
        else
            return pkt;

        if (payloadOffset < 0 || payloadOffset >= data.Length)
            return pkt;

        int payloadLen = data.Length - payloadOffset;
        pkt.Payload = new byte[payloadLen];
        Buffer.BlockCopy(data, payloadOffset, pkt.Payload, 0, payloadLen);

        // Layer 7 dissection
        if (pkt.Protocol == IpProtocol.Udp && (pkt.SourcePort == 53 || pkt.DestPort == 53))
            pkt.Dns = ParseDns(pkt.Payload);
        else if (pkt.Protocol == IpProtocol.Tcp && payloadLen > 0)
            ParseTcpPayload(pkt);

        return pkt;
    }

    // ── Ethernet ─────────────────────────────────────────────────────

    private static int ParseEthernet(byte[] data, ParsedPacket pkt)
    {
        if (data.Length < 14) return -1;

        pkt.DestMac = FormatMac(data, 0);
        pkt.SourceMac = FormatMac(data, 6);

        ushort etherType = ReadBE16(data, 12);
        int offset = 14;

        // 802.1Q VLAN tag
        if (etherType == 0x8100 && data.Length >= 18)
        {
            etherType = ReadBE16(data, 16);
            offset = 18;
        }

        if (etherType != 0x0800) // only IPv4
            return -1;

        return offset;
    }

    // ── Linux cooked capture v1 ──────────────────────────────────────

    private static int ParseLinuxSll(byte[] data, ParsedPacket pkt)
    {
        if (data.Length < 16) return -1;

        ushort protocol = ReadBE16(data, 14);
        if (protocol != 0x0800) return -1;

        return 16;
    }

    // ── IPv4 ─────────────────────────────────────────────────────────

    private static int ParseIPv4(byte[] data, int offset, ParsedPacket pkt)
    {
        if (offset + 20 > data.Length) return -1;

        byte versionIhl = data[offset];
        if ((versionIhl >> 4) != 4) return -1; // not IPv4

        int ihl = (versionIhl & 0x0F) * 4;
        if (ihl < 20 || offset + ihl > data.Length) return -1;

        pkt.Protocol = (IpProtocol)data[offset + 9];
        pkt.SourceIp = new IPAddress(new ReadOnlySpan<byte>(data, offset + 12, 4)).ToString();
        pkt.DestIp = new IPAddress(new ReadOnlySpan<byte>(data, offset + 16, 4)).ToString();

        return offset + ihl;
    }

    // ── TCP ──────────────────────────────────────────────────────────

    private static int ParseTcp(byte[] data, int offset, ParsedPacket pkt)
    {
        if (offset + 20 > data.Length) return -1;

        pkt.SourcePort = ReadBE16(data, offset);
        pkt.DestPort = ReadBE16(data, offset + 2);

        byte flagsByte = data[offset + 13];
        pkt.TcpFlags = (TcpFlags)(flagsByte & 0x3F);

        int dataOffset = ((data[offset + 12] >> 4) & 0x0F) * 4;
        if (dataOffset < 20) dataOffset = 20;

        return offset + dataOffset;
    }

    // ── UDP ──────────────────────────────────────────────────────────

    private static int ParseUdp(byte[] data, int offset, ParsedPacket pkt)
    {
        if (offset + 8 > data.Length) return -1;

        pkt.SourcePort = ReadBE16(data, offset);
        pkt.DestPort = ReadBE16(data, offset + 2);

        return offset + 8;
    }

    // ── DNS ──────────────────────────────────────────────────────────

    private static DnsInfo? ParseDns(byte[] data)
    {
        if (data.Length < 12) return null;

        var dns = new DnsInfo
        {
            TransactionId = ReadBE16(data, 0),
            IsResponse = (data[2] & 0x80) != 0,
            ResponseCode = (ushort)(ReadBE16(data, 2) & 0x0F)
        };

        ushort qdCount = ReadBE16(data, 4);
        ushort anCount = ReadBE16(data, 6);

        int offset = 12;

        // Parse questions
        for (int i = 0; i < qdCount && offset < data.Length; i++)
        {
            string? name = ReadDnsName(data, ref offset);
            if (name is null || offset + 4 > data.Length) break;
            dns.QueryNames.Add(name);
            offset += 4; // QTYPE + QCLASS
        }

        // Parse answers
        for (int i = 0; i < anCount && offset < data.Length; i++)
        {
            string? name = ReadDnsName(data, ref offset);
            if (name is null || offset + 10 > data.Length) break;

            ushort type = ReadBE16(data, offset);
            offset += 4; // TYPE + CLASS
            offset += 4; // TTL
            ushort rdLen = ReadBE16(data, offset);
            offset += 2;

            if (offset + rdLen > data.Length) break;

            string rdata = type switch
            {
                1 when rdLen == 4 => new IPAddress(new ReadOnlySpan<byte>(data, offset, 4)).ToString(),
                28 when rdLen == 16 => new IPAddress(new ReadOnlySpan<byte>(data, offset, 16)).ToString(),
                5 => ReadDnsName(data, ref offset) ?? "(parse error)", // CNAME — note: advances offset
                _ => $"(type {type}, {rdLen} bytes)"
            };

            // Only advance offset for non-CNAME records (CNAME already advanced it)
            if (type != 5)
                offset += rdLen;

            dns.Answers.Add(new DnsAnswer(name ?? "", type, rdata));
        }

        return dns;
    }

    private static string? ReadDnsName(byte[] data, ref int offset)
    {
        var parts = new List<string>();
        int jumps = 0;
        int savedOffset = -1;
        int pos = offset;
        int totalBytes = 0;

        while (pos < data.Length && totalBytes < 255) // RFC 1035: max name length 255
        {
            byte len = data[pos];

            if (len == 0)
            {
                pos++;
                break;
            }

            // Pointer (compression)
            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 1 >= data.Length) return null;
                if (savedOffset < 0) savedOffset = pos + 2;
                pos = ((len & 0x3F) << 8) | data[pos + 1];
                if (++jumps > 16) return null; // prevent pointer loops
                continue;
            }

            pos++;
            if (pos + len > data.Length) return null;
            parts.Add(Encoding.ASCII.GetString(data, pos, len));
            pos += len;
            totalBytes += len + 1;
        }

        offset = savedOffset >= 0 ? savedOffset : pos;
        return parts.Count > 0 ? string.Join('.', parts) : null;
    }

    // ── TCP payload: TLS or HTTP ─────────────────────────────────────

    private static void ParseTcpPayload(ParsedPacket pkt)
    {
        var payload = pkt.Payload;
        if (payload.Length == 0) return;

        // Try TLS first (content type 20-23, version 0x0300-0x0304)
        if (payload.Length >= 5)
        {
            byte ct = payload[0];
            ushort ver = ReadBE16(payload, 1);
            if (ct >= 20 && ct <= 23 && ver >= 0x0300 && ver <= 0x0304)
            {
                pkt.Tls = ParseTls(payload);
                return;
            }
        }

        // Try HTTP (starts with method or "HTTP/")
        if (payload.Length >= 4)
        {
            pkt.Http = TryParseHttp(payload);
        }
    }

    // ── TLS ──────────────────────────────────────────────────────────

    private static TlsInfo? ParseTls(byte[] data)
    {
        if (data.Length < 5) return null;

        var tls = new TlsInfo
        {
            ContentType = data[0],
            RecordVersion = ReadBE16(data, 1)
        };

        ushort recordLen = ReadBE16(data, 3);
        int payloadStart = 5;

        if (tls.ContentType == 22 && payloadStart + 4 <= data.Length) // Handshake
        {
            tls.Handshake = ParseTlsHandshake(data, payloadStart, Math.Min(recordLen, data.Length - payloadStart));
        }
        else if (tls.ContentType == 21 && payloadStart + 2 <= data.Length) // Alert
        {
            tls.Alert = new TlsAlertInfo
            {
                Level = data[payloadStart],
                Description = data[payloadStart + 1]
            };
        }

        return tls;
    }

    private static TlsHandshakeInfo? ParseTlsHandshake(byte[] data, int offset, int maxLen)
    {
        if (offset + 4 > data.Length) return null;

        var hs = new TlsHandshakeInfo
        {
            HandshakeType = data[offset]
        };

        int hsLen = (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
        int hsStart = offset + 4;

        if (hs.HandshakeType == 1) // ClientHello
            ParseClientHello(data, hsStart, hsLen, hs);
        else if (hs.HandshakeType == 2) // ServerHello
            ParseServerHello(data, hsStart, hsLen, hs);
        else
            return hs;

        return hs;
    }

    private static void ParseClientHello(byte[] data, int offset, int length, TlsHandshakeInfo hs)
    {
        int end = Math.Min(offset + length, data.Length);
        if (offset + 2 > end) return;

        hs.ClientVersion = ReadBE16(data, offset);
        offset += 2;

        // Random (32 bytes)
        offset += 32;
        if (offset >= end) return;

        // Session ID
        byte sidLen = data[offset++];
        offset += sidLen;
        if (offset + 2 > end) return;

        // Cipher Suites
        ushort csLen = ReadBE16(data, offset);
        offset += 2;
        int csEnd = offset + csLen;
        while (offset + 2 <= csEnd && offset + 2 <= end)
        {
            hs.OfferedCipherSuites.Add(ReadBE16(data, offset));
            offset += 2;
        }
        offset = csEnd;
        if (offset >= end) return;

        // Compression Methods
        byte cmLen = data[offset++];
        offset += cmLen;
        if (offset + 2 > end) return;

        // Extensions
        ushort extTotalLen = ReadBE16(data, offset);
        offset += 2;
        int extEnd = Math.Min(offset + extTotalLen, end);

        while (offset + 4 <= extEnd)
        {
            ushort extType = ReadBE16(data, offset);
            ushort extLen = ReadBE16(data, offset + 2);
            int extDataStart = offset + 4;
            offset = extDataStart + extLen;

            switch (extType)
            {
                case 0: // SNI
                    ParseSni(data, extDataStart, extLen, hs);
                    break;
                case 43: // supported_versions
                    ParseSupportedVersions(data, extDataStart, extLen, hs);
                    break;
            }
        }
    }

    private static void ParseServerHello(byte[] data, int offset, int length, TlsHandshakeInfo hs)
    {
        int end = Math.Min(offset + length, data.Length);
        if (offset + 2 > end) return;

        hs.ClientVersion = ReadBE16(data, offset); // server's chosen version
        offset += 2;

        // Random (32 bytes)
        offset += 32;
        if (offset >= end) return;

        // Session ID
        byte sidLen = data[offset++];
        offset += sidLen;
        if (offset + 2 > end) return;

        // Selected cipher suite
        hs.SelectedCipherSuite = ReadBE16(data, offset);
        offset += 2;

        // Compression method
        offset += 1;
        if (offset + 2 > end) return;

        // Extensions
        ushort extTotalLen = ReadBE16(data, offset);
        offset += 2;
        int extEnd = Math.Min(offset + extTotalLen, end);

        while (offset + 4 <= extEnd)
        {
            ushort extType = ReadBE16(data, offset);
            ushort extLen = ReadBE16(data, offset + 2);
            int extDataStart = offset + 4;
            offset = extDataStart + extLen;

            if (extType == 43) // supported_versions
            {
                if (extLen >= 2)
                    hs.SupportedVersions.Add(ReadBE16(data, extDataStart));
            }
        }
    }

    private static void ParseSni(byte[] data, int offset, int length, TlsHandshakeInfo hs)
    {
        int end = Math.Min(offset + length, data.Length);
        if (offset + 2 > end) return;

        ushort listLen = ReadBE16(data, offset);
        offset += 2;
        int listEnd = Math.Min(offset + listLen, end);

        while (offset + 3 <= listEnd)
        {
            byte nameType = data[offset++];
            ushort nameLen = ReadBE16(data, offset);
            offset += 2;

            if (nameType == 0 && offset + nameLen <= listEnd) // host_name
            {
                hs.ServerName = Encoding.ASCII.GetString(data, offset, nameLen);
                return;
            }
            offset += nameLen;
        }
    }

    private static void ParseSupportedVersions(byte[] data, int offset, int length, TlsHandshakeInfo hs)
    {
        int end = Math.Min(offset + length, data.Length);
        if (offset >= end) return;

        byte listLen = data[offset++];
        int listEnd = Math.Min(offset + listLen, end);

        while (offset + 2 <= listEnd)
        {
            hs.SupportedVersions.Add(ReadBE16(data, offset));
            offset += 2;
        }
    }

    // ── HTTP (basic request/response detection) ──────────────────────

    private static HttpInfo? TryParseHttp(byte[] data)
    {
        // HTTP methods or response
        string start;
        try
        {
            int lineEnd = Math.Min(data.Length, 256);
            start = Encoding.ASCII.GetString(data, 0, lineEnd);
        }
        catch (ArgumentException)
        {
            return null;
        }

        var http = new HttpInfo();
        var lines = start.Split("\r\n", StringSplitOptions.None);
        if (lines.Length == 0) return null;

        string firstLine = lines[0];

        if (firstLine.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
        {
            // Response: "HTTP/1.1 200 OK"
            var parts = firstLine.Split(' ', 3);
            if (parts.Length >= 2 && int.TryParse(parts[1], out int code))
            {
                http.StatusCode = code;
                http.StatusPhrase = parts.Length >= 3 ? parts[2] : "";
            }
            else return null;
        }
        else
        {
            // Request: "CONNECT host:443 HTTP/1.1"
            var parts = firstLine.Split(' ', 3);
            if (parts.Length >= 2 && IsHttpMethod(parts[0]))
            {
                http.Method = parts[0];
                http.RequestUri = parts[1];
            }
            else return null;
        }

        // Parse headers
        for (int i = 1; i < lines.Length; i++)
        {
            if (string.IsNullOrEmpty(lines[i])) break;
            int colon = lines[i].IndexOf(':');
            if (colon > 0)
            {
                string key = lines[i][..colon].Trim();
                string val = lines[i][(colon + 1)..].Trim();
                http.Headers[key] = val;
            }
        }

        return http;
    }

    private static bool IsHttpMethod(string s) =>
        s is "GET" or "POST" or "PUT" or "DELETE" or "CONNECT" or "HEAD" or "OPTIONS" or "PATCH" or "TRACE";

    // ── Helpers ──────────────────────────────────────────────────────

    private static ushort ReadBE16(byte[] data, int offset) =>
        (ushort)((data[offset] << 8) | data[offset + 1]);

    private static string FormatMac(byte[] data, int offset) =>
        $"{data[offset]:X2}:{data[offset + 1]:X2}:{data[offset + 2]:X2}:{data[offset + 3]:X2}:{data[offset + 4]:X2}:{data[offset + 5]:X2}";
}
