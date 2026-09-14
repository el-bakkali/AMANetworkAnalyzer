namespace AMANetworkAnalyzer.Parsers;

using System.Buffers.Binary;
using System.Net;
using System.Text;
using AMANetworkAnalyzer.Models;

/// <summary>
/// Dissects raw packet bytes into structured <see cref="ParsedPacket"/> objects.
/// Supports Ethernet, IPv4, TCP, UDP, DNS, TLS (Client/Server Hello + Alerts), and basic HTTP.
/// </summary>
/// <remarks>
/// Every input here is attacker-controlled. Parsers slice into the region they own and never
/// trust a declared length without checking it against the bytes actually present.
/// </remarks>
public static class PacketParser
{
    private const int MaxDnsRecords = 64;
    private const int MaxCipherSuites = 512;
    private const int MaxTlsExtensions = 64;
    private const int MaxHttpHeaders = 64;
    private const int HttpPreviewBytes = 1024;

    public static List<ParsedPacket> ParseAll(List<RawPacket> rawPackets)
    {
        ArgumentNullException.ThrowIfNull(rawPackets);

        var parsed = new List<ParsedPacket>(rawPackets.Count);
        for (int i = 0; i < rawPackets.Count; i++)
            parsed.Add(Parse(rawPackets[i], i));
        return parsed;
    }

    public static ParsedPacket Parse(RawPacket raw, int index)
    {
        ArgumentNullException.ThrowIfNull(raw);

        var packet = new ParsedPacket { Index = index, Timestamp = raw.Timestamp };
        ReadOnlySpan<byte> data = raw.Data;

        int ipOffset = raw.LinkType switch
        {
            LinkLayerType.Ethernet => ParseEthernet(data, packet),
            LinkLayerType.LinuxSll => ParseLinuxSll(data),
            LinkLayerType.Raw => 0,
            _ => -1
        };

        if (ipOffset < 0 || ipOffset >= data.Length)
            return packet;

        int transportOffset = ParseIPv4(data, ipOffset, packet);
        if (transportOffset < 0 || transportOffset >= data.Length)
            return packet;

        int payloadOffset = packet.Protocol switch
        {
            IpProtocol.Tcp => ParseTcp(data, transportOffset, packet),
            IpProtocol.Udp => ParseUdp(data, transportOffset, packet),
            _ => -1
        };

        if (payloadOffset < 0 || payloadOffset >= data.Length)
            return packet;

        // A slice of the captured frame, not a copy.
        packet.Payload = raw.Data.AsMemory(payloadOffset);
        ReadOnlySpan<byte> payload = packet.Payload.Span;

        if (packet.Protocol == IpProtocol.Udp && (packet.SourcePort == 53 || packet.DestPort == 53))
            packet.Dns = ParseDns(payload);
        else if (packet.Protocol == IpProtocol.Tcp && payload.Length > 0)
            ParseTcpPayload(payload, packet);

        return packet;
    }

    // ── Ethernet ─────────────────────────────────────────────────────

    private static int ParseEthernet(ReadOnlySpan<byte> data, ParsedPacket packet)
    {
        if (data.Length < 14) return -1;

        packet.DestMac = FormatMac(data[..6]);
        packet.SourceMac = FormatMac(data.Slice(6, 6));

        ushort etherType = ReadBE16(data, 12);
        int offset = 14;

        // 802.1Q VLAN tag
        if (etherType == 0x8100)
        {
            if (data.Length < 18) return -1;
            etherType = ReadBE16(data, 16);
            offset = 18;
        }

        return etherType == 0x0800 ? offset : -1; // IPv4 only
    }

    // ── Linux cooked capture v1 ──────────────────────────────────────

    private static int ParseLinuxSll(ReadOnlySpan<byte> data)
    {
        if (data.Length < 16) return -1;
        return ReadBE16(data, 14) == 0x0800 ? 16 : -1;
    }

    // ── IPv4 ─────────────────────────────────────────────────────────

    private static int ParseIPv4(ReadOnlySpan<byte> data, int offset, ParsedPacket packet)
    {
        if (offset + 20 > data.Length) return -1;

        byte versionIhl = data[offset];
        if ((versionIhl >> 4) != 4) return -1;

        int headerLength = (versionIhl & 0x0F) * 4;
        if (headerLength < 20 || offset + headerLength > data.Length) return -1;

        // A declared total length shorter than the header means a malformed packet.
        ushort totalLength = ReadBE16(data, offset + 2);
        if (totalLength != 0 && totalLength < headerLength) return -1;

        packet.Protocol = (IpProtocol)data[offset + 9];
        packet.SourceIp = new IPAddress(data.Slice(offset + 12, 4)).ToString();
        packet.DestIp = new IPAddress(data.Slice(offset + 16, 4)).ToString();

        return offset + headerLength;
    }

    // ── TCP ──────────────────────────────────────────────────────────

    private static int ParseTcp(ReadOnlySpan<byte> data, int offset, ParsedPacket packet)
    {
        if (offset + 20 > data.Length) return -1;

        packet.SourcePort = ReadBE16(data, offset);
        packet.DestPort = ReadBE16(data, offset + 2);
        packet.TcpFlags = (TcpFlags)(data[offset + 13] & 0x3F);

        int dataOffset = ((data[offset + 12] >> 4) & 0x0F) * 4;
        if (dataOffset < 20) dataOffset = 20;

        return offset + dataOffset;
    }

    // ── UDP ──────────────────────────────────────────────────────────

    private static int ParseUdp(ReadOnlySpan<byte> data, int offset, ParsedPacket packet)
    {
        if (offset + 8 > data.Length) return -1;

        packet.SourcePort = ReadBE16(data, offset);
        packet.DestPort = ReadBE16(data, offset + 2);

        return offset + 8;
    }

    // ── DNS ──────────────────────────────────────────────────────────

    private static DnsInfo? ParseDns(ReadOnlySpan<byte> data)
    {
        if (data.Length < 12) return null;

        var dns = new DnsInfo
        {
            TransactionId = ReadBE16(data, 0),
            IsResponse = (data[2] & 0x80) != 0,
            ResponseCode = (ushort)(ReadBE16(data, 2) & 0x000F)
        };

        int questionCount = Math.Min((int)ReadBE16(data, 4), MaxDnsRecords);
        int answerCount = Math.Min((int)ReadBE16(data, 6), MaxDnsRecords);

        int offset = 12;

        for (int i = 0; i < questionCount && offset < data.Length; i++)
        {
            string? name = ReadDnsName(data, ref offset);
            if (name is null || offset + 4 > data.Length) break;

            if (name.Length > 0) dns.QueryNames.Add(name);
            offset += 4; // QTYPE + QCLASS
        }

        for (int i = 0; i < answerCount && offset < data.Length; i++)
        {
            string? name = ReadDnsName(data, ref offset);
            if (name is null || offset + 10 > data.Length) break;

            ushort type = ReadBE16(data, offset);
            offset += 8; // TYPE + CLASS + TTL
            ushort rdataLength = ReadBE16(data, offset);
            offset += 2;

            if (offset + rdataLength > data.Length) break;

            int rdataStart = offset;
            string rdata = ReadDnsRecordData(data, type, rdataStart, rdataLength);

            // Always resynchronise from the declared record boundary. Deriving the next
            // offset from a parsed name instead would desynchronise the whole answer
            // section on an uncompressed CNAME.
            offset = rdataStart + rdataLength;

            dns.Answers.Add(new DnsAnswer(name, type, rdata));
        }

        return dns;
    }

    private static string ReadDnsRecordData(ReadOnlySpan<byte> data, ushort type, int start, int length)
    {
        switch (type)
        {
            case 1 when length == 4:
                return new IPAddress(data.Slice(start, 4)).ToString();

            case 28 when length == 16:
                return new IPAddress(data.Slice(start, 16)).ToString();

            case 5: // CNAME — parsed with a local cursor so it cannot move the record offset
            {
                int cursor = start;
                return ReadDnsName(data, ref cursor) ?? "(unparsable CNAME)";
            }

            default:
                return $"(type {type}, {length} bytes)";
        }
    }

    /// <summary>
    /// Reads a DNS name, following compression pointers. Returns null when the encoding is
    /// malformed, or an empty string for the root name.
    /// </summary>
    private static string? ReadDnsName(ReadOnlySpan<byte> data, ref int offset)
    {
        var labels = new List<string>(8);
        int jumps = 0;
        int returnOffset = -1;
        int position = offset;
        int totalLength = 0;

        while (position < data.Length)
        {
            byte length = data[position];

            if (length == 0)
            {
                position++;
                break;
            }

            if ((length & 0xC0) == 0xC0) // compression pointer
            {
                if (position + 1 >= data.Length) return null;
                if (returnOffset < 0) returnOffset = position + 2;

                int target = ((length & 0x3F) << 8) | data[position + 1];

                // A pointer must move strictly backwards; anything else can loop.
                if (target >= position) return null;
                if (++jumps > 16) return null;

                position = target;
                continue;
            }

            position++;
            if (position + length > data.Length) return null;

            totalLength += length + 1;
            if (totalLength > SafeText.MaxHostNameLength) return null;

            string? label = SafeText.HostName(data.Slice(position, length));
            if (label is not null) labels.Add(label);

            position += length;
        }

        offset = returnOffset >= 0 ? returnOffset : position;
        return labels.Count > 0 ? string.Join('.', labels) : string.Empty;
    }

    // ── TCP payload: TLS or HTTP ─────────────────────────────────────

    private static void ParseTcpPayload(ReadOnlySpan<byte> payload, ParsedPacket packet)
    {
        if (payload.Length >= 5)
        {
            byte contentType = payload[0];
            ushort version = ReadBE16(payload, 1);
            if (contentType is >= 20 and <= 23 && version is >= 0x0300 and <= 0x0304)
            {
                packet.Tls = ParseTls(payload);
                return;
            }
        }

        if (payload.Length >= 4)
            packet.Http = TryParseHttp(payload);
    }

    // ── TLS ──────────────────────────────────────────────────────────

    private static TlsInfo ParseTls(ReadOnlySpan<byte> data)
    {
        var tls = new TlsInfo
        {
            ContentType = data[0],
            RecordVersion = ReadBE16(data, 1)
        };

        ushort recordLength = ReadBE16(data, 3);
        const int recordStart = 5;
        int available = data.Length - recordStart;

        if (tls.ContentType == 22 && available >= 4)
        {
            tls.Handshake = ParseTlsHandshake(data.Slice(recordStart, Math.Min(recordLength, available)));
        }
        else if (tls.ContentType == 21 && available >= 2)
        {
            tls.Alert = new TlsAlertInfo
            {
                Level = data[recordStart],
                Description = data[recordStart + 1]
            };
        }

        return tls;
    }

    private static TlsHandshakeInfo? ParseTlsHandshake(ReadOnlySpan<byte> record)
    {
        if (record.Length < 4) return null;

        var handshake = new TlsHandshakeInfo { HandshakeType = record[0] };

        int declaredLength = (record[1] << 16) | (record[2] << 8) | record[3];
        int available = record.Length - 4;
        ReadOnlySpan<byte> body = record.Slice(4, Math.Min(declaredLength, available));

        switch (handshake.HandshakeType)
        {
            case 1: ParseClientHello(body, handshake); break;
            case 2: ParseServerHello(body, handshake); break;
        }

        return handshake;
    }

    private static void ParseClientHello(ReadOnlySpan<byte> body, TlsHandshakeInfo handshake)
    {
        int offset = 0;
        if (!TryRead16(body, ref offset, out ushort clientVersion)) return;
        handshake.ClientVersion = clientVersion;

        if (!TrySkip(body, ref offset, 32)) return;                     // Random
        if (!TryReadVector8(body, ref offset, out _)) return;           // Session ID
        if (!TryReadVector16(body, ref offset, out var cipherSuites)) return;

        for (int i = 0; i + 2 <= cipherSuites.Length && handshake.OfferedCipherSuites.Count < MaxCipherSuites; i += 2)
            handshake.OfferedCipherSuites.Add(ReadBE16(cipherSuites, i));

        if (!TryReadVector8(body, ref offset, out _)) return;           // Compression methods

        ParseExtensions(body, offset, handshake, clientHello: true);
    }

    private static void ParseServerHello(ReadOnlySpan<byte> body, TlsHandshakeInfo handshake)
    {
        int offset = 0;
        if (!TryRead16(body, ref offset, out ushort serverVersion)) return;
        handshake.ClientVersion = serverVersion; // the version the server selected

        if (!TrySkip(body, ref offset, 32)) return;                     // Random
        if (!TryReadVector8(body, ref offset, out _)) return;           // Session ID
        if (!TryRead16(body, ref offset, out ushort selectedCipher)) return;
        handshake.SelectedCipherSuite = selectedCipher;

        if (!TrySkip(body, ref offset, 1)) return;                      // Compression method

        ParseExtensions(body, offset, handshake, clientHello: false);
    }

    private static void ParseExtensions(
        ReadOnlySpan<byte> body, int offset, TlsHandshakeInfo handshake, bool clientHello)
    {
        if (!TryRead16(body, ref offset, out ushort extensionsLength)) return;

        int end = Math.Min(offset + extensionsLength, body.Length);
        int processed = 0;

        while (offset + 4 <= end && processed < MaxTlsExtensions)
        {
            ushort extensionType = ReadBE16(body, offset);
            ushort extensionLength = ReadBE16(body, offset + 2);
            int dataStart = offset + 4;

            if (dataStart + extensionLength > end) return;

            ReadOnlySpan<byte> extension = body.Slice(dataStart, extensionLength);

            switch (extensionType)
            {
                case 0 when clientHello:
                    ParseServerNameIndication(extension, handshake);
                    break;

                case 43: // supported_versions
                    if (clientHello) ParseSupportedVersions(extension, handshake);
                    else if (extension.Length >= 2) handshake.SupportedVersions.Add(ReadBE16(extension, 0));
                    break;
            }

            offset = dataStart + extensionLength;
            processed++;
        }
    }

    private static void ParseServerNameIndication(ReadOnlySpan<byte> extension, TlsHandshakeInfo handshake)
    {
        int offset = 0;
        if (!TryRead16(extension, ref offset, out ushort listLength)) return;

        int end = Math.Min(offset + listLength, extension.Length);

        while (offset + 3 <= end)
        {
            byte nameType = extension[offset];
            ushort nameLength = ReadBE16(extension, offset + 1);
            int nameStart = offset + 3;

            if (nameStart + nameLength > end) return;

            if (nameType == 0) // host_name
            {
                handshake.ServerName = SafeText.HostName(extension.Slice(nameStart, nameLength));
                return;
            }

            offset = nameStart + nameLength;
        }
    }

    private static void ParseSupportedVersions(ReadOnlySpan<byte> extension, TlsHandshakeInfo handshake)
    {
        if (extension.Length < 1) return;

        int listLength = extension[0];
        int end = Math.Min(1 + listLength, extension.Length);

        for (int offset = 1; offset + 2 <= end; offset += 2)
            handshake.SupportedVersions.Add(ReadBE16(extension, offset));
    }

    // ── HTTP (basic request/response detection) ──────────────────────

    private static HttpInfo? TryParseHttp(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> preview = data.Length > HttpPreviewBytes ? data[..HttpPreviewBytes] : data;

        // ASCII maps bytes above 0x7F to '?', so no non-ASCII reaches the UI.
        string text = Encoding.ASCII.GetString(preview);
        var lines = text.Split("\r\n");
        if (lines.Length == 0) return null;

        var http = new HttpInfo();
        string firstLine = lines[0];

        if (firstLine.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
        {
            var parts = firstLine.Split(' ', 3);
            if (parts.Length < 2 || !int.TryParse(parts[1], out int statusCode)) return null;
            if (statusCode is < 100 or > 599) return null;

            http.StatusCode = statusCode;
            http.StatusPhrase = parts.Length >= 3 ? SafeText.SingleLine(parts[2], 128) : string.Empty;
        }
        else
        {
            var parts = firstLine.Split(' ', 3);
            if (parts.Length < 2 || !IsHttpMethod(parts[0])) return null;

            http.Method = parts[0];
            http.RequestUri = SafeText.SingleLine(parts[1], 2048);
        }

        for (int i = 1; i < lines.Length && http.Headers.Count < MaxHttpHeaders; i++)
        {
            if (lines[i].Length == 0) break;

            int colon = lines[i].IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0) continue;

            string key = SafeText.SingleLine(lines[i][..colon].Trim(), 128);
            string value = SafeText.SingleLine(lines[i][(colon + 1)..].Trim(), 1024);
            if (key.Length > 0) http.Headers[key] = value;
        }

        return http;
    }

    private static bool IsHttpMethod(string value) =>
        value is "GET" or "POST" or "PUT" or "DELETE" or "CONNECT" or "HEAD" or "OPTIONS" or "PATCH" or "TRACE";

    // ── Bounds-checked cursor helpers ────────────────────────────────

    private static bool TrySkip(ReadOnlySpan<byte> data, ref int offset, int count)
    {
        if (offset + count > data.Length) return false;
        offset += count;
        return true;
    }

    private static bool TryRead16(ReadOnlySpan<byte> data, ref int offset, out ushort value)
    {
        if (offset + 2 > data.Length) { value = 0; return false; }
        value = ReadBE16(data, offset);
        offset += 2;
        return true;
    }

    /// <summary>Reads a TLS vector with a single-byte length prefix.</summary>
    private static bool TryReadVector8(ReadOnlySpan<byte> data, ref int offset, out ReadOnlySpan<byte> value)
    {
        value = default;
        if (offset + 1 > data.Length) return false;

        int length = data[offset];
        if (offset + 1 + length > data.Length) return false;

        value = data.Slice(offset + 1, length);
        offset += 1 + length;
        return true;
    }

    /// <summary>Reads a TLS vector with a two-byte length prefix.</summary>
    private static bool TryReadVector16(ReadOnlySpan<byte> data, ref int offset, out ReadOnlySpan<byte> value)
    {
        value = default;
        if (offset + 2 > data.Length) return false;

        int length = ReadBE16(data, offset);
        if (offset + 2 + length > data.Length) return false;

        value = data.Slice(offset + 2, length);
        offset += 2 + length;
        return true;
    }

    private static ushort ReadBE16(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));

    private static string FormatMac(ReadOnlySpan<byte> mac) =>
        $"{mac[0]:X2}:{mac[1]:X2}:{mac[2]:X2}:{mac[3]:X2}:{mac[4]:X2}:{mac[5]:X2}";
}
