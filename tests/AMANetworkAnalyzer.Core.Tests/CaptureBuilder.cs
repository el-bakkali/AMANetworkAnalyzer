namespace AMANetworkAnalyzer.Core.Tests;

using System.Buffers.Binary;
using System.Net;
using System.Text;

/// <summary>
/// Builds real capture bytes in memory so the readers can be exercised without fixture files.
/// Supports both byte orders, which is what makes the big-endian regression testable.
/// </summary>
internal static class CaptureBuilder
{
    public const uint PcapMagicMicros = 0xA1B2C3D4;
    public const uint PcapngByteOrderMagic = 0x1A2B3C4D;

    // ── Containers ───────────────────────────────────────────────────

    public static byte[] Pcap(IEnumerable<byte[]> packets, bool bigEndian = false, uint linkType = 1)
    {
        var output = new MemoryStream();

        Write32(output, PcapMagicMicros, bigEndian);
        Write16(output, 2, bigEndian);          // version major
        Write16(output, 4, bigEndian);          // version minor
        Write32(output, 0, bigEndian);          // thiszone
        Write32(output, 0, bigEndian);          // sigfigs
        Write32(output, 65535, bigEndian);      // snaplen
        Write32(output, linkType, bigEndian);

        uint seconds = 1_700_000_000;
        foreach (byte[] packet in packets)
        {
            Write32(output, seconds++, bigEndian);
            Write32(output, 0, bigEndian);
            Write32(output, (uint)packet.Length, bigEndian);
            Write32(output, (uint)packet.Length, bigEndian);
            output.Write(packet);
        }

        return output.ToArray();
    }

    public static byte[] Pcapng(IEnumerable<byte[]> packets, bool bigEndian = false, ushort linkType = 1)
    {
        var output = new MemoryStream();

        // Section Header Block
        Write32(output, 0x0A0D0D0A, bigEndian);
        Write32(output, 28, bigEndian);
        Write32(output, PcapngByteOrderMagic, bigEndian);
        Write16(output, 1, bigEndian);          // major version
        Write16(output, 0, bigEndian);          // minor version
        Write64(output, unchecked((ulong)-1L), bigEndian);
        Write32(output, 28, bigEndian);

        // Interface Description Block
        Write32(output, 0x00000001, bigEndian);
        Write32(output, 20, bigEndian);
        Write16(output, linkType, bigEndian);
        Write16(output, 0, bigEndian);          // reserved
        Write32(output, 65535, bigEndian);      // snaplen
        Write32(output, 20, bigEndian);

        ulong timestamp = 1_700_000_000UL * 1_000_000UL;
        foreach (byte[] packet in packets)
        {
            int padded = (packet.Length + 3) & ~3;
            uint blockLength = (uint)(32 + padded);

            Write32(output, 0x00000006, bigEndian);   // Enhanced Packet Block
            Write32(output, blockLength, bigEndian);
            Write32(output, 0, bigEndian);            // interface id
            Write32(output, (uint)(timestamp >> 32), bigEndian);
            Write32(output, (uint)timestamp, bigEndian);
            Write32(output, (uint)packet.Length, bigEndian);
            Write32(output, (uint)packet.Length, bigEndian);
            output.Write(packet);
            output.Write(new byte[padded - packet.Length]);
            Write32(output, blockLength, bigEndian);

            timestamp += 1_000_000UL;
        }

        return output.ToArray();
    }

    // ── Frames ───────────────────────────────────────────────────────

    public static byte[] Udp(string sourceIp, string destIp, ushort sourcePort, ushort destPort, byte[] payload)
    {
        byte[] transport = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(transport, sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(transport.AsSpan(2), destPort);
        BinaryPrimitives.WriteUInt16BigEndian(transport.AsSpan(4), (ushort)transport.Length);
        payload.CopyTo(transport.AsSpan(8));

        return Ethernet(IPv4(sourceIp, destIp, protocol: 17, transport));
    }

    public static byte[] Tcp(
        string sourceIp, string destIp, ushort sourcePort, ushort destPort, byte flags, byte[] payload)
    {
        byte[] transport = new byte[20 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(transport, sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(transport.AsSpan(2), destPort);
        transport[12] = 5 << 4; // data offset = 5 words
        transport[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(transport.AsSpan(14), 65535);
        payload.CopyTo(transport.AsSpan(20));

        return Ethernet(IPv4(sourceIp, destIp, protocol: 6, transport));
    }

    private static byte[] IPv4(string sourceIp, string destIp, byte protocol, byte[] transport)
    {
        byte[] header = new byte[20 + transport.Length];
        header[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), (ushort)header.Length);
        header[8] = 64;          // TTL
        header[9] = protocol;
        IPAddress.Parse(sourceIp).GetAddressBytes().CopyTo(header.AsSpan(12));
        IPAddress.Parse(destIp).GetAddressBytes().CopyTo(header.AsSpan(16));
        transport.CopyTo(header.AsSpan(20));
        return header;
    }

    private static byte[] Ethernet(byte[] ipPacket)
    {
        byte[] frame = new byte[14 + ipPacket.Length];
        for (int i = 0; i < 6; i++) frame[i] = (byte)(0xA0 + i);
        for (int i = 0; i < 6; i++) frame[6 + i] = (byte)(0xB0 + i);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(12), 0x0800);
        ipPacket.CopyTo(frame.AsSpan(14));
        return frame;
    }

    // ── DNS ──────────────────────────────────────────────────────────

    public static byte[] EncodeName(string name)
    {
        var output = new MemoryStream();
        foreach (string label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            output.WriteByte((byte)label.Length);
            output.Write(Encoding.ASCII.GetBytes(label));
        }
        output.WriteByte(0);
        return output.ToArray();
    }

    public static byte[] DnsQuery(ushort transactionId, string name)
    {
        var output = new MemoryStream();
        Write16(output, transactionId, bigEndian: true);
        Write16(output, 0x0100, bigEndian: true);   // standard query, recursion desired
        Write16(output, 1, bigEndian: true);        // qdcount
        Write16(output, 0, bigEndian: true);        // ancount
        Write16(output, 0, bigEndian: true);        // nscount
        Write16(output, 0, bigEndian: true);        // arcount

        output.Write(EncodeName(name));
        Write16(output, 1, bigEndian: true);        // QTYPE A
        Write16(output, 1, bigEndian: true);        // QCLASS IN
        return output.ToArray();
    }

    /// <summary>
    /// Builds a DNS response whose CNAME record declares more rdata than the encoded name
    /// occupies. A parser that derives the next offset from the parsed name instead of the
    /// declared rdata length desynchronises and misreads every following record.
    /// </summary>
    public static byte[] DnsResponseWithOversizedCname(
        ushort transactionId, string queryName, string cname, string address, int cnamePadding)
    {
        var output = new MemoryStream();
        Write16(output, transactionId, bigEndian: true);
        Write16(output, 0x8180, bigEndian: true);   // response, no error
        Write16(output, 1, bigEndian: true);        // qdcount
        Write16(output, 2, bigEndian: true);        // ancount
        Write16(output, 0, bigEndian: true);
        Write16(output, 0, bigEndian: true);

        output.Write(EncodeName(queryName));
        Write16(output, 1, bigEndian: true);
        Write16(output, 1, bigEndian: true);

        // Answer 1: CNAME with padded rdata
        byte[] encodedCname = EncodeName(cname);
        output.Write(EncodeName(queryName));
        Write16(output, 5, bigEndian: true);        // TYPE CNAME
        Write16(output, 1, bigEndian: true);        // CLASS IN
        Write32(output, 300, bigEndian: true);      // TTL
        Write16(output, (ushort)(encodedCname.Length + cnamePadding), bigEndian: true);
        output.Write(encodedCname);
        output.Write(new byte[cnamePadding]);

        // Answer 2: A record that only parses if answer 1 resynchronised correctly
        output.Write(EncodeName(cname));
        Write16(output, 1, bigEndian: true);        // TYPE A
        Write16(output, 1, bigEndian: true);        // CLASS IN
        Write32(output, 300, bigEndian: true);      // TTL
        Write16(output, 4, bigEndian: true);        // RDLENGTH
        output.Write(IPAddress.Parse(address).GetAddressBytes());

        return output.ToArray();
    }

    public static byte[] DnsResponseWithAddress(
        ushort transactionId, string queryName, string address, ushort responseCode = 0)
    {
        var output = new MemoryStream();
        Write16(output, transactionId, bigEndian: true);
        Write16(output, (ushort)(0x8180 | responseCode), bigEndian: true);
        Write16(output, 1, bigEndian: true);
        Write16(output, responseCode == 0 ? (ushort)1 : (ushort)0, bigEndian: true);
        Write16(output, 0, bigEndian: true);
        Write16(output, 0, bigEndian: true);

        output.Write(EncodeName(queryName));
        Write16(output, 1, bigEndian: true);
        Write16(output, 1, bigEndian: true);

        if (responseCode == 0)
        {
            output.Write([0xC0, 0x0C]);             // pointer to the question name
            Write16(output, 1, bigEndian: true);
            Write16(output, 1, bigEndian: true);
            Write32(output, 300, bigEndian: true);
            Write16(output, 4, bigEndian: true);
            output.Write(IPAddress.Parse(address).GetAddressBytes());
        }

        return output.ToArray();
    }

    // ── TLS ──────────────────────────────────────────────────────────

    public static byte[] TlsClientHello(string serverName, params ushort[] cipherSuites)
    {
        var extensions = new MemoryStream();

        byte[] hostBytes = Encoding.ASCII.GetBytes(serverName);
        Write16(extensions, 0, bigEndian: true);                            // extension: server_name
        Write16(extensions, (ushort)(hostBytes.Length + 5), bigEndian: true);
        Write16(extensions, (ushort)(hostBytes.Length + 3), bigEndian: true); // server_name_list length
        extensions.WriteByte(0);                                            // host_name
        Write16(extensions, (ushort)hostBytes.Length, bigEndian: true);
        extensions.Write(hostBytes);

        Write16(extensions, 43, bigEndian: true);                           // supported_versions
        Write16(extensions, 5, bigEndian: true);
        extensions.WriteByte(4);
        Write16(extensions, 0x0304, bigEndian: true);
        Write16(extensions, 0x0303, bigEndian: true);

        byte[] extensionBytes = extensions.ToArray();

        var body = new MemoryStream();
        Write16(body, 0x0303, bigEndian: true);                             // client version
        body.Write(new byte[32]);                                           // random
        body.WriteByte(0);                                                  // session id length
        Write16(body, (ushort)(cipherSuites.Length * 2), bigEndian: true);
        foreach (ushort suite in cipherSuites)
            Write16(body, suite, bigEndian: true);
        body.WriteByte(1);                                                  // compression methods length
        body.WriteByte(0);                                                  // null compression
        Write16(body, (ushort)extensionBytes.Length, bigEndian: true);
        body.Write(extensionBytes);

        byte[] bodyBytes = body.ToArray();

        var record = new MemoryStream();
        record.WriteByte(22);                                               // handshake
        Write16(record, 0x0301, bigEndian: true);                           // record version
        Write16(record, (ushort)(bodyBytes.Length + 4), bigEndian: true);
        record.WriteByte(1);                                                // ClientHello
        record.WriteByte((byte)(bodyBytes.Length >> 16));
        record.WriteByte((byte)(bodyBytes.Length >> 8));
        record.WriteByte((byte)bodyBytes.Length);
        record.Write(bodyBytes);

        return record.ToArray();
    }

    public static byte[] TlsAlert(byte level, byte description) =>
        [21, 0x03, 0x03, 0x00, 0x02, level, description];

    // ── Primitive writers ────────────────────────────────────────────

    private static void Write16(Stream stream, ushort value, bool bigEndian)
    {
        Span<byte> buffer = stackalloc byte[2];
        if (bigEndian) BinaryPrimitives.WriteUInt16BigEndian(buffer, value);
        else BinaryPrimitives.WriteUInt16LittleEndian(buffer, value);
        stream.Write(buffer);
    }

    private static void Write32(Stream stream, uint value, bool bigEndian)
    {
        Span<byte> buffer = stackalloc byte[4];
        if (bigEndian) BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        else BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        stream.Write(buffer);
    }

    private static void Write64(Stream stream, ulong value, bool bigEndian)
    {
        Span<byte> buffer = stackalloc byte[8];
        if (bigEndian) BinaryPrimitives.WriteUInt64BigEndian(buffer, value);
        else BinaryPrimitives.WriteUInt64LittleEndian(buffer, value);
        stream.Write(buffer);
    }

    /// <summary>Writes bytes to a temp file and returns a handle that deletes it on dispose.</summary>
    public static TempCapture ToTempFile(byte[] contents, string extension = ".pcap")
    {
        string path = Path.Combine(Path.GetTempPath(), $"amatest_{Guid.NewGuid():N}{extension}");
        File.WriteAllBytes(path, contents);
        return new TempCapture(path);
    }
}

internal sealed class TempCapture(string path) : IDisposable
{
    public string Path { get; } = path;

    public void Dispose()
    {
        try { if (File.Exists(Path)) File.Delete(Path); }
        catch (IOException) { /* best effort */ }
    }
}
