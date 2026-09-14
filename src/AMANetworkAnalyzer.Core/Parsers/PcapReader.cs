namespace AMANetworkAnalyzer.Parsers;

using System.Buffers.Binary;
using AMANetworkAnalyzer.Models;

/// <summary>
/// Reads pcap (classic) and pcapng capture files using streaming I/O.
/// Pure managed code — no native dependencies.
/// </summary>
public static class PcapReader
{
    /// <summary>Refuse files larger than this to bound worst-case work.</summary>
    public const long MaxFileSize = 2L * 1024 * 1024 * 1024;

    private const int MaxPacketSize = 65535;
    private const int MaxBlockSize = 16 * 1024 * 1024;
    private const int MaxWarnings = 100;

    private const uint PcapMagicMicros = 0xA1B2C3D4;
    private const uint PcapMagicMicrosSwapped = 0xD4C3B2A1;
    private const uint PcapMagicNanos = 0xA1B23C4D;
    private const uint PcapMagicNanosSwapped = 0x4D3CB2A1;
    private const uint PcapngSectionHeader = 0x0A0D0D0A;
    private const uint PcapngByteOrderMagic = 0x1A2B3C4D;
    private const uint PcapngByteOrderMagicSwapped = 0x4D3C2B1A;

    private static readonly DateTime UnixEpoch = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>True if the value identifies a supported capture format.</summary>
    public static bool IsKnownMagic(uint magic) => magic
        is PcapMagicMicros or PcapMagicMicrosSwapped
        or PcapMagicNanos or PcapMagicNanosSwapped
        or PcapngSectionHeader;

    /// <summary>Read packets from a pcap/pcapng file. Returns packets and any parse warnings.</summary>
    public static (List<RawPacket> Packets, List<string> Warnings) ReadFile(string filePath)
    {
        var warnings = new List<string>();
        var packets = new List<RawPacket>();
        foreach (var packet in Stream(filePath, warnings))
            packets.Add(packet);
        return (packets, warnings);
    }

    /// <summary>
    /// Reads and dissects a capture in a single pass, retaining only the parsed result.
    /// Preferred over <see cref="ReadFile"/> followed by a separate parse, which would
    /// hold the raw and parsed representations of the whole capture at the same time.
    /// </summary>
    public static (List<ParsedPacket> Packets, List<string> Warnings) ReadAndParse(
        string filePath, CancellationToken cancellationToken = default)
    {
        var warnings = new List<string>();
        var parsed = new List<ParsedPacket>();

        int index = 0;
        foreach (var raw in Stream(filePath, warnings))
        {
            if ((index & 0x3FF) == 0)
                cancellationToken.ThrowIfCancellationRequested();

            parsed.Add(PacketParser.Parse(raw, index));
            index++;
        }

        return (parsed, warnings);
    }

    /// <summary>
    /// Lazily yields packets from a capture file. Warnings are appended to
    /// <paramref name="warnings"/> as they are encountered.
    /// </summary>
    public static IEnumerable<RawPacket> Stream(string filePath, List<string> warnings)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        ArgumentNullException.ThrowIfNull(warnings);

        var fileInfo = new FileInfo(filePath);
        if (!fileInfo.Exists)
            throw new FileNotFoundException("Capture file not found.", filePath);
        if (fileInfo.Length > MaxFileSize)
            throw new InvalidDataException($"File exceeds the {MaxFileSize / (1024 * 1024)} MB safety limit.");
        if (fileInfo.Length < 4)
            throw new InvalidDataException("File is too small to be a valid capture.");

        return StreamCore(filePath, warnings);
    }

    private static IEnumerable<RawPacket> StreamCore(string filePath, List<string> warnings)
    {
        using var stream = new FileStream(
            filePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 65536, FileOptions.SequentialScan);

        byte[] magicBuffer = new byte[4];
        if (ReadFully(stream, magicBuffer, 0, 4) < 4)
            throw new InvalidDataException("Cannot read file magic number.");

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(magicBuffer);
        stream.Position = 0;

        IEnumerable<RawPacket> packets = magic switch
        {
            PcapMagicMicros => ReadPcapStream(stream, bigEndian: false, nanoseconds: false, warnings),
            PcapMagicMicrosSwapped => ReadPcapStream(stream, bigEndian: true, nanoseconds: false, warnings),
            PcapMagicNanos => ReadPcapStream(stream, bigEndian: false, nanoseconds: true, warnings),
            PcapMagicNanosSwapped => ReadPcapStream(stream, bigEndian: true, nanoseconds: true, warnings),
            PcapngSectionHeader => ReadPcapngStream(stream, warnings),
            _ => throw new InvalidDataException(
                $"Unsupported file format (magic: 0x{magic:X8}). Expected .pcap or .pcapng.")
        };

        foreach (var packet in packets)
            yield return packet;
    }

    // ── pcap classic (streaming) ─────────────────────────────────

    private static IEnumerable<RawPacket> ReadPcapStream(
        FileStream stream, bool bigEndian, bool nanoseconds, List<string> warnings)
    {
        byte[] header = new byte[24];
        if (ReadFully(stream, header, 0, 24) < 24)
            throw new InvalidDataException("Pcap global header is incomplete.");

        var linkType = (LinkLayerType)Read32(header, 20, bigEndian);

        byte[] packetHeader = new byte[16];
        int truncatedCount = 0;

        while (true)
        {
            long headerOffset = stream.Position;
            int headerRead = ReadFully(stream, packetHeader, 0, 16);
            if (headerRead == 0) break;
            if (headerRead < 16)
            {
                truncatedCount++;
                AddWarning(warnings, $"Pcap file truncated — incomplete packet header at offset {headerOffset}.");
                break;
            }

            uint timestampSeconds = Read32(packetHeader, 0, bigEndian);
            uint timestampFraction = Read32(packetHeader, 4, bigEndian);
            uint capturedLength = Read32(packetHeader, 8, bigEndian);
            uint originalLength = Read32(packetHeader, 12, bigEndian);

            if (capturedLength > MaxPacketSize)
            {
                AddWarning(warnings,
                    $"Packet at offset {headerOffset} declares an unrealistic captured length ({capturedLength}). Stopping parse.");
                break;
            }

            byte[] packetData = new byte[capturedLength];
            int dataRead = ReadFully(stream, packetData, 0, (int)capturedLength);
            if (dataRead < (int)capturedLength)
            {
                truncatedCount++;
                AddWarning(warnings, $"Pcap file truncated — packet data incomplete ({dataRead}/{capturedLength} bytes).");
                if (dataRead <= 40) break;
                Array.Resize(ref packetData, dataRead);
            }

            if (originalLength > capturedLength) truncatedCount++;

            yield return new RawPacket(
                ToTimestamp(timestampSeconds, timestampFraction, nanoseconds), packetData, linkType);
        }

        if (truncatedCount > 0)
            AddWarning(warnings, $"Total packets with truncation indicators: {truncatedCount}.");
    }

    private static DateTime ToTimestamp(uint seconds, uint fraction, bool nanoseconds)
    {
        long microseconds = nanoseconds ? fraction / 1000 : fraction;
        return UnixEpoch.AddSeconds(seconds).AddTicks(microseconds * 10);
    }

    // ── pcapng (streaming) ───────────────────────────────────────

    private static IEnumerable<RawPacket> ReadPcapngStream(FileStream stream, List<string> warnings)
    {
        var interfaces = new List<PcapngInterface>();
        bool bigEndian = false;
        int truncatedBlocks = 0;

        byte[] blockHeader = new byte[8];
        byte[] byteOrderMagic = new byte[4];
        byte[] trailer = new byte[4];

        while (true)
        {
            long blockOffset = stream.Position;
            int headerRead = ReadFully(stream, blockHeader, 0, 8);
            if (headerRead == 0) break;
            if (headerRead < 8)
            {
                truncatedBlocks++;
                AddWarning(warnings, "Pcapng file truncated — incomplete block header.");
                break;
            }

            // The Section Header Block type is byte-order independent by design, so it
            // identifies itself before the section's endianness is known.
            bool isSectionHeader =
                BinaryPrimitives.ReadUInt32LittleEndian(blockHeader) == PcapngSectionHeader;
            int byteOrderMagicConsumed = 0;

            if (isSectionHeader)
            {
                if (ReadFully(stream, byteOrderMagic, 0, 4) < 4)
                {
                    AddWarning(warnings, "Pcapng file truncated — incomplete section header.");
                    break;
                }
                byteOrderMagicConsumed = 4;

                uint bom = BinaryPrimitives.ReadUInt32LittleEndian(byteOrderMagic);
                if (bom == PcapngByteOrderMagicSwapped)
                {
                    bigEndian = true;
                }
                else if (bom == PcapngByteOrderMagic)
                {
                    bigEndian = false;
                }
                else
                {
                    AddWarning(warnings, $"Invalid pcapng byte-order magic (0x{bom:X8}). Stopping parse.");
                    break;
                }

                interfaces.Clear();
            }

            // Every other field, including the type of non-section blocks, follows the
            // section's byte order.
            uint blockType = isSectionHeader ? PcapngSectionHeader : Read32(blockHeader, 0, bigEndian);
            uint blockLength = Read32(blockHeader, 4, bigEndian);

            if (blockLength < 12 || blockLength % 4 != 0)
            {
                AddWarning(warnings, $"Invalid pcapng block length ({blockLength}) at offset {blockOffset}. Stopping parse.");
                break;
            }
            if (blockLength > MaxBlockSize)
            {
                AddWarning(warnings, $"Pcapng block length {blockLength} exceeds the {MaxBlockSize} byte maximum. Stopping parse.");
                break;
            }

            int bodyLength = (int)blockLength - 12 - byteOrderMagicConsumed;
            if (bodyLength < 0)
            {
                AddWarning(warnings, $"Malformed pcapng block at offset {blockOffset}. Stopping parse.");
                break;
            }

            byte[] body = new byte[bodyLength];
            if (ReadFully(stream, body, 0, bodyLength) < bodyLength)
            {
                truncatedBlocks++;
                AddWarning(warnings, "Pcapng file truncated — incomplete block body.");
                break;
            }

            if (ReadFully(stream, trailer, 0, 4) < 4)
            {
                truncatedBlocks++;
                AddWarning(warnings, "Pcapng file truncated — missing block trailer.");
                break;
            }

            switch (blockType)
            {
                case 0x00000001: // Interface Description Block
                    if (bodyLength >= 8)
                        interfaces.Add(ReadInterfaceDescription(body, bodyLength, bigEndian));
                    break;

                case 0x00000006: // Enhanced Packet Block
                {
                    if (bodyLength < 20) break;

                    uint interfaceId = Read32(body, 0, bigEndian);
                    uint timestampHigh = Read32(body, 4, bigEndian);
                    uint timestampLow = Read32(body, 8, bigEndian);
                    uint capturedLength = Read32(body, 12, bigEndian);

                    if (capturedLength > MaxPacketSize || 20 + (long)capturedLength > bodyLength)
                    {
                        truncatedBlocks++;
                        break;
                    }

                    var iface = interfaceId < interfaces.Count
                        ? interfaces[(int)interfaceId]
                        : interfaces.Count > 0 ? interfaces[0] : null;

                    byte[] packetData = new byte[capturedLength];
                    Buffer.BlockCopy(body, 20, packetData, 0, (int)capturedLength);

                    long rawTimestamp = ((long)timestampHigh << 32) | timestampLow;
                    yield return new RawPacket(
                        ConvertPcapngTimestamp(rawTimestamp, iface?.TimestampResolution ?? 6),
                        packetData,
                        iface?.LinkType ?? LinkLayerType.Ethernet);
                    break;
                }

                case 0x00000003: // Simple Packet Block
                {
                    if (bodyLength < 4 || interfaces.Count == 0) break;

                    uint originalLength = Read32(body, 0, bigEndian);
                    uint capturedLength = Math.Min(originalLength, interfaces[0].SnapLength);
                    if (capturedLength > MaxPacketSize || 4 + (long)capturedLength > bodyLength) break;

                    byte[] packetData = new byte[capturedLength];
                    Buffer.BlockCopy(body, 4, packetData, 0, (int)capturedLength);

                    yield return new RawPacket(DateTime.MinValue, packetData, interfaces[0].LinkType);
                    break;
                }
            }
        }

        if (truncatedBlocks > 0)
            AddWarning(warnings, $"Pcapng file has {truncatedBlocks} truncated or invalid blocks.");
    }

    private static PcapngInterface ReadInterfaceDescription(byte[] body, int bodyLength, bool bigEndian)
    {
        ushort linkType = Read16(body, 0, bigEndian);
        uint snapLength = Read32(body, 4, bigEndian);
        byte timestampResolution = 6;

        int offset = 8;
        while (offset + 4 <= bodyLength)
        {
            ushort optionCode = Read16(body, offset, bigEndian);
            ushort optionLength = Read16(body, offset + 2, bigEndian);
            if (optionCode == 0) break;

            long valueEnd = (long)offset + 4 + optionLength;
            if (valueEnd > bodyLength) break;

            if (optionCode == 9 && optionLength >= 1)
                timestampResolution = body[offset + 4];

            offset += 4 + ((optionLength + 3) & ~3);
        }

        return new PcapngInterface((LinkLayerType)linkType, snapLength, timestampResolution);
    }

    private static DateTime ConvertPcapngTimestamp(long rawTimestamp, byte resolution)
    {
        if (rawTimestamp < 0) return DateTime.MinValue;

        double divisor = (resolution & 0x80) != 0
            ? Math.Pow(2, resolution & 0x7F)
            : Math.Pow(10, resolution);

        if (divisor <= 0 || double.IsInfinity(divisor)) return DateTime.MinValue;

        double seconds = rawTimestamp / divisor;

        // Reject anything outside 1970..2100 rather than surfacing a nonsense date.
        if (seconds is < 0 or > 4_102_444_800d) return DateTime.MinValue;

        return UnixEpoch.AddTicks((long)(seconds * TimeSpan.TicksPerSecond));
    }

    // ── Helpers ──────────────────────────────────────────────────

    private static void AddWarning(List<string> warnings, string message)
    {
        if (warnings.Count < MaxWarnings)
            warnings.Add(message);
        else if (warnings.Count == MaxWarnings)
            warnings.Add("Additional parser warnings suppressed.");
    }

    private static int ReadFully(Stream stream, byte[] buffer, int offset, int count)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            int bytesRead = stream.Read(buffer, offset + totalRead, count - totalRead);
            if (bytesRead == 0) break;
            totalRead += bytesRead;
        }
        return totalRead;
    }

    private static ushort Read16(byte[] data, int offset, bool bigEndian)
    {
        var span = data.AsSpan(offset, 2);
        return bigEndian
            ? BinaryPrimitives.ReadUInt16BigEndian(span)
            : BinaryPrimitives.ReadUInt16LittleEndian(span);
    }

    private static uint Read32(byte[] data, int offset, bool bigEndian)
    {
        var span = data.AsSpan(offset, 4);
        return bigEndian
            ? BinaryPrimitives.ReadUInt32BigEndian(span)
            : BinaryPrimitives.ReadUInt32LittleEndian(span);
    }

    private sealed record PcapngInterface(LinkLayerType LinkType, uint SnapLength, byte TimestampResolution);
}
