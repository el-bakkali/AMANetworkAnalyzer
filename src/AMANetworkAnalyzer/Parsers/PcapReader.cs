namespace AMANetworkAnalyzer.Parsers;

using System.Buffers.Binary;
using AMANetworkAnalyzer.Models;

/// <summary>
/// Reads pcap (classic) and pcapng capture files using streaming I/O.
/// Pure managed code — no native dependencies.
/// </summary>
public static class PcapReader
{
    private const long MaxFileSize = 2L * 1024 * 1024 * 1024; // 2 GB safety limit
    private const int MaxPacketSize = 65535;

    /// <summary>Read packets from a pcap/pcapng file. Returns packets and any parse warnings.</summary>
    public static (List<RawPacket> Packets, List<string> Warnings) ReadFile(string filePath)
    {
        var warnings = new List<string>();

        var fileInfo = new FileInfo(filePath);
        if (fileInfo.Length > MaxFileSize)
            throw new InvalidDataException($"File exceeds {MaxFileSize / (1024 * 1024)} MB safety limit.");
        if (fileInfo.Length < 4)
            throw new InvalidDataException("File is too small to be a valid capture.");

        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 65536);

        byte[] magicBuf = new byte[4];
        if (stream.Read(magicBuf, 0, 4) < 4)
            throw new InvalidDataException("Cannot read file magic number.");

        uint magic = BitConverter.ToUInt32(magicBuf, 0);
        stream.Position = 0;

        var packets = magic switch
        {
            0xa1b2c3d4 => ReadPcapStream(stream, swapped: false, nsResolution: false, warnings),
            0xd4c3b2a1 => ReadPcapStream(stream, swapped: true, nsResolution: false, warnings),
            0xa1b23c4d => ReadPcapStream(stream, swapped: false, nsResolution: true, warnings),
            0x4d3cb2a1 => ReadPcapStream(stream, swapped: true, nsResolution: true, warnings),
            0x0a0d0d0a => ReadPcapngStream(stream, warnings),
            _ => throw new InvalidDataException(
                $"Unsupported file format (magic: 0x{magic:X8}). Expected .pcap or .pcapng.")
        };

        return (packets, warnings);
    }

    // ── pcap classic (streaming) ─────────────────────────────────

    private static List<RawPacket> ReadPcapStream(FileStream stream, bool swapped, bool nsResolution, List<string> warnings)
    {
        byte[] header = new byte[24];
        if (stream.Read(header, 0, 24) < 24)
            throw new InvalidDataException("Pcap global header is incomplete.");

        uint network = Read32(header, 20, swapped);
        var linkType = (LinkLayerType)network;

        var packets = new List<RawPacket>();
        byte[] pktHeader = new byte[16];
        int truncatedCount = 0;

        while (true)
        {
            int bytesRead = ReadFully(stream, pktHeader, 0, 16);
            if (bytesRead == 0) break;
            if (bytesRead < 16)
            {
                truncatedCount++;
                warnings.Add($"Pcap file truncated — incomplete packet header at offset {stream.Position - bytesRead}.");
                break;
            }

            uint tsSec = Read32(pktHeader, 0, swapped);
            uint tsFrac = Read32(pktHeader, 4, swapped);
            uint capturedLen = Read32(pktHeader, 8, swapped);
            uint originalLen = Read32(pktHeader, 12, swapped);

            if (capturedLen > MaxPacketSize)
            {
                warnings.Add($"Packet at offset {stream.Position - 16} has unrealistic captured length ({capturedLen}). Stopping parse.");
                break;
            }

            byte[] pktData = new byte[capturedLen];
            int pktBytesRead = ReadFully(stream, pktData, 0, (int)capturedLen);
            if (pktBytesRead < (int)capturedLen)
            {
                truncatedCount++;
                warnings.Add($"Pcap file truncated — packet data incomplete ({pktBytesRead}/{capturedLen} bytes).");
                if (pktBytesRead > 40)
                {
                    byte[] partial = new byte[pktBytesRead];
                    Buffer.BlockCopy(pktData, 0, partial, 0, pktBytesRead);
                    pktData = partial;
                }
                else break;
            }

            if (originalLen > capturedLen) truncatedCount++;

            long microseconds = nsResolution ? tsFrac / 1000 : tsFrac;
            var ts = DateTimeOffset.FromUnixTimeSeconds(tsSec).UtcDateTime
                         .AddTicks(microseconds * 10);

            packets.Add(new RawPacket(ts, pktData, linkType));
        }

        if (truncatedCount > 0)
            warnings.Add($"Total packets with truncation indicators: {truncatedCount}.");

        return packets;
    }

    // ── pcapng (streaming) ───────────────────────────────────────

    private static List<RawPacket> ReadPcapngStream(FileStream stream, List<string> warnings)
    {
        var packets = new List<RawPacket>();
        var interfaces = new List<PcapngInterface>();
        bool swapped = false;
        int truncatedBlocks = 0;
        byte[] blockHeaderBuf = new byte[8];

        while (true)
        {
            int headerRead = ReadFully(stream, blockHeaderBuf, 0, 8);
            if (headerRead == 0) break;
            if (headerRead < 8)
            {
                warnings.Add("Pcapng file truncated — incomplete block header.");
                truncatedBlocks++;
                break;
            }

            uint blockType = Read32(blockHeaderBuf, 0, swapped);
            uint blockLen = Read32(blockHeaderBuf, 4, swapped);

            if (blockLen < 12)
            {
                warnings.Add($"Invalid pcapng block length ({blockLen}). Stopping parse.");
                break;
            }

            int bodyLen = (int)blockLen - 12;
            if (bodyLen < 0 || blockLen > 16 * 1024 * 1024)
            {
                warnings.Add($"Block length {blockLen} exceeds maximum. Stopping parse.");
                break;
            }

            byte[] body = new byte[bodyLen];
            int bodyRead = ReadFully(stream, body, 0, bodyLen);
            if (bodyRead < bodyLen)
            {
                warnings.Add("Pcapng file truncated — incomplete block body.");
                truncatedBlocks++;
                break;
            }

            byte[] trailBuf = new byte[4];
            ReadFully(stream, trailBuf, 0, 4);

            switch (blockType)
            {
                case 0x0a0d0d0a: // Section Header Block
                    if (bodyLen >= 4)
                    {
                        uint bom = BitConverter.ToUInt32(body, 0);
                        swapped = bom == 0x4d3c2b1a;
                        blockLen = Read32(blockHeaderBuf, 4, swapped);
                    }
                    interfaces.Clear();
                    break;

                case 0x00000001: // Interface Description Block
                    if (bodyLen >= 8)
                    {
                        ushort lt = Read16(body, 0, swapped);
                        uint snap = Read32(body, 4, swapped);
                        byte tsResol = 6;
                        int optOff = 8;
                        while (optOff + 4 <= bodyLen)
                        {
                            ushort optCode = Read16(body, optOff, swapped);
                            ushort optLen = Read16(body, optOff + 2, swapped);
                            if (optCode == 0) break;
                            int optValueEnd = optOff + 4 + optLen;
                            if (optValueEnd > bodyLen) break;
                            if (optCode == 9 && optLen >= 1)
                                tsResol = body[optOff + 4];
                            optOff += 4 + ((optLen + 3) & ~3);
                            if (optOff < 0) break;
                        }
                        interfaces.Add(new PcapngInterface((LinkLayerType)lt, snap, tsResol));
                    }
                    break;

                case 0x00000006: // Enhanced Packet Block
                    if (bodyLen >= 20)
                    {
                        uint ifId = Read32(body, 0, swapped);
                        uint tsHigh = Read32(body, 4, swapped);
                        uint tsLow = Read32(body, 8, swapped);
                        uint capLen = Read32(body, 12, swapped);
                        int pktStart = 20;

                        if (capLen > MaxPacketSize || pktStart + (int)capLen > bodyLen)
                        {
                            truncatedBlocks++;
                            break;
                        }

                        byte[] pktData = new byte[capLen];
                        Buffer.BlockCopy(body, pktStart, pktData, 0, (int)capLen);

                        var iface = ifId < interfaces.Count ? interfaces[(int)ifId] : interfaces.FirstOrDefault();
                        var linkType = iface?.LinkType ?? LinkLayerType.Ethernet;

                        long tsVal = ((long)tsHigh << 32) | tsLow;
                        DateTime ts = ConvertPcapngTimestamp(tsVal, iface?.TsResol ?? 6);

                        packets.Add(new RawPacket(ts, pktData, linkType));
                    }
                    break;

                case 0x00000003: // Simple Packet Block
                    if (bodyLen >= 4 && interfaces.Count > 0)
                    {
                        uint origLen = Read32(body, 0, swapped);
                        uint capLen = Math.Min(origLen, interfaces[0].SnapLen);
                        if (capLen > MaxPacketSize) break;
                        int pktStart = 4;

                        if (pktStart + (int)capLen <= bodyLen)
                        {
                            byte[] pktData = new byte[capLen];
                            Buffer.BlockCopy(body, pktStart, pktData, 0, (int)capLen);
                            packets.Add(new RawPacket(DateTime.MinValue, pktData, interfaces[0].LinkType));
                        }
                    }
                    break;
            }
        }

        if (truncatedBlocks > 0)
            warnings.Add($"Pcapng file has {truncatedBlocks} truncated or invalid blocks.");

        return packets;
    }

    private static DateTime ConvertPcapngTimestamp(long tsVal, byte tsResol)
    {
        double divisor;
        if ((tsResol & 0x80) != 0)
        {
            int exp = tsResol & 0x7F;
            divisor = Math.Pow(2, exp);
        }
        else
        {
            divisor = Math.Pow(10, tsResol);
        }

        double seconds = tsVal / divisor;
        if (seconds < 0 || seconds > 4_102_444_800)
            return DateTime.UtcNow;

        long ticks = (long)(seconds * TimeSpan.TicksPerSecond);
        var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        try { return epoch.AddTicks(ticks); }
        catch (ArgumentOutOfRangeException) { return DateTime.UtcNow; }
    }

    // ── Stream helpers ───────────────────────────────────────────

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

    // ── Endian helpers ───────────────────────────────────────────

    private static ushort Read16(byte[] data, int offset, bool swapped)
    {
        ushort val = BitConverter.ToUInt16(data, offset);
        return swapped ? BinaryPrimitives.ReverseEndianness(val) : val;
    }

    private static uint Read32(byte[] data, int offset, bool swapped)
    {
        uint val = BitConverter.ToUInt32(data, offset);
        return swapped ? BinaryPrimitives.ReverseEndianness(val) : val;
    }

    private sealed record PcapngInterface(LinkLayerType LinkType, uint SnapLen, byte TsResol);
}
