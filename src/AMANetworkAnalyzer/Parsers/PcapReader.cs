namespace AMANetworkAnalyzer.Parsers;

using System.Buffers.Binary;
using AMANetworkAnalyzer.Models;

/// <summary>
/// Reads pcap (classic) and pcapng capture files.  Pure managed code — no native dependencies.
/// </summary>
public static class PcapReader
{
    public static List<RawPacket> ReadFile(string filePath)
    {
        byte[] fileBytes = File.ReadAllBytes(filePath);
        if (fileBytes.Length < 4)
            throw new InvalidDataException("File is too small to be a valid capture.");

        uint magic = BitConverter.ToUInt32(fileBytes, 0);

        return magic switch
        {
            // pcap classic — native byte order (little-endian on x86)
            0xa1b2c3d4 => ReadPcap(fileBytes, swapped: false, nsResolution: false),
            // pcap classic — swapped byte order
            0xd4c3b2a1 => ReadPcap(fileBytes, swapped: true, nsResolution: false),
            // pcap with nanosecond timestamps — native
            0xa1b23c4d => ReadPcap(fileBytes, swapped: false, nsResolution: true),
            // pcap with nanosecond timestamps — swapped
            0x4d3cb2a1 => ReadPcap(fileBytes, swapped: true, nsResolution: true),
            // pcapng (Section Header Block type)
            0x0a0d0d0a => ReadPcapng(fileBytes),
            _ => throw new InvalidDataException(
                $"Unsupported file format (magic: 0x{magic:X8}). Expected .pcap or .pcapng.")
        };
    }

    // ── pcap classic ─────────────────────────────────────────────────

    private static List<RawPacket> ReadPcap(byte[] data, bool swapped, bool nsResolution)
    {
        if (data.Length < 24)
            throw new InvalidDataException("Pcap global header is incomplete.");

        // Global header: magic(4) + version(4) + thiszone(4) + sigfigs(4) + snaplen(4) + network(4) = 24
        uint snapLen = Read32(data, 16, swapped);
        uint network = Read32(data, 20, swapped);
        var linkType = (LinkLayerType)network;

        var packets = new List<RawPacket>();
        int offset = 24;

        while (offset + 16 <= data.Length)
        {
            uint tsSec = Read32(data, offset, swapped);
            uint tsFrac = Read32(data, offset + 4, swapped);
            uint capturedLen = Read32(data, offset + 8, swapped);
            uint originalLen = Read32(data, offset + 12, swapped);
            offset += 16;

            if (capturedLen > 65535) // max realistic captured packet size
                break;

            if (offset + (int)capturedLen > data.Length)
                break;

            byte[] pktData = new byte[capturedLen];
            Buffer.BlockCopy(data, offset, pktData, 0, (int)capturedLen);
            offset += (int)capturedLen;

            long microseconds = nsResolution ? tsFrac / 1000 : tsFrac;
            var ts = DateTimeOffset.FromUnixTimeSeconds(tsSec).UtcDateTime
                         .AddTicks(microseconds * 10); // 1 µs = 10 ticks

            packets.Add(new RawPacket(ts, pktData, linkType));
        }

        return packets;
    }

    // ── pcapng ───────────────────────────────────────────────────────

    private static List<RawPacket> ReadPcapng(byte[] data)
    {
        var packets = new List<RawPacket>();
        var interfaces = new List<PcapngInterface>();
        bool swapped = false;
        int offset = 0;

        while (offset + 12 <= data.Length)
        {
            uint blockType = Read32(data, offset, swapped);
            uint blockLen = Read32(data, offset + 4, swapped);

            if (blockLen < 12 || offset + (int)blockLen > data.Length)
                break;

            int bodyOffset = offset + 8;
            int bodyLen = (int)blockLen - 12; // minus type(4) + length(4) + trailing length(4)

            switch (blockType)
            {
                case 0x0a0d0d0a: // Section Header Block
                    if (bodyLen >= 4)
                    {
                        uint bom = BitConverter.ToUInt32(data, bodyOffset);
                        swapped = bom == 0x4d3c2b1a;
                        // re-read blockLen with correct endianness
                        blockLen = Read32(data, offset + 4, swapped);
                        bodyLen = (int)blockLen - 12;
                    }
                    interfaces.Clear();
                    break;

                case 0x00000001: // Interface Description Block
                    if (bodyLen >= 8)
                    {
                        ushort lt = Read16(data, bodyOffset, swapped);
                        uint snap = Read32(data, bodyOffset + 4, swapped);
                        // Parse options for if_tsresol (option code 9)
                        byte tsResol = 6; // default: microseconds (10^-6)
                        int optOff = bodyOffset + 8;
                        int optEnd = bodyOffset + bodyLen;
                        while (optOff + 4 <= optEnd)
                        {
                            ushort optCode = Read16(data, optOff, swapped);
                            ushort optLen = Read16(data, optOff + 2, swapped);
                            if (optCode == 0) break; // opt_endofopt
                            if (optCode == 9 && optLen >= 1) // if_tsresol
                                tsResol = data[optOff + 4];
                            optOff += 4 + ((optLen + 3) & ~3); // padded to 4 bytes
                        }
                        interfaces.Add(new PcapngInterface((LinkLayerType)lt, snap, tsResol));
                    }
                    break;

                case 0x00000006: // Enhanced Packet Block
                    if (bodyLen >= 20)
                    {
                        uint ifId = Read32(data, bodyOffset, swapped);
                        uint tsHigh = Read32(data, bodyOffset + 4, swapped);
                        uint tsLow = Read32(data, bodyOffset + 8, swapped);
                        uint capLen = Read32(data, bodyOffset + 12, swapped);
                        // uint origLen = Read32(data, bodyOffset + 16, swapped);
                        int pktStart = bodyOffset + 20;

                        if (capLen > 65535 || pktStart + (int)capLen > data.Length)
                            break;

                        byte[] pktData = new byte[capLen];
                        Buffer.BlockCopy(data, pktStart, pktData, 0, (int)capLen);

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
                        uint origLen = Read32(data, bodyOffset, swapped);
                        uint capLen = Math.Min(origLen, interfaces[0].SnapLen);
                        int pktStart = bodyOffset + 4;

                        if (pktStart + (int)capLen <= data.Length)
                        {
                            byte[] pktData = new byte[capLen];
                            Buffer.BlockCopy(data, pktStart, pktData, 0, (int)capLen);
                            packets.Add(new RawPacket(DateTime.MinValue, pktData, interfaces[0].LinkType));
                        }
                    }
                    break;
            }

            // Advance to next block (block length is padded to 4 bytes in pcapng)
            offset += (int)((blockLen + 3) & ~3u);
            if ((int)blockLen <= 0) break; // prevent infinite loop
        }

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

        // Validate the result is in a reasonable range (1970 to 2100)
        if (seconds < 0 || seconds > 4_102_444_800)
            return DateTime.UtcNow;

        long ticks = (long)(seconds * TimeSpan.TicksPerSecond);
        var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        try
        {
            return epoch.AddTicks(ticks);
        }
        catch (ArgumentOutOfRangeException)
        {
            return DateTime.UtcNow;
        }
    }

    // ── Endian helpers ───────────────────────────────────────────────

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
