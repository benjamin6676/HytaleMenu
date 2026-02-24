using System.Net;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Writes a packet list to a standard libpcap v2.4 .pcap file.
/// The output can be opened directly in Wireshark, tcpdump, or any other
/// pcap-compatible analyser.
///
/// Link-layer type: LINKTYPE_RAW (101) — raw UDP/IP payload without Ethernet header.
/// </summary>
public static class PcapWriter
{
    // ── libpcap global header constants ────────────────────────────────────
    private const uint Magic        = 0xa1b2c3d4;  // little-endian pcap magic
    private const ushort VerMajor   = 2;
    private const ushort VerMinor   = 4;
    private const int  ThisZone     = 0;           // GMT
    private const uint SigFigs      = 0;
    private const uint SnapLen      = 65535;
    private const uint Network      = 101;          // LINKTYPE_RAW (IP)

    // Fake IPs used to give Wireshark something meaningful to display
    private static readonly byte[] ClientIp = { 10, 0, 0, 1 };
    private static readonly byte[] ServerIpFallback = { 10, 0, 0, 2 };

    // ── Public API ─────────────────────────────────────────────────────────

    /// <summary>
    /// Write <paramref name="packets"/> to <paramref name="path"/> in libpcap format.
    /// Returns number of packets written.
    /// </summary>
    public static int Write(string path, IEnumerable<CapturedPacket> packets,
                            string? serverIp = null)
    {
        byte[] srvIpBytes = ServerIpFallback;
        if (serverIp != null && IPAddress.TryParse(serverIp, out IPAddress? addr))
            srvIpBytes = addr.GetAddressBytes();

        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
        using var bw = new BinaryWriter(fs);

        WriteGlobalHeader(bw);

        int written = 0;
        foreach (var pkt in packets)
        {
            byte[] udpPayload = pkt.RawBytes;
            bool   cs         = pkt.Direction == PacketDirection.ClientToServer;

            byte[] src  = cs ? ClientIp    : srvIpBytes;
            byte[] dst  = cs ? srvIpBytes  : ClientIp;
            ushort sport = cs ? (ushort)49152 : (ushort)5520;
            ushort dport = cs ? (ushort)5520  : (ushort)49152;

            byte[] ipPacket = BuildIpUdpPacket(src, dst, sport, dport, udpPayload);
            WritePacketHeader(bw, pkt.Timestamp, ipPacket.Length);
            bw.Write(ipPacket);
            written++;
        }

        return written;
    }

    // ── pcap global header ─────────────────────────────────────────────────

    private static void WriteGlobalHeader(BinaryWriter bw)
    {
        bw.Write(Magic);
        bw.Write(VerMajor);
        bw.Write(VerMinor);
        bw.Write(ThisZone);
        bw.Write(SigFigs);
        bw.Write(SnapLen);
        bw.Write(Network);
    }

    // ── per-packet record header ───────────────────────────────────────────

    private static void WritePacketHeader(BinaryWriter bw, DateTime ts, int captureLen)
    {
        var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        long totalUs = (long)(ts.ToUniversalTime() - epoch).TotalMicroseconds;
        uint tsSec   = (uint)(totalUs / 1_000_000);
        uint tsUsec  = (uint)(totalUs % 1_000_000);

        bw.Write(tsSec);
        bw.Write(tsUsec);
        bw.Write((uint)captureLen);  // captured length
        bw.Write((uint)captureLen);  // original length
    }

    // ── IP + UDP frame builder ─────────────────────────────────────────────

    private static byte[] BuildIpUdpPacket(byte[] srcIp, byte[] dstIp,
                                            ushort srcPort, ushort dstPort,
                                            byte[] payload)
    {
        // UDP header (8 bytes)
        ushort udpLen = (ushort)(8 + payload.Length);
        byte[] udp = new byte[udpLen];
        udp[0] = (byte)(srcPort >> 8);  udp[1] = (byte)srcPort;
        udp[2] = (byte)(dstPort >> 8);  udp[3] = (byte)dstPort;
        udp[4] = (byte)(udpLen   >> 8); udp[5] = (byte)udpLen;
        udp[6] = 0; udp[7] = 0;  // checksum (disabled)
        Array.Copy(payload, 0, udp, 8, payload.Length);

        // IPv4 header (20 bytes)
        ushort ipTotalLen = (ushort)(20 + udp.Length);
        byte[] ip = new byte[20];
        ip[0]  = 0x45;  // version=4, IHL=5
        ip[1]  = 0;     // DSCP/ECN
        ip[2]  = (byte)(ipTotalLen >> 8);
        ip[3]  = (byte)ipTotalLen;
        ip[4]  = 0; ip[5] = 0;  // ID
        ip[6]  = 0x40;  // DF flag, no frag offset
        ip[7]  = 0;
        ip[8]  = 64;    // TTL
        ip[9]  = 17;    // protocol = UDP
        ip[10] = 0; ip[11] = 0;  // checksum (zero = not computed)
        Array.Copy(srcIp, 0, ip, 12, 4);
        Array.Copy(dstIp, 0, ip, 16, 4);

        // Combine IP + UDP
        byte[] result = new byte[ip.Length + udp.Length];
        Array.Copy(ip,  0, result, 0,         ip.Length);
        Array.Copy(udp, 0, result, ip.Length, udp.Length);
        return result;
    }
}
