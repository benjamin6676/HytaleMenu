using System.IO.Compression;
using System.Text;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Heuristic packet analyser.
///
/// Key methods:
///   Analyse()                - full structural parse of one packet
///   TryDecompress()          - auto-detects and strips zlib/gzip/raw-deflate/LZ4 compression
///   ScanUint32Identifiers()  - Schema Discovery: score every 4-byte window
///   AggregateAcrossPackets() - combine discoveries across many packets
/// </summary>
public static class PacketAnalyser
{
    private static readonly Dictionary<int, string> KnownCsIds = new()
    {
        { 0x01, "Chat / Command" },     { 0x02, "Player Move" },
        { 0x03, "Player Look" },        { 0x04, "Player Action" },
        { 0x05, "Dig / Break Block" },  { 0x06, "Use Item" },
        { 0x07, "Drop Item" },          { 0x08, "Pick Up Item" },
        { 0x09, "Inventory Click" },    { 0x0A, "Inventory Close" },
        { 0x0B, "Trade Accept" },       { 0x0C, "Trade Cancel" },
        { 0x0D, "Container Open" },     { 0x0E, "Container Move Item" },
        { 0x0F, "Container Close" },    { 0x10, "Handshake / Login" },
        { 0x11, "Keep Alive Response" },{ 0x12, "Respawn Request" },
        { 0x20, "Entity Interact" },    { 0x21, "Entity Attack" },
        { 0x22, "Entity Use" },         { 0x2A, "Give Item (suspected)" },
        { 0x30, "Transaction Start" },  { 0x31, "Transaction Commit" },
        { 0x32, "Transaction Rollback" },
    };

    private static readonly Dictionary<int, string> KnownScIds = new()
    {
        { 0x01, "Chat Message" },       { 0x02, "Player Spawn" },
        { 0x03, "Entity Update" },      { 0x04, "Inventory Update" },
        { 0x05, "Item Pickup Confirm" },{ 0x06, "Block Update" },
        { 0x07, "Sound Effect" },       { 0x08, "Particle Effect" },
        { 0x09, "World State" },        { 0x0A, "Time Update" },
        { 0x10, "Login Success" },      { 0x11, "Login Failure" },
        { 0x12, "Keep Alive" },         { 0x20, "Item Spawn (world)" },
        { 0x21, "Item Despawn" },       { 0x22, "Inventory Slot Update" },
        { 0x23, "Health Update" },      { 0x24, "XP Update" },
        { 0x30, "Transaction Ack" },    { 0x31, "Transaction Denied" },
    };

    // ── Full structural analysis ──────────────────────────────────────────

    public static AnalysisResult Analyse(CapturedPacket pkt)
    {
        var result = new AnalysisResult();
        var data   = pkt.RawBytes;

        if (data.Length == 0)
        {
            result.Summary    = "Empty packet";
            result.ActionHint = PacketActionHint.Unknown;
            return result;
        }

        result.PacketId = data[0];
        bool cs = pkt.Direction == PacketDirection.ClientToServer;

        // ── Use OpcodeRegistry for authoritative label ───────────────────
        var opcodeInfo = OpcodeRegistry.Lookup(data[0], pkt.Direction);
        if (opcodeInfo != null)
        {
            result.IdGuess    = opcodeInfo.Name;
            result.ActionHint = GuessAction(data[0], cs);
        }
        else
        {
            var lookup = cs ? KnownCsIds : KnownScIds;
            if (lookup.TryGetValue(data[0], out string? idName))
            {
                result.IdGuess    = idName;
                result.ActionHint = GuessAction(data[0], cs);
            }
            else
            {
                result.IdGuess    = $"Unknown (0x{data[0]:X2})";
                result.ActionHint = PacketActionHint.Unknown;
            }
        }

        result.Fields.Add(new PacketField("Packet ID", $"0x{data[0]:X2}", 0, 1, FieldType.Id));

        if (data.Length >= 3)
        {
            ushort val16 = BitConverter.ToUInt16(data, 1);
            if (val16 == data.Length - 3)
                result.Fields.Add(new PacketField("Length (guessed)", val16.ToString(), 1, 2, FieldType.Length));
            else
                result.Fields.Add(new PacketField("Seq / Type (guessed)", $"0x{val16:X4}", 1, 2, FieldType.Unknown));
        }

        for (int i = 1; i + 4 <= data.Length; i++)
        {
            int v = BitConverter.ToInt32(data, i);
            if (v > 0 && v < 10000)
            {
                string fn = GuessInt32FieldName(v, i, data);
                result.Fields.Add(new PacketField(fn, v.ToString(), i, 4, FieldType.Int32));
                if (v >= 100 && v <= 9999 && i <= 8)
                    result.Guesses.Add(new FieldGuess(fn, v, i, FieldConfidence.Medium));
            }
        }

        foreach (var (offset, str) in FindStrings(data, 3))
        {
            result.Fields.Add(new PacketField($"String @ {offset}", $"\"{str}\"", offset, str.Length, FieldType.String));
            if (IsLikelyCommand(str))
            {
                result.Guesses.Add(new FieldGuess("Command/Chat", 0, offset, FieldConfidence.High, str));
                result.ActionHint = PacketActionHint.Command;
            }
            if (IsLikelyPlayerName(str))
                result.Guesses.Add(new FieldGuess("Player Name", 0, offset, FieldConfidence.Medium, str));

            // Heuristic: some servers or mods use string tokens like "mk_4" or "item_123".
            // If we detect a token with a numeric suffix, assume that suffix may be the
            // numeric ItemID and map it for convenience.
            var parts = str.Split('_');
            if (parts.Length >= 2 && int.TryParse(parts[^1], out int parsedId))
            {
                uint pid = (uint)parsedId;
                if (!result.Fields.Any(f => f.Name == $"Item ID? ({pid})"))
                    result.Fields.Add(new PacketField($"Item ID? ({pid})", pid.ToString(), offset, 4, FieldType.Int32));
            }
        }

        int floatCount = 0;
        for (int i = 1; i + 4 <= data.Length && floatCount < 6; i += 4)
        {
            float f = BitConverter.ToSingle(data, i);
            if (IsReasonableCoord(f))
            {
                string axis = floatCount switch { 0 => "X", 1 => "Y", 2 => "Z", _ => $"F{floatCount}" };
                result.Fields.Add(new PacketField($"Float/{axis} @ {i}", $"{f:F2}", i, 4, FieldType.Float));
                floatCount++;
            }
        }

        result.Summary = OpcodeRegistry.FullLabel(data[0], pkt.Direction) + $" - {data.Length}b";
        return result;
    }

    // ── Schema Discovery ─────────────────────────────────────────────────

    /// <summary>
    /// Scan every 4-byte window in <paramref name="data"/> and score each
    /// uint32 value as a potential identifier (Item ID, Entity ID, etc.).
    ///
    /// Scoring factors:
    ///   · Value range matching known ID bands (item 100-9999, entity 1000-999999)
    ///   · Byte offset proximity to packet start
    ///   · Adjacent byte context (stack count / slot index neighbours)
    ///   · Recurrence across packets (applied by AggregateAcrossPackets)
    /// </summary>
    public static List<DiscoveredId> ScanUint32Identifiers(byte[] data)
    {
        var candidates = new Dictionary<uint, DiscoveredId>();
        if (data.Length < 4) return new List<DiscoveredId>();

        for (int i = 0; i + 4 <= data.Length; i++)
        {
            uint v = BitConverter.ToUInt32(data, i);

            if (v == 0 || v == 0xFFFFFFFF || v == 0xDEADBEEF) continue;
            if (v == (uint)data.Length || v == (uint)(data.Length - 1)) continue;

            int             score   = 0;
            string          typeTag = "Unknown";
            FieldConfidence conf    = FieldConfidence.Low;

            if (v >= 100 && v <= 9_999)
            {
                score  += 60;
                typeTag = "Item ID";
                conf    = FieldConfidence.Medium;
                // Bonus: followed by plausible stack count byte
                if (i + 4 < data.Length && data[i + 4] >= 1 && data[i + 4] <= 255)
                    score += 15;
                // Bonus: preceded by plausible slot index byte
                if (i >= 1 && data[i - 1] <= 64)
                    score += 10;
                // Bonus: early in packet
                if (i <= 4)      { score += 20; conf = FieldConfidence.High; }
                else if (i <= 8)   score += 10;
            }
            else if (v >= 1_000 && v <= 999_999)
            {
                score  += 50;
                typeTag = "Entity/Player ID";
                conf    = FieldConfidence.Medium;
                if (i <= 6) { score += 15; conf = FieldConfidence.High; }
            }
            else if (v >= 1 && v <= 99)
            {
                score  += 20;
                typeTag = v <= 64 ? "Slot/Count" : "Small Int";
                conf    = FieldConfidence.Low;
            }
            else if (v >= 1_000_000 && v <= 0x7FFF_FFFF)
            {
                score  += 25;
                typeTag = "Large ID / Token";
                conf    = FieldConfidence.Low;
            }
            else continue;

            if (score < 20) continue;

            if (candidates.TryGetValue(v, out var existing))
            {
                if (score > existing.Score)
                {
                    existing.Score      = score;
                    existing.Offset     = i;
                    existing.Confidence = conf;
                    existing.TypeTag    = typeTag;
                }
                existing.OccurrenceCount++;
            }
            else
            {
                candidates[v] = new DiscoveredId
                {
                    Value = v, Offset = i, Score = score,
                    TypeTag = typeTag, Confidence = conf, OccurrenceCount = 1,
                };
            }
        }

        return candidates.Values
            .OrderByDescending(c => c.Score)
            .ThenBy(c => c.Offset)
            .ToList();
    }

    /// <summary>
    /// Aggregate ScanUint32Identifiers results across many packets.
    /// IDs that appear in multiple packets receive a frequency bonus so
    /// stable item/entity IDs rise above ephemeral noise values.
    /// </summary>
    public static List<DiscoveredId> AggregateAcrossPackets(
        IEnumerable<CapturedPacket> packets, int maxPackets = 200)
    {
        var agg  = new Dictionary<uint, DiscoveredId>();
        int seen = 0;

        foreach (var pkt in packets)
        {
            if (seen++ >= maxPackets) break;
            foreach (var id in ScanUint32Identifiers(pkt.RawBytes))
            {
                if (agg.TryGetValue(id.Value, out var ex))
                {
                    ex.OccurrenceCount++;
                    ex.Score = Math.Max(ex.Score, id.Score) + ex.OccurrenceCount * 5;
                    if (id.Confidence > ex.Confidence) ex.Confidence = id.Confidence;
                }
                else
                {
                    agg[id.Value] = new DiscoveredId
                    {
                        Value = id.Value, Offset = id.Offset, Score = id.Score,
                        TypeTag = id.TypeTag, Confidence = id.Confidence, OccurrenceCount = 1,
                    };
                }
            }
        }

        return agg.Values
            .OrderByDescending(c => c.OccurrenceCount)
            .ThenByDescending(c => c.Score)
            .ToList();
    }

    // ── Decompression Layer ───────────────────────────────────────────────

    /// <summary>
    /// Auto-detects and decompresses a packet payload.
    /// Supported formats (detected by magic bytes):
    ///   · Zlib   - 78 01 / 78 9C / 78 DA / 78 5E
    ///   · Gzip   - 1F 8B
    ///   · LZ4 frame - 04 22 4D 18
    ///   · Raw deflate - fallback attempt when no magic matches
    ///
    /// Returns the decompressed bytes on success, or null if the payload
    /// is not recognised as compressed or decompression fails.
    /// <paramref name="method"/> is set to the detected format name.
    /// </summary>
    public static byte[]? TryDecompress(byte[] data, out string method)
    {

        method = "none";
        if (data.Length < 4) return null;

        // ── Gzip (1F 8B) ──────────────────────────────────────────────────
        if (data[0] == 0x1F && data[1] == 0x8B)
        {
            method = "gzip";
            try
            {
                using var ms = new MemoryStream(data);
                using var gz = new GZipStream(ms, CompressionMode.Decompress);
                using var out_ = new MemoryStream();
                gz.CopyTo(out_);
                return out_.ToArray();
            }
            catch { return null; }
        }

        // Zstd magic: 28 B5 2F FD
        if (data[0] == 0x28 && data[1] == 0xB5 &&
            data[2] == 0x2F && data[3] == 0xFD)
        {
            method = "zstd";
            try
            {
                using var d = new ZstdSharp.Decompressor();
                using var ms = new MemoryStream();
                using var zs = new ZstdSharp.DecompressionStream(new MemoryStream(data), d);
                zs.CopyTo(ms);
                return ms.ToArray();
            }
            catch { return null; }

        }


        // ── Zlib (78 xx) ──────────────────────────────────────────────────
        if (data[0] == 0x78 &&
            (data[1] == 0x01 || data[1] == 0x9C ||
             data[1] == 0xDA || data[1] == 0x5E))
        {
            method = "zlib";
            try
            {
                // Skip 2-byte zlib header before DeflateStream
                using var ms = new MemoryStream(data, 2, data.Length - 2);
                using var df = new DeflateStream(ms, CompressionMode.Decompress);
                using var out_ = new MemoryStream();
                df.CopyTo(out_);
                return out_.ToArray();
            }
            catch { return null; }
        }


        // Zstd magic: 28 B5 2F FD
        if (data[0] == 0x28 && data[1] == 0xB5 &&
            data[2] == 0x2F && data[3] == 0xFD)
        {
            method = "zstd";
            try
            {
                using var d = new ZstdSharp.Decompressor();
                using var ms = new MemoryStream();
                using var zs = new ZstdSharp.DecompressionStream(new MemoryStream(data), d);
                zs.CopyTo(ms);
                return ms.ToArray();
            }
            catch { return null; }
        }


        // ── LZ4 frame magic (04 22 4D 18) ────────────────────────────────
        if (data[0] == 0x04 && data[1] == 0x22 &&
            data[2] == 0x4D && data[3] == 0x18)
        {
            method = "lz4";
            // Pure-managed LZ4 block decompressor (no native dependency).
            // Reads the LZ4 frame format: FLG, BD, [content size], then blocks.
            try { return DecompressLz4Frame(data); }
            catch { return null; }
        }

        // ── Raw deflate fallback ──────────────────────────────────────────
        method = "deflate(try)";
        try
        {
            using var ms = new MemoryStream(data);
            using var df = new DeflateStream(ms, CompressionMode.Decompress);
            using var out_ = new MemoryStream();
            df.CopyTo(out_);
            var result = out_.ToArray();
            if (result.Length > 0) { method = "deflate"; return result; }
        }
        catch { }

        method = "none";
        return null;

    }


    /// <summary>
    /// Minimal managed LZ4 frame decompressor.
    /// Handles the common subset: FLG byte, optional content-size field,
    /// and sequential data blocks. Does not handle block independence or
    /// partial block checksums - sufficient for typical game protocol payloads.
    /// </summary>
    private static byte[] DecompressLz4Frame(byte[] src)
    {
        int pos = 4; // skip magic
        byte flg = src[pos++];
        byte bd  = src[pos++];

        bool hasContentSize = (flg & 0x08) != 0;
        bool hasBlockChecksum = (flg & 0x10) != 0;

        if (hasContentSize) pos += 8; // skip 8-byte content size field
        pos++; // skip header checksum

        var output = new MemoryStream();

        while (pos + 4 <= src.Length)
        {
            uint blockSize = BitConverter.ToUInt32(src, pos); pos += 4;
            if (blockSize == 0) break; // end mark

            bool isUncompressed = (blockSize & 0x80000000u) != 0;
            int  dataSize       = (int)(blockSize & 0x7FFFFFFF);

            if (pos + dataSize > src.Length) break;

            if (isUncompressed)
            {
                output.Write(src, pos, dataSize);
            }
            else
            {
                // LZ4 block decompression
                byte[] block = DecompressLz4Block(src, pos, dataSize);
                output.Write(block, 0, block.Length);
            }

            pos += dataSize;
            if (hasBlockChecksum) pos += 4;
        }

        return output.ToArray();
    }

    private static byte[] DecompressLz4Block(byte[] src, int srcOff, int srcLen)
    {
        var dst = new List<byte>(srcLen * 4);
        int i   = srcOff;
        int end = srcOff + srcLen;

        while (i < end)
        {
            byte token    = src[i++];
            int  litLen   = (token >> 4) & 0xF;
            int  matchLen = token & 0xF;

            // Extended literal length
            if (litLen == 15)
            { byte x; do { x = src[i++]; litLen += x; } while (x == 255); }

            // Literals
            for (int k = 0; k < litLen && i < end; k++) dst.Add(src[i++]);
            if (i >= end) break;

            // Match offset (little-endian 16-bit)
            int offset = src[i] | (src[i + 1] << 8); i += 2;

            // Extended match length
            if (matchLen == 15)
            { byte x; do { x = src[i++]; matchLen += x; } while (x == 255 && i < end); }
            matchLen += 4; // minimum match length is 4

            int matchStart = dst.Count - offset;
            for (int k = 0; k < matchLen; k++)
                dst.Add(dst[matchStart + (k % offset)]);
        }

        return dst.ToArray();
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static PacketActionHint GuessAction(int id, bool cs)
    {
        if (!cs) return PacketActionHint.ServerResponse;
        return id switch
        {
            0x01 => PacketActionHint.Command,
            0x07 => PacketActionHint.DropItem,
            0x08 => PacketActionHint.PickupItem,
            0x09 => PacketActionHint.InventoryAction,
            0x0B => PacketActionHint.TradeAccept,
            0x0C => PacketActionHint.TradeCancel,
            0x0E => PacketActionHint.ContainerMove,
            0x2A => PacketActionHint.GiveItem,
            0x30 => PacketActionHint.TransactionStart,
            0x31 => PacketActionHint.TransactionCommit,
            _    => PacketActionHint.Unknown,
        };
    }

    private static string GuessInt32FieldName(int v, int offset, byte[] data)
    {
        if (v >= 100  && v <= 9999  && offset <= 5) return $"Item ID? ({v})";
        if (v >= 1    && v <= 200   && offset >= 5) return $"Stack Count? ({v})";
        if (v >= 1000 && v <= 99999)                return $"Entity/Player ID? ({v})";
        if (v >= 1    && v <= 255   && offset <= 3) return $"Slot Index? ({v})";
        return $"Int32 ({v})";
    }

    private static List<(int offset, string value)> FindStrings(byte[] data, int minLen)
    {
        var results = new List<(int, string)>();
        int i = 0;
        while (i < data.Length)
        {
            if (data[i] >= 32 && data[i] < 127)
            {
                int start = i;
                var sb = new StringBuilder();
                while (i < data.Length && data[i] >= 32 && data[i] < 127)
                { sb.Append((char)data[i]); i++; }
                if (sb.Length >= minLen) results.Add((start, sb.ToString()));
            }
            else i++;
        }
        return results;
    }

    private static bool IsLikelyCommand(string s)    => s.StartsWith("/") && s.Length > 1;
    private static bool IsLikelyPlayerName(string s) => s.Length is >= 3 and <= 16
                                                      && s.All(c => char.IsLetterOrDigit(c) || c == '_');
    private static bool IsReasonableCoord(float f)   => !float.IsNaN(f) && !float.IsInfinity(f)
                                                      && f >= -100_000f && f <= 100_000f
                                                      && MathF.Abs(f) > 0.001f;
}

// ── Result types ──────────────────────────────────────────────────────────────

public class AnalysisResult
{
    public int               PacketId   { get; set; }
    public string            IdGuess    { get; set; } = "";
    public string            Summary    { get; set; } = "";
    public PacketActionHint  ActionHint { get; set; } = PacketActionHint.Unknown;
    public List<PacketField> Fields     { get; set; } = new();
    public List<FieldGuess>  Guesses    { get; set; } = new();
}

public class PacketField
{
    public string    Name   { get; }
    public string    Value  { get; }
    public int       Offset { get; }
    public int       Length { get; }
    public FieldType Type   { get; }
    public PacketField(string name, string value, int offset, int length, FieldType type)
    { Name = name; Value = value; Offset = offset; Length = length; Type = type; }
}

public class FieldGuess
{
    public string          Name       { get; }
    public int             IntValue   { get; }
    public int             Offset     { get; }
    public FieldConfidence Confidence { get; }
    public string?         StrValue   { get; }
    public FieldGuess(string name, int intValue, int offset,
                      FieldConfidence confidence, string? strValue = null)
    { Name = name; IntValue = intValue; Offset = offset; Confidence = confidence; StrValue = strValue; }
}

/// <summary>
/// A uint32 candidate produced by ScanUint32Identifiers / AggregateAcrossPackets.
/// Properties are mutable so OccurrenceCount and Score can be updated during aggregation.
/// </summary>
public class DiscoveredId
{
    public uint            Value           { get; set; }
    public int             Offset          { get; set; }
    public int             Score           { get; set; }
    public string          TypeTag         { get; set; } = "";
    public FieldConfidence Confidence      { get; set; }
    public int             OccurrenceCount { get; set; }
    /// Set by ItemInspectorTab when this ID appears in ≥2 packets within a 5-second window
    public bool            BoostedToHigh   { get; set; }
    /// Name linked from a String field found in the same packet as this ID
    public string?         LinkedName      { get; set; }

    public string ConfidenceLabel
    {
        get
        {
            if (BoostedToHigh || Confidence == FieldConfidence.High) return "HIGH[*]";
            return Confidence switch
            {
                FieldConfidence.Medium => "MED",
                _                      => "LOW",
            };
        }
    }
}

public enum FieldType       { Id, Length, Int32, Float, String, Unknown }
public enum FieldConfidence { Low, Medium, High }
public enum PacketActionHint
{
    Unknown, Command, DropItem, PickupItem, InventoryAction,
    TradeAccept, TradeCancel, ContainerMove, GiveItem,
    TransactionStart, TransactionCommit, ServerResponse
}
