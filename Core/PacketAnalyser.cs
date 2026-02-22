using System.Text;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Heuristic packet analyser.
///
/// Since Hytale's packet format is not publicly documented, this class uses
/// pattern-matching and structural analysis to make educated guesses about
/// what a captured packet contains.  Every field is labelled as a "hint"
/// rather than a definitive parse — you confirm by watching in-game behaviour.
///
/// How to use:
///   var result = PacketAnalyser.Analyse(packet);
///   // result.Summary    — one-line human-readable description
///   // result.Fields     — list of detected fields with names + values
///   // result.Guesses    — list of named fields the parser thinks it found
///   // result.ActionHint — best guess at what the packet does
/// </summary>
public static class PacketAnalyser
{
    // ── Known/guessed packet ID ranges (update as you discover real IDs) ──

    // Client → Server guesses
    private static readonly Dictionary<int, string> KnownCsIds = new()
    {
        { 0x01, "Chat / Command" },
        { 0x02, "Player Move" },
        { 0x03, "Player Look" },
        { 0x04, "Player Action" },
        { 0x05, "Dig / Break Block" },
        { 0x06, "Use Item" },
        { 0x07, "Drop Item" },
        { 0x08, "Pick Up Item" },
        { 0x09, "Inventory Click" },
        { 0x0A, "Inventory Close" },
        { 0x0B, "Trade Accept" },
        { 0x0C, "Trade Cancel" },
        { 0x0D, "Container Open" },
        { 0x0E, "Container Move Item" },
        { 0x0F, "Container Close" },
        { 0x10, "Handshake / Login" },
        { 0x11, "Keep Alive Response" },
        { 0x12, "Respawn Request" },
        { 0x20, "Entity Interact" },
        { 0x21, "Entity Attack" },
        { 0x22, "Entity Use" },
        { 0x2A, "Give Item (suspected)" },
        { 0x30, "Transaction Start" },
        { 0x31, "Transaction Commit" },
        { 0x32, "Transaction Rollback" },
    };

    // Server → Client guesses
    private static readonly Dictionary<int, string> KnownScIds = new()
    {
        { 0x01, "Chat Message" },
        { 0x02, "Player Spawn" },
        { 0x03, "Entity Update" },
        { 0x04, "Inventory Update" },
        { 0x05, "Item Pickup Confirm" },
        { 0x06, "Block Update" },
        { 0x07, "Sound Effect" },
        { 0x08, "Particle Effect" },
        { 0x09, "World State" },
        { 0x0A, "Time Update" },
        { 0x10, "Login Success" },
        { 0x11, "Login Failure" },
        { 0x12, "Keep Alive" },
        { 0x20, "Item Spawn (world)" },
        { 0x21, "Item Despawn" },
        { 0x22, "Inventory Slot Update" },
        { 0x23, "Health Update" },
        { 0x24, "XP Update" },
        { 0x30, "Transaction Ack" },
        { 0x31, "Transaction Denied" },
    };

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

        // ── Packet ID lookup ──────────────────────────────────────────────
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

        // ── Structural analysis ───────────────────────────────────────────
        result.Fields.Add(new PacketField("Packet ID", $"0x{data[0]:X2}", 0, 1, FieldType.Id));

        if (data.Length >= 3)
        {
            // Bytes 1-2: often a length or sequence number
            ushort val16 = BitConverter.ToUInt16(data, 1);
            if (val16 == data.Length - 3)
                result.Fields.Add(new PacketField("Length (guessed)", val16.ToString(), 1, 2, FieldType.Length));
            else
                result.Fields.Add(new PacketField("Seq / Type (guessed)", $"0x{val16:X4}", 1, 2, FieldType.Unknown));
        }

        // ── Int32 scan — look for values that look like item IDs / entity IDs
        for (int i = 1; i + 4 <= data.Length; i += 1)
        {
            int v = BitConverter.ToInt32(data, i);
            if (v > 0 && v < 10000)
            {
                string fieldName = GuessInt32FieldName(v, i, data);
                result.Fields.Add(new PacketField(fieldName, v.ToString(), i, 4, FieldType.Int32));

                // Special tracking for item-like values
                if (v >= 100 && v <= 9999 && i <= 8)
                    result.Guesses.Add(new FieldGuess(fieldName, v, i, FieldConfidence.Medium));
            }
        }

        // ── String scan — look for readable ASCII sequences ───────────────
        var strings = FindStrings(data, 3);
        foreach (var (offset, str) in strings)
        {
            result.Fields.Add(new PacketField($"String @ {offset}", $"\"{str}\"", offset, str.Length, FieldType.String));
            if (IsLikelyCommand(str))
            {
                result.Guesses.Add(new FieldGuess("Command/Chat", 0, offset, FieldConfidence.High, str));
                result.ActionHint = PacketActionHint.Command;
            }
            if (IsLikelyPlayerName(str))
                result.Guesses.Add(new FieldGuess("Player Name", 0, offset, FieldConfidence.Medium, str));
        }

        // ── Float scan — coordinates, angles ─────────────────────────────
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

        // ── Summary ───────────────────────────────────────────────────────
        string dir = cs ? "C→S" : "S→C";
        result.Summary = $"[{dir}] 0x{data[0]:X2} · {result.IdGuess} · {data.Length}b";

        return result;
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
                {
                    sb.Append((char)data[i]);
                    i++;
                }
                if (sb.Length >= minLen)
                    results.Add((start, sb.ToString()));
            }
            else i++;
        }
        return results;
    }

    private static bool IsLikelyCommand(string s) =>
        s.StartsWith("/") && s.Length > 1;

    private static bool IsLikelyPlayerName(string s) =>
        s.Length >= 3 && s.Length <= 16 &&
        s.All(c => char.IsLetterOrDigit(c) || c == '_');

    private static bool IsReasonableCoord(float f) =>
        !float.IsNaN(f) && !float.IsInfinity(f) &&
        f >= -100000f && f <= 100000f &&
        MathF.Abs(f) > 0.001f;
}

// ── Result types ──────────────────────────────────────────────────────────────

public class AnalysisResult
{
    public int                 PacketId   { get; set; }
    public string              IdGuess    { get; set; } = "";
    public string              Summary    { get; set; } = "";
    public PacketActionHint    ActionHint { get; set; } = PacketActionHint.Unknown;
    public List<PacketField>   Fields     { get; set; } = new();
    public List<FieldGuess>    Guesses    { get; set; } = new();
}

public class PacketField
{
    public string    Name      { get; }
    public string    Value     { get; }
    public int       Offset    { get; }
    public int       Length    { get; }
    public FieldType Type      { get; }

    public PacketField(string name, string value, int offset, int length, FieldType type)
    {
        Name = name; Value = value; Offset = offset;
        Length = length; Type = type;
    }
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
    {
        Name = name; IntValue = intValue; Offset = offset;
        Confidence = confidence; StrValue = strValue;
    }
}

public enum FieldType    { Id, Length, Int32, Float, String, Unknown }
public enum FieldConfidence { Low, Medium, High }
public enum PacketActionHint
{
    Unknown, Command, DropItem, PickupItem, InventoryAction,
    TradeAccept, TradeCancel, ContainerMove, GiveItem,
    TransactionStart, TransactionCommit, ServerResponse
}
