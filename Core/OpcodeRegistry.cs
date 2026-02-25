using System.Collections.Concurrent;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Central OpCode registry for Hytale packet decoding.
///
/// Provides:
///   - Known C->S and S->C opcode labels so the log shows
///     "[0x4A] EntitySpawn" instead of raw hex.
///   - StructuredPacket: a decoded view of a CapturedPacket with
///     named fields, extracted IDs, confidence scores, and source tags.
///   - Runtime opcode learning: when the user confirms a label it is
///     persisted to config.json and immediately reflected in all UI.
///
/// Confidence scoring:
///   Source         Score range
///   Memory (RAM)   85-100   ColAccent (green)
///   Confirmed pkt  65-84    ColAccentMid
///   Inferred       40-64    ColWarn (yellow)
///   Uncertain      0-39     ColDanger (red)
/// </summary>
public static class OpcodeRegistry
{
    // ── Known Client -> Server opcodes ────────────────────────────────────
    private static readonly Dictionary<byte, OpcodeInfo> CsOpcodes = new()
    {
        { 0x01, new("ChatMessage",      "Chat / Command send",             OpcodeCategory.Chat) },
        { 0x02, new("PlayerMove",       "Position update (XYZ + yaw/pitch)",OpcodeCategory.Movement) },
        { 0x03, new("PlayerLook",       "Camera direction update",         OpcodeCategory.Movement) },
        { 0x04, new("PlayerAction",     "Generic player action",           OpcodeCategory.Action) },
        { 0x05, new("DigBlock",         "Block break / dig start",         OpcodeCategory.World) },
        { 0x06, new("UseItem",          "Right-click / use held item",     OpcodeCategory.Item) },
        { 0x07, new("DropItem",         "Drop item from inventory",        OpcodeCategory.Item) },
        { 0x08, new("PickupItem",       "Pick up world entity",            OpcodeCategory.Item) },
        { 0x09, new("InventoryClick",   "Click slot in open container",    OpcodeCategory.Inventory) },
        { 0x0A, new("InventoryClose",   "Close container / inventory",     OpcodeCategory.Inventory) },
        { 0x0B, new("TradeAccept",      "Accept active trade offer",       OpcodeCategory.Trade) },
        { 0x0C, new("TradeCancel",      "Cancel active trade",             OpcodeCategory.Trade) },
        { 0x0D, new("ContainerOpen",    "Request to open container",       OpcodeCategory.Inventory) },
        { 0x0E, new("ContainerMove",    "Move item between container slots",OpcodeCategory.Inventory) },
        { 0x0F, new("ContainerClose",   "Close container interaction",     OpcodeCategory.Inventory) },
        { 0x10, new("Handshake",        "Login / handshake initiation",    OpcodeCategory.Auth) },
        { 0x11, new("KeepAliveReply",   "Heartbeat acknowledgement",       OpcodeCategory.System) },
        { 0x12, new("RespawnRequest",   "Request respawn after death",     OpcodeCategory.System) },
        { 0x20, new("EntityInteract",   "Right-click entity (NPC/mob)",    OpcodeCategory.Entity) },
        { 0x21, new("EntityAttack",     "Melee attack on entity",          OpcodeCategory.Entity) },
        { 0x22, new("EntityUse",        "Secondary interact with entity",  OpcodeCategory.Entity) },
        { 0x2A, new("GiveItem",         "Suspected: give item to player",  OpcodeCategory.Item) },
        { 0x30, new("TransactionStart", "Begin atomic inventory transaction",OpcodeCategory.Transaction) },
        { 0x31, new("TransactionCommit","Commit inventory transaction",    OpcodeCategory.Transaction) },
        { 0x32, new("TransactionRollback","Rollback / abort transaction",  OpcodeCategory.Transaction) },
        { 0x4A, new("EntitySync4A",     "High-freq entity/item sync (0x4A)",OpcodeCategory.Entity) },
        { 0xFF, new("Debug",            "Debug / internal opcode",         OpcodeCategory.System) },
    };

    // ── Known Server -> Client opcodes ────────────────────────────────────
    private static readonly Dictionary<byte, OpcodeInfo> ScOpcodes = new()
    {
        { 0x01, new("ChatMessage",      "Chat message from server",        OpcodeCategory.Chat) },
        { 0x02, new("PlayerSpawn",      "Spawn player entity",             OpcodeCategory.Entity) },
        { 0x03, new("EntityUpdate",     "Entity position / state update",  OpcodeCategory.Entity) },
        { 0x04, new("InventoryUpdate",  "Full inventory contents sync",    OpcodeCategory.Inventory) },
        { 0x05, new("ItemPickupConfirm","Server confirms item pickup",     OpcodeCategory.Item) },
        { 0x06, new("BlockUpdate",      "Single block state change",       OpcodeCategory.World) },
        { 0x07, new("SoundEffect",      "Play sound at world position",    OpcodeCategory.Audio) },
        { 0x08, new("ParticleEffect",   "Spawn particle at position",      OpcodeCategory.Visual) },
        { 0x09, new("WorldState",       "World / chunk data transfer",     OpcodeCategory.World) },
        { 0x0A, new("TimeUpdate",       "Day/night time sync",             OpcodeCategory.World) },
        { 0x10, new("LoginSuccess",     "Authentication accepted",         OpcodeCategory.Auth) },
        { 0x11, new("LoginFailure",     "Authentication rejected",         OpcodeCategory.Auth) },
        { 0x12, new("KeepAlive",        "Heartbeat ping from server",      OpcodeCategory.System) },
        { 0x20, new("ItemSpawnWorld",   "Item entity spawned in world",    OpcodeCategory.Item) },
        { 0x21, new("ItemDespawn",      "Item entity removed from world",  OpcodeCategory.Item) },
        { 0x22, new("InventorySlot",    "Single inventory slot update",    OpcodeCategory.Inventory) },
        { 0x23, new("HealthUpdate",     "Player health / status change",   OpcodeCategory.Entity) },
        { 0x24, new("XpUpdate",         "Experience points update",        OpcodeCategory.Entity) },
        { 0x30, new("TransactionAck",   "Transaction acknowledged",        OpcodeCategory.Transaction) },
        { 0x31, new("TransactionDenied","Transaction rejected by server",  OpcodeCategory.Transaction) },
        { 0x4A, new("EntitySync4A",     "High-freq entity/item sync (0x4A)",OpcodeCategory.Entity) },
    };

    // Runtime user-learned opcodes (persisted via GlobalConfig)
    private static readonly ConcurrentDictionary<byte, OpcodeInfo> UserCsOpcodes = new();
    private static readonly ConcurrentDictionary<byte, OpcodeInfo> UserScOpcodes = new();

    // ── Lookup ────────────────────────────────────────────────────────────

    public static OpcodeInfo? Lookup(byte opcode, PacketDirection dir)
    {
        bool cs = dir == PacketDirection.ClientToServer;
        var userMap    = cs ? UserCsOpcodes : UserScOpcodes;
        var builtInMap = cs ? CsOpcodes     : ScOpcodes;
        if (userMap.TryGetValue(opcode, out var u)) return u;
        if (builtInMap.TryGetValue(opcode, out var b)) return b;
        return null;
    }

    /// <summary>Short display label: "EntitySync4A" or "Unk(0xXX)"</summary>
    public static string Label(byte opcode, PacketDirection dir)
        => Lookup(opcode, dir)?.Name ?? $"Unk(0x{opcode:X2})";

    /// <summary>Full label with direction and description.</summary>
    public static string FullLabel(byte opcode, PacketDirection dir)
    {
        var info = Lookup(opcode, dir);
        string prefix = dir == PacketDirection.ClientToServer ? "C->S" : "S->C";
        if (info == null) return $"[{prefix}] 0x{opcode:X2} Unknown";
        return $"[{prefix}] 0x{opcode:X2} {info.Name}";
    }

    /// <summary>Register a user-learned opcode name at runtime.</summary>
    public static void Learn(byte opcode, PacketDirection dir, string name, string description = "")
    {
        var info = new OpcodeInfo(name, description, OpcodeCategory.Unknown);
        if (dir == PacketDirection.ClientToServer)
            UserCsOpcodes[opcode] = info;
        else
            UserScOpcodes[opcode] = info;
    }

    public static IEnumerable<(byte opcode, OpcodeInfo info, bool isCs)> AllKnown()
    {
        foreach (var kv in CsOpcodes)  yield return (kv.Key, kv.Value, true);
        foreach (var kv in ScOpcodes)  yield return (kv.Key, kv.Value, false);
        foreach (var kv in UserCsOpcodes) yield return (kv.Key, kv.Value, true);
        foreach (var kv in UserScOpcodes) yield return (kv.Key, kv.Value, false);
    }

    // ── Structured packet decoder ─────────────────────────────────────────

    /// <summary>
    /// Decode a CapturedPacket into a StructuredPacket with named fields,
    /// extracted IDs, XYZ coords, and confidence scores.
    /// </summary>
    public static StructuredPacket Decode(CapturedPacket pkt)
    {
        var sp   = new StructuredPacket(pkt);
        var data = pkt.RawBytes;
        if (data.Length == 0) return sp;

        byte opcode = data[0];
        sp.Opcode  = opcode;
        sp.Info    = Lookup(opcode, pkt.Direction);
        sp.Label   = FullLabel(opcode, pkt.Direction);

        // Category-specific field extraction
        switch (sp.Info?.Category)
        {
            case OpcodeCategory.Entity:
            case OpcodeCategory.Item:
                ExtractEntityFields(sp, data);
                break;
            case OpcodeCategory.Inventory:
                ExtractInventoryFields(sp, data);
                break;
            case OpcodeCategory.Movement:
                ExtractMovementFields(sp, data);
                break;
            case OpcodeCategory.Chat:
                ExtractChatFields(sp, data);
                break;
            case OpcodeCategory.Transaction:
                ExtractTransactionFields(sp, data);
                break;
            default:
                ExtractGenericFields(sp, data);
                break;
        }

        // Confidence: known opcode = starts at Medium, unknown = Low
        if (sp.Info != null)
        {
            sp.ConfidenceScore = 50;  // known opcode baseline
            sp.ConfidenceSource = "Opcode known";
        }
        else
        {
            sp.ConfidenceScore = 25;
            sp.ConfidenceSource = "Unknown opcode";
        }

        // Boost confidence if IDs were resolved from IdNameMap
        if (sp.ExtractedIds.Any())
            sp.ConfidenceScore = Math.Min(100, sp.ConfidenceScore + sp.ExtractedIds.Count * 10);

        return sp;
    }

    // ── Field extractors ──────────────────────────────────────────────────

    private static void ExtractEntityFields(StructuredPacket sp, byte[] data)
    {
        // Try LE uint32 at offsets 1-8 for entity/item IDs
        for (int i = 1; i + 4 <= Math.Min(data.Length, 16); i++)
        {
            uint v = BitConverter.ToUInt32(data, i);
            if (v >= 100 && v <= 9_999_999)
            {
                sp.ExtractedIds.Add(new ExtractedField("EntityID", v, i,
                    v <= 9999 ? ConfidenceSource.Packet : ConfidenceSource.Inferred));
            }
        }
        // Try XYZ floats from offset 5 onwards
        TryExtractXYZ(sp, data, startOffset: 5);
    }

    private static void ExtractInventoryFields(StructuredPacket sp, byte[] data)
    {
        if (data.Length >= 5)
        {
            byte slotIdx = data[1];
            sp.Fields.Add(new PacketFieldEx("SlotIndex", slotIdx.ToString(), 1, ConfidenceSource.Packet, 70));
        }
        for (int i = 2; i + 4 <= Math.Min(data.Length, 12); i++)
        {
            uint v = BitConverter.ToUInt32(data, i);
            if (v >= 100 && v <= 9999)
            {
                sp.ExtractedIds.Add(new ExtractedField("ItemID", v, i, ConfidenceSource.Packet));
                if (i + 4 < data.Length)
                    sp.Fields.Add(new PacketFieldEx("StackSize", data[i + 4].ToString(), i + 4, ConfidenceSource.Inferred, 55));
                break;
            }
        }
    }

    private static void ExtractMovementFields(StructuredPacket sp, byte[] data)
    {
        TryExtractXYZ(sp, data, startOffset: 1);
        // Yaw + pitch
        if (data.Length >= 13)
        {
            float yaw = BitConverter.ToSingle(data, Math.Min(9, data.Length - 4));
            if (!float.IsNaN(yaw) && yaw >= -360f && yaw <= 360f)
                sp.Fields.Add(new PacketFieldEx("Yaw", $"{yaw:F1}", 9, ConfidenceSource.Inferred, 60));
        }
    }

    private static void ExtractChatFields(StructuredPacket sp, byte[] data)
    {
        // Chat: opcode + length prefix + UTF-8 string
        if (data.Length > 3)
        {
            string text = System.Text.Encoding.UTF8.GetString(data, 1, data.Length - 1)
                .Replace("\0", "").Trim();
            if (text.Length > 0 && text.Length <= 256)
                sp.Fields.Add(new PacketFieldEx("Message", text, 1, ConfidenceSource.Packet, 80));
        }
    }

    private static void ExtractTransactionFields(StructuredPacket sp, byte[] data)
    {
        if (data.Length >= 5)
        {
            uint txId = BitConverter.ToUInt32(data, 1);
            sp.Fields.Add(new PacketFieldEx("TransactionID", $"0x{txId:X8}", 1, ConfidenceSource.Packet, 75));
        }
        for (int i = 5; i + 4 <= Math.Min(data.Length, 20); i++)
        {
            uint v = BitConverter.ToUInt32(data, i);
            if (v >= 100 && v <= 9999)
                sp.ExtractedIds.Add(new ExtractedField("ItemID", v, i, ConfidenceSource.Inferred));
        }
    }

    private static void ExtractGenericFields(StructuredPacket sp, byte[] data)
    {
        for (int i = 1; i + 4 <= Math.Min(data.Length, 16); i++)
        {
            uint v = BitConverter.ToUInt32(data, i);
            if (v >= 100 && v <= 9999)
                sp.ExtractedIds.Add(new ExtractedField("ID?", v, i, ConfidenceSource.Uncertain));
        }
    }

    private static void TryExtractXYZ(StructuredPacket sp, byte[] data, int startOffset)
    {
        for (int i = startOffset; i + 12 <= data.Length; i += 4)
        {
            float x = BitConverter.ToSingle(data, i);
            float y = BitConverter.ToSingle(data, i + 4);
            float z = BitConverter.ToSingle(data, i + 8);
            if (IsCoord(x) && IsCoord(y) && IsCoord(z))
            {
                sp.Position = new System.Numerics.Vector3(x, y, z);
                sp.Fields.Add(new PacketFieldEx("X", $"{x:F2}", i,      ConfidenceSource.Inferred, 65));
                sp.Fields.Add(new PacketFieldEx("Y", $"{y:F2}", i + 4,  ConfidenceSource.Inferred, 65));
                sp.Fields.Add(new PacketFieldEx("Z", $"{z:F2}", i + 8,  ConfidenceSource.Inferred, 65));
                break;
            }
        }
    }

    private static bool IsCoord(float f)
        => !float.IsNaN(f) && !float.IsInfinity(f) && f >= -100_000f && f <= 100_000f;
}

// ── Supporting types ──────────────────────────────────────────────────────────

public class OpcodeInfo
{
    public string          Name        { get; }
    public string          Description { get; }
    public OpcodeCategory  Category    { get; }
    public OpcodeInfo(string name, string desc, OpcodeCategory cat)
    { Name = name; Description = desc; Category = cat; }
}

public enum OpcodeCategory
{
    Unknown, Chat, Movement, Action, World, Item, Inventory, Trade,
    Auth, System, Entity, Transaction, Audio, Visual
}

public enum ConfidenceSource { Memory, Packet, Inferred, Uncertain }

public class StructuredPacket
{
    public CapturedPacket   Raw              { get; }
    public byte             Opcode           { get; set; }
    public OpcodeInfo?      Info             { get; set; }
    public string           Label            { get; set; } = "";
    public int              ConfidenceScore  { get; set; }  // 0-100
    public string           ConfidenceSource { get; set; } = "";
    public System.Numerics.Vector3? Position { get; set; }
    public List<PacketFieldEx>  Fields       { get; } = new();
    public List<ExtractedField> ExtractedIds { get; } = new();

    public StructuredPacket(CapturedPacket raw) { Raw = raw; }

    public string ConfidenceLabel => ConfidenceScore switch
    {
        >= 85 => $"[MEM {ConfidenceScore}%]",
        >= 65 => $"[PKT {ConfidenceScore}%]",
        >= 40 => $"[INF {ConfidenceScore}%]",
        _     => $"[UNK {ConfidenceScore}%]",
    };

    public System.Numerics.Vector4 ConfidenceColor => ConfidenceScore switch
    {
        >= 85 => MenuRenderer.ColAccent,
        >= 65 => MenuRenderer.ColAccentMid,
        >= 40 => MenuRenderer.ColWarn,
        _     => MenuRenderer.ColDanger,
    };
}

public class PacketFieldEx
{
    public string           Name       { get; }
    public string           Value      { get; }
    public int              Offset     { get; }
    public ConfidenceSource Source     { get; }
    public int              Score      { get; }
    public PacketFieldEx(string name, string value, int offset, ConfidenceSource src, int score)
    { Name = name; Value = value; Offset = offset; Source = src; Score = score; }

    public string SourceLabel => Source switch
    {
        ConfidenceSource.Memory    => "[MEM]",
        ConfidenceSource.Packet    => "[PKT]",
        ConfidenceSource.Inferred  => "[INF]",
        _                          => "[UNK]",
    };
}

public class ExtractedField
{
    public string           Name   { get; }
    public uint             Value  { get; }
    public int              Offset { get; }
    public ConfidenceSource Source { get; }
    public string?          ResolvedName { get; set; }  // filled by EntityTracker
    public ExtractedField(string name, uint value, int offset, ConfidenceSource src)
    { Name = name; Value = value; Offset = offset; Source = src; }
}
