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
    // ── Real Hytale Client -> Server packet IDs ───────────────────────────
    // Source: hytalemodding.dev (build 2026.01.13-dcad8778f)
    // Hytale uses VarInt-encoded packet IDs on the wire (same as Minecraft).
    // IDs 0-127 = single byte; 128+ = multi-byte VarInt.
    // Use DecodePacketId() to extract the ID from raw bytes / hex preview.
    private static readonly Dictionary<ushort, OpcodeInfo> CsOpcodes = new()
    {
        // ── Auth / setup ──────────────────────────────────────────────────
        { 0,    new("Connect",               "Initial connection handshake",            OpcodeCategory.Auth) },
        { 1,    new("Disconnect",            "Disconnect notification",                 OpcodeCategory.Auth) },
        { 12,   new("AuthToken",             "Authentication token",                    OpcodeCategory.Auth) },
        { 15,   new("PasswordResponse",      "Password authentication",                 OpcodeCategory.Auth) },
        { 18,   new("ClientReferral",        "Client referral / relay",                 OpcodeCategory.System) },
        { 23,   new("RequestAssets",         "Asset download request",                  OpcodeCategory.System) },
        // ── Player / movement ─────────────────────────────────────────────
        { 100,  new("SetClientId",           "Set client connection identifier",        OpcodeCategory.System) },
        { 101,  new("SetGameMode",           "Request game mode change",                OpcodeCategory.System) },
        { 102,  new("SetMovementStates",     "Batch movement state flags",              OpcodeCategory.Movement) },
        { 103,  new("SetBlockPlacementOverride","Override block placement",             OpcodeCategory.World) },
        { 104,  new("JoinWorld",             "Join / teleport to world",                OpcodeCategory.World) },
        { 105,  new("ClientReady",           "Client ready for gameplay",               OpcodeCategory.System) },
        { 106,  new("LoadHotbar",            "Load hotbar row from inventory",          OpcodeCategory.Inventory) },
        { 107,  new("SaveHotbar",            "Save current hotbar row",                 OpcodeCategory.Inventory) },
        { 108,  new("ClientMovement",        "Position + orientation update",           OpcodeCategory.Movement) },
        { 109,  new("ClientTeleport",        "Teleport acknowledgement",                OpcodeCategory.Movement) },
        { 110,  new("UpdateMovementSettings","Movement settings / modifiers",           OpcodeCategory.Movement) },
        { 111,  new("MouseInteraction",      "Mouse click / aim interaction",           OpcodeCategory.Action) },
        { 112,  new("DamageInfo",            "Client-reported damage event",            OpcodeCategory.Entity) },
        { 113,  new("ReticleEvent",          "Reticle / crosshair event",               OpcodeCategory.Action) },
        { 116,  new("SyncPlayerPreferences", "Client preferences sync",                 OpcodeCategory.System) },
        { 117,  new("ClientPlaceBlock",      "Place block in world",                    OpcodeCategory.World) },
        { 118,  new("UpdateMemoriesFeatureStatus","Memories feature toggle",            OpcodeCategory.System) },
        { 119,  new("RemoveMapMarker",       "Remove map waypoint marker",              OpcodeCategory.World) },
        // ── Inventory ─────────────────────────────────────────────────────
        { 170,  new("UpdatePlayerInventory", "Full inventory contents sync",            OpcodeCategory.Inventory) },
        { 171,  new("SetCreativeItem",       "Set item in creative slot",               OpcodeCategory.Inventory) },
        { 172,  new("DropCreativeItem",      "Drop item from creative inventory",       OpcodeCategory.Inventory) },
        { 173,  new("SmartGiveCreativeItem", "Smart-give creative item",                OpcodeCategory.Inventory) },
        { 174,  new("DropItemStack",         "Drop item stack from slot",               OpcodeCategory.Inventory) },
        { 175,  new("MoveItemStack",         "Move item between slots",                 OpcodeCategory.Inventory) },
        { 176,  new("SmartMoveItemStack",    "Smart-move item stack",                   OpcodeCategory.Inventory) },
        { 177,  new("SetActiveSlot",         "Switch active hotbar slot",               OpcodeCategory.Inventory) },
        { 178,  new("SwitchHotbarBlockSet",  "Cycle block set on hotbar",               OpcodeCategory.Inventory) },
        { 179,  new("InventoryAction",       "Generic inventory action",                OpcodeCategory.Inventory) },
        // ── Windows / UI ──────────────────────────────────────────────────
        { 200,  new("OpenWindow",            "Server-opened UI window",                 OpcodeCategory.System) },
        { 201,  new("UpdateWindow",          "Window contents update",                  OpcodeCategory.System) },
        { 202,  new("CloseWindow",           "Close UI window",                         OpcodeCategory.System) },
        { 203,  new("SendWindowAction",      "Interact with window element",            OpcodeCategory.System) },
        { 204,  new("ClientOpenWindow",      "Client-initiated window open",            OpcodeCategory.System) },
        // ── Chat / other ──────────────────────────────────────────────────
        { 211,  new("ChatMessage",           "Player chat message",                     OpcodeCategory.Chat) },
        { 219,  new("CustomPageEvent",       "Custom UI page event",                    OpcodeCategory.System) },
        { 232,  new("UpdateLanguage",        "Client language setting",                 OpcodeCategory.System) },
        { 243,  new("UpdateWorldMapVisible", "Toggle world map visibility",             OpcodeCategory.World) },
        { 244,  new("TeleportToWorldMapMarker","Teleport to map marker",                OpcodeCategory.Movement) },
        { 245,  new("TeleportToWorldMapPosition","Teleport to map position",            OpcodeCategory.Movement) },
        { 251,  new("UpdateServerAccess",    "Update server access flags",              OpcodeCategory.Auth) },
        { 252,  new("SetServerAccess",       "Set server access + password",            OpcodeCategory.Auth) },
        { 158,  new("SetPaused",             "Client pause state",                      OpcodeCategory.System) },
        { 160,  new("SetEntitySeed",         "Entity random seed",                      OpcodeCategory.Entity) },
        { 166,  new("MountMovement",         "Movement while mounted",                  OpcodeCategory.Movement) },
        { 216,  new("SetPage",               "Navigate to page",                        OpcodeCategory.System) },
        // ── Interaction (SyncInteractionChains - key exploit surface) ─────
        { 290,  new("SyncInteractionChains", "Player interaction batch (primary/secondary/use/F-key)", OpcodeCategory.Action) },
        // ── Builder tools ─────────────────────────────────────────────────
        { 400,  new("BuilderToolArgUpdate",  "Builder tool argument",                   OpcodeCategory.World) },
        { 401,  new("BuilderToolEntityAction","Builder entity action",                  OpcodeCategory.World) },
        { 402,  new("BuilderToolSetEntityTransform","Set entity transform",             OpcodeCategory.World) },
        { 405,  new("BuilderToolSelectionTransform","Transform selection",              OpcodeCategory.World) },
        { 409,  new("BuilderToolSelectionUpdate","Update selection",                    OpcodeCategory.World) },
        { 412,  new("BuilderToolGeneralAction","Builder general action",                OpcodeCategory.World) },
        { 413,  new("BuilderToolOnUseInteraction","Builder use interaction",            OpcodeCategory.World) },
        { 414,  new("BuilderToolLineAction", "Builder line draw action",                OpcodeCategory.World) },
        // ── Misc ──────────────────────────────────────────────────────────
        { 282,  new("RequestFlyCameraMode",  "Request fly/camera mode",                 OpcodeCategory.Movement) },
        { 294,  new("DismountNPC",           "Dismount from NPC",                       OpcodeCategory.Entity) },
        { 0x4A, new("EntitySync4A",          "High-freq entity/item sync (legacy 0x4A)",OpcodeCategory.Entity) },
        { 0xFF, new("Debug",                 "Debug / internal packet",                 OpcodeCategory.System) },
    };

    // ── Real Hytale Server -> Client packet IDs ───────────────────────────
    private static readonly Dictionary<ushort, OpcodeInfo> ScOpcodes = new()
    {
        { 1,    new("Disconnect",            "Server disconnect",                        OpcodeCategory.System) },
        { 3,    new("Pong",                  "Keepalive pong",                           OpcodeCategory.System) },
        { 0x4A, new("EntitySync4A",          "High-freq entity/item sync (0x4A)",        OpcodeCategory.Entity) },
        // IDs below are inferred (S->C not fully documented by hytalemodding.dev)
        { 0x02, new("PlayerSpawn",           "Spawn player entity",                      OpcodeCategory.Entity) },
        // 0x03 = 3 = "Pong" (already defined above; EntityUpdate is a different ID)
        { 200,  new("EntityUpdate",          "Entity position / state update",           OpcodeCategory.Entity) },
        { 0x04, new("InventoryUpdate",       "Full inventory contents sync",             OpcodeCategory.Inventory) },
        { 0x06, new("BlockUpdate",           "Single block state change",                OpcodeCategory.World) },
        { 0x0A, new("TimeUpdate",            "Day/night time sync",                      OpcodeCategory.World) },
        { 0x10, new("LoginSuccess",          "Authentication accepted",                  OpcodeCategory.Auth) },
        { 0x12, new("KeepAlive",             "Heartbeat ping from server",               OpcodeCategory.System) },
        { 0x20, new("ItemSpawnWorld",        "Item entity spawned in world",             OpcodeCategory.Item) },
        { 0x22, new("InventorySlot",         "Single inventory slot update",             OpcodeCategory.Inventory) },
        { 0x23, new("HealthUpdate",          "Player health / status change",            OpcodeCategory.Entity) },
        { 0x30, new("TransactionAck",        "Transaction acknowledged",                 OpcodeCategory.Transaction) },
        { 0x31, new("TransactionDenied",     "Transaction rejected by server",           OpcodeCategory.Transaction) },
    };

    // Runtime user-learned opcodes
    private static readonly ConcurrentDictionary<ushort, OpcodeInfo> UserCsOpcodes;
    private static readonly ConcurrentDictionary<ushort, OpcodeInfo> UserScOpcodes;

    // Indicates whether static init succeeded
    private static readonly bool _initOk;
    private static readonly string _initError = "";

    static OpcodeRegistry()
    {
        UserCsOpcodes = new();
        UserScOpcodes = new();
        try
        {
            // Validate no duplicate keys exist
            var seen = new Dictionary<(ushort, bool), string>();
            foreach (var kv in CsOpcodes)
            {
                var key = (kv.Key, true);
                if (seen.ContainsKey(key))
                    throw new InvalidOperationException(
                        $"Duplicate C->S opcode {kv.Key}: '{kv.Value.Name}' vs '{seen[key]}'");
                seen[key] = kv.Value.Name;
            }
            foreach (var kv in ScOpcodes)
            {
                var key = (kv.Key, false);
                if (seen.ContainsKey(key))
                    throw new InvalidOperationException(
                        $"Duplicate S->C opcode {kv.Key}: '{kv.Value.Name}' vs '{seen[key]}'");
                seen[key] = kv.Value.Name;
            }
            _initOk = true;
        }
        catch (Exception ex)
        {
            _initOk    = false;
            _initError = ex.Message;
            // Don't rethrow — a TypeInitializationException would crash the whole app.
            // The tab will show an error banner instead.
        }
    }

    // ── VarInt decoder (Netty / Hytale wire format) ───────────────────────

    /// <summary>
    /// Decode a Hytale/Netty VarInt packet ID from raw bytes.
    /// IDs 0-127: single byte. 128+: low 7 bits of each byte, MSB = "more follows".
    /// Returns the decoded ID and how many bytes it consumed.
    /// </summary>
    public static ushort DecodePacketId(byte[] data, out int bytesConsumed)
    {
        int result = 0;
        bytesConsumed = 0;
        for (int i = 0; i < Math.Min(3, data.Length); i++)
        {
            byte b = data[i];
            result |= (b & 0x7F) << (7 * i);
            bytesConsumed = i + 1;
            if ((b & 0x80) == 0) break;
        }
        return (ushort)result;
    }

    /// <summary>Decode VarInt from a hex-preview string ("6C 00 AB...").</summary>
    public static ushort DecodePacketIdFromHex(string hexPreview)
    {
        var tokens = hexPreview.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var bytes  = new List<byte>(3);
        foreach (var t in tokens)
        {
            if (bytes.Count >= 3) break;
            if (byte.TryParse(t, System.Globalization.NumberStyles.HexNumber, null, out byte b))
                bytes.Add(b);
        }
        return bytes.Count > 0 ? DecodePacketId(bytes.ToArray(), out _) : (ushort)0;
    }

    // ── Lookup ────────────────────────────────────────────────────────────

    private static readonly OpcodeInfo _unknownInfo =
        new("UNKNOWN", "Unrecognised packet ID", OpcodeCategory.Unknown);

    /// <summary>
    /// Look up an opcode. Never returns null — unknown IDs get an UNKNOWN sentinel
    /// so callers don't need null-checks and can't trigger a NullReferenceException.
    /// </summary>
    public static OpcodeInfo Lookup(ushort id, PacketDirection dir)
    {
        try
        {
            if (!_initOk) return _unknownInfo;
            bool cs = dir == PacketDirection.ClientToServer;
            var userMap    = cs ? UserCsOpcodes : UserScOpcodes;
            var builtInMap = cs ? CsOpcodes     : ScOpcodes;
            if (userMap    != null && userMap.TryGetValue(id, out var u)) return u;
            if (builtInMap != null && builtInMap.TryGetValue(id, out var b)) return b;
            return _unknownInfo;
        }
        catch
        {
            return _unknownInfo;
        }
    }

    /// <summary>Legacy byte overload — wraps to ushort.</summary>
    public static OpcodeInfo Lookup(byte opcode, PacketDirection dir)
        => Lookup((ushort)opcode, dir);

    /// <summary>Returns the init error message if static init failed, else empty string.</summary>
    public static string InitError => _initOk ? "" : _initError;

    public static string Label(ushort id, PacketDirection dir)
        => Lookup(id, dir)?.Name ?? $"Unk({id})";

    public static string Label(byte opcode, PacketDirection dir)
        => Label((ushort)opcode, dir);

    public static string FullLabel(ushort id, PacketDirection dir)
    {
        var info = Lookup(id, dir);   // always non-null
        string prefix = dir == PacketDirection.ClientToServer ? "C->S" : "S->C";
        bool isKnown = info.Name != "UNKNOWN";
        if (!isKnown) return $"[{prefix}] ID {id} Unknown";
        return $"[{prefix}] {id} {info.Name}";
    }

    public static string FullLabel(byte opcode, PacketDirection dir)
        => FullLabel((ushort)opcode, dir);

    public static void Learn(ushort id, PacketDirection dir, string name, string description = "")
    {
        var info = new OpcodeInfo(name, description, OpcodeCategory.Unknown);
        if (dir == PacketDirection.ClientToServer)
            UserCsOpcodes[id] = info;
        else
            UserScOpcodes[id] = info;
    }

    public static void Learn(byte opcode, PacketDirection dir, string name, string description = "")
        => Learn((ushort)opcode, dir, name, description);

    public static IEnumerable<(ushort id, OpcodeInfo info, bool isCs)> AllKnown()
    {
        foreach (var kv in CsOpcodes)     yield return (kv.Key, kv.Value, true);
        foreach (var kv in ScOpcodes)     yield return (kv.Key, kv.Value, false);
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

        ushort opcode = DecodePacketId(data, out int idBytes);
        sp.Opcode  = opcode;
        sp.Info    = Lookup(opcode, pkt.Direction);
        sp.Label   = FullLabel(opcode, pkt.Direction);

        // Category-specific field extraction
        // Special case: PlayerSpawn (0x02) has a known layout:
        //   [opcode 1-3B VarInt][entityId 4B][nameLen 1B or 2B][name UTF-8][xyz 12B]
        // We handle it specifically BEFORE the generic Entity extractor so
        // the extracted ID gets labeled "PlayerID" (not generic "EntityID").
        bool handledSpecially = false;

        // ── PlayerSpawn (S->C 0x02): entityId + name + XYZ ────────────
        if (sp.Opcode == 0x02 && pkt.Direction == PacketDirection.ServerToClient && data.Length >= 5)
        {
            ExtractPlayerSpawnFields(sp, data);
            handledSpecially = true;
        }

        // ── MouseInteraction (C->S 111): targetEntityId + itemInHandId ─
        else if (sp.Opcode == 111 && pkt.Direction == PacketDirection.ClientToServer && data.Length >= 5)
        {
            ExtractMouseInteractionFields(sp, data);
            handledSpecially = true;
        }

        // ── SyncInteractionChains (C->S 290): interacted entityId ──────
        else if (sp.Opcode == 290 && pkt.Direction == PacketDirection.ClientToServer && data.Length >= 5)
        {
            ExtractSyncInteractionFields(sp, data);
            handledSpecially = true;
        }

        // ── ChatMessage (C->S 211 or S->C relay): try to extract sender ─
        else if (sp.Opcode == 211 && data.Length >= 4)
        {
            ExtractChatWithSenderFields(sp, data);
            handledSpecially = true;
        }

        if (!handledSpecially)
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
        if (sp.Info.Name != "UNKNOWN")
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
        // Entity packet layouts vary. We try multiple strategies:
        //
        // Strategy A: LE uint32 at offsets 1-12 (standard 4-byte entity ID)
        // Strategy B: BE uint32 as fallback (some packets use network byte order)
        // Strategy C: uint64 at offsets 1-8 (future-proof for 8-byte IDs)
        //
        // Range: 1..16_000_000 (consistent with SmartDetect and entity coord scanner)
        // BUG FIX: was 100..9_999_999 which missed IDs 1-99 and was inconsistent.

        var seen = new HashSet<uint>();

        for (int i = 1; i + 4 <= Math.Min(data.Length, 16); i++)
        {
            // LE uint32
            uint vLe = BitConverter.ToUInt32(data, i);
            if (IdRanges.IsEntityId(vLe) && seen.Add(vLe))
            {
                var src = IdRanges.IsItemId(vLe) ? ConfidenceSource.Packet : ConfidenceSource.Inferred;
                string fldName = IdRanges.IsItemId(vLe) ? "ItemID"
                        : IdRanges.IsPlayerId(vLe) ? "PlayerID"
                        : IdRanges.IsMobId(vLe)    ? "MobID"
                        : "EntityID";
                sp.ExtractedIds.Add(new ExtractedField(fldName, vLe, i, src));
            }

            // BE uint32 (different value only)
            uint vBe = (uint)(data[i] << 24 | data[i+1] << 16 | data[i+2] << 8 | data[i+3]);
            if (vBe != vLe && IdRanges.IsEntityId(vBe) && seen.Add(vBe))
                sp.ExtractedIds.Add(new ExtractedField("EntityID(BE)", vBe, i, ConfidenceSource.Inferred));
        }

        // Strategy C: 8-byte int64 probe (covers UUID-style 64-bit entity IDs)
        // If the low 32 bits are in a plausible ID range, register it with lower confidence.
        if (data.Length >= 9)
        {
            long v64 = BitConverter.ToInt64(data, 1);
            uint low32 = (uint)(v64 & 0xFFFF_FFFF);
            if (v64 > 0 && v64 <= 4_000_000_000L && IdRanges.IsEntityId(low32)
                && seen.Add(low32))
            {
                sp.ExtractedIds.Add(new ExtractedField("EntityID(64)", low32, 1,
                    ConfidenceSource.Inferred) { Confidence = 45 });
            }
        }

        // XYZ floats - start at offset 5 (after opcode + 4-byte entity ID)
        TryExtractXYZ(sp, data, startOffset: 5);
    }

    private static void ExtractInventoryFields(StructuredPacket sp, byte[] data)
    {
        // Inventory packet layout (typical):
        //   byte 0   : opcode
        //   byte 1   : SlotIndex
        //   bytes 2-5: ItemID (uint32 LE)  -- range consistent with SmartDetect (up to 4M)
        //   byte 6   : StackSize
        //
        // BUG FIX: upper bound was 9999, missing any item ID above 9999.
        // Now uses 16_000_000 consistent with entity/SmartDetect scanning.
        if (data.Length >= 2)
        {
            byte slotIdx = data[1];
            sp.Fields.Add(new PacketFieldEx("SlotIndex", slotIdx.ToString(), 1, ConfidenceSource.Packet, 70));
        }
        for (int i = 2; i + 4 <= Math.Min(data.Length, 14); i++)
        {
            uint v = BitConverter.ToUInt32(data, i);
            if (IdRanges.IsBroadEntityId(v))
            {
                // Prefer IDs in item-likely range; use lower confidence for large IDs
                var src = IdRanges.IsItemId(v) ? ConfidenceSource.Packet : ConfidenceSource.Inferred;
                int conf = IdRanges.IsItemId(v) ? 85 : 55;
                sp.ExtractedIds.Add(new ExtractedField("ItemID", v, i, src) { Confidence = conf });
                if (i + 4 < data.Length)
                    sp.Fields.Add(new PacketFieldEx("StackSize", data[i + 4].ToString(), i + 4,
                        ConfidenceSource.Inferred, 55));
                break;
            }
        }
    }

    private static void ExtractMovementFields(StructuredPacket sp, byte[] data)
    {
        // Movement packet layout (typical):
        //   byte 0    : opcode
        //   bytes 1-4 : EntityID (uint32 LE) -- who is moving
        //   bytes 5-8 : X (float)
        //   bytes 9-12: Y (float)
        //   bytes 13-16: Z (float)
        //   bytes 17-20: Yaw (float, optional)
        //   bytes 21-24: Pitch (float, optional)
        //
        // BUG FIX: previous code called TryExtractXYZ(startOffset:1) which
        // consumed the EntityID bytes as X, losing the player/entity ID entirely.
        // Now we extract the EntityID first, then XYZ from the correct offset.

        if (data.Length >= 5)
        {
            // Try LE uint32 entity ID at offset 1
            uint entityId = BitConverter.ToUInt32(data, 1);
            if (entityId >= 1 && entityId <= 16_000_000)
            {
                sp.ExtractedIds.Add(new ExtractedField("EntityID", entityId, 1,
                    ConfidenceSource.Packet));
                // XYZ starts after the entity ID
                TryExtractXYZ(sp, data, startOffset: 5);
            }
            else
            {
                // No valid entity ID at offset 1 - fall back to scanning
                // Try BE uint32 as alternative
                uint entityIdBe = (uint)(data[1] << 24 | data[2] << 16 | data[3] << 8 | data[4]);
                if (entityIdBe >= 1 && entityIdBe <= 16_000_000)
                {
                    sp.ExtractedIds.Add(new ExtractedField("EntityID", entityIdBe, 1,
                        ConfidenceSource.Inferred));
                    TryExtractXYZ(sp, data, startOffset: 5);
                }
                else
                {
                    // Fallback: XYZ might start at offset 1 (no entity ID prefix)
                    TryExtractXYZ(sp, data, startOffset: 1);
                }
            }
        }

        // Yaw + pitch after XYZ block (if position was found)
        if (sp.Position.HasValue && data.Length >= 21)
        {
            // Yaw is 4 bytes after the 12-byte XYZ block (starting at 5+12=17)
            float yaw = BitConverter.ToSingle(data, Math.Min(17, data.Length - 4));
            if (!float.IsNaN(yaw) && yaw >= -360f && yaw <= 360f)
                sp.Fields.Add(new PacketFieldEx("Yaw", $"{yaw:F1}", 17, ConfidenceSource.Inferred, 60));
        }
    }

    /// <summary>
    /// MouseInteraction (C->S ID 111) layout (observed from hytalemodding.dev):
    ///   [VarInt opcode (111) = 0x6F, 1 byte]
    ///   bytes 1-4 : targetEntityId (uint32 LE)  — entity/item the crosshair is on
    ///   byte  5   : interactionType (0=Primary/left, 1=Secondary/right, 2=Use/F)
    ///   bytes 6-9 : itemInHandId (uint32 LE)    — item currently held by the player
    /// </summary>
    private static void ExtractMouseInteractionFields(StructuredPacket sp, byte[] data)
    {
        // ── Target entity (what cursor is pointing at) ─────────────────
        if (data.Length >= 5)
        {
            uint targetId = BitConverter.ToUInt32(data, 1);
            if (IdRanges.IsBroadEntityId(targetId))
            {
                sp.ExtractedIds.Add(new ExtractedField("TargetEntityId", targetId, 1,
                    ConfidenceSource.Packet) { Confidence = 88 });
                sp.Fields.Add(new PacketFieldEx("TargetEntityId", targetId.ToString(), 1,
                    ConfidenceSource.Packet, 88));
            }
        }

        // ── Interaction type ───────────────────────────────────────────
        if (data.Length >= 6)
        {
            string iType = data[5] switch { 0 => "Primary", 1 => "Secondary", 2 => "Use", _ => $"{data[5]}" };
            sp.Fields.Add(new PacketFieldEx("InteractionType", iType, 5, ConfidenceSource.Packet, 80));
        }

        // ── Item in hand ───────────────────────────────────────────────
        if (data.Length >= 10)
        {
            uint itemInHand = BitConverter.ToUInt32(data, 6);
            if (IdRanges.IsBroadEntityId(itemInHand))
            {
                sp.ExtractedIds.Add(new ExtractedField("ItemInHandId", itemInHand, 6,
                    ConfidenceSource.Packet) { Confidence = 82 });
                sp.Fields.Add(new PacketFieldEx("ItemInHandId", itemInHand.ToString(), 6,
                    ConfidenceSource.Packet, 82));
            }
        }
    }

    /// <summary>
    /// SyncInteractionChains (C->S ID 290): carries one or more interaction chains.
    /// Each chain starts with an entityId (uint32 LE) describing the interaction target.
    /// Layout is not fully documented; we scan for any valid entity IDs in the payload.
    /// </summary>
    private static void ExtractSyncInteractionFields(StructuredPacket sp, byte[] data)
    {
        // Try offset 1 first (most likely), then scan wider
        for (int off = 1; off + 4 <= Math.Min(data.Length, 16); off++)
        {
            uint id = BitConverter.ToUInt32(data, off);
            if (IdRanges.IsBroadEntityId(id))
            {
                sp.ExtractedIds.Add(new ExtractedField("InteractionTarget", id, off,
                    ConfidenceSource.Packet) { Confidence = 78 });
                sp.Fields.Add(new PacketFieldEx("InteractionTarget", id.ToString(), off,
                    ConfidenceSource.Packet, 78));
                break;  // first valid ID is sufficient
            }
        }
    }

    /// <summary>
    /// ChatMessage (211) – try to extract a sender username that precedes the message.
    /// Hytale chat packets observed layout variants:
    ///   Variant A (C->S player send): [opcode][msgLen VarInt][UTF-8 message]
    ///   Variant B (S->C relay):       [opcode][senderLen byte][senderUTF8][msgLen][msg]
    /// We try both; a valid sender name must be 3-32 chars alphanumeric/underscore.
    /// </summary>
    private static void ExtractChatWithSenderFields(StructuredPacket sp, byte[] data)
    {
        if (data.Length < 4) return;

        // ── Variant B: first byte after opcode = sender name length ───
        byte possibleSenderLen = data[1];
        if (possibleSenderLen >= 3 && possibleSenderLen <= 32
            && 2 + possibleSenderLen < data.Length)
        {
            try
            {
                string sender = System.Text.Encoding.UTF8
                    .GetString(data, 2, possibleSenderLen).Trim();
                // Validate: alphanumeric + underscore, starts with letter
                if (sender.Length >= 3
                    && char.IsLetter(sender[0])
                    && sender.All(c => char.IsLetterOrDigit(c) || c == '_')
                    && sender.Any(c => "aeiouAEIOU".Contains(c) || char.IsDigit(c)))
                {
                    sp.Fields.Add(new PacketFieldEx("SenderName", sender, 2,
                        ConfidenceSource.Packet, 82));

                    // Rest of packet = message
                    int msgOff = 2 + possibleSenderLen;
                    if (msgOff + 1 < data.Length)
                    {
                        string msg = System.Text.Encoding.UTF8
                            .GetString(data, msgOff, data.Length - msgOff)
                            .Replace("\0", "").Trim();
                        if (msg.Length > 0)
                            sp.Fields.Add(new PacketFieldEx("Message", msg, msgOff,
                                ConfidenceSource.Packet, 75));
                    }
                    return;
                }
            }
            catch { }
        }

        // ── Variant A: plain message, no sender prefix ─────────────────
        try
        {
            string text = System.Text.Encoding.UTF8
                .GetString(data, 1, data.Length - 1)
                .Replace("\0", "").Trim();
            if (text.Length > 0 && text.Length <= 256)
                sp.Fields.Add(new PacketFieldEx("Message", text, 1,
                    ConfidenceSource.Packet, 65));
        }
        catch { }
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

    /// <summary>
    /// Extract fields from a S->C PlayerSpawn (0x02) packet.
    ///
    /// Hytale alpha PlayerSpawn layout (observed):
    ///   byte  0    : opcode (0x02)
    ///   bytes 1-4  : entityId (uint32 LE)  -- THE PLAYER ENTITY ID
    ///   byte  5    : name length (uint8)
    ///   bytes 6..  : player name (UTF-8, name_len bytes)
    ///   bytes after: X, Y, Z (3x float32 LE)
    ///
    /// BUG FIX: previously ExtractEntityFields was called which looped over all
    /// 4-byte windows including the name bytes, producing garbage IDs.
    /// Now we parse the specific layout: read ID first, skip the string, then XYZ.
    /// </summary>
    private static void ExtractPlayerSpawnFields(StructuredPacket sp, byte[] data)
    {
        // ── PlayerID at offset 1 ──────────────────────────────────────────
        uint entityId = BitConverter.ToUInt32(data, 1);
        if (IdRanges.IsEntityId(entityId))
        {
            sp.ExtractedIds.Add(new ExtractedField("PlayerID", entityId, 1,
                ConfidenceSource.Packet) { Confidence = 90 });
            sp.Fields.Add(new PacketFieldEx("PlayerID", entityId.ToString(), 1,
                ConfidenceSource.Packet, 90));
        }

        // ── Try to read player name ───────────────────────────────────────
        // Layout variant A: byte 5 = name length (0-63)
        int xyzStart = 5;
        if (data.Length >= 7)
        {
            byte nameLen = data[5];
            if (nameLen > 0 && nameLen <= 64 && 6 + nameLen <= data.Length)
            {
                string playerName = System.Text.Encoding.UTF8.GetString(data, 6, nameLen).Trim();
                if (playerName.Length >= 3 && playerName.All(c => char.IsLetterOrDigit(c) || c == '_'))
                {
                    sp.Fields.Add(new PacketFieldEx("PlayerName", playerName, 6,
                        ConfidenceSource.Packet, 85));
                    xyzStart = 6 + nameLen;
                }
            }
        }

        // ── XYZ after name ────────────────────────────────────────────────
        TryExtractXYZ(sp, data, xyzStart);
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
            if (IdRanges.IsBroadEntityId(v))
                sp.ExtractedIds.Add(new ExtractedField("ItemID", v, i, ConfidenceSource.Inferred));
        }
    }

    private static void ExtractGenericFields(StructuredPacket sp, byte[] data)
    {
        // Scan first 20 bytes for entity IDs (both byte orders).
        var seen = new HashSet<uint>();
        for (int i = 1; i + 4 <= Math.Min(data.Length, 20); i++)
        {
            uint vLe = BitConverter.ToUInt32(data, i);
            if (IdRanges.IsEntityId(vLe) && seen.Add(vLe))
                sp.ExtractedIds.Add(new ExtractedField("ID?", vLe, i, ConfidenceSource.Uncertain));

            uint vBe = (uint)(data[i] << 24 | data[i+1] << 16 | data[i+2] << 8 | data[i+3]);
            if (vBe != vLe && IdRanges.IsEntityId(vBe) && seen.Add(vBe))
                sp.ExtractedIds.Add(new ExtractedField("ID?(BE)", vBe, i, ConfidenceSource.Uncertain));
        }
        // NOTE: Display name extraction is NOT done here.
        // ProcessAutoNaming in SmartDetect handles name extraction from the full UTF-8
        // payload window, with proper quality gates. Doing it here caused false positives:
        // any 3-byte sequence after a coincidental length byte was treated as a name,
        // flooding the Packet Book with garbage like "QAI", "EurLnM", "Wl7oHk".
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
    public ushort           Opcode           { get; set; }
    public OpcodeInfo       Info             { get; set; } = new("UNKNOWN", "", OpcodeCategory.Unknown);
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
    public string           Name         { get; }
    public uint             Value        { get; }
    public int              Offset       { get; }
    public ConfidenceSource Source       { get; }
    public int              Confidence   { get; set; }   // 0-100, default from Source
    public string?          ResolvedName { get; set; }   // filled by EntityTracker

    public ExtractedField(string name, uint value, int offset, ConfidenceSource src)
    {
        Name       = name;
        Value      = value;
        Offset     = offset;
        Source     = src;
        Confidence = src switch
        {
            ConfidenceSource.Memory    => 95,
            ConfidenceSource.Packet    => 80,
            ConfidenceSource.Inferred  => 55,
            _                          => 30,
        };
    }
}
