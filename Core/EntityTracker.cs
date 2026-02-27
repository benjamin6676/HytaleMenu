using System.Collections.Concurrent;
using System.Numerics;

namespace HytaleSecurityTester.Core;

/// <summary>
/// EntityTracker - Cross-packet ID lifecycle tracker.
///
/// Connects IDs seen in packets to their history, movement, state changes,
/// and resolved names.  Feeds the Item Inspector name column, ESP overlay,
/// and confidence scoring.
///
/// Each TrackedEntity holds:
///   - Current XYZ (updated from movement packets)
///   - First / last seen timestamps
///   - Packet history (ring buffer, last 64 packets)
///   - EntityClass (Item / Player / Unknown) with confidence score
///   - Owner chain: ActorID -> UID -> PlayerName
///   - Delta map: per-field min/max across lifetime
///   - FlaggedEvents: out-of-order ACKs, desync, authority leak detections
///
/// Designed for high-throughput: all writes are lock-free via ConcurrentDictionary.
/// UI reads take .ToArray() snapshots - never iterates live dictionaries.
/// </summary>
public class EntityTracker
{
    // ── Singleton ─────────────────────────────────────────────────────────
    public static readonly EntityTracker Instance = new();
    private EntityTracker() { }

    // ── Active entity table ───────────────────────────────────────────────
    public ConcurrentDictionary<uint, TrackedEntity> Entities { get; } = new();

    // ── Slot-to-Instance map (for container desync detection) ─────────────
    // slot -> (itemId, lastSeen)
    private readonly ConcurrentDictionary<int, (uint itemId, DateTime ts)> _slotMap = new();

    // ── Last N move/interaction events (for timeline) ─────────────────────
    private readonly ConcurrentQueue<EntityEvent> _eventQueue = new();
    private const int MaxEvents = 500;

    public IReadOnlyCollection<EntityEvent> RecentEvents
    {
        get
        {
            var snap = _eventQueue.ToArray();
            return snap;
        }
    }

    // ── Core update entry points ──────────────────────────────────────────

    /// <summary>
    /// Called by SmartDetectionEngine for every processed packet.
    /// Updates entity state from a structured packet.
    /// </summary>
    public void ProcessStructuredPacket(StructuredPacket sp)
    {
        if (sp.Raw.IsMarker) return;

        foreach (var field in sp.ExtractedIds)
        {
            var entity = GetOrCreate(field.Value);
            entity.LastSeen   = sp.Raw.Timestamp;
            entity.PacketCount++;

            // Apply position if available
            if (sp.Position.HasValue)
            {
                var prev = entity.Position;
                entity.Position = sp.Position.Value;

                if (prev.HasValue)
                {
                    float dist = Vector3.Distance(prev.Value, sp.Position.Value);
                    if (dist > 0.01f)
                    {
                        entity.TotalDistanceMoved += dist;
                        entity.MoveCount++;
                        if (dist > 0.5f)
                            entity.EntityClass = EntityClass.Player; // moving -> likely player
                    }
                }

                AddEvent(entity.Id, EntityEventType.Move,
                    $"({sp.Position.Value.X:F1},{sp.Position.Value.Y:F1},{sp.Position.Value.Z:F1})",
                    sp.Raw.Timestamp, sp.ConfidenceScore);
            }

            // Classify from opcode category
            if (sp.Info.Name != "UNKNOWN") // Lookup now returns non-null sentinel
            {
                entity.EntityClass = sp.Info.Category switch
                {
                    OpcodeCategory.Item      => EntityClass.Item,
                    OpcodeCategory.Inventory => EntityClass.Item,
                    // BUG FIX: Entity packets with movement = could be Player or Mob.
                    // Use move frequency to disambiguate (matches SmartDetect logic).
                    OpcodeCategory.Entity when entity.MoveCount > 10 => EntityClass.Player,
                    OpcodeCategory.Entity when entity.MoveCount > 3  => EntityClass.Mob,
                    _ => entity.EntityClass,
                };
            }

            // Resolve name from shared stores (in priority order)
            if (string.IsNullOrEmpty(entity.Name))
            {
                // 1. Registry (highest: from server's own item table)
                if (RegistrySyncParser.NumericIdToName.TryGetValue(field.Value, out var regName)
                    && !string.IsNullOrEmpty(regName))
                {
                    entity.Name           = regName;
                    entity.NameConfidence = 100;
                    entity.NameSource     = ConfidenceSource.Packet;
                }
                // 2. GlobalConfig (persisted manual names + auto-named names)
                else
                {
                    var cfgName = GlobalConfig.Instance.GetName(field.Value);
                    if (!string.IsNullOrEmpty(cfgName))
                    {
                        entity.Name           = cfgName;
                        entity.NameConfidence = 80;
                        entity.NameSource     = ConfidenceSource.Packet;
                    }
                }
            }

            // Back-fill field's ResolvedName
            if (!string.IsNullOrEmpty(entity.Name))
                field.ResolvedName = entity.Name;

            // Track packet in ring buffer
            entity.AddPacketRef((byte)sp.Opcode, sp.Raw.Timestamp);
        }

        // ── Propagate PlayerName / SenderName from packet fields ──────────
        // OpcodeRegistry.Decode() extracts these from PlayerSpawn (0x02),
        // ChatMessage (211) and similar packets. Push them into the entity
        // so the name shows properly in Item Inspector and the ESP overlay.
        var nameField = sp.Fields.FirstOrDefault(f =>
            f.Name == "PlayerName" || f.Name == "SenderName");
        if (nameField != null && !string.IsNullOrEmpty(nameField.Value))
        {
            // Cross-reference: find the entity ID extracted from the same packet
            foreach (var idf in sp.ExtractedIds)
            {
                var ent = GetOrCreate(idf.Value);
                if (string.IsNullOrEmpty(ent.Name) ||
                    ent.NameConfidence < nameField.Score)
                {
                    ent.Name           = nameField.Value;
                    ent.NameConfidence = nameField.Score;
                    ent.NameSource     = ConfidenceSource.Packet;
                    ent.EntityClass    = EntityClass.Player;
                    idf.ResolvedName   = nameField.Value;
                }
            }
        }

        // Slot-map update for container desync detection
        ProcessSlotMapUpdate(sp);
    }

    /// <summary>Public accessor for GetOrCreate – lets SmartDetect push names in.</summary>
    public TrackedEntity? GetOrCreatePublic(uint id)
    {
        if (id == 0 || id > 16_000_000) return null;
        return GetOrCreate(id);
    }

    /// <summary>
    /// Register a manual name from context menu / ManuallyNameId.
    /// </summary>
    public void RegisterName(uint id, string name, ConfidenceSource source)
    {
        var entity = GetOrCreate(id);
        entity.Name              = name;
        entity.NameConfidence    = source == ConfidenceSource.Memory ? 100
                                 : source == ConfidenceSource.Packet  ? 80
                                 : source == ConfidenceSource.Inferred ? 55 : 30;
        entity.NameSource        = source;
    }

    /// <summary>
    /// Called when AOB scan resolves a memory address.
    /// Entities whose IDs are read directly from RAM get Memory-level confidence.
    /// </summary>
    public void RegisterMemoryConfirmed(uint id, string name)
    {
        RegisterName(id, name, ConfidenceSource.Memory);
        if (Entities.TryGetValue(id, out var e))
        {
            e.MemoryConfirmed = true;
            AddEvent(id, EntityEventType.MemoryConfirm, $"RAM confirmed: {name}", DateTime.Now, 100);
        }
    }

    // ── Desync / Authority Leak detection ─────────────────────────────────

    /// <summary>
    /// Check if a container move packet claims to move an item from a slot
    /// the server should know is empty.  Flags as DesyncVulnerability.
    /// </summary>
    public bool CheckDesync(int slot, uint claimedItemId, DateTime ts)
    {
        if (!_slotMap.TryGetValue(slot, out var recorded)) return false;
        if (recorded.itemId != claimedItemId)
        {
            var entity = GetOrCreate(claimedItemId);
            entity.FlaggedEvents.Add(new FlaggedEvent
            {
                Type        = FlagType.DesyncVulnerability,
                Description = $"Slot {slot} expected ID {recorded.itemId}, got {claimedItemId}",
                Timestamp   = ts,
                Confidence  = 82,
            });
            return true;
        }
        return false;
    }

    public void UpdateSlot(int slot, uint itemId, DateTime ts)
        => _slotMap[slot] = (itemId, ts);

    // ── Snapshot helpers for UI ───────────────────────────────────────────

    public TrackedEntity[] GetSnapshot()     => Entities.Values.ToArray();
    public TrackedEntity[] GetPlayers()      => Entities.Values.Where(e => e.EntityClass == EntityClass.Player).ToArray();
    public TrackedEntity[] GetItems()        => Entities.Values.Where(e => e.EntityClass == EntityClass.Item).ToArray();
    public TrackedEntity[] GetMobs()         => Entities.Values.Where(e => e.EntityClass == EntityClass.Mob).ToArray();   // BUG FIX: was missing
    public TrackedEntity[] GetFlagged()      => Entities.Values.Where(e => e.FlaggedEvents.Count > 0).ToArray();

    // ── Internals ─────────────────────────────────────────────────────────

    private TrackedEntity GetOrCreate(uint id)
        => Entities.GetOrAdd(id, k => new TrackedEntity(k));

    private void ProcessSlotMapUpdate(StructuredPacket sp)
    {
        if (sp.Info.Category != OpcodeCategory.Inventory) return;
        var slotField = sp.Fields.FirstOrDefault(f => f.Name == "SlotIndex");
        var itemField = sp.ExtractedIds.FirstOrDefault(f => f.Name == "ItemID");
        if (slotField == null || itemField == null) return;
        if (int.TryParse(slotField.Value, out int slot))
        {
            CheckDesync(slot, itemField.Value, sp.Raw.Timestamp);
            UpdateSlot(slot, itemField.Value, sp.Raw.Timestamp);
        }
    }

    private void AddEvent(uint id, EntityEventType type, string detail, DateTime ts, int confidence)
    {
        var ev = new EntityEvent
        {
            EntityId   = id,
            Type       = type,
            Detail     = detail,
            Timestamp  = ts,
            Confidence = confidence,
        };
        _eventQueue.Enqueue(ev);
        while (_eventQueue.Count > MaxEvents && _eventQueue.TryDequeue(out _)) { }
    }
}

// ── Data types ────────────────────────────────────────────────────────────────

public class TrackedEntity
{
    private const int RingSize = 64;
    private readonly (byte opcode, DateTime ts)[] _ring = new (byte, DateTime)[RingSize];
    private int _ringHead;

    public uint         Id                  { get; }
    public string       Name                { get; set; } = "";
    public int          NameConfidence      { get; set; }   // 0-100
    public ConfidenceSource NameSource      { get; set; } = ConfidenceSource.Uncertain;
    public EntityClass  EntityClass         { get; set; } = EntityClass.Unknown;
    public Vector3?     Position            { get; set; }
    public DateTime     FirstSeen           { get; set; }
    public DateTime     LastSeen            { get; set; }
    public int          PacketCount         { get; set; }
    public int          MoveCount           { get; set; }
    public float        TotalDistanceMoved  { get; set; }
    public bool         MemoryConfirmed     { get; set; }
    public string       OwnerActorId        { get; set; } = "";
    public string       OwnerPlayerName     { get; set; } = "";
    public List<FlaggedEvent> FlaggedEvents { get; } = new();

    public string ClassLabel => EntityClass switch
    {
        EntityClass.Player  => "[P]",
        EntityClass.Mob     => "[M]",   // BUG FIX: was missing, mobs showed as [?]
        EntityClass.Item    => "[I]",
        _                   => "[?]",
    };

    public string ConfidenceLabel
    {
        get
        {
            if (MemoryConfirmed) return "[MEM]";
            return NameConfidence switch
            {
                >= 85 => "[PKT]",
                >= 55 => "[INF]",
                _     => "[UNK]",
            };
        }
    }

    public System.Numerics.Vector4 ConfidenceColor => (MemoryConfirmed ? 100 : NameConfidence) switch
    {
        >= 85 => MenuRenderer.ColAccent,
        >= 65 => MenuRenderer.ColAccentMid,
        >= 40 => MenuRenderer.ColWarn,
        _     => MenuRenderer.ColDanger,
    };

    public TrackedEntity(uint id)
    {
        Id        = id;
        FirstSeen = DateTime.Now;
        LastSeen  = DateTime.Now;
    }

    public void AddPacketRef(byte opcode, DateTime ts)
    {
        _ring[_ringHead % RingSize] = (opcode, ts);
        _ringHead++;
    }

    public (byte opcode, DateTime ts)[] GetRecentPackets()
    {
        int count = Math.Min(_ringHead, RingSize);
        var result = new (byte, DateTime)[count];
        for (int i = 0; i < count; i++)
            result[i] = _ring[(_ringHead - count + i) % RingSize];
        return result;
    }
}

public class FlaggedEvent
{
    public FlagType  Type        { get; set; }
    public string    Description { get; set; } = "";
    public DateTime  Timestamp   { get; set; }
    public int       Confidence  { get; set; }
}

public enum FlagType { DesyncVulnerability, AuthorityLeak, OutOfOrderAck, DuplicateMove, Suspicious }

public class EntityEvent
{
    public uint            EntityId   { get; set; }
    public EntityEventType Type       { get; set; }
    public string          Detail     { get; set; } = "";
    public DateTime        Timestamp  { get; set; }
    public int             Confidence { get; set; }
}

public enum EntityEventType { Spawn, Move, SlotChange, NameResolved, MemoryConfirm, Flagged, Despawn }
