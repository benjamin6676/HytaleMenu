using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Smart Detection Engine — runs entirely on a dedicated background thread.
///
/// The UI thread NEVER calls any detection logic directly; it only reads
/// from the thread-safe output collections below. All writes from the
/// background thread go through ConcurrentDictionary or lock-guarded lists.
///
/// Features implemented:
///   · Sequence Correlation  — uint32 followed by byte 1–64 → Confirmed Item + Stack
///   · Input Mirroring       — watches C→S Drop/Interact packets for unknown IDs
///   · Entity Delta Tracking — IDs with changing X/Y/Z coords → Active Entity list
///   · Automatic Naming      — strings within 16 bytes of an ID → Book auto-save
///   · 0x4A Dedicated Parser — extracts Player/Entity ID at bytes 1–4
///   · String Correlation    — short metadata strings linked to co-occurring Item IDs
///   · High-Confidence Auto-Pin — HIGH★ IDs saved to Book automatically
///   · Delta Watcher         — static vs. dynamic value classification
///   · Purge Old Entities    — entities unseen for >30 s are removed automatically
/// </summary>
public class SmartDetectionEngine : IDisposable
{
    // ── Inputs (injected) ─────────────────────────────────────────────────
    private readonly PacketCapture _capture;
    private readonly PacketStore   _store;
    private readonly TestLog       _log;
    private readonly ServerConfig  _config;

    // ── Background thread ─────────────────────────────────────────────────
    private readonly CancellationTokenSource _cts = new();
    private readonly Thread                  _thread;

    // ── Confirmed Item IDs (Sequence Correlation) ─────────────────────────
    // key = itemId, value = (stackSize, firstSeen, packetCount)
    public ConcurrentDictionary<uint, ConfirmedItem> ConfirmedItems { get; } = new();

    // ── Input Mirroring suggestion ────────────────────────────────────────
    // The most recent unknown ID found in a Drop/Interact C→S packet
    private volatile uint   _suggestedTargetId = 0;
    private volatile string _suggestedSource   = "";
    public uint   SuggestedTargetId => _suggestedTargetId;
    public string SuggestedSource   => _suggestedSource;
    public bool   HasSuggestion     => _suggestedTargetId > 0;

    // ── Active Entities (Delta Tracking) ──────────────────────────────────
    // key = entityId, value = tracking entry
    public ConcurrentDictionary<uint, TrackedEntity> ActiveEntities { get; } = new();

    // ── String ↔ ItemID correlation table ─────────────────────────────────
    // key = metaString, value = most-correlated ItemId
    public ConcurrentDictionary<string, uint> StringCorrelation { get; } = new();

    // ── ID → Name mapping (auto-naming from nearby UTF-8 strings) ─────────
    // key = uint ID, value = discovered name
    public ConcurrentDictionary<uint, string> IdNameMap { get; } = new();

    // ── 0x4A parsed entities ──────────────────────────────────────────────
    public ConcurrentDictionary<uint, Pkt4AEntry> Pkt4AEntities { get; } = new();

    // ── Delta Watcher: static vs dynamic classification ───────────────────
    // key = ID, value = classification
    public ConcurrentDictionary<uint, DeltaClass> DeltaClassifications { get; } = new();

    // ── Auto-pin tracking (IDs already saved to Book) ─────────────────────
    private readonly ConcurrentDictionary<uint, bool> _autoPinned = new();

    // ── Internal state (background thread only — no lock needed) ──────────
    private int   _lastProcessedCount = 0;

    // For delta watcher: id → observed values ring buffer (last 16)
    private readonly Dictionary<uint, RingBuffer16> _deltaHistory = new();

    // For string correlation: (metaStr, pktHash) seen pairings
    private readonly Dictionary<string, Dictionary<uint, int>> _strItemCoOccur = new();

    // For entity coord tracking: id → recent float triplets
    // _coordLock guards _coordHistory as it is accessed from both background
    // thread (every 150ms) and potentially from the UI thread via PurgeStaleEntities().
    private readonly object _coordLock = new();
    private readonly Dictionary<uint, List<(float x, float y, float z, DateTime t)>> _coordHistory = new();

    // For Sequence Correlation pre-screening: id → list of (timestamp, packetIndex)
    // We require an ID to appear in ≥2 DIFFERENT packets before it enters ConfirmedItems.
    private readonly Dictionary<uint, HashSet<int>> _seqPreScreen = new();

    // ─────────────────────────────────────────────────────────────────────

    public SmartDetectionEngine(PacketCapture capture, PacketStore store,
                                  TestLog log, ServerConfig config)
    {
        _capture = capture;
        _store   = store;
        _log     = log;
        _config  = config;

        _thread = new Thread(BackgroundLoop)
        {
            Name         = "SmartDetection",
            IsBackground = true,
            Priority     = ThreadPriority.BelowNormal,  // never starve the UI
        };
        _thread.Start();
    }

    // ── Background loop ───────────────────────────────────────────────────

    private void BackgroundLoop()
    {
        _log.Info("[SmartDetect] Background engine started.");

        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var packets = _capture.GetPackets();

                if (packets.Count > _lastProcessedCount)
                {
                    // Only process newly arrived packets since last pass
                    var newPkts = packets.Skip(_lastProcessedCount).ToList();
                    int baseIdx = _lastProcessedCount;
                    _lastProcessedCount = packets.Count;

                    for (int pi = 0; pi < newPkts.Count; pi++)
                        ProcessPacket(newPkts[pi], baseIdx + pi);
                }

                // Periodic maintenance (every cycle, cheap)
                PurgeStaleEntities();
            }
            catch (Exception ex) when (!(ex is OperationCanceledException))
            {
                // Never crash the background thread — log and continue
                _log.Error($"[SmartDetect] Error: {ex.Message}");
            }

            // Yield for ~150ms — fine-grained enough for real-time feel
            // without burning CPU on an idle session
            Thread.Sleep(150);
        }

        _log.Info("[SmartDetect] Background engine stopped.");
    }

    // ── Per-packet processing ─────────────────────────────────────────────

    private void ProcessPacket(CapturedPacket pkt, int pktIndex)
    {
        var data = pkt.RawBytes;
        if (data.Length < 2) return;

        bool cs = pkt.Direction == PacketDirection.ClientToServer;

        // ── 1. Dedicated 0x4A parser ───────────────────────────────────────
        if (data[0] == 0x4A && data.Length >= 5)
            Process0x4A(data, pkt.Timestamp);

        // ── 2. Sequence Correlation: uint32 → byte 1–64 ───────────────────
        ProcessSequenceCorrelation(data, pkt.Timestamp, pktIndex);

        // ── 3. Input Mirroring: C→S Drop/Interact packets ─────────────────
        if (cs) ProcessInputMirroring(data[0], data);

        // ── 4. Entity Delta Tracking: floats that look like coords ────────
        ProcessEntityCoords(data, pkt.Timestamp);

        // ── 5. Automatic Naming: strings near IDs ─────────────────────────
        ProcessAutoNaming(data);

        // ── 6. String Correlation: metadata strings + item IDs ────────────
        ProcessStringCorrelation(data);

        // ── 7. Delta Watcher: static vs dynamic IDs ───────────────────────
        ProcessDeltaWatcher(data);

        // ── 8. High-Confidence Auto-Pin: save HIGH IDs to Book ────────────
        // (called after AggregateAcrossPackets updates _discovered, which we
        //  don't own here — instead we check ConfirmedItems and known-high IDs)
        AutoPinHighConfidenceItems();
    }

    // ── Feature 1: 0x4A dedicated parser ─────────────────────────────────

    private void Process0x4A(byte[] data, DateTime ts)
    {
        // Layout assumption: [0x4A][4-byte primary entity ID][4-byte secondary entity ID?][...rest]
        uint primaryId = BitConverter.ToUInt32(data, 1);

        // Sanity-check: entity IDs typically 1 000 – 4 000 000
        if (primaryId < 1_000 || primaryId > 4_000_000) return;

        AddOrUpdate4AEntry(primaryId, ts);

        // Parse optional secondary entity field at bytes 5–8
        if (data.Length >= 9)
        {
            uint secondaryId = BitConverter.ToUInt32(data, 5);
            if (secondaryId >= 1_000 && secondaryId <= 4_000_000 && secondaryId != primaryId)
                AddOrUpdate4AEntry(secondaryId, ts);
        }

        // Scan remaining bytes for a UTF-8 name hint
        if (data.Length > 9 && !IdNameMap.ContainsKey(primaryId))
        {
            int scanStart = Math.Min(9, data.Length);
            string suffix = Encoding.UTF8.GetString(data, scanStart, data.Length - scanStart)
                .Replace("\0", " ");

            var m = ItemNameRx.Match(suffix);
            if (m.Success)
            {
                IdNameMap[primaryId] = m.Value;
                _log.Info($"[SmartDetect] 0x4A name hint: {primaryId} → '{m.Value}'");
            }
        }
    }

    private void AddOrUpdate4AEntry(uint entityId, DateTime ts) =>
        Pkt4AEntities.AddOrUpdate(entityId,
            _ => new Pkt4AEntry { EntityId = entityId, FirstSeen = ts, LastSeen = ts, PacketCount = 1 },
            (_, ex) => { ex.LastSeen = ts; ex.PacketCount++; return ex; });

    // ── Feature 2: Sequence Correlation ──────────────────────────────────

    private void ProcessSequenceCorrelation(byte[] data, DateTime ts, int pktIndex)
    {
        // Scan every 4-byte window; if uint32 is in item-ID range (100–9999)
        // AND the immediately following byte is 1–64 → candidate for Confirmed Item + Stack.
        // To prevent false-positives, an ID must appear in ≥2 DIFFERENT packets before
        // it is added to ConfirmedItems (pre-screen buffer).
        for (int i = 1; i + 4 < data.Length; i++)
        {
            uint v = BitConverter.ToUInt32(data, i);
            if (v < 100 || v > 9_999) continue;

            byte nextByte = data[i + 4];
            if (nextByte < 1 || nextByte > 64) continue;

            byte prevByte = i > 0 ? data[i - 1] : (byte)255;
            int  slot     = prevByte <= 63 ? prevByte : 0;

            // Pre-screen: record which packet indices this ID has appeared in
            if (!_seqPreScreen.TryGetValue(v, out var seen))
                _seqPreScreen[v] = seen = new HashSet<int>();
            seen.Add(pktIndex);

            // Only confirm once seen in ≥2 distinct packets
            if (seen.Count < 2) continue;

            ConfirmedItems.AddOrUpdate(v,
                _ => new ConfirmedItem
                {
                    ItemId     = v,
                    StackSize  = nextByte,
                    SlotIndex  = (byte)slot,
                    FirstSeen  = ts,
                    LastSeen   = ts,
                    PacketCount = 1,
                    NameHint   = IdNameMap.TryGetValue(v, out var n) ? n : "",
                },
                (_, ex) =>
                {
                    ex.LastSeen    = ts;
                    ex.PacketCount++;
                    ex.StackSize   = nextByte;
                    if (IdNameMap.TryGetValue(v, out var nm)) ex.NameHint = nm;
                    return ex;
                });
        }
    }

    // ── Feature 3: Input Mirroring ────────────────────────────────────────

    // Packet IDs heuristically associated with Drop / Interact actions
    private static readonly HashSet<byte> DropInteractIds = new()
    {
        0x07, // Drop Item
        0x08, // Pick Up Item
        0x20, // Entity Interact
        0x21, // Entity Attack
        0x22, // Entity Use
        0x04, // Player Action (generic)
        0x06, // Use Item
    };

    private void ProcessInputMirroring(byte pktId, byte[] data)
    {
        if (!DropInteractIds.Contains(pktId)) return;
        if (data.Length < 5) return;

        // First uint32 after header = candidate ID
        uint candidateId = BitConverter.ToUInt32(data, 1);

        // Must be in a meaningful ID range, not already the active target,
        // and not already a confirmed item (we want unknown IDs)
        bool alreadyKnown  = ConfirmedItems.ContainsKey(candidateId);
        bool isActiveTarget = _config.HasTargetItem && (uint)_config.TargetItemId == candidateId;

        if (!alreadyKnown && !isActiveTarget &&
            candidateId >= 100 && candidateId <= 4_000_000)
        {
            string src = pktId switch
            {
                0x07 => "Drop packet (0x07)",
                0x08 => "Pick-Up packet (0x08)",
                0x20 => "Entity Interact (0x20)",
                0x21 => "Entity Attack (0x21)",
                0x22 => "Entity Use (0x22)",
                0x06 => "Use Item (0x06)",
                _    => $"C→S 0x{pktId:X2}",
            };

            // Only update suggestion if it changed to avoid noisy log spam
            if (_suggestedTargetId != candidateId)
            {
                _suggestedTargetId = candidateId;
                _suggestedSource   = src;
                _log.Info($"[SmartDetect] Input Mirror → suggested ID {candidateId} from {src}");
            }
        }
    }

    // ── Feature 4: Entity Delta / Coord tracking ──────────────────────────

    private void ProcessEntityCoords(byte[] data, DateTime ts)
    {
        if (data.Length < 13) return;

        for (int i = 1; i + 16 <= data.Length; i++)
        {
            uint candidate = BitConverter.ToUInt32(data, i);
            if (candidate < 1_000 || candidate > 4_000_000) continue;

            float x = BitConverter.ToSingle(data, i + 4);
            float y = BitConverter.ToSingle(data, i + 8);
            float z = BitConverter.ToSingle(data, i + 12);

            if (!IsPlausibleCoord(x) || !IsPlausibleCoord(y) || !IsPlausibleCoord(z))
                continue;

            // Record coord history for this ID — locked because PurgeStaleEntities
            // may be called from the UI thread at the same time.
            float maxDelta;
            lock (_coordLock)
            {
                if (!_coordHistory.TryGetValue(candidate, out var history))
                    _coordHistory[candidate] = history = new List<(float, float, float, DateTime)>();

                history.Add((x, y, z, ts));
                if (history.Count > 32) history.RemoveAt(0);

                if (history.Count < 3) continue;

                maxDelta = 0f;
                for (int k = 1; k < history.Count; k++)
                {
                    float dx = history[k].x - history[k-1].x;
                    float dy = history[k].y - history[k-1].y;
                    float dz = history[k].z - history[k-1].z;
                    float d  = MathF.Sqrt(dx*dx + dy*dy + dz*dz);
                    if (d > maxDelta) maxDelta = d;
                }
            }

            bool isDynamic = maxDelta > 0.01f;

            // Check LocalPlayer label
            bool   isLocalPlayer = _config.HasLocalPlayer && _config.LocalPlayerEntityId == candidate;
            string nameHint      = isLocalPlayer ? "★ LocalPlayer"
                                 : IdNameMap.TryGetValue(candidate, out var nm) ? nm : "";

            var entry = ActiveEntities.AddOrUpdate(candidate,
                _ => new TrackedEntity
                {
                    EntityId    = candidate,
                    X = x, Y = y, Z = z,
                    LastSeen    = ts,
                    FirstSeen   = ts,
                    UpdateCount = 1,
                    IsDynamic   = isDynamic,
                    MaxDelta    = maxDelta,
                    NameHint    = nameHint,
                    IsLocalPlayer = isLocalPlayer,
                },
                (_, ex) =>
                {
                    ex.X = x; ex.Y = y; ex.Z = z;
                    ex.LastSeen    = ts;
                    ex.UpdateCount++;
                    if (isDynamic) ex.IsDynamic = true;
                    if (maxDelta > ex.MaxDelta) ex.MaxDelta = maxDelta;
                    ex.NameHint     = nameHint;
                    ex.IsLocalPlayer = isLocalPlayer;
                    return ex;
                });

            // Update the Application ESP overlay
            lock (Application.EntityPositions)
            {
                var existing = Application.EntityPositions
                    .FirstOrDefault(e => e.Label.StartsWith(candidate.ToString()));
                string label = isLocalPlayer
                    ? $"{candidate} ★ LocalPlayer"
                    : $"{candidate}{(string.IsNullOrEmpty(entry.NameHint) ? "" : " " + entry.NameHint)}".TrimEnd();

                if (existing != null)
                {
                    existing.Position = new System.Numerics.Vector3(x, y, z);
                    existing.Label    = label;
                }
                else
                {
                    Application.EntityPositions.Add(new EntityOverlayEntry
                    {
                        Position = new System.Numerics.Vector3(x, y, z),
                        Label    = label,
                        Color    = isLocalPlayer
                            ? new System.Numerics.Vector4(0.18f, 0.65f, 0.95f, 0.95f)  // blue = local player
                            : isDynamic
                                ? new System.Numerics.Vector4(0.18f, 0.95f, 0.45f, 0.85f)  // green = dynamic
                                : new System.Numerics.Vector4(0.95f, 0.70f, 0.18f, 0.70f), // amber = static
                    });
                }
            }
        }
    }

    private static bool IsPlausibleCoord(float f) =>
        !float.IsNaN(f) && !float.IsInfinity(f) &&
        f >= -100_000f && f <= 100_000f && MathF.Abs(f) > 0.001f;

    // ── Feature 5: Automatic Naming ───────────────────────────────────────

    // Matches item name patterns — requires either snake_case (has underscore) OR
    // length ≥5 to eliminate short noise like "vd", "Fa", etc.
    private static readonly Regex ItemNameRx =
        new(@"[a-z][a-z0-9_]*_[a-z0-9_]+|[a-z][a-z0-9_]{4,31}", RegexOptions.Compiled);

    private void ProcessAutoNaming(byte[] data)
    {
        // Find all uint32 IDs in the plausible range
        for (int i = 1; i + 4 <= data.Length; i++)
        {
            uint id = BitConverter.ToUInt32(data, i);
            if ((id < 100 || id > 9_999) && (id < 1_000 || id > 4_000_000)) continue;
            if (IdNameMap.ContainsKey(id)) continue; // already named

            // Scan window: 16 bytes before and after the ID
            int winStart = Math.Max(0, i - 16);
            int winEnd   = Math.Min(data.Length, i + 4 + 16);
            int winLen   = winEnd - winStart;

            string window = Encoding.UTF8.GetString(data, winStart, winLen)
                .Replace("\0", " ");

            // Find all snake_case or alphanumeric item-name-like strings
            foreach (Match m in ItemNameRx.Matches(window))
            {
                string candidate = m.Value;
                if (candidate.Length < 3) continue;
                // Reject obvious noise: pure digits, single-char repetitions
                if (candidate.All(char.IsDigit)) continue;
                if (candidate.Distinct().Count() < 2) continue;

                IdNameMap[id] = candidate;

                // Auto-save to PacketBook under a schema label
                string bookLabel = $"Schema:{id}={candidate}";
                if (_store.Get(bookLabel) == null)
                {
                    _store.Save(bookLabel,
                        $"Auto-named: ID {id} found with string '{candidate}' (within 16 bytes)",
                        BitConverter.GetBytes(id),
                        PacketDirection.ServerToClient);
                    _log.Success($"[SmartDetect] Auto-named: {id} → '{candidate}' saved to Book.");
                }
                break; // take first match per ID per packet
            }
        }
    }

    // ── Feature 6: String Correlation ────────────────────────────────────

    private void ProcessStringCorrelation(byte[] data)
    {
        // Collect metadata strings (2–8 chars — the short ones seen in UI)
        var metaStrings = new List<string>();
        int i = 0;
        while (i < data.Length)
        {
            if (data[i] >= 0x41 && data[i] <= 0x7A) // A-z range
            {
                int start = i;
                while (i < data.Length && data[i] >= 0x20 && data[i] < 0x7F) i++;
                int len = i - start;
                if (len >= 2 && len <= 8)
                    metaStrings.Add(Encoding.ASCII.GetString(data, start, len));
            }
            else i++;
        }

        // Collect item IDs from same packet
        var itemIds = new List<uint>();
        for (int k = 1; k + 4 <= data.Length; k++)
        {
            uint v = BitConverter.ToUInt32(data, k);
            if (v >= 100 && v <= 9_999) itemIds.Add(v);
        }

        if (metaStrings.Count == 0 || itemIds.Count == 0) return;

        // Record every (string, itemId) co-occurrence
        uint primaryId = itemIds[0]; // use highest-priority ID (earliest in packet)

        foreach (var ms in metaStrings)
        {
            if (!_strItemCoOccur.TryGetValue(ms, out var idCounts))
                _strItemCoOccur[ms] = idCounts = new Dictionary<uint, int>();

            idCounts.TryGetValue(primaryId, out int count);
            idCounts[primaryId] = count + 1;

            // When co-occurrence is strong (≥5), update the public correlation table
            if (idCounts[primaryId] >= 5)
                StringCorrelation[ms] = primaryId;
        }
    }

    // ── Feature 7: Delta Watcher (Static vs Dynamic) ──────────────────────

    private void ProcessDeltaWatcher(byte[] data)
    {
        for (int i = 1; i + 4 <= data.Length; i++)
        {
            uint v = BitConverter.ToUInt32(data, i);
            // Only classify IDs in the "constant value" range the user mentioned
            if (v < 100 || v > 9_999) continue;

            if (!_deltaHistory.TryGetValue(v, out var ring))
                _deltaHistory[v] = ring = new RingBuffer16();

            ring.Add(v); // record each occurrence's surrounding context byte
            // Actually track the *next* byte as the "associated value"
            byte associated = i + 4 < data.Length ? data[i + 4] : (byte)0;
            ring.AddValue(associated);

            // After enough samples, classify
            if (ring.SampleCount >= 8)
            {
                bool isStatic = ring.AllValuesSame;
                DeltaClassifications[v] = isStatic ? DeltaClass.Static : DeltaClass.Dynamic;
            }
        }
    }

    // ── Feature 8: High-Confidence Auto-Pin ──────────────────────────────

    private void AutoPinHighConfidenceItems()
    {
        foreach (var kv in ConfirmedItems)
        {
            var item = kv.Value;
            // Auto-pin confirmed items seen ≥3 times
            if (item.PacketCount < 3) continue;
            if (_autoPinned.ContainsKey(item.ItemId)) continue;

            _autoPinned[item.ItemId] = true;

            string label = $"AutoPin:{item.ItemId}";
            if (_store.Get(label) == null)
            {
                var payload = new byte[6];
                BitConverter.GetBytes(item.ItemId).CopyTo(payload, 0);
                payload[4] = item.StackSize;
                payload[5] = item.SlotIndex;
                _store.Save(label,
                    $"Auto-pinned Item ID {item.ItemId}" +
                    (string.IsNullOrEmpty(item.NameHint) ? "" : $" ({item.NameHint})") +
                    $" — stack ×{item.StackSize}, slot {item.SlotIndex}",
                    payload,
                    PacketDirection.ServerToClient);
                _log.Success($"[SmartDetect] Auto-pinned HIGH-confidence ID {item.ItemId}" +
                             $"{(string.IsNullOrEmpty(item.NameHint) ? "" : $" ({item.NameHint})")} → Book.");
            }
        }
    }

    // ── Purge stale entities ──────────────────────────────────────────────

    public void PurgeStaleEntities()
    {
        var cutoff = DateTime.Now - TimeSpan.FromSeconds(30);
        foreach (var kv in ActiveEntities)
        {
            if (kv.Value.LastSeen < cutoff)
            {
                ActiveEntities.TryRemove(kv.Key, out _);
                lock (_coordLock) { _coordHistory.Remove(kv.Key); }

                // Remove from ESP overlay
                lock (Application.EntityPositions)
                {
                    Application.EntityPositions.RemoveAll(
                        e => e.Label.StartsWith(kv.Key.ToString()));
                }
            }
        }

        // Also prune 4A entities not seen for 60s
        var cutoff4A = DateTime.Now - TimeSpan.FromSeconds(60);
        foreach (var kv in Pkt4AEntities)
            if (kv.Value.LastSeen < cutoff4A)
                Pkt4AEntities.TryRemove(kv.Key, out _);
    }

    // ── Public control ────────────────────────────────────────────────────

    public void DismissSuggestion() => _suggestedTargetId = 0;

    public void Dispose()
    {
        _cts.Cancel();
        _thread.Join(1000);
        _cts.Dispose();
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

public class ConfirmedItem
{
    public uint     ItemId      { get; set; }
    public byte     StackSize   { get; set; }
    public byte     SlotIndex   { get; set; }
    public DateTime FirstSeen   { get; set; }
    public DateTime LastSeen    { get; set; }
    public int      PacketCount { get; set; }
    public string   NameHint    { get; set; } = "";
}

public class TrackedEntity
{
    public uint     EntityId    { get; set; }
    public float    X           { get; set; }
    public float    Y           { get; set; }
    public float    Z           { get; set; }
    public DateTime FirstSeen   { get; set; }
    public DateTime LastSeen    { get; set; }
    public int      UpdateCount { get; set; }
    public bool     IsDynamic   { get; set; }   // true = player/mob, false = static object
    public float    MaxDelta    { get; set; }   // largest single-frame movement seen
    public string   NameHint    { get; set; } = "";
    public bool     IsLocalPlayer { get; set; }  // true = identified as the local player

    public string ClassLabel => IsLocalPlayer ? "★ LocalPlayer"
                              : IsDynamic     ? "Dynamic"
                              :                 "Static";
}

public class Pkt4AEntry
{
    public uint     EntityId    { get; set; }
    public DateTime FirstSeen   { get; set; }
    public DateTime LastSeen    { get; set; }
    public int      PacketCount { get; set; }
}

public enum DeltaClass { Unknown, Static, Dynamic }

/// <summary>Small value ring-buffer used by DeltaWatcher — no heap allocation after init.</summary>
internal class RingBuffer16
{
    private readonly byte[] _values  = new byte[16];
    private          int    _head    = 0;
    public           int    SampleCount { get; private set; }

    public void Add(uint _)  { } // placeholder — actual tracking via AddValue
    public void AddValue(byte v)
    {
        _values[_head % 16] = v;
        _head++;
        SampleCount = Math.Min(SampleCount + 1, 16);
    }

    public bool AllValuesSame
    {
        get
        {
            if (SampleCount < 2) return true;
            byte first = _values[0];
            for (int i = 1; i < SampleCount; i++)
                if (_values[i] != first) return false;
            return true;
        }
    }
}
