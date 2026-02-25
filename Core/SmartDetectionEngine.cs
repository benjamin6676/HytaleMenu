using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Smart Detection Engine - runs on a background thread.
/// All output collections are thread-safe (ConcurrentDictionary or lock-guarded).
/// </summary>
public class SmartDetectionEngine : IDisposable
{
    // ── Inputs ────────────────────────────────────────────────────────────
    private readonly PacketCapture _capture;
    private readonly PacketStore   _store;
    private readonly TestLog       _log;
    private readonly ServerConfig  _config;

    // ── Background thread ─────────────────────────────────────────────────
    private readonly CancellationTokenSource _cts = new();
    private readonly Thread                  _thread;

    // ── Outputs ──────────────────────────────────────────────────────────
    public ConcurrentDictionary<uint, ConfirmedItem>    ConfirmedItems       { get; } = new();
    public ConcurrentDictionary<uint, TrackedEntity>    ActiveEntities       { get; } = new();
    public ConcurrentDictionary<string, uint>           StringCorrelation    { get; } = new();
    public ConcurrentDictionary<uint, string>           IdNameMap            { get; } = new();
    public ConcurrentDictionary<uint, Pkt4AEntry>       Pkt4AEntities        { get; } = new();
    public ConcurrentDictionary<uint, DeltaClass>       DeltaClassifications { get; } = new();
    public ConcurrentDictionary<uint, EntityClass>      EntityClassifications{ get; } = new();

    // Input-mirror suggestion
    private volatile uint   _suggestedTargetId = 0;
    private volatile string _suggestedSource   = "";
    public uint   SuggestedTargetId => _suggestedTargetId;
    public string SuggestedSource   => _suggestedSource;
    public bool   HasSuggestion     => _suggestedTargetId > 0;

    // ── Force-scan progress (read from UI) ───────────────────────────────
    private volatile bool   _forceScanRunning  = false;
    private volatile string _forceScanStatus   = "";
    private volatile int    _forceScanProgress = 0;
    public bool   ForceScanRunning  => _forceScanRunning;
    public string ForceScanStatus   => _forceScanStatus;
    public int    ForceScanProgress => _forceScanProgress;

    // ── Op-code monitor ───────────────────────────────────────────────────
    // Op-codes we treat as "admin only" - fire event when seen outbound from server
    private static readonly HashSet<byte> AdminOpCodes = new()
    { 0x50, 0x51, 0x52, 0x60, 0x61, 0x70, 0x71 };
    public event Action<byte, byte[]>? OnAdminOpCodeDetected;

    // Permission-bit sniffer: id -> (myBits, adminBits)
    public ConcurrentDictionary<uint, (byte myBits, byte adminBits)> PermissionBits { get; }
    = new ConcurrentDictionary<uint, (byte myBits, byte adminBits)>();

    // Loot-drop listener
    public event Action<uint, byte[]>? OnLootDropDetected;
    private volatile bool _lootDropArmed = false;

    // ── Private state ─────────────────────────────────────────────────────
    private int _lastProcessedCount = 0;
    private readonly Dictionary<uint, RingBuffer16> _deltaHistory = new();
    private readonly Dictionary<string, Dictionary<uint, int>> _strItemCoOccur = new();
    private readonly object _coordLock = new();
    private readonly Dictionary<uint, List<(float x, float y, float z, DateTime t)>> _coordHistory = new();
    private readonly Dictionary<uint, HashSet<int>> _seqPreScreen = new();
    // Movement-update frequency per entity (for heuristic classification)
    private readonly Dictionary<uint, int> _moveFrequency = new();
    private readonly Dictionary<uint, bool> _autoPinned = new();
    // IDs found via force-scan are pinned so PurgeStaleEntities never removes them
    private readonly ConcurrentDictionary<uint, bool> _forcePinned4A       = new();
    private readonly ConcurrentDictionary<uint, bool> _forcePinnedEntities = new();

    // ── Name-detection regexes ─────────────────────────────────────────────
    //
    // Priority 1: Hytale namespace strings  hytale:iron_sword
    // Priority 2: Snake_case identifiers with at least one _  iron_sword / oak_log
    // Priority 3: Camel/PascalCase player names  3-16 alphanumeric, no dots
    //
    // Explicitly rejected:
    //   - Strings with dots (p.fc, y.d, e.5, m.r0) - these are fragments
    //   - All-digit strings
    //   - Single-char-variety strings ("aaaa")
    //   - Strings shorter than 4 chars (unless namespace-prefixed)
    //   - Strings containing only uppercase (likely hex junk)
    private static readonly Regex ItemNameRx =
        new(@"(?:hytale:[a-z][a-z0-9_]{2,31})|(?:[a-z][a-z0-9]{1,6}_[a-z0-9_]{2,24})|(?:[A-Za-z][A-Za-z0-9]{2,15})",
            RegexOptions.Compiled);

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
            Name = "SmartDetection", IsBackground = true,
            Priority = ThreadPriority.BelowNormal,
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
                // GetPacketCount() is cheap (just reads .Count).
                // Only call GetPackets() (which copies the list) when there are new packets.
                int currentCount = _capture.GetPacketCount();
                if (currentCount > _lastProcessedCount)
                {
                    var packets  = _capture.GetPackets();
                    var newPkts  = packets.Skip(_lastProcessedCount).ToList();
                    int baseIdx  = _lastProcessedCount;
                    _lastProcessedCount = packets.Count;
                    for (int pi = 0; pi < newPkts.Count; pi++)
                        ProcessPacket(newPkts[pi], baseIdx + pi);
                }
                PurgeStaleEntities();
                AutoPinHighConfidenceItems();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.Error($"[SmartDetect] Error: {ex.Message}");
            }
            Thread.Sleep(300); // was 150ms - halve CPU use on idle
        }
        _log.Info("[SmartDetect] Background engine stopped.");
    }

    // ── Per-packet processing ─────────────────────────────────────────────

    private void ProcessPacket(CapturedPacket pkt, int pktIndex)
    {
        var data = pkt.RawBytes;
        if (data.Length < 2) return;
        bool cs = pkt.Direction == PacketDirection.ClientToServer;

        // Heuristic classification by opcode
        var hint = ClassifyByOpCode(data[0], cs, data.Length);

        // Admin op-code monitor
        if (!cs && AdminOpCodes.Contains(data[0]))
            OnAdminOpCodeDetected?.Invoke(data[0], data);

        // Loot-drop listener
        if (_lootDropArmed && cs && (data[0] == 0x07 || data[0] == 0x06))
        {
            _lootDropArmed = false;
            if (data.Length >= 5)
            {
                uint dropId = BitConverter.ToUInt32(data, 1);
                if (dropId >= 100 && dropId <= 9_999)
                {
                    OnLootDropDetected?.Invoke(dropId, data);
                    _log.Success($"[SmartDetect] [*] Loot-drop captured! Item ID {dropId} in 0x{data[0]:X2}");
                }
            }
        }

        // 1. 0x4A parser (both endianness)
        if (data.Length >= 5)
        {
            bool is4ALE = data[0] == 0x4A;
            bool is4ABE = data[data.Length - 1] == 0x4A;  // BE: header at end
            if (is4ALE) Process0x4A(data, pkt.Timestamp, false);
            else if (is4ABE && data.Length >= 5) Process0x4A(data, pkt.Timestamp, true);
            // Also: try matching any packet with plausible movement size
            else if (data.Length >= 7 && data.Length <= 174) TryParseAs0x4A(data, pkt.Timestamp);
        }

        // 2. Sequence correlation (LE + BE + VarInt)
        ProcessSequenceCorrelation(data, pkt.Timestamp, pktIndex);

        // 3. Input mirroring
        if (cs) ProcessInputMirroring(data[0], data);

        // 4. Entity coords
        ProcessEntityCoords(data, pkt.Timestamp, hint);

        // 5. Auto-naming
        ProcessAutoNaming(data);

        // 6. String correlation
        ProcessStringCorrelation(data);

        // 7. Delta watcher
        ProcessDeltaWatcher(data);

        // 8. Permission bit sniffer
        if (!cs) ProcessPermissionBits(data);
    }

    // ── FORCE SCAN (processes all existing packets from scratch) ──────────

    public void ForceScan(IReadOnlyList<CapturedPacket> allPackets)
    {
        if (_forceScanRunning) return;
        _forceScanRunning = true;
        _forceScanStatus  = "Starting full scan...";
        _forceScanProgress = 0;

        Task.Run(() =>
        {
            try
            {
                int total = allPackets.Count;
                _log.Info($"[SmartDetect] Force scan started - {total} packets");

                for (int i = 0; i < total; i++)
                {
                    if (_cts.IsCancellationRequested) break;
                    ProcessPacket(allPackets[i], i);
                    // Pin every entity found so purge never removes force-scan results
                    foreach (var id in Pkt4AEntities.Keys)      _forcePinned4A[id]       = true;
                    foreach (var id in ActiveEntities.Keys)     _forcePinnedEntities[id] = true;
                    if (i % 500 == 0)
                    {
                        _forceScanProgress = (i * 100) / total;
                        _forceScanStatus   = $"Scanning... {i}/{total} ({_forceScanProgress}%)";
                    }
                }

                _forceScanStatus   = $"Complete - {Pkt4AEntities.Count} entities, " +
                                     $"{ConfirmedItems.Count} items, {ActiveEntities.Count} tracked";
                _forceScanProgress = 100;
                _log.Success($"[SmartDetect] Force scan complete. " +
                             $"4A={Pkt4AEntities.Count} Items={ConfirmedItems.Count} Entities={ActiveEntities.Count}");
            }
            catch (Exception ex) { _forceScanStatus = $"Error: {ex.Message}"; }
            finally { _forceScanRunning = false; }
        });
    }

    public void Force0x4AScan(IReadOnlyList<CapturedPacket> allPackets)
    {
        if (_forceScanRunning) return;
        _forceScanRunning  = true;
        _forceScanStatus   = "0x4A scan started...";
        _forceScanProgress = 0;

        Task.Run(() =>
        {
            try
            {
                int found = 0, total = allPackets.Count;
                for (int i = 0; i < total; i++)
                {
                    if (_cts.IsCancellationRequested) break;
                    var data = allPackets[i].RawBytes;
                    var ts   = allPackets[i].Timestamp;

                    // Try both endianness
                    if (data.Length >= 5 && data[0] == 0x4A)
                    { Process0x4A(data, ts, false); _forcePinned4A[BitConverter.ToUInt32(data, 1)] = true; found++; }
                    else if (data.Length >= 5 && data[data.Length-1] == 0x4A)
                    { Process0x4A(data, ts, true); found++; }
                    else if (data.Length >= 7 && data.Length <= 174)
                    { TryParseAs0x4A(data, ts); }

                    if (i % 1000 == 0)
                    {
                        _forceScanProgress = (i * 100) / total;
                        _forceScanStatus   = $"0x4A scan: {i}/{total} - found {Pkt4AEntities.Count} entities";
                    }
                }
                _forceScanStatus   = $"0x4A scan done - {Pkt4AEntities.Count} entities from {found} matching packets";
                _forceScanProgress = 100;
                _log.Success($"[SmartDetect] 0x4A scan complete: {Pkt4AEntities.Count} entities.");
            }
            catch (Exception ex) { _forceScanStatus = $"Error: {ex.Message}"; }
            finally { _forceScanRunning = false; }
        });
    }

    public void ForceSequenceScan(IReadOnlyList<CapturedPacket> allPackets)
    {
        if (_forceScanRunning) return;
        _forceScanRunning  = true;
        _forceScanStatus   = "Sequence scan started...";
        _forceScanProgress = 0;

        Task.Run(() =>
        {
            try
            {
                int total = allPackets.Count;
                for (int i = 0; i < total; i++)
                {
                    if (_cts.IsCancellationRequested) break;
                    ProcessSequenceCorrelation(allPackets[i].RawBytes, allPackets[i].Timestamp, i);
                    if (i % 1000 == 0)
                    {
                        _forceScanProgress = (i * 100) / total;
                        _forceScanStatus   = $"Seq scan: {i}/{total} - {ConfirmedItems.Count} items";
                    }
                }
                _forceScanStatus   = $"Seq scan done - {ConfirmedItems.Count} confirmed items";
                _forceScanProgress = 100;
                _log.Success($"[SmartDetect] Sequence scan complete: {ConfirmedItems.Count} items.");
            }
            catch (Exception ex) { _forceScanStatus = $"Error: {ex.Message}"; }
            finally { _forceScanRunning = false; }
        });
    }

    public void ArmLootDropListener()
    {
        _lootDropArmed = true;
        _log.Info("[SmartDetect] Loot-drop listener ARMED - next Drop/Use packet will be captured.");
    }

    // ── 0x4A parser (both endianness + fallback) ──────────────────────────

    private void Process0x4A(byte[] data, DateTime ts, bool bigEndian)
    {
        // Read 4-byte entity ID - try both byte orders
        uint primaryId = bigEndian
            ? (uint)(data[1] << 24 | data[2] << 16 | data[3] << 8 | data[4])
            : BitConverter.ToUInt32(data, 1);

        // Widen range: Hytale entity IDs could be as low as 1 or as high as ~16M
        if (primaryId == 0 || primaryId > 16_000_000) return;

        // If range 1-99 it's suspicious but still register
        AddOrUpdate4AEntry(primaryId, ts, data);

        // Secondary ID at bytes 5-8
        if (data.Length >= 9)
        {
            uint secondaryId = bigEndian
                ? (uint)(data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8])
                : BitConverter.ToUInt32(data, 5);
            if (secondaryId != 0 && secondaryId != primaryId && secondaryId <= 16_000_000)
                AddOrUpdate4AEntry(secondaryId, ts, null);
        }

        // Name hint scan
        if (data.Length > 9 && !IdNameMap.ContainsKey(primaryId))
        {
            string suffix = Encoding.UTF8.GetString(data, Math.Min(9, data.Length - 1),
                                                    data.Length - Math.Min(9, data.Length)).Replace("\0", " ");
            var m = ItemNameRx.Match(suffix);
            if (m.Success)
            {
                IdNameMap[primaryId] = m.Value;
                _log.Info($"[SmartDetect] 0x4A name: {primaryId} -> '{m.Value}'");
            }
        }
    }

    /// Try to parse any 7-174 byte packet as a movement packet
    private void TryParseAs0x4A(byte[] data, DateTime ts)
    {
        // Scan for a uint32 in plausible entity-ID range at offsets 1-5
        for (int i = 1; i <= Math.Min(5, data.Length - 4); i++)
        {
            uint v = BitConverter.ToUInt32(data, i);
            if (v < 100 || v > 4_000_000) continue;

            // Check if bytes after it look like floats (coords)
            if (i + 16 <= data.Length)
            {
                float x = BitConverter.ToSingle(data, i + 4);
                float y = BitConverter.ToSingle(data, i + 8);
                float z = BitConverter.ToSingle(data, i + 12);
                if (IsPlausibleCoord(x) && IsPlausibleCoord(y) && IsPlausibleCoord(z))
                {
                    AddOrUpdate4AEntry(v, ts, data);
                    return;
                }
            }
        }
    }

    private void AddOrUpdate4AEntry(uint entityId, DateTime ts, byte[]? data)
    {
        Pkt4AEntities.AddOrUpdate(entityId,
            _ => new Pkt4AEntry
            {
                EntityId = entityId, FirstSeen = ts, LastSeen = ts,
                RegisteredAt = DateTime.Now, PacketCount = 1,
                NameHint = (data != null && IdNameMap.TryGetValue(entityId, out var n)) ? n : "",
            },
            (_, ex) =>
            {
                ex.LastSeen = ts; ex.RegisteredAt = DateTime.Now; ex.PacketCount++;
                if (data != null && IdNameMap.TryGetValue(entityId, out var nm)) ex.NameHint = nm;
                return ex;
            });
    }

    // ── Sequence Correlation (LE + BE + VarInt) ───────────────────────────

    private void ProcessSequenceCorrelation(byte[] data, DateTime ts, int pktIndex)
    {
        // ── LE uint32 scan ────────────────────────────────────────────────
        for (int i = 1; i + 4 < data.Length; i++)
        {
            uint v = BitConverter.ToUInt32(data, i);
            if (v < 100 || v > 9_999) continue;

            byte nextByte = data[i + 4];
            if (nextByte < 1 || nextByte > 64) continue;

            TryConfirmItem(v, nextByte, i > 0 ? data[i - 1] : (byte)255, ts, pktIndex);
        }

        // ── BE uint32 scan ────────────────────────────────────────────────
        for (int i = 1; i + 4 < data.Length; i++)
        {
            uint v = (uint)(data[i] << 24 | data[i+1] << 16 | data[i+2] << 8 | data[i+3]);
            if (v < 100 || v > 9_999) continue;
            if (v == BitConverter.ToUInt32(data, i)) continue; // same as LE, skip

            byte nextByte = data[i + 4];
            if (nextByte < 1 || nextByte > 64) continue;

            TryConfirmItem(v, nextByte, i > 0 ? data[i - 1] : (byte)255, ts, pktIndex);
        }

        // ── VarInt scan: look for sequence of continuation bytes ──────────
        for (int i = 1; i < data.Length - 1; i++)
        {
            if (!TryReadVarInt(data, i, out uint varint, out int varLen)) continue;
            if (varint < 100 || varint > 9_999) continue;
            int afterIdx = i + varLen;
            if (afterIdx >= data.Length) continue;
            byte after = data[afterIdx];
            if (after < 1 || after > 64) continue;

            TryConfirmItem(varint, after, i > 0 ? data[i - 1] : (byte)255, ts, pktIndex);
        }
    }

    private void TryConfirmItem(uint v, byte stackByte, byte prevByte, DateTime ts, int pktIndex)
    {
        int slot = prevByte <= 63 ? prevByte : 0;

        if (!_seqPreScreen.TryGetValue(v, out var seen))
            _seqPreScreen[v] = seen = new HashSet<int>();
        seen.Add(pktIndex);
        if (seen.Count < 2) return;

        ConfirmedItems.AddOrUpdate(v,
            _ => new ConfirmedItem
            {
                ItemId = v, StackSize = stackByte, SlotIndex = (byte)slot,
                FirstSeen = ts, LastSeen = ts, PacketCount = 1,
                NameHint = IdNameMap.TryGetValue(v, out var n) ? n : "",
                EntityClass = EntityClass.Item,
            },
            (_, ex) =>
            {
                ex.LastSeen = ts; ex.PacketCount++;
                ex.StackSize = stackByte;
                if (IdNameMap.TryGetValue(v, out var nm)) ex.NameHint = nm;
                return ex;
            });

        EntityClassifications[v] = EntityClass.Item;
    }

    private static bool TryReadVarInt(byte[] data, int offset, out uint value, out int bytesRead)
    {
        value = 0; bytesRead = 0;
        int shift = 0;
        while (offset + bytesRead < data.Length && shift < 35)
        {
            byte b = data[offset + bytesRead++];
            value |= (uint)(b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0) return bytesRead >= 2 && value <= 9_999; // require multi-byte
        }
        return false;
    }

    // ── Input Mirroring ───────────────────────────────────────────────────

    private static readonly HashSet<byte> DropInteractIds =
        new() { 0x07, 0x08, 0x20, 0x21, 0x22, 0x04, 0x06 };

    private void ProcessInputMirroring(byte pktId, byte[] data)
    {
        if (!DropInteractIds.Contains(pktId) || data.Length < 5) return;
        uint candidateId = BitConverter.ToUInt32(data, 1);
        if (candidateId < 100 || candidateId > 4_000_000) return;
        if (ConfirmedItems.ContainsKey(candidateId)) return;

        string src = pktId switch
        {
            0x07 => "Drop packet (0x07)",
            0x08 => "Pick-Up packet (0x08)",
            0x20 => "Entity Interact (0x20)",
            0x21 => "Entity Attack (0x21)",
            0x22 => "Entity Use (0x22)",
            0x06 => "Use Item (0x06)",
            _    => $"C->S 0x{pktId:X2}",
        };
        if (_suggestedTargetId != candidateId)
        {
            _suggestedTargetId = candidateId;
            _suggestedSource   = src;
            _log.Info($"[SmartDetect] Mirror -> {candidateId} from {src}");
        }
    }

    // ── Entity Delta / Coord tracking ─────────────────────────────────────

    private void ProcessEntityCoords(byte[] data, DateTime ts, EntityClass hint)
    {
        if (data.Length < 13) return;

        // Try multiple layout offsets - Hytale may not always have ID at byte 1
        for (int idOff = 1; idOff <= Math.Min(5, data.Length - 16); idOff++)
        {
            uint candidate = BitConverter.ToUInt32(data, idOff);
            // Widen range - also try BE
            if (candidate == 0 || candidate > 16_000_000)
            {
                candidate = (uint)(data[idOff] << 24 | data[idOff+1] << 16 |
                                   data[idOff+2] << 8  | data[idOff+3]);
                if (candidate == 0 || candidate > 16_000_000) continue;
            }

            // Try reading floats at multiple offsets after the ID
            for (int floatOff = 4; floatOff <= 8; floatOff += 4)
            {
                int fBase = idOff + floatOff;
                if (fBase + 12 > data.Length) break;

                float x = BitConverter.ToSingle(data, fBase);
                float y = BitConverter.ToSingle(data, fBase + 4);
                float z = BitConverter.ToSingle(data, fBase + 8);

                if (!IsPlausibleCoord(x) || !IsPlausibleCoord(y) || !IsPlausibleCoord(z)) continue;

                RegisterEntityCoord(candidate, x, y, z, ts, hint);
                goto nextIdOff;
            }
            nextIdOff:;
        }
    }

    private void RegisterEntityCoord(uint candidate, float x, float y, float z,
                                       DateTime ts, EntityClass hint)
    {
        float maxDelta;
        lock (_coordLock)
        {
            if (!_coordHistory.TryGetValue(candidate, out var history))
                _coordHistory[candidate] = history = new();

            history.Add((x, y, z, ts));
            if (history.Count > 32) history.RemoveAt(0);
            if (history.Count < 2) return;

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

        // Track movement frequency
        _moveFrequency.TryGetValue(candidate, out int freq);
        _moveFrequency[candidate] = freq + 1;
        int moveFreq = _moveFrequency[candidate];

        // Classify entity
        EntityClass cls = hint;
        if (cls == EntityClass.Unknown)
        {
            if (isDynamic && moveFreq > 10 && maxDelta > 0.1f) cls = EntityClass.Player;
            else if (isDynamic && moveFreq > 5)                 cls = EntityClass.Mob;
            else if (!isDynamic)                                 cls = EntityClass.Item;
        }
        if (cls != EntityClass.Unknown)
            EntityClassifications[candidate] = cls;

        bool isLocalPlayer = _config.HasLocalPlayer && _config.LocalPlayerEntityId == candidate;
        string nameHint    = isLocalPlayer ? "[*] LocalPlayer"
                           : IdNameMap.TryGetValue(candidate, out var nm) ? nm : "";

        var entry = ActiveEntities.AddOrUpdate(candidate,
            _ => new TrackedEntity
            {
                EntityId = candidate, X = x, Y = y, Z = z,
                FirstSeen = ts, LastSeen = ts, RegisteredAt = DateTime.Now,
                UpdateCount = 1,
                IsDynamic = isDynamic, MaxDelta = maxDelta,
                NameHint = nameHint, IsLocalPlayer = isLocalPlayer,
                EntityClass = cls,
            },
            (_, ex) =>
            {
                ex.X = x; ex.Y = y; ex.Z = z;
                ex.LastSeen = ts; ex.RegisteredAt = DateTime.Now; ex.UpdateCount++;
                if (isDynamic) ex.IsDynamic = true;
                if (maxDelta > ex.MaxDelta) ex.MaxDelta = maxDelta;
                ex.NameHint     = nameHint;
                ex.IsLocalPlayer = isLocalPlayer;
                ex.EntityClass   = cls;
                return ex;
            });

        // Push to ESP overlay
        lock (Application.EntityPositions)
        {
            var existing = Application.EntityPositions
                .FirstOrDefault(e => e.Label.StartsWith(candidate.ToString()));

            string label = BuildEspLabel(candidate, nameHint, cls, isLocalPlayer);

            System.Numerics.Vector4 color = isLocalPlayer
                ? new(0.18f, 0.65f, 0.95f, 0.95f)  // blue
                : cls == EntityClass.Player
                    ? new(0.18f, 0.95f, 0.45f, 0.85f)  // green
                    : cls == EntityClass.Mob
                        ? new(0.95f, 0.28f, 0.22f, 0.85f)  // red
                        : cls == EntityClass.Item
                            ? new(0.95f, 0.75f, 0.10f, 0.70f)  // yellow
                            : isDynamic
                                ? new(0.18f, 0.95f, 0.45f, 0.85f)  // green (dynamic)
                                : new(0.95f, 0.70f, 0.18f, 0.70f); // amber (static)

            if (existing != null)
            {
                existing.Position = new(x, y, z);
                existing.Label    = label;
                existing.Color    = color;
            }
            else
            {
                Application.EntityPositions.Add(new EntityOverlayEntry
                {
                    Position = new(x, y, z),
                    Label    = label,
                    Color    = color,
                });
            }
        }
    }

    private static string BuildEspLabel(uint id, string name, EntityClass cls, bool isLocal)
    {
        string prefix = isLocal ? "[[*]]" : cls switch
        {
            EntityClass.Player => "[P]",
            EntityClass.Mob    => "[M]",
            EntityClass.Item   => "[I]",
            _                  => "   ",
        };
        string namePart = string.IsNullOrEmpty(name) ? $"ID:{id}" : name;
        return $"{prefix} {namePart}";
    }

    private static bool IsPlausibleCoord(float f) =>
        !float.IsNaN(f) && !float.IsInfinity(f) &&
        f >= -100_000f && f <= 100_000f && MathF.Abs(f) > 0.001f;

    // ── Classify by opcode ────────────────────────────────────────────────

    private static EntityClass ClassifyByOpCode(byte opCode, bool cs, int len)
    {
        if (cs)
        {
            // C->S movement packets -> player
            if (opCode == 0x02 || opCode == 0x03 || opCode == 0x04A) return EntityClass.Player;
            // C->S inventory actions -> item
            if (opCode == 0x09 || opCode == 0x0E || opCode == 0x07 || opCode == 0x08)
                return EntityClass.Item;
        }
        else
        {
            // S->C entity update -> could be player or mob, lean player if small
            if (opCode == 0x03) return len < 50 ? EntityClass.Player : EntityClass.Mob;
            // S->C inventory update -> item
            if (opCode == 0x04 || opCode == 0x22) return EntityClass.Item;
            // S->C player spawn -> player
            if (opCode == 0x02) return EntityClass.Player;
        }
        return EntityClass.Unknown;
    }

    // ── Auto-naming ───────────────────────────────────────────────────────

    // Secondary junk-filter: tokens that look like fragment artefacts
    private static readonly Regex JunkRx =
        new(@"\.", RegexOptions.Compiled);  // dots = serialisation fragment

    private static bool IsHighQualityName(string s)
    {
        if (s.Length < 3) return false;
        if (s.All(char.IsDigit)) return false;
        if (s.Distinct().Count() < 2) return false;
        if (JunkRx.IsMatch(s)) return false;
        // Must have at least one letter
        if (!s.Any(char.IsLetter)) return false;
        // Hytale-namespace: always accept
        if (s.StartsWith("hytale:", StringComparison.Ordinal)) return true;
        // Must be at least 4 chars unless it contains _
        if (s.Length < 4 && !s.Contains('_')) return false;
        // All-uppercase short strings are likely hex junk
        if (s.Length <= 6 && s.All(c => char.IsUpper(c) || char.IsDigit(c))) return false;
        return true;
    }

    private void ProcessAutoNaming(byte[] data)
    {
        for (int i = 1; i + 4 <= data.Length; i++)
        {
            uint id = BitConverter.ToUInt32(data, i);
            if ((id < 100 || id > 9_999) && (id < 1_000 || id > 4_000_000)) continue;
            if (IdNameMap.ContainsKey(id)) continue;

            int winStart = Math.Max(0, i - 64);
            int winEnd   = Math.Min(data.Length, i + 4 + 64);
            string window = Encoding.UTF8.GetString(data, winStart, winEnd - winStart)
                .Replace("\0", " ");

            // Walk matches in priority order - prefer Hytale-namespace first
            Match? best = null;
            foreach (Match m in ItemNameRx.Matches(window))
            {
                string candidate = m.Value;
                if (!IsHighQualityName(candidate)) continue;
                // Prefer hytale: prefix over anything else
                if (best == null || candidate.StartsWith("hytale:"))
                {
                    best = m;
                    if (candidate.StartsWith("hytale:")) break;
                }
            }

            if (best == null) continue;
            string name = best.Value;
            IdNameMap[id] = name;
            string bookLabel = $"Schema:{id}={name}";
            if (_store.Get(bookLabel) == null)
            {
                _store.Save(bookLabel,
                    $"Auto-named: ID {id} found with string '{name}' (within 16 bytes)",
                    BitConverter.GetBytes(id), PacketDirection.ServerToClient);
                _log.Success($"[SmartDetect] Auto-named: {id} -> '{name}' -> Book.");
            }
        }
    }

    // ── String Correlation ────────────────────────────────────────────────

    private void ProcessStringCorrelation(byte[] data)
    {
        var metaStrings = new List<string>();
        int i = 0;
        while (i < data.Length)
        {
            if (data[i] >= 0x41 && data[i] <= 0x7A)
            {
                int start = i;
                while (i < data.Length && data[i] >= 0x20 && data[i] < 0x7F) i++;
                int len = i - start;
                if (len >= 2 && len <= 8)
                    metaStrings.Add(Encoding.ASCII.GetString(data, start, len));
            }
            else i++;
        }

        var itemIds = new List<uint>();
        for (int k = 1; k + 4 <= data.Length; k++)
        {
            uint v = BitConverter.ToUInt32(data, k);
            if (v >= 100 && v <= 9_999) itemIds.Add(v);
        }

        if (metaStrings.Count == 0 || itemIds.Count == 0) return;
        uint primaryId = itemIds[0];

        foreach (var ms in metaStrings)
        {
            if (!_strItemCoOccur.TryGetValue(ms, out var idCounts))
                _strItemCoOccur[ms] = idCounts = new();
            idCounts.TryGetValue(primaryId, out int count);
            idCounts[primaryId] = count + 1;
            if (idCounts[primaryId] >= 5)
                StringCorrelation[ms] = primaryId;
        }
    }

    // ── Delta Watcher ─────────────────────────────────────────────────────

    private void ProcessDeltaWatcher(byte[] data)
    {
        for (int i = 1; i + 4 <= data.Length; i++)
        {
            uint v = BitConverter.ToUInt32(data, i);
            if (v < 100 || v > 9_999) continue;
            if (!_deltaHistory.TryGetValue(v, out var ring))
                _deltaHistory[v] = ring = new();
            byte assoc = i + 4 < data.Length ? data[i + 4] : (byte)0;
            ring.AddValue(assoc);
            if (ring.SampleCount >= 8)
                DeltaClassifications[v] = ring.AllValuesSame ? DeltaClass.Static : DeltaClass.Dynamic;
        }
    }

    // ── Auto-pin high-confidence items ────────────────────────────────────
    //
    // Smart filter: skip items with no resolved name and no interesting metadata.
    // This prevents the Book from filling up with thousands of generic anonymous IDs.
    // An item qualifies for auto-pin when:
    //   a) it has a resolved name in IdNameMap, OR
    //   b) it has a non-zero slot index (not in slot 0) which implies real inventory,  OR
    //   c) its stack count is unusual (>1 and non-default values like 64)

    private void AutoPinHighConfidenceItems()
    {
        foreach (var kv in ConfirmedItems)
        {
            var item = kv.Value;
            if (item.PacketCount < 3 || _autoPinned.ContainsKey(item.ItemId)) continue;

            // Smart auto-pin filter - skip anonymous items with no interesting metadata
            bool hasName     = !string.IsNullOrEmpty(item.NameHint);
            bool hasSlot     = item.SlotIndex > 0;
            bool hasRareStack = item.StackSize > 1 && item.StackSize != 64;

            if (!hasName && !hasSlot && !hasRareStack)
                continue; // skip - generic noise

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
                    $" - stackx{item.StackSize}, slot {item.SlotIndex}",
                    payload, PacketDirection.ServerToClient);
                _log.Success($"[SmartDetect] Auto-pinned {item.ItemId}" +
                             $"{(string.IsNullOrEmpty(item.NameHint) ? "" : $" ({item.NameHint})")}");
            }
        }
    }

    // ── Permission bit sniffer ────────────────────────────────────────────

    private void ProcessPermissionBits(byte[] data)
    {
        // Need at least: 4 bytes ID + 1 byte flags
        if (data.Length < 6)
            return;

        // Ensure every access is safe
        for (int i = 1; i + 4 < data.Length; i++)
        {
            // Safe ID read
            uint id = BitConverter.ToUInt32(data, i);
            if (id < 1_000 || id > 4_000_000)
                continue;

            int flagIndex = i + 4;
            if (flagIndex >= data.Length)
                continue;

            byte flags = data[flagIndex];

            // Skip useless values
            if (flags == 0x00 || flags == 0xFF)
                continue;

            PermissionBits.AddOrUpdate(id,
                _ => (myBits: flags, adminBits: (byte)0),
                (_, ex) =>
                {
                    // Track highest observed admin bits safely
                    byte newAdmin = (byte)(ex.adminBits | flags);
                    return (ex.myBits, newAdmin);
                });
        }
    }

    // ── Purge stale ───────────────────────────────────────────────────────

    public void PurgeStaleEntities()
    {
        // Use RegisteredAt (wall clock) not LastSeen (packet timestamp).
        // Force-pinned IDs (found via manual force-scan) are NEVER purged.
        var cutoff = DateTime.Now - TimeSpan.FromSeconds(60);
        foreach (var kv in ActiveEntities)
        {
            if (_forcePinnedEntities.ContainsKey(kv.Key)) continue;
            if (kv.Value.RegisteredAt < cutoff)
            {
                ActiveEntities.TryRemove(kv.Key, out _);
                lock (_coordLock) { _coordHistory.Remove(kv.Key); }
                lock (Application.EntityPositions)
                    Application.EntityPositions.RemoveAll(e => e.Label.Contains($"ID:{kv.Key}") ||
                                                               e.Label.Contains($" {kv.Key}"));
            }
        }
        var cutoff4A = DateTime.Now - TimeSpan.FromSeconds(120);
        foreach (var kv in Pkt4AEntities)
        {
            if (_forcePinned4A.ContainsKey(kv.Key)) continue;
            if (kv.Value.RegisteredAt < cutoff4A)
                Pkt4AEntities.TryRemove(kv.Key, out _);
        }
    }

    public void ClearForcePins()
    {
        _forcePinned4A.Clear();
        _forcePinnedEntities.Clear();
        _log.Info("[SmartDetect] Force-pins cleared - entries will now expire normally.");
    }

    public void DismissSuggestion() => _suggestedTargetId = 0;

    public void Dispose()
    {
        _cts.Cancel();
        _thread.Join(1000);
        _cts.Dispose();
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

public enum EntityClass { Unknown, Player, Mob, Item }
public enum DeltaClass  { Unknown, Static, Dynamic }

public class ConfirmedItem
{
    public uint        ItemId      { get; set; }
    public byte        StackSize   { get; set; }
    public byte        SlotIndex   { get; set; }
    public DateTime    FirstSeen   { get; set; }
    public DateTime    LastSeen    { get; set; }
    public int         PacketCount { get; set; }
    public string      NameHint    { get; set; } = "";
    public EntityClass EntityClass { get; set; } = EntityClass.Item;
}

public class TrackedEntity
{
    public uint        EntityId     { get; set; }
    public float       X            { get; set; }
    public float       Y            { get; set; }
    public float       Z            { get; set; }
    public DateTime    FirstSeen    { get; set; }
    public DateTime    LastSeen     { get; set; }
    /// <summary>Wall-clock time this entry was last updated - used for purge so
    /// force-scanned entities (with old packet timestamps) don't get immediately purged.</summary>
    public DateTime    RegisteredAt { get; set; }
    public int         UpdateCount  { get; set; }
    public bool        IsDynamic    { get; set; }
    public float       MaxDelta     { get; set; }
    public string      NameHint     { get; set; } = "";
    public bool        IsLocalPlayer { get; set; }
    public EntityClass EntityClass  { get; set; } = EntityClass.Unknown;

    public string ClassLabel => IsLocalPlayer  ? "[*] LocalPlayer"
                             : EntityClass == EntityClass.Player ? "PLAYER"
                             : EntityClass == EntityClass.Mob    ? "MOB"
                             : EntityClass == EntityClass.Item   ? "ITEM"
                             : IsDynamic ? "Dynamic" : "Static";

    public System.Numerics.Vector4 BadgeColor => IsLocalPlayer
        ? new(0.18f, 0.65f, 0.95f, 1f)
        : EntityClass switch
        {
            EntityClass.Player => new(0.18f, 0.95f, 0.45f, 1f),
            EntityClass.Mob    => new(0.95f, 0.28f, 0.22f, 1f),
            EntityClass.Item   => new(0.95f, 0.75f, 0.10f, 1f),
            _                  => new(0.60f, 0.60f, 0.60f, 1f),
        };

    public float DistanceTo(float px, float py, float pz)
    {
        float dx = X - px, dy = Y - py, dz = Z - pz;
        return MathF.Sqrt(dx*dx + dy*dy + dz*dz);
    }
}

public class Pkt4AEntry
{
    public uint     EntityId    { get; set; }
    public DateTime FirstSeen   { get; set; }
    public DateTime LastSeen    { get; set; }
    public DateTime RegisteredAt { get; set; }
    public int      PacketCount { get; set; }
    public string   NameHint    { get; set; } = "";
}

internal class RingBuffer16
{
    private readonly byte[] _values = new byte[16];
    private int _head = 0;
    public int SampleCount { get; private set; }

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
