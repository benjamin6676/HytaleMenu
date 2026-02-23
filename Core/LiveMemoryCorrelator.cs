using System.Text;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Live Memory Correlator.
///
/// Watches the PacketStore for new entries and simultaneously polls a set of
/// user-configured memory addresses in the target process. When a packet
/// arrives, it compares a snapshot of memory taken *before* the packet with
/// one taken *after* (within a configurable polling window), then reports
/// which addresses changed value and by how much.
///
/// This lets you map game protocol fields directly to memory locations:
/// e.g. send a "give 64 diamonds" packet, see which memory address jumps
/// from 0 to 64 — that's the inventory slot count field.
///
/// Usage:
///   1. Add memory addresses to watch via AddWatch()
///   2. Call Start() — correlator runs on its own background thread
///   3. Query Results for the list of CorrelationHit records
///   4. Call Stop() when done
/// </summary>
public class LiveMemoryCorrelator
{
    private readonly TestLog      _log;
    private readonly PacketStore  _store;
    private readonly MemoryReader _reader;

    private readonly object       _lock    = new();
    private readonly List<CorrelationHit>   _results = new();
    private readonly List<MemoryWatch>      _watches = new();

    private CancellationTokenSource? _cts;
    private bool                     _running = false;
    private int                      _lastPacketCount = 0;

    // Config
    public int  PollIntervalMs  { get; set; } = 150;  // how often to poll memory
    public int  WindowMs        { get; set; } = 800;  // how long after a packet to observe
    public int  MaxResults      { get; set; } = 500;

    public bool IsRunning => _running;

    public LiveMemoryCorrelator(TestLog log, PacketStore store, MemoryReader reader)
    {
        _log = log; _store = store; _reader = reader;
    }

    // ── Watch management ──────────────────────────────────────────────────

    public void AddWatch(IntPtr address, string label, WatchSize size = WatchSize.Int32)
    {
        lock (_lock)
            _watches.Add(new MemoryWatch { Address = address, Label = label, Size = size });
    }

    public void RemoveWatch(IntPtr address)
    {
        lock (_lock)
            _watches.RemoveAll(w => w.Address == address);
    }

    public void ClearWatches() { lock (_lock) _watches.Clear(); }

    public List<MemoryWatch> GetWatches()
    { lock (_lock) return new List<MemoryWatch>(_watches); }

    // ── Results ───────────────────────────────────────────────────────────

    public List<CorrelationHit> GetResults()
    { lock (_lock) return new List<CorrelationHit>(_results); }

    public void ClearResults() { lock (_lock) _results.Clear(); }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    public void Start()
    {
        if (_running) return;
        _running         = true;
        _lastPacketCount = _store.GetAll().Count;
        _cts             = new CancellationTokenSource();

        Task.Run(() => CorrelatorLoop(_cts.Token));
        _log.Info("[Correlator] Started — monitoring PacketStore + memory.");
    }

    public void Stop()
    {
        _cts?.Cancel();
        _running = false;
        _log.Info("[Correlator] Stopped.");
    }

    // ── Core loop ─────────────────────────────────────────────────────────

    private async Task CorrelatorLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(PollIntervalMs, ct);

                var packets = _store.GetAll();
                if (packets.Count <= _lastPacketCount)
                    continue;

                // New packet(s) arrived
                var newPkts = packets.Skip(_lastPacketCount).ToList();
                _lastPacketCount = packets.Count;

                // Snapshot memory BEFORE processing (already passed, but capture now as "before")
                var before = SnapshotMemory();

                // Wait the observation window
                await Task.Delay(WindowMs, ct);

                // Snapshot memory AFTER
                var after = SnapshotMemory();

                // Diff
                foreach (var kv in before)
                {
                    if (!after.TryGetValue(kv.Key, out long afterVal)) continue;
                    long beforeVal = kv.Value;
                    if (beforeVal == afterVal) continue;

                    var watch = _watches.FirstOrDefault(w => w.Address == kv.Key);
                    string label = watch?.Label ?? $"0x{kv.Key.ToInt64():X}";

                    foreach (var pkt in newPkts)
                    {
                        lock (_lock)
                        {
                            if (_results.Count >= MaxResults) break;
                            _results.Add(new CorrelationHit
                            {
                                Address     = kv.Key,
                                Label       = label,
                                ValueBefore = beforeVal,
                                ValueAfter  = afterVal,
                                Delta       = afterVal - beforeVal,
                                PacketLabel = pkt.Label,
                                PacketHex   = pkt.HexString[..Math.Min(32, pkt.HexString.Length)],
                                Timestamp   = DateTime.Now,
                            });
                        }

                        _log.Info($"[Correlator] {label} " +
                                  $"{beforeVal} → {afterVal} (Δ{afterVal - beforeVal:+#;-#;0}) " +
                                  $"— triggered by '{pkt.Label}'");
                    }
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.Error($"[Correlator] Loop error: {ex.Message}");
                await Task.Delay(500);
            }
        }

        _running = false;
    }

    private Dictionary<IntPtr, long> SnapshotMemory()
    {
        var snap = new Dictionary<IntPtr, long>();
        if (!_reader.IsAttached) return snap;

        lock (_lock)
        {
            foreach (var w in _watches)
            {
                long v = 0;
                bool ok = w.Size switch
                {
                    WatchSize.Byte  => _reader.ReadBytes(w.Address, new byte[1]) &&
                                       TryReadByte(w.Address, out v),
                    WatchSize.Int16 => TryReadInt16(w.Address, out v),
                    WatchSize.Int32 => _reader.ReadInt32(w.Address, out int v32) && (v = v32) >= long.MinValue,
                    WatchSize.Int64 => _reader.ReadInt64(w.Address, out v),
                    WatchSize.Float => _reader.ReadFloat(w.Address, out float vf) && (v = (long)(vf * 1000)) >= long.MinValue,
                    _               => _reader.ReadInt32(w.Address, out int vi) && (v = vi) >= long.MinValue,
                };
                if (ok) snap[w.Address] = v;
            }
        }

        return snap;
    }

    private bool TryReadByte(IntPtr addr, out long v)
    {
        var buf = new byte[1];
        if (_reader.ReadBytes(addr, buf)) { v = buf[0]; return true; }
        v = 0; return false;
    }

    private bool TryReadInt16(IntPtr addr, out long v)
    {
        var buf = new byte[2];
        if (_reader.ReadBytes(addr, buf)) { v = BitConverter.ToInt16(buf, 0); return true; }
        v = 0; return false;
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

public class MemoryWatch
{
    public IntPtr    Address { get; set; }
    public string    Label   { get; set; } = "";
    public WatchSize Size    { get; set; } = WatchSize.Int32;
    public string AddressHex => $"0x{Address.ToInt64():X16}";
}

public enum WatchSize { Byte, Int16, Int32, Int64, Float }

public class CorrelationHit
{
    public IntPtr   Address     { get; set; }
    public string   Label       { get; set; } = "";
    public long     ValueBefore { get; set; }
    public long     ValueAfter  { get; set; }
    public long     Delta       { get; set; }
    public string   PacketLabel { get; set; } = "";
    public string   PacketHex   { get; set; } = "";
    public DateTime Timestamp   { get; set; }
    public string AddressHex => $"0x{Address.ToInt64():X16}";
    public string DeltaStr   => Delta > 0 ? $"+{Delta}" : $"{Delta}";
}
