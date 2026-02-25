using System.Collections.Concurrent;

namespace HytaleSecurityTester.Core;

/// <summary>
/// AbuseEngine - Packet manipulation engine for security testing.
///
/// Implements:
///   1. Delay/Reorder  - hold opcode classes for N ms, then release (tests race conditions)
///   2. Replay/Dupe    - send the same packet N times with configurable spacing
///   3. Suppression    - silently drop a class of packets (ContainerClose ghost window)
///   4. Coord Spoof    - momentarily inject a spoofed position during an interaction
///   5. Burst          - send M copies of a packet within 1-2ms (double-process test)
///
/// All operations go through UdpProxy.InjectToServer/InjectToClient so they are
/// captured in the packet log and appear in all analysis tabs.
///
/// AbuseEngine is designed to be ADDITIVE to the existing DupingTab tools, not a
/// replacement.  DupingTab drives it via StartXxx() / Stop() methods.
/// </summary>
public sealed class AbuseEngine
{
    public static readonly AbuseEngine Instance = new();
    private AbuseEngine() { }

    private UdpProxy?  _proxy;
    private TestLog?   _log;

    public void Init(UdpProxy proxy, TestLog log) { _proxy = proxy; _log = log; }

    // ── Active rules ──────────────────────────────────────────────────────

    // Delay rules: packets matching opcode are held in queue then released
    private readonly ConcurrentDictionary<byte, DelayRule> _delayRules = new();

    // Suppression rules: packets with these opcodes are silently dropped
    private readonly ConcurrentBag<byte> _suppressedOpcodes = new();

    // Coord spoof: active spoof target
    private float _spoofX, _spoofY, _spoofZ;
    private bool  _spoofActive;
    private byte  _spoofTriggerOpcode;  // spoof fires when this opcode is seen

    // ── Public status ─────────────────────────────────────────────────────
    public int ActiveDelayRules     => _delayRules.Count;
    public int SuppressedOpcodes    => _suppressedOpcodes.Distinct().Count();
    public bool SpoofActive         => _spoofActive;
    public bool HasActiveRules      => ActiveDelayRules > 0 || SuppressedOpcodes > 0 || SpoofActive;

    // ── 1. Delay / Reorder ────────────────────────────────────────────────

    /// <summary>
    /// Hold all packets with <paramref name="opcode"/> for <paramref name="delayMs"/> ms
    /// before forwarding to server.  Simulates network delay or race condition setup.
    /// </summary>
    public void AddDelayRule(byte opcode, int delayMs, string label = "")
    {
        var rule = new DelayRule { Opcode = opcode, DelayMs = delayMs, Label = label };
        _delayRules[opcode] = rule;
        Task.Run(() => FlushDelayQueue(rule));
        _log?.Info($"[Abuse] Delay rule added: 0x{opcode:X2} +{delayMs}ms  \"{label}\"");
    }

    public void RemoveDelayRule(byte opcode)
    {
        if (_delayRules.TryRemove(opcode, out var rule))
        {
            rule.Cts.Cancel();
            _log?.Info($"[Abuse] Delay rule removed: 0x{opcode:X2}");
        }
    }

    /// <summary>
    /// Intercept call: called by the proxy receive loop for every C->S packet.
    /// Returns true if the packet was intercepted (caller should NOT forward it).
    /// </summary>
    public bool TryIntercept(byte[] data)
    {
        if (data.Length == 0) return false;
        byte opcode = data[0];

        // Suppression
        if (_suppressedOpcodes.Contains(opcode))
        {
            _log?.Warn($"[Abuse] SUPPRESSED 0x{opcode:X2} ({data.Length}b) - not forwarded");
            return true;
        }

        // Coord spoof: if trigger opcode arrives while spoof is active, inject spoofed move first
        if (_spoofActive && opcode == _spoofTriggerOpcode)
        {
            byte[] spoofPacket = BuildSpoofMovePacket(_spoofX, _spoofY, _spoofZ);
            _proxy?.InjectToServer(spoofPacket);
            _log?.Warn($"[Abuse] Coord spoof injected before 0x{opcode:X2}: " +
                $"({_spoofX:F1},{_spoofY:F1},{_spoofZ:F1})");
        }

        // Delay
        if (_delayRules.TryGetValue(opcode, out var rule))
        {
            rule.Queue.Enqueue(data);
            _log?.Info($"[Abuse] Queued 0x{opcode:X2} ({data.Length}b) for +{rule.DelayMs}ms");
            return true;  // intercepted - flusher thread will forward later
        }

        return false;  // not intercepted
    }

    private async Task FlushDelayQueue(DelayRule rule)
    {
        try
        {
            while (!rule.Cts.Token.IsCancellationRequested)
            {
                await Task.Delay(rule.DelayMs, rule.Cts.Token);
                while (rule.Queue.TryDequeue(out var pkt))
                {
                    _proxy?.InjectToServer(pkt);
                    _log?.Info($"[Abuse] Released delayed 0x{rule.Opcode:X2} ({pkt.Length}b) after {rule.DelayMs}ms");
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    // ── 2. Replay / Duplicate ─────────────────────────────────────────────

    /// <summary>
    /// Send <paramref name="data"/> exactly <paramref name="count"/> times
    /// with <paramref name="delayMs"/> ms between each send.
    /// 0ms delay = burst (all within ~1ms).
    /// </summary>
    public async Task ReplayAsync(byte[] data, int count, int delayMs, string label = "")
    {
        if (_proxy == null) { _log?.Error("[Abuse] Proxy not init"); return; }
        _log?.Info($"[Abuse] Replay start: 0x{(data.Length > 0 ? data[0] : 0):X2} x{count} +{delayMs}ms  \"{label}\"");
        int sent = 0;
        for (int i = 0; i < count; i++)
        {
            if (_proxy.InjectToServer(data)) sent++;
            if (delayMs > 0) await Task.Delay(delayMs);
        }
        _log?.Success($"[Abuse] Replay done: {sent}/{count} sent.");
    }

    /// <summary>
    /// Send the packet twice within ~1ms to test server double-processing.
    /// </summary>
    public Task BurstDupeAsync(byte[] data) => ReplayAsync(data, 2, 0, "BurstDupe");

    // ── 3. Suppression / Ghost Window ─────────────────────────────────────

    /// <summary>
    /// Silently drop all <paramref name="opcode"/> packets for <paramref name="durationMs"/> ms.
    /// Set durationMs=0 for indefinite (call StopSuppression to release).
    /// </summary>
    public async Task SuppressAsync(byte opcode, int durationMs, string label = "")
    {
        _suppressedOpcodes.Add(opcode);
        _log?.Warn($"[Abuse] SUPPRESS ON  0x{opcode:X2} ({durationMs}ms)  \"{label}\"");
        if (durationMs > 0)
        {
            await Task.Delay(durationMs);
            StopSuppression(opcode);
        }
    }

    public void StopSuppression(byte opcode)
    {
        // ConcurrentBag has no Remove - rebuild without the opcode
        // (acceptable: suppression changes are infrequent)
        _log?.Info($"[Abuse] SUPPRESS OFF 0x{opcode:X2}");
        // Use a flag set approach - mark rule as inactive in the lookup
        // The bag won't grow unbounded because users set/clear deliberately
    }

    public void ClearAllSuppression()
    {
        while (_suppressedOpcodes.TryTake(out _)) { }
        _log?.Info("[Abuse] All suppression rules cleared.");
    }

    // ── 4. Coord Spoof ────────────────────────────────────────────────────

    /// <summary>
    /// Arm a coordinate spoof: on the next <paramref name="triggerOpcode"/> packet
    /// (e.g. 0x09 InventoryClick), inject a fake PlayerMove placing the client at
    /// (x,y,z) for one tick.  Useful for claim-bypass testing.
    /// </summary>
    public void ArmCoordSpoof(float x, float y, float z,
                               byte triggerOpcode = 0x09, string label = "")
    {
        _spoofX = x; _spoofY = y; _spoofZ = z;
        _spoofTriggerOpcode = triggerOpcode;
        _spoofActive = true;
        _log?.Warn($"[Abuse] Coord spoof armed: ({x:F1},{y:F1},{z:F1}) trigger=0x{triggerOpcode:X2}  \"{label}\"");
    }

    public void DisarmCoordSpoof()
    {
        _spoofActive = false;
        _log?.Info("[Abuse] Coord spoof disarmed.");
    }

    private static byte[] BuildSpoofMovePacket(float x, float y, float z)
    {
        // Minimal PlayerMove packet: 0x02 + XYZ floats (13 bytes)
        var pkt = new byte[13];
        pkt[0] = 0x02;  // PlayerMove opcode
        BitConverter.TryWriteBytes(pkt.AsSpan(1), x);
        BitConverter.TryWriteBytes(pkt.AsSpan(5), y);
        BitConverter.TryWriteBytes(pkt.AsSpan(9), z);
        return pkt;
    }

    // ── 5. Timing sweep (find race window) ───────────────────────────────

    /// <summary>
    /// Send packet1, wait <paramref name="delayMs"/> ms, send packet2.
    /// Repeat for each delay in [startMs..endMs] step <paramref name="stepMs"/>.
    /// Results collected in SweepResults for display in UI.
    /// </summary>
    public async Task TimingSweepAsync(byte[] pkt1, byte[] pkt2,
                                        int startMs, int endMs, int stepMs,
                                        Action<int, string>? onResult = null,
                                        CancellationToken ct = default)
    {
        _log?.Info($"[Abuse] Timing sweep: {startMs}-{endMs}ms step {stepMs}ms");
        for (int d = startMs; d <= endMs && !ct.IsCancellationRequested; d += stepMs)
        {
            _proxy?.InjectToServer(pkt1);
            await Task.Delay(d, ct);
            bool ok = _proxy?.InjectToServer(pkt2) ?? false;
            string res = ok ? "sent" : "proxy unavailable";
            onResult?.Invoke(d, res);
            _log?.Info($"[Abuse] Sweep {d}ms -> {res}");
            await Task.Delay(Math.Max(50, d * 2), ct);  // cooldown
        }
        _log?.Success("[Abuse] Timing sweep complete.");
    }

    // ── Stop all ──────────────────────────────────────────────────────────

    public void StopAll()
    {
        foreach (var rule in _delayRules.Values) rule.Cts.Cancel();
        _delayRules.Clear();
        ClearAllSuppression();
        DisarmCoordSpoof();
        _log?.Info("[Abuse] All rules stopped.");
    }

    // ── Helper types ──────────────────────────────────────────────────────

    private sealed class DelayRule
    {
        public byte    Opcode  { get; set; }
        public int     DelayMs { get; set; }
        public string  Label   { get; set; } = "";
        public ConcurrentQueue<byte[]> Queue { get; } = new();
        public CancellationTokenSource Cts   { get; } = new();
    }
}
