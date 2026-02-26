using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace HytaleSecurityTester.Core;

/// <summary>
/// A full-duplex UDP proxy that sits between the game client and the server.
/// </summary>
public class UdpProxy : IDisposable
{
    // ── Public state ──────────────────────────────────────────────────────
    public bool IsRunning { get; private set; }
    public int TotalClients { get; private set; }
    public int ActiveSessions => _sessions.Count;
    public string StatusMessage { get; private set; } = "Stopped";

    // ── Events ────────────────────────────────────────────────────────────
    public event Action<CapturedPacket>? OnPacket;

    // ── Private ───────────────────────────────────────────────────────────
    private readonly TestLog _log;
    private readonly PacketLog _pktLog;

    private UdpClient? _listener;
    private CancellationTokenSource? _cts;

    private readonly ConcurrentDictionary<string, UdpSession> _sessions = new();
    private IPEndPoint _serverEp = new(IPAddress.Loopback, 0);

    public UdpProxy(TestLog log, PacketLog pktLog)
    {
        _log = log;
        _pktLog = pktLog;
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    public void Start(string listenIp, int listenPort, string serverIp, int serverPort)
    {
        if (IsRunning) { _log.Warn("[UdpProxy] Already running."); return; }

        try
        {
            _serverEp = new IPEndPoint(IPAddress.Parse(serverIp), serverPort);
            _listener = new UdpClient(new IPEndPoint(IPAddress.Any, listenPort));
            _cts = new CancellationTokenSource();

            IsRunning = true;
            TotalClients = 0;
            StatusMessage = $"Listening on 0.0.0.0:{listenPort}";

            _log.Success($"[UdpProxy] Started on 0.0.0.0:{listenPort} -> {serverIp}:{serverPort}");
            Task.Run(() => ReceiveLoop(_cts.Token));
        }
        catch (Exception ex)
        {
            IsRunning = false;
            StatusMessage = $"Failed: {ex.Message}";
            _log.Error($"[UdpProxy] Start failed: {ex.Message}");
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;
        _cts?.Cancel();

        foreach (var s in _sessions.Values)
            s.Dispose();
        _sessions.Clear();

        try { _listener?.Close(); } catch { }
        _listener = null;

        IsRunning = false;
        StatusMessage = "Stopped";
        _log.Warn("[UdpProxy] Stopped.");
    }

    public void Dispose() => Stop();

    // ── Injection ─────────────────────────────────────────────────────────

    public bool InjectToServer(byte[] data)
    {
        var session = GetLatestSession();
        if (session == null) return false;

        try
        {
            session.ServerSocket.Send(data, data.Length);
            _log.Info($"[UdpProxy] [^] Injected {data.Length}b to server.");
            FirePacket(data, PacketDirection.ClientToServer, injected: true);
            return true;
        }
        catch (Exception ex)
        {
            _log.Error($"[UdpProxy] Inject to server failed: {ex.Message}");
            return false;
        }
    }

    public bool InjectToClient(byte[] data)
    {
        var session = GetLatestSession();
        if (session == null) return false;

        try
        {
            _listener!.Send(data, data.Length, session.ClientEndpoint);
            _log.Info($"[UdpProxy] ▼ Injected {data.Length}b to client.");
            FirePacket(data, PacketDirection.ServerToClient, injected: true);
            return true;
        }
        catch (Exception ex)
        {
            _log.Error($"[UdpProxy] Inject to client failed: {ex.Message}");
            return false;
        }
    }

    // ── Core receive loop ─────────────────────────────────────────────────

    private async Task ReceiveLoop(CancellationToken ct)
    {
        _log.Info("[UdpProxy] Waiting for client packets...");
        try
        {
            while (!ct.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try
                {
                    result = await _listener!.ReceiveAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    if (!ct.IsCancellationRequested)
                        _log.Error($"[UdpProxy] Receive: {ex.Message}");
                    continue;
                }

                string key = result.RemoteEndPoint.ToString();

                if (!_sessions.TryGetValue(key, out var session))
                {
                    session = CreateSession(result.RemoteEndPoint, ct);
                    if (session != null)
                    {
                        _sessions[key] = session;
                        TotalClients++;
                        StatusMessage = $"Active sessions: {_sessions.Count}";
                        _log.Success($"[UdpProxy] New client: {result.RemoteEndPoint} (total={TotalClients})");
                    }
                }

                if (session == null) continue;

                byte[] data = result.Buffer;
                try
                {
                    await session.ServerSocket.SendAsync(data, data.Length);
                }
                catch (Exception ex)
                {
                    _log.Error($"[UdpProxy] Forward C->S: {ex.Message}");
                }

                FirePacket(data, PacketDirection.ClientToServer);
            }
        }
        catch (Exception ex)
        {
            if (IsRunning) _log.Error($"[UdpProxy] ReceiveLoop crashed: {ex.Message}");
        }
        finally
        {
            IsRunning = false;
        }
    }

    private UdpSession? CreateSession(IPEndPoint clientEp, CancellationToken ct)
    {
        try
        {
            // WORKING PATTERN: Create unbound socket and Connect() to server
            var serverSocket = new UdpClient();
            serverSocket.Connect(_serverEp);

            var session = new UdpSession(clientEp, serverSocket, DateTimeOffset.UtcNow);
            Task.Run(() => ServerReceiveLoop(session, ct), ct);
            return session;
        }
        catch (Exception ex)
        {
            _log.Error($"[UdpProxy] Failed to create session: {ex.Message}");
            return null;
        }
    }

    private async Task ServerReceiveLoop(UdpSession session, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try
                {
                    // WORKING PATTERN: Connected socket - ReceiveAsync returns server data
                    result = await session.ServerSocket.ReceiveAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    if (!ct.IsCancellationRequested)
                        _log.Error($"[UdpProxy] S->C receive: {ex.Message}");
                    break;
                }

                byte[] data = result.Buffer;
                session.LastActivity = DateTimeOffset.UtcNow;

                try
                {
                    await _listener!.SendAsync(data, data.Length, session.ClientEndpoint);
                }
                catch (Exception ex)
                {
                    _log.Error($"[UdpProxy] Forward S->C: {ex.Message}");
                }

                FirePacket(data, PacketDirection.ServerToClient);
            }
        }
        catch (Exception ex)
        {
            if (!ct.IsCancellationRequested)
                _log.Error($"[UdpProxy] ServerReceiveLoop: {ex.Message}");
        }
        finally
        {
            _sessions.TryRemove(session.ClientEndpoint.ToString(), out _);
            session.Dispose();
            StatusMessage = _sessions.Count > 0
                ? $"Active sessions: {_sessions.Count}"
                : $"Listening - {TotalClients} total";
            _log.Info($"[UdpProxy] Session closed: {session.ClientEndpoint}");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private void FirePacket(byte[] data, PacketDirection dir, bool injected = false)
{
    // Try decompression
    byte[]? decompressed = null;
    string compression = "none";
    
    try
    {
        decompressed = PacketAnalyser.TryDecompress(data, out string method);
        if (decompressed != null && method != "none")
            compression = method;
        else
            decompressed = null;
    }
    catch { }

    // Use decompressed data for analysis if available
    byte[] analysisData = decompressed ?? data;

    // Decode opcode
    ushort opcode = 0;
    int opcodeBytes = 0;
    string opcodeName = "UNKNOWN";
    OpcodeInfo info = new("UNKNOWN", "", OpcodeCategory.Unknown);
    
    if (analysisData.Length > 0)
    {
        try
        {
            opcode = OpcodeRegistry.DecodePacketId(analysisData, out opcodeBytes);
            info = OpcodeRegistry.Lookup(opcode, dir);
            opcodeName = info.Name;
        }
        catch { }
    }

    // Create CapturedPacket (original format for compatibility)
    var pkt = new CapturedPacket
    {
        Timestamp = DateTime.Now,
        Direction = dir,
        RawBytes = (byte[])data.Clone(),
        HexString = PacketCapture.ToHex(data),
        AsciiPreview = PacketCapture.ToAscii(data),
        Injected = injected,
    };

    // NEW: Create StructuredPacket for EntityTracker
    var sp = new StructuredPacket(pkt)
    {
        Opcode = opcode,
        Info = info,
        Label = OpcodeRegistry.FullLabel(opcode, dir),
    };

    // Extract fields using existing OpcodeRegistry logic
    ExtractFields(sp, analysisData, opcode, dir);

    // Feed into EntityTracker
    EntityTracker.Instance.ProcessStructuredPacket(sp);

    // Log with entity info
    var entities = sp.ExtractedIds;
    if (entities.Count > 0)
    {
        var summary = string.Join(", ", entities.Select(e => 
            $"{e.Name}:{e.Value}").Take(3));
        _log.Info($"[PACKET] {dir} {opcodeName} [{summary}]");
    }

    OnPacket?.Invoke(pkt);
    _pktLog.Add(dir, data.Length, pkt.HexString[..Math.Min(48, pkt.HexString.Length)], injected);
}

// Add field extraction matching your OpcodeRegistry patterns
private void ExtractFields(StructuredPacket sp, byte[] data, ushort opcode, PacketDirection dir)
{
    if (data.Length == 0) return;

    // Use existing extraction logic from OpcodeRegistry
    switch (opcode)
    {
        case 0x02 when dir == PacketDirection.ServerToClient: // PlayerSpawn
            ExtractPlayerSpawnFields(sp, data);
            break;
        case 111 when dir == PacketDirection.ClientToServer: // MouseInteraction
            ExtractMouseInteractionFields(sp, data);
            break;
        case 0x22: // InventorySlot
            ExtractInventorySlotFields(sp, data);
            break;
        case 0x20: // ItemSpawnWorld
            ExtractItemSpawnFields(sp, data);
            break;
        default:
            // Generic entity ID scan
            ExtractGenericEntityIds(sp, data);
            break;
    }

    // Update confidence
    sp.ConfidenceScore = sp.Info.Name != "UNKNOWN" ? 50 : 25;
    if (sp.ExtractedIds.Count > 0)
        sp.ConfidenceScore = Math.Min(100, sp.ConfidenceScore + sp.ExtractedIds.Count * 10);
}

private void ExtractPlayerSpawnFields(StructuredPacket sp, byte[] data)
{
    if (data.Length < 5) return;
    
    uint playerId = BitConverter.ToUInt32(data, 1);
    sp.ExtractedIds.Add(new ExtractedField("PlayerID", playerId, 1, ConfidenceSource.Packet));

    // Try to extract name
    if (data.Length >= 6)
    {
        byte nameLen = data[5];
        if (nameLen > 0 && nameLen <= 64 && 6 + nameLen <= data.Length)
        {
            try
            {
                string name = System.Text.Encoding.UTF8.GetString(data, 6, nameLen).Trim();
                if (name.Length >= 2)
                {
                    sp.Fields.Add(new PacketFieldEx("PlayerName", name, 6, ConfidenceSource.Packet, 85));
                    // Register with tracker immediately
                    EntityTracker.Instance.RegisterName(playerId, name, ConfidenceSource.Packet);
                }
            }
            catch { }
        }
    }

    // Try to extract position
    int xyzOffset = 6 + (data.Length > 5 ? data[5] : 0);
    if (data.Length >= xyzOffset + 12)
    {
        float x = BitConverter.ToSingle(data, xyzOffset);
        float y = BitConverter.ToSingle(data, xyzOffset + 4);
        float z = BitConverter.ToSingle(data, xyzOffset + 8);
        sp.Position = new System.Numerics.Vector3(x, y, z);
    }
}

private void ExtractMouseInteractionFields(StructuredPacket sp, byte[] data)
{
    if (data.Length < 5) return;
    
    uint targetId = BitConverter.ToUInt32(data, 1);
    sp.ExtractedIds.Add(new ExtractedField("TargetID", targetId, 1, ConfidenceSource.Packet));

    if (data.Length >= 10)
    {
        uint itemId = BitConverter.ToUInt32(data, 6);
        if (IsPlausibleId(itemId))
        {
            sp.ExtractedIds.Add(new ExtractedField("ItemInHand", itemId, 6, ConfidenceSource.Packet));
        }
    }
}

private void ExtractInventorySlotFields(StructuredPacket sp, byte[] data)
{
    if (data.Length < 2) return;
    
    byte slot = data[1];
    sp.Fields.Add(new PacketFieldEx("SlotIndex", slot.ToString(), 1, ConfidenceSource.Packet, 70));

    if (data.Length >= 6)
    {
        uint itemId = BitConverter.ToUInt32(data, 2);
        sp.ExtractedIds.Add(new ExtractedField("ItemID", itemId, 2, ConfidenceSource.Packet));
    }
}

private void ExtractItemSpawnFields(StructuredPacket sp, byte[] data)
{
    if (data.Length < 9) return;
    
    uint entityId = BitConverter.ToUInt32(data, 1);
    uint itemId = BitConverter.ToUInt32(data, 5);
    
    sp.ExtractedIds.Add(new ExtractedField("EntityID", entityId, 1, ConfidenceSource.Packet));
    sp.ExtractedIds.Add(new ExtractedField("ItemID", itemId, 5, ConfidenceSource.Packet));

    if (data.Length >= 21)
    {
        float x = BitConverter.ToSingle(data, 9);
        float y = BitConverter.ToSingle(data, 13);
        float z = BitConverter.ToSingle(data, 17);
        sp.Position = new System.Numerics.Vector3(x, y, z);
    }
}

private void ExtractGenericEntityIds(StructuredPacket sp, byte[] data)
{
    var seen = new HashSet<uint>();
    for (int i = 1; i + 4 <= Math.Min(data.Length, 32); i++)
    {
        uint id = BitConverter.ToUInt32(data, i);
        if (IsPlausibleId(id) && seen.Add(id))
        {
            sp.ExtractedIds.Add(new ExtractedField("ID?", id, i, ConfidenceSource.Inferred));
        }
    }
}

private bool IsPlausibleId(uint id) => id > 0 && id < 16_000_000;

    private UdpSession? GetLatestSession()
    {
        if (_sessions.IsEmpty) return null;
        return _sessions.Values
            .OrderByDescending(s => s.LastActivity)
            .FirstOrDefault();
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

public class UdpSession : IDisposable
{
    public IPEndPoint ClientEndpoint { get; }
    public UdpClient ServerSocket { get; }
    public DateTimeOffset LastActivity { get; set; }

    public UdpSession(IPEndPoint clientEp, UdpClient serverSocket, DateTimeOffset created)
    {
        ClientEndpoint = clientEp;
        ServerSocket = serverSocket;
        LastActivity = created;
    }

    public void Dispose()
    {
        try { ServerSocket.Close(); } catch { }
    }
}