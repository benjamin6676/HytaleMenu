using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace HytaleSecurityTester.Core;

/// <summary>
/// A full-duplex UDP proxy that sits between the game client and the server.
///
/// Architecture:
///   Game Client  ──UDP──►  UdpProxy (listenPort)  ──UDP──►  Game Server
///   Game Client  ◄──UDP──  UdpProxy               ◄──UDP──  Game Server
///
/// Each unique client endpoint gets its own dedicated "server-side" UdpClient
/// so multiple clients can be proxied simultaneously without cross-talk.
///
/// Injection:
///   Call InjectToServer(data) to send extra bytes to the server inside an
///   existing session.  Call InjectToClient(data) to send bytes back to the
///   client (useful for response spoofing tests).
/// </summary>
public class UdpProxy : IDisposable
{
    // ── Public state ──────────────────────────────────────────────────────
    public bool   IsRunning      { get; private set; }
    public int    TotalClients   { get; private set; }
    public int    ActiveSessions => _sessions.Count;
    public string StatusMessage  { get; private set; } = "Stopped";

    // ── Events ────────────────────────────────────────────────────────────
    /// Fired for every packet observed in either direction.
    public event Action<CapturedPacket>? OnPacket;

    // ── Private ───────────────────────────────────────────────────────────
    private readonly TestLog   _log;
    private readonly PacketLog _pktLog;

    private UdpClient?               _listener;
    private CancellationTokenSource? _cts;

    // clientEndpoint → Session
    private readonly ConcurrentDictionary<string, UdpSession> _sessions = new();

    private IPEndPoint _serverEp = new(IPAddress.Loopback, 0);

    public UdpProxy(TestLog log, PacketLog pktLog)
    {
        _log    = log;
        _pktLog = pktLog;
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    public void Start(string listenIp, int listenPort,
                      string serverIp,  int serverPort)
    {
        if (IsRunning) { _log.Warn("[UdpProxy] Already running."); return; }

        try
        {
            _serverEp = new IPEndPoint(IPAddress.Parse(serverIp), serverPort);
            _listener = new UdpClient(new IPEndPoint(IPAddress.Any, listenPort));
            _cts      = new CancellationTokenSource();

            IsRunning     = true;
            TotalClients  = 0;
            StatusMessage = $"Listening on 0.0.0.0:{listenPort}";

            _log.Success($"[UdpProxy] Started on 0.0.0.0:{listenPort} → {serverIp}:{serverPort}");
            Task.Run(() => ReceiveLoop(_cts.Token));
        }
        catch (Exception ex)
        {
            IsRunning     = false;
            StatusMessage = $"Failed: {ex.Message}";
            _log.Error($"[UdpProxy] Start failed: {ex.Message}");
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;
        _cts?.Cancel();

        // Close all sessions
        foreach (var s in _sessions.Values)
            s.Dispose();
        _sessions.Clear();

        try { _listener?.Close(); } catch { }
        _listener = null;

        IsRunning     = false;
        StatusMessage = "Stopped";
        _log.Warn("[UdpProxy] Stopped.");
    }

    public void Dispose() => Stop();

    // ── Injection ─────────────────────────────────────────────────────────

    /// <summary>
    /// Injects raw bytes into the most-recently-seen session, sending them
    /// to the game server as if they came from the client.
    /// Returns true if a session existed to inject into.
    /// </summary>
    public bool InjectToServer(byte[] data)
    {
        var session = GetLatestSession();
        if (session == null) return false;

        try
        {
            session.ServerSocket.Send(data, data.Length, _serverEp);
            _log.Info($"[UdpProxy] ▲ Injected {data.Length}b to server.");
            FirePacket(data, PacketDirection.ClientToServer, injected: true);
            return true;
        }
        catch (Exception ex)
        {
            _log.Error($"[UdpProxy] Inject to server failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Injects raw bytes back to the most-recently-seen client,
    /// as if they came from the server.  Useful for spoofed response tests.
    /// </summary>
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

    /// Listens for inbound UDP packets from any game client.
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

                // New client?
                if (!_sessions.TryGetValue(key, out var session))
                {
                    session = CreateSession(result.RemoteEndPoint, ct);
                    _sessions[key] = session;
                    TotalClients++;
                    StatusMessage = $"Active sessions: {_sessions.Count}";
                    _log.Success($"[UdpProxy] New client: {result.RemoteEndPoint}  " +
                                 $"(total={TotalClients})");
                }

                // Forward client → server
                byte[] data = result.Buffer;
                try
                {
                    await session.ServerSocket.SendAsync(data, data.Length, _serverEp);
                }
                catch (Exception ex)
                {
                    _log.Error($"[UdpProxy] Forward C→S: {ex.Message}");
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

    /// Creates a dedicated server-side socket for a client and starts its
    /// reverse-direction loop (server → client).
    private UdpSession CreateSession(IPEndPoint clientEp, CancellationToken ct)
    {
        // Bind to any available local port for talking to the real server
        var serverSocket = new UdpClient(0);
        var session      = new UdpSession(clientEp, serverSocket,
                                          DateTimeOffset.UtcNow);

        // Start the server→client direction on its own task
        Task.Run(() => ServerReceiveLoop(session, ct), ct);
        return session;
    }

    /// Forwards packets from the real server back to the original client.
    private async Task ServerReceiveLoop(UdpSession session, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try
                {
                    result = await session.ServerSocket.ReceiveAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    if (!ct.IsCancellationRequested)
                        _log.Error($"[UdpProxy] S→C receive: {ex.Message}");
                    break;
                }

                byte[] data = result.Buffer;
                session.LastActivity = DateTimeOffset.UtcNow;

                // Forward server → client
                try
                {
                    await _listener!.SendAsync(data, data.Length, session.ClientEndpoint);
                }
                catch (Exception ex)
                {
                    _log.Error($"[UdpProxy] Forward S→C: {ex.Message}");
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
            // Clean up stale session
            _sessions.TryRemove(session.ClientEndpoint.ToString(), out _);
            session.Dispose();
            StatusMessage = _sessions.Count > 0
                ? $"Active sessions: {_sessions.Count}"
                : $"Listening — {TotalClients} total";
            _log.Info($"[UdpProxy] Session closed: {session.ClientEndpoint}");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private void FirePacket(byte[] data, PacketDirection dir, bool injected = false)
    {
        var pkt = new CapturedPacket
        {
            Timestamp    = DateTime.Now,
            Direction    = dir,
            RawBytes     = (byte[])data.Clone(),
            HexString    = PacketCapture.ToHex(data),
            AsciiPreview = PacketCapture.ToAscii(data),
            Injected     = injected,
        };
        OnPacket?.Invoke(pkt);

        // Per-packet traffic goes to PacketLog only — keeps TestLog clean
        _pktLog.Add(dir, data.Length,
            pkt.HexString[..Math.Min(48, pkt.HexString.Length)],
            injected);
    }

    private UdpSession? GetLatestSession()
    {
        if (_sessions.IsEmpty) return null;
        return _sessions.Values
            .OrderByDescending(s => s.LastActivity)
            .FirstOrDefault();
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

/// Holds per-client state for one proxied UDP session.
public class UdpSession : IDisposable
{
    public IPEndPoint     ClientEndpoint { get; }
    public UdpClient      ServerSocket   { get; }
    public DateTimeOffset LastActivity   { get; set; }

    public UdpSession(IPEndPoint clientEp, UdpClient serverSocket,
                      DateTimeOffset created)
    {
        ClientEndpoint = clientEp;
        ServerSocket   = serverSocket;
        LastActivity   = created;
    }

    public void Dispose()
    {
        try { ServerSocket.Close(); } catch { }
    }
}
