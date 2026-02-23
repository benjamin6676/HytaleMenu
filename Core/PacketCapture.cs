using System.Net;
using System.Net.Sockets;
using System.Text;

namespace HytaleSecurityTester.Core;

public class PacketCapture
{
    private readonly TestLog   _log;
    private readonly PacketLog _pktLog;
    private TcpListener?     _listener;
    private CancellationTokenSource? _cts;

    private readonly List<CapturedPacket> _packets       = new();
    private readonly object               _packetsLock   = new();
    private readonly List<NetworkStream>  _serverStreams  = new();
    private readonly object               _sessionsLock   = new();

    public bool   IsRunning      { get; private set; } = false;
    public int    TotalClients   { get; set; }         = 0;
    public int    ActiveSessions { get; private set; } = 0;

    public event Action<CapturedPacket>? OnPacket;
    public string StatusMessage  { get; set; }         = "Stopped";

    public PacketCapture(TestLog log, PacketLog pktLog)
    {
        _log    = log;
        _pktLog = pktLog;
    }

    public List<CapturedPacket> GetPackets()
    {
        lock (_packetsLock) return new List<CapturedPacket>(_packets);
    }

    public void ClearPackets()
    {
        lock (_packetsLock) _packets.Clear();
    }

    public void AddPacketExternal(CapturedPacket packet)
    {
        lock (_packetsLock) _packets.Add(packet);
    }

    public void IncrementClients()
    {
        TotalClients++;
        ActiveSessions++;
        StatusMessage = $"Client connected ({ActiveSessions} active)";
    }

    public void Start(string listenIp, int listenPort,
                      string targetIp, int targetPort)
    {
        if (IsRunning) { _log.Warn("[Capture] Already running."); return; }

        _cts = new CancellationTokenSource();

        try
        {
            _listener     = new TcpListener(IPAddress.Any, listenPort);
            _listener.Start();
            IsRunning     = true;
            StatusMessage = $"Listening on 0.0.0.0:{listenPort}";
            TotalClients  = 0;

            _log.Success($"[Capture] Proxy on 0.0.0.0:{listenPort} → {targetIp}:{targetPort}");
            Task.Run(() => ListenLoop(targetIp, targetPort, _cts.Token));
        }
        catch (Exception ex)
        {
            IsRunning     = false;
            StatusMessage = $"Failed: {ex.Message}";
            _log.Error($"[Capture] Bind failed: {ex.Message}");
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { }
        IsRunning      = false;
        StatusMessage  = "Stopped";
        ActiveSessions = 0;
        _log.Warn("[Capture] Stopped.");
    }

    public async Task<bool> InjectToServer(byte[] data)
    {
        lock (_sessionsLock)
        {
            if (_serverStreams.Count == 0) return false;
            _serverStreams.Last().Write(data, 0, data.Length);
            return true;
        }
    }

    private async Task ListenLoop(string targetIp, int targetPort,
                                   CancellationToken ct)
    {
        _log.Info("[Capture] Waiting for client...");
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await _listener!.AcceptTcpClientAsync(ct);
                TotalClients++;
                ActiveSessions++;
                StatusMessage = $"Client connected ({ActiveSessions} active)";
                _log.Success($"[Capture] Client connected from {client.Client.RemoteEndPoint}");
                _ = Task.Run(() => HandleClient(client, targetIp, targetPort, ct), ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (IsRunning) _log.Error($"[Capture] Listener: {ex.Message}");
        }
    }

    private async Task HandleClient(TcpClient client, string targetIp,
                                     int targetPort, CancellationToken ct)
    {
        TcpClient?     server       = null;
        NetworkStream? serverStream = null;
        try
        {
            server = new TcpClient();
            await server.ConnectAsync(targetIp, targetPort, ct);
            _log.Success($"[Capture] Connected to server {targetIp}:{targetPort}");

            var clientStream = client.GetStream();
            serverStream     = server.GetStream();

            lock (_sessionsLock) _serverStreams.Add(serverStream);

            var toServer   = PipeAsync(clientStream, serverStream,
                PacketDirection.ClientToServer, ct);
            var fromServer = PipeAsync(serverStream, clientStream,
                PacketDirection.ServerToClient, ct);

            await Task.WhenAny(toServer, fromServer);
        }
        catch (Exception ex)
        {
            _log.Error($"[Capture] Session: {ex.Message}");
        }
        finally
        {
            ActiveSessions = Math.Max(0, ActiveSessions - 1);
            StatusMessage  = ActiveSessions > 0
                ? $"Active: {ActiveSessions}"
                : $"Listening — {TotalClients} total";

            if (serverStream != null)
                lock (_sessionsLock) _serverStreams.Remove(serverStream);

            client.Dispose();
            server?.Dispose();
            _log.Info("[Capture] Client disconnected.");
        }
    }

    private async Task PipeAsync(NetworkStream source, NetworkStream dest,
                                  PacketDirection direction, CancellationToken ct)
    {
        var buffer = new byte[65536];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int n = await source.ReadAsync(buffer, ct);
                if (n == 0) break;

                var chunk = new byte[n];
                Array.Copy(buffer, chunk, n);
                await dest.WriteAsync(buffer.AsMemory(0, n), ct);

                var packet = new CapturedPacket
                {
                    Timestamp    = DateTime.Now,
                    Direction    = direction,
                    RawBytes     = chunk,
                    HexString    = ToHex(chunk),
                    AsciiPreview = ToAscii(chunk),
                };

                lock (_packetsLock) _packets.Add(packet);
                OnPacket?.Invoke(packet);

                // Per-packet traffic goes to PacketLog only
                _pktLog.Add(direction, n,
                    packet.HexString[..Math.Min(48, packet.HexString.Length)]);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!ct.IsCancellationRequested)
                _log.Error($"[Capture] Pipe ({direction}): {ex.Message}");
        }
    }

    public static string ToHex(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 3);
        for (int i = 0; i < data.Length; i++)
        {
            sb.AppendFormat("{0:X2}", data[i]);
            if (i < data.Length - 1) sb.Append(' ');
        }
        return sb.ToString();
    }

    public static string ToAscii(byte[] data)
    {
        var sb = new StringBuilder(data.Length);
        foreach (byte b in data)
            sb.Append(b >= 32 && b < 127 ? (char)b : '.');
        return sb.ToString();
    }
}

public class CapturedPacket
{
    public DateTime        Timestamp    { get; set; }
    public PacketDirection Direction    { get; set; }
    public byte[]          RawBytes     { get; set; } = Array.Empty<byte>();
    public string          HexString    { get; set; } = "";
    public string          AsciiPreview { get; set; } = "";
    /// True when this packet was manually injected by the tool (not organic traffic)
    public bool            Injected     { get; set; } = false;
    /// User-supplied comment (set via double-click in CaptureTab)
    public string          Comment      { get; set; } = "";

    public string DirectionLabel =>
        Direction == PacketDirection.ClientToServer ? "C→S" : "S→C";
    public string TimestampLabel =>
        Timestamp.ToString("HH:mm:ss.fff");
}

public enum PacketDirection
{
    ClientToServer,
    ServerToClient,
}
