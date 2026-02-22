using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Tracks live connection statistics, rolling ping history, packet rate,
/// server fingerprint information, and GeoIP data.
///
/// Subscribe to UdpProxy.OnPacket and feed packets here to keep counters
/// up to date in real time.
/// </summary>
public class ServerStats
{
    // ── Live counters ─────────────────────────────────────────────────────
    public long   PacketsSentTotal     { get; private set; }
    public long   PacketsReceivedTotal { get; private set; }
    public long   BytesSentTotal       { get; private set; }
    public long   BytesReceivedTotal   { get; private set; }
    public double PacketsPerSecondOut  { get; private set; }
    public double PacketsPerSecondIn   { get; private set; }
    public double BytesPerSecondOut    { get; private set; }
    public double BytesPerSecondIn     { get; private set; }

    // ── Uptime ────────────────────────────────────────────────────────────
    public DateTime?   ConnectedAt  { get; private set; }
    public TimeSpan    Uptime       => ConnectedAt.HasValue
        ? DateTime.Now - ConnectedAt.Value : TimeSpan.Zero;

    // ── Ping history (rolling 60 samples) ────────────────────────────────
    private readonly Queue<PingSample>    _pingSamples   = new();
    private const int                     MaxPingSamples = 60;
    public  IReadOnlyCollection<PingSample> PingHistory  => _pingSamples;
    public  double LastPingMs    { get; private set; } = -1;
    public  double AvgPingMs     { get; private set; } = -1;
    public  double MinPingMs     { get; private set; } = -1;
    public  double MaxPingMs     { get; private set; } = -1;
    private bool   _pinging      = false;

    // ── Unique packet IDs seen ────────────────────────────────────────────
    private readonly ConcurrentDictionary<int, int> _packetIdCountsCs = new();
    private readonly ConcurrentDictionary<int, int> _packetIdCountsSc = new();
    public  IReadOnlyDictionary<int, int> PacketIdCountsCs => _packetIdCountsCs;
    public  IReadOnlyDictionary<int, int> PacketIdCountsSc => _packetIdCountsSc;

    // ── Rate tracking ─────────────────────────────────────────────────────
    private long   _pktOutWindow, _pktInWindow;
    private long   _bytesOutWindow, _bytesInWindow;
    private DateTime _rateWindowStart = DateTime.Now;

    // ── Server fingerprint ────────────────────────────────────────────────
    public ServerFingerprint Fingerprint { get; } = new();

    // ── GeoIP ─────────────────────────────────────────────────────────────
    public GeoInfo? GeoData { get; private set; }

    // ── Active connections (from netstat) ─────────────────────────────────
    public List<NetworkConnection> ActiveConnections { get; private set; } = new();

    private readonly TestLog _log;

    public ServerStats(TestLog log) => _log = log;

    // ── Feed packets ──────────────────────────────────────────────────────

    public void OnPacket(CapturedPacket pkt)
    {
        if (ConnectedAt == null) ConnectedAt = DateTime.Now;

        bool cs = pkt.Direction == PacketDirection.ClientToServer;
        int  len = pkt.RawBytes.Length;

        if (cs)
        {
            PacketsSentTotal++;
            BytesSentTotal += len;
            Interlocked.Increment(ref _pktOutWindow);
            Interlocked.Add(ref _bytesOutWindow, len);
            if (len > 0) _packetIdCountsCs.AddOrUpdate(pkt.RawBytes[0], 1, (_, v) => v + 1);
        }
        else
        {
            PacketsReceivedTotal++;
            BytesReceivedTotal += len;
            Interlocked.Increment(ref _pktInWindow);
            Interlocked.Add(ref _bytesInWindow, len);
            if (len > 0) _packetIdCountsSc.AddOrUpdate(pkt.RawBytes[0], 1, (_, v) => v + 1);

            // Feed into fingerprinter
            Fingerprint.ObserveServerPacket(pkt);
        }

        // Refresh rate every second
        var elapsed = (DateTime.Now - _rateWindowStart).TotalSeconds;
        if (elapsed >= 1.0)
        {
            PacketsPerSecondOut = _pktOutWindow   / elapsed;
            PacketsPerSecondIn  = _pktInWindow    / elapsed;
            BytesPerSecondOut   = _bytesOutWindow / elapsed;
            BytesPerSecondIn    = _bytesInWindow  / elapsed;
            _pktOutWindow = _pktInWindow = _bytesOutWindow = _bytesInWindow = 0;
            _rateWindowStart = DateTime.Now;
        }
    }

    public void Reset()
    {
        PacketsSentTotal = PacketsReceivedTotal = 0;
        BytesSentTotal   = BytesReceivedTotal   = 0;
        PacketsPerSecondOut = PacketsPerSecondIn = 0;
        BytesPerSecondOut   = BytesPerSecondIn   = 0;
        ConnectedAt = null;
        _pingSamples.Clear();
        _packetIdCountsCs.Clear();
        _packetIdCountsSc.Clear();
        Fingerprint.Reset();
        GeoData = null;
    }

    // ── Ping ──────────────────────────────────────────────────────────────

    public void StartPingLoop(string ip, int port, CancellationToken ct)
    {
        Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                await PingOnce(ip, port);
                await Task.Delay(2000, ct).ContinueWith(_ => { });
            }
        }, ct);
    }

    private async Task PingOnce(string ip, int port)
    {
        if (_pinging) return;
        _pinging = true;
        try
        {
            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = 1500;
            var ep = new IPEndPoint(IPAddress.Parse(ip), port);
            var sw = Stopwatch.StartNew();
            await udp.SendAsync(new byte[] { 0x00 }, 1, ep);
            try
            {
                var remote = new IPEndPoint(IPAddress.Any, 0);
                udp.Receive(ref remote);
                sw.Stop();
                RecordPing(sw.Elapsed.TotalMilliseconds);
            }
            catch
            {
                sw.Stop();
                // No reply is normal for game UDP — record the RTT anyway
                RecordPing(sw.Elapsed.TotalMilliseconds);
            }
        }
        catch { }
        finally { _pinging = false; }
    }

    private void RecordPing(double ms)
    {
        LastPingMs = ms;
        _pingSamples.Enqueue(new PingSample(DateTime.Now, ms));
        if (_pingSamples.Count > MaxPingSamples) _pingSamples.Dequeue();
        var vals = _pingSamples.Select(s => s.Ms).ToList();
        AvgPingMs = vals.Average();
        MinPingMs = vals.Min();
        MaxPingMs = vals.Max();
    }

    // ── GeoIP lookup ──────────────────────────────────────────────────────

    public void LookupGeo(string ip)
    {
        Task.Run(async () =>
        {
            try
            {
                // ip-api.com — free, no API key needed, returns JSON
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                string url = $"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,timezone";
                string json = await http.GetStringAsync(url);

                // Simple manual parse — no Newtonsoft/System.Text.Json needed
                GeoData = new GeoInfo
                {
                    Ip       = ip,
                    Country  = Extract(json, "country"),
                    Region   = Extract(json, "regionName"),
                    City     = Extract(json, "city"),
                    Isp      = Extract(json, "isp"),
                    Org      = Extract(json, "org"),
                    Timezone = Extract(json, "timezone"),
                    Lat      = double.TryParse(Extract(json, "lat"), out double lat) ? lat : 0,
                    Lon      = double.TryParse(Extract(json, "lon"), out double lon) ? lon : 0,
                };
                _log.Success($"[GeoIP] {ip} → {GeoData.City}, {GeoData.Country} ({GeoData.Isp})");
            }
            catch (Exception ex)
            {
                _log.Warn($"[GeoIP] Lookup failed: {ex.Message}");
                GeoData = new GeoInfo { Ip = ip, Country = "Lookup failed" };
            }
        });
    }

    private static string Extract(string json, string key)
    {
        string search = $"\"{key}\":";
        int idx = json.IndexOf(search);
        if (idx < 0) return "";
        idx += search.Length;
        if (idx >= json.Length) return "";
        if (json[idx] == '"')
        {
            int end = json.IndexOf('"', idx + 1);
            return end < 0 ? "" : json[(idx + 1)..end];
        }
        // Number value
        int endNum = idx;
        while (endNum < json.Length && json[endNum] != ',' && json[endNum] != '}')
            endNum++;
        return json[idx..endNum].Trim();
    }

    // ── Netstat scan ──────────────────────────────────────────────────────

    public void RefreshConnections()
    {
        Task.Run(() =>
        {
            var results = new List<NetworkConnection>();
            try
            {
                // Try ss first (Linux), fall back to netstat
                string tool = "ss", args = "-unp";
                try
                {
                    var test = Process.Start(new ProcessStartInfo
                    {
                        FileName = "ss", Arguments = "--version",
                        RedirectStandardOutput = true,
                        UseShellExecute = false, CreateNoWindow = true
                    });
                    test?.WaitForExit(500);
                }
                catch { tool = "netstat"; args = "-n -p UDP"; }

                var psi = new ProcessStartInfo
                {
                    FileName = tool, Arguments = args,
                    RedirectStandardOutput = true,
                    UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return;
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(3000);

                foreach (var line in output.Split('\n'))
                {
                    if (!line.Contains("ESTABLISHED") && !line.Contains("UDP")) continue;
                    var parts = line.Trim().Split(new[] { ' ', '\t' },
                        StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 4) continue;

                    // Parse both netstat and ss formats
                    string foreign = "";
                    string local   = "";
                    for (int i = 0; i < parts.Length - 1; i++)
                    {
                        if (parts[i].Contains(':') && !parts[i].StartsWith("::"))
                        {
                            if (string.IsNullOrEmpty(local))  local   = parts[i];
                            else if (string.IsNullOrEmpty(foreign)) foreign = parts[i];
                        }
                    }

                    if (string.IsNullOrEmpty(foreign) || foreign == "*:*") continue;
                    int lc = foreign.LastIndexOf(':');
                    if (lc < 0) continue;
                    string rip = foreign[..lc];
                    if (!int.TryParse(foreign[(lc + 1)..], out int rport)) continue;
                    if (rip.StartsWith("127.") || rip.StartsWith("0.")) continue;
                    if (rport is 443 or 80 or 53 or 67 or 68) continue;

                    results.Add(new NetworkConnection
                    {
                        RemoteIp   = rip,
                        RemotePort = rport,
                        LocalAddr  = local,
                        Protocol   = line.Contains("TCP") ? "TCP" : "UDP"
                    });
                }
            }
            catch (Exception ex) { _log.Error($"[NetScan] {ex.Message}"); }
            ActiveConnections = results;
        });
    }

    // ── Port scanner ──────────────────────────────────────────────────────

    public async Task<List<PortScanResult>> ScanPorts(string ip, int basePort,
                                                        int range = 10)
    {
        var results = new List<PortScanResult>();
        var tasks   = new List<Task>();

        for (int p = Math.Max(1, basePort - range);
                 p <= Math.Min(65535, basePort + range); p++)
        {
            int port = p;
            tasks.Add(Task.Run(async () =>
            {
                var r = new PortScanResult { Port = port };
                try
                {
                    using var udp = new UdpClient();
                    udp.Client.ReceiveTimeout = 500;
                    var ep = new IPEndPoint(IPAddress.Parse(ip), port);
                    var sw = Stopwatch.StartNew();
                    await udp.SendAsync(new byte[] { 0xFF }, 1, ep);
                    try { var remote = new IPEndPoint(IPAddress.Any, 0); udp.Receive(ref remote); r.Responded = true; }
                    catch { r.Responded = false; }
                    r.RttMs = (int)sw.ElapsedMilliseconds;
                    r.Hint  = GetPortHint(port);
                }
                catch { r.Error = true; }
                lock (results) results.Add(r);
            }));
        }
        await Task.WhenAll(tasks);
        return results.OrderBy(r => r.Port).ToList();
    }

    private static string GetPortHint(int p) => p switch
    {
        5520 => "Hytale game",
        5521 => "HyTester proxy",
        25565 => "Minecraft",
        19132 => "Bedrock",
        27015 => "Source engine",
        7777  => "Common game",
        8080  => "HTTP alt",
        3306  => "MySQL",
        5432  => "PostgreSQL",
        6379  => "Redis",
        _ => ""
    };
}

// ── Supporting types ──────────────────────────────────────────────────────────

public class PingSample
{
    public DateTime Timestamp { get; }
    public double   Ms        { get; }
    public PingSample(DateTime ts, double ms) { Timestamp = ts; Ms = ms; }
}

public class GeoInfo
{
    public string Ip       { get; set; } = "";
    public string Country  { get; set; } = "";
    public string Region   { get; set; } = "";
    public string City     { get; set; } = "";
    public string Isp      { get; set; } = "";
    public string Org      { get; set; } = "";
    public string Timezone { get; set; } = "";
    public double Lat      { get; set; }
    public double Lon      { get; set; }
}

public class NetworkConnection
{
    public string RemoteIp   { get; set; } = "";
    public int    RemotePort { get; set; }
    public string LocalAddr  { get; set; } = "";
    public string Protocol   { get; set; } = "UDP";
}

public class PortScanResult
{
    public int    Port      { get; set; }
    public bool   Responded { get; set; }
    public bool   Error     { get; set; }
    public int    RttMs     { get; set; }
    public string Hint      { get; set; } = "";
}

/// <summary>
/// Fingerprints the server by observing keep-alive interval,
/// response patterns, and protocol characteristics.
/// </summary>
public class ServerFingerprint
{
    public string Software       { get; private set; } = "Unknown";
    public string ProtocolHint   { get; private set; } = "Unknown";
    public int    KeepAliveMs    { get; private set; } = -1;
    public int    AvgResponseMs  { get; private set; } = -1;
    public bool   HasEncryption  { get; private set; }
    public bool   HasCompression { get; private set; }
    public string Notes          { get; private set; } = "";

    private DateTime? _lastServerPkt;
    private readonly List<int> _keepAliveIntervals = new();
    private readonly List<int> _responseTimes      = new();

    public void ObserveServerPacket(CapturedPacket pkt)
    {
        var now = DateTime.Now;
        if (_lastServerPkt.HasValue)
        {
            int ms = (int)(now - _lastServerPkt.Value).TotalMilliseconds;
            if (ms > 500 && ms < 60000) // filter out noise
                _keepAliveIntervals.Add(ms);
            if (_keepAliveIntervals.Count >= 3)
                KeepAliveMs = (int)_keepAliveIntervals.TakeLast(5).Average();
        }
        _lastServerPkt = now;

        // Detect encryption hints
        if (pkt.RawBytes.Length > 0)
        {
            byte first = pkt.RawBytes[0];
            // High entropy first bytes + non-printable data = likely encrypted
            bool allNonPrintable = pkt.RawBytes.Take(16).All(b => b < 32 || b > 126);
            if (allNonPrintable && pkt.RawBytes.Length > 8)
                HasEncryption = true;

            // Detect compression — zlib magic bytes
            if (pkt.RawBytes.Length >= 2 &&
                ((pkt.RawBytes[0] == 0x78 && pkt.RawBytes[1] == 0x9C) ||
                 (pkt.RawBytes[0] == 0x78 && pkt.RawBytes[1] == 0xDA)))
                HasCompression = true;
        }

        // Build notes
        var sb = new System.Text.StringBuilder();
        if (HasEncryption)  sb.Append("Encrypted traffic detected. ");
        if (HasCompression) sb.Append("zlib compression detected. ");
        if (KeepAliveMs > 0) sb.Append($"Keep-alive ~{KeepAliveMs}ms. ");
        Notes = sb.ToString();

        // Guess software
        Software = HasEncryption ? "Custom encrypted protocol"
                 : HasCompression ? "Compressed game protocol"
                 : "Plain UDP game server";
    }

    public void Reset()
    {
        Software = ProtocolHint = "Unknown";
        KeepAliveMs = AvgResponseMs = -1;
        HasEncryption = HasCompression = false;
        Notes = "";
        _lastServerPkt = null;
        _keepAliveIntervals.Clear();
        _responseTimes.Clear();
    }
}
