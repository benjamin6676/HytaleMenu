using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;

namespace HytaleSecurityTester.Tabs;

public class DashboardTab : ITab
{
    public string Title => "  Dashboard  ";

    private readonly TestLog      _log;
    private readonly ServerConfig _config;
    private readonly ServerStats  _stats;

    private string _inputIp   = "149.56.241.73";
    private int    _inputPort = 5520;

    // IP Presets - user can save frequently used server IPs
    private List<(string Label, string Ip, int Port)> _presets = new()
    {
        ("Hytide", "149.56.241.73", 5520),
        ("HyTown", "51.195.60.80", 5520),
        ("Hyblock", "66.70.180.128", 5520),
    };
    private string _presetLabel = "My Server";
    private bool   _detecting = false;
    private bool   _pinging   = false;

    // Port scan
    private bool   _scanning        = false;
    private int    _scanRange        = 10;
    private List<PortScanResult> _scanResults = new();

    // Ping loop
    private CancellationTokenSource? _pingLoopCts;

    // Sub-tab
    private int _subTab = 0;
    private static readonly string[] SubTabs =
        { "Connection", "Live Stats", "Fingerprint", "Geo / Ports", "Threat Summary" };

    public DashboardTab(TestLog log, ServerConfig config, ServerStats stats)
    {
        _log = log; _config = config; _stats = stats;
    }

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;

        RenderTopBar(w);
        ImGui.Spacing();
        RenderSubTabBar();
        ImGui.Spacing();

        switch (_subTab)
        {
            case 0: RenderConnection(w); break;
            case 1: RenderLiveStats(w);  break;
            case 2: RenderFingerprint(w); break;
            case 3: RenderGeoAndPorts(w); break;
            case 4: RenderThreatSummary(w); break;
        }
    }

    // ── Top status bar ─────────────────────────────────────────────────────

    private void RenderTopBar(float w)
    {
        bool connected = _config.IsSet;
        var bgCol = connected
            ? new Vector4(0.05f, 0.15f, 0.07f, 1f)
            : new Vector4(0.14f, 0.05f, 0.05f, 1f);

        ImGui.PushStyleColor(ImGuiCol.ChildBg, bgCol);
        ImGui.BeginChild("##dbtop", new Vector2(w, 48), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        var dl = ImGui.GetWindowDrawList();
        var p  = ImGui.GetWindowPos();
        dl.AddRectFilled(p, p + new Vector2(4, 48),
            ImGui.ColorConvertFloat4ToU32(connected ? MenuRenderer.ColAccent : MenuRenderer.ColDanger));

        ImGui.SetCursorPos(new Vector2(14, 8));
        ImGui.PushStyleColor(ImGuiCol.Text, connected ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(connected ? "[>] CONNECTED" : "[>] NOT CONFIGURED");
        ImGui.PopStyleColor();

        if (connected)
        {
            ImGui.SameLine(0, 24);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColText);
            ImGui.TextUnformatted($"{_config.ServerIp}:{_config.ServerPort}");
            ImGui.PopStyleColor();

            ImGui.SameLine(0, 24);
            UiHelper.MutedLabel($"UDP  ·  uptime {FormatUptime(_stats.Uptime)}");

            ImGui.SameLine(0, 24);
            double ping = _stats.LastPingMs;
            var pingCol = ping < 0 ? MenuRenderer.ColTextMuted
                        : ping < 50  ? MenuRenderer.ColAccent
                        : ping < 150 ? MenuRenderer.ColWarn
                        : MenuRenderer.ColDanger;
            ImGui.PushStyleColor(ImGuiCol.Text, pingCol);
            ImGui.TextUnformatted(ping < 0 ? "ping: -" : $"ping: {ping:F0}ms");
            ImGui.PopStyleColor();

            ImGui.SetCursorPos(new Vector2(14, 28));
            UiHelper.MutedLabel(
                $"↑ {_stats.PacketsPerSecondOut:F1} pkt/s  {FormatBytes(_stats.BytesPerSecondOut)}/s   " +
                $"↓ {_stats.PacketsPerSecondIn:F1} pkt/s  {FormatBytes(_stats.BytesPerSecondIn)}/s");
        }

        ImGui.EndChild();
    }

    // ── Sub-tab bar ────────────────────────────────────────────────────────

    private void RenderSubTabBar()
    {
        if (!ImGui.BeginTabBar("##db_subtabs", ImGuiTabBarFlags.FittingPolicyScroll))
            return;
        for (int i = 0; i < SubTabs.Length; i++)
            if (ImGui.TabItemButton(SubTabs[i] + $"##dbst{i}", ImGuiTabItemFlags.None))
                _subTab = i;
        ImGui.EndTabBar();
    }

    // ── Connection sub-tab ─────────────────────────────────────────────────

    private void RenderConnection(float w)
    {
        float half = (w - 12) * 0.5f;

        UiHelper.SectionBox("SERVER CONFIG", half, 320, () =>
        {
            if (_config.IsSet)
            {
                UiHelper.Pill($"ACTIVE  {_config.ServerIp}:{_config.ServerPort}",
                    MenuRenderer.ColAccent, MenuRenderer.ColAccentDim);
                ImGui.Spacing();
            }

            UiHelper.MutedLabel("IP Address");
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("##dip", ref _inputIp, 128);
            ImGui.Spacing();
            UiHelper.MutedLabel("Port");
            ImGui.SetNextItemWidth(110);
            if (ImGui.InputInt("##dport", ref _inputPort))
                _inputPort = Math.Clamp(_inputPort, 1, 65535);
            ImGui.Spacing();

            // Presets row
            UiHelper.MutedLabel("Presets:");
            ImGui.SameLine(0, 8);
            foreach (var (label, ip, port) in _presets)
            {
                bool active = _config.IsSet && _config.ServerIp == ip && _config.ServerPort == port;
                ImGui.PushStyleColor(ImGuiCol.Button,
                    active ? MenuRenderer.ColAccentDim : MenuRenderer.ColBg3);
                ImGui.PushStyleColor(ImGuiCol.Text,
                    active ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
                if (ImGui.Button($"{label}##preset_{label}", new Vector2(0, 22)))
                {
                    _inputIp   = ip;
                    _inputPort = port;
                }
                ImGui.PopStyleColor(2);
                ImGui.SameLine(0, 4);
            }
            ImGui.NewLine();
            ImGui.Spacing();

            // Save current IP as new preset
            ImGui.SetNextItemWidth(130);
            ImGui.InputText("Label##plbl", ref _presetLabel, 32);
            ImGui.SameLine(0, 6);
            UiHelper.SecondaryButton("Save Preset##psave", 100, 22, () =>
            {
                string lbl = string.IsNullOrWhiteSpace(_presetLabel) ? _inputIp : _presetLabel;
                _presets.RemoveAll(p => p.Ip == _inputIp && p.Port == _inputPort);
                _presets.Add((lbl, _inputIp, _inputPort));
                _log.Info($"[Presets] Saved: {lbl} = {_inputIp}:{_inputPort}");
            });
            ImGui.SameLine(0, 4);
            if (_presets.Count > 1)
            {
                UiHelper.DangerButton("[x] Last##pdel", 66, 22, () =>
                {
                    _presets.RemoveAt(_presets.Count - 1);
                });
            }
            ImGui.Spacing();

            UiHelper.PrimaryButton("Set Active Server", -1, 32, () =>
            {
                _config.Set(_inputIp, _inputPort);
                _log.Success($"[Config] Server -> {_inputIp}:{_inputPort}");
                StartPingLoop();
                _stats.LookupGeo(_inputIp);
            });

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            ImGui.BeginDisabled(_detecting);
            UiHelper.SecondaryButton(
                _detecting ? "Detecting..." : "[!]  Auto-Detect from Game",
                -1, 28, AutoDetect);
            ImGui.EndDisabled();
            ImGui.Spacing();
            UiHelper.MutedLabel("Be connected in-game first.");
        });

        ImGui.SameLine(0, 12);

        UiHelper.SectionBox("DETECTED CONNECTIONS", half, 230, () =>
        {
            UiHelper.SecondaryButton("Refresh##dbref", -1, 26, () =>
            {
                _stats.RefreshConnections();
                _log.Info("[NetScan] Scanning active connections...");
            });
            ImGui.Spacing();

            var conns = _stats.ActiveConnections;
            if (conns.Count == 0)
            {
                UiHelper.MutedLabel("No active UDP connections found.");
                UiHelper.MutedLabel("Click Refresh while game is running.");
            }
            else
            {
                foreach (var c in conns.Take(8))
                {
                    bool isActive = _config.IsSet &&
                                    c.RemoteIp == _config.ServerIp &&
                                    c.RemotePort == _config.ServerPort;

                    ImGui.PushStyleColor(ImGuiCol.Text,
                        isActive ? MenuRenderer.ColAccent : MenuRenderer.ColText);
                    ImGui.TextUnformatted($"  {c.Protocol,-4} {c.RemoteIp}:{c.RemotePort}");
                    ImGui.PopStyleColor();

                    if (!isActive)
                    {
                        ImGui.SameLine(0, 8);
                        UiHelper.SecondaryButton($"Use##use{c.RemotePort}", 45, 18, () =>
                        {
                            _inputIp   = c.RemoteIp;
                            _inputPort = c.RemotePort;
                            _config.Set(c.RemoteIp, c.RemotePort);
                            StartPingLoop();
                            _stats.LookupGeo(c.RemoteIp);
                            _log.Success($"[Dashboard] Server set to {c.RemoteIp}:{c.RemotePort}");
                        });
                    }
                    else
                    {
                        ImGui.SameLine(0, 8);
                        UiHelper.AccentText("<- active");
                    }
                }
            }
        });

        ImGui.Spacing(); ImGui.Spacing();

        UiHelper.SectionBox("QUICK ACTIONS", w, 60, () =>
        {
            bool has = _config.IsSet;
            ImGui.BeginDisabled(!has || _pinging);
            UiHelper.SecondaryButton("Ping", 100, 28, PingOnce);
            ImGui.EndDisabled();
            ImGui.SameLine(0, 8);
            ImGui.BeginDisabled(!has);
            UiHelper.SecondaryButton("Resolve DNS", 120, 28, ResolveDns);
            ImGui.EndDisabled();
            ImGui.SameLine(0, 8);
            UiHelper.SecondaryButton("Clear Stats", 110, 28, () =>
            { _stats.Reset(); _log.Info("[Stats] Reset."); });
            ImGui.SameLine(0, 8);
            UiHelper.DangerButton("Clear Logs", 110, 28, () =>
            { _log.Clear(); _log.Info("Log cleared."); });
        });
    }

    // ── Live Stats sub-tab ─────────────────────────────────────────────────

    private void RenderLiveStats(float w)
    {
        float half = (w - 12) * 0.5f;

        UiHelper.SectionBox("TRAFFIC COUNTERS", half, 160, () =>
        {
            UiHelper.StatusRow("Pkts sent",   $"{_stats.PacketsSentTotal:N0}",     true, 100);
            UiHelper.StatusRow("Pkts rcvd",   $"{_stats.PacketsReceivedTotal:N0}", true, 100);
            UiHelper.StatusRow("Bytes sent",  FormatBytes(_stats.BytesSentTotal),   true, 100);
            UiHelper.StatusRow("Bytes rcvd",  FormatBytes(_stats.BytesReceivedTotal), true, 100);
            ImGui.Spacing();
            UiHelper.StatusRow("Out rate",
                $"{_stats.PacketsPerSecondOut:F1} pkt/s  {FormatBytes(_stats.BytesPerSecondOut)}/s",
                true, 100);
            UiHelper.StatusRow("In rate",
                $"{_stats.PacketsPerSecondIn:F1} pkt/s  {FormatBytes(_stats.BytesPerSecondIn)}/s",
                true, 100);
        });

        ImGui.SameLine(0, 12);

        UiHelper.SectionBox("PING STATS", half, 160, () =>
        {
            double last = _stats.LastPingMs;
            double avg  = _stats.AvgPingMs;
            double min  = _stats.MinPingMs;
            double max  = _stats.MaxPingMs;

            UiHelper.StatusRow("Last",    last < 0 ? "-" : $"{last:F0}ms", last >= 0, 60);
            UiHelper.StatusRow("Average", avg  < 0 ? "-" : $"{avg:F0}ms",  avg  >= 0, 60);
            UiHelper.StatusRow("Min",     min  < 0 ? "-" : $"{min:F0}ms",  true,      60);
            UiHelper.StatusRow("Max",     max  < 0 ? "-" : $"{max:F0}ms",  max < 200, 60);
            UiHelper.StatusRow("Samples", $"{_stats.PingHistory.Count}", true, 60);
            ImGui.Spacing();
            UiHelper.StatusRow("Uptime", FormatUptime(_stats.Uptime), _config.IsSet, 60);
        });

        ImGui.Spacing(); ImGui.Spacing();

        // Ping graph
        UiHelper.SectionBox("PING HISTORY (last 60 samples)", w, 120, () =>
        {
            var samples = _stats.PingHistory.ToList();
            if (samples.Count < 2)
            { UiHelper.MutedLabel("Waiting for ping data..."); return; }

            float gw = ImGui.GetContentRegionAvail().X;
            float gh = 70f;
            var cp   = ImGui.GetCursorScreenPos();
            var gdl  = ImGui.GetWindowDrawList();

            double maxMs = Math.Max(samples.Max(s => s.Ms), 1);
            float xStep  = gw / (samples.Count - 1);

            // Background
            gdl.AddRectFilled(cp, cp + new Vector2(gw, gh),
                ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBg2));

            // Grid lines at 50/100/200ms
            foreach (int gridMs in new[] { 50, 100, 200 })
            {
                float gy = cp.Y + gh - (float)(gridMs / maxMs * gh);
                if (gy < cp.Y) break;
                gdl.AddLine(new Vector2(cp.X, gy), new Vector2(cp.X + gw, gy),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
                gdl.AddText(new Vector2(cp.X + 2, gy - 12),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColTextMuted),
                    $"{gridMs}ms");
            }

            // Ping line
            for (int i = 0; i < samples.Count - 1; i++)
            {
                float x1 = cp.X + i       * xStep;
                float x2 = cp.X + (i + 1) * xStep;
                float y1 = cp.Y + gh - (float)(samples[i].Ms     / maxMs * gh);
                float y2 = cp.Y + gh - (float)(samples[i + 1].Ms / maxMs * gh);
                y1 = Math.Clamp(y1, cp.Y, cp.Y + gh);
                y2 = Math.Clamp(y2, cp.Y, cp.Y + gh);

                var lineCol = samples[i].Ms < 50  ? MenuRenderer.ColAccent
                            : samples[i].Ms < 150 ? MenuRenderer.ColWarn
                            : MenuRenderer.ColDanger;
                gdl.AddLine(new Vector2(x1, y1), new Vector2(x2, y2),
                    ImGui.ColorConvertFloat4ToU32(lineCol), 1.5f);
            }

            ImGui.Dummy(new Vector2(gw, gh));
        });

        ImGui.Spacing(); ImGui.Spacing();

        // Packet ID frequency table
        float idW = (w - 12) * 0.5f;

        UiHelper.SectionBox("CLIENT->SERVER PACKET IDs SEEN", idW, 160, () =>
        {
            var ids = _stats.PacketIdCountsCs
                .OrderByDescending(kv => kv.Value).Take(10).ToList();
            if (ids.Count == 0) { UiHelper.MutedLabel("No packets yet."); return; }
            foreach (var kv in ids)
            {
                UiHelper.MutedLabel($"  0x{kv.Key:X2}");
                ImGui.SameLine(60);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                ImGui.TextUnformatted($"{kv.Value,6}x");
                ImGui.PopStyleColor();
                ImGui.SameLine(110);
                UiHelper.MutedLabel(PacketAnalyser.Analyse(
                    new CapturedPacket { RawBytes = new[] { (byte)kv.Key },
                    Direction = PacketDirection.ClientToServer }).IdGuess);
            }
        });

        ImGui.SameLine(0, 12);

        UiHelper.SectionBox("SERVER->CLIENT PACKET IDs SEEN", idW, 160, () =>
        {
            var ids = _stats.PacketIdCountsSc
                .OrderByDescending(kv => kv.Value).Take(10).ToList();
            if (ids.Count == 0) { UiHelper.MutedLabel("No packets yet."); return; }
            foreach (var kv in ids)
            {
                UiHelper.MutedLabel($"  0x{kv.Key:X2}");
                ImGui.SameLine(60);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
                ImGui.TextUnformatted($"{kv.Value,6}x");
                ImGui.PopStyleColor();
                ImGui.SameLine(110);
                UiHelper.MutedLabel(PacketAnalyser.Analyse(
                    new CapturedPacket { RawBytes = new[] { (byte)kv.Key },
                    Direction = PacketDirection.ServerToClient }).IdGuess);
            }
        });
    }

    // ── Fingerprint sub-tab ────────────────────────────────────────────────

    private void RenderFingerprint(float w)
    {
        var fp = _stats.Fingerprint;

        UiHelper.SectionBox("SERVER FINGERPRINT", w, 180, () =>
        {
            UiHelper.StatusRow("Software",    fp.Software,       !fp.Software.Contains("Unknown"), 120);
            UiHelper.StatusRow("Encryption",  fp.HasEncryption  ? "Detected"  : "Not detected",
                !fp.HasEncryption, 120);
            UiHelper.StatusRow("Compression", fp.HasCompression ? "zlib detected" : "Not detected",
                true, 120);
            UiHelper.StatusRow("Keep-alive",
                fp.KeepAliveMs > 0 ? $"~{fp.KeepAliveMs}ms interval" : "Not measured yet",
                fp.KeepAliveMs > 0, 120);
            UiHelper.StatusRow("Avg response",
                fp.AvgResponseMs > 0 ? $"{fp.AvgResponseMs}ms" : "-",
                fp.AvgResponseMs > 0, 120);
            ImGui.Spacing();
            if (!string.IsNullOrEmpty(fp.Notes))
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
                ImGui.BeginChild("##fpnotes", new Vector2(-1, 50), ImGuiChildFlags.Border);
                ImGui.PopStyleColor();
                ImGui.SetCursorPos(new Vector2(8, 8));
                UiHelper.MutedLabel(fp.Notes);
                ImGui.EndChild();
            }
        });

        ImGui.Spacing(); ImGui.Spacing();

        UiHelper.SectionBox("NOTES", w, 100, () =>
        {
            UiHelper.MutedLabel("Fingerprint data is collected automatically as packets flow");
            UiHelper.MutedLabel("through the proxy. Start Capture tab and play the game normally");
            UiHelper.MutedLabel("for 30+ seconds to get accurate fingerprint data.");
            ImGui.Spacing();
            UiHelper.MutedLabel("Encryption detected = packet IDs/structures are guesses only.");
            UiHelper.MutedLabel("No encryption = Item Inspector + Diff Analysis will work better.");
        });
    }

    // ── Geo & Ports sub-tab ────────────────────────────────────────────────

    private void RenderGeoAndPorts(float w)
    {
        float half = (w - 12) * 0.5f;

        // GeoIP
        UiHelper.SectionBox("GEO / HOSTING INFO", half, 200, () =>
        {
            var geo = _stats.GeoData;
            if (geo == null)
            {
                UiHelper.MutedLabel("No GeoIP data yet.");
                ImGui.Spacing();
                ImGui.BeginDisabled(!_config.IsSet);
                UiHelper.SecondaryButton("Lookup##geolookup", -1, 28, () =>
                    _stats.LookupGeo(_config.ServerIp));
                ImGui.EndDisabled();
                UiHelper.MutedLabel("Requires internet access.");
            }
            else
            {
                UiHelper.StatusRow("IP",       geo.Ip,       true, 80);
                UiHelper.StatusRow("Country",  geo.Country,  true, 80);
                UiHelper.StatusRow("Region",   geo.Region,   true, 80);
                UiHelper.StatusRow("City",     geo.City,     true, 80);
                UiHelper.StatusRow("ISP",      geo.Isp,      true, 80);
                UiHelper.StatusRow("Org",      geo.Org,      true, 80);
                UiHelper.StatusRow("Timezone", geo.Timezone, true, 80);
                ImGui.Spacing();
                UiHelper.SecondaryButton("Refresh##georef", -1, 26, () =>
                    _stats.LookupGeo(_config.ServerIp));
            }
        });

        ImGui.SameLine(0, 12);

        // Port scanner
        UiHelper.SectionBox("PORT SCANNER", half, 200, () =>
        {
            UiHelper.MutedLabel("Scans adjacent ports to find other services.");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("Scan range##psr", ref _scanRange);
            _scanRange = Math.Clamp(_scanRange, 1, 50);
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel($"±{_scanRange} ports");
            ImGui.Spacing();

            ImGui.BeginDisabled(!_config.IsSet || _scanning);
            UiHelper.SecondaryButton(_scanning ? "Scanning..." : "Scan Ports##scanports",
                -1, 28, RunPortScan);
            ImGui.EndDisabled();
            ImGui.Spacing();

            if (_scanResults.Count > 0)
            {
                foreach (var r in _scanResults.Take(10))
                {
                    bool isMain = r.Port == _config.ServerPort;
                    var  col    = isMain ? MenuRenderer.ColAccent
                                : r.Responded ? MenuRenderer.ColWarn
                                : MenuRenderer.ColTextMuted;
                    ImGui.PushStyleColor(ImGuiCol.Text, col);
                    string hint = !string.IsNullOrEmpty(r.Hint) ? $" ({r.Hint})" : "";
                    string resp = r.Responded ? $"replied {r.RttMs}ms" : "no reply";
                    ImGui.TextUnformatted($"  :{r.Port,-6} {resp}{hint}");
                    ImGui.PopStyleColor();
                }
            }
        });
    }

    // ── Logic ─────────────────────────────────────────────────────────────

    private void StartPingLoop()
    {
        _pingLoopCts?.Cancel();
        _pingLoopCts = new CancellationTokenSource();
        _stats.StartPingLoop(_config.ServerIp, _config.ServerPort, _pingLoopCts.Token);
    }

    private void AutoDetect()
    {
        _detecting = true;
        _log.Info("[AutoDetect] Scanning connections...");
        Task.Run(() =>
        {
            try
            {
                _stats.RefreshConnections();
                System.Threading.Thread.Sleep(1500);
                var conns = _stats.ActiveConnections;
                if (conns.Count == 0)
                { _log.Warn("[AutoDetect] None found - be connected in game first."); return; }

                var best = conns
                    .OrderByDescending(c => c.RemotePort == 5520 ? 100 : 0)
                    .ThenByDescending(c => c.RemotePort > 1024 && c.RemotePort < 30000 ? 1 : 0)
                    .First();

                _inputIp   = best.RemoteIp;
                _inputPort = best.RemotePort;
                _config.Set(best.RemoteIp, best.RemotePort);
                StartPingLoop();
                _stats.LookupGeo(best.RemoteIp);
                _log.Success($"[AutoDetect] Detected: {best.RemoteIp}:{best.RemotePort}");
            }
            catch (Exception ex) { _log.Error($"[AutoDetect] {ex.Message}"); }
            finally { _detecting = false; }
        });
    }

    private void PingOnce()
    {
        if (!_config.IsSet) return;
        _pinging = true;
        string ip = _config.ServerIp; int port = _config.ServerPort;
        Task.Run(async () =>
        {
            try
            {
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = 2000;
                var ep = new IPEndPoint(IPAddress.Parse(ip), port);
                var sw = Stopwatch.StartNew();
                await udp.SendAsync(new byte[] { 0x00 }, 1, ep);
                try
                {
                    var remote = new IPEndPoint(IPAddress.Any, 0);
                    udp.Receive(ref remote); sw.Stop();
                    _log.Success($"[Ping] {sw.ElapsedMilliseconds}ms from {ip}:{port}");
                }
                catch { sw.Stop(); _log.Info($"[Ping] No reply in {sw.ElapsedMilliseconds}ms (normal)"); }
            }
            catch (Exception ex) { _log.Error($"[Ping] {ex.Message}"); }
            finally { _pinging = false; }
        });
    }

    private void ResolveDns()
    {
        string addr = _inputIp.Trim();
        if (string.IsNullOrWhiteSpace(addr)) return;
        Task.Run(() =>
        {
            try
            {
                string host = addr.Contains(':') ? addr.Split(':')[0] : addr;
                var ips = Dns.GetHostAddresses(host);
                var ip  = ips.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                          ?? ips.FirstOrDefault();
                if (ip != null) { _inputIp = ip.ToString(); _log.Success($"[DNS] {host} -> {_inputIp}"); }
                else _log.Error($"[DNS] Could not resolve {host}");
            }
            catch (Exception ex) { _log.Error($"[DNS] {ex.Message}"); }
        });
    }

    private void RunPortScan()
    {
        if (!_config.IsSet || _scanning) return;
        _scanning = true;
        _scanResults.Clear();
        _log.Info($"[Ports] Scanning :{_config.ServerPort}±{_scanRange}...");
        Task.Run(async () =>
        {
            try
            {
                _scanResults = await _stats.ScanPorts(_config.ServerIp,
                    _config.ServerPort, _scanRange);
                int replied = _scanResults.Count(r => r.Responded);
                _log.Success($"[Ports] Scan done - {replied} ports replied.");
            }
            catch (Exception ex) { _log.Error($"[Ports] {ex.Message}"); }
            finally { _scanning = false; }
        });
    }

    // ── Threat Summary sub-tab ─────────────────────────────────────────────

    private void RenderThreatSummary(float w)
    {
        var feed = AlertBus.GetFeed();

        float half = (w - 12) * 0.5f;

        // ── Alert Feed ────────────────────────────────────────────────────
        UiHelper.SectionBox("LIVE ALERT FEED", half, 0, () =>
        {
            if (feed.Count == 0)
            {
                UiHelper.MutedLabel("No alerts yet - run tests in other tabs.");
                UiHelper.MutedLabel("Claims, admin opcodes, privilege probes and new");
                UiHelper.MutedLabel("protocol opcodes all push alerts here.");
                return;
            }

            UiHelper.SecondaryButton("Clear All##tsclear", -1, 24, AlertBus.ClearAll);
            ImGui.Spacing();

            float feedH = ImGui.GetContentRegionAvail().Y - 30;
            ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
            ImGui.BeginChild("##ts_feed", new Vector2(-1, feedH), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();

            foreach (var alert in feed)
            {
                var col = alert.Level switch
                {
                    AlertLevel.Critical => MenuRenderer.ColDanger,
                    AlertLevel.Warn     => MenuRenderer.ColWarn,
                    _                   => MenuRenderer.ColBlue,
                };
                string glyph = alert.Level switch
                {
                    AlertLevel.Critical => "!!",
                    AlertLevel.Warn     => "! ",
                    _                   => "· ",
                };
                ImGui.PushStyleColor(ImGuiCol.Text, col);
                ImGui.TextUnformatted($"  {glyph}");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 4);
                UiHelper.MutedLabel(alert.At.ToString("HH:mm:ss"));
                ImGui.SameLine(0, 8);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColText);
                ImGui.TextUnformatted(alert.Message);
                ImGui.PopStyleColor();
            }

            ImGui.EndChild();
        });

        ImGui.SameLine(0, 12);

        // ── Session summary ────────────────────────────────────────────────
        UiHelper.SectionBox("SESSION THREAT SUMMARY", half, 0, () =>
        {
            var byCrit     = feed.Count(a => a.Level == AlertLevel.Critical);
            var byWarn     = feed.Count(a => a.Level == AlertLevel.Warn);
            var byInfo     = feed.Count(a => a.Level == AlertLevel.Info);
            var modAudit   = feed.Count(a => a.SectionIndex == AlertBus.Sec_ModAudit);
            var priv       = feed.Count(a => a.SectionIndex == AlertBus.Sec_Privilege);
            var protoMap   = feed.Count(a => a.SectionIndex == AlertBus.Sec_ProtoMap);

            UiHelper.StatusRow("Total alerts",    feed.Count.ToString(), feed.Count > 0, 140);
            ImGui.Spacing();
            UiHelper.StatusRow("Critical",        byCrit.ToString(),   byCrit == 0,  140);
            UiHelper.StatusRow("Warning",         byWarn.ToString(),   byWarn == 0,  140);
            UiHelper.StatusRow("Info",            byInfo.ToString(),   true,          140);
            ImGui.Spacing();
            UiHelper.StatusRow("Mod Audit hits",  modAudit.ToString(), modAudit == 0, 140);
            UiHelper.StatusRow("Privilege hits",  priv.ToString(),     priv == 0,     140);
            UiHelper.StatusRow("New opcodes",     protoMap.ToString(), true,          140);
            ImGui.Spacing();

            // Severity indicator
            string risk  = byCrit > 0 ? "CRITICAL" : byWarn > 3 ? "HIGH" : byWarn > 0 ? "MEDIUM" : "LOW";
            var riskCol  = byCrit > 0 ? MenuRenderer.ColDanger : byWarn > 3 ? MenuRenderer.ColDanger
                         : byWarn > 0 ? MenuRenderer.ColWarn : MenuRenderer.ColAccent;
            ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
            ImGui.BeginChild("##ts_risk", new Vector2(-1, 40), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();
            ImGui.SetCursorPos(new Vector2(8, 8));
            ImGui.PushStyleColor(ImGuiCol.Text, riskCol);
            ImGui.TextUnformatted($"  OVERALL SESSION RISK:  {risk}");
            ImGui.PopStyleColor();
            ImGui.EndChild();

            ImGui.Spacing();

            // Copy report button
            UiHelper.SecondaryButton("Copy Report to Clipboard##tsrpt", -1, 28, () =>
            {
                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"# HytaleSecurityTester - Threat Report");
                sb.AppendLine($"# Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"# Server: {(_config.IsSet ? $"{_config.ServerIp}:{_config.ServerPort}" : "not set")}");
                sb.AppendLine();
                sb.AppendLine($"Overall Risk: {risk}");
                sb.AppendLine($"Alerts: {feed.Count} total  (Critical:{byCrit}  Warn:{byWarn}  Info:{byInfo})");
                sb.AppendLine();
                sb.AppendLine("--- Alert Feed ---");
                foreach (var a in feed)
                    sb.AppendLine($"[{a.Level,-8}] {a.At:HH:mm:ss}  {a.Message}");
                ImGui.SetClipboardText(sb.ToString());
                _log.Success("[Dashboard] Threat report copied to clipboard.");
            });

            ImGui.Spacing();
            UiHelper.MutedLabel("Tips: start Capture, run Mod Audit, run Privilege probes,");
            UiHelper.MutedLabel("then return here for a consolidated risk summary.");
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static string FormatUptime(TimeSpan t)
    {
        if (t.TotalSeconds < 1) return "-";
        if (t.TotalMinutes < 1) return $"{t.Seconds}s";
        if (t.TotalHours   < 1) return $"{t.Minutes}m {t.Seconds}s";
        return $"{(int)t.TotalHours}h {t.Minutes}m";
    }

    private static string FormatBytes(double bytes)
    {
        if (bytes < 1024)    return $"{bytes:F0}B";
        if (bytes < 1048576) return $"{bytes / 1024:F1}KB";
        return $"{bytes / 1048576:F1}MB";
    }
}
