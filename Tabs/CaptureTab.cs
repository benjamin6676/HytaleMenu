using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace HytaleSecurityTester.Tabs;

public class CaptureTab : ITab
{
    public string Title => "  Capture  ";

    private readonly TestLog       _log;
    private readonly PacketCapture _capture;
    private readonly ServerConfig  _config;

    public PacketCapture Capture => _capture;

    private int _listenPort = 5521;

    private enum CaptureMode { Udp, Tcp, Tls }
    private CaptureMode _mode = CaptureMode.Udp;

    private bool                     _tlsIntercepting = false;
    private string                   _tlsCertStatus   = "Not generated";
    private X509Certificate2?        _tlsCert;
    private CancellationTokenSource? _tlsCts;

    private UdpProxy _udpProxy;

    private int    _selectedIndex    = -1;
    private string _filterText       = "";
    private bool   _showClientServer = true;
    private bool   _showServerClient = true;
    private bool   _autoScroll       = true;

    public CaptureTab(TestLog log, ServerConfig config)
    {
        _log      = log;
        _config   = config;
        _capture  = new PacketCapture(log);
        _udpProxy = new UdpProxy(log);

        // Forward UdpProxy packets into the shared capture list
        _udpProxy.OnPacket += pkt =>
        {
            _capture.AddPacketExternal(pkt);
            if (pkt.Injected)
                _log.Warn($"[UDP][INJ] {pkt.DirectionLabel} {pkt.RawBytes.Length}b");
        };

        _config.OnChanged += () =>
            _listenPort = _config.ServerPort + 1;
    }

    private bool IsRunning =>
        _capture.IsRunning || _tlsIntercepting || _udpProxy.IsRunning;

    public void Render()
    {
        ImGui.Spacing();
        RenderSetupPanel();
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();
        RenderPacketList();
    }

    // ── Setup panel ───────────────────────────────────────────────────────

    private void RenderSetupPanel()
    {
        bool   running = IsRunning;
        string localIp = GetLocalIp();
        float  w       = ImGui.GetContentRegionAvail().X;
        float  half    = (w - 12) * 0.5f;

        // Config + Mode side by side
        UiHelper.SectionBox("SERVER / PROXY CONFIG", half, 185, () =>
        {
            if (_config.IsSet)
            {
                UiHelper.Pill(
                    $"● {_config.ServerIp}:{_config.ServerPort}",
                    MenuRenderer.ColAccent, MenuRenderer.ColAccentDim);
                ImGui.Spacing();
            }
            else
            {
                UiHelper.DangerText("Set server IP in Dashboard tab first.");
                ImGui.Spacing();
            }

            ImGui.BeginDisabled(true);
            string dispIp   = _config.IsSet ? _config.ServerIp  : "— not set —";
            int    dispPort = _config.IsSet ? _config.ServerPort : 0;
            ImGui.SetNextItemWidth(190);
            ImGui.InputText("Server IP##csr",  ref dispIp,   64);
            ImGui.SameLine();
            ImGui.SetNextItemWidth(90);
            ImGui.InputInt("Port##csrp", ref dispPort);
            ImGui.EndDisabled();

            ImGui.Spacing();

            ImGui.BeginDisabled(running);
            ImGui.SetNextItemWidth(90);
            if (ImGui.InputInt("Proxy Port##plp", ref _listenPort))
                _listenPort = Math.Clamp(_listenPort, 1, 65535);
            ImGui.SameLine();
            UiHelper.MutedLabel("← client connects here");
            ImGui.EndDisabled();
        });

        ImGui.SameLine(0, 12);

        UiHelper.SectionBox("CAPTURE MODE", half, 185, () =>
        {
            UiHelper.MutedLabel("Select capture protocol:");
            ImGui.Spacing();

            ImGui.BeginDisabled(running);

            void ModeBtn(string lbl, CaptureMode m)
            {
                bool sel = _mode == m;
                ImGui.PushStyleColor(ImGuiCol.Button,
                    sel ? new Vector4(0.18f, 0.95f, 0.45f, 0.22f)
                        : MenuRenderer.ColBg3);
                ImGui.PushStyleColor(ImGuiCol.Text,
                    sel ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
                if (ImGui.Button(lbl + $"##cm{(int)m}", new Vector2(-1, 26)))
                    _mode = m;
                ImGui.PopStyleColor(2);
            }

            ModeBtn("UDP  —  Hytale (recommended)", CaptureMode.Udp);
            ModeBtn("TCP  —  Plain unencrypted",     CaptureMode.Tcp);
            ModeBtn("TLS  —  HTTPS intercept",       CaptureMode.Tls);

            ImGui.EndDisabled();

            ImGui.Spacing();
            string desc = _mode switch
            {
                CaptureMode.Udp => "Best for Hytale. Proxies UDP game packets.",
                CaptureMode.Tcp => "Use if server communicates over plain TCP.",
                CaptureMode.Tls => "Decrypts TLS. Fails if game pins certificates.",
                _               => ""
            };
            UiHelper.MutedLabel(desc);
        });

        ImGui.Spacing(); ImGui.Spacing();

        // Start / Stop row
        if (!running)
        {
            ImGui.BeginDisabled(!_config.IsSet);
            UiHelper.PrimaryButton(
                $"▶  Start {_mode} Capture + Copy Address",
                360, 34, () => StartCapture(localIp));
            ImGui.EndDisabled();

            if (!_config.IsSet)
            {
                ImGui.SameLine(0, 10);
                UiHelper.DangerText("Set server in Dashboard first");
            }
        }
        else
        {
            UiHelper.DangerButton("■  Stop", 100, 34, StopCapture);
            ImGui.SameLine(0, 16);
            string addr = $"{localIp}:{_listenPort}";
            UiHelper.AccentText($"Connect game to:  {addr}");
            ImGui.SameLine(0, 10);
            UiHelper.SecondaryButton("Copy##cpa", 54, 34, () =>
            {
                ImGui.SetClipboardText(addr);
                _log.Info($"[Capture] Copied {addr}");
            });
        }

        ImGui.Spacing();

        // TLS status row
        if (_mode == CaptureMode.Tls)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.10f, 0.07f, 0.18f, 1f));
            ImGui.BeginChild("##tlsi", new Vector2(-1, 30), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();
            ImGui.SetCursorPos(new Vector2(12, 6));
            ImGui.PushStyleColor(ImGuiCol.Text,
                _tlsIntercepting ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted(
                _tlsIntercepting ? "● TLS Active — Decrypting" : "● TLS Inactive");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 20);
            UiHelper.MutedLabel(_tlsCertStatus);
            ImGui.EndChild();
            ImGui.Spacing();
        }

        // Status bar (3-step progress)
        var  pkts      = _capture.GetPackets();
        bool hasClient = _capture.TotalClients > 0 || _udpProxy.TotalClients > 0;
        bool hasPkts   = pkts.Count > 0;
        string modeStatus = _mode switch {
            CaptureMode.Udp => _udpProxy.IsRunning   ? $"● PROXY ON (UDP)" : "● PROXY OFF",
            CaptureMode.Tcp => _capture.IsRunning     ? $"● PROXY ON (TCP)" : "● PROXY OFF",
            CaptureMode.Tls => _tlsIntercepting       ? $"● PROXY ON (TLS)" : "● PROXY OFF",
            _               => "● PROXY OFF"
        };

        ImGui.PushStyleColor(ImGuiCol.ChildBg,
            running ? new Vector4(0.05f, 0.15f, 0.06f, 1f)
                    : new Vector4(0.13f, 0.05f, 0.05f, 1f));
        ImGui.BeginChild("##sbar", new Vector2(-1, 34), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 8));

        ImGui.PushStyleColor(ImGuiCol.Text,
            running ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(running ? $"● PROXY ON ({_mode})" : "● PROXY OFF");
        ImGui.PopStyleColor();

        ImGui.SameLine(200);
        ImGui.PushStyleColor(ImGuiCol.Text,
            hasClient ? MenuRenderer.ColAccent
                      : (running ? MenuRenderer.ColWarn : MenuRenderer.ColTextMuted));
        ImGui.TextUnformatted(hasClient ? "● CLIENT CONNECTED"
                                        : (running ? "● WAITING FOR CLIENT" : "● —"));
        ImGui.PopStyleColor();

        ImGui.SameLine(420);
        ImGui.PushStyleColor(ImGuiCol.Text,
            hasPkts ? MenuRenderer.ColAccent
                    : (hasClient ? MenuRenderer.ColWarn : MenuRenderer.ColTextMuted));
        ImGui.TextUnformatted(hasPkts ? $"● {pkts.Count} PACKETS"
                                      : (hasClient ? "● DO SOMETHING IN GAME" : "● —"));
        ImGui.PopStyleColor();

        ImGui.EndChild();
    }

    // ── Packet list ───────────────────────────────────────────────────────

    private void RenderPacketList()
    {
        var   packets = _capture.GetPackets();
        float w       = ImGui.GetContentRegionAvail().X;

        // Filter toolbar
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##fbar", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.SetNextItemWidth(180);
        ImGui.InputText("##flt", ref _filterText, 128);
        ImGui.SameLine(0, 12);
        ImGui.Checkbox("C→S##cs", ref _showClientServer);
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("S→C##sc", ref _showServerClient);
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("Auto-scroll##as", ref _autoScroll);
        ImGui.SameLine(0, 16);
        UiHelper.MutedLabel($"{packets.Count} packets  |  filter:");
        ImGui.EndChild();

        ImGui.Spacing();

        if (packets.Count == 0)
        {
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 40);
            float tw = ImGui.CalcTextSize("Start proxy above and connect your game client.").X;
            ImGui.SetCursorPosX((w - tw) * 0.5f);
            UiHelper.MutedLabel("Start proxy above and connect your game client.");
            return;
        }

        var filtered = packets.Where(p =>
        {
            if (!_showClientServer && p.Direction == PacketDirection.ClientToServer)
                return false;
            if (!_showServerClient && p.Direction == PacketDirection.ServerToClient)
                return false;
            if (!string.IsNullOrWhiteSpace(_filterText))
            {
                string f = _filterText.ToUpper();
                if (!p.HexString.Contains(f) && !p.AsciiPreview.ToUpper().Contains(f))
                    return false;
            }
            return true;
        }).ToList();

        float dw = 390f;
        float lw = ImGui.GetContentRegionAvail().X - dw - 8;
        float h  = ImGui.GetContentRegionAvail().Y;

        // Packet list pane
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##pl", new Vector2(lw, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 6));
        UiHelper.MutedLabel("   #      Time           Dir            Bytes  Preview");

        var dl = ImGui.GetWindowDrawList();
        var lp = ImGui.GetWindowPos();
        float ly = ImGui.GetCursorScreenPos().Y - 2;
        dl.AddLine(new Vector2(lp.X, ly), new Vector2(lp.X + lw, ly),
            ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        for (int i = 0; i < filtered.Count; i++)
        {
            var  p   = filtered[i];
            bool cs  = p.Direction == PacketDirection.ClientToServer;
            var  col = cs ? MenuRenderer.ColBlue : MenuRenderer.ColWarn;

            string dir = cs ? "C → S" : "S → C";
            string prv = p.AsciiPreview.Length > 18
                ? p.AsciiPreview[..18] + "…" : p.AsciiPreview;

            if (_selectedIndex == i)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(lw, 20),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }

            ImGui.PushStyleColor(ImGuiCol.Text, col);
            if (ImGui.Selectable(
                $"   {i + 1,-5} {p.TimestampLabel}  {dir,-14} {p.RawBytes.Length,-7} {prv}##pk{i}",
                _selectedIndex == i, ImGuiSelectableFlags.None, new Vector2(0, 20)))
                _selectedIndex = i;
            ImGui.PopStyleColor();
        }

        if (_autoScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 20)
            ImGui.SetScrollHereY(1.0f);

        ImGui.EndChild();
        ImGui.SameLine(0, 8);

        // Detail pane
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##pd", new Vector2(dw, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        if (_selectedIndex >= 0 && _selectedIndex < filtered.Count)
        {
            var  p  = filtered[_selectedIndex];
            bool cs = p.Direction == PacketDirection.ClientToServer;

            ImGui.SetCursorPos(new Vector2(12, 10));
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
            ImGui.TextUnformatted("PACKET DETAIL");
            ImGui.PopStyleColor();

            var ddl = ImGui.GetWindowDrawList();
            var dp  = ImGui.GetWindowPos();
            float dly = ImGui.GetCursorScreenPos().Y - 2;
            ddl.AddLine(new Vector2(dp.X + 12, dly),
                        new Vector2(dp.X + dw  - 12, dly),
                        ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
            ImGui.Spacing();

            UiHelper.StatusRow("Time",      p.TimestampLabel, true, 80);
            UiHelper.StatusRow("Direction",
                cs ? "Client → Server" : "Server → Client", cs, 80);
            UiHelper.StatusRow("Size",      $"{p.RawBytes.Length} bytes", true, 80);

            if (p.RawBytes.Length > 0)
            {
                ImGui.Spacing();
                UiHelper.MutedLabel("Packet ID (first byte):");
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
                ImGui.Text($"  0x{p.RawBytes[0]:X2}   ({p.RawBytes[0]})");
                ImGui.PopStyleColor();
            }

            ImGui.Spacing();
            ddl.AddLine(
                new Vector2(dp.X + 12, ImGui.GetCursorScreenPos().Y),
                new Vector2(dp.X + dw  - 12, ImGui.GetCursorScreenPos().Y),
                ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
            ImGui.Spacing();

            UiHelper.MutedLabel("Hex dump:");
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.7f, 1.0f, 0.7f, 1f));
            for (int row = 0; row < p.RawBytes.Length; row += 16)
            {
                int    len = Math.Min(16, p.RawBytes.Length - row);
                string hex = string.Join(" ", p.RawBytes.Skip(row).Take(len)
                    .Select(b => $"{b:X2}"));
                string asc = new string(p.RawBytes.Skip(row).Take(len)
                    .Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
                ImGui.Text($"{row:X4}  {hex,-47}  {asc}");
            }
            ImGui.PopStyleColor();

            ImGui.Spacing();
            UiHelper.MutedLabel("ASCII:");
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.9f, 0.9f, 0.6f, 1f));
            ImGui.TextWrapped(p.AsciiPreview);
            ImGui.PopStyleColor();

            ImGui.Spacing();
            UiHelper.SecondaryButton("Copy Hex##cph", -1, 26, () =>
            {
                ImGui.SetClipboardText(p.HexString);
                _log.Info($"[Capture] Pkt #{_selectedIndex + 1} copied.");
            });
            UiHelper.SecondaryButton("Send to Log##stl", -1, 26, () =>
                _log.Info($"[Capture] Pkt #{_selectedIndex + 1}:\n{p.HexString}"));
        }
        else
        {
            ImGui.SetCursorPosY(h * 0.4f);
            float tw2 = ImGui.CalcTextSize("← select a packet").X;
            ImGui.SetCursorPosX((dw - tw2) * 0.5f);
            UiHelper.MutedLabel("← select a packet");
        }

        ImGui.EndChild();
    }

    // ── Start / Stop ──────────────────────────────────────────────────────

    private void StartCapture(string localIp)
    {
        switch (_mode)
        {
            case CaptureMode.Udp:
                _udpProxy.Start("0.0.0.0", _listenPort,
                    _config.ServerIp, _config.ServerPort);
                break;
            case CaptureMode.Tcp:
                _capture.Start("0.0.0.0", _listenPort,
                    _config.ServerIp, _config.ServerPort);
                break;
            case CaptureMode.Tls:
                StartTlsProxy();
                break;
        }

        string addr = $"{localIp}:{_listenPort}";
        ImGui.SetClipboardText(addr);
        _log.Success($"[Capture] Address copied: {addr}");
        _log.Info("[Capture] Disconnect in game and reconnect to address above.");
    }

    private void StopCapture()
    {
        _capture.Stop();
        _udpProxy.Stop();
        _tlsCts?.Cancel();
        _tlsIntercepting = false;
        _log.Warn("[Capture] All capture stopped.");
    }

    /// Exposed so PacketTab and PrivilegeTab can inject packets via the proxy.
    public UdpProxy UdpProxy => _udpProxy;

    // ── TLS proxy ─────────────────────────────────────────────────────────

    private void StartTlsProxy()
    {
        _tlsCertStatus = "Generating...";
        try
        {
            _tlsCert       = GenerateSelfSignedCert(_config.ServerIp);
            _tlsCertStatus = $"Ready (CN={_config.ServerIp})";
            _log.Success("[TLS] Certificate generated.");
        }
        catch (Exception ex)
        {
            _tlsCertStatus = $"Error: {ex.Message}";
            _log.Error($"[TLS] Cert: {ex.Message}");
            return;
        }

        _tlsCts          = new CancellationTokenSource();
        _tlsIntercepting = true;
        Task.Run(() => TlsListenLoop(_tlsCts.Token));
        _log.Success($"[TLS] Proxy on port {_listenPort}");
    }

    private async Task TlsListenLoop(CancellationToken ct)
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Any, _listenPort);
        listener.Start();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                _capture.IncrementClients();
                _log.Success($"[TLS] Client from {client.Client.RemoteEndPoint}");
                _ = Task.Run(() => HandleTlsClient(client, ct), ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (_tlsIntercepting) _log.Error($"[TLS] Listener: {ex.Message}");
        }
        finally
        {
            listener.Stop();
            _tlsIntercepting = false;
        }
    }

    private async Task HandleTlsClient(System.Net.Sockets.TcpClient client,
                                        CancellationToken ct)
    {
        System.Net.Sockets.TcpClient? server = null;
        SslStream? clientSsl = null;
        SslStream? serverSsl = null;
        try
        {
            clientSsl = new SslStream(client.GetStream(), false,
                (s, c, ch, e) => true);
            await clientSsl.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions
                {
                    ServerCertificate         = _tlsCert,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols       =
                        System.Security.Authentication.SslProtocols.Tls12 |
                        System.Security.Authentication.SslProtocols.Tls13,
                }, ct);
            _log.Success("[TLS] ✓ Client handshake — decrypting!");

            server    = new System.Net.Sockets.TcpClient();
            await server.ConnectAsync(_config.ServerIp, _config.ServerPort, ct);
            serverSsl = new SslStream(server.GetStream(), false,
                (s, c, ch, e) => true);
            await serverSsl.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = _config.ServerIp,
                    RemoteCertificateValidationCallback = (s, c, ch, e) => true,
                    EnabledSslProtocols =
                        System.Security.Authentication.SslProtocols.Tls12 |
                        System.Security.Authentication.SslProtocols.Tls13,
                }, ct);
            _log.Success("[TLS] ✓ Server handshake — full intercept active!");

            await Task.WhenAny(
                TlsPipeAsync(clientSsl, serverSsl, PacketDirection.ClientToServer, ct),
                TlsPipeAsync(serverSsl, clientSsl, PacketDirection.ServerToClient, ct));
        }
        catch (Exception ex)
        {
            if (ex.Message.Contains("authentication") || ex.Message.Contains("handshake"))
            {
                _log.Error("[TLS] Handshake failed — game likely pins certificates.");
                _log.Warn("[TLS] Switch to UDP mode instead.");
            }
            else _log.Error($"[TLS] {ex.Message}");
        }
        finally
        {
            clientSsl?.Dispose(); serverSsl?.Dispose();
            client.Dispose(); server?.Dispose();
        }
    }

    private async Task TlsPipeAsync(SslStream source, SslStream dest,
                                     PacketDirection dir, CancellationToken ct)
    {
        var buf = new byte[65536];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int n = await source.ReadAsync(buf, ct);
                if (n == 0) break;
                var chunk = new byte[n];
                Array.Copy(buf, chunk, n);
                await dest.WriteAsync(buf.AsMemory(0, n), ct);
                var pkt = new CapturedPacket
                {
                    Timestamp    = DateTime.Now,
                    Direction    = dir,
                    RawBytes     = chunk,
                    HexString    = PacketCapture.ToHex(chunk),
                    AsciiPreview = PacketCapture.ToAscii(chunk),
                };
                _capture.AddPacketExternal(pkt);
                string d = dir == PacketDirection.ClientToServer ? "C→S" : "S→C";
                _log.Info($"[TLS][{d}] {n}b decrypted | " +
                          $"{pkt.HexString[..Math.Min(48, pkt.HexString.Length)]}");
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!ct.IsCancellationRequested)
                _log.Error($"[TLS] Pipe ({dir}): {ex.Message}");
        }
    }

    private static X509Certificate2 GenerateSelfSignedCert(string host)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            $"CN={host}", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature |
            X509KeyUsageFlags.KeyEncipherment, false));

        var san = new SubjectAlternativeNameBuilder();
        if (IPAddress.TryParse(host, out var ip)) san.AddIpAddress(ip);
        else san.AddDnsName(host);
        req.CertificateExtensions.Add(san.Build());

        var cert = req.CreateSelfSigned(
            DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddYears(1));

        return new X509Certificate2(
            cert.Export(X509ContentType.Pfx), (string?)null,
            X509KeyStorageFlags.Exportable);
    }

    private static string GetLocalIp()
    {
        try
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            var ip   = host.AddressList.FirstOrDefault(
                a => a.AddressFamily == AddressFamily.InterNetwork);
            return ip?.ToString() ?? "127.0.0.1";
        }
        catch { return "127.0.0.1"; }
    }
}
