using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Text;
using System.Net.Sockets;

namespace HytaleSecurityTester.Tabs;

public class PacketTab : ITab
{
    public string Title => "  Packet Exploiting  ";

    private readonly TestLog       _log;
    private readonly PacketCapture _capture;
    private readonly UdpProxy      _udpProxy;
    private readonly ServerConfig  _config;

    // Shared paste field — used by both Replay and Sequence tests
    private string _capturedPacket = "";

    // Malformed
    private int    _packetId    = 0x00;
    private string _payloadHex  = "DEADBEEF00FF";
    private int    _payloadLen  = 64;

    // Replay
    private int  _replayCount   = 50;
    private int  _replayDelayMs = 10;

    // Flood
    private int  _floodCount    = 500;
    private int  _floodPacketId = 0x10;
    private bool _floodRunning  = false;
    private CancellationTokenSource? _floodCts;

    // Sequence
    private bool _outOfOrder   = false;
    private bool _duplicateSeq = false;
    private int  _seqOffset    = -1;

    public PacketTab(TestLog log, PacketCapture capture, UdpProxy udpProxy, ServerConfig config)
    {
        _log      = log;
        _capture  = capture;
        _udpProxy = udpProxy;
        _config   = config;
    }

    public void Render()
    {
        float w    = ImGui.GetContentRegionAvail().X;
        float half = (w - 12) * 0.5f;

        RenderStatusBar(w);
        ImGui.Spacing(); ImGui.Spacing();

        UiHelper.SectionBox("MALFORMED PACKETS", half, 210, RenderMalformed);
        ImGui.SameLine(0, 12);
        UiHelper.SectionBox("REPLAY ATTACK",     half, 210, RenderReplay);

        ImGui.Spacing(); ImGui.Spacing();

        UiHelper.SectionBox("FLOOD / RATE LIMIT",     half, 160, RenderFlood);
        ImGui.SameLine(0, 12);
        UiHelper.SectionBox("SEQUENCE MANIPULATION",  half, 160, RenderSequence);

        ImGui.Spacing(); ImGui.Spacing();

        UiHelper.SectionBox(
            "CAPTURED PACKET HEX  ← paste here for Replay & Sequence tests",
            w, 66, RenderPasteField);
    }

    private void RenderStatusBar(float w)
    {
        bool srv = _config.IsSet;
        bool ses = _capture.IsRunning && _capture.ActiveSessions > 0;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##pst", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));
        ImGui.PushStyleColor(ImGuiCol.Text,
            srv ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(srv
            ? $"● {_config.ServerIp}:{_config.ServerPort}"
            : "● No server — set in Dashboard");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 24);
        ImGui.PushStyleColor(ImGuiCol.Text,
            ses ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(ses
            ? "● Proxy session active — injecting via proxy"
            : "● No proxy session — will send direct UDP");
        ImGui.PopStyleColor();
        ImGui.EndChild();
    }

    private void RenderMalformed()
    {
        UiHelper.MutedLabel("Craft packets with invalid fields to probe server validation.");
        ImGui.Spacing();

        ImGui.SetNextItemWidth(110);
        ImGui.InputInt("Packet ID##pid", ref _packetId);
        _packetId = Math.Clamp(_packetId, 0, 0xFFFF);
        ImGui.SameLine();
        UiHelper.AccentText($"0x{_packetId:X4}");

        ImGui.SetNextItemWidth(-72);
        ImGui.InputText("Payload##pay", ref _payloadHex, 512);
        ImGui.SameLine(0, 6);
        UiHelper.SecondaryButton("Rnd", 62, 22, () => _payloadHex = RandomHex(16));

        ImGui.SetNextItemWidth(100);
        ImGui.InputInt("Pad bytes##pl", ref _payloadLen);
        _payloadLen = Math.Clamp(_payloadLen, 0, 65535);
        ImGui.Spacing();

        UiHelper.WarnButton("Send Malformed", 148, 28, SendMalformed);
        ImGui.SameLine(0, 6);
        UiHelper.WarnButton("Oversized 1MB",  130, 28, SendOversized);
        ImGui.SameLine(0, 6);
        UiHelper.WarnButton("Empty", 80, 28,
            () => SendRaw(new byte[] { (byte)_packetId }, "empty"));
    }

    private void RenderReplay()
    {
        UiHelper.MutedLabel("Re-send a captured packet to test replay protection.");
        ImGui.Spacing();
        UiHelper.MutedLabel("Uses the hex pasted in the field at the bottom.");
        ImGui.Spacing();

        ImGui.SetNextItemWidth(110);
        ImGui.InputInt("Count##rc", ref _replayCount);
        _replayCount = Math.Clamp(_replayCount, 1, 10000);
        ImGui.SameLine(0, 12);
        ImGui.SetNextItemWidth(110);
        ImGui.InputInt("Delay ms##rd", ref _replayDelayMs);
        _replayDelayMs = Math.Clamp(_replayDelayMs, 0, 5000);
        ImGui.Spacing();

        UiHelper.WarnButton("Start Replay", 148, 28, () =>
        {
            if (string.IsNullOrWhiteSpace(_capturedPacket))
                _log.Error("[Replay] Paste packet hex in the field at the bottom first.");
            else StartReplay();
        });

        ImGui.Spacing();
        UiHelper.MutedLabel("Watch: item duped or action repeats = no replay protection.");
    }

    private void RenderFlood()
    {
        UiHelper.MutedLabel("Rapidly flood the server to test rate limiting.");
        ImGui.Spacing();

        ImGui.SetNextItemWidth(110);
        ImGui.InputInt("Packet ID##fid", ref _floodPacketId);
        ImGui.SameLine();
        UiHelper.AccentText($"0x{_floodPacketId:X2}");

        ImGui.SetNextItemWidth(110);
        ImGui.InputInt("Count##fc", ref _floodCount);
        _floodCount = Math.Clamp(_floodCount, 1, 100_000);
        ImGui.Spacing();

        if (_floodRunning)
        {
            UiHelper.DangerButton("Stop", 100, 28, () =>
            {
                _floodCts?.Cancel();
                _floodRunning = false;
                _log.Warn("[Flood] Stopped.");
            });
            ImGui.SameLine(0, 10);
            UiHelper.WarnText("● Flooding...");
        }
        else
        {
            UiHelper.WarnButton("Start Flood", 130, 28, StartFlood);
        }
    }

    private void RenderSequence()
    {
        UiHelper.MutedLabel("Test out-of-order or duplicate sequence IDs.");
        ImGui.Spacing();

        ImGui.Checkbox("Out-of-order##oo", ref _outOfOrder);
        ImGui.SameLine(0, 16);
        ImGui.Checkbox("Duplicate seq##ds", ref _duplicateSeq);

        ImGui.SetNextItemWidth(100);
        ImGui.InputInt("Seq offset##so", ref _seqOffset);
        ImGui.Spacing();

        UiHelper.WarnButton("Run Sequence Test", 170, 28, () =>
        {
            if (string.IsNullOrWhiteSpace(_capturedPacket))
            { _log.Error("[SeqTest] Paste packet hex at the bottom first."); return; }
            try
            {
                string clean = _capturedPacket.Replace(" ", "");
                if (clean.Length % 2 != 0) clean += "0";
                byte[] bp = Convert.FromHexString(clean);
                Task.Run(async () =>
                {
                    if (_outOfOrder)
                    {
                        for (int s = 3; s >= 1; s--)
                        {
                            var p = ModifySeq(bp, s + _seqOffset);
                            if (!await TrySendAsync(p)) break;
                            await Task.Delay(10);
                        }
                    }

                    if (_duplicateSeq)
                    {
                        for (int i = 0; i < 5; i++)
                        {
                            var p = ModifySeq(bp, _seqOffset);
                            if (!await TrySendAsync(p)) break;
                            await Task.Delay(10);
                        }
                    }

                    _log.Success("[SeqTest] Done.");
                });
            }
            catch (Exception ex) { _log.Error($"[SeqTest] {ex.Message}"); }
        });
    }

    private void RenderPasteField()
    {
        UiHelper.MutedLabel("Capture tab → click packet → Copy Hex → Ctrl+V here");
        ImGui.SetNextItemWidth(-1);
        ImGui.InputText("##ch", ref _capturedPacket, 4096);
    }

    // ── Logic ─────────────────────────────────────────────────────────────

    private void SendMalformed()
    {
        try
        {
            string clean = _payloadHex.Replace(" ", "");
            if (clean.Length % 2 != 0) clean += "0";
            byte[] payload;
            try { payload = Convert.FromHexString(clean); }
            catch { _log.Error("[Malformed] Invalid hex."); return; }

            var pkt = new List<byte> { (byte)(_packetId & 0xFF) };
            pkt.AddRange(payload);
            if (_payloadLen > 0)
            {
                var pad = new byte[_payloadLen];
                new Random().NextBytes(pad);
                pkt.AddRange(pad);
            }
            SendRaw(pkt.ToArray(), "malformed");
        }
        catch (Exception ex) { _log.Error($"[Malformed] {ex.Message}"); }
    }

    private void SendOversized()
    {
        var data = new byte[1024 * 1024];
        new Random().NextBytes(data);
        data[0] = (byte)(_packetId & 0xFF);
        SendRaw(data, "oversized");
    }

    private void StartReplay()
    {
        try
        {
            string clean = _capturedPacket.Replace(" ", "").Replace("\n", "");
            if (clean.Length % 2 != 0) clean += "0";
            byte[] data  = Convert.FromHexString(clean);
            int    count = _replayCount;
            int    delay = _replayDelayMs;

            _log.Info($"[Replay] {count}x delay={delay}ms");

            Task.Run(async () =>
            {
                int sent = 0;
                for (int i = 0; i < count; i++)
                {
                    bool ok = await TrySendAsync(data);
                    if (!ok)
                        try { DirectSend(data); ok = true; }
                        catch (Exception ex) { _log.Error($"[Replay] {ex.Message}"); break; }
                    sent++;
                    if (delay > 0) await Task.Delay(delay);
                }
                _log.Success($"[Replay] {sent}/{count} sent.");
            });
        }
        catch (Exception ex) { _log.Error($"[Replay] {ex.Message}"); }
    }

    private void StartFlood()
    {
        _floodRunning = true;
        _floodCts     = new CancellationTokenSource();
        int count = _floodCount, pid = _floodPacketId;
        var cts   = _floodCts;

        _log.Info($"[Flood] {count}x ID=0x{pid:X2}");

        Task.Run(async () =>
        {
            var rng = new Random(); int sent = 0;
            try
            {
                for (int i = 0; i < count; i++)
                {
                    if (cts.IsCancellationRequested) break;
                    var data = new byte[rng.Next(4, 64)];
                    rng.NextBytes(data); data[0] = (byte)(pid & 0xFF);
                    if (!await TrySendAsync(data)) break;
                    sent++;
                    if (sent % 100 == 0) _log.Info($"[Flood] {sent}/{count}");
                }
            }
            catch (Exception ex) { _log.Error($"[Flood] {ex.Message}"); }
            finally { _floodRunning = false; _log.Success($"[Flood] {sent}/{count}."); }
        });
    }

    private void SendRaw(byte[] data, string lbl)
    {
        // Prefer UDP proxy injection (injects into the real game session)
        if (_udpProxy.IsRunning && _udpProxy.InjectToServer(data))
        {
            _log.Success($"[{lbl}] {data.Length}b injected via UDP proxy.");
            return;
        }
        // Fall back to legacy TCP session injection
        bool tcpOk = _capture.InjectToServer(data).GetAwaiter().GetResult();
        if (tcpOk) { _log.Success($"[{lbl}] {data.Length}b injected via TCP."); return; }

        // Last resort: direct UDP (no active session)
        _log.Warn($"[{lbl}] No active session — sending direct UDP to " +
                  $"{_config.ServerIp}:{_config.ServerPort}");
        try { DirectSend(data); _log.Success($"[{lbl}] {data.Length}b sent."); }
        catch (Exception ex) { _log.Error($"[{lbl}] {ex.Message}"); }
    }

    private async Task<bool> TrySendAsync(byte[] data)
    {
        if (_udpProxy.IsRunning && _udpProxy.InjectToServer(data)) return true;
        if (await _capture.InjectToServer(data)) return true;
        try { DirectSend(data); return true; }
        catch { return false; }
    }

    private void DirectSend(byte[] data)
    {
        using var udp = new UdpClient();
        udp.Connect(_config.ServerIp, _config.ServerPort);
        udp.Send(data, data.Length);
    }

    private static byte[] ModifySeq(byte[] src, int seq)
    {
        var c = (byte[])src.Clone();
        if (c.Length >= 5)
        {
            var b = BitConverter.GetBytes(seq);
            c[1] = b[0]; c[2] = b[1]; c[3] = b[2]; c[4] = b[3];
        }
        return c;
    }

    private static string RandomHex(int n)
    {
        var rng = new Random(); var sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.AppendFormat("{0:X2}", rng.Next(256));
        return sb.ToString();
    }
}
