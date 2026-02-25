using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Text;
using System.Net.Sockets;
using System.Diagnostics;

namespace HytaleSecurityTester.Tabs;

public class PacketTab : ITab
{
    public string Title => "  Packet Exploiting  ";

    private readonly TestLog       _log;
    private readonly PacketCapture _capture;
    private readonly UdpProxy      _udpProxy;
    private readonly ServerConfig  _config;

    // ── Hex Editor state ─────────────────────────────────────────────────
    private string _hexEditorInput  = "2A 00 00 00 00";
    private int    _hexEditorCursor = -1;   // byte index of highlighted/edited byte
    private string _hexEditorError  = "";

    // Target ID integration - linked from ItemInspector via ServerConfig
    private bool   _hexHighlightTargetId = true;

    // ── Malformed ────────────────────────────────────────────────────────
    private int    _packetId    = 0x00;
    private string _payloadHex  = "DEADBEEF00FF";
    private int    _payloadLen  = 64;

    // ── Replay ───────────────────────────────────────────────────────────
    private int  _replayCount   = 50;
    private int  _replayDelayMs = 10;

    // ── Flood ────────────────────────────────────────────────────────────
    private int  _floodCount    = 500;
    private int  _floodPacketId = 0x10;
    private int  _burstRatePps  = 1000;     // packets per second cap
    private int  _interPktDelayMs = 0;      // ms between each send
    private bool _floodRunning  = false;
    private CancellationTokenSource? _floodCts;

    // ── Sequence ─────────────────────────────────────────────────────────
    private bool _outOfOrder   = false;
    private bool _duplicateSeq = false;
    private int  _seqOffset    = -1;

    // ── Sequence Builder / Combo chains ──────────────────────────────────
    private List<(string Label, string Hex, int DelayMs)> _comboChain = new();
    private string _comboNewLabel = "";
    private string _comboNewHex   = "";
    private int    _comboNewDelay = 0;
    private bool   _comboRunning  = false;

    // ── Shared paste ─────────────────────────────────────────────────────
    private string _capturedPacket = "";

    // ── Auto-checksum ────────────────────────────────────────────────────
    private bool   _autoChecksum   = false;
    private int    _checksumOffset = 1;     // byte offset where checksum lives

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

        // ── Sub-section layout ─────────────────────────────────────────
        if (ImGui.BeginTabBar("##pkttabs", ImGuiTabBarFlags.FittingPolicyScroll))
        {
            if (ImGui.BeginTabItem("  Hex Editor  "))
            { ImGui.Spacing(); RenderHexEditor(w); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Malformed  "))
            { ImGui.Spacing(); UiHelper.SectionBox("MALFORMED PACKETS", w, 0, RenderMalformed); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Replay  "))
            { ImGui.Spacing(); UiHelper.SectionBox("REPLAY ATTACK", w, 0, RenderReplay); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Flood  "))
            { ImGui.Spacing(); RenderFloodSection(w); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Sequence  "))
            { ImGui.Spacing(); UiHelper.SectionBox("SEQUENCE MANIPULATION", w, 0, RenderSequence); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Combo Chain  "))
            { ImGui.Spacing(); RenderComboChain(w); ImGui.EndTabItem(); }
            ImGui.EndTabBar();
        }
    }

    private void RenderStatusBar(float w)
    {
        bool srv    = _config.IsSet;
        bool udpRun = _udpProxy.IsRunning;
        bool tcpSes = _capture.IsRunning && _capture.ActiveSessions > 0;
        bool anyProxy = udpRun || tcpSes;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##pst", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, srv ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(srv
            ? $"[>] {_config.ServerIp}:{_config.ServerPort}"
            : "[>] No server - set in Dashboard");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 24);
        ImGui.PushStyleColor(ImGuiCol.Text, anyProxy ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
        string proxyState = udpRun  ? $"[>] UDP proxy ({_udpProxy.ActiveSessions} session(s))"
                          : tcpSes  ? "[>] TCP session active"
                          :           "[>] No proxy - start in Capture tab";
        ImGui.TextUnformatted(proxyState);
        ImGui.PopStyleColor();
        if (_config.HasTargetItem)
        {
            ImGui.SameLine(0, 24);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
            ImGui.TextUnformatted($"[*] Target ID: {_config.TargetItemId}");
            ImGui.PopStyleColor();
        }
        ImGui.EndChild();
    }

    // ── Hex Editor ────────────────────────────────────────────────────────

    private void RenderHexEditor(float w)
    {
        UiHelper.SectionBox("HEX EDITOR", w, 0, () =>
        {
            UiHelper.MutedLabel("Edit packet bytes directly. Space-separated hex (e.g. 2A 00 01 FF).");
            ImGui.Spacing();

            // Target-ID auto-inject
            if (_config.HasTargetItem)
            {
                ImGui.Checkbox("Highlight/inject Target ID bytes##hxlnk", ref _hexHighlightTargetId);
                if (_hexHighlightTargetId)
                {
                    ImGui.SameLine(0, 10);
                    UiHelper.MutedLabel($"(Target ID: {_config.TargetItemId} = 0x{_config.TargetItemId:X8})");
                    ImGui.SameLine(0, 10);
                    UiHelper.SecondaryButton("Inject at cursor##hxinj", 130, 22, () =>
                    {
                        InjectTargetIdAtCursor();
                    });
                }
            }

            // Main hex input
            ImGui.SetNextItemWidth(-1);
            bool changed = ImGui.InputText("##hexedit", ref _hexEditorInput, 4096);
            if (changed) _hexEditorError = "";

            if (!string.IsNullOrEmpty(_hexEditorError))
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
                ImGui.TextUnformatted($"  {_hexEditorError}");
                ImGui.PopStyleColor();
            }

            // Parse and display byte preview with colour coding
            ImGui.Spacing();
            var bytes = TryParseHexEditor(_hexEditorInput);
            if (bytes != null && bytes.Length > 0)
            {
                // Render bytes as coloured tiles
                var dl  = ImGui.GetWindowDrawList();
                var pos = ImGui.GetCursorScreenPos();
                const float TileW = 30f, TileH = 22f, TileGap = 3f;
                float rowW = w - 24f;
                int   cols = Math.Max(1, (int)(rowW / (TileW + TileGap)));

                // Find target ID byte positions
                var targetBytes = _config.HasTargetItem && _hexHighlightTargetId
                    ? BitConverter.GetBytes(_config.TargetItemId) : null;
                var highlightSet = new HashSet<int>();
                if (targetBytes != null)
                {
                    for (int si = 0; si <= bytes.Length - 4; si++)
                    {
                        if (bytes[si] == targetBytes[0] && bytes[si+1] == targetBytes[1] &&
                            bytes[si+2] == targetBytes[2] && bytes[si+3] == targetBytes[3])
                            for (int k = 0; k < 4; k++) highlightSet.Add(si + k);
                    }
                }

                float totalH = ((bytes.Length + cols - 1) / cols) * (TileH + TileGap);
                ImGui.Dummy(new Vector2(rowW, totalH));

                for (int bi = 0; bi < bytes.Length; bi++)
                {
                    int row = bi / cols, col = bi % cols;
                    var tp = pos + new Vector2(col * (TileW + TileGap), row * (TileH + TileGap));

                    bool isSelected = _hexEditorCursor == bi;
                    bool isTarget   = highlightSet.Contains(bi);

                    var tileBg = isSelected ? MenuRenderer.ColAccentDim
                               : isTarget   ? MenuRenderer.ColWarnDim
                               : MenuRenderer.ColBg3;
                    var tileText = isSelected ? MenuRenderer.ColAccent
                                 : isTarget   ? MenuRenderer.ColWarn
                                 : bi == 0    ? MenuRenderer.ColBlue   // packet ID byte
                                 :              MenuRenderer.ColText;

                    dl.AddRectFilled(tp, tp + new Vector2(TileW, TileH),
                        ImGui.ColorConvertFloat4ToU32(tileBg), 2f);
                    dl.AddText(tp + new Vector2(4, 4),
                        ImGui.ColorConvertFloat4ToU32(tileText),
                        $"{bytes[bi]:X2}");

                    // Click to select
                    ImGui.SetCursorScreenPos(tp);
                    ImGui.InvisibleButton($"##hxtile{bi}", new Vector2(TileW, TileH));
                    if (ImGui.IsItemClicked())
                        _hexEditorCursor = bi;
                }

                ImGui.SetCursorScreenPos(pos + new Vector2(0, totalH + 6));
                ImGui.Spacing();
                UiHelper.MutedLabel($"{bytes.Length} bytes  |  " +
                    (bytes.Length > 0 ? $"Pkt ID: 0x{bytes[0]:X2}" : "") +
                    (_hexEditorCursor >= 0 ? $"  |  Selected byte [{_hexEditorCursor}] = 0x{bytes[_hexEditorCursor]:X2}" : ""));
            }

            ImGui.Spacing();

            // Auto-checksum option
            ImGui.Checkbox("Auto-recalculate checksum before send##hexcs", ref _autoChecksum);
            if (_autoChecksum)
            {
                ImGui.SameLine(0, 10);
                ImGui.SetNextItemWidth(80);
                ImGui.InputInt("at byte##csbyte", ref _checksumOffset);
                _checksumOffset = Math.Clamp(_checksumOffset, 0, 255);
                ImGui.SameLine(0, 6);
                UiHelper.MutedLabel("(XOR checksum of all other bytes)");
            }

            ImGui.Spacing();

            UiHelper.WarnButton("Send via Proxy##hexsend", 160, 28, () =>
            {
                var data = TryParseHexEditor(_hexEditorInput);
                if (data == null || data.Length == 0)
                { _log.Error("[HexEd] Invalid hex - cannot send."); return; }
                if (_autoChecksum) ApplyXorChecksum(data, _checksumOffset);
                SendRaw(data, "HexEditor");
            });
            ImGui.SameLine(0, 8);
            UiHelper.SecondaryButton("Copy Hex##hexcopy", 100, 28, () =>
                ImGui.SetClipboardText(_hexEditorInput));
            ImGui.SameLine(0, 8);
            UiHelper.SecondaryButton("Load Captured##hexload", 140, 28, () =>
                _hexEditorInput = _capturedPacket);
        });

        ImGui.Spacing();
        UiHelper.SectionBox("CAPTURED PACKET HEX  <- paste here", w, 0, RenderPasteField);
    }

    private void InjectTargetIdAtCursor()
    {
        if (!_config.HasTargetItem) return;
        var bytes = TryParseHexEditor(_hexEditorInput);
        if (bytes == null) return;

        int insertAt = _hexEditorCursor >= 0 ? _hexEditorCursor : 0;
        var idBytes  = BitConverter.GetBytes(_config.TargetItemId);

        var list = new List<byte>(bytes);
        if (insertAt + 4 <= list.Count)
            for (int i = 0; i < 4; i++) list[insertAt + i] = idBytes[i];
        else
        {
            list.AddRange(new byte[Math.Max(0, insertAt - list.Count)]);
            list.AddRange(idBytes);
        }

        _hexEditorInput = string.Join(" ", list.Select(b => $"{b:X2}"));
        _log.Info($"[HexEd] Target ID 0x{_config.TargetItemId:X8} injected at byte {insertAt}.");
    }

    private static byte[]? TryParseHexEditor(string input)
    {
        try
        {
            var tokens = input.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var list   = new List<byte>(tokens.Length);
            foreach (var t in tokens)
            {
                string clean = t.Replace("0x", "").Replace("0X", "");
                list.Add(Convert.ToByte(clean, 16));
            }
            return list.ToArray();
        }
        catch { return null; }
    }

    private static void ApplyXorChecksum(byte[] data, int offset)
    {
        if (offset < 0 || offset >= data.Length) return;
        byte cs = 0;
        for (int i = 0; i < data.Length; i++)
            if (i != offset) cs ^= data[i];
        data[offset] = cs;
    }

    // ── Malformed ────────────────────────────────────────────────────────

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

    // ── Replay ───────────────────────────────────────────────────────────

    private void RenderReplay()
    {
        UiHelper.MutedLabel("Re-send a captured packet to test replay protection.");
        ImGui.Spacing();
        UiHelper.MutedLabel("Uses the hex from the 'Captured Packet Hex' field below.");
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
                _log.Error("[Replay] Paste packet hex in the field below first.");
            else StartReplay();
        });

        ImGui.Spacing();
        UiHelper.MutedLabel("Watch: item duped or action repeats = no replay protection.");
    }

    // ── Flood ────────────────────────────────────────────────────────────

    private void RenderFloodSection(float w)
    {
        float half = (w - 12) * 0.5f;

        UiHelper.SectionBox("FLOOD / RATE LIMIT TEST", half, 0, () =>
        {
            UiHelper.MutedLabel("Rapidly flood to test rate limiting.");
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
                UiHelper.WarnText("[>] Flooding...");
            }
            else
            {
                UiHelper.WarnButton("Start Flood", 130, 28, StartFlood);
            }
        });

        ImGui.SameLine(0, 12);

        UiHelper.SectionBox("SEND RATE CONTROLS", half, 0, () =>
        {
            UiHelper.MutedLabel("Burst Rate: max packets per second (0 = unlimited).");
            ImGui.SetNextItemWidth(-1);
            ImGui.SliderInt("Burst pkt/s##brrate", ref _burstRatePps, 0, 10000);

            ImGui.Spacing();
            UiHelper.MutedLabel("Inter-packet delay: wait between each send.");
            ImGui.SetNextItemWidth(-1);
            ImGui.SliderInt("Delay ms##ipd", ref _interPktDelayMs, 0, 1000);
            UiHelper.MutedLabel(_interPktDelayMs == 0
                ? "0 ms = send as fast as possible"
                : $"{_interPktDelayMs} ms between each packet");
        });

        ImGui.Spacing();
        UiHelper.SectionBox("CAPTURED PACKET HEX  <- paste here", w, 0, RenderPasteField);
    }

    // ── Sequence ─────────────────────────────────────────────────────────

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
                        for (int s = 3; s >= 1; s--)
                        { var p = ModifySeq(bp, s + _seqOffset); if (!await TrySendAsync(p)) break; await Task.Delay(10); }

                    if (_duplicateSeq)
                        for (int i = 0; i < 5; i++)
                        { var p = ModifySeq(bp, _seqOffset); if (!await TrySendAsync(p)) break; await Task.Delay(10); }

                    _log.Success("[SeqTest] Done.");
                });
            }
            catch (Exception ex) { _log.Error($"[SeqTest] {ex.Message}"); }
        });
    }

    // ── Combo Chain (Sequence Builder) ────────────────────────────────────

    private void RenderComboChain(float w)
    {
        UiHelper.SectionBox("SEQUENCE BUILDER - COMBO CHAIN", w, 0, () =>
        {
            UiHelper.MutedLabel("Chain multiple hex packets to fire as a single 'Combo' action.");
            UiHelper.MutedLabel("Each step fires after the specified delay. Useful for multi-step exploits.");
            ImGui.Spacing();

            // Add step
            ImGui.SetNextItemWidth(120);
            ImGui.InputText("Label##cbnl", ref _comboNewLabel, 32);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(-200);
            ImGui.InputText("Hex##cbnhex", ref _comboNewHex, 2048);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(80);
            ImGui.InputInt("Delay ms##cbndly", ref _comboNewDelay);
            _comboNewDelay = Math.Max(0, _comboNewDelay);
            ImGui.SameLine(0, 8);
            UiHelper.PrimaryButton("Add Step##cbadd", 80, 26, () =>
            {
                if (string.IsNullOrWhiteSpace(_comboNewHex)) return;
                string lbl = string.IsNullOrWhiteSpace(_comboNewLabel)
                    ? $"Step {_comboChain.Count + 1}" : _comboNewLabel;
                _comboChain.Add((lbl, _comboNewHex.Trim(), _comboNewDelay));
                _comboNewLabel = "";
                _comboNewHex   = "";
                _comboNewDelay = 0;
            });

            ImGui.Spacing();

            // Chain display
            if (_comboChain.Count == 0)
            {
                UiHelper.MutedLabel("No steps yet - add steps above.");
            }
            else
            {
                int removeIdx = -1;
                for (int ci = 0; ci < _comboChain.Count; ci++)
                {
                    var (lbl, hex, delay) = _comboChain[ci];
                    ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
                    ImGui.BeginChild($"##cbstep{ci}", new Vector2(-1, 50), ImGuiChildFlags.Border);
                    ImGui.PopStyleColor();
                    ImGui.SetCursorPos(new Vector2(8, 6));
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
                    ImGui.TextUnformatted($"[{ci + 1}] {lbl}");
                    ImGui.PopStyleColor();
                    ImGui.SameLine(0, 12);
                    UiHelper.MutedLabel($"delay: {delay}ms");
                    ImGui.SameLine(0, 12);
                    ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.6f, 1f, 0.6f, 1f));
                    string preview = hex.Length > 60 ? hex[..60] + "..." : hex;
                    ImGui.TextUnformatted(preview);
                    ImGui.PopStyleColor();
                    ImGui.SameLine(ImGui.GetContentRegionAvail().X - 50);
                    UiHelper.DangerButton($"✕##cbdel{ci}", 32, 20, () => removeIdx = ci);
                    ImGui.EndChild();
                    ImGui.Spacing();
                }
                if (removeIdx >= 0) _comboChain.RemoveAt(removeIdx);

                ImGui.Spacing();

                if (_comboRunning)
                {
                    UiHelper.DangerButton("Abort Combo##cbabort", 130, 30, () => _comboRunning = false);
                    ImGui.SameLine(0, 10);
                    UiHelper.WarnText("[>] Combo running...");
                }
                else
                {
                    UiHelper.WarnButton($"Fire Combo ({_comboChain.Count} steps)##cbfire", 200, 30, FireCombo);
                    ImGui.SameLine(0, 8);
                    UiHelper.DangerButton("Clear All##cbclear", 100, 30, () => _comboChain.Clear());
                }
            }
        });
    }

    private void FireCombo()
    {
        if (_comboChain.Count == 0) return;
        _comboRunning = true;
        var chain = _comboChain.ToList(); // snapshot

        _log.Info($"[Combo] Firing {chain.Count}-step combo chain.");

        Task.Run(async () =>
        {
            for (int ci = 0; ci < chain.Count; ci++)
            {
                if (!_comboRunning) { _log.Warn("[Combo] Aborted."); return; }
                var (lbl, hex, delay) = chain[ci];

                string clean = hex.Replace(" ", "");
                if (clean.Length % 2 != 0) clean += "0";
                byte[]? data;
                try { data = Convert.FromHexString(clean); }
                catch { _log.Error($"[Combo] Step {ci + 1} ({lbl}): invalid hex."); continue; }

                if (_autoChecksum && data.Length > _checksumOffset)
                    ApplyXorChecksum(data, _checksumOffset);

                bool ok = await TrySendAsync(data);
                _log.Info($"[Combo] Step {ci + 1}/{chain.Count} ({lbl}): {(ok ? "sent" : "FAILED")} {data.Length}b");

                if (delay > 0 && ci < chain.Count - 1)
                    await Task.Delay(delay);
            }
            _comboRunning = false;
            _log.Success("[Combo] Chain complete.");
        });
    }

    // ── Paste field ────────────────────────────────────────────────────────

    private void RenderPasteField()
    {
        UiHelper.MutedLabel("Capture tab -> click packet -> Copy Hex -> Ctrl+V here");
        ImGui.SetNextItemWidth(-1);
        ImGui.InputText("##ch", ref _capturedPacket, 4096);
    }

    // ── Logic ──────────────────────────────────────────────────────────────

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
                    if (!await TrySendAsync(data)) break;
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
        int  count    = _floodCount;
        int  pid      = _floodPacketId;
        int  ratePps  = _burstRatePps;
        int  delayMs  = _interPktDelayMs;
        var  cts      = _floodCts;

        _log.Info($"[Flood] {count}x ID=0x{pid:X2} rate={ratePps}pps delay={delayMs}ms");

        Task.Run(async () =>
        {
            var rng = new Random(); int sent = 0;
            var sw  = Stopwatch.StartNew();
            try
            {
                for (int i = 0; i < count; i++)
                {
                    if (cts.IsCancellationRequested) break;

                    // Rate limiting via Stopwatch
                    if (ratePps > 0)
                    {
                        double targetMs = sent * 1000.0 / ratePps;
                        while (sw.Elapsed.TotalMilliseconds < targetMs)
                            await Task.Yield();
                    }

                    var data = new byte[rng.Next(4, 64)];
                    rng.NextBytes(data); data[0] = (byte)(pid & 0xFF);
                    if (!await TrySendAsync(data)) break;
                    sent++;
                    if (delayMs > 0) await Task.Delay(delayMs);
                    if (sent % 100 == 0) _log.Info($"[Flood] {sent}/{count}");
                }
            }
            catch (Exception ex) { _log.Error($"[Flood] {ex.Message}"); }
            finally { _floodRunning = false; _log.Success($"[Flood] {sent}/{count}."); }
        });
    }

    private void SendRaw(byte[] data, string lbl)
    {
        if (_udpProxy.IsRunning && _udpProxy.InjectToServer(data))
        { _log.Success($"[{lbl}] {data.Length}b -> UDP proxy."); return; }
        bool tcpOk = _capture.InjectToServer(data).GetAwaiter().GetResult();
        if (tcpOk) { _log.Success($"[{lbl}] {data.Length}b -> TCP."); return; }
        _log.Warn($"[{lbl}] No session - direct UDP.");
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
