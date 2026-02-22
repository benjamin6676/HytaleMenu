using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Response Analyser tab.
///
/// Every time you fire a test packet from ANY tab, this tab captures what
/// the server sends back and tells you whether it accepted, denied, or
/// ignored the packet — so you're never testing blind.
///
/// Features:
///   - Live response feed with outcome classification
///   - Per-response detail: server packet IDs, hex dump, analysis
///   - Statistics: accept rate, deny rate, no-response rate
///   - Filter by outcome type
///   - Manual test-fire with response tracking built in
/// </summary>
public class ResponseAnalyserTab : ITab
{
    public string Title => "  Response Analyser  ";

    private readonly TestLog         _log;
    private readonly ResponseTracker _tracker;
    private readonly PacketCapture   _capture;
    private readonly UdpProxy        _udpProxy;
    private readonly PacketStore     _store;
    private readonly ServerConfig    _config;

    // UI state
    private int    _selectedIdx     = -1;
    private int    _filterMode      = 0; // 0=all, 1=accepted, 2=denied, 3=no response, 4=kicked
    private bool   _autoScroll      = true;
    private int    _windowMs        = 500;
    private bool   _tracking        = true;

    // Manual fire
    private string _testHex         = "";
    private string _testTag         = "Manual test";
    private int    _testCount       = 1;
    private int    _testDelayMs     = 100;

    // Stats
    private int _totalSent   = 0;
    private int _accepted     = 0;
    private int _denied       = 0;
    private int _noResponse   = 0;
    private int _kicked       = 0;

    // Flush timer
    private DateTime _lastFlush = DateTime.Now;

    public ResponseAnalyserTab(TestLog log, ResponseTracker tracker,
                                PacketCapture capture, UdpProxy udpProxy,
                                PacketStore store, ServerConfig config)
    {
        _log = log; _tracker = tracker; _capture = capture;
        _udpProxy = udpProxy; _store = store; _config = config;
    }

    public void Render()
    {
        // Flush pending responses every frame
        if ((DateTime.Now - _lastFlush).TotalMilliseconds > 100)
        {
            var flushed = _tracker.Flush();
            foreach (var r in flushed)
            {
                _totalSent++;
                switch (r.Outcome)
                {
                    case ResponseOutcome.Accepted:
                    case ResponseOutcome.AcceptedUnknown: _accepted++;    break;
                    case ResponseOutcome.Denied:           _denied++;      break;
                    case ResponseOutcome.NoResponse:       _noResponse++;  break;
                    case ResponseOutcome.Kicked:           _kicked++;      break;
                }
            }
            _lastFlush = DateTime.Now;
        }

        float w = ImGui.GetContentRegionAvail().X;

        RenderTopBar(w);
        ImGui.Spacing();
        RenderStatsRow(w);
        ImGui.Spacing();
        RenderManualFire(w);
        ImGui.Spacing();
        RenderResponseFeed(w);
    }

    // ── Top bar ───────────────────────────────────────────────────────────

    private void RenderTopBar(float w)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##rastop", new Vector2(w, 34), ImGuiChildFlags.Borders);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(12, 7));
        ImGui.PushStyleColor(ImGuiCol.Text, _tracking ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(_tracking ? "● Tracking active" : "● Tracking paused");
        ImGui.PopStyleColor();

        ImGui.SameLine(0, 16);
        if (ImGui.Checkbox("Auto-track##ratrk", ref _tracking)) { }

        ImGui.SameLine(0, 16);
        UiHelper.MutedLabel("Response window:");
        ImGui.SameLine(0, 6);
        ImGui.SetNextItemWidth(80);
        if (ImGui.InputInt("ms##rawnd", ref _windowMs))
        {
            _windowMs = Math.Clamp(_windowMs, 50, 5000);
            _tracker.ResponseWindowMs = _windowMs;
        }

        ImGui.SameLine(0, 24);
        UiHelper.SecondaryButton("Clear History##racl", 110, 22, () =>
        {
            _tracker.Clear();
            _totalSent = _accepted = _denied = _noResponse = _kicked = 0;
            _selectedIdx = -1;
            _log.Info("[ResponseAnalyser] History cleared.");
        });

        ImGui.EndChild();
    }

    // ── Stats row ─────────────────────────────────────────────────────────

    private void RenderStatsRow(float w)
    {
        float blockW = (w - 4 * 8f) / 5f;

        RenderStatBlock("SENT", _totalSent.ToString(),
            MenuRenderer.ColText, blockW);
        ImGui.SameLine(0, 8);
        RenderStatBlock("ACCEPTED", _accepted.ToString(),
            MenuRenderer.ColAccent, blockW);
        ImGui.SameLine(0, 8);
        RenderStatBlock("DENIED", _denied.ToString(),
            MenuRenderer.ColDanger, blockW);
        ImGui.SameLine(0, 8);
        RenderStatBlock("NO REPLY", _noResponse.ToString(),
            MenuRenderer.ColTextMuted, blockW);
        ImGui.SameLine(0, 8);
        RenderStatBlock("KICKED", _kicked.ToString(),
            MenuRenderer.ColWarn, blockW);
    }

    private void RenderStatBlock(string label, string value, Vector4 col, float w)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild($"##rasb_{label}", new Vector2(w, 60), ImGuiChildFlags.Borders);
        ImGui.PopStyleColor();

        var dl = ImGui.GetWindowDrawList();
        var p  = ImGui.GetWindowPos();
        dl.AddRectFilled(p, p + new Vector2(w, 3),
            ImGui.ColorConvertFloat4ToU32(col));

        ImGui.SetCursorPos(new Vector2(8, 10));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(label);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 30));
        ImGui.PushStyleColor(ImGuiCol.Text, col);
        ImGui.TextUnformatted(value);
        ImGui.PopStyleColor();

        // Percentage
        if (_totalSent > 0 && label != "SENT")
        {
            float pct = label switch
            {
                "ACCEPTED" => (float)_accepted   / _totalSent * 100,
                "DENIED"   => (float)_denied     / _totalSent * 100,
                "NO REPLY" => (float)_noResponse / _totalSent * 100,
                "KICKED"   => (float)_kicked     / _totalSent * 100,
                _          => 0
            };
            ImGui.SetCursorPos(new Vector2(8, 46));
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted($"{pct:F0}%");
            ImGui.PopStyleColor();
        }

        ImGui.EndChild();
    }

    // ── Manual fire panel ─────────────────────────────────────────────────

    private void RenderManualFire(float w)
    {
        UiHelper.SectionBox("MANUAL TEST FIRE", w, 100, () =>
        {
            UiHelper.MutedLabel("Send a packet and track what the server sends back.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(200);
            ImGui.InputText("Tag##ratag", ref _testTag, 64);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(80);
            ImGui.InputInt("Count##racnt", ref _testCount);
            _testCount = Math.Clamp(_testCount, 1, 1000);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(80);
            ImGui.InputInt("Delay ms##radly", ref _testDelayMs);
            _testDelayMs = Math.Clamp(_testDelayMs, 0, 5000);
            ImGui.SameLine(0, 16);
            UiHelper.WarnButton("Fire + Track##rafire", 120, 28, DoManualFire);

            ImGui.Spacing();
            ImGui.SetNextItemWidth(w - 200);
            ImGui.InputText("Hex##rahex", ref _testHex, 1024);
            ImGui.SameLine(0, 8);

            // Book picker
            var saved = _store.GetAll();
            if (saved.Count > 0 && ImGui.BeginCombo("From book##rabk", ""))
            {
                foreach (var s in saved)
                    if (ImGui.Selectable(s.Label)) { _testHex = s.HexString; _testTag = s.Label; }
                ImGui.EndCombo();
            }
        });
    }

    private void DoManualFire()
    {
        if (string.IsNullOrWhiteSpace(_testHex))
        { _log.Error("[RA] Paste a packet hex first."); return; }

        byte[] data;
        try
        {
            string clean = _testHex.Replace(" ", "");
            if (clean.Length % 2 != 0) clean += "0";
            data = Convert.FromHexString(clean);
        }
        catch { _log.Error("[RA] Invalid hex."); return; }

        int count = _testCount, delay = _testDelayMs;
        string tag = _testTag;

        _log.Info($"[RA] Firing '{tag}' ×{count} with response tracking...");

        Task.Run(async () =>
        {
            for (int i = 0; i < count; i++)
            {
                // Register the send BEFORE firing so we capture the response
                _tracker.RecordSend($"{tag} #{i+1}", data, "ManualFire");

                bool ok = false;
                if (_udpProxy.IsRunning) ok = _udpProxy.InjectToServer(data);
                if (!ok) ok = await _capture.InjectToServer(data);
                if (!ok)
                {
                    try
                    {
                        using var udp = new System.Net.Sockets.UdpClient();
                        udp.Connect(_config.ServerIp, _config.ServerPort);
                        udp.Send(data, data.Length);
                    }
                    catch (Exception ex) { _log.Error($"[RA] Send: {ex.Message}"); break; }
                }

                if (delay > 0) await Task.Delay(delay);
            }
        });
    }

    // ── Response feed ──────────────────────────────────────────────────────

    private void RenderResponseFeed(float w)
    {
        var history = GetFilteredHistory();

        float feedW = w * 0.45f;
        float detW  = w - feedW - 8;
        float h     = ImGui.GetContentRegionAvail().Y;

        // Filter bar
        RenderFilterBar();
        ImGui.Spacing();

        // Feed list
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##rafeed", new Vector2(feedW, h - 30), ImGuiChildFlags.Borders);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 6));
        UiHelper.MutedLabel("  Time        Tag                    Outcome");
        ImGui.Separator();

        var dl = ImGui.GetWindowDrawList();
        var lp = ImGui.GetWindowPos();

        for (int i = 0; i < history.Count; i++)
        {
            var r   = history[i];
            var col = OutcomeColor(r.Outcome);
            string outcomeStr = r.Outcome switch
            {
                ResponseOutcome.Accepted        => "✓ ACCEPTED",
                ResponseOutcome.AcceptedUnknown => "? ACCEPTED?",
                ResponseOutcome.Denied          => "✗ DENIED",
                ResponseOutcome.NoResponse      => "— NO REPLY",
                ResponseOutcome.Kicked          => "⚠ KICKED",
                _                               => "?"
            };

            bool sel = _selectedIdx == i;
            if (sel)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(feedW, 22),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }

            ImGui.PushStyleColor(ImGuiCol.Text, col);
            if (ImGui.Selectable(
                $"  {r.TimeLabel}  {Truncate(r.Tag, 22),-22}  {outcomeStr}##raf{i}",
                sel, ImGuiSelectableFlags.None, new Vector2(0, 22)))
                _selectedIdx = i;
            ImGui.PopStyleColor();
        }

        // Auto-scroll to bottom
        if (_autoScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 4)
            ImGui.SetScrollHereY(1.0f);

        ImGui.EndChild();
        ImGui.SameLine(0, 8);

        // Detail panel
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##radet", new Vector2(detW, h - 30), ImGuiChildFlags.Borders);
        ImGui.PopStyleColor();

        if (_selectedIdx >= 0 && _selectedIdx < history.Count)
            RenderResponseDetail(history[_selectedIdx], detW);
        else
        {
            ImGui.SetCursorPosY((h - 30) * 0.4f);
            float tw = ImGui.CalcTextSize("← select a response").X;
            ImGui.SetCursorPosX((detW - tw) * 0.5f);
            UiHelper.MutedLabel("← select a response");
        }

        ImGui.EndChild();
    }

    private void RenderFilterBar()
    {
        string[] labels = { "All", "Accepted", "Denied", "No Reply", "Kicked" };
        for (int i = 0; i < labels.Length; i++)
        {
            bool sel = _filterMode == i;
            ImGui.PushStyleColor(ImGuiCol.Button,
                sel ? new Vector4(0.18f, 0.95f, 0.45f, 0.22f) : MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text,
                sel ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
            if (ImGui.Button(labels[i] + $"##raf{i}", new Vector2(90, 24)))
                _filterMode = i;
            ImGui.PopStyleColor(2);
            if (i < labels.Length - 1) ImGui.SameLine(0, 4);
        }
        ImGui.SameLine(0, 20);
        ImGui.Checkbox("Auto-scroll##raas", ref _autoScroll);
    }

    private void RenderResponseDetail(ResponseRecord r, float w)
    {
        ImGui.SetCursorPos(new Vector2(12, 10));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("RESPONSE DETAIL");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        UiHelper.StatusRow("Tag",       r.Tag,       true, 80);
        UiHelper.StatusRow("Sent at",   r.TimeLabel, true, 80);
        UiHelper.StatusRow("Outcome",   r.Outcome.ToString(),
            r.Outcome is ResponseOutcome.Accepted or ResponseOutcome.AcceptedUnknown, 80);
        UiHelper.StatusRow("Responses", $"{r.ResponseCount} packet(s)", true, 80);

        ImGui.Spacing();

        // Outcome banner
        var (bannerCol, bannerBg, bannerText) = r.Outcome switch
        {
            ResponseOutcome.Accepted =>
                (MenuRenderer.ColAccent, MenuRenderer.ColAccentDim,
                 "✓  SERVER ACCEPTED THIS PACKET"),
            ResponseOutcome.AcceptedUnknown =>
                (MenuRenderer.ColWarn, MenuRenderer.ColWarnDim,
                 "?  SERVER RESPONDED — OUTCOME UNCLEAR"),
            ResponseOutcome.Denied =>
                (MenuRenderer.ColDanger, MenuRenderer.ColDangerDim,
                 "✗  SERVER DENIED / RETURNED ERROR"),
            ResponseOutcome.Kicked =>
                (MenuRenderer.ColWarn, MenuRenderer.ColWarnDim,
                 "⚠  SERVER SENT A KICK / DISCONNECT"),
            _ =>
                (MenuRenderer.ColTextMuted, MenuRenderer.ColBg2,
                 "—  NO RESPONSE FROM SERVER"),
        };

        ImGui.PushStyleColor(ImGuiCol.ChildBg, bannerBg);
        ImGui.BeginChild("##rabanner", new Vector2(-1, 36), ImGuiChildFlags.Borders);
        ImGui.PopStyleColor();
        var dl = ImGui.GetWindowDrawList();
        var bp = ImGui.GetWindowPos();
        dl.AddRectFilled(bp, bp + new Vector2(4, 36),
            ImGui.ColorConvertFloat4ToU32(bannerCol));
        ImGui.SetCursorPos(new Vector2(12, 10));
        ImGui.PushStyleColor(ImGuiCol.Text, bannerCol);
        ImGui.TextUnformatted(bannerText);
        ImGui.PopStyleColor();
        ImGui.EndChild();

        ImGui.Spacing();
        UiHelper.MutedLabel(r.Summary);
        ImGui.Spacing();

        var dl2 = ImGui.GetWindowDrawList();
        var wp  = ImGui.GetWindowPos();
        dl2.AddLine(new Vector2(wp.X + 12, ImGui.GetCursorScreenPos().Y),
                    new Vector2(wp.X + w  - 12, ImGui.GetCursorScreenPos().Y),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
        ImGui.Spacing();

        // Sent packet
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted($"SENT PACKET ({r.SentBytes.Length}b):");
        ImGui.PopStyleColor();
        ImGui.Spacing();
        RenderMiniHexDump(r.SentBytes, MenuRenderer.ColBlue);

        // Response packets
        if (r.Responses.Count > 0)
        {
            ImGui.Spacing();
            dl2.AddLine(new Vector2(wp.X + 12, ImGui.GetCursorScreenPos().Y),
                        new Vector2(wp.X + w  - 12, ImGui.GetCursorScreenPos().Y),
                        ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
            ImGui.Spacing();

            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
            ImGui.TextUnformatted($"SERVER RESPONSES ({r.Responses.Count}):");
            ImGui.PopStyleColor();
            ImGui.Spacing();

            foreach (var resp in r.Responses)
            {
                if (resp.RawBytes.Length == 0) continue;
                var analysis = PacketAnalyser.Analyse(resp);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted($"  0x{resp.RawBytes[0]:X2}  {analysis.IdGuess}  {resp.RawBytes.Length}b");
                ImGui.PopStyleColor();

                if (!string.IsNullOrEmpty(resp.AsciiPreview))
                {
                    ImGui.SameLine(0, 8);
                    UiHelper.MutedLabel($"\"{Truncate(resp.AsciiPreview, 30)}\"");
                }

                RenderMiniHexDump(resp.RawBytes, MenuRenderer.ColAccent);
                ImGui.Spacing();
            }
        }
        else
        {
            ImGui.Spacing();
            UiHelper.MutedLabel("No server packets received in the response window.");
            UiHelper.MutedLabel("Increase response window or check proxy is running.");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private List<ResponseRecord> GetFilteredHistory()
    {
        var all = _tracker.GetHistory();
        return _filterMode switch
        {
            1 => all.Where(r => r.Outcome is ResponseOutcome.Accepted
                                          or ResponseOutcome.AcceptedUnknown).ToList(),
            2 => all.Where(r => r.Outcome == ResponseOutcome.Denied).ToList(),
            3 => all.Where(r => r.Outcome == ResponseOutcome.NoResponse).ToList(),
            4 => all.Where(r => r.Outcome == ResponseOutcome.Kicked).ToList(),
            _ => all
        };
    }

    private static Vector4 OutcomeColor(ResponseOutcome o) => o switch
    {
        ResponseOutcome.Accepted        => MenuRenderer.ColAccent,
        ResponseOutcome.AcceptedUnknown => MenuRenderer.ColWarn,
        ResponseOutcome.Denied          => MenuRenderer.ColDanger,
        ResponseOutcome.Kicked          => MenuRenderer.ColWarn,
        _                               => MenuRenderer.ColTextMuted
    };

    private static void RenderMiniHexDump(byte[] data, Vector4 col)
    {
        int show = Math.Min(data.Length, 32);
        string hex = string.Join(" ", data.Take(show).Select(b => $"{b:X2}"));
        if (data.Length > show) hex += " ...";
        ImGui.PushStyleColor(ImGuiCol.Text, col);
        ImGui.TextUnformatted($"  {hex}");
        ImGui.PopStyleColor();
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
