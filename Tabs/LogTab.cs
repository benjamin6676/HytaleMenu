using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

public class LogTab : ITab
{
    public string Title => "  Log  ";

    private readonly TestLog   _log;
    private readonly PacketLog _pktLog;

    private bool _autoScrollGeneral = true;
    private bool _autoScrollPackets = true;
    private bool _showCS            = true;
    private bool _showSC            = true;
    private bool _showInjected      = true;

    // Regex / opcode filter
    private string _regexFilter     = "";
    private bool   _regexEnabled    = false;
    private System.Text.RegularExpressions.Regex? _compiledRegex;
    private string _regexError      = "";

    // Spam suppression — packets with the same first byte seen N+ times
    private int  _spamThreshold     = 5;      // hide if seen >= this many times
    private bool _spamSuppression   = true;
    private readonly Dictionary<byte, int>  _spamCounts  = new();
    private readonly HashSet<byte>          _hiddenOpcodes = new();
    private DateTime                        _spamResetTime = DateTime.Now;

    public LogTab(TestLog log, PacketLog pktLog)
    {
        _log    = log;
        _pktLog = pktLog;
    }

    public void Render()
    {
        float w  = ImGui.GetContentRegionAvail().X;
        float h  = ImGui.GetContentRegionAvail().Y;
        float topH = h * 0.45f;
        float botH = h * 0.50f;

        RenderGeneralLog(w, topH);
        ImGui.Spacing();
        RenderPacketFeed(w, botH);
    }

    private void RenderGeneralLog(float w, float h)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##ltb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("GENERAL LOG");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 20);
        UiHelper.DangerButton("Clear##lgc", 70, 22, () =>
        {
            _log.Clear(); _log.Info("Log cleared.");
        });
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("Auto-scroll##lgas", ref _autoScrollGeneral);
        ImGui.SameLine(0, 16);
        UiHelper.MutedLabel("Test results, errors, dupe output — no packet spam.");
        ImGui.EndChild();

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##lgb", new Vector2(w, h - 34),
            ImGuiChildFlags.Border, ImGuiWindowFlags.HorizontalScrollbar);
        ImGui.PopStyleColor();

        string text = _log.GetText();
        foreach (var line in text.Split('\n'))
        {
            if (string.IsNullOrEmpty(line)) continue;
            Vector4 col;
            if      (line.Contains("[OK]"))    col = MenuRenderer.ColAccent;
            else if (line.Contains("[WARN]"))  col = MenuRenderer.ColWarn;
            else if (line.Contains("[ERROR]")) col = MenuRenderer.ColDanger;
            else                               col = MenuRenderer.ColTextMuted;
            ImGui.PushStyleColor(ImGuiCol.Text, col);
            ImGui.TextUnformatted(line);
            ImGui.PopStyleColor();
        }
        if (_autoScrollGeneral) ImGui.SetScrollHereY(1.0f);
        ImGui.EndChild();
    }

    private void RenderPacketFeed(float w, float h)
    {
        // ── Toolbar row 1 ──────────────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##lptb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("PACKET TRAFFIC");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 20);
        UiHelper.DangerButton("Clear##lpc", 70, 22, () => { _pktLog.Clear(); _spamCounts.Clear(); });
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("Auto-scroll##lpas", ref _autoScrollPackets);
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("C\u2192S##lpcs", ref _showCS);
        ImGui.SameLine(0, 6);
        ImGui.Checkbox("S\u2192C##lpsc", ref _showSC);
        ImGui.SameLine(0, 6);
        ImGui.Checkbox("Injected##lpinj", ref _showInjected);
        var entries = _pktLog.GetEntries();
        ImGui.SameLine(0, 16);
        UiHelper.MutedLabel($"{entries.Count} packets");
        ImGui.EndChild();

        // ── Toolbar row 2 — filter + spam suppression ─────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##lptb2", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));

        ImGui.Checkbox("Spam suppress##lpss", ref _spamSuppression);
        ImGui.SameLine(0, 6);
        ImGui.SetNextItemWidth(60);
        if (ImGui.InputInt("threshold##lpthr", ref _spamThreshold))
            _spamThreshold = Math.Clamp(_spamThreshold, 2, 9999);
        ImGui.SameLine(0, 10);

        ImGui.Checkbox("Regex##lpre", ref _regexEnabled);
        ImGui.SameLine(0, 6);
        ImGui.SetNextItemWidth(200);
        if (ImGui.InputText("##lpregex", ref _regexFilter, 128))
        {
            _regexError = "";
            _compiledRegex = null;
            if (!string.IsNullOrWhiteSpace(_regexFilter) && _regexEnabled)
            {
                try { _compiledRegex = new System.Text.RegularExpressions.Regex(
                    _regexFilter, System.Text.RegularExpressions.RegexOptions.IgnoreCase); }
                catch (Exception ex) { _regexError = ex.Message; }
            }
        }
        if (!string.IsNullOrEmpty(_regexError))
        {
            ImGui.SameLine(0, 6);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
            ImGui.TextUnformatted("Invalid regex");
            ImGui.PopStyleColor();
        }
        if (_hiddenOpcodes.Count > 0)
        {
            ImGui.SameLine(0, 14);
            UiHelper.MutedLabel($"{_hiddenOpcodes.Count} opcode(s) hidden");
            ImGui.SameLine(0, 6);
            UiHelper.SecondaryButton("Show all##lpshow", 74, 22, () => _hiddenOpcodes.Clear());
        }
        ImGui.EndChild();

        // ── Build spam counts and hidden set ──────────────────────────────
        if (_spamSuppression && (DateTime.Now - _spamResetTime).TotalSeconds > 2)
        {
            _spamCounts.Clear();
            foreach (var e in entries)
            {
                if (e.HexPreview.Length >= 2 && byte.TryParse(
                    e.HexPreview[..2], System.Globalization.NumberStyles.HexNumber, null, out byte op))
                {
                    _spamCounts[op] = _spamCounts.GetValueOrDefault(op) + 1;
                    if (_spamCounts[op] >= _spamThreshold)
                        _hiddenOpcodes.Add(op);
                }
            }
            _spamResetTime = DateTime.Now;
        }

        // ── Spam legend ───────────────────────────────────────────────────
        float feedTop = 64f; // two toolbars
        if (_hiddenOpcodes.Count > 0 && _spamSuppression)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.1f, 0.07f, 0.02f, 1f));
            ImGui.BeginChild("##lpspam", new Vector2(w, 26), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();
            ImGui.SetCursorPos(new Vector2(8, 4));
            UiHelper.MutedLabel("Hidden spam opcodes:");
            foreach (byte op in _hiddenOpcodes.ToList())
            {
                ImGui.SameLine(0, 6);
                ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColWarnDim);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                if (ImGui.Button($"0x{op:X2} ×{_spamCounts.GetValueOrDefault(op)} ✕##lpop{op}",
                    new Vector2(0, 18)))
                    _hiddenOpcodes.Remove(op);
                ImGui.PopStyleColor(2);
            }
            ImGui.EndChild();
            feedTop += 30f;
        }

        // ── Content ───────────────────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.06f, 0.08f, 0.07f, 1f));
        ImGui.BeginChild("##lpb", new Vector2(w, h - feedTop - 8),
            ImGuiChildFlags.Border, ImGuiWindowFlags.HorizontalScrollbar);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 4));
        UiHelper.MutedLabel("   Time            Dir    Bytes  INJ   Hex preview");

        foreach (var e in entries)
        {
            bool cs = e.Direction == PacketDirection.ClientToServer;
            if (!_showCS && cs)  continue;
            if (!_showSC && !cs) continue;
            if (!_showInjected && e.Injected) continue;

            // Spam suppression
            if (_spamSuppression && e.HexPreview.Length >= 2 &&
                byte.TryParse(e.HexPreview[..2],
                    System.Globalization.NumberStyles.HexNumber, null, out byte eOp) &&
                _hiddenOpcodes.Contains(eOp))
                continue;

            // Regex filter
            if (_regexEnabled && _compiledRegex != null)
            {
                string line = $"{e.TimeLabel} {e.DirectionLabel} {e.ByteLength} {e.HexPreview}";
                if (!_compiledRegex.IsMatch(line)) continue;
            }

            var col = e.Injected ? MenuRenderer.ColWarn
                    : cs         ? MenuRenderer.ColBlue
                    :              MenuRenderer.ColAccent;

            string injTag = e.Injected ? "INJ" : "   ";
            ImGui.PushStyleColor(ImGuiCol.Text, col);
            ImGui.TextUnformatted(
                $"   {e.TimeLabel}  {e.DirectionLabel,-5}  {e.ByteLength,5}b  {injTag}  {e.HexPreview}");
            ImGui.PopStyleColor();
        }

        if (_autoScrollPackets) ImGui.SetScrollHereY(1.0f);
        ImGui.EndChild();
    }
}
