using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Text.RegularExpressions;

namespace HytaleSecurityTester.Tabs;

public class LogTab : ITab
{
    public string Title => "  Log  ";

    private readonly TestLog _log;
    private readonly PacketLog _pktLog;

    private bool _autoScrollGeneral = true;
    private bool _autoScrollPackets = true;
    private bool _showCS = true;
    private bool _showSC = true;
    private bool _showInjected = true;

    // Regex / opcode filter
    private string _regexFilter = "";
    private bool _regexEnabled = false;
    private Regex? _compiledRegex;
    private string _regexError = "";

    // Spam suppression
    private int _spamThreshold = 5;
    private bool _spamSuppression = true;
    private readonly Dictionary<byte, int> _spamCounts = new();
    private readonly HashSet<byte> _hiddenOpcodes = new();
    private DateTime _spamResetTime = DateTime.Now;

    public LogTab(TestLog log, PacketLog pktLog)
    {
        _log = log;
        _pktLog = pktLog;
    }

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;
        float h = ImGui.GetContentRegionAvail().Y;

        float topH = h * 0.45f;
        float botH = h * 0.50f;

        RenderGeneralLog(w, topH);
        ImGui.Spacing();
        RenderPacketFeed(w, botH);
    }

    // ──────────────────────────────────────────────────────────────
    // GENERAL LOG
    // ──────────────────────────────────────────────────────────────

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
            _log.Clear();
            _log.Info("Log cleared.");
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

        foreach (var line in _log.GetText().Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;

            Vector4 col =
                line.Contains("[OK]") ? MenuRenderer.ColAccent :
                line.Contains("[WARN]") ? MenuRenderer.ColWarn :
                line.Contains("[ERROR]") ? MenuRenderer.ColDanger :
                                           MenuRenderer.ColTextMuted;

            ImGui.PushStyleColor(ImGuiCol.Text, col);
            ImGui.TextUnformatted(line);
            ImGui.PopStyleColor();
        }

        if (_autoScrollGeneral)
            ImGui.SetScrollHereY(1.0f);

        ImGui.EndChild();
    }

    // ──────────────────────────────────────────────────────────────
    // PACKET FEED
    // ──────────────────────────────────────────────────────────────

    private void RenderPacketFeed(float w, float h)
    {
        var entries = _pktLog.GetEntries();

        // ── Toolbar row 1
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##lptb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("PACKET TRAFFIC");
        ImGui.PopStyleColor();

        ImGui.SameLine(0, 20);
        UiHelper.DangerButton("Clear##lpc", 70, 22, () =>
        {
            _pktLog.Clear();
            _spamCounts.Clear();
            _hiddenOpcodes.Clear();
        });

        ImGui.SameLine(0, 10);
        ImGui.Checkbox("Auto-scroll##lpas", ref _autoScrollPackets);

        ImGui.SameLine(0, 10);
        ImGui.Checkbox("C→S##lpcs", ref _showCS);
        ImGui.SameLine(0, 6);
        ImGui.Checkbox("S→C##lpsc", ref _showSC);
        ImGui.SameLine(0, 6);
        ImGui.Checkbox("Injected##lpinj", ref _showInjected);

        ImGui.SameLine(0, 16);
        UiHelper.MutedLabel($"{entries.Count} packets");
        ImGui.EndChild();

        // ── Toolbar row 2 (FIXED THRESHOLD VISIBILITY)
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##lptb2", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 4));

        ImGui.Checkbox("Spam suppress##lpss", ref _spamSuppression);
        ImGui.SameLine(0, 10);

        UiHelper.MutedLabel("Threshold");
        ImGui.SameLine(0, 6);

        ImGui.SetNextItemWidth(60);
        if (ImGui.InputInt("##lpthr", ref _spamThreshold))
            _spamThreshold = Math.Clamp(_spamThreshold, 2, 9999);

        ImGui.SameLine(0, 6);
        UiHelper.MutedLabel($"= {_spamThreshold}");

        ImGui.SameLine(0, 30);

        ImGui.Checkbox("Regex##lpre", ref _regexEnabled);
        ImGui.SameLine(0, 6);

        ImGui.SetNextItemWidth(200);
        if (ImGui.InputText("##lpregex", ref _regexFilter, 128))
        {
            _regexError = "";
            _compiledRegex = null;

            if (_regexEnabled && !string.IsNullOrWhiteSpace(_regexFilter))
            {
                try
                {
                    _compiledRegex = new Regex(
                        _regexFilter, RegexOptions.IgnoreCase);
                }
                catch (Exception ex)
                {
                    _regexError = ex.Message;
                }
            }
        }

        if (!string.IsNullOrEmpty(_regexError))
        {
            ImGui.SameLine(0, 6);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
            ImGui.TextUnformatted("Invalid regex");
            ImGui.PopStyleColor();
        }

        ImGui.EndChild();

        // ── Build spam suppression cache
        if (_spamSuppression &&
            (DateTime.Now - _spamResetTime).TotalSeconds > 2)
        {
            _spamCounts.Clear();
            _hiddenOpcodes.Clear();

            foreach (var e in entries)
            {
                if (e.HexPreview.Length < 2) continue;

                if (byte.TryParse(e.HexPreview[..2],
                    System.Globalization.NumberStyles.HexNumber,
                    null, out byte op))
                {
                    _spamCounts[op] = _spamCounts.GetValueOrDefault(op) + 1;
                    if (_spamCounts[op] >= _spamThreshold)
                        _hiddenOpcodes.Add(op);
                }
            }

            _spamResetTime = DateTime.Now;
        }

        float feedTop = 64f;

        // ── Spam legend
        if (_spamSuppression && _hiddenOpcodes.Count > 0)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg,
                new Vector4(0.1f, 0.07f, 0.02f, 1f));
            ImGui.BeginChild("##lpspam", new Vector2(w, 26),
                ImGuiChildFlags.Border);
            ImGui.PopStyleColor();

            ImGui.SetCursorPos(new Vector2(8, 4));
            UiHelper.MutedLabel("Hidden spam opcodes:");

            foreach (byte op in _hiddenOpcodes.ToList())
            {
                ImGui.SameLine(0, 6);
                if (ImGui.Button(
                    $"0x{op:X2} ×{_spamCounts.GetValueOrDefault(op)} ✕##op{op}",
                    new Vector2(0, 18)))
                {
                    _hiddenOpcodes.Remove(op);
                }
            }

            ImGui.EndChild();
            feedTop += 30f;
        }

        // ── Packet list
        ImGui.PushStyleColor(ImGuiCol.ChildBg,
            new Vector4(0.06f, 0.08f, 0.07f, 1f));
        ImGui.BeginChild("##lpb",
            new Vector2(w, h - feedTop - 8),
            ImGuiChildFlags.Border,
            ImGuiWindowFlags.HorizontalScrollbar);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 4));
        UiHelper.MutedLabel("   Time            Dir    Bytes  INJ   Hex preview");

        foreach (var e in entries)
        {
            bool cs = e.Direction == PacketDirection.ClientToServer;
            if (!_showCS && cs) continue;
            if (!_showSC && !cs) continue;
            if (!_showInjected && e.Injected) continue;

            if (_spamSuppression &&
                e.HexPreview.Length >= 2 &&
                byte.TryParse(e.HexPreview[..2],
                    System.Globalization.NumberStyles.HexNumber,
                    null, out byte op) &&
                _hiddenOpcodes.Contains(op))
                continue;

            if (_regexEnabled && _compiledRegex != null)
            {
                string line =
                    $"{e.TimeLabel} {e.DirectionLabel} {e.ByteLength} {e.HexPreview}";
                if (!_compiledRegex.IsMatch(line))
                    continue;
            }

            Vector4 col =
                e.Injected ? MenuRenderer.ColWarn :
                cs ? MenuRenderer.ColBlue :
                             MenuRenderer.ColAccent;

            string inj = e.Injected ? "INJ" : "   ";

            ImGui.PushStyleColor(ImGuiCol.Text, col);
            ImGui.TextUnformatted(
                $"   {e.TimeLabel}  {e.DirectionLabel,-5}  {e.ByteLength,5}b  {inj}  {e.HexPreview}");
            ImGui.PopStyleColor();
        }

        if (_autoScrollPackets)
            ImGui.SetScrollHereY(1.0f);

        ImGui.EndChild();
    }
}