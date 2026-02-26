using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Dashboard Log tab  — three sub-tabs:
///   1. GENERAL LOG   — important events: test results, errors, dupe output
///   2. SD LOG        — SmartDetect noise (auto-naming, scoring) kept separate
///   3. PACKET FEED   — raw packet traffic with spam suppression + regex
///
/// Performance fixes vs v15:
///   - ImGuiListClipper for both lists (O(visible) not O(total))
///   - Line-cache array only rebuilt on version change (no split every frame)
///   - Pre-filtered packet list rebuilt only when entries count changes
/// </summary>
public class LogTab : ITab
{
    public string Title => "  Log  ";

    private readonly TestLog   _log;
    private readonly TestLog   _sdLog;
    private readonly PacketLog _pktLog;

    // ── General log cache ─────────────────────────────────────────────────
    private bool         _autoScrollGeneral = true;
    private int          _cachedLogVersion  = -1;
    private string[]     _cachedLogLines    = Array.Empty<string>();

    // ── SD log cache ──────────────────────────────────────────────────────
    private bool         _autoScrollSd  = true;
    private int          _cachedSdVersion = -1;
    private string[]     _cachedSdLines   = Array.Empty<string>();

    // ── Packet feed ───────────────────────────────────────────────────────
    private bool   _autoScrollPackets = true;
    private bool   _showCS            = true;
    private bool   _showSC            = true;
    private bool   _showInjected      = true;

    private string _regexFilter        = "";
    private bool   _regexEnabled       = false;
    private System.Text.RegularExpressions.Regex? _compiledRegex;
    private string _regexError         = "";

    // Spam suppression
    private int      _spamThreshold   = 5;
    private bool     _spamSuppression = true;
    private readonly Dictionary<ushort, int>  _spamCounts    = new();
    private readonly HashSet<ushort>          _hiddenIds     = new();
    private DateTime                          _spamResetTime = DateTime.Now;

    // Filtered + pre-resolved list (only rebuilt when entries change)
    private int                       _cachedEntryCount  = -1;
    private List<(PacketLogEntry e, ushort id, OpcodeInfo info)> _filteredEntries = new();

    // Learn-opcode modal
    private bool   _learnOpen   = false;
    private ushort _learnId     = 0;
    private int    _learnDir    = 0;
    private string _learnName   = "";

    public LogTab(TestLog log, PacketLog pktLog, TestLog sdLog)
    {
        _log    = log;
        _pktLog = pktLog;
        _sdLog  = sdLog;
    }

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;
        float h = ImGui.GetContentRegionAvail().Y;

        if (!ImGui.BeginTabBar("##logsubs", ImGuiTabBarFlags.None)) return;

        if (ImGui.BeginTabItem("General Log##ltg"))
        {
            RenderGeneralLog(w, h - 28);
            ImGui.EndTabItem();
        }
        if (ImGui.BeginTabItem("SD Log##ltsd"))
        {
            RenderSdLog(w, h - 28);
            ImGui.EndTabItem();
        }
        if (ImGui.BeginTabItem("Packet Feed##ltpf"))
        {
            RenderPacketFeed(w, h - 28);
            ImGui.EndTabItem();
        }

        ImGui.EndTabBar();
    }

    // ── General log ───────────────────────────────────────────────────────

    private void RenderGeneralLog(float w, float h)
    {
        // Toolbar
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##ltb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("GENERAL LOG");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 20);
        UiHelper.DangerButton("Clear##lgc", 70, 22, () => { _log.Clear(); _log.Info("Log cleared."); });
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("Auto-scroll##lgas", ref _autoScrollGeneral);
        ImGui.SameLine(0, 16);
        UiHelper.MutedLabel("Test results, errors, dupe output - no packet spam.");
        ImGui.EndChild();

        // Refresh cache when log version changes
        int ver = _log.Version;
        if (ver != _cachedLogVersion)
        {
            _cachedLogLines  = _log.GetLines().ToArray();
            _cachedLogVersion = ver;
        }

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##lgb", new Vector2(w, h - 34),
            ImGuiChildFlags.Border, ImGuiWindowFlags.HorizontalScrollbar);
        ImGui.PopStyleColor();

        float lineH = ImGui.GetTextLineHeightWithSpacing();
        var clipper = new ImGuiListClipper();
        clipper.Begin(_cachedLogLines.Length, lineH);
        while (clipper.Step())
        {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
            {
                var line = _cachedLogLines[i];
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
        }
        if (_autoScrollGeneral) ImGui.SetScrollHereY(1.0f);
        ImGui.EndChild();
    }

    // ── SmartDetect noise log ─────────────────────────────────────────────

    private void RenderSdLog(float w, float h)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##sdtb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("SMARTDETECT LOG");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 20);
        UiHelper.DangerButton("Clear##sdc", 70, 22, () => _sdLog.Clear());
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("Auto-scroll##sdas", ref _autoScrollSd);
        ImGui.SameLine(0, 16);
        UiHelper.MutedLabel("Auto-naming, scoring noise - kept separate from main log.");
        ImGui.EndChild();

        int ver = _sdLog.Version;
        if (ver != _cachedSdVersion)
        {
            _cachedSdLines   = _sdLog.GetLines().ToArray();
            _cachedSdVersion = ver;
        }

        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.05f, 0.07f, 0.06f, 1f));
        ImGui.BeginChild("##sdb", new Vector2(w, h - 34),
            ImGuiChildFlags.Border, ImGuiWindowFlags.HorizontalScrollbar);
        ImGui.PopStyleColor();

        float lineH = ImGui.GetTextLineHeightWithSpacing();
        var clipper = new ImGuiListClipper();
        clipper.Begin(_cachedSdLines.Length, lineH);
        while (clipper.Step())
        {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
            {
                var line = _cachedSdLines[i];
                if (string.IsNullOrEmpty(line)) continue;
                Vector4 col;
                if      (line.Contains("[OK]"))    col = MenuRenderer.ColAccentMid;
                else if (line.Contains("[WARN]"))  col = MenuRenderer.ColWarn;
                else if (line.Contains("[ERROR]")) col = MenuRenderer.ColDanger;
                else                               col = MenuRenderer.ColTextMuted;
                ImGui.PushStyleColor(ImGuiCol.Text, col);
                ImGui.TextUnformatted(line);
                ImGui.PopStyleColor();
            }
        }
        if (_autoScrollSd) ImGui.SetScrollHereY(1.0f);
        ImGui.EndChild();
    }

    // ── Packet feed ───────────────────────────────────────────────────────

    private void RenderPacketFeed(float w, float h)
    {
        // Toolbar row 1
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
            _pktLog.Clear(); _spamCounts.Clear();
            _cachedEntryCount = -1;
        });
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("Auto-scroll##lpas", ref _autoScrollPackets);
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("C\u2192S##lpcs", ref _showCS);
        ImGui.SameLine(0, 6);
        ImGui.Checkbox("S\u2192C##lpsc", ref _showSC);
        ImGui.SameLine(0, 6);
        ImGui.Checkbox("Injected##lpinj", ref _showInjected);
        ImGui.SameLine(0, 16);
        UiHelper.MutedLabel($"{_pktLog.Count} packets");
        ImGui.EndChild();

        // Toolbar row 2 - filter + spam suppression
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
        if (_hiddenIds.Count > 0)
        {
            ImGui.SameLine(0, 14);
            UiHelper.MutedLabel($"{_hiddenIds.Count} ID(s) hidden");
            ImGui.SameLine(0, 6);
            UiHelper.SecondaryButton("Show all##lpshow", 74, 22, () => _hiddenIds.Clear());
        }
        ImGui.EndChild();

        // Rebuild filtered list + spam map when entry count changes
        RebuildFilteredEntries();

        float feedTop = 64f;

        // Spam legend
        if (_hiddenIds.Count > 0 && _spamSuppression)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.1f, 0.07f, 0.02f, 1f));
            ImGui.BeginChild("##lpspam", new Vector2(w, 26), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();
            ImGui.SetCursorPos(new Vector2(8, 4));
            UiHelper.MutedLabel("Hidden spam IDs:");
            foreach (ushort id in _hiddenIds.ToList())
            {
                ImGui.SameLine(0, 6);
                var info = OpcodeRegistry.Lookup(id, PacketDirection.ClientToServer)
                         ?? OpcodeRegistry.Lookup(id, PacketDirection.ServerToClient);
                string tag = (info != null && info.Name != "UNKNOWN") ? info.Name : $"ID {id}";
                ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColWarnDim);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                if (ImGui.Button($"{tag} x{_spamCounts.GetValueOrDefault(id)} [x]##lpop{id}",
                    new Vector2(0, 18)))
                    _hiddenIds.Remove(id);
                ImGui.PopStyleColor(2);
            }
            ImGui.EndChild();
            feedTop += 30f;
        }

        // Packet list with ImGuiListClipper
        const float RowH = 18f;
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.06f, 0.08f, 0.07f, 1f));
        ImGui.BeginChild("##lpb", new Vector2(w, h - feedTop - 8),
            ImGuiChildFlags.Border, ImGuiWindowFlags.HorizontalScrollbar);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 4));
        UiHelper.MutedLabel("   Time            Dir    Bytes  INJ   ID / Name / Hex");

        var clipper = new ImGuiListClipper();
        clipper.Begin(_filteredEntries.Count, RowH);
        while (clipper.Step())
        {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
            {
                var (e, id, info) = _filteredEntries[i];
                bool cs  = e.Direction == PacketDirection.ClientToServer;
                var  col = e.Injected ? MenuRenderer.ColWarn
                         : cs         ? MenuRenderer.ColBlue
                         :              MenuRenderer.ColAccent;

                string injTag  = e.Injected ? "INJ" : "   ";
                bool   isKnown  = info != null && info.Name != "UNKNOWN";
                string namePart = isKnown
                    ? $"[{info!.Name,-22}]"
                    : $"[ID {id,-20}]";

                ImGui.PushStyleColor(ImGuiCol.Text, col);
                bool clicked = ImGui.Selectable(
                    $"   {e.TimeLabel}  {e.DirectionLabel,-5}  {e.ByteLength,5}b  {injTag}  {namePart} {e.HexPreview}##lr{i}",
                    false, ImGuiSelectableFlags.None, new Vector2(0, RowH));
                ImGui.PopStyleColor();

                // Right-click: Learn Opcode
                if (ImGui.IsItemHovered() && ImGui.IsMouseClicked(ImGuiMouseButton.Right))
                {
                    _learnId   = id;
                    _learnDir  = cs ? 0 : 1;
                    _learnName = info?.Name ?? "";
                    _learnOpen = true;
                }
            }
        }

        // Learn modal
        if (_learnOpen) { ImGui.OpenPopup("##learn_modal"); _learnOpen = false; }
        bool modalOpen = true;
        if (ImGui.BeginPopupModal("##learn_modal", ref modalOpen,
            ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoTitleBar))
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
            ImGui.TextUnformatted($"Label packet ID {_learnId}  ({(_learnDir == 0 ? "C->S" : "S->C")})");
            ImGui.PopStyleColor();
            ImGui.Spacing();
            ImGui.SetNextItemWidth(260);
            ImGui.InputText("Name##lnm", ref _learnName, 48);
            ImGui.Spacing();
            if (ImGui.Button("Save & Learn##lnsave", new Vector2(120, 26)))
            {
                var dir = _learnDir == 0
                    ? PacketDirection.ClientToServer
                    : PacketDirection.ServerToClient;
                OpcodeRegistry.Learn(_learnId, dir, _learnName, "User-defined");
                _cachedEntryCount = -1; // force rebuild so new name shows immediately
                ImGui.CloseCurrentPopup();
            }
            ImGui.SameLine(0, 8);
            if (ImGui.Button("Cancel##lncancel", new Vector2(80, 26)))
                ImGui.CloseCurrentPopup();
            ImGui.EndPopup();
        }

        if (_autoScrollPackets) ImGui.SetScrollHereY(1.0f);
        ImGui.EndChild();
    }

    private void RebuildFilteredEntries()
    {
        var raw = _pktLog.GetEntries();

        // Rebuild spam counts every 2 s
        if (_spamSuppression && (DateTime.Now - _spamResetTime).TotalSeconds > 2)
        {
            _spamCounts.Clear();
            foreach (var e in raw)
            {
                ushort id = OpcodeRegistry.DecodePacketIdFromHex(e.HexPreview);
                _spamCounts[id] = _spamCounts.GetValueOrDefault(id) + 1;
                if (_spamCounts[id] >= _spamThreshold)
                    _hiddenIds.Add(id);
            }
            _spamResetTime = DateTime.Now;
        }

        // Only rebuild filtered list when entry count changes (or flags changed)
        // A simple version check keeps this O(1) on most frames
        if (raw.Count == _cachedEntryCount && _compiledRegex == null) return;

        _cachedEntryCount = raw.Count;
        _filteredEntries.Clear();

        foreach (var e in raw)
        {
            bool cs = e.Direction == PacketDirection.ClientToServer;
            if (!_showCS && cs)  continue;
            if (!_showSC && !cs) continue;
            if (!_showInjected && e.Injected) continue;

            ushort id = OpcodeRegistry.DecodePacketIdFromHex(e.HexPreview);

            if (_spamSuppression && _hiddenIds.Contains(id)) continue;

            if (_regexEnabled && _compiledRegex != null)
            {
                string line = $"{e.TimeLabel} {e.DirectionLabel} {e.ByteLength} {e.HexPreview}";
                if (!_compiledRegex.IsMatch(line)) continue;
            }

            var info = OpcodeRegistry.Lookup(id, e.Direction);
            _filteredEntries.Add((e, id, info));
        }
    }
}
