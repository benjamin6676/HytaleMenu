using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Linq;

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

    // ── Deep Log ─────────────────────────────────────────────────────────
    private bool   _autoScrollDeep = true;
    private string _deepFilter     = "";
    private List<PacketLogEntry> _deepSnapshot = new();
    private bool   _deepLive       = true;    // live vs snapshot mode
    private bool   _showOnlyAnalyzed = true;  // only show entries with analysis
    private bool   _showCompressedOnly = false;
    private int    _deepShowLast    = 50;
    private readonly SmartDetectionEngine _smart;
    private readonly ServerConfig         _deepCfg;

    public LogTab(TestLog log, PacketLog pktLog, TestLog sdLog,
                  SmartDetectionEngine smart, ServerConfig config)
    {
        _log    = log;
        _pktLog = pktLog;
        _sdLog  = sdLog;
        _smart  = smart;
        _deepCfg = config;
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
        if (ImGui.BeginTabItem("Deep Log##ltdl"))
        {
            RenderDeepLog(w, h - 28);
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
        ImGui.SameLine(0, 10);
        // Dump diagnostics button - also accessible from Inspector sidebar
        ImGui.PushStyleColor(ImGuiCol.Button,  new Vector4(0.15f, 0.4f, 0.8f, 0.7f));
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.2f, 0.5f, 1f, 0.85f));
        ImGui.PushStyleColor(ImGuiCol.Text,    new Vector4(0.7f, 0.9f, 1f, 1f));
        if (ImGui.Button("Dump Diagnostics##lgdump", new Vector2(140, 22)))
            DumpQuickDiagToLog();
        ImGui.PopStyleColor(3);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Writes a full analysis snapshot:\n" +
                "LocalPlayer, registry, items, entities, AOB addresses.\n" +
                "Screenshot this log window and share for debugging.");
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

    // ── DEEP LOG ──────────────────────────────────────────────────────────
    // Shows per-packet analysis: compression, decompression, encryption,
    // packet ID, packet name, and last 5 packets of each type.
    // Best used for screenshotting and sharing for debugging.

    private void RenderDeepLog(float w, float h)
    {
        // ── Toolbar ──────────────────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##dltb", new Vector2(w, 54), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("DEEP PACKET LOG  —  Compression · Encryption · ID · Name · Last-5 per type");
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 24));

        // Toggle: Live vs Snapshot
        ImGui.PushStyleColor(ImGuiCol.Button,
            _deepLive ? new Vector4(0.15f, 0.5f, 0.2f, 0.75f) : MenuRenderer.ColBg3);
        if (ImGui.Button(_deepLive ? "LIVE##dlive" : "SNAPSHOT##dlive", new Vector2(82, 22)))
            _deepLive = !_deepLive;
        ImGui.PopStyleColor();
        if (ImGui.IsItemHovered()) ImGui.SetTooltip("Toggle Live (auto-update) or Snapshot mode.");

        ImGui.SameLine(0, 6);
        // Snapshot button
        ImGui.BeginDisabled(_deepLive);
        if (ImGui.Button("Snapshot Now##dlsnap", new Vector2(110, 22)))
            _deepSnapshot = GetDeepEntries();
        ImGui.EndDisabled();
        if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
            ImGui.SetTooltip("Freeze current state for screenshot / analysis.Disable LIVE mode first.");

        ImGui.SameLine(0, 12);
        ImGui.Checkbox("Analyzed only##dlao", ref _showOnlyAnalyzed);
        if (ImGui.IsItemHovered()) ImGui.SetTooltip("Only show packets that went through full analysis (have compression/name data).");

        ImGui.SameLine(0, 8);
        ImGui.Checkbox("Compressed only##dlco", ref _showCompressedOnly);

        ImGui.SameLine(0, 12);
        ImGui.SetNextItemWidth(55);
        ImGui.InputInt("Last##dlast", ref _deepShowLast);
        _deepShowLast = Math.Clamp(_deepShowLast, 5, 500);

        ImGui.SameLine(0, 12);
        ImGui.SetNextItemWidth(160);
        ImGui.InputText("Filter##dlf", ref _deepFilter, 64);

        ImGui.SameLine(0, 8);
        UiHelper.DangerButton("Clear##dlc", 56, 22, () => { _pktLog.Clear(); _deepSnapshot.Clear(); });

        ImGui.EndChild();

        // ── Status summary pills ──────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.05f, 0.07f, 0.06f, 1f));
        ImGui.BeginChild("##dlsum", new Vector2(w, 42), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));

        // LocalPlayer status
        bool hasLP = _deepCfg.HasLocalPlayer;
        ImGui.PushStyleColor(ImGuiCol.Text, hasLP
            ? new Vector4(0.3f, 1f, 0.5f, 1f)
            : new Vector4(1f, 0.4f, 0.3f, 1f));
        ImGui.TextUnformatted(hasLP
            ? $"✓ LocalPlayer  ID={_deepCfg.LocalPlayerEntityId}  Name={_deepCfg.LocalPlayerName}"
            : "✗ LocalPlayer NOT found  →  AOB scan needed (Memory tab → LocalPlayer)");
        ImGui.PopStyleColor();

        ImGui.SameLine(0, 20);
        // Registry status
        int regCount = RegistrySyncParser.NumericIdToName.Count;
        int litCount = RegistrySyncParser.LiteralNames.Count;
        bool regOk   = regCount > 0 || litCount > 0;
        ImGui.PushStyleColor(ImGuiCol.Text, regOk
            ? new Vector4(0.3f, 1f, 0.5f, 1f)
            : new Vector4(1f, 0.7f, 0.2f, 1f));
        ImGui.TextUnformatted(regOk
            ? $"✓ Registry  {regCount} IDs  {litCount} strings"
            : $"⚠ Registry empty  ({RegistrySyncParser.SeenRegistryOpcodes.Count} reg pkts seen)");
        ImGui.PopStyleColor();

        ImGui.SameLine(0, 20);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted($"Total: {_pktLog.Count} pkts  {_pktLog.OpcodeTypeCount} opcode types");
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 23));
        // IdNameMap
        int idMapCount = _smart.IdNameMap.Count;
        ImGui.PushStyleColor(ImGuiCol.Text, idMapCount > 0
            ? new Vector4(0.3f, 1f, 0.5f, 1f) : new Vector4(1f, 0.7f, 0.2f, 1f));
        ImGui.TextUnformatted($"IdNameMap: {idMapCount}  Confirmed items: {_smart.ConfirmedItems.Count}  Entities: {_smart.ActiveEntities.Count}");
        ImGui.PopStyleColor();

        ImGui.SameLine(0, 20);
        var aoh = AutoUpdateHandler.Instance;
        bool aobOk = aoh.LocalPlayerAddr != 0 || aoh.HoverIdAddr != 0;
        ImGui.PushStyleColor(ImGuiCol.Text, aobOk
            ? new Vector4(0.3f, 1f, 0.5f, 1f) : new Vector4(1f, 0.4f, 0.3f, 1f));
        ImGui.TextUnformatted(aobOk
            ? $"AOB: LocalPlayer=0x{aoh.LocalPlayerAddr:X}  HoverID=0x{aoh.HoverIdAddr:X}"
            : "AOB: No symbols found yet (run scan in Memory tab)");
        ImGui.PopStyleColor();

        ImGui.EndChild();

        // ── One-per-opcode type table ─────────────────────────────────────
        float onePerH = Math.Min(h * 0.35f, 180f);
        ImGui.Spacing();
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.04f, 0.06f, 0.08f, 1f));
        ImGui.BeginChild("##dlopt", new Vector2(w, onePerH), ImGuiChildFlags.Border,
            ImGuiWindowFlags.HorizontalScrollbar);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("ONE PER OPCODE  (newest sample of each unique packet type seen)");
        ImGui.PopStyleColor();
        ImGui.Separator();

        UiHelper.MutedLabel($"  {"Dir",-5} {"ID",6} {"Name",-22} {"Compr",-20} {"CSize",6} {"DSize",6} {"Enc",-24} Hex");
        ImGui.Separator();

        var onePer = _pktLog.GetOnePerOpcode();
        if (!string.IsNullOrEmpty(_deepFilter))
            onePer = onePer.Where(e =>
                e.PacketName.Contains(_deepFilter, StringComparison.OrdinalIgnoreCase) ||
                e.HexPreview.Contains(_deepFilter, StringComparison.OrdinalIgnoreCase) ||
                e.PacketId.ToString().Contains(_deepFilter)).ToList();

        const float RowH = 18f;
        var clipper1 = new ImGuiListClipper();
        clipper1.Begin(onePer.Count, RowH);
        while (clipper1.Step())
        {
            for (int i = clipper1.DisplayStart; i < clipper1.DisplayEnd; i++)
            {
                var e = onePer[i];
                bool cs = e.Direction == PacketDirection.ClientToServer;
                var col = cs ? MenuRenderer.ColBlue : MenuRenderer.ColAccent;
                if (e.IsCompressed) col = new Vector4(0.9f, 0.8f, 0.2f, 1f); // yellow = compressed
                bool hasEnc = e.EncryptionType != "none" && !string.IsNullOrEmpty(e.EncryptionType);

                ImGui.PushStyleColor(ImGuiCol.Text, col);
                ImGui.TextUnformatted(
                    $"  {e.DirectionLabel,-5} {e.PacketId,6}  {(e.PacketName.Length > 20 ? e.PacketName[..20] : e.PacketName),-22}" +
                    $"  {e.CompressionMethod,-20} {e.CompressedSize,6} {e.DecompressedSize,6}" +
                    $"  {(hasEnc ? e.EncryptionType : "-"),-24}" +
                    $"  {e.HexPreview[..Math.Min(32, e.HexPreview.Length)]}");
                ImGui.PopStyleColor();

                // Right-click for last 5
                if (ImGui.IsItemHovered() && ImGui.IsMouseClicked(ImGuiMouseButton.Right))
                    ImGui.OpenPopup($"##dlast5_{e.PacketId}");

                if (ImGui.BeginPopup($"##dlast5_{e.PacketId}"))
                {
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
                    ImGui.TextUnformatted($"Last 5 packets of opcode 0x{e.PacketId:X2} ({e.PacketName}):");
                    ImGui.PopStyleColor();
                    ImGui.Separator();
                    var last5 = _pktLog.GetByOpcode(e.PacketId);
                    foreach (var p5 in last5)
                    {
                        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                        ImGui.TextUnformatted($"  {p5.TimeLabel}  {p5.CompressionSummary}");
                        ImGui.TextUnformatted($"    RAW: {p5.HexPreview[..Math.Min(48, p5.HexPreview.Length)]}");
                        if (p5.IsCompressed && p5.DecompressedHexPreview.Length > 0)
                            ImGui.TextUnformatted($"    DEC: {p5.DecompressedHexPreview[..Math.Min(48, p5.DecompressedHexPreview.Length)]}");
                        ImGui.PopStyleColor();
                        ImGui.Separator();
                    }
                    ImGui.EndPopup();
                }
            }
        }
        ImGui.EndChild();

        // ── Main packet list with full analysis ───────────────────────────
        float listH = h - onePerH - 100f;
        ImGui.Spacing();
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.04f, 0.06f, 0.05f, 1f));
        ImGui.BeginChild("##dlmain", new Vector2(w, listH), ImGuiChildFlags.Border,
            ImGuiWindowFlags.HorizontalScrollbar);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted($"LAST {_deepShowLast} PACKETS  (right-click one-per-opcode table for last-5 of a specific type)");
        ImGui.PopStyleColor();
        ImGui.Separator();
        UiHelper.MutedLabel($"  {"Time",-15} {"Dir",-5} {"ID",6} {"Name",-22} {"Compression",-28} {"Enc",-24} Bytes  Hex");
        ImGui.Separator();

        var entries = _deepLive ? GetDeepEntries() : _deepSnapshot;
        if (!string.IsNullOrEmpty(_deepFilter))
            entries = entries.Where(e =>
                e.PacketName.Contains(_deepFilter, StringComparison.OrdinalIgnoreCase) ||
                e.HexPreview.Contains(_deepFilter, StringComparison.OrdinalIgnoreCase) ||
                e.PacketId.ToString().Contains(_deepFilter)).ToList();

        var clipper2 = new ImGuiListClipper();
        clipper2.Begin(entries.Count, RowH);
        while (clipper2.Step())
        {
            for (int i = clipper2.DisplayStart; i < clipper2.DisplayEnd; i++)
            {
                var e = entries[i];
                bool cs = e.Direction == PacketDirection.ClientToServer;
                var col = cs ? MenuRenderer.ColBlue : MenuRenderer.ColAccent;
                if (e.IsCompressed) col = new Vector4(0.9f, 0.8f, 0.2f, 1f);
                bool hasEnc = e.EncryptionType != "none" && !string.IsNullOrEmpty(e.EncryptionType);

                ImGui.PushStyleColor(ImGuiCol.Text, col);
                ImGui.TextUnformatted(
                    $"  {e.TimeLabel,-15} {e.DirectionLabel,-5} {e.PacketId,6}  " +
                    $"{(e.PacketName.Length > 20 ? e.PacketName[..20] : e.PacketName),-22}" +
                    $"  {e.CompressionSummary,-28}" +
                    $"  {(hasEnc ? e.EncryptionType[..Math.Min(22, e.EncryptionType.Length)] : "-"),-24}" +
                    $"  {e.ByteLength,5}B  {e.HexPreview[..Math.Min(28, e.HexPreview.Length)]}");
                ImGui.PopStyleColor();
            }
        }

        if (_autoScrollDeep && _deepLive) ImGui.SetScrollHereY(1.0f);
        ImGui.EndChild();
    }

    private List<PacketLogEntry> GetDeepEntries()
    {
        var all = _pktLog.GetLastN(_deepShowLast);
        if (_showOnlyAnalyzed) all = all.Where(e => e.PacketName.Length > 0).ToList();
        if (_showCompressedOnly) all = all.Where(e => e.IsCompressed).ToList();
        return all;
    }
    // ─────────────────────────────────────────────────────────────────────
    /// <summary>
    /// Writes a concise diagnostic snapshot to the General Log.
    /// Covers: LocalPlayer, registry state, items, entities, AOB addresses,
    /// last 3 registry packets seen, compression summary.
    /// Called from both General Log toolbar button AND Inspector → Dump Diag button.
    /// </summary>
    private void DumpQuickDiagToLog()
    {
        var sb = new System.Text.StringBuilder();
        var aoh = AutoUpdateHandler.Instance;

        sb.AppendLine("╔═══════════════════════════════════════════════════════╗");
        sb.AppendLine("║  MENU DIAGNOSTIC DUMP  ← Screenshot and share        ║");
        sb.AppendLine($"╚════════ {DateTime.Now:HH:mm:ss dd-MMM-yyyy} ══════════════════════╝");

        // LocalPlayer
        bool hasLP = _deepCfg.HasLocalPlayer;
        sb.AppendLine(hasLP
            ? $"  [OK] LocalPlayer  ID={_deepCfg.LocalPlayerEntityId}  Name={_deepCfg.LocalPlayerName}"
            : "  [!!] LocalPlayer NOT FOUND - memory scan needed!");

        // AOB symbols
        sb.AppendLine($"  AOB:  LP=0x{aoh.LocalPlayerAddr:X}  pCords=0x{aoh.PlayerCoordsAddr:X}  HoverID=0x{aoh.HoverIdAddr:X}");
        if (aoh.PlayerCoordsAddr != 0)
            sb.AppendLine($"  XYZ: {aoh.PlayerX:F2}, {aoh.PlayerY:F2}, {aoh.PlayerZ:F2}" +
                          $"  Fly={aoh.IsFlying}  GM={aoh.Gamemode}  Stam={aoh.Stamina:F0}");

        // Registry
        sb.AppendLine($"  Registry: {RegistrySyncParser.NumericIdToName.Count} numeric IDs  {RegistrySyncParser.LiteralNames.Count} strings  HasLive={RegistrySyncParser.HasLiveData}");
        sb.AppendLine($"  RegPkts seen: {string.Join(", ", RegistrySyncParser.SeenRegistryOpcodes.Select(k => $"0x{k.Key:X2}×{k.Value}"))}");
        if (RegistrySyncParser.NumericIdToName.Count > 0)
        {
            sb.AppendLine("  First 5 numeric ID→name:");
            foreach (var kv in RegistrySyncParser.NumericIdToName.Take(5))
                sb.AppendLine($"    [{kv.Key}] → {kv.Value}");
        }

        // Items + entities
        sb.AppendLine($"  IdNameMap: {_smart.IdNameMap.Count}  ConfirmedItems: {_smart.ConfirmedItems.Count}  Entities: {_smart.ActiveEntities.Count}");
        var namedItems = _smart.ConfirmedItems.Values.Where(i => !string.IsNullOrEmpty(i.NameHint)).Take(8).ToList();
        if (namedItems.Any())
        {
            sb.AppendLine("  Named items:");
            foreach (var it in namedItems)
                sb.AppendLine($"    ID={it.ItemId}  name={it.NameHint}  stack={it.StackSize}  slot={it.SlotIndex}");
        }
        else sb.AppendLine("  No named items yet.");

        // Packet log summary
        sb.AppendLine($"  PacketLog: {_pktLog.Count} total  {_pktLog.OpcodeTypeCount} opcode types");
        var perType = _pktLog.GetOnePerOpcode().Take(8).ToList();
        if (perType.Any())
        {
            sb.AppendLine("  Per-opcode (newest):");
            foreach (var e in perType)
                sb.AppendLine($"    0x{e.PacketId:X2} {e.PacketName,-20} {e.CompressionSummary}");
        }

        // Recent registry packets decompressed hex
        var regPkts = _pktLog.GetOnePerOpcode()
            .Where(e => e.PacketId >= 0x28 && e.PacketId <= 0x55).Take(3).ToList();
        if (regPkts.Any())
        {
            sb.AppendLine("  Registry range pkts (0x28-0x55) decomp hex preview:");
            foreach (var rp in regPkts)
                sb.AppendLine($"    0x{rp.PacketId:X2} compr={rp.CompressionMethod} raw={rp.HexPreview[..Math.Min(32,rp.HexPreview.Length)]}" +
                              $"dec={rp.DecompressedHexPreview[..Math.Min(32,rp.DecompressedHexPreview.Length)]}");
        }
        else sb.AppendLine("  ⚠ No registry range packets (0x28-0x55) seen yet - connect to a server!");

        sb.AppendLine("╚═══════════════════════════════════════════════════════╝");

        foreach (var line in sb.ToString().Split('\n'))
            if (line.Trim().Length > 0) _log.Info(line.TrimEnd());
        _log.Success("[Diag] Snapshot complete - screenshot General Log tab now.");
    }

}
