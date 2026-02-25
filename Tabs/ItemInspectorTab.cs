using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Collections.Concurrent;
// WindowsClipboard is in Core (same assembly) - use direct class name since Core is already imported


namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Item Inspector - three complementary views of captured traffic:
///
///   SMART DETECTION PANEL (right sidebar, always visible)
///     Powered by SmartDetectionEngine running on its own background thread.
///     Reads from ConcurrentDictionary collections - zero UI-thread locking.
///     Shows: Confirmed Items (Sequence Correlation), Active Entities
///     (Delta Tracking), Input Mirror suggestion, Delta Watcher, Auto-Names.
///
///   DISCOVERED IDs (top panel, main area)
///     Schema Discovery via PacketAnalyser.AggregateAcrossPackets().
///     Every uint32 candidate is scored and ranked. Click "Set Target".
///
///   PACKET LIST + DETAIL (bottom panels, main area)
///     Per-packet view: select a packet to see hex dump, parsed fields,
///     and confidence-ranked item cards.
///
/// Workflow:
///   1. Start UDP proxy in Capture tab
///   2. Hold, pick up, or swap items in-game
///   3. Smart Detection sidebar fills automatically on background thread
///   4. Click "Set Target" on any Confirmed Item -> DupingTab fills in
/// </summary>
public class ItemInspectorTab : ITab
{
    public string Title => "  Item Inspector  ";

    private readonly TestLog              _log;
    private readonly PacketCapture        _capture;
    private readonly UdpProxy             _udpProxy;
    private readonly PacketStore          _store;
    private readonly ServerConfig         _config;
    private readonly SmartDetectionEngine _smart;

    // ── UI state ──────────────────────────────────────────────────────────
    private int    _selectedIdx  = -1;
    private bool   _autoScan     = true;
    private string _saveLabel    = "";
    private string _saveNotes    = "";
    private bool   _showAllPkts  = false;

    // Pinned item
    private DetectedItem? _pinnedItem;

    // Item-packet scan cache (throttled)
    private List<ItemScanResult> _scanResults  = new();
    private int                  _lastPktCount = 0;
    private DateTime             _lastScanTime = DateTime.MinValue;
    private const double ScanMs  = 3000;

    // Schema discovery cache
    private List<DiscoveredId>   _discovered      = new();
    private int                  _discPktCount    = 0;
    private DateTime             _discScanTime    = DateTime.MinValue;
    private const double         DiscMs           = 5000;
    private bool                 _discScanRunning = false;
    private bool                 _discShowAll     = false;
    private int                  _discSelected    = -1;

    // Search / async filter
    private string             _searchText    = "";
    private List<DiscoveredId> _filteredDisc  = new();
    private bool               _filterDirty   = true;
    private CancellationTokenSource? _filterCts;
    private bool               _filterRunning = false;

    // Confidence time-window scoring
    private readonly Dictionary<ulong, List<DateTime>> _idSeenTimes = new();

    // Smart Detection sidebar state
    private int  _sdEntitySelected = -1;
    private bool _sdShowDynamic    = true;
    private bool _sdShowStatic     = true;

    // Keyword filter
    private string _keywordFilter     = "";
    private bool   _keywordCaseSens   = false;

    // Force-scan progress display
    private string _forceScanMsg = "";

    // ── NEW: Confirmed Items table UI state ───────────────────────────────

    // Group-by-ID toggle: collapse multiple rows for same ItemId into one
    private bool _groupById      = true;

    // Stack delta tracking: itemId -> (previousStack, changeTime)
    private readonly Dictionary<uint, (byte PrevStack, DateTime ChangeAt)> _stackDeltas = new();

    // Context-menu state
    private uint  _ctxMenuId    = 0;
    private bool  _ctxMenuOpen  = false;

    public DetectedItem? PinnedItem => _pinnedItem;

    public ItemInspectorTab(TestLog log, PacketCapture capture,
                             UdpProxy udpProxy, PacketStore store,
                             ServerConfig config,
                             SmartDetectionEngine smart)
    {
        _log      = log;
        _capture  = capture;
        _udpProxy = udpProxy;
        _store    = store;
        _config   = config;
        _smart    = smart;
    }

    // ── Render ────────────────────────────────────────────────────────────

    public void Render()
    {
        float w    = ImGui.GetContentRegionAvail().X;
        float sdW  = 276f;
        float mainW = w - sdW - 8f;

        RenderStatusBar(w);
        ImGui.Spacing(); ImGui.Spacing();

        // Throttled auto-scan
        // Cache packet list ONCE per frame - GetPackets() copies 348k items each call
        var packets = _capture.GetPackets();

        if (_autoScan && packets.Count != _lastPktCount &&
            (DateTime.Now - _lastScanTime).TotalMilliseconds > ScanMs)
        {
            _lastPktCount = packets.Count;
            _lastScanTime = DateTime.Now;
            // Run on background thread - don't block UI
            var snap = packets;
            Task.Run(() =>
            {
                var r = ScanPackets(snap);
                _scanResults = r;
            });
        }

        if (_autoScan && packets.Count != _discPktCount && !_discScanRunning &&
            (DateTime.Now - _discScanTime).TotalMilliseconds > DiscMs)
        {
            _discPktCount    = packets.Count;
            _discScanTime    = DateTime.Now;
            _discScanRunning = true;
            var snap = packets;
            Task.Run(() =>
            {
                var d = PacketAnalyser.AggregateAcrossPackets(snap, 300);
                BoostConfidenceByTimeWindow(snap);
                _discovered      = d;
                _filterDirty     = true;
                _discScanRunning = false;
            });
        }

        // ── Top control row ───────────────────────────────────────────────
        float half = (mainW - 12) * 0.5f;

        UiHelper.SectionBox("SCAN CONTROLS", half, 98, () =>
        {
            ImGui.Checkbox("Auto-scan##asc", ref _autoScan);
            ImGui.Spacing();
            UiHelper.PrimaryButton("Scan Now", 110, 26, () =>
            {
                var all = _capture.GetPackets();
                _scanResults  = ScanPackets(all);
                _discovered   = PacketAnalyser.AggregateAcrossPackets(all);
                BoostConfidenceByTimeWindow(all);
                _lastPktCount = _discPktCount = all.Count;
                _lastScanTime = _discScanTime = DateTime.Now;
                _filterDirty  = true;
                _log.Info($"[Inspector] {all.Count} pkts -> {_scanResults.Count} item-related, " +
                          $"{_discovered.Count} IDs, {_smart.ConfirmedItems.Count} confirmed.");
            });
            ImGui.SameLine(0, 8);
            ImGui.Checkbox("Show all pkts##sap", ref _showAllPkts);
        });

        ImGui.SameLine(0, 12);

        UiHelper.SectionBox("PINNED ITEM", half, 90, () =>
        {
            if (_pinnedItem == null)
            {
                UiHelper.MutedLabel("No item pinned.");
                UiHelper.MutedLabel("Select a result -> Pin.");
            }
            else
            {
                UiHelper.AccentText($"Item ID: {_pinnedItem.ItemId}");
                ImGui.SameLine(0, 12);
                UiHelper.MutedLabel($"x{_pinnedItem.StackCount}  slot {_pinnedItem.SlotIndex}");
                if (!string.IsNullOrEmpty(_pinnedItem.NameHint))
                { ImGui.SameLine(0, 12); UiHelper.MutedLabel($"({_pinnedItem.NameHint})"); }
                ImGui.Spacing();
                UiHelper.DangerButton("Clear##clrpin", 60, 22, () => _pinnedItem = null);
                ImGui.SameLine(0, 8);
                UiHelper.WarnButton("Set Target->Dupe##todupe", 140, 22, () =>
                {
                    _config.SetTargetItemId(_pinnedItem.ItemId, "Item Inspector (pin)");
                    _log.Success($"[Inspector] Target -> {_pinnedItem.ItemId}");
                });
            }
        });

        ImGui.Spacing(); ImGui.Spacing();

        float availH = ImGui.GetContentRegionAvail().Y;

        // ── Left: main panel ──────────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##inspMain", new Vector2(mainW, availH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        if (ImGui.BeginTabBar("##inspTabs", ImGuiTabBarFlags.FittingPolicyScroll))
        {
            if (ImGui.BeginTabItem("  Discovery  "))
            {
                float discH  = 220f;
                float listH  = ImGui.GetContentRegionAvail().Y - discH - 12f;
                float listW  = ImGui.GetContentRegionAvail().X * 0.54f;
                float detW   = ImGui.GetContentRegionAvail().X - listW - 8f;
                RenderDiscoveredIds(ImGui.GetContentRegionAvail().X, discH);
                ImGui.Spacing();
                RenderPacketList(listW, listH, packets);
                ImGui.SameLine(0, 8);
                RenderDetailPanel(detW, listH, packets);
                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("  Confirmed Items  "))
            {
                RenderConfirmedItemsTable(ImGui.GetContentRegionAvail().X,
                                          ImGui.GetContentRegionAvail().Y);
                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("  0x4A Entities  "))
            {
                Render0x4APanel(ImGui.GetContentRegionAvail().X,
                                ImGui.GetContentRegionAvail().Y);
                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("  String Corr.  "))
            {
                RenderStringCorrelationTable(ImGui.GetContentRegionAvail().X,
                                             ImGui.GetContentRegionAvail().Y);
                ImGui.EndTabItem();
            }

            ImGui.EndTabBar();
        }

        ImGui.EndChild();
        ImGui.SameLine(0, 8);

        // ── Right: Smart Detection sidebar ────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##sdSidebar", new Vector2(sdW, availH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        RenderSmartDetectionSidebar(sdW, availH);
        ImGui.EndChild();
    }

    // ── Smart Detection Sidebar ───────────────────────────────────────────
    //
    // All data is read from ConcurrentDictionary - reads are thread-safe
    // with no locking needed. ToList() snapshots are taken once per frame.

    private void RenderSmartDetectionSidebar(float w, float h)
    {
        // Header strip
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##sdhdr", new Vector2(w - 4, 26), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("SMART DETECTION");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 8);
        UiHelper.MutedLabel("background thread [>]");
        ImGui.EndChild();

        ImGui.Spacing();

        // ── LocalPlayer status pill ───────────────────────────────────────
        if (_config.HasLocalPlayer)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.04f, 0.10f, 0.20f, 1f));
            ImGui.BeginChild("##sdlp", new Vector2(w - 4, 28), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();
            ImGui.SetCursorPos(new Vector2(8, 5));
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.18f, 0.65f, 0.95f, 1f));
            ImGui.TextUnformatted(
                $"[*] LocalPlayer  ID {_config.LocalPlayerEntityId}" +
                (string.IsNullOrEmpty(_config.LocalPlayerName) ? "" : $"  ({_config.LocalPlayerName})"));
            ImGui.PopStyleColor();
            ImGui.EndChild();
        }

        ImGui.Spacing();

        // ── Input Mirror suggestion (highest priority alert) ──────────────
        if (_smart.HasSuggestion)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.08f, 0.16f, 0.07f, 1f));
            ImGui.BeginChild("##sdmirror", new Vector2(w - 4, 70), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();
            ImGui.SetCursorPos(new Vector2(6, 4));
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
            ImGui.TextUnformatted("⟹ Input Mirror Suggestion");
            ImGui.PopStyleColor();
            ImGui.SetCursorPosX(6);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
            ImGui.TextUnformatted($"ID  {_smart.SuggestedTargetId}");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 8);
            string srcShort = _smart.SuggestedSource.Length > 20
                ? _smart.SuggestedSource[..20] + "..." : _smart.SuggestedSource;
            UiHelper.MutedLabel(srcShort);
            ImGui.SetCursorPosX(6);
            UiHelper.WarnButton("Set Target##mirtgt", 90, 22, () =>
            {
                _config.SetTargetItemId((int)_smart.SuggestedTargetId, "Input Mirror");
                _log.Success($"[Inspector] Input Mirror -> Target {_smart.SuggestedTargetId}");
                _smart.DismissSuggestion();
            });
            ImGui.SameLine(0, 4);
            UiHelper.SecondaryButton("Dismiss##mirdis", 62, 22,
                () => _smart.DismissSuggestion());
            ImGui.EndChild();
            ImGui.Spacing();
        }

        // ── Active Entities (Delta Tracking) ─────────────────────────────
        var entities = _smart.ActiveEntities.Values
            .Where(e => e.IsLocalPlayer ||
                        (_sdShowDynamic && e.IsDynamic) ||
                        (_sdShowStatic && !e.IsDynamic))
            .OrderByDescending(e => e.IsLocalPlayer ? int.MaxValue : e.UpdateCount)
            .ToList();

        ImGui.SetCursorPosX(4);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted($"ACTIVE ENTITIES  ({_smart.ActiveEntities.Count})");
        ImGui.PopStyleColor();
        ImGui.SetCursorPosX(4);
        ImGui.Checkbox("Dyn##sdd", ref _sdShowDynamic);
        ImGui.SameLine(0, 6);
        ImGui.Checkbox("Static##sds", ref _sdShowStatic);
        ImGui.SameLine(w - 56);
        if (ImGui.SmallButton("Purge##sdp"))
        {
            _smart.PurgeStaleEntities();
            _log.Info("[Inspector] Stale entities purged.");
        }

        float entityH = Math.Clamp(entities.Count * 22f + 8f, 50f, 200f);

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg0);
        ImGui.BeginChild("##sdentities", new Vector2(w - 4, entityH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        if (entities.Count == 0)
        {
            ImGui.SetCursorPos(new Vector2(6, 8));
            UiHelper.MutedLabel("None yet. Movement");
            UiHelper.MutedLabel("packets populate this.");
        }
        else
        {
            var dl = ImGui.GetWindowDrawList();
            for (int ei = 0; ei < entities.Count; ei++)
            {
                var  ent    = entities[ei];
                bool selE   = _sdEntitySelected == ei;
                var  rowBg  = ent.IsLocalPlayer
                    ? new Vector4(0.04f, 0.10f, 0.20f, 1f)   // dark blue = local player
                    : ent.IsDynamic
                        ? new Vector4(0.05f, 0.14f, 0.07f, 1f)
                        : new Vector4(0.14f, 0.11f, 0.04f, 1f);
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(w - 8, 20),
                    ImGui.ColorConvertFloat4ToU32(rowBg));
                if (selE)
                    dl.AddRectFilled(sp, sp + new Vector2(w - 8, 20),
                        ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));

                var rowColor = ent.IsLocalPlayer
                    ? new Vector4(0.18f, 0.65f, 0.95f, 1f)  // blue = local player
                    : ent.IsDynamic ? MenuRenderer.ColAccent : MenuRenderer.ColWarn;

                string displayIcon = ent.IsLocalPlayer ? "[*]" : ent.IsDynamic ? ">" : "■";
                string displayHint = ent.IsLocalPlayer
                    ? " LocalPlayer"
                    : string.IsNullOrEmpty(ent.NameHint) ? ""
                        : " " + ent.NameHint[..Math.Min(6, ent.NameHint.Length)];

                ImGui.PushStyleColor(ImGuiCol.Text, rowColor);
                bool clicked = ImGui.Selectable(
                    $" {displayIcon} {ent.EntityId,-8}{displayHint}",
                    selE, ImGuiSelectableFlags.None, new Vector2(0, 20));
                ImGui.PopStyleColor();

                if (clicked) _sdEntitySelected = ei;

                if (ImGui.IsItemHovered())
                {
                    ImGui.BeginTooltip();
                    ImGui.PushStyleColor(ImGuiCol.Text,
                        ent.IsDynamic ? MenuRenderer.ColAccent : MenuRenderer.ColWarn);
                    ImGui.TextUnformatted($"Entity ID: {ent.EntityId}");
                    ImGui.PopStyleColor();
                    UiHelper.MutedLabel($"{(ent.IsDynamic ? "Dynamic - player/mob" : "Static - world object")}");
                    UiHelper.MutedLabel($"Pos: ({ent.X:F1}, {ent.Y:F1}, {ent.Z:F1})");
                    UiHelper.MutedLabel($"Updates: {ent.UpdateCount}  Δmax: {ent.MaxDelta:F2}m");
                    UiHelper.MutedLabel($"Last: {ent.LastSeen:HH:mm:ss}");
                    if (!string.IsNullOrEmpty(ent.NameHint))
                        UiHelper.MutedLabel($"Name: {ent.NameHint}");
                    ImGui.EndTooltip();
                }

                if (ImGui.BeginPopupContextItem($"##entctx{ei}"))
                {
                    ImGui.TextUnformatted($"Entity {ent.EntityId}");
                    ImGui.Separator();
                    if (ImGui.MenuItem("Set as Target"))
                    {
                        _config.SetTargetItemId((int)ent.EntityId, "Active Entities");
                        _log.Success($"[Inspector] Entity {ent.EntityId} -> Target.");
                    }
                    if (ImGui.MenuItem("Pin as Item"))
                        _pinnedItem = new DetectedItem
                        {
                            ItemId = (int)ent.EntityId, StackCount = 1,
                            Confidence = FieldConfidence.Medium, NameHint = ent.NameHint,
                        };
                    ImGui.EndPopup();
                }
            }
        }

        ImGui.EndChild();
        ImGui.Spacing();

        // ── Delta Watcher - Static vs Dynamic classification ──────────────
        var delta = _smart.DeltaClassifications.ToList();
        if (delta.Count > 0)
        {
            ImGui.SetCursorPosX(4);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
            ImGui.TextUnformatted($"DELTA WATCHER  ({delta.Count})");
            ImGui.PopStyleColor();

            float deltaH = Math.Clamp(delta.Count * 18f + 8f, 40f, 130f);
            ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg0);
            ImGui.BeginChild("##sddelta", new Vector2(w - 4, deltaH), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();
            foreach (var kv in delta.OrderBy(kv => kv.Value))
            {
                bool stat = kv.Value == DeltaClass.Static;
                ImGui.PushStyleColor(ImGuiCol.Text,
                    stat ? MenuRenderer.ColWarn : MenuRenderer.ColAccent);
                ImGui.TextUnformatted($"  {(stat ? "■" : ">")} {kv.Key,-8} {(stat ? "Static" : "Dynamic")}");
                ImGui.PopStyleColor();
            }
            ImGui.EndChild();
            ImGui.Spacing();
        }

        // ── Auto-Named IDs ────────────────────────────────────────────────
        var names = _smart.IdNameMap.ToList();
        if (names.Count > 0)
        {
            ImGui.SetCursorPosX(4);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
            ImGui.TextUnformatted($"AUTO-NAMED  ({names.Count})");
            ImGui.PopStyleColor();

            float nameH = Math.Clamp(names.Count * 18f + 8f, 40f, 120f);
            ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg0);
            ImGui.BeginChild("##sdnames", new Vector2(w - 4, nameH), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();
            foreach (var kv in names.OrderBy(kv => kv.Key))
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                ImGui.TextUnformatted($"  {kv.Key,-6}");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 6);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                ImGui.TextUnformatted(kv.Value);
                ImGui.PopStyleColor();
            }
            ImGui.EndChild();
            ImGui.Spacing();
        }

        // ── Auto-Pin status ───────────────────────────────────────────────
        int pinnedCount = _smart.ConfirmedItems.Values.Count(i => i.PacketCount >= 3);
        if (pinnedCount > 0)
        {
            ImGui.SetCursorPosX(4);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
            ImGui.TextUnformatted($"[*] {pinnedCount} item(s) auto-pinned to Book");
            ImGui.PopStyleColor();
        }
    }

    // ── Confirmed Items table ─────────────────────────────────────────────

    private void RenderConfirmedItemsTable(float w, float h)
    {
        // ── Build display list (with optional Group-by-ID) ────────────────
        var rawItems = _smart.ConfirmedItems.Values
            .OrderByDescending(i => i.PacketCount)
            .ToList();

        // Update stack delta tracker
        foreach (var it in rawItems)
        {
            if (_stackDeltas.TryGetValue(it.ItemId, out var prev))
            {
                if (prev.PrevStack != it.StackSize)
                    _stackDeltas[it.ItemId] = (it.StackSize, DateTime.Now);
            }
            else
            {
                _stackDeltas[it.ItemId] = (it.StackSize, DateTime.MinValue);
            }
        }

        // Group-by-ID: merge all entries with same ItemId
        var displayItems = rawItems; // default: ungrouped
        if (_groupById)
        {
            displayItems = rawItems
                .GroupBy(i => i.ItemId)
                .Select(g =>
                {
                    var best = g.OrderByDescending(x => x.PacketCount).First();
                    best.PacketCount = g.Sum(x => x.PacketCount); // aggregate count
                    return best;
                })
                .OrderByDescending(i => i.PacketCount)
                .ToList();
        }

        // ── Header box ────────────────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##cithdr", new Vector2(w, 62), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("CONFIRMED ITEMS  -  Sequence Correlation: uint32 followed by byte 1-64  (LE + BE + VarInt)");
        ImGui.PopStyleColor();
        ImGui.SetCursorPosX(8);

        // Smart auto-pin notice
        int namedCount = rawItems.Count(i => !string.IsNullOrEmpty(i.NameHint));
        UiHelper.MutedLabel($"{displayItems.Count} shown ({rawItems.Count} total)  ·  " +
                            $"{namedCount} named  ·  Smart auto-pin: named + slotted only");

        ImGui.SetCursorPosX(8);
        if (_smart.ForceScanRunning)
        {
            UiHelper.WarnText($"[>] Scanning... {_smart.ForceScanProgress}%  {_smart.ForceScanStatus}");
        }
        else
        {
            UiHelper.WarnButton("Scan History##fsseq", 140, 22, () =>
            {
                _smart.ForceSequenceScan(_capture.GetPackets());
                _log.Info("[Inspector] Force sequence scan started.");
            });
            ImGui.SameLine(0, 8);
            UiHelper.SecondaryButton("Arm Loot-Drop##loot", 140, 22, () =>
            {
                _smart.ArmLootDropListener();
                _log.Info("[Inspector] Loot-drop listener armed - drop an item now.");
            });
            ImGui.SameLine(0, 8);
            // Group-by toggle
            ImGui.PushStyleColor(ImGuiCol.Text, _groupById ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
            ImGui.Checkbox("Group by ID##grpid", ref _groupById);
            ImGui.PopStyleColor();
        }
        ImGui.EndChild();

        ImGui.Spacing();

        // ── Column header row ─────────────────────────────────────────────
        // Uses short timestamp (HH:mm:ss) and a Name column
        UiHelper.MutedLabel(
            "  [T]  Item ID     Stack    Slot   Name                 Pkts  First");

        var dlC = ImGui.GetWindowDrawList();
        float hly = ImGui.GetCursorScreenPos().Y;
        dlC.AddLine(new Vector2(ImGui.GetWindowPos().X, hly),
                    new Vector2(ImGui.GetWindowPos().X + w, hly),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        const float RowH = 22f;
        float tableH = h - 85f;
        ImGui.BeginChild("##citable", new Vector2(w, tableH), ImGuiChildFlags.None);

        var clip = new ImGuiListClipper();
        clip.Begin(displayItems.Count, RowH);
        while (clip.Step())
        {
            for (int ci = clip.DisplayStart; ci < clip.DisplayEnd; ci++)
            {
                var  it  = displayItems[ci];
                var  sp  = ImGui.GetCursorScreenPos();
                bool hi  = it.PacketCount >= 3;

                // ── Row hover highlight ───────────────────────────────────
                bool isHovered = ImGui.IsMouseHoveringRect(sp, sp + new Vector2(w, RowH));
                if (isHovered)
                {
                    ImGui.GetWindowDrawList().AddRectFilled(sp, sp + new Vector2(w, RowH),
                        ImGui.ColorConvertFloat4ToU32(new Vector4(0.18f, 0.95f, 0.45f, 0.22f)));
                }
                else if (hi)
                {
                    ImGui.GetWindowDrawList().AddRectFilled(sp, sp + new Vector2(w, RowH),
                        ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
                }

                // ── [I] badge ────────────────────────────────────────────
                ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.95f, 0.75f, 0.10f, 1f));
                ImGui.TextUnformatted("[I]");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 4);

                // ── Stack with delta indicator ────────────────────────────
                string stackStr;
                Vector4 stackColor = MenuRenderer.ColText;
                if (_stackDeltas.TryGetValue(it.ItemId, out var delta) &&
                    delta.ChangeAt > DateTime.MinValue &&
                    (DateTime.Now - delta.ChangeAt).TotalSeconds < 5.0)
                {
                    int diff = it.StackSize - delta.PrevStack;
                    string sign = diff >= 0 ? "+" : "";
                    stackStr  = $"{it.StackSize}({sign}{diff})";
                    stackColor = diff >= 0
                        ? new Vector4(0.18f, 0.95f, 0.45f, 1f)   // green = gained
                        : new Vector4(0.95f, 0.28f, 0.22f, 1f);   // red   = lost
                }
                else
                {
                    stackStr = $"{it.StackSize}";
                }

                string nameStr  = string.IsNullOrEmpty(it.NameHint) ? "-" : it.NameHint;
                // Short timestamp HH:mm:ss
                string timeStr  = it.FirstSeen.ToString("HH:mm:ss");

                // Selectable row (stretch to avoid button area)
                ImGui.PushStyleColor(ImGuiCol.Text,
                    hi ? MenuRenderer.ColAccent : MenuRenderer.ColText);
                ImGui.Selectable(
                    $"  {it.ItemId,-10} ",
                    false, ImGuiSelectableFlags.None, new Vector2(100, RowH));
                ImGui.PopStyleColor();

                // ── Right-click context menu on the ID ───────────────────
                if (ImGui.IsItemHovered() && ImGui.IsMouseClicked(ImGuiMouseButton.Right))
                {
                    _ctxMenuId   = it.ItemId;
                    _ctxMenuOpen = true;
                    ImGui.OpenPopup($"##ctxci{it.ItemId}");
                }
                if (ImGui.BeginPopup($"##ctxci{it.ItemId}"))
                {
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
                    ImGui.TextUnformatted($"ID: {it.ItemId}  (0x{it.ItemId:X})");
                    ImGui.PopStyleColor();
                    ImGui.Separator();
                    if (ImGui.MenuItem("Copy Hex"))
                    {
                        WindowsClipboard.Set($"0x{it.ItemId:X8}");
                        _log.Info($"[Inspector] Copied 0x{it.ItemId:X8} to clipboard.");
                    }
                    if (ImGui.MenuItem("Copy Decimal"))
                        WindowsClipboard.Set(it.ItemId.ToString());
                    if (ImGui.MenuItem("Filter (show only this ID)"))
                        _keywordFilter = it.ItemId.ToString();
                    if (ImGui.MenuItem("Search in Memory"))
                        _log.Info($"[Inspector] Memory search for 0x{it.ItemId:X8} - open Memory tab.");
                    if (ImGui.MenuItem("Send to Spoofer"))
                    {
                        _config.SetTargetItemId((int)it.ItemId, "Spoofer via context menu");
                        _log.Success($"[Inspector] {it.ItemId} -> Target (Spoofer).");
                    }
                    ImGui.EndPopup();
                }

                ImGui.SameLine(0, 0);

                // Stack column with colour
                ImGui.PushStyleColor(ImGuiCol.Text, stackColor);
                ImGui.TextUnformatted($"{stackStr,-9}");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 0);

                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColText);
                ImGui.TextUnformatted($"{it.SlotIndex,-6} {nameStr,-20} {it.PacketCount,-5} {timeStr}");
                ImGui.PopStyleColor();

                if (ImGui.IsItemHovered()) RenderIdTooltip((uint)it.ItemId);

                // ── Icon-style action buttons ─────────────────────────────
                // Using compact text glyphs instead of verbose labels
                float btnX = w - 178;
                ImGui.SameLine(btnX, 0);

                // [+] Set Target (crosshair symbol)
                UiHelper.WarnButton($"(+)##ciset{ci}", 38, 20, () =>
                {
                    _config.SetTargetItemId((int)it.ItemId, "Confirmed Items");
                    _log.Success($"[Inspector] {it.ItemId} -> Target.");
                });
                if (ImGui.IsItemHovered())
                {
                    ImGui.SetTooltip($"Set Target  (currently: {_config.TargetItemId})");
                }
                ImGui.SameLine(0, 3);

                // [o] ESP (eye symbol)
                UiHelper.SecondaryButton($"[o]##ciesp{ci}", 38, 20, () =>
                {
                    PushIdToEsp((uint)it.ItemId, it.NameHint, EntityClass.Item);
                    _log.Info($"[Inspector] {it.ItemId} -> ESP.");
                });
                if (ImGui.IsItemHovered()) ImGui.SetTooltip("Push to ESP overlay");
                ImGui.SameLine(0, 3);

                // [p] Pin
                UiHelper.SecondaryButton($"[p]##cipin{ci}", 38, 20, () =>
                {
                    _pinnedItem = new DetectedItem
                    {
                        ItemId    = (int)it.ItemId, StackCount = it.StackSize,
                        SlotIndex = it.SlotIndex,   Confidence = FieldConfidence.High,
                        NameHint  = it.NameHint,
                    };
                });
                if (ImGui.IsItemHovered()) ImGui.SetTooltip("Pin item for dupe setup");

                ImGui.SameLine(0, 3);
                // [=] More / Book
                UiHelper.SecondaryButton($"[=]##cibook{ci}", 38, 20, () =>
                {
                    var payload = new byte[6];
                    BitConverter.GetBytes((uint)it.ItemId).CopyTo(payload, 0);
                    payload[4] = it.StackSize; payload[5] = it.SlotIndex;
                    _store.Save($"Manual:{it.ItemId}", $"Manually pinned {it.ItemId}", payload,
                                PacketDirection.ServerToClient);
                    _log.Info($"[Inspector] {it.ItemId} saved to Book.");
                });
                if (ImGui.IsItemHovered()) ImGui.SetTooltip("Save to Packet Book");
            }
        }
        clip.End();

        if (displayItems.Count == 0)
        {
            ImGui.SetCursorPosY(tableH * 0.4f);
            UiHelper.MutedLabel("  No confirmed items yet.");
            UiHelper.MutedLabel("  Fires when uint32 is immediately followed by byte 1-64.");
        }

        ImGui.EndChild();
    }

    // ── 0x4A Entities panel ───────────────────────────────────────────────

    private void Render0x4APanel(float w, float h)
    {
        var entries = _smart.Pkt4AEntities.Values
            .OrderByDescending(e => e.PacketCount)
            .ToList();

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##4Ahdr", new Vector2(w, 62), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("0x4A DEDICATED PARSER  -  LE + BE endianness, size 7-174 bytes  ·  Proxy Sync: auto");
        ImGui.PopStyleColor();
        ImGui.SetCursorPosX(8);
        UiHelper.MutedLabel($"{entries.Count} entities extracted from 0x4A packets");
        ImGui.SetCursorPosX(8);

        if (_smart.ForceScanRunning)
        {
            UiHelper.WarnText($"[>] Scanning... {_smart.ForceScanProgress}%  {_smart.ForceScanStatus}");
        }
        else
        {
            UiHelper.WarnButton("Force Scan 0x4A##fs4a", 160, 22, () =>
            {
                _smart.Force0x4AScan(_capture.GetPackets());
                _log.Info("[Inspector] Force 0x4A scan started.");
            });
            ImGui.SameLine(0, 8);
            UiHelper.WarnButton("Force Scan ALL##fsall", 150, 22, () =>
            {
                _smart.ForceScan(_capture.GetPackets());
                _log.Info("[Inspector] Full force scan started.");
            });
        }
        ImGui.EndChild();

        ImGui.Spacing();
        UiHelper.MutedLabel("  Entity ID     Packets   First Seen    Last Seen");

        const float RowH4 = 22f;
        ImGui.BeginChild("##4Atable", new Vector2(w, h - 80f), ImGuiChildFlags.None);

        var clip = new ImGuiListClipper();
        clip.Begin(entries.Count, RowH4);
        while (clip.Step())
        {
            for (int qi = clip.DisplayStart; qi < clip.DisplayEnd; qi++)
            {
                var e = entries[qi];
                bool isLP = _config.HasLocalPlayer && _config.LocalPlayerEntityId == e.EntityId;

                // Classification badge - [?] replaced with meaningful tags
                _smart.EntityClassifications.TryGetValue(e.EntityId, out var cls);
                string badge = isLP ? "[*]"
                             : cls == EntityClass.Player ? "[P]"
                             : cls == EntityClass.Mob    ? "[M]"
                             : cls == EntityClass.Item   ? "[I]" : "[E]";   // [E] = unknown Entity
                var badgeColor = isLP ? new Vector4(0.18f, 0.65f, 0.95f, 1f)
                               : cls == EntityClass.Player ? new Vector4(0.18f, 0.95f, 0.45f, 1f)
                               : cls == EntityClass.Mob    ? new Vector4(0.95f, 0.28f, 0.22f, 1f)
                               : cls == EntityClass.Item   ? new Vector4(0.95f, 0.75f, 0.10f, 1f)
                               : MenuRenderer.ColTextMuted;  // grey for unclassified

                ImGui.PushStyleColor(ImGuiCol.Text, badgeColor);
                ImGui.TextUnformatted(badge);
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 4);

                string nameHint = !string.IsNullOrEmpty(e.NameHint) ? $"  [{e.NameHint}]" : "";
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                ImGui.Selectable(
                    $"  {e.EntityId,-14}{nameHint,-14} {e.PacketCount,-9}" +
                    $"{e.FirstSeen:HH:mm:ss}    {e.LastSeen:HH:mm:ss}##4a{qi}",
                    false, ImGuiSelectableFlags.None, new Vector2(w - 190, RowH4));
                ImGui.PopStyleColor();

                if (ImGui.IsItemHovered()) RenderIdTooltip(e.EntityId);

                ImGui.SameLine(0, 4);
                UiHelper.WarnButton($"Target##4aset{qi}", 56, 20, () =>
                {
                    _config.SetTargetItemId((int)e.EntityId, "0x4A Parser");
                    // Also sync to ESP with name from IdNameMap
                    PushIdToEsp(e.EntityId, e.NameHint,
                        cls == EntityClass.Unknown ? EntityClass.Player : cls);
                    _log.Success($"[Inspector] 0x4A entity {e.EntityId} -> Target.");
                });
                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip($"Set as dupe/spoofer target  (crosshair)");
                ImGui.SameLine(0, 4);
                UiHelper.SecondaryButton($"[o]##4aesp{qi}", 38, 20, () =>
                {
                    PushIdToEsp(e.EntityId, e.NameHint,
                        cls == EntityClass.Unknown ? EntityClass.Player : cls);
                    _log.Info($"[Inspector] Entity {e.EntityId} -> ESP.");
                });
                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip("Push to ESP overlay with resolved name");
                // Right-click context menu
                if (ImGui.IsItemHovered(ImGuiHoveredFlags.None) &&
                    ImGui.IsMouseClicked(ImGuiMouseButton.Right))
                    ImGui.OpenPopup($"##ctx4a{qi}");
                if (ImGui.BeginPopup($"##ctx4a{qi}"))
                {
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
                    ImGui.TextUnformatted($"Entity {e.EntityId}  (0x{e.EntityId:X})  {badge}");
                    ImGui.PopStyleColor();
                    ImGui.Separator();
                    if (ImGui.MenuItem("Copy Hex"))     WindowsClipboard.Set($"0x{e.EntityId:X8}");
                    if (ImGui.MenuItem("Copy Decimal")) WindowsClipboard.Set(e.EntityId.ToString());
                    if (ImGui.MenuItem("Filter"))       _keywordFilter = e.EntityId.ToString();
                    if (ImGui.MenuItem("Search in Memory"))
                        _log.Info($"[Inspector] Open Memory tab and search 0x{e.EntityId:X8}");
                    if (ImGui.MenuItem("Send to Spoofer"))
                    {
                        _config.SetTargetItemId((int)e.EntityId, "Spoofer via context");
                        _log.Success($"[Inspector] {e.EntityId} -> Target.");
                    }
                    ImGui.EndPopup();
                }
            }
        }
        clip.End();

        if (entries.Count == 0)
        {
            ImGui.SetCursorPosY((h - 80f) * 0.4f);
            UiHelper.MutedLabel("  No 0x4A packets captured yet.");
            UiHelper.MutedLabel("  Parser activates automatically on first 0x4A.");
        }

        ImGui.EndChild();
    }

    // ── String Correlation table ──────────────────────────────────────────

    private void RenderStringCorrelationTable(float w, float h)
    {
        var corr = _smart.StringCorrelation.ToList().OrderBy(kv => kv.Key).ToList();

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##scorrhdr", new Vector2(w, 44), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("STRING CORRELATION  -  Metadata strings linked to co-occurring Item IDs");
        ImGui.PopStyleColor();
        ImGui.SetCursorPosX(8);
        UiHelper.MutedLabel("Strings (2-8 chars) that co-occur with the same Item ID ≥5 times are linked.");
        ImGui.EndChild();

        ImGui.Spacing();
        UiHelper.MutedLabel("  Metadata String     Linked Item ID");

        const float RowHS = 22f;
        ImGui.BeginChild("##scorrtable", new Vector2(w, h - 80f), ImGuiChildFlags.None);

        var clip = new ImGuiListClipper();
        clip.Begin(corr.Count, RowHS);
        while (clip.Step())
        {
            for (int si = clip.DisplayStart; si < clip.DisplayEnd; si++)
            {
                var (meta, itemId) = corr[si];
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                ImGui.TextUnformatted($"  \"{meta}\"");
                ImGui.PopStyleColor();
                ImGui.SameLine(160);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
                ImGui.TextUnformatted($"{itemId}");
                ImGui.PopStyleColor();
                ImGui.SameLine(260);
                UiHelper.WarnButton($"Target##sc{si}", 80, 20, () =>
                {
                    _config.SetTargetItemId((int)itemId,
                        $"String Corr (\"{meta}\")");
                    _log.Success($"[Inspector] '{meta}' -> {itemId} -> Target.");
                });
            }
        }
        clip.End();

        if (corr.Count == 0)
        {
            ImGui.SetCursorPosY((h - 80f) * 0.4f);
            UiHelper.MutedLabel("  No correlations yet.");
        }

        ImGui.EndChild();
    }

    // ── Discovered IDs ────────────────────────────────────────────────────

    private void RenderDiscoveredIds(float w, float h)
    {
        // Header with two rows
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##dischdr", new Vector2(w, 54), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(10, 5));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("DISCOVERED IDs  -  Automated Schema Discovery");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 20);
        UiHelper.MutedLabel($"{_discovered.Count} candidates  ·  {_discPktCount} packets scanned");
        ImGui.SameLine(0, 14);
        ImGui.Checkbox("Show Low##discall", ref _discShowAll);
        if (_config.HasTargetItem)
        {
            ImGui.SameLine(0, 20);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
            ImGui.TextUnformatted($"[*] {_config.TargetItemId}  [{_config.TargetItemSource}]");
            ImGui.PopStyleColor();
        }

        ImGui.SetCursorPos(new Vector2(10, 30));
        UiHelper.MutedLabel("Filter:");
        ImGui.SameLine(0, 6);
        ImGui.SetNextItemWidth(-120);  // stretch to fill, leaving room for Show Low button
        if (ImGui.InputText("##discSearch", ref _searchText, 64))
            _filterDirty = true;
        ImGui.SameLine(0, 8);
        if (_filterRunning)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted("[>] filtering...");
            ImGui.PopStyleColor();
        }
        ImGui.EndChild();

        // Async filter
        var preFilter = _discShowAll
            ? _discovered
            : _discovered.Where(d => d.Confidence >= FieldConfidence.Medium || d.BoostedToHigh).ToList();

        if (_filterDirty)
        {
            _filterDirty = false;
            _filterCts?.Cancel();
            _filterCts = new CancellationTokenSource();
            var cts = _filterCts;
            var snapshot = preFilter.ToList();
            string search = _searchText.ToUpperInvariant();
            _filterRunning = true;
            Task.Run(() =>
            {
                var result = string.IsNullOrWhiteSpace(search)
                    ? snapshot
                    : snapshot.Where(d =>
                        d.Value.ToString().Contains(search) ||
                        d.TypeTag.ToUpperInvariant().Contains(search) ||
                        (d.LinkedName ?? "").ToUpperInvariant().Contains(search))
                      .ToList();
                if (!cts.IsCancellationRequested)
                {
                    _filteredDisc  = result;
                    _filterRunning = false;
                }
            });
        }
        else if (!_filterRunning && _filteredDisc.Count == 0 && preFilter.Count > 0)
        {
            _filteredDisc = preFilter;
        }

        var show = _filteredDisc;

        // Table with clipper
        float tableH = h - 56f;
        float btnW   = 116f;
        float pinW   = 70f;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##disctbl", new Vector2(w, tableH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 4));
        UiHelper.MutedLabel($"  {"Value",-12} {"Type",-20} {"Conf",-8} {"Seen",-6} {"Score",-7}  Action");

        var dlh = ImGui.GetWindowDrawList();
        float hly = ImGui.GetCursorScreenPos().Y - 2;
        dlh.AddLine(new Vector2(ImGui.GetWindowPos().X, hly),
                    new Vector2(ImGui.GetWindowPos().X + w, hly),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        var dl = ImGui.GetWindowDrawList();

        var clip = new ImGuiListClipper();
        clip.Begin(show.Count, 22f);
        while (clip.Step())
        {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++)
            {
                var  d        = show[i];
                bool sel      = _discSelected == i;
                bool isTarget = _config.HasTargetItem && _config.TargetItemId == (int)d.Value;
                bool itemLike = d.TypeTag == "Item ID";
                bool canTgt   = itemLike || d.TypeTag == "Entity/Player ID";

                // Keyword match highlight
                bool kwMatch = !string.IsNullOrEmpty(_keywordFilter) && (
                    d.Value.ToString().Contains(_keywordFilter,
                        _keywordCaseSens ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrEmpty(d.LinkedName) && d.LinkedName.Contains(_keywordFilter,
                        _keywordCaseSens ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase)));

                if (sel || isTarget || kwMatch)
                {
                    var sp = ImGui.GetCursorScreenPos();
                    dl.AddRectFilled(sp, sp + new Vector2(w, 22),
                        ImGui.ColorConvertFloat4ToU32(isTarget
                            ? MenuRenderer.ColWarnDim
                            : kwMatch
                                ? new Vector4(0.20f, 0.18f, 0.02f, 1f)  // yellow tint for keyword
                                : MenuRenderer.ColAccentDim));
                }

                // [P]/[I] badge
                _smart.EntityClassifications.TryGetValue(d.Value, out var dCls);
                bool isPlayer = d.TypeTag == "Entity/Player ID" || dCls == EntityClass.Player;
                string typeBadge = dCls == EntityClass.Player ? "[P]"
                                 : dCls == EntityClass.Mob    ? "[M]"
                                 : dCls == EntityClass.Item || itemLike ? "[I]" : "   ";
                var badgeCol = dCls == EntityClass.Player ? new Vector4(0.18f, 0.95f, 0.45f, 1f)
                             : dCls == EntityClass.Mob    ? new Vector4(0.95f, 0.28f, 0.22f, 1f)
                             : dCls == EntityClass.Item   ? new Vector4(0.95f, 0.75f, 0.10f, 1f)
                             : MenuRenderer.ColTextMuted;

                ImGui.PushStyleColor(ImGuiCol.Text, badgeCol);
                ImGui.TextUnformatted(typeBadge);
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 4);

                var rowCol = (kwMatch)
                           ? new Vector4(0.95f, 0.85f, 0.10f, 1f) // bold yellow for keyword match
                           : (d.BoostedToHigh || d.Confidence == FieldConfidence.High)
                           ? MenuRenderer.ColAccent
                           : d.Confidence == FieldConfidence.Medium
                           ? MenuRenderer.ColBlue
                           : MenuRenderer.ColTextMuted;

                ImGui.PushStyleColor(ImGuiCol.Text, rowCol);
                if (ImGui.Selectable(
                    $"  {d.Value,-12} {d.TypeTag,-20} {d.ConfidenceLabel,-8}x{d.OccurrenceCount,-5} {d.Score,-7}##dsel{i}",
                    sel, ImGuiSelectableFlags.None, new Vector2(w - btnW - pinW - 80f, 22)))
                    _discSelected = i;
                ImGui.PopStyleColor();

                if (ImGui.IsItemHovered()) RenderIdTooltip(d.Value);

                ImGui.SameLine(0, 4);
                UiHelper.SecondaryButton($"-> ESP##desp{i}", 48, 20, () =>
                {
                    PushIdToEsp(d.Value, d.LinkedName ?? "",
                        dCls == EntityClass.Unknown
                            ? (itemLike ? EntityClass.Item : EntityClass.Player)
                            : dCls);
                    _log.Info($"[Inspector] {d.Value} -> ESP.");
                });

                ImGui.SameLine(0, 6);
                ImGui.BeginDisabled(!canTgt);
                ImGui.PushStyleColor(ImGuiCol.Button,
                    isTarget ? MenuRenderer.ColWarnDim : MenuRenderer.ColBg3);
                ImGui.PushStyleColor(ImGuiCol.Text,
                    isTarget ? MenuRenderer.ColWarn : MenuRenderer.ColAccent);
                if (ImGui.Button((isTarget ? "[*] TARGET" : "Set Target") + $"##dset{i}",
                                 new Vector2(btnW, 20)))
                {
                    _config.SetTargetItemId((int)d.Value, "Item Inspector");
                    _log.Success($"[Inspector] Target -> {d.Value} ({d.TypeTag})");
                }
                ImGui.PopStyleColor(2);
                ImGui.EndDisabled();

                ImGui.SameLine(0, 4);
                ImGui.BeginDisabled(!itemLike || string.IsNullOrEmpty(d.LinkedName));
                ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
                ImGui.PushStyleColor(ImGuiCol.Text, string.IsNullOrEmpty(d.LinkedName)
                    ? MenuRenderer.ColTextMuted : MenuRenderer.ColBlue);
                if (ImGui.Button($"Link##dlnk{i}", new Vector2(42, 20)) &&
                    !string.IsNullOrEmpty(d.LinkedName))
                {
                    string lbl = $"Schema:{d.Value}={d.LinkedName}";
                    _store.Save(lbl,
                        $"Auto-linked ID {d.Value} -> '{d.LinkedName}'",
                        BitConverter.GetBytes((uint)d.Value),
                        PacketDirection.ServerToClient);
                    _log.Success($"[Inspector] Schema: {d.Value} -> '{d.LinkedName}' -> Book.");
                }
                ImGui.PopStyleColor(2);
                ImGui.EndDisabled();

                ImGui.SameLine(0, 4);
                ImGui.BeginDisabled(!itemLike);
                ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                if (ImGui.Button($"Pin##dpin{i}", new Vector2(pinW - 4f, 20)))
                {
                    _pinnedItem = new DetectedItem
                    {
                        ItemId = (int)d.Value, StackCount = 1,
                        Confidence = d.Confidence, NameHint = GuessItemName((int)d.Value),
                    };
                    _log.Info($"[Inspector] Pinned {d.Value}.");
                }
                ImGui.PopStyleColor(2);
                ImGui.EndDisabled();
            }
        }
        clip.End();

        if (show.Count == 0)
        {
            ImGui.SetCursorPos(new Vector2(8, tableH * 0.4f));
            UiHelper.MutedLabel(_discPktCount == 0
                ? "No packets captured yet - start proxy and play."
                : "No Medium/High IDs - try Show Low or capture more traffic.");
        }

        ImGui.EndChild();
    }

    // ── Packet list ───────────────────────────────────────────────────────

    private void RenderPacketList(float w, float h, List<CapturedPacket> packets)
    {
        var display = _showAllPkts
            ? packets.Select((p, i) => ItemScanResult.FromPacket(p, i)).ToList()
            : _scanResults;

        const float RowH = 20f;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##ilist", new Vector2(w, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 6));
        UiHelper.MutedLabel($"  #    Dir     PktID   Fields / Guess                 Size");

        var dl = ImGui.GetWindowDrawList();
        float ly = ImGui.GetCursorScreenPos().Y - 2;
        dl.AddLine(new Vector2(ImGui.GetWindowPos().X, ly),
                   new Vector2(ImGui.GetWindowPos().X + w, ly),
                   ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        var clipper = new ImGuiListClipper();
        clipper.Begin(display.Count, RowH);
        while (clipper.Step())
        {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
            {
                var  r   = display[i];
                bool cs  = r.Packet.Direction == PacketDirection.ClientToServer;
                var  col = r.HasItemData
                    ? (cs ? MenuRenderer.ColBlue : MenuRenderer.ColAccent)
                    : MenuRenderer.ColTextMuted;

                string dir     = cs ? "C->S" : "S->C";
                string idStr   = r.Packet.RawBytes.Length > 0 ? $"0x{r.Packet.RawBytes[0]:X2}" : "0x??";
                string summary = r.HasItemData
                    ? $"ItemID={r.BestItem?.ItemId}x{r.BestItem?.StackCount} slot={r.BestItem?.SlotIndex}"
                    : r.Analysis.IdGuess;

                bool sel = _selectedIdx == i;
                if (sel)
                {
                    var sp2 = ImGui.GetCursorScreenPos();
                    dl.AddRectFilled(sp2, sp2 + new Vector2(w, RowH),
                        ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
                }

                ImGui.PushStyleColor(ImGuiCol.Text, col);
                if (ImGui.Selectable(
                    $"  {i+1,-5} {dir,-7} {idStr,-8} {summary,-35} {r.Packet.RawBytes.Length}b##ir{i}",
                    sel, ImGuiSelectableFlags.None, new Vector2(0, RowH)))
                    _selectedIdx = i;
                ImGui.PopStyleColor();
            }
        }
        clipper.End();

        ImGui.EndChild();
    }

    // ── Detail panel ──────────────────────────────────────────────────────

    private void RenderDetailPanel(float w, float h, List<CapturedPacket> packets)
    {
        var display = _showAllPkts
            ? packets.Select((p, i) => ItemScanResult.FromPacket(p, i)).ToList()
            : _scanResults;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##idet", new Vector2(w, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        if (_selectedIdx < 0 || _selectedIdx >= display.Count)
        {
            ImGui.SetCursorPosY(h * 0.4f);
            float tw = ImGui.CalcTextSize("<- select a packet").X;
            ImGui.SetCursorPosX((w - tw) * 0.5f);
            UiHelper.MutedLabel("<- select a packet");
            ImGui.EndChild();
            return;
        }

        var r   = display[_selectedIdx];
        var pkt = r.Packet;
        bool cs = pkt.Direction == PacketDirection.ClientToServer;

        ImGui.SetCursorPos(new Vector2(12, 10));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("PACKET DETAIL");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        UiHelper.StatusRow("Direction", cs ? "Client -> Server" : "Server -> Client", cs, 80);
        UiHelper.StatusRow("Size",      $"{pkt.RawBytes.Length} bytes", true, 80);
        UiHelper.StatusRow("Packet ID", pkt.RawBytes.Length > 0 ? $"0x{pkt.RawBytes[0]:X2}" : "??", true, 80);
        UiHelper.StatusRow("Guess",     r.Analysis.IdGuess, r.HasItemData, 80);

        var dlp = ImGui.GetWindowDrawList();
        var wpp = ImGui.GetWindowPos();
        ImGui.Spacing();
        dlp.AddLine(new Vector2(wpp.X + 12, ImGui.GetCursorScreenPos().Y),
                    new Vector2(wpp.X + w  - 12, ImGui.GetCursorScreenPos().Y),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
        ImGui.Spacing();

        // Item cards
        if (r.HasItemData)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
            ImGui.TextUnformatted("ITEM DATA DETECTED");
            ImGui.PopStyleColor();
            ImGui.Spacing();

            foreach (var item in r.Items)
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
                ImGui.BeginChild($"##icard{item.GetHashCode()}", new Vector2(-1, 72), ImGuiChildFlags.Border);
                ImGui.PopStyleColor();

                ImGui.SetCursorPos(new Vector2(8, 6));
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
                ImGui.TextUnformatted($"Item ID: {item.ItemId}");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 16);
                UiHelper.MutedLabel($"Stack: {item.StackCount}   Slot: {item.SlotIndex}");
                if (!string.IsNullOrEmpty(item.NameHint))
                { ImGui.SameLine(0, 10); UiHelper.MutedLabel($"({item.NameHint})"); }

                ImGui.SetCursorPosX(8);
                UiHelper.MutedLabel($"Confidence: {item.Confidence}   Offset: +{item.Offset}");

                ImGui.SetCursorPosX(8);
                UiHelper.PrimaryButton($"Pin##pin{item.GetHashCode()}", 70, 22, () =>
                {
                    _pinnedItem = item;
                    _log.Success($"[Inspector] Pinned {item.ItemId}x{item.StackCount}.");
                });
                ImGui.SameLine(0, 6);
                UiHelper.WarnButton($"Set Target##setT{item.GetHashCode()}", 90, 22, () =>
                {
                    _config.SetTargetItemId(item.ItemId, "Item Inspector");
                    _log.Success($"[Inspector] Target -> {item.ItemId}.");
                });
                ImGui.EndChild();
                ImGui.Spacing();
            }
        }
        else
        {
            UiHelper.MutedLabel("No item fields detected in this packet.");
        }

        ImGui.Spacing();
        dlp.AddLine(new Vector2(wpp.X + 12, ImGui.GetCursorScreenPos().Y),
                    new Vector2(wpp.X + w  - 12, ImGui.GetCursorScreenPos().Y),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
        ImGui.Spacing();

        // All parsed fields with clipper - no flicker even with many strings
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("ALL PARSED FIELDS");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        var fields = r.Analysis.Fields;
        var fClip = new ImGuiListClipper();
        fClip.Begin(fields.Count, 18f);
        while (fClip.Step())
        {
            for (int fi = fClip.DisplayStart; fi < fClip.DisplayEnd; fi++)
            {
                var f = fields[fi];
                var fCol = f.Type switch
                {
                    FieldType.Id     => MenuRenderer.ColWarn,
                    FieldType.Int32  => MenuRenderer.ColBlue,
                    FieldType.String => MenuRenderer.ColAccent,
                    FieldType.Float  => new Vector4(0.8f, 0.6f, 1f, 1f),
                    _                => MenuRenderer.ColTextMuted,
                };
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                ImGui.TextUnformatted($"  {f.Name,-28}");
                ImGui.PopStyleColor();
                ImGui.SameLine();
                ImGui.PushStyleColor(ImGuiCol.Text, fCol);
                ImGui.TextUnformatted(f.Value);
                ImGui.PopStyleColor();
            }
        }
        fClip.End();

        ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

        // Hex dump
        UiHelper.MutedLabel("Hex dump:");
        ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.7f, 1.0f, 0.7f, 1f));
        for (int row = 0; row < pkt.RawBytes.Length; row += 16)
        {
            int    len = Math.Min(16, pkt.RawBytes.Length - row);
            string hex = string.Join(" ", pkt.RawBytes.Skip(row).Take(len).Select(b => $"{b:X2}"));
            string asc = new string(pkt.RawBytes.Skip(row).Take(len)
                .Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
            ImGui.Text($"  {row:X4}  {hex,-47}  {asc}");
        }
        ImGui.PopStyleColor();

        ImGui.Spacing();
        UiHelper.SecondaryButton("Copy Hex##cph", -1, 26, () =>
        {
            ImGui.SetClipboardText(pkt.HexString);
            _log.Info("[Inspector] Hex copied.");
        });
        ImGui.Spacing();

        ImGui.SetNextItemWidth(-1);
        ImGui.InputText("Label##isl", ref _saveLabel, 64);
        ImGui.SetNextItemWidth(-1);
        ImGui.InputText("Notes##isn", ref _saveNotes, 128);
        UiHelper.PrimaryButton("Save to Packet Book##ispb", -1, 26, () =>
        {
            if (string.IsNullOrWhiteSpace(_saveLabel))
            { _log.Error("[Inspector] Enter a label first."); return; }
            _store.Save(_saveLabel, _saveNotes, pkt.RawBytes, pkt.Direction);
            _log.Success($"[Inspector] Saved as '{_saveLabel}'.");
            _saveLabel = ""; _saveNotes = "";
        });

        ImGui.EndChild();
    }

    // ── Status bar ────────────────────────────────────────────────────────

    private void RenderStatusBar(float w)
    {
        bool proxy = _udpProxy.IsRunning || _capture.IsRunning;
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##instsb", new Vector2(w, 52), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, proxy ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(proxy ? "[>] Proxy active" : "[>] No proxy - start Capture tab first");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 24);
        UiHelper.MutedLabel($"{_lastPktCount} pkts  |  {_scanResults.Count} item  |  {_discovered.Count} IDs  |  " +
                            $"{_smart.ConfirmedItems.Count} confirmed  |  " +
                            $"{_smart.ActiveEntities.Count} entities  |  SmartDetect [>]");

        // ── Keyword filter row ────────────────────────────────────────────
        ImGui.SetCursorPos(new Vector2(12, 30));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("Filter:");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 6);
        ImGui.SetNextItemWidth(-100);  // stretch, leaving room for Case/Clear buttons
        if (ImGui.InputText("##kwfilter", ref _keywordFilter, 64))
            _filterDirty = true;
        ImGui.SameLine(0, 8);
        ImGui.Checkbox("Case##kwcs", ref _keywordCaseSens);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Case-sensitive keyword matching");
        ImGui.SameLine(0, 8);
        if (ImGui.SmallButton("Clear##kwclr")) { _keywordFilter = ""; _filterDirty = true; }
        ImGui.SameLine(0, 16);
        if (!string.IsNullOrEmpty(_keywordFilter))
        {
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.95f, 0.85f, 0.10f, 1f)); // bold yellow
            ImGui.TextUnformatted($"  [*] Filtering for '{_keywordFilter}'");
            ImGui.PopStyleColor();
        }
        ImGui.EndChild();
    }

    // ── Tooltip: hex preview + associated strings ─────────────────────────

    private void RenderIdTooltip(uint id)
    {
        ImGui.BeginTooltip();
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted($"ID: {id}  (0x{id:X8})");
        ImGui.PopStyleColor();

        // Name from IdNameMap
        if (_smart.IdNameMap.TryGetValue(id, out var name))
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
            ImGui.TextUnformatted($"  Name: {name}");
            ImGui.PopStyleColor();
        }

        // Classification
        if (_smart.EntityClassifications.TryGetValue(id, out var cls))
        {
            string clsLabel = cls switch
            {
                EntityClass.Player => "PLAYER",
                EntityClass.Mob    => "MOB",
                EntityClass.Item   => "ITEM",
                _                  => "Unknown",
            };
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
            ImGui.TextUnformatted($"  Class: {clsLabel}");
            ImGui.PopStyleColor();
        }

        // Entity position if tracked
        if (_smart.ActiveEntities.TryGetValue(id, out var ent))
        {
            UiHelper.MutedLabel($"  Pos: ({ent.X:F1}, {ent.Y:F1}, {ent.Z:F1})");
            UiHelper.MutedLabel($"  Updates: {ent.UpdateCount}  Δmax: {ent.MaxDelta:F2}m");
        }

        // Hex preview: find last packet containing this ID (limit search to recent 200 packets)
        var pkts = _capture.GetPackets();
        int searchFrom = Math.Max(0, pkts.Count - 200);
        for (int pi = pkts.Count - 1; pi >= searchFrom; pi--)
        {
            var data = pkts[pi].RawBytes;
            for (int bi = 1; bi + 4 <= data.Length; bi++)
            {
                if (BitConverter.ToUInt32(data, bi) != id) continue;
                ImGui.Separator();
                UiHelper.MutedLabel("  Hex preview (last packet):");
                int previewStart = Math.Max(0, bi - 4);
                int previewLen   = Math.Min(24, data.Length - previewStart);
                string hex = string.Join(" ",
                    data.Skip(previewStart).Take(previewLen).Select(b => $"{b:X2}"));
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColText);
                ImGui.TextUnformatted($"  {hex}");
                ImGui.PopStyleColor();
                goto doneHex;
            }
        }
        doneHex:
        ImGui.EndTooltip();
    }

    // ── Push an ID to the ESP overlay ─────────────────────────────────────

    private static void PushIdToEsp(uint id, string nameHint, EntityClass cls)
    {
        string label = $"[{cls.ToString()[0]}] {(string.IsNullOrEmpty(nameHint) ? id.ToString() : nameHint)}";
        var color = cls switch
        {
            EntityClass.Player => new System.Numerics.Vector4(0.18f, 0.95f, 0.45f, 0.9f),
            EntityClass.Mob    => new System.Numerics.Vector4(0.95f, 0.28f, 0.22f, 0.9f),
            EntityClass.Item   => new System.Numerics.Vector4(0.95f, 0.75f, 0.10f, 0.9f),
            _                  => new System.Numerics.Vector4(0.28f, 0.72f, 1.00f, 0.9f),
        };

        lock (Application.EntityPositions)
        {
            var existing = Application.EntityPositions.FirstOrDefault(e => e.Label == label);
            if (existing == null)
                Application.EntityPositions.Add(new EntityOverlayEntry
                {
                    Position = System.Numerics.Vector3.Zero,
                    Label    = label,
                    Color    = color,
                });
        }
    }

    // ── Confidence time-window boost ──────────────────────────────────────

    private void BoostConfidenceByTimeWindow(List<CapturedPacket> packets)
    {
        var now    = DateTime.Now;
        var cutoff = now - TimeSpan.FromSeconds(30);
        var win5   = TimeSpan.FromSeconds(5);

        foreach (var pkt in packets)
        {
            if (pkt.Timestamp < cutoff) continue;
            for (int i = 1; i + 4 <= pkt.RawBytes.Length; i++)
            {
                uint v = BitConverter.ToUInt32(pkt.RawBytes, i);
                if (v < 100 || v > 9999) continue;
                if (!_idSeenTimes.TryGetValue(v, out var times))
                    _idSeenTimes[v] = times = new List<DateTime>();
                if (times.Count == 0 || (pkt.Timestamp - times[^1]).TotalMilliseconds > 50)
                    times.Add(pkt.Timestamp);
            }
        }

        foreach (var disc in _discovered)
        {
            if (!_idSeenTimes.TryGetValue((ulong)disc.Value, out var times)) continue;
            times.RemoveAll(t => now - t > win5);
            if (times.Count >= 2) disc.BoostedToHigh = true;
        }
    }

    // ── Scanning ──────────────────────────────────────────────────────────

    private static List<ItemScanResult> ScanPackets(List<CapturedPacket> packets)
    {
        var results = new List<ItemScanResult>();
        for (int i = 0; i < packets.Count; i++)
        {
            var r = ItemScanResult.FromPacket(packets[i], i);
            if (r.HasItemData) results.Add(r);
        }
        return results;
    }

    private static string GuessItemName(int id) => ItemScanResult.GuessItemNamePublic(id);
}

// ── Supporting types ──────────────────────────────────────────────────────────

public class ItemScanResult
{
    public CapturedPacket     Packet   { get; private set; } = null!;
    public int                Index    { get; private set; }
    public AnalysisResult     Analysis { get; private set; } = null!;
    public List<DetectedItem> Items    { get; private set; } = new();
    public bool               HasItemData => Items.Count > 0;
    public DetectedItem?      BestItem    => Items.FirstOrDefault();

    public static ItemScanResult FromPacket(CapturedPacket pkt, int idx)
    {
        var r = new ItemScanResult { Packet = pkt, Index = idx };
        r.Analysis = PacketAnalyser.Analyse(pkt);
        r.Items    = ExtractItems(pkt.RawBytes, r.Analysis);
        return r;
    }

    private static List<DetectedItem> ExtractItems(byte[] data, AnalysisResult analysis)
    {
        var items = new List<DetectedItem>();

        for (int i = 1; i + 4 <= data.Length; i++)
        {
            int v = BitConverter.ToInt32(data, i);
            if (v < 100 || v > 9999) continue;

            int count = 1;
            if (i + 4 < data.Length)
            {
                byte nb = data[i + 4];
                if (nb >= 1 && nb <= 255) count = nb;
            }

            int slot = 0;
            if (i >= 1)
            {
                byte pb = data[i - 1];
                if (pb <= 64) slot = pb;
            }

            var conf = i <= 5 ? FieldConfidence.High
                     : i <= 9 ? FieldConfidence.Medium
                               : FieldConfidence.Low;

            if (items.Any(x => x.ItemId == v)) continue;

            items.Add(new DetectedItem
            {
                ItemId = v, StackCount = count, SlotIndex = slot,
                Offset = i, Confidence = conf, NameHint = GuessItemNamePublic(v),
            });
        }

        foreach (var guess in analysis.Guesses)
        {
            if (guess.Name.Contains("Item") && guess.IntValue >= 100
                && !items.Any(x => x.ItemId == guess.IntValue))
            {
                items.Add(new DetectedItem
                {
                    ItemId = guess.IntValue, StackCount = 1, SlotIndex = 0,
                    Offset = guess.Offset, Confidence = guess.Confidence,
                    NameHint = GuessItemNamePublic(guess.IntValue),
                });
            }
        }

        return items;
    }

    public static string GuessItemNamePublic(int id) => id switch
    {
        1    => "Stone",        2   => "Grass Block",
        264  => "Diamond",      265 => "Iron Ingot",
        266  => "Gold Ingot",   267 => "Iron Sword",
        276  => "Diamond Sword",278 => "Diamond Pickaxe",
        282  => "Mushroom Stew",297 => "Bread",
        1001 => "Item 1001",   1002 => "Item 1002",
        _    => ""
    };
}

public class DetectedItem
{
    public int             ItemId     { get; set; }
    public int             StackCount { get; set; } = 1;
    public int             SlotIndex  { get; set; }
    public int             Offset     { get; set; }
    public FieldConfidence Confidence { get; set; }
    public string          NameHint   { get; set; } = "";
}
