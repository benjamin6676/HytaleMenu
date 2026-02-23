using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Item Inspector — two complementary views of the same captured traffic:
///
///   DISCOVERED IDs (top panel)
///     Automated Schema Discovery via PacketAnalyser.AggregateAcrossPackets().
///     Every uint32 candidate is scored and ranked. Click "Set Target" on any
///     Item ID row to push it into ServerConfig.TargetItemId — which the Dupe
///     Methods tab reads automatically, completing the capture→test workflow.
///
///   PACKET LIST + DETAIL (bottom panels)
///     Traditional per-packet view: packets that contain item-like fields are
///     highlighted. Select one to see the full hex dump, parsed fields, and
///     confidence-ranked item cards with individual Pin / Set Target buttons.
///
/// Workflow:
///   1. Start UDP proxy in Capture tab
///   2. Hold, pick up, or swap items in-game
///   3. Click "Scan Now" (or let auto-scan run)
///   4. Find your item ID in Discovered IDs — click "Set Target"
///   5. Switch to Dupe Methods — the item ID is already filled in
/// </summary>
public class ItemInspectorTab : ITab
{
    public string Title => "  Item Inspector  ";

    private readonly TestLog       _log;
    private readonly PacketCapture _capture;
    private readonly UdpProxy      _udpProxy;
    private readonly PacketStore   _store;
    private readonly ServerConfig  _config;

    // ── UI state ──────────────────────────────────────────────────────────
    private int    _selectedIdx = -1;
    private bool   _autoScan   = true;
    private string _saveLabel  = "";
    private string _saveNotes  = "";
    private bool   _showAllPkts = false;

    // Pinned item
    private DetectedItem? _pinnedItem;

    // Item-packet scan cache (throttled)
    private List<ItemScanResult> _scanResults  = new();
    private int                  _lastPktCount = 0;
    private DateTime             _lastScanTime = DateTime.MinValue;
    private const double         ScanMs        = 800;

    // Schema discovery cache (slightly longer throttle — heavier scan)
    private List<DiscoveredId> _discovered      = new();
    private int                _discPktCount    = 0;
    private DateTime           _discScanTime    = DateTime.MinValue;
    private const double       DiscMs           = 1200;
    private bool               _discShowAll     = false;
    private int                _discSelected    = -1;

    public DetectedItem? PinnedItem => _pinnedItem;

    public ItemInspectorTab(TestLog log, PacketCapture capture,
                             UdpProxy udpProxy, PacketStore store,
                             ServerConfig config)
    {
        _log = log; _capture = capture; _udpProxy = udpProxy;
        _store = store; _config = config;
    }

    // ── Render ────────────────────────────────────────────────────────────

    public void Render()
    {
        float w    = ImGui.GetContentRegionAvail().X;
        float half = (w - 12) * 0.5f;

        RenderStatusBar(w);
        ImGui.Spacing(); ImGui.Spacing();

        // Throttled auto-scan for both caches
        var packets = _capture.GetPackets();

        if (_autoScan && packets.Count != _lastPktCount &&
            (DateTime.Now - _lastScanTime).TotalMilliseconds > ScanMs)
        {
            _scanResults  = ScanPackets(packets);
            _lastPktCount = packets.Count;
            _lastScanTime = DateTime.Now;
        }

        if (_autoScan && packets.Count != _discPktCount &&
            (DateTime.Now - _discScanTime).TotalMilliseconds > DiscMs)
        {
            _discovered   = PacketAnalyser.AggregateAcrossPackets(packets);
            _discPktCount = packets.Count;
            _discScanTime = DateTime.Now;
        }

        // ── Top control row ───────────────────────────────────────────────
        UiHelper.SectionBox("SCAN CONTROLS", half, 90, () =>
        {
            ImGui.Checkbox("Auto-scan##asc", ref _autoScan);
            ImGui.Spacing();
            UiHelper.PrimaryButton("Scan Now", 110, 26, () =>
            {
                var all = _capture.GetPackets();
                _scanResults  = ScanPackets(all);
                _discovered   = PacketAnalyser.AggregateAcrossPackets(all);
                _lastPktCount = _discPktCount = all.Count;
                _lastScanTime = _discScanTime = DateTime.Now;
                _log.Info($"[Inspector] {all.Count} packets → {_scanResults.Count} item-related," +
                          $" {_discovered.Count} IDs discovered.");
            });
            ImGui.SameLine(0, 8);
            ImGui.Checkbox("Show all packets##sap", ref _showAllPkts);
        });

        ImGui.SameLine(0, 12);

        UiHelper.SectionBox("PINNED ITEM", half, 90, () =>
        {
            if (_pinnedItem == null)
            {
                UiHelper.MutedLabel("No item pinned.");
                UiHelper.MutedLabel("Select a result below → Pin.");
            }
            else
            {
                UiHelper.AccentText($"Item ID: {_pinnedItem.ItemId}");
                ImGui.SameLine(0, 12);
                UiHelper.MutedLabel($"×{_pinnedItem.StackCount}  slot {_pinnedItem.SlotIndex}");
                if (!string.IsNullOrEmpty(_pinnedItem.NameHint))
                { ImGui.SameLine(0, 12); UiHelper.MutedLabel(_pinnedItem.NameHint); }
                ImGui.Spacing();
                UiHelper.DangerButton("Clear##clrpin", 60, 22, () => _pinnedItem = null);
                ImGui.SameLine(0, 8);
                UiHelper.WarnButton("Set Target→Dupe##todupe", 140, 22, () =>
                {
                    _config.SetTargetItemId(_pinnedItem.ItemId, "Item Inspector (pin)");
                    _log.Success($"[Inspector] Target → {_pinnedItem.ItemId} pushed to Dupe tab.");
                });
            }
        });

        ImGui.Spacing(); ImGui.Spacing();

        // ── Layout: Discovered IDs section, then packet list+detail ──────
        float availH = ImGui.GetContentRegionAvail().Y;
        float discH  = 220f;
        float listH  = availH - discH - 12f;
        float listW  = w * 0.55f;
        float detW   = w - listW - 8f;

        RenderDiscoveredIds(w, discH);
        ImGui.Spacing();
        RenderPacketList(listW, listH, packets);
        ImGui.SameLine(0, 8);
        RenderDetailPanel(detW, listH, packets);
    }

    // ── Discovered IDs ────────────────────────────────────────────────────

    private void RenderDiscoveredIds(float w, float h)
    {
        // ── Header bar ────────────────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##dischdr", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("DISCOVERED IDs  —  Automated Schema Discovery");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 20);
        UiHelper.MutedLabel($"{_discovered.Count} candidates  ·  {_discPktCount} packets scanned");
        ImGui.SameLine(0, 14);
        ImGui.Checkbox("Show Low##discall", ref _discShowAll);
        if (_config.HasTargetItem)
        {
            ImGui.SameLine(0, 20);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
            ImGui.TextUnformatted($"★ Target: {_config.TargetItemId}  [{_config.TargetItemSource}]  → Dupe tab live");
            ImGui.PopStyleColor();
        }
        ImGui.EndChild();

        // ── Table ─────────────────────────────────────────────────────────
        var show = _discShowAll
            ? _discovered
            : _discovered.Where(d => d.Confidence >= FieldConfidence.Medium).ToList();

        float tableH = h - 34f;
        float btnW   = 116f;
        float pinW   = 70f;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##disctbl", new Vector2(w, tableH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        // Column headers
        ImGui.SetCursorPos(new Vector2(8, 4));
        UiHelper.MutedLabel($"  {"Value",-12} {"Type",-20} {"Conf",-6} {"Seen",-6} {"Score",-7}  Action");

        var dlh = ImGui.GetWindowDrawList();
        float hly = ImGui.GetCursorScreenPos().Y - 2;
        dlh.AddLine(new Vector2(ImGui.GetWindowPos().X, hly),
                    new Vector2(ImGui.GetWindowPos().X + w, hly),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        var dl = ImGui.GetWindowDrawList();

        for (int i = 0; i < show.Count; i++)
        {
            var  d        = show[i];
            bool sel      = _discSelected == i;
            bool isTarget = _config.HasTargetItem && _config.TargetItemId == (int)d.Value;
            bool itemLike = d.TypeTag == "Item ID";
            bool canTarget = itemLike || d.TypeTag == "Entity/Player ID";

            // Row highlight
            if (sel || isTarget)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(w, 22),
                    ImGui.ColorConvertFloat4ToU32(isTarget
                        ? MenuRenderer.ColWarnDim : MenuRenderer.ColAccentDim));
            }

            // Row text color
            var rowCol = d.Confidence == FieldConfidence.High   ? MenuRenderer.ColAccent
                       : d.Confidence == FieldConfidence.Medium ? MenuRenderer.ColBlue
                       :                                          MenuRenderer.ColTextMuted;

            // Selectable row (leaves room for buttons on the right)
            ImGui.PushStyleColor(ImGuiCol.Text, rowCol);
            if (ImGui.Selectable(
                $"  {d.Value,-12} {d.TypeTag,-20} {d.ConfidenceLabel,-6} ×{d.OccurrenceCount,-5} {d.Score,-7}##dsel{i}",
                sel, ImGuiSelectableFlags.None, new Vector2(w - btnW - pinW - 28f, 22)))
                _discSelected = i;
            ImGui.PopStyleColor();

            // "Set Target" button
            ImGui.SameLine(0, 6);
            ImGui.BeginDisabled(!canTarget);
            ImGui.PushStyleColor(ImGuiCol.Button,
                isTarget ? MenuRenderer.ColWarnDim : MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text,
                isTarget ? MenuRenderer.ColWarn : MenuRenderer.ColAccent);
            if (ImGui.Button(
                (isTarget ? "★ TARGET" : "Set Target") + $"##dset{i}",
                new Vector2(btnW, 20)))
            {
                _config.SetTargetItemId((int)d.Value, "Item Inspector");
                _log.Success($"[Inspector] Target → {d.Value} ({d.TypeTag}, ×{d.OccurrenceCount}) " +
                             $"— Dupe tab updated.");
            }
            ImGui.PopStyleColor(2);
            ImGui.EndDisabled();

            // "Pin" button (item IDs only)
            ImGui.SameLine(0, 4);
            ImGui.BeginDisabled(!itemLike);
            ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            if (ImGui.Button($"Pin##dpin{i}", new Vector2(pinW - 4f, 20)))
            {
                _pinnedItem = new DetectedItem
                {
                    ItemId     = (int)d.Value,
                    StackCount = 1,
                    SlotIndex  = 0,
                    Confidence = d.Confidence,
                    NameHint   = GuessItemName((int)d.Value),
                };
                _log.Info($"[Inspector] Pinned discovered item {d.Value}.");
            }
            ImGui.PopStyleColor(2);
            ImGui.EndDisabled();
        }

        if (show.Count == 0)
        {
            float cx = w * 0.5f - 140f;
            float cy = tableH * 0.4f;
            ImGui.SetCursorPos(new Vector2(MathF.Max(8, cx), MathF.Max(8, cy)));
            UiHelper.MutedLabel(_discPktCount == 0
                ? "No packets captured yet — start the proxy and play."
                : "No Medium/High confidence IDs yet — try toggling Show Low, or capture more traffic.");
        }

        ImGui.EndChild();
    }

    // ── Packet list ───────────────────────────────────────────────────────

    private void RenderPacketList(float w, float h, List<CapturedPacket> packets)
    {
        var display = _showAllPkts
            ? packets.Select((p, i) => ItemScanResult.FromPacket(p, i)).ToList()
            : _scanResults;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##ilist", new Vector2(w, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 6));
        UiHelper.MutedLabel($"  #    Dir     PktID   Fields detected                Size");

        var dl = ImGui.GetWindowDrawList();
        float ly = ImGui.GetCursorScreenPos().Y - 2;
        dl.AddLine(new Vector2(ImGui.GetWindowPos().X, ly),
                   new Vector2(ImGui.GetWindowPos().X + w, ly),
                   ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        for (int i = 0; i < display.Count; i++)
        {
            var  r   = display[i];
            bool cs  = r.Packet.Direction == PacketDirection.ClientToServer;
            var  col = r.HasItemData
                ? (cs ? MenuRenderer.ColBlue : MenuRenderer.ColAccent)
                : MenuRenderer.ColTextMuted;

            string dir     = cs ? "C\u2192S" : "S\u2192C";
            string idStr   = r.Packet.RawBytes.Length > 0 ? $"0x{r.Packet.RawBytes[0]:X2}" : "0x??";
            string summary = r.HasItemData
                ? $"ItemID={r.BestItem?.ItemId}  ×{r.BestItem?.StackCount}  slot={r.BestItem?.SlotIndex}"
                : r.Analysis.IdGuess;

            bool sel = _selectedIdx == i;
            if (sel)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(w, 20),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }

            ImGui.PushStyleColor(ImGuiCol.Text, col);
            if (ImGui.Selectable(
                $"  {i+1,-5} {dir,-7} {idStr,-8} {summary,-35} {r.Packet.RawBytes.Length}b##ir{i}",
                sel, ImGuiSelectableFlags.None, new Vector2(0, 20)))
                _selectedIdx = i;
            ImGui.PopStyleColor();
        }

        ImGui.EndChild();
    }

    // ── Detail panel ─────────────────────────────────────────────────────

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
            float tw = ImGui.CalcTextSize("← select a packet").X;
            ImGui.SetCursorPosX((w - tw) * 0.5f);
            UiHelper.MutedLabel("← select a packet");
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

        UiHelper.StatusRow("Direction", cs ? "Client → Server" : "Server → Client", cs, 80);
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

        // ── Detected item cards ───────────────────────────────────────────
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
                    _log.Success($"[Inspector] Pinned {item.ItemId}×{item.StackCount}.");
                });
                ImGui.SameLine(0, 6);
                UiHelper.WarnButton($"Set Target##setT{item.GetHashCode()}", 90, 22, () =>
                {
                    _config.SetTargetItemId(item.ItemId, "Item Inspector");
                    _log.Success($"[Inspector] Target → {item.ItemId} pushed to Dupe tab.");
                });

                ImGui.EndChild();
                ImGui.Spacing();
            }
        }
        else
        {
            UiHelper.MutedLabel("No item fields detected in this packet.");
            UiHelper.MutedLabel("Try packets with ID 0x04–0x0F or 0x20–0x25.");
        }

        ImGui.Spacing();
        dlp.AddLine(new Vector2(wpp.X + 12, ImGui.GetCursorScreenPos().Y),
                    new Vector2(wpp.X + w  - 12, ImGui.GetCursorScreenPos().Y),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
        ImGui.Spacing();

        // ── All parsed fields ─────────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("ALL PARSED FIELDS");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        foreach (var f in r.Analysis.Fields)
        {
            var col = f.Type switch
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
            ImGui.PushStyleColor(ImGuiCol.Text, col);
            ImGui.TextUnformatted(f.Value);
            ImGui.PopStyleColor();
        }

        ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

        // ── Hex dump ──────────────────────────────────────────────────────
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

        // ── Actions ───────────────────────────────────────────────────────
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
        ImGui.BeginChild("##instsb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, proxy ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(proxy ? "● Proxy active — live scan" : "● No proxy — start Capture tab first");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 24);
        int total = _capture.GetPackets().Count;
        UiHelper.MutedLabel($"{total} packets captured  |  {_scanResults.Count} item-related  |  {_discovered.Count} IDs discovered");
        ImGui.EndChild();
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

            // Deduplicate same item ID
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

    private static string GuessItemName(int id) => GuessItemNamePublic(id);

    public static string GuessItemNamePublic(int id) => id switch
    {
        1    => "Stone",       2   => "Grass Block",
        264  => "Diamond",     265 => "Iron Ingot",
        266  => "Gold Ingot",  267 => "Iron Sword",
        276  => "Diamond Sword", 278 => "Diamond Pickaxe",
        282  => "Mushroom Stew", 297 => "Bread",
        1001 => "Item 1001",  1002 => "Item 1002",
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
