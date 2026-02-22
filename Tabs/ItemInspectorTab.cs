using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Item Inspector tab.
///
/// Scans every captured packet and tries to identify held-item information:
/// item ID, stack count, slot index, durability, and any other parseable
/// fields.  Also lets you pin a "current item" and send it to the Dupe or
/// Privilege tabs automatically.
///
/// Workflow:
///   1. Start UDP proxy in Capture tab
///   2. Hold or pick up an item in-game
///   3. Come here — the inspector will highlight packets that look like
///      inventory/item updates and extract the suspected field values
///   4. Confirm by comparing the extracted ID with what you're holding
///   5. Pin the packet and push it to other tabs for testing
/// </summary>
public class ItemInspectorTab : ITab
{
    public string Title => "  Item Inspector  ";

    private readonly TestLog       _log;
    private readonly PacketCapture _capture;
    private readonly UdpProxy      _udpProxy;
    private readonly PacketStore   _store;
    private readonly ServerConfig  _config;

    // UI state
    private int    _selectedIdx   = -1;
    private bool   _autoScan      = true;
    private string _saveLabel     = "";
    private string _saveNotes     = "";
    private bool   _showAllPkts   = false;

    // Pinned item
    private DetectedItem? _pinnedItem;

    // Scan cache
    private List<ItemScanResult> _scanResults = new();
    private int                  _lastPktCount = 0;

    public DetectedItem? PinnedItem => _pinnedItem;

    public ItemInspectorTab(TestLog log, PacketCapture capture,
                             UdpProxy udpProxy, PacketStore store,
                             ServerConfig config)
    {
        _log = log; _capture = capture; _udpProxy = udpProxy;
        _store = store; _config = config;
    }

    public void Render()
    {
        float w    = ImGui.GetContentRegionAvail().X;
        float half = (w - 12) * 0.5f;

        RenderStatusBar(w);
        ImGui.Spacing(); ImGui.Spacing();

        // Auto-rescan when new packets arrive
        var packets = _capture.GetPackets();
        if (_autoScan && packets.Count != _lastPktCount)
        {
            _scanResults  = ScanPackets(packets);
            _lastPktCount = packets.Count;
        }

        UiHelper.SectionBox("SCAN CONTROLS", half, 90, () =>
        {
            ImGui.Checkbox("Auto-scan new packets##asc", ref _autoScan);
            ImGui.Spacing();
            UiHelper.PrimaryButton("Scan Now", 110, 26, () =>
            {
                _scanResults  = ScanPackets(_capture.GetPackets());
                _lastPktCount = packets.Count;
                _log.Info($"[Inspector] Scanned {packets.Count} packets → {_scanResults.Count} item-related found.");
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
                UiHelper.WarnButton("→ Dupe Tab##todupe", 100, 22, () =>
                    _log.Info($"[Inspector] Pinned item {_pinnedItem.ItemId} — " +
                              "paste this ID into Dupe Methods tab."));
            }
        });

        ImGui.Spacing(); ImGui.Spacing();

        // Results list + detail panel
        float listH = ImGui.GetContentRegionAvail().Y;
        float listW = w * 0.55f;
        float detW  = w - listW - 8;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##ilist", new Vector2(listW, listH), ImGuiChildFlags.Borders);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 6));
        UiHelper.MutedLabel($"  #    Dir     ID      Fields detected                Size");

        var dl  = ImGui.GetWindowDrawList();
        var lp  = ImGui.GetWindowPos();
        float ly = ImGui.GetCursorScreenPos().Y - 2;
        dl.AddLine(new Vector2(lp.X, ly), new Vector2(lp.X + listW, ly),
            ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        var display = _showAllPkts
            ? _capture.GetPackets().Select((p, i) => (i, ItemScanResult.FromPacket(p, i)))
                      .Select(t => t.Item2).ToList()
            : _scanResults;

        for (int i = 0; i < display.Count; i++)
        {
            var r   = display[i];
            bool cs = r.Packet.Direction == PacketDirection.ClientToServer;
            var col = r.HasItemData
                ? (cs ? MenuRenderer.ColBlue : MenuRenderer.ColAccent)
                : MenuRenderer.ColTextMuted;

            string dir     = cs ? "C→S" : "S→C";
            string idStr   = r.Packet.RawBytes.Length > 0 ? $"0x{r.Packet.RawBytes[0]:X2}" : "0x??"; 
            string summary = r.HasItemData
                ? $"ItemID={r.BestItem?.ItemId}  stack={r.BestItem?.StackCount}  slot={r.BestItem?.SlotIndex}"
                : r.Analysis.IdGuess;

            if (_selectedIdx == i)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(listW, 20),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }

            ImGui.PushStyleColor(ImGuiCol.Text, col);
            if (ImGui.Selectable(
                $"  {i+1,-5} {dir,-7} {idStr,-8} {summary,-35} {r.Packet.RawBytes.Length}b##ir{i}",
                _selectedIdx == i, ImGuiSelectableFlags.None, new Vector2(0, 20)))
                _selectedIdx = i;
            ImGui.PopStyleColor();
        }

        ImGui.EndChild();
        ImGui.SameLine(0, 8);

        // Detail panel
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##idet", new Vector2(detW, listH), ImGuiChildFlags.Borders);
        ImGui.PopStyleColor();

        if (_selectedIdx >= 0 && _selectedIdx < display.Count)
        {
            var r = display[_selectedIdx];
            RenderDetailPanel(r, detW);
        }
        else
        {
            ImGui.SetCursorPosY(listH * 0.4f);
            float tw = ImGui.CalcTextSize("← select a packet").X;
            ImGui.SetCursorPosX((detW - tw) * 0.5f);
            UiHelper.MutedLabel("← select a packet");
        }

        ImGui.EndChild();
    }

    private void RenderDetailPanel(ItemScanResult r, float w)
    {
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

        ImGui.Spacing();
        var dl = ImGui.GetWindowDrawList();
        var wp = ImGui.GetWindowPos();
        dl.AddLine(new Vector2(wp.X + 12, ImGui.GetCursorScreenPos().Y),
                   new Vector2(wp.X + w  - 12, ImGui.GetCursorScreenPos().Y),
                   ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
        ImGui.Spacing();

        // ── Detected items ────────────────────────────────────────────────
        if (r.HasItemData)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
            ImGui.TextUnformatted("ITEM DATA DETECTED");
            ImGui.PopStyleColor();
            ImGui.Spacing();

            foreach (var item in r.Items)
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
                ImGui.BeginChild($"##icard{item.GetHashCode()}", new Vector2(-1, 70),
                    ImGuiChildFlags.Borders);
                ImGui.PopStyleColor();

                ImGui.SetCursorPos(new Vector2(8, 6));
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
                ImGui.TextUnformatted($"Item ID: {item.ItemId}");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 16);
                UiHelper.MutedLabel($"Stack: {item.StackCount}   Slot: {item.SlotIndex}");
                if (!string.IsNullOrEmpty(item.NameHint))
                { ImGui.SameLine(0, 12); UiHelper.MutedLabel($"({item.NameHint})"); }
                ImGui.SetCursorPosX(8);
                UiHelper.MutedLabel($"Confidence: {item.Confidence}   Byte offset: {item.Offset}");
                ImGui.SetCursorPosX(8);
                UiHelper.PrimaryButton($"Pin this item##pin{item.GetHashCode()}", 120, 22,
                    () =>
                    {
                        _pinnedItem = item;
                        _log.Success($"[Inspector] Pinned item {item.ItemId}×{item.StackCount}.");
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
        dl.AddLine(new Vector2(wp.X + 12, ImGui.GetCursorScreenPos().Y),
                   new Vector2(wp.X + w  - 12, ImGui.GetCursorScreenPos().Y),
                   ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
        ImGui.Spacing();

        // ── All fields from analyser ──────────────────────────────────────
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

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        // ── Hex dump ──────────────────────────────────────────────────────
        UiHelper.MutedLabel("Hex dump:");
        ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.7f, 1.0f, 0.7f, 1f));
        for (int row = 0; row < pkt.RawBytes.Length; row += 16)
        {
            int    len  = Math.Min(16, pkt.RawBytes.Length - row);
            string hex  = string.Join(" ", pkt.RawBytes.Skip(row).Take(len).Select(b => $"{b:X2}"));
            string asc  = new string(pkt.RawBytes.Skip(row).Take(len)
                .Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
            ImGui.Text($"  {row:X4}  {hex,-47}  {asc}");
        }
        ImGui.PopStyleColor();

        ImGui.Spacing();

        // ── Actions ───────────────────────────────────────────────────────
        UiHelper.SecondaryButton("Copy Hex##cph", -1, 26, () =>
        {
            ImGui.SetClipboardText(pkt.HexString);
            _log.Info($"[Inspector] Packet hex copied.");
        });
        ImGui.Spacing();

        // Save to packet store
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
    }

    private void RenderStatusBar(float w)
    {
        bool proxy = _udpProxy.IsRunning || _capture.IsRunning;
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##instsb", new Vector2(w, 30), ImGuiChildFlags.Borders);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, proxy ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(proxy ? "● Proxy active — live scan" : "● No proxy — start Capture tab first");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 24);
        int total = _capture.GetPackets().Count;
        UiHelper.MutedLabel($"{total} packets captured  |  {_scanResults.Count} item-related");
        ImGui.EndChild();
    }

    // ── Packet scanning ───────────────────────────────────────────────────

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
}

// ── Supporting types ──────────────────────────────────────────────────────────

public class ItemScanResult
{
    public CapturedPacket  Packet    { get; private set; } = null!;
    public int             Index     { get; private set; }
    public AnalysisResult  Analysis  { get; private set; } = null!;
    public List<DetectedItem> Items  { get; private set; } = new();
    public bool            HasItemData => Items.Count > 0;
    public DetectedItem?   BestItem    => Items.FirstOrDefault();

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

        // Strategy: look for int32 values in item-ID range (100–9999)
        // followed by or preceded by a count value (1–999)
        for (int i = 1; i + 8 <= data.Length; i++)
        {
            int v1 = BitConverter.ToInt32(data, i);
            if (v1 < 100 || v1 > 9999) continue;

            // Check next int32 as count
            int count = 1;
            int slot  = 0;
            if (i + 8 <= data.Length)
            {
                int v2 = BitConverter.ToInt32(data, i + 4);
                if (v2 >= 1 && v2 <= 999) count = v2;
            }
            // Check for slot before the item ID
            if (i >= 5)
            {
                int vs = BitConverter.ToInt32(data, i - 4);
                if (vs >= 0 && vs <= 255) slot = vs;
            }

            // Confidence based on position
            var conf = i <= 5 ? FieldConfidence.High
                     : i <= 9 ? FieldConfidence.Medium
                               : FieldConfidence.Low;

            items.Add(new DetectedItem
            {
                ItemId     = v1,
                StackCount = count,
                SlotIndex  = slot,
                Offset     = i,
                Confidence = conf,
                NameHint   = GuessItemName(v1),
            });

            // Deduplicate — don't add the same ID twice
            if (items.Count(x => x.ItemId == v1) > 1)
                items.RemoveAll(x => x.ItemId == v1 && x.Offset != i);
        }

        // Also pick up from analyser guesses
        foreach (var guess in analysis.Guesses)
        {
            if (guess.Name.Contains("Item") && guess.IntValue >= 100)
            {
                if (!items.Any(x => x.ItemId == guess.IntValue))
                    items.Add(new DetectedItem
                    {
                        ItemId     = guess.IntValue,
                        StackCount = 1,
                        SlotIndex  = 0,
                        Offset     = guess.Offset,
                        Confidence = guess.Confidence,
                        NameHint   = GuessItemName(guess.IntValue),
                    });
            }
        }

        return items;
    }

    private static string GuessItemName(int id) => id switch
    {
        // Common Minecraft-like IDs for reference; update with real Hytale IDs
        // once you capture them
        1    => "Stone",
        2    => "Grass Block",
        264  => "Diamond",
        265  => "Iron Ingot",
        266  => "Gold Ingot",
        267  => "Iron Sword",
        276  => "Diamond Sword",
        278  => "Diamond Pickaxe",
        282  => "Mushroom Stew",
        297  => "Bread",
        1001 => "Item 1001",
        1002 => "Item 1002",
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
