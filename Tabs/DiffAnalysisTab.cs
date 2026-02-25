using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.IO;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Differential Analysis tab.
///
/// The most powerful way to reverse-engineer what each byte in a packet means.
///
/// Workflow:
///   1. Do the same action in-game multiple times, changing ONE thing each time
///      (e.g. drop item ID 100, then drop item ID 200, then 300)
///   2. Capture each packet via the Capture tab
///   3. Come here, paste each packet hex with a label
///   4. Click Analyse - the tool diffs all captures and highlights which bytes
///      changed and by how much
///   5. A 4-byte region that increased by 100 each time = that's the item ID field
///   6. Save your findings to the Packet Book for use in other tabs
/// </summary>
public class DiffAnalysisTab : ITab
{
    public string Title => "  Diff Analysis  ";

    private readonly TestLog     _log;
    private readonly PacketStore _store;
    private readonly PacketCapture _capture;

    // Capture slots - up to 8
    private readonly List<DiffSlot> _slots = new();
    private int _maxSlots = 8;

    // Results
    private MultiDiffResult? _multiResult;
    private DiffResult?      _pairResult;
    private int              _pairA = 0, _pairB = 1;
    private int              _viewMode = 0; // 0=field map, 1=pair diff, 2=byte grid

    // Selected field for detail
    private int _selectedField = -1;

    public DiffAnalysisTab(TestLog log, PacketStore store, PacketCapture capture)
    {
        _log = log; _store = store; _capture = capture;
        // Start with 3 empty slots
        _slots.Add(new DiffSlot { Label = "Capture A" });
        _slots.Add(new DiffSlot { Label = "Capture B" });
        _slots.Add(new DiffSlot { Label = "Capture C" });
    }

    // ── Public API - called from CaptureTab right-click menu ─────────────

    /// <summary>Sets slot 0 (Diff A) hex from an external packet.</summary>
    public void SetSlotA(string hexString)
    {
        if (_slots.Count > 0) { _slots[0].Hex = hexString; _multiResult = null; }
    }
    /// <summary>Sets slot 1 (Diff B) hex from an external packet.</summary>
    public void SetSlotB(string hexString)
    {
        while (_slots.Count < 2) _slots.Add(new DiffSlot { Label = $"Capture {(char)('A' + _slots.Count)}" });
        _slots[1].Hex = hexString; _multiResult = null;
    }

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;

        RenderInstructions(w);
        ImGui.Spacing();
        RenderCaptureSlots(w);
        ImGui.Spacing();
        RenderAnalyseBar(w);
        ImGui.Spacing();

        if (_multiResult != null)
        {
            RenderViewModeTabs();
            ImGui.Spacing();
            switch (_viewMode)
            {
                case 0: RenderFieldMap(w);  break;
                case 1: RenderPairDiff(w);  break;
                case 2: RenderByteGrid(w);  break;
            }
        }
    }

    // ── Instructions ──────────────────────────────────────────────────────

    private void RenderInstructions(float w)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##diffinfo", new Vector2(w, 44), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));
        UiHelper.AccentText("Workflow: ");
        ImGui.SameLine();
        UiHelper.MutedLabel("Do the same action in-game changing ONE value each time (e.g. drop item 100, then 200, then 300).");
        ImGui.SetCursorPos(new Vector2(12, 24));
        UiHelper.MutedLabel("Capture each result -> paste hex below -> click Analyse. Changed bytes = the field you varied.");
        ImGui.EndChild();
    }

    // ── Capture slots ──────────────────────────────────────────────────────

    private void RenderCaptureSlots(float w)
    {
        float slotW = (w - (_slots.Count - 1) * 8f) / Math.Min(_slots.Count, 4);

        for (int i = 0; i < _slots.Count; i++)
        {
            if (i > 0 && i % 4 == 0) ImGui.Spacing();
            if (i % 4 != 0) ImGui.SameLine(0, 8);

            var slot = _slots[i];
            bool hasData = !string.IsNullOrWhiteSpace(slot.Hex);
            var borderCol = hasData ? MenuRenderer.ColAccent : MenuRenderer.ColBorder;

            ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
            ImGui.BeginChild($"##slot{i}", new Vector2(slotW, 130), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();

            // Accent left border if populated
            if (hasData)
            {
                var dl = ImGui.GetWindowDrawList();
                var sp = ImGui.GetWindowPos();
                dl.AddRectFilled(sp, sp + new Vector2(3, 130),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccent));
            }

            ImGui.SetCursorPos(new Vector2(8, 6));
            ImGui.SetNextItemWidth(slotW - 50);
            // InputText requires a ref to a local string variable (can't pass property directly)
            string slotLabel = slot.Label;
            ImGui.InputText($"##slbl{i}", ref slotLabel, 32);
            slot.Label = slotLabel;
            ImGui.SameLine(0, 4);

            // Delete slot button (only if > 2 slots)
            if (_slots.Count > 2)
            {
                UiHelper.DangerButton($"x##sldel{i}", 24, 22, () =>
                { _slots.RemoveAt(i); _multiResult = null; });
            }

            ImGui.SetCursorPos(new Vector2(8, 32));
            UiHelper.MutedLabel("Hex:");
            ImGui.SetNextItemWidth(slotW - 16);
            ImGui.SetCursorPos(new Vector2(8, 46));
            string slotHex = slot.Hex;
            ImGui.InputText($"##shex{i}", ref slotHex, 1024);
            slot.Hex = slotHex;

            ImGui.SetCursorPos(new Vector2(8, 72));
            if (hasData)
            {
                byte[] bytes = TryParse(slot.Hex);
                UiHelper.AccentText($"{bytes.Length}b  ID:0x{(bytes.Length > 0 ? bytes[0].ToString("X2") : "??")}");
            }
            else UiHelper.MutedLabel("empty");

            ImGui.SetCursorPos(new Vector2(8, 94));
            // Load from capture list
            var pkts = _capture.GetPackets();
            if (pkts.Count > 0)
            {
                if (ImGui.BeginCombo($"From capture##sc{i}", ""))
                {
                    foreach (var (pkt, idx) in pkts.Select((p, idx) => (p, idx)).TakeLast(20))
                    {
                        bool cs = pkt.Direction == PacketDirection.ClientToServer;
                        string lbl = $"#{idx+1} {(cs?"C->S":"S->C")} 0x{(pkt.RawBytes.Length > 0 ? pkt.RawBytes[0].ToString("X2") : "??")} {pkt.RawBytes.Length}b";
                        if (ImGui.Selectable(lbl))
                        {
                            slot.Hex   = pkt.HexString;
                            slot.Label = $"Pkt#{idx+1}";
                        }
                    }
                    ImGui.EndCombo();
                }
            }

            // Load from book
            var saved = _store.GetAll();
            if (saved.Count > 0)
            {
                ImGui.SameLine(0, 4);
                if (ImGui.BeginCombo($"From book##sb{i}", ""))
                {
                    foreach (var s in saved)
                        if (ImGui.Selectable(s.Label))
                        { slot.Hex = s.HexString; slot.Label = s.Label; }
                    ImGui.EndCombo();
                }
            }

            ImGui.EndChild();
        }

        ImGui.Spacing();

        // Add slot button
        if (_slots.Count < _maxSlots)
        {
            UiHelper.SecondaryButton($"+ Add Slot##addslot", 110, 26, () =>
            {
                _slots.Add(new DiffSlot { Label = $"Capture {(char)('A' + _slots.Count)}" });
                _multiResult = null;
            });
        }
    }

    // ── Analyse bar ───────────────────────────────────────────────────────

    private void RenderAnalyseBar(float w)
    {
        int populated = _slots.Count(s => !string.IsNullOrWhiteSpace(s.Hex));
        bool canAnalyse = populated >= 2;

        ImGui.BeginDisabled(!canAnalyse);
        UiHelper.PrimaryButton($">  Analyse {populated} Packets##analyse", 200, 32, RunAnalysis);
        ImGui.EndDisabled();

        ImGui.SameLine(0, 16);
        UiHelper.MutedLabel(canAnalyse
            ? $"{populated} packets ready - click Analyse"
            : "Populate at least 2 slots to analyse.");

        ImGui.SameLine(0, 24);
        UiHelper.DangerButton("Clear All##clrall", 90, 32, () =>
        {
            foreach (var s in _slots) { s.Hex = ""; }
            _multiResult = null; _pairResult = null;
        });

        if (_multiResult != null)
        {
            ImGui.SameLine(0, 16);
            UiHelper.SecondaryButton("Export Field Map##expfm", 140, 32, ExportFieldMap);
        }
    }

    private void RunAnalysis()
    {
        var packets = _slots
            .Where(s => !string.IsNullOrWhiteSpace(s.Hex))
            .Select(s => new LabelledPacket { Label = s.Label, Data = TryParse(s.Hex) })
            .Where(p => p.Data.Length > 0)
            .ToList();

        if (packets.Count < 2) { _log.Error("[Diff] Need at least 2 valid packets."); return; }

        _multiResult = DiffEngine.MultiDiff(packets);
        _pairResult  = _multiResult.PairDiffs.FirstOrDefault();
        _log.Success($"[Diff] {_multiResult.Summary}");
    }

    // ── View mode tabs ────────────────────────────────────────────────────

    private void RenderViewModeTabs()
    {
        string[] modes = { "Field Map", "Pair Diff", "Byte Grid" };
        for (int i = 0; i < modes.Length; i++)
        {
            bool sel = _viewMode == i;
            ImGui.PushStyleColor(ImGuiCol.Button,
                sel ? new Vector4(0.18f, 0.95f, 0.45f, 0.22f) : MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text,
                sel ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
            if (ImGui.Button(modes[i] + $"##vm{i}", new Vector2(120, 26))) _viewMode = i;
            ImGui.PopStyleColor(2);
            if (i < modes.Length - 1) ImGui.SameLine(0, 4);
        }
        ImGui.SameLine(0, 24);
        UiHelper.MutedLabel(_multiResult?.Summary ?? "");
    }

    // ── Field Map view ────────────────────────────────────────────────────

    private void RenderFieldMap(float w)
    {
        if (_multiResult == null) return;

        float listW = w * 0.55f;
        float detW  = w - listW - 8;
        float h     = ImGui.GetContentRegionAvail().Y;

        // Field list
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##fmlist", new Vector2(listW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 6));
        UiHelper.MutedLabel("  Off  Type         Unique  Hint                              Values");
        ImGui.Spacing();

        var dl = ImGui.GetWindowDrawList();
        var lp = ImGui.GetWindowPos();
        float ly = ImGui.GetCursorScreenPos().Y - 2;
        dl.AddLine(new Vector2(lp.X, ly), new Vector2(lp.X + listW, ly),
            ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        // Group fixed bytes into ranges for cleaner display
        int i = 0;
        while (i < _multiResult.Fields.Count)
        {
            var field = _multiResult.Fields[i];

            // Collapse consecutive fixed bytes
            if (field.IsFixed)
            {
                int start = i;
                while (i < _multiResult.Fields.Count && _multiResult.Fields[i].IsFixed) i++;
                int count = i - start;
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                ImGui.Selectable(
                    $"  {start:X4}  Fixed ({count}b)    -       Header/padding                    " +
                    $"{string.Join(" ", _multiResult.Fields.Skip(start).Take(Math.Min(count, 6)).Select(f => $"{f.FixedVal:X2}"))}..." +
                    $"##fmf{start}",
                    false, ImGuiSelectableFlags.None, new Vector2(0, 18));
                ImGui.PopStyleColor();
                continue;
            }

            // Variable field
            var col = field.Hint.Contains("Item")     ? MenuRenderer.ColAccent
                    : field.Hint.Contains("stack")    ? MenuRenderer.ColWarn
                    : field.Hint.Contains("entity")   ? MenuRenderer.ColBlue
                    : field.Hint.Contains("Variable") ? MenuRenderer.ColText
                    : MenuRenderer.ColTextMuted;

            bool sel = _selectedField == i;
            if (sel)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(listW, 20),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }

            string valPreview = field.Int32Interpretation != null
                ? string.Join(", ", field.Int32Interpretation.Take(3))
                : string.Join(" ", field.Values.Take(4).Select(v => $"{v:X2}"));

            ImGui.PushStyleColor(ImGuiCol.Text, col);
            if (ImGui.Selectable(
                $"  {field.Offset:X4}  Variable     {field.UniqueCount,-7} {field.Hint,-35} {valPreview}##fmv{i}",
                sel, ImGuiSelectableFlags.None, new Vector2(0, 20)))
                _selectedField = i;
            ImGui.PopStyleColor();

            i++;
        }
        ImGui.EndChild();
        ImGui.SameLine(0, 8);

        // Detail panel
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##fmdet", new Vector2(detW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        if (_selectedField >= 0 && _selectedField < _multiResult.Fields.Count)
            RenderFieldDetail(_multiResult.Fields[_selectedField], detW);
        else
        {
            ImGui.SetCursorPosY(h * 0.4f);
            float tw = ImGui.CalcTextSize("<- select a variable field").X;
            ImGui.SetCursorPosX((detW - tw) * 0.5f);
            UiHelper.MutedLabel("<- select a variable field");
        }
        ImGui.EndChild();
    }

    private void RenderFieldDetail(FieldMapEntry field, float w)
    {
        ImGui.SetCursorPos(new Vector2(12, 10));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted($"FIELD @ OFFSET 0x{field.Offset:X4}");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        UiHelper.StatusRow("Offset",   $"0x{field.Offset:X4} ({field.Offset})", true, 90);
        UiHelper.StatusRow("Fixed",    field.IsFixed ? "Yes" : "No",            !field.IsFixed, 90);
        UiHelper.StatusRow("Unique",   $"{field.UniqueCount} distinct values",  true, 90);
        UiHelper.StatusRow("Hint",     field.Hint, !field.Hint.Contains("Unknown"), 90);

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        // Values across all captures
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("VALUES ACROSS CAPTURES:");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        var slots = _slots.Where(s => !string.IsNullOrWhiteSpace(s.Hex)).ToList();
        for (int i = 0; i < slots.Count && i < field.Values.Count; i++)
        {
            UiHelper.MutedLabel($"  {slots[i].Label,-16}");
            ImGui.SameLine();
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
            ImGui.TextUnformatted($"0x{field.Values[i]:X2} ({field.Values[i]})");
            ImGui.PopStyleColor();
        }

        if (field.Int32Interpretation != null)
        {
            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
            ImGui.TextUnformatted("AS INT32 (little-endian):");
            ImGui.PopStyleColor();
            ImGui.Spacing();
            for (int i = 0; i < slots.Count && i < field.Int32Interpretation.Count; i++)
            {
                UiHelper.MutedLabel($"  {slots[i].Label,-16}");
                ImGui.SameLine();
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                ImGui.TextUnformatted($"{field.Int32Interpretation[i]}");
                ImGui.PopStyleColor();
            }

            // Delta analysis
            if (field.Int32Interpretation.Count >= 2)
            {
                var vals = field.Int32Interpretation;
                var deltas = vals.Zip(vals.Skip(1), (a, b) => b - a).ToList();
                bool consistent = deltas.Distinct().Count() == 1;
                ImGui.Spacing();
                UiHelper.MutedLabel($"  Delta between captures: {string.Join(", ", deltas)}");
                if (consistent && deltas[0] != 0)
                    UiHelper.AccentText($"  [OK] Consistent delta of {deltas[0]} - this field tracks your test variable.");
            }
        }

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        // Save interpretation
        if (ImGui.Button($"Save as named field##sfld{field.Offset}", new Vector2(-1, 26)))
        {
            string note = $"Offset:0x{field.Offset:X4} Hint:{field.Hint}";
            _log.Success($"[Diff] Field at 0x{field.Offset:X4} noted: {field.Hint}");
        }
    }

    // ── Pair Diff view ────────────────────────────────────────────────────

    private void RenderPairDiff(float w)
    {
        if (_multiResult == null || _multiResult.PairDiffs.Count == 0) return;

        // Pair selector
        var populated = _slots.Where(s => !string.IsNullOrWhiteSpace(s.Hex)).ToList();
        ImGui.SetNextItemWidth(160);
        if (ImGui.BeginCombo("Compare##pairA", populated.ElementAtOrDefault(_pairA)?.Label ?? "A"))
        {
            for (int i = 0; i < populated.Count; i++)
                if (ImGui.Selectable(populated[i].Label)) { _pairA = i; UpdatePairDiff(); }
            ImGui.EndCombo();
        }
        ImGui.SameLine(0, 8);
        UiHelper.MutedLabel("vs");
        ImGui.SameLine(0, 8);
        ImGui.SetNextItemWidth(160);
        if (ImGui.BeginCombo("##pairB", populated.ElementAtOrDefault(_pairB)?.Label ?? "B"))
        {
            for (int i = 0; i < populated.Count; i++)
                if (ImGui.Selectable(populated[i].Label)) { _pairB = i; UpdatePairDiff(); }
            ImGui.EndCombo();
        }

        ImGui.Spacing();
        if (_pairResult == null) return;

        UiHelper.MutedLabel(_pairResult.Summary);
        ImGui.Spacing();

        // Changed regions summary
        if (_pairResult.ChangedRegions.Count == 0)
        {
            UiHelper.AccentText("Packets are identical.");
            return;
        }

        float h = ImGui.GetContentRegionAvail().Y;
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##pdiff", new Vector2(w, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 8));
        UiHelper.MutedLabel($"  Off    Len  {_pairResult.LabelA,-22} {_pairResult.LabelB,-22} Delta   Hint");
        ImGui.Separator();

        foreach (var region in _pairResult.ChangedRegions)
        {
            bool isItem = region.Hint.Contains("item") || region.Hint.Contains("Item");
            var  col    = isItem    ? MenuRenderer.ColAccent
                        : region.Delta != 0 ? MenuRenderer.ColWarn
                        : MenuRenderer.ColText;

            ImGui.PushStyleColor(ImGuiCol.Text, col);
            ImGui.TextUnformatted(
                $"  0x{region.StartOffset:X4}  {region.Length,3}b  " +
                $"{region.InterpretationA,-22} {region.InterpretationB,-22} " +
                $"{(region.Delta >= 0 ? "+" : "")}{region.Delta,-7} {region.Hint}");
            ImGui.PopStyleColor();
        }

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        // Full byte-by-byte visual diff
        UiHelper.MutedLabel("Byte diff (green=same, amber=changed, red=removed, blue=added):");
        ImGui.Spacing();

        int col16 = 0;
        foreach (var bd in _pairResult.Bytes)
        {
            if (col16 == 16) { ImGui.NewLine(); col16 = 0; }
            var byteCol = bd.Kind switch
            {
                DiffKind.Same    => MenuRenderer.ColTextMuted,
                DiffKind.Changed => MenuRenderer.ColWarn,
                DiffKind.Removed => MenuRenderer.ColDanger,
                DiffKind.Added   => MenuRenderer.ColBlue,
                _                => MenuRenderer.ColTextMuted
            };
            ImGui.PushStyleColor(ImGuiCol.Text, byteCol);
            ImGui.TextUnformatted($"{bd.B ?? bd.A ?? 0:X2}");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 4);
            col16++;
        }
        ImGui.NewLine();
        ImGui.EndChild();
    }

    // ── Byte Grid view ────────────────────────────────────────────────────

    private void RenderByteGrid(float w)
    {
        if (_multiResult == null) return;

        var populated = _slots.Where(s => !string.IsNullOrWhiteSpace(s.Hex)).ToList();
        int maxLen    = populated.Max(s => TryParse(s.Hex).Length);

        UiHelper.MutedLabel("Each column = one capture. Each row = one byte offset. Amber = changed from previous.");
        ImGui.Spacing();

        float h = ImGui.GetContentRegionAvail().Y;
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##bgrid", new Vector2(w, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        // Header
        ImGui.SetCursorPos(new Vector2(8, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("  Off  ");
        foreach (var s in populated) { ImGui.SameLine(0, 2); ImGui.TextUnformatted($"  {s.Label[..Math.Min(s.Label.Length, 8)]}  "); }
        ImGui.PopStyleColor();
        ImGui.Separator();

        var parsedSlots = populated.Select(s => TryParse(s.Hex)).ToList();

        for (int offset = 0; offset < maxLen; offset++)
        {
            var vals = parsedSlots.Select(p => offset < p.Length ? (byte?)p[offset] : null).ToList();
            bool allSame = vals.Where(v => v.HasValue).Distinct().Count() <= 1;

            if (allSame && vals.All(v => v.HasValue))
            {
                // Skip fixed rows unless they're the first
                if (offset > 0) continue;
            }

            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted($"  {offset:X4}  ");
            ImGui.PopStyleColor();

            for (int si = 0; si < parsedSlots.Count; si++)
            {
                var val  = vals[si];
                var prev = si > 0 ? vals[si - 1] : null;
                bool changed = val.HasValue && prev.HasValue && val != prev;

                var col = val == null    ? MenuRenderer.ColTextMuted
                        : changed        ? MenuRenderer.ColWarn
                        : allSame        ? MenuRenderer.ColTextMuted
                        : MenuRenderer.ColText;

                ImGui.SameLine(0, 2);
                ImGui.PushStyleColor(ImGuiCol.Text, col);
                ImGui.TextUnformatted(val.HasValue ? $"  {val:X2}  " : "  --  ");
                ImGui.PopStyleColor();
            }
        }
        ImGui.EndChild();
    }

    // ── Export ────────────────────────────────────────────────────────────

    private void ExportFieldMap()
    {
        if (_multiResult == null) return;
        try
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"# Diff Analysis Export - {DateTime.Now:yyyy-MM-dd HH:mm}");
            sb.AppendLine($"# {_multiResult.Summary}");
            sb.AppendLine();
            sb.AppendLine("Offset\tFixed\tHint\tValues");
            foreach (var f in _multiResult.Fields.Where(f => !f.IsFixed))
                sb.AppendLine($"0x{f.Offset:X4}\t{f.IsFixed}\t{f.Hint}\t{string.Join(",", f.Values.Select(v => v.ToString()))}");

            string path = $"HyTester_FieldMap_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            File.WriteAllText(path, sb.ToString());
            ImGui.SetClipboardText(sb.ToString());
            _log.Success($"[Diff] Field map exported to {path} and copied to clipboard.");
        }
        catch (Exception ex) { _log.Error($"[Diff] Export: {ex.Message}"); }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private void UpdatePairDiff()
    {
        if (_multiResult == null) return;
        int idx = Math.Min(_pairA, _pairB);
        _pairResult = idx < _multiResult.PairDiffs.Count
            ? _multiResult.PairDiffs[idx] : null;
    }

    private static byte[] TryParse(string hex)
    {
        try
        {
            string clean = hex.Replace(" ", "").Replace("\n", "");
            if (clean.Length % 2 != 0) clean += "0";
            return Convert.FromHexString(clean);
        }
        catch { return Array.Empty<byte>(); }
    }
}

public class DiffSlot
{
    public string Label { get; set; } = "";
    public string Hex   { get; set; } = "";
}
