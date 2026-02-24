using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Text.Json;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Protocol Encyclopedia.
///
/// Keeps a persistent, annotated map of every opcode seen or manually added.
/// For each opcode you document:
///   - Human name, direction (C→S / S→C / both)
///   - Understanding status (Unknown / Partial / Confirmed)
///   - Field annotations (byte offset, type, meaning)
///   - Free-form notes
///
/// The map auto-populates from captured traffic so nothing is missed.
/// Everything persists to %AppData%/HytaleSecurityTester/proto_map.json.
/// </summary>
public class ProtocolMapTab : ITab
{
    public string Title => "  Protocol Map  ";

    private readonly TestLog      _log;
    private readonly PacketCapture _capture;

    // ── Persistent state ──────────────────────────────────────────────────
    private readonly ProtoMap _map;

    // ── UI state ──────────────────────────────────────────────────────────
    private int    _selectedId   = -1;
    private int    _filterDir    = 0;       // 0=all 1=CS 2=SC
    private int    _filterStatus = 0;       // 0=all 1=unknown 2=partial 3=confirmed
    private string _searchText   = "";
    private int    _lastPktCount = 0;
    private DateTime _lastScan   = DateTime.MinValue;

    // Detail pane edit buffers
    private string _editName    = "";
    private string _editNotes   = "";
    private string _editFieldOff = "0";
    private string _editFieldType = "byte";
    private string _editFieldName = "";

    // New-entry form
    private int    _newOpcode  = 0;
    private int    _newDir     = 0;
    private string _newName    = "";

    private static readonly string[] StatusLabels = { "All", "Unknown", "Partial", "Confirmed" };
    private static readonly string[] DirLabels    = { "All", "C→S", "S→C" };
    private static readonly string[] FieldTypes   = { "byte", "int16", "int32", "float", "string(utf8)", "string(ascii)", "bool", "bytes" };

    // ─────────────────────────────────────────────────────────────────────

    public ProtocolMapTab(TestLog log, PacketCapture capture)
    {
        _log     = log;
        _capture = capture;
        _map     = ProtoMap.Load();
    }

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;
        AutoScanPackets();

        RenderToolbar(w);
        ImGui.Spacing();

        float listW = w * 0.36f;
        float detW  = w - listW - 10;
        float h     = ImGui.GetContentRegionAvail().Y;

        // Left — opcode list
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##pm_list", new Vector2(listW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        RenderOpcodeList(listW);
        ImGui.EndChild();

        ImGui.SameLine(0, 10);

        // Right — detail pane
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##pm_det", new Vector2(detW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        if (_selectedId >= 0 && _map.Entries.TryGetValue(_selectedId, out var entry))
            RenderDetail(entry, detW);
        else
        {
            ImGui.SetCursorPosY(h * 0.4f);
            UiHelper.MutedLabel("   ← select an opcode to annotate");
        }
        ImGui.EndChild();
    }

    // ── Toolbar ───────────────────────────────────────────────────────────

    private void RenderToolbar(float w)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##pm_toolbar", new Vector2(w, 36), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 6));

        // Search
        ImGui.SetNextItemWidth(180);
        ImGui.InputText("##pmsr", ref _searchText, 64);
        ImGui.SameLine(0, 8);
        UiHelper.MutedLabel("Search");

        // Direction filter
        ImGui.SameLine(0, 16);
        ImGui.SetNextItemWidth(70);
        ImGui.Combo("Dir##pmdf", ref _filterDir, DirLabels, DirLabels.Length);

        // Status filter
        ImGui.SameLine(0, 8);
        ImGui.SetNextItemWidth(90);
        ImGui.Combo("Status##pmsf", ref _filterStatus, StatusLabels, StatusLabels.Length);

        // Stats
        int unknown   = _map.Entries.Values.Count(e => e.Status == OpcodeStatus.Unknown);
        int confirmed = _map.Entries.Values.Count(e => e.Status == OpcodeStatus.Confirmed);
        ImGui.SameLine(0, 16);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted($"Total:{_map.Entries.Count}  ✓{confirmed}  ?{unknown}");
        ImGui.PopStyleColor();

        // Export
        ImGui.SameLine(0, 16);
        UiHelper.SecondaryButton("Export JSON##pmexp", 110, 22, ExportJson);

        ImGui.EndChild();
    }

    // ── Opcode list ───────────────────────────────────────────────────────

    private void RenderOpcodeList(float w)
    {
        // Add new entry row at top
        ImGui.SetCursorPos(new Vector2(6, 6));
        ImGui.SetNextItemWidth(56); ImGui.InputInt("##pmnew_op", ref _newOpcode);
        _newOpcode = Math.Clamp(_newOpcode, 0, 255);
        ImGui.SameLine(0, 4);
        ImGui.SetNextItemWidth(48);
        ImGui.Combo("##pmnewdir", ref _newDir, new[] { "C→S", "S→C", "Both" }, 3);
        ImGui.SameLine(0, 4);
        ImGui.SetNextItemWidth(90); ImGui.InputText("##pmnewname", ref _newName, 32);
        ImGui.SameLine(0, 4);
        UiHelper.PrimaryButton("+##pmnewadd", 26, 22, () =>
        {
            _map.GetOrAdd(_newOpcode, (ProtoDirection)_newDir, _newName);
            _map.Save();
            _selectedId = _newOpcode;
            _log.Success($"[ProtoMap] Added 0x{_newOpcode:X2}.");
        });

        ImGui.Spacing();

        // Filter and display entries
        var filtered = _map.Entries.Values
            .Where(e =>
            {
                if (_filterDir == 1 && e.Direction == ProtoDirection.SC) return false;
                if (_filterDir == 2 && e.Direction == ProtoDirection.CS) return false;
                if (_filterStatus == 1 && e.Status != OpcodeStatus.Unknown)   return false;
                if (_filterStatus == 2 && e.Status != OpcodeStatus.Partial)   return false;
                if (_filterStatus == 3 && e.Status != OpcodeStatus.Confirmed) return false;
                if (_searchText.Length > 0 &&
                    !e.Name.ToLower().Contains(_searchText.ToLower()) &&
                    !$"0x{e.Opcode:X2}".Contains(_searchText.ToLower()))
                    return false;
                return true;
            })
            .OrderBy(e => e.Opcode)
            .ToList();

        float lineH = 20f;
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##pm_listscroll", new Vector2(w - 4, -1), ImGuiChildFlags.None);
        ImGui.PopStyleColor();

        var dl = ImGui.GetWindowDrawList();
        var wp = ImGui.GetWindowPos();

        foreach (var e in filtered)
        {
            bool sel = _selectedId == e.Opcode;
            if (sel)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(w, lineH),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }

            var statusCol = e.Status switch
            {
                OpcodeStatus.Confirmed => MenuRenderer.ColAccent,
                OpcodeStatus.Partial   => MenuRenderer.ColWarn,
                _                      => MenuRenderer.ColTextMuted,
            };

            var dirCol = e.Direction switch
            {
                ProtoDirection.CS   => MenuRenderer.ColBlue,
                ProtoDirection.SC   => MenuRenderer.ColAccentMid,
                _                   => MenuRenderer.ColTextMuted,
            };

            ImGui.SetCursorPosX(6);
            ImGui.PushStyleColor(ImGuiCol.Text, statusCol);
            string statusGlyph = e.Status == OpcodeStatus.Confirmed ? "✓"
                               : e.Status == OpcodeStatus.Partial   ? "~" : "?";
            ImGui.TextUnformatted(statusGlyph);
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 4);
            ImGui.PushStyleColor(ImGuiCol.Text, dirCol);
            string dirStr = e.Direction == ProtoDirection.CS ? "→" : e.Direction == ProtoDirection.SC ? "←" : "↔";
            ImGui.TextUnformatted(dirStr);
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 4);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
            ImGui.TextUnformatted($"0x{e.Opcode:X2}");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 6);
            ImGui.PushStyleColor(ImGuiCol.Text, sel ? MenuRenderer.ColText : MenuRenderer.ColTextMuted);
            string nameDisplay = e.Name.Length > 0 ? e.Name : "(unnamed)";
            if (nameDisplay.Length > 22) nameDisplay = nameDisplay[..19] + "…";
            ImGui.TextUnformatted(nameDisplay);
            ImGui.PopStyleColor();

            // occurrence badge
            if (e.SeenCount > 0)
            {
                float rX = ImGui.GetWindowPos().X + w - 48;
                float rY = ImGui.GetCursorScreenPos().Y - lineH + 2;
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                ImGui.SetCursorPosX(w - 46);
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() - lineH);
                ImGui.TextUnformatted($"×{Math.Min(e.SeenCount, 9999)}");
                ImGui.PopStyleColor();
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + lineH - 6);
            }

            // Invisible selectable
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() - lineH + 2);
            if (ImGui.Selectable($"##pmsel{e.Opcode}", sel, ImGuiSelectableFlags.None, new Vector2(w - 8, lineH)))
            {
                _selectedId = e.Opcode;
                var selEntry = _map.Entries[e.Opcode];
                _editName  = selEntry.Name;
                _editNotes = selEntry.Notes;
            }
        }

        ImGui.EndChild();
    }

    // ── Detail pane ───────────────────────────────────────────────────────

    private void RenderDetail(OpcodeEntry e, float w)
    {
        ImGui.SetCursorPos(new Vector2(10, 8));

        // Header
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
        ImGui.TextUnformatted($"0x{e.Opcode:X2}");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 10);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted(e.Name.Length > 0 ? e.Name.ToUpper() : "(UNNAMED OPCODE)");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 10);
        UiHelper.MutedLabel($"seen ×{e.SeenCount}  last {(e.LastSeen == DateTime.MinValue ? "never" : e.LastSeen.ToString("HH:mm:ss"))}");

        ImGui.Spacing();

        // Editable name
        ImGui.SetNextItemWidth(w * 0.5f);
        if (ImGui.InputText("Name##pmdn", ref _editName, 64) && _editName != e.Name)
        {
            e.Name = _editName;
            _map.Save();
        }

        // Direction
        ImGui.SameLine(0, 12);
        int dir = (int)e.Direction;
        ImGui.SetNextItemWidth(80);
        if (ImGui.Combo("Dir##pmddir", ref dir, new[] { "C→S", "S→C", "Both" }, 3))
        {
            e.Direction = (ProtoDirection)dir;
            _map.Save();
        }

        // Status
        ImGui.SameLine(0, 8);
        int status = (int)e.Status;
        ImGui.SetNextItemWidth(100);
        if (ImGui.Combo("Status##pmds", ref status, new[] { "Unknown", "Partial", "Confirmed" }, 3))
        {
            e.Status = (OpcodeStatus)status;
            if (e.Status == OpcodeStatus.Confirmed)
                AlertBus.ClearBadge(AlertBus.Sec_ProtoMap);
            _map.Save();
        }

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        // ── Field annotations ──────────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted($"FIELD MAP  ({e.Fields.Count} annotations)");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        // Table header
        UiHelper.MutedLabel($"  {"Offset",-8} {"Type",-14} {"Field Name",-22}");
        var dl = ImGui.GetWindowDrawList();
        float sepY = ImGui.GetCursorScreenPos().Y;
        dl.AddLine(new Vector2(ImGui.GetWindowPos().X + 6, sepY),
                   new Vector2(ImGui.GetWindowPos().X + w - 6, sepY),
                   ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
        ImGui.Spacing();

        int removeFieldIdx = -1;
        for (int fi = 0; fi < e.Fields.Count; fi++)
        {
            var f = e.Fields[fi];
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
            ImGui.TextUnformatted($"  +{f.Offset,-7} {f.Type,-14} ");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 0);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColText);
            ImGui.TextUnformatted(f.FieldName);
            ImGui.PopStyleColor();
            ImGui.SameLine(w - 40);
            ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
            if (ImGui.Button($"✕##pmfdel{fi}", new Vector2(24, 18))) removeFieldIdx = fi;
            ImGui.PopStyleColor(2);
        }
        if (removeFieldIdx >= 0) { e.Fields.RemoveAt(removeFieldIdx); _map.Save(); }

        // Add field row
        ImGui.Spacing();
        ImGui.SetNextItemWidth(60);  ImGui.InputText("Offset##pmfoff",  ref _editFieldOff,  8);
        ImGui.SameLine(0, 6);
        ImGui.SetNextItemWidth(110); ImGui.Combo("##pmftype", ref FieldTypeIndex(ref _editFieldType), FieldTypes, FieldTypes.Length);
        ImGui.SameLine(0, 6);
        ImGui.SetNextItemWidth(160); ImGui.InputText("Field name##pmfname", ref _editFieldName, 48);
        ImGui.SameLine(0, 6);
        UiHelper.PrimaryButton("Add##pmfadd", 40, 22, () =>
        {
            if (!string.IsNullOrWhiteSpace(_editFieldName))
            {
                int off = int.TryParse(_editFieldOff, out int v) ? v : 0;
                e.Fields.Add(new FieldAnnotation
                { Offset = off, Type = _editFieldType, FieldName = _editFieldName });
                e.Fields.Sort((a, b) => a.Offset.CompareTo(b.Offset));
                _editFieldName = "";
                _map.Save();
            }
        });

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        // ── Notes ──────────────────────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("NOTES");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        ImGui.SetNextItemWidth(-1);
        float notesH = Math.Max(80, ImGui.GetContentRegionAvail().Y - 90);
        if (ImGui.InputTextMultiline("##pmdn_notes", ref _editNotes, 4096, new Vector2(-1, notesH)))
        {
            e.Notes = _editNotes;
            _map.Save();
        }

        ImGui.Spacing();

        // Sample hex from last seen packet
        if (e.SampleHex.Length > 0)
        {
            ImGui.Separator();
            ImGui.Spacing();
            UiHelper.MutedLabel("Last seen sample:");
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.6f, 1f, 0.6f, 1f));
            ImGui.TextWrapped(e.SampleHex);
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 8);
            UiHelper.SecondaryButton("Copy##pmcopy", 52, 20, () =>
                ImGui.SetClipboardText(e.SampleHex));
        }

        // Delete entry
        ImGui.Spacing();
        UiHelper.DangerButton("Delete Entry##pmdelentry", 130, 24, () =>
        {
            _map.Entries.TryRemove(e.Opcode, out _);
            _selectedId = -1;
            _map.Save();
            _log.Warn($"[ProtoMap] Deleted 0x{e.Opcode:X2}.");
        });
    }

    // ── Auto-scan new captured packets ────────────────────────────────────

    private void AutoScanPackets()
    {
        var pkts = _capture.GetPackets();
        if (pkts.Count == _lastPktCount) return;
        if ((DateTime.Now - _lastScan).TotalMilliseconds < 500) return;

        int start = Math.Max(_lastPktCount, pkts.Count - 200);
        for (int i = start; i < pkts.Count; i++)
        {
            var pkt = pkts[i];
            if (pkt.RawBytes.Length == 0) continue;
            int op  = pkt.RawBytes[0];
            var dir = pkt.Direction == PacketDirection.ClientToServer
                      ? ProtoDirection.CS : ProtoDirection.SC;

            var entry = _map.GetOrAdd(op, dir, "");
            entry.SeenCount++;
            entry.LastSeen = DateTime.Now;

            // Store sample hex (first 32 bytes)
            if (entry.SampleHex.Length == 0)
            {
                int take = Math.Min(32, pkt.RawBytes.Length);
                entry.SampleHex = string.Join(" ", pkt.RawBytes.Take(take).Select(b => $"{b:X2}"));
            }

            // If unknown opcode seen for first time, fire alert
            if (entry.SeenCount == 1 && entry.Status == OpcodeStatus.Unknown)
                AlertBus.Push(AlertBus.Sec_ProtoMap, AlertLevel.Info,
                    $"New opcode 0x{op:X2} ({(dir == ProtoDirection.CS ? "C→S" : "S→C")})");
        }

        _lastPktCount = pkts.Count;
        _lastScan     = DateTime.Now;

        if (pkts.Count % 500 == 0 && pkts.Count > 0) _map.Save();
    }

    // ── Export ─────────────────────────────────────────────────────────────

    private void ExportJson()
    {
        string json = JsonSerializer.Serialize(_map.Entries.Values.OrderBy(e => e.Opcode).ToList(),
            new JsonSerializerOptions { WriteIndented = true });
        ImGui.SetClipboardText(json);
        _log.Success($"[ProtoMap] Exported {_map.Entries.Count} entries to clipboard (JSON).");
    }

    // ── Ugly ref trick for Combo ───────────────────────────────────────────

    private ref int FieldTypeIndex(ref string current)
    {
        // ImGui.Combo needs an int ref; we maintain a local shadow
        // This is a workaround — we use a fixed storage slot
        _ftIdx = Array.IndexOf(FieldTypes, current);
        if (_ftIdx < 0) _ftIdx = 0;
        return ref _ftIdx;
    }
    private int _ftIdx = 0;
}

// ── ProtoMap data model ────────────────────────────────────────────────────────

public sealed class ProtoMap
{
    private static string SavePath
    {
        get
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "HytaleSecurityTester");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "proto_map.json");
        }
    }

    public System.Collections.Concurrent.ConcurrentDictionary<int, OpcodeEntry> Entries { get; set; }
        = new();

    public OpcodeEntry GetOrAdd(int opcode, ProtoDirection dir, string name)
    {
        return Entries.GetOrAdd(opcode, _ => new OpcodeEntry
        {
            Opcode    = opcode,
            Direction = dir,
            Name      = name,
            Status    = OpcodeStatus.Unknown,
        });
    }

    public static ProtoMap Load()
    {
        try
        {
            if (!File.Exists(SavePath)) return new ProtoMap();
            var list = JsonSerializer.Deserialize<List<OpcodeEntry>>(File.ReadAllText(SavePath));
            var m    = new ProtoMap();
            if (list != null)
                foreach (var e in list)
                    m.Entries[e.Opcode] = e;
            return m;
        }
        catch { return new ProtoMap(); }
    }

    public void Save()
    {
        try
        {
            string json = JsonSerializer.Serialize(
                Entries.Values.OrderBy(e => e.Opcode).ToList(),
                new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SavePath, json);
        }
        catch { }
    }
}

public sealed class OpcodeEntry
{
    public int              Opcode     { get; set; }
    public string           Name       { get; set; } = "";
    public ProtoDirection   Direction  { get; set; }
    public OpcodeStatus     Status     { get; set; } = OpcodeStatus.Unknown;
    public string           Notes      { get; set; } = "";
    public List<FieldAnnotation> Fields { get; set; } = new();
    public int              SeenCount  { get; set; }
    public DateTime         LastSeen   { get; set; } = DateTime.MinValue;
    public string           SampleHex  { get; set; } = "";
}

public sealed class FieldAnnotation
{
    public int    Offset    { get; set; }
    public string Type      { get; set; } = "byte";
    public string FieldName { get; set; } = "";
}

public enum OpcodeStatus { Unknown, Partial, Confirmed }
public enum ProtoDirection { CS, SC, Both }
