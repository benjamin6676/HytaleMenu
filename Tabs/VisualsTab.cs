using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Visuals / ESP tab.
///
/// Controls the entity overlay drawn by Application.DrawEntityOverlays()
/// and provides a Dynamic Component Finder that uses the AOB scanner to
/// automatically discover and register new entity types for the overlay.
///
/// Sections:
///   OVERLAY CONTROL     — master enable, VP matrix source, registered entities list
///   DYNAMIC COMPONENT FINDER — define AOB signatures per entity type; scanner
///                              reads Vector3 position at a configurable struct
///                              offset from each match and feeds Application.EntityPositions
///   MANUAL ENTITY EDITOR — hand-add overlay entries for quick testing
/// </summary>
public class VisualsTab : ITab
{
    public string Title => "  Visuals / ESP  ";

    private readonly TestLog     _log;
    private readonly MemoryReader _reader = new();

    // ── Overlay master state ──────────────────────────────────────────────
    private bool _overlayEnabled  = true;
    private bool _showLabels      = true;
    private float _boxAlpha       = 0.9f;

    // ── VP matrix source ──────────────────────────────────────────────────
    private string _vpModuleName   = "";
    private string _vpAobPattern   = "48 8B 05 ?? ?? ?? ?? 48 85 C0"; // placeholder
    private int    _vpStructOffset  = 0x1A0;   // byte offset from AOB hit to float[16]
    private bool   _vpAutoRefresh   = false;
    private bool   _vpScanning      = false;
    private string _vpStatus        = "Not configured";

    // ── Entity type registry ──────────────────────────────────────────────
    private readonly List<EntityTypeEntry> _entityTypes = new()
    {
        new EntityTypeEntry { Name = "Player",   Pattern = "50 6C 61 79 65 72",          PosOffset = 0x30, Color = new Vector4(0.18f, 0.95f, 0.45f, 0.9f), Enabled = true },
        new EntityTypeEntry { Name = "Monster",  Pattern = "4D 6F 6E 73 74 65 72 ?? ??", PosOffset = 0x30, Color = new Vector4(0.95f, 0.28f, 0.22f, 0.9f), Enabled = true },
        new EntityTypeEntry { Name = "NPC",      Pattern = "4E 50 43 ?? ?? ??",          PosOffset = 0x28, Color = new Vector4(0.28f, 0.72f, 1.00f, 0.9f), Enabled = false },
        new EntityTypeEntry { Name = "Item Drop",Pattern = "49 74 65 6D ?? ?? ?? ??",    PosOffset = 0x20, Color = new Vector4(0.95f, 0.75f, 0.10f, 0.9f), Enabled = false },
    };

    // ── Dynamic Component Finder ──────────────────────────────────────────
    private bool   _dcfRunning      = false;
    private string _dcfStatus       = "";
    private int    _dcfSelectedType = 0;   // which EntityTypeEntry is being scanned
    private int    _dcfRefreshMs    = 2000;
    private bool   _dcfAutoLoop     = false;
    private CancellationTokenSource? _dcfCts;
    private int    _dcfFound        = 0;
    private DateTime _dcfLastRun    = DateTime.MinValue;

    // Edit state for the new-type form
    private string _newName        = "Custom";
    private string _newPattern     = "";
    private int    _newPosOffset   = 0x30;
    private Vector4 _newColor      = new(0.95f, 0.75f, 0.10f, 0.9f);
    private int    _editingType    = -1;

    // ── Manual entity editor ──────────────────────────────────────────────
    private float _manX = 0, _manY = 0, _manZ = 0;
    private string _manLabel = "Test";

    // ── Modules cache ─────────────────────────────────────────────────────
    private List<ModuleInfo> _modules    = new();
    private string           _selModule  = "";

    // ── Process attach ────────────────────────────────────────────────────
    private List<System.Diagnostics.Process> _procs = new();
    private int                              _manualPid = 0;

    public VisualsTab(TestLog log) { _log = log; }

    // ── Render ────────────────────────────────────────────────────────────

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;

        RenderStatusBar(w);
        ImGui.Spacing();

        float availH = ImGui.GetContentRegionAvail().Y;
        float leftW  = w * 0.58f;
        float rightW = w - leftW - 8f;

        // Left column
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##visleft", new Vector2(leftW, availH), ImGuiChildFlags.None);
        ImGui.PopStyleColor();

        RenderOverlayControl(leftW);
        ImGui.Spacing();
        RenderDCF(leftW);
        ImGui.Spacing();
        RenderManualEditor(leftW);

        ImGui.EndChild();
        ImGui.SameLine(0, 8);

        // Right column — entity type registry
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##visright", new Vector2(rightW, availH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        RenderEntityRegistry(rightW);
        ImGui.EndChild();
    }

    // ══════════════════════════════════════════════════════════════════════
    // STATUS BAR
    // ══════════════════════════════════════════════════════════════════════

    private void RenderStatusBar(float w)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##vissb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));

        bool att = _reader.IsAttached;
        ImGui.PushStyleColor(ImGuiCol.Text, att ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(att
            ? $"● Memory attached — {_reader.ProcessName} (PID {_reader.Pid})"
            : "● No memory process — attach below to enable AOB scanning");
        ImGui.PopStyleColor();

        ImGui.SameLine(0, 24);
        int cnt = Application.EntityPositions.Count;
        ImGui.PushStyleColor(ImGuiCol.Text, cnt > 0 ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted($"● {cnt} overlay entries  |  overlay {(_overlayEnabled ? "ON" : "OFF")}");
        ImGui.PopStyleColor();

        ImGui.EndChild();
    }

    // ══════════════════════════════════════════════════════════════════════
    // OVERLAY CONTROL
    // ══════════════════════════════════════════════════════════════════════

    private void RenderOverlayControl(float w)
    {
        UiHelper.SectionBox("OVERLAY CONTROL", w, 210, () =>
        {
            // Master toggle
            ImGui.Checkbox("Enable entity overlay##oven", ref _overlayEnabled);
            ImGui.SameLine(0, 16);
            ImGui.Checkbox("Show labels##ovlbl", ref _showLabels);
            ImGui.SameLine(0, 16);
            UiHelper.SecondaryButton("Clear all##ovclear", 80, 22, () =>
            {
                lock (Application.EntityPositions) Application.EntityPositions.Clear();
                _log.Info("[Visuals] Overlay cleared.");
            });

            ImGui.SetNextItemWidth(200);
            ImGui.SliderFloat("Box opacity##ovalf", ref _boxAlpha, 0.1f, 1f);
            ImGui.Spacing();

            // VP matrix config
            UiHelper.MutedLabel("VP Matrix source (AOB hit + struct offset → float[16]):");
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("AOB pattern##vpao", ref _vpAobPattern, 256);

            ImGui.SetNextItemWidth(150);
            ImGui.InputInt("Struct offset (hex)##vpoff", ref _vpStructOffset);
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel($"0x{_vpStructOffset:X}");

            ImGui.SetNextItemWidth(200);
            if (_modules.Count == 0 && _reader.IsAttached)
                _modules = _reader.GetModules();
            if (ImGui.BeginCombo("Module##vpmod",
                string.IsNullOrEmpty(_selModule) ? "All modules" : _selModule))
            {
                if (ImGui.Selectable("All modules##vpall")) _selModule = "";
                foreach (var m in _modules)
                    if (ImGui.Selectable($"{m.Name}##vpmod{m.Name}")) _selModule = m.Name;
                ImGui.EndCombo();
            }

            ImGui.Spacing();
            ImGui.Checkbox("Auto-refresh VP matrix every frame##vpau", ref _vpAutoRefresh);
            ImGui.SameLine(0, 12);
            ImGui.BeginDisabled(!_reader.IsAttached || _vpScanning);
            UiHelper.WarnButton(_vpScanning ? "Scanning...##vpscan" : "Apply VP Matrix##vpscan",
                140, 24, ApplyVpMatrix);
            ImGui.EndDisabled();

            ImGui.Spacing();
            ImGui.PushStyleColor(ImGuiCol.Text,
                _vpStatus.Contains("OK") ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted($"  {_vpStatus}");
            ImGui.PopStyleColor();
        });

        // VP auto-refresh: every frame if enabled
        if (_vpAutoRefresh && _reader.IsAttached && !_vpScanning)
            Task.Run(ApplyVpMatrix); // fire-and-forget; IsAttached guard prevents spam
    }

    private void ApplyVpMatrix()
    {
        if (_vpScanning || !_reader.IsAttached) return;
        _vpScanning = true;
        Task.Run(() =>
        {
            try
            {
                var matches = string.IsNullOrEmpty(_selModule)
                    ? _reader.AobScanAllModules(_vpAobPattern)
                    : new List<AobMatch>
                    {
                        new AobMatch
                        {
                            Address = _reader.AobScanModule(_selModule, _vpAobPattern, out _),
                            Module  = _selModule
                        }
                    };

                var hit = matches.FirstOrDefault(m => m.Address != IntPtr.Zero);
                if (hit == null || hit.Address == IntPtr.Zero)
                {
                    _vpStatus = "Pattern not found — check AOB and module.";
                    return;
                }

                // Read 64 bytes (float[16]) from hit.Address + struct offset
                var matAddr = hit.Address + _vpStructOffset;
                var buf = new byte[64];
                if (!_reader.ReadBytes(matAddr, buf))
                {
                    _vpStatus = $"Found at {hit.AddressHex} but ReadBytes failed.";
                    return;
                }

                var m4 = new Matrix4x4(
                    BitConverter.ToSingle(buf, 0),  BitConverter.ToSingle(buf, 4),
                    BitConverter.ToSingle(buf, 8),  BitConverter.ToSingle(buf, 12),
                    BitConverter.ToSingle(buf, 16), BitConverter.ToSingle(buf, 20),
                    BitConverter.ToSingle(buf, 24), BitConverter.ToSingle(buf, 28),
                    BitConverter.ToSingle(buf, 32), BitConverter.ToSingle(buf, 36),
                    BitConverter.ToSingle(buf, 40), BitConverter.ToSingle(buf, 44),
                    BitConverter.ToSingle(buf, 48), BitConverter.ToSingle(buf, 52),
                    BitConverter.ToSingle(buf, 56), BitConverter.ToSingle(buf, 60));

                Application.ViewProjectionMatrix = m4;
                _vpStatus = $"OK — matrix applied from {hit.AddressHex} [{hit.Module}]";
            }
            catch (Exception ex) { _vpStatus = $"Error: {ex.Message}"; }
            finally { _vpScanning = false; }
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // DYNAMIC COMPONENT FINDER
    // ══════════════════════════════════════════════════════════════════════

    private void RenderDCF(float w)
    {
        UiHelper.SectionBox("DYNAMIC COMPONENT FINDER", w, 290, () =>
        {
            UiHelper.MutedLabel("Runs the AOB scanner for each enabled entity type, reads the Vector3");
            UiHelper.MutedLabel("position at [hit + PosOffset] and registers new overlay entries.");
            ImGui.Spacing();

            // Process attach (needed for memory reads)
            if (!_reader.IsAttached)
            {
                UiHelper.MutedLabel("Attach to game process first:");
                if (ImGui.Button("Refresh process list##dcfpl", new Vector2(180, 24)))
                    _procs = System.Diagnostics.Process.GetProcesses()
                        .Where(p => { try { return !string.IsNullOrEmpty(p.MainWindowTitle); } catch { return false; } })
                        .OrderBy(p => p.ProcessName).ToList();

                foreach (var p in _procs.Take(8))
                {
                    if (ImGui.Button($"{p.ProcessName} ({p.Id})##dcfp{p.Id}", new Vector2(-1, 20)))
                    {
                        string err = _reader.Attach(p.Id);
                        if (string.IsNullOrEmpty(err))
                        {
                            _modules = _reader.GetModules();
                            _log.Success($"[Visuals] Attached to {p.ProcessName}.");
                        }
                        else _log.Error($"[Visuals] Attach failed: {err}");
                    }
                }
                return;
            }

            // Config
            ImGui.SetNextItemWidth(100); ImGui.InputInt("Refresh ms##dcfrms", ref _dcfRefreshMs);
            _dcfRefreshMs = Math.Clamp(_dcfRefreshMs, 200, 60_000);
            ImGui.SameLine(0, 12);
            ImGui.Checkbox("Auto-loop##dcfal", ref _dcfAutoLoop);
            ImGui.SameLine(0, 12);
            UiHelper.MutedLabel($"Found this run: {_dcfFound}");

            ImGui.Spacing();

            if (_dcfRunning)
            {
                UiHelper.DangerButton("Stop Finder##dcfstop", 120, 28, () =>
                {
                    _dcfCts?.Cancel();
                    _dcfRunning = false;
                    _log.Warn("[DCF] Stopped.");
                });
                ImGui.SameLine(0, 12);
                UiHelper.WarnText("● Scanning...");
            }
            else
            {
                UiHelper.WarnButton("Run Component Finder##dcfrun", 200, 28, RunDCF);
                ImGui.SameLine(0, 12);
                if (_dcfLastRun != DateTime.MinValue)
                    UiHelper.MutedLabel($"Last run: {_dcfLastRun:HH:mm:ss}  |  {_dcfFound} entities registered");
            }

            if (_dcfStatus.Length > 0)
            {
                ImGui.Spacing();
                ImGui.PushStyleColor(ImGuiCol.Text,
                    _dcfStatus.StartsWith("Error") ? MenuRenderer.ColDanger : MenuRenderer.ColBlue);
                ImGui.TextWrapped(_dcfStatus);
                ImGui.PopStyleColor();
            }

            ImGui.Spacing();
            UiHelper.MutedLabel("Tip: start with a short refresh interval (500ms) to track moving entities.");
            UiHelper.MutedLabel("Increase PosOffset in the registry if boxes appear offset from entities.");
        });
    }

    private void RunDCF()
    {
        if (!_reader.IsAttached) { _log.Error("[DCF] Attach to a process first."); return; }
        _dcfRunning = true;
        _dcfFound   = 0;
        _dcfCts     = new CancellationTokenSource();
        var cts     = _dcfCts;

        Task.Run(async () =>
        {
            do
            {
                int found = 0;
                foreach (var et in _entityTypes.Where(e => e.Enabled && e.Pattern.Length > 0))
                {
                    try
                    {
                        List<AobMatch> matches = _reader.AobScanAllModules(et.Pattern, 64);
                        foreach (var m in matches)
                        {
                            if (cts.Token.IsCancellationRequested) break;
                            if (m.Address == IntPtr.Zero) continue;

                            // Read Vector3 at hit + PosOffset
                            var posAddr = m.Address + et.PosOffset;
                            if (!_reader.ReadFloat(posAddr, out float x)) continue;
                            if (!_reader.ReadFloat(posAddr + 4, out float y)) continue;
                            if (!_reader.ReadFloat(posAddr + 8, out float z)) continue;

                            // Sanity-check: position must be within plausible world bounds
                            if (Math.Abs(x) > 1_000_000 || Math.Abs(y) > 100_000 || Math.Abs(z) > 1_000_000)
                                continue;

                            var entry = new EntityOverlayEntry
                            {
                                Position = new Vector3(x, y, z),
                                Label    = $"{et.Name}  {m.AddressHex[^6..]}",
                                Width    = et.BoxWidth,
                                Height   = et.BoxHeight,
                                Color    = new Vector4(et.Color.X, et.Color.Y, et.Color.Z, _boxAlpha),
                            };

                            lock (Application.EntityPositions)
                            {
                                // Update existing entry for this address or add new
                                bool updated = false;
                                for (int i = 0; i < Application.EntityPositions.Count; i++)
                                {
                                    if (Application.EntityPositions[i].Label == entry.Label)
                                    {
                                        Application.EntityPositions[i] = entry;
                                        updated = true;
                                        break;
                                    }
                                }
                                if (!updated)
                                {
                                    if (_overlayEnabled)
                                        Application.EntityPositions.Add(entry);
                                }
                            }
                            found++;
                        }

                        _dcfStatus = $"[{et.Name}] {matches.Count} AOB hit(s) → {found} position(s) valid";
                    }
                    catch (Exception ex)
                    {
                        _dcfStatus = $"Error scanning [{et.Name}]: {ex.Message}";
                    }
                }

                _dcfFound    = found;
                _dcfLastRun  = DateTime.Now;
                _log.Info($"[DCF] Scan complete — {found} entity position(s) registered.");

                if (_dcfAutoLoop && !cts.Token.IsCancellationRequested)
                    await Task.Delay(_dcfRefreshMs, cts.Token).ContinueWith(_ => { });

            } while (_dcfAutoLoop && !cts.Token.IsCancellationRequested);

            _dcfRunning = false;
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // ENTITY TYPE REGISTRY (right sidebar)
    // ══════════════════════════════════════════════════════════════════════

    private void RenderEntityRegistry(float w)
    {
        ImGui.SetCursorPos(new Vector2(8, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("ENTITY TYPE REGISTRY");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        var dl  = ImGui.GetWindowDrawList();
        float sepY = ImGui.GetCursorScreenPos().Y;
        dl.AddLine(new Vector2(ImGui.GetWindowPos().X + 4, sepY),
                   new Vector2(ImGui.GetWindowPos().X + w - 4, sepY),
                   ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
        ImGui.Spacing();

        for (int i = 0; i < _entityTypes.Count; i++)
        {
            var et  = _entityTypes[i];
            bool sel = _editingType == i;

            // Row background for selected
            if (sel)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(w - 8, 22),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }

            // Color swatch
            ImGui.SetCursorPosX(8);
            ImGui.PushStyleColor(ImGuiCol.Button, et.Color);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, et.Color);
            ImGui.Button($"##etcol{i}", new Vector2(14, 14));
            ImGui.PopStyleColor(2);
            ImGui.SameLine(0, 6);

            // Enable checkbox
            bool en = et.Enabled;
            if (ImGui.Checkbox($"##eten{i}", ref en)) et.Enabled = en;
            ImGui.SameLine(0, 4);

            // Name (clickable to expand edit form)
            ImGui.PushStyleColor(ImGuiCol.Text,
                et.Enabled ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
            if (ImGui.Selectable($"{et.Name}##etsel{i}", sel,
                ImGuiSelectableFlags.None, new Vector2(w - 90, 20)))
                _editingType = sel ? -1 : i;
            ImGui.PopStyleColor();

            // Delete button
            ImGui.SameLine(w - 34);
            ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
            if (ImGui.Button($"✕##etdel{i}", new Vector2(22, 20)))
            {
                _entityTypes.RemoveAt(i);
                if (_editingType == i) _editingType = -1;
                i--;
            }
            ImGui.PopStyleColor(2);

            // Inline edit form for selected type
            if (sel && i < _entityTypes.Count)
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
                ImGui.BeginChild($"##etedit{i}", new Vector2(w - 10, 200), ImGuiChildFlags.Border);
                ImGui.PopStyleColor();
                ImGui.SetCursorPos(new Vector2(6, 6));

                ImGui.SetNextItemWidth(-1); ImGui.InputText($"Name##etn{i}", ref et.Name, 32);
                ImGui.SetNextItemWidth(-1); ImGui.InputText($"AOB Pattern##etp{i}", ref et.Pattern, 256);
                UiHelper.MutedLabel("Hex bytes with ?? wildcards");

                ImGui.SetNextItemWidth(90); ImGui.InputInt($"Pos offset##etpo{i}", ref et.PosOffset);
                ImGui.SameLine(0, 8); UiHelper.MutedLabel($"= 0x{et.PosOffset:X}  (byte offset to Vector3)");

                ImGui.SetNextItemWidth(90); ImGui.InputFloat($"Box W##etbw{i}", ref et.BoxWidth, 1f);
                ImGui.SameLine(0, 8);
                ImGui.SetNextItemWidth(90); ImGui.InputFloat($"Box H##etbh{i}", ref et.BoxHeight, 1f);

                float[] col4 = { et.Color.X, et.Color.Y, et.Color.Z, et.Color.W };
                if (ImGui.ColorEdit4($"Color##etc{i}", ref col4[0],
                    ImGuiColorEditFlags.NoInputs | ImGuiColorEditFlags.AlphaBar))
                    et.Color = new Vector4(col4[0], col4[1], col4[2], col4[3]);

                ImGui.EndChild();
            }

            ImGui.Spacing();
        }

        // Separator before add-new form
        ImGui.Spacing();
        var dl2 = ImGui.GetWindowDrawList();
        float sy2 = ImGui.GetCursorScreenPos().Y;
        dl2.AddLine(new Vector2(ImGui.GetWindowPos().X + 4, sy2),
                    new Vector2(ImGui.GetWindowPos().X + w - 4, sy2),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
        ImGui.Spacing();

        // Add new entity type
        ImGui.SetCursorPosX(8);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("ADD NEW TYPE");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        ImGui.SetCursorPosX(8);
        ImGui.SetNextItemWidth(w - 16); ImGui.InputText("Name##newn", ref _newName, 32);
        ImGui.SetCursorPosX(8);
        ImGui.SetNextItemWidth(w - 16); ImGui.InputText("Pattern##newp", ref _newPattern, 256);
        ImGui.SetCursorPosX(8);
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Offset##newoff", ref _newPosOffset);
        ImGui.SameLine(0, 8);
        float[] nc = { _newColor.X, _newColor.Y, _newColor.Z, _newColor.W };
        if (ImGui.ColorEdit4("##newcol", ref nc[0],
            ImGuiColorEditFlags.NoInputs | ImGuiColorEditFlags.AlphaBar))
            _newColor = new Vector4(nc[0], nc[1], nc[2], nc[3]);

        ImGui.SetCursorPosX(8);
        ImGui.BeginDisabled(string.IsNullOrWhiteSpace(_newName) || string.IsNullOrWhiteSpace(_newPattern));
        UiHelper.PrimaryButton("Add Type##addnew", w - 16, 26, () =>
        {
            _entityTypes.Add(new EntityTypeEntry
            {
                Name      = _newName,
                Pattern   = _newPattern,
                PosOffset = _newPosOffset,
                Color     = _newColor,
                Enabled   = true,
            });
            _log.Success($"[Visuals] Added entity type '{_newName}'.");
            _newName = "Custom"; _newPattern = ""; _newPosOffset = 0x30;
        });
        ImGui.EndDisabled();
    }

    // ══════════════════════════════════════════════════════════════════════
    // MANUAL ENTITY EDITOR
    // ══════════════════════════════════════════════════════════════════════

    private void RenderManualEditor(float w)
    {
        UiHelper.SectionBox("MANUAL OVERLAY ENTRY", w, 110, () =>
        {
            UiHelper.MutedLabel("Hand-add a world-space position for quick testing (no memory read needed).");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(90); ImGui.InputFloat("X##manx", ref _manX, 1f);
            ImGui.SameLine(0, 6);
            ImGui.SetNextItemWidth(90); ImGui.InputFloat("Y##many", ref _manY, 1f);
            ImGui.SameLine(0, 6);
            ImGui.SetNextItemWidth(90); ImGui.InputFloat("Z##manz", ref _manZ, 1f);
            ImGui.SameLine(0, 6);
            ImGui.SetNextItemWidth(100); ImGui.InputText("Label##manl", ref _manLabel, 32);
            ImGui.SameLine(0, 6);
            UiHelper.PrimaryButton("Add##manadd", 50, 22, () =>
            {
                lock (Application.EntityPositions)
                    Application.EntityPositions.Add(new EntityOverlayEntry
                    {
                        Position = new Vector3(_manX, _manY, _manZ),
                        Label    = _manLabel,
                    });
                _log.Info($"[Visuals] Manual entry added: {_manLabel} ({_manX:F1},{_manY:F1},{_manZ:F1})");
            });
        });
    }
}

// ── Entity type definition (mutable for inline editing) ───────────────────────

public class EntityTypeEntry
{
    public string  Name      { get; set; } = "";
    public string  Pattern   { get; set; } = "";
    public int     PosOffset { get; set; } = 0x30;
    public Vector4 Color     { get; set; } = new(0.18f, 0.95f, 0.45f, 0.9f);
    public bool    Enabled   { get; set; } = true;
    public float   BoxWidth  { get; set; } = 40f;
    public float   BoxHeight { get; set; } = 80f;
}
