using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Settings tab - Keybinds, Memory/AOB, Display.
///
/// v3 fixes:
///  - All Unicode glyphs replaced with ASCII (renders correctly with default ImGui font).
///  - Force Memory Rescan is a real ImGui.Button (not TextUnformatted).
///  - "Build changed" banner shows Dismiss button; clears after scan.
///  - Pattern Editor: user can view and override every AOB signature.
///  - Status bar shows live keybind labels from GlobalHotkeyConfig.
///  - Hotkey buttons pulse amber during capture mode.
///  - Open Config Folder button opens explorer to %AppData%\HytaleSecurityTester.
/// </summary>
public class SettingsTab : ITab
{
    public string Title => "  Settings  ";

    private readonly TestLog _log;

    private int _subTab = 0;
    private static readonly string[] SubTabs = { "Keybinds", "Memory", "Display" };

    // For hotkey button pulse animation
    private float _flashTimer = 0f;

    // Pattern editor state
    private string   _editKey        = "";   // which signature we're editing
    private string   _editPattern    = "";   // text field content
    private string   _editMsg        = "";   // feedback after save/reset

    // Auto-discover state
    private string   _discoverKey     = "";   // which sig is being discovered
    private bool     _discoverRunning = false;
    private List<PatternCandidate> _discoverResults = new();
    private readonly object _discoverLock = new();  // guards _discoverResults across bg thread
    private string   _discoverStatus  = "";   // progress/result message

    public SettingsTab(TestLog log) { _log = log; }

    // ══════════════════════════════════════════════════════════════════════
    // RENDER
    // ══════════════════════════════════════════════════════════════════════

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;
        _flashTimer += ImGui.GetIO().DeltaTime;

        RenderStatusBar(w);
        ImGui.Spacing();

        if (ImGui.BeginTabBar("##set_tabs", ImGuiTabBarFlags.None))
        {
            for (int i = 0; i < SubTabs.Length; i++)
                if (ImGui.TabItemButton(SubTabs[i] + $"##sett{i}"))
                    _subTab = i;
            ImGui.EndTabBar();
        }

        ImGui.Spacing();

        switch (_subTab)
        {
            case 0: RenderKeybinds(w);        break;
            case 1: RenderMemorySettings(w);  break;
            case 2: RenderDisplaySettings(w); break;
        }
    }

    // ── Status bar ────────────────────────────────────────────────────────

    private static void RenderStatusBar(float w)
    {
        var cfg = GlobalHotkeyConfig.Instance;
        bool att = SharedMemoryReader.IsAttached;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##set_statbar", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 6));

        ImGui.PushStyleColor(ImGuiCol.Text, att ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(att
            ? $"[>] Attached: {SharedMemoryReader.ProcessName} (PID {SharedMemoryReader.Pid})"
            : "[!] Not attached - attach in Memory tab");
        ImGui.PopStyleColor();

        // Live keybind summary - shows current bindings, not hardcoded text
        ImGui.SameLine(0, 20);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(
            $"Toggle:[{GlobalHotkeyConfig.KeyLabel(cfg.MenuToggleHotkey)}]  " +
            $"Marker:[{GlobalHotkeyConfig.KeyLabel(cfg.MarkerHotkey)}]  " +
            $"Lock:[{GlobalHotkeyConfig.KeyLabel(cfg.LockHotkey)}]  " +
            $"Panic:[{GlobalHotkeyConfig.KeyLabel(cfg.PanicHotkey)}]");
        ImGui.PopStyleColor();

        ImGui.EndChild();
    }

    // ── Keybinds tab ──────────────────────────────────────────────────────

    private void RenderKeybinds(float w)
    {
        var cfg = GlobalHotkeyConfig.Instance;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##kbd_box", new Vector2(w, 240), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(10, 8));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("KEYBINDS");
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 26));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted("Click a button to enter capture mode. Press the new key. Esc cancels.");
        ImGui.PopStyleColor();

        ImGui.SetCursorPosY(48);
        ImGui.Spacing();

        RenderKeyRow("Menu Toggle",   0, cfg.MenuToggleHotkey, "Show/hide the overlay.", cfg);
        RenderKeyRow("Marker",        1, cfg.MarkerHotkey,     "Place a position marker on ESP.", cfg);
        RenderKeyRow("Lock Target",   2, cfg.LockHotkey,       "Lock hovered item as dupe target.", cfg);
        RenderKeyRow("Panic (Close)", 3, cfg.PanicHotkey,      "Instantly close the application.", cfg);

        ImGui.Spacing(); ImGui.Spacing();
        ImGui.SetCursorPosX(10);

        // Reset to Defaults
        ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColDanger with { W = 0.28f });
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColDanger with { W = 0.45f });
        ImGui.PushStyleColor(ImGuiCol.ButtonActive,  MenuRenderer.ColDanger with { W = 0.65f });
        if (ImGui.Button("Reset to Defaults##kbdreset", new Vector2(160, 26)))
        {
            cfg.ResetDefaults();
            _log.Info("[Settings] Hotkeys reset to defaults.");
        }
        ImGui.PopStyleColor(3);
        ImGui.SameLine(0, 12);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted("Saved to config.json on every change.");
        ImGui.PopStyleColor();

        ImGui.EndChild();
        ImGui.Spacing();
        RenderOpenFolderButton(w);
    }

    private void RenderKeyRow(string label, int slot, Silk.NET.Input.Key currentKey,
                               string tooltip, GlobalHotkeyConfig cfg)
    {
        ImGui.SetCursorPosX(12);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColText);
        ImGui.TextUnformatted($"{label,-18}");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 8);

        bool capturing = cfg.IsCapturing && cfg.CaptureSlot == slot;

        if (capturing)
        {
            // Amber pulse during capture mode
            float pulse = 0.35f + 0.20f * MathF.Abs(MathF.Sin(_flashTimer * 4.5f));
            ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColWarn with { W = pulse });
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColWarn with { W = pulse + 0.15f });
            ImGui.PushStyleColor(ImGuiCol.ButtonActive,  MenuRenderer.ColWarn with { W = 0.80f });
            ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColWarn);
            if (ImGui.Button($"[ PRESS ANY KEY... ]##kbr{slot}", new Vector2(200, 26)))
                cfg.CancelCapture();
            ImGui.PopStyleColor(4);
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColAccentDim);
            ImGui.PushStyleColor(ImGuiCol.ButtonActive,  MenuRenderer.ColAccent with { W = 0.30f });
            ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColAccent);
            if (ImGui.Button($"[ {GlobalHotkeyConfig.KeyLabel(currentKey),-16} ]##kbr{slot}",
                             new Vector2(200, 26)))
                cfg.BeginCapture(slot);
            ImGui.PopStyleColor(4);
        }

        if (ImGui.IsItemHovered())
        {
            ImGui.BeginTooltip();
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted(tooltip);
            ImGui.PopStyleColor();
            ImGui.EndTooltip();
        }
    }

    // ── Memory/AOB tab ────────────────────────────────────────────────────

    private void RenderMemorySettings(float w)
    {
        var au  = AutoUpdateHandler.Instance;
        bool att = SharedMemoryReader.IsAttached;

        // ── Attach + build status box ──────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##mem_status", new Vector2(w, 110), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(10, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("GAME ATTACHMENT");
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 24));

        if (att)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
            ImGui.TextUnformatted($"[>] Attached: {SharedMemoryReader.ProcessName}  (PID {SharedMemoryReader.Pid})");
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
            ImGui.TextUnformatted("[!] Not attached - use Memory tab -> Quick Attach -> HytaleClient");
            ImGui.PopStyleColor();
        }

        // Build hash line
        if (!string.IsNullOrEmpty(au.CurrentGameHash))
        {
            ImGui.SetCursorPosX(10);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            string hashShort = au.CurrentGameHash[..Math.Min(16, au.CurrentGameHash.Length)];
            ImGui.TextUnformatted($"Build hash: {hashShort}...");
            ImGui.PopStyleColor();
        }

        // Build-changed banner
        if (au.WasUpdated)
        {
            ImGui.SetCursorPosX(10);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
            ImGui.TextUnformatted("[!] Build changed since last run - re-scan recommended.");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 8);
            ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColWarnDim);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColWarn with { W = 0.30f });
            ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColWarn);
            if (ImGui.Button("Dismiss##dismisswarn", new Vector2(70, 20)))
                au.DismissUpdateWarning();
            ImGui.PopStyleColor(3);
        }

        // Scan summary
        if (!string.IsNullOrEmpty(au.ScanSummary))
        {
            ImGui.SetCursorPosX(10);
            bool allFound = au.ScanSummary.StartsWith("4/");
            ImGui.PushStyleColor(ImGuiCol.Text,
                allFound ? MenuRenderer.ColAccent : MenuRenderer.ColWarn);
            ImGui.TextUnformatted($"Last scan: {au.ScanSummary}");
            ImGui.PopStyleColor();
        }

        ImGui.EndChild();
        ImGui.Spacing();

        // ── AOB address table ──────────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##aob_addrs", new Vector2(w, 110), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(10, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("RESOLVED ADDRESSES");
        ImGui.PopStyleColor();

        float col = 12f;
        ImGui.SetCursorPos(new Vector2(col, 24));
        RenderAddrRow("EntityList",      au.EntityListAddr);
        ImGui.SetCursorPosX(col);
        RenderAddrRow("LocalPlayer",     au.LocalPlayerAddr);
        ImGui.SetCursorPosX(col);
        RenderAddrRow("ItemList",        au.ItemListAddr);
        ImGui.SetCursorPosX(col);
        RenderAddrRow("HoverID",         au.HoverIdAddr);
        ImGui.SetCursorPosX(col);
        RenderAddrRow("OnChat",          au.OnChatFuncAddr);
        ImGui.SetCursorPosX(col);
        RenderAddrRow("SetCursorHidden", au.SetCursorHiddenAddr);
        ImGui.SetCursorPosX(col);
        RenderAddrRow("DoMoveCycle",     au.DoMoveCycleAddr);

        ImGui.EndChild();
        ImGui.Spacing();

        // ── Force Rescan button ────────────────────────────────────────────
        if (au.ScanRunning)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
            ImGui.TextUnformatted($"[>] {au.ScanStatus}");
            ImGui.PopStyleColor();
            ImGui.SetNextItemWidth(w);
            ImGui.ProgressBar(au.ScanProgress / 100f, new Vector2(w, 18),
                $"{au.ScanProgress}%  {au.ScanStatus}");
        }
        else
        {
            bool canScan = att;
            if (!canScan) ImGui.BeginDisabled();

            ImGui.PushStyleColor(ImGuiCol.Button,
                canScan ? MenuRenderer.ColAccentDim : MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered,
                canScan ? MenuRenderer.ColAccent with { W = 0.35f } : MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.ButtonActive,
                canScan ? MenuRenderer.ColAccent with { W = 0.60f } : MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text,
                canScan ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);

            if (ImGui.Button("[ Force Memory Rescan ]##fmrescan", new Vector2(220, 28)))
            {
                _log.Info("[Settings] Force Memory Rescan - started.");
                _log.Info($"[Settings] Target: {SharedMemoryReader.ProcessName} PID {SharedMemoryReader.Pid}");
                _ = au.ForceRescanAsync();
            }

            ImGui.PopStyleColor(4);
            if (!canScan)
            {
                ImGui.EndDisabled();
                ImGui.SameLine(0, 8);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                ImGui.TextUnformatted("<- attach to HytaleClient first");
                ImGui.PopStyleColor();
            }
            else if (!string.IsNullOrEmpty(au.ScanStatus) && au.ScanStatus != "Not scanned yet.")
            {
                ImGui.SameLine(0, 8);
                bool ok = au.ScanStatus.Contains("Done") && !au.ScanStatus.Contains("0/");
                ImGui.PushStyleColor(ImGuiCol.Text,
                    ok ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
                ImGui.TextUnformatted(au.ScanStatus);
                ImGui.PopStyleColor();
            }
        }

        ImGui.Spacing(); ImGui.Spacing();

        // ── Pattern Editor ─────────────────────────────────────────────────
        RenderPatternEditor(w, au);

        ImGui.Spacing();
        RenderOpenFolderButton(w);
    }

    // ── Pattern Editor ────────────────────────────────────────────────────

    private void RenderPatternEditor(float w, AutoUpdateHandler au)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        float edH = 220f;
        ImGui.BeginChild("##pat_editor", new Vector2(w, edH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(10, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("PATTERN EDITOR");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 10);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
        ImGui.TextUnformatted("[*] Discover");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 4);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted("= auto-find pattern from live memory. No Cheat Engine needed.");
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(10, 22));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted("Format: space-separated hex bytes.  ?? = wildcard.  " +
            "Example:  48 89 05 ?? ?? ?? ?? 48 8B");
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(10, 38));

        float btnW  = 80f;
        float entW  = w - 20 - btnW - 4;

        // One row per signature
        foreach (var sigName in au.SignatureNames)
        {
            string effective = au.GetEffectivePattern(sigName);
            string builtin   = au.GetBuiltInPattern(sigName);
            bool   custom    = au.UserSignatures.ContainsKey(sigName);

            // Label
            ImGui.SetCursorPosX(10);
            ImGui.PushStyleColor(ImGuiCol.Text,
                custom ? MenuRenderer.ColWarn : MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted($"{sigName + (custom ? " [custom]" : ""),-24}");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 4);

            // Select-to-edit
            bool isEditing = _editKey == sigName;
            if (isEditing)
            {
                ImGui.SetNextItemWidth(entW - 100);
                if (ImGui.InputText($"##pat_{sigName}", ref _editPattern, 200))
                { }

                ImGui.SameLine(0, 4);

                // Save button
                ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColAccentDim);
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColAccent with { W = 0.35f });
                ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColAccent);
                if (ImGui.Button($"Save##patsave_{sigName}", new Vector2(48, 20)))
                {
                    au.SetUserPattern(sigName, _editPattern);
                    _editMsg = $"Saved. Run Force Rescan to apply.";
                    _editKey = "";
                }
                ImGui.PopStyleColor(3);
                ImGui.SameLine(0, 3);

                // Reset to built-in
                if (!string.IsNullOrEmpty(builtin))
                {
                    ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColDanger with { W = 0.22f });
                    ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColDanger with { W = 0.38f });
                    ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColDanger);
                    if (ImGui.Button($"Reset##patreset_{sigName}", new Vector2(46, 20)))
                    {
                        au.SetUserPattern(sigName, "");  // clears override
                        _editMsg = $"Reset to built-in pattern.";
                        _editKey = "";
                    }
                    ImGui.PopStyleColor(3);
                    ImGui.SameLine(0, 3);
                }

                // Cancel
                ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColBg3);
                ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColTextMuted);
                if (ImGui.Button($"Cancel##patcancel_{sigName}", new Vector2(50, 20)))
                    _editKey = "";
                ImGui.PopStyleColor(2);
            }
            else
            {
                // Show effective pattern (truncated if long)
                string display = effective.Length > 52 ? effective[..52] + "..." : effective;
                ImGui.PushStyleColor(ImGuiCol.Text,
                    custom ? MenuRenderer.ColWarn : MenuRenderer.ColTextMuted);
                ImGui.TextUnformatted($"{display}");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 6);

                ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColBg3);
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColAccentDim);
                ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColAccent);
                if (ImGui.Button($"Edit##patedit_{sigName}", new Vector2(40, 18)))
                {
                    _editKey     = sigName;
                    _editPattern = effective;
                    _editMsg     = "";
                }
                ImGui.PopStyleColor(3);

                // ── Auto-Discover button ──────────────────────────────────
                ImGui.SameLine(0, 4);
                bool discovering = _discoverKey == sigName && _discoverRunning;
                if (discovering) ImGui.BeginDisabled();
                ImGui.PushStyleColor(ImGuiCol.Button,        new Vector4(0.08f, 0.25f, 0.12f, 1f));
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.08f, 0.25f, 0.12f, 0.6f));
                ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColAccent);
                if (ImGui.Button($"{(discovering ? "..." : "[*] Discover")}##padis_{sigName}",
                    new Vector2(discovering ? 28 : 90, 18)))
                {
                    _discoverKey     = sigName;
                    _discoverResults.Clear();
                    _discoverStatus  = "Scanning...";
                    _discoverRunning = true;
                    _editMsg         = "";

                    var reader = SharedMemoryReader.Instance;
                    Task.Run(() =>
                    {
                        var results = AutoUpdateHandler.Instance
                                          .AutoDiscoverCandidates(sigName, reader);
                        lock (_discoverLock) { _discoverResults = results; }
                        _discoverStatus  = results.Count > 0
                            ? $"{results.Count} candidate(s) found - click 'Use This' to apply"
                            : "No candidates found. Game must be running.";
                        _discoverRunning = false;
                    });
                }
                ImGui.PopStyleColor(3);
                if (discovering) ImGui.EndDisabled();
            }
        }

        // Feedback message
        if (!string.IsNullOrEmpty(_editMsg))
        {
            ImGui.Spacing();
            ImGui.SetCursorPosX(10);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
            ImGui.TextUnformatted(_editMsg);
            ImGui.PopStyleColor();
        }

        ImGui.EndChild();

        // ── Auto-Discover results panel ───────────────────────────────────
        RenderDiscoverPanel(w, au);
    }

    private void RenderDiscoverPanel(float w, AutoUpdateHandler au)
    {
        if (string.IsNullOrEmpty(_discoverKey) && _discoverResults.Count == 0)
            return;

        ImGui.Spacing();
        float panelH = _discoverResults.Count > 0
            ? Math.Clamp(_discoverResults.Count * 52f + 50f, 80f, 340f)
            : 44f;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, new System.Numerics.Vector4(0.06f, 0.10f, 0.07f, 1f));
        ImGui.BeginChild("##discover_panel", new System.Numerics.Vector2(w, panelH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new System.Numerics.Vector2(10, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted($"AUTO-DISCOVER: {_discoverKey}");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 12);
        ImGui.PushStyleColor(ImGuiCol.Text,
            _discoverRunning ? MenuRenderer.ColWarn : MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(_discoverRunning ? "[scanning...]" : _discoverStatus);
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 10);
        if (ImGui.SmallButton("Clear##disclear"))
        {
            _discoverKey     = "";
            lock (_discoverLock) { _discoverResults.Clear(); }
            _discoverStatus  = "";
        }

        ImGui.Spacing();

        if (_discoverResults.Count == 0 && !_discoverRunning)
        {
            ImGui.SetCursorPosX(10);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
            ImGui.TextUnformatted("No candidates found. Game must be running and attached.");
            ImGui.PopStyleColor();
        }

        // ── THREAD-SAFETY: snapshot under lock before iteration ────────
        List<PatternCandidate> snapshot;
        lock (_discoverLock) { snapshot = new List<PatternCandidate>(_discoverResults); }

        int rank = 1;
        foreach (var cand in snapshot)
        {
            // Score badge
            ImGui.PushStyleColor(ImGuiCol.Text, cand.ScoreColor);
            ImGui.SetCursorPosX(10);
            ImGui.TextUnformatted($"{cand.ScoreLabel} #{rank}");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 8);

            // Short description
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted($"instr@0x{cand.InstrAddr:X}  {cand.Description}");
            ImGui.PopStyleColor();

            // Pattern preview
            ImGui.SetCursorPosX(20);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
            ImGui.TextUnformatted(cand.ShortPattern);
            ImGui.PopStyleColor();

            // Action buttons
            ImGui.SameLine(0, 10);
            ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColAccentDim);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColAccent with { W = 0.35f });
            ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColAccent);
            if (ImGui.Button($"Use This##duse{rank}", new System.Numerics.Vector2(76, 18)))
            {
                au.SetUserPattern(cand.SignatureName, cand.Pattern);
                _editMsg         = $"Pattern for '{cand.SignatureName}' set from discovery. Run Force Rescan.";
                _discoverKey     = "";
                lock (_discoverLock) { _discoverResults.Clear(); }
                _discoverStatus  = "";
                _log.Success($"[AutoDiscover] Applied pattern for {cand.SignatureName}: {cand.Pattern}");
            }
            ImGui.PopStyleColor(3);
            ImGui.SameLine(0, 4);
            ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColTextMuted);
            if (ImGui.Button($"Copy##dcop{rank}", new System.Numerics.Vector2(44, 18)))
                WindowsClipboard.Set(cand.Pattern);
            ImGui.PopStyleColor(2);

            ImGui.Spacing();
            rank++;
        }

        ImGui.EndChild();
    }

    private static void RenderAddrRow(string name, long addr)
    {
        bool found = addr != 0;
        ImGui.PushStyleColor(ImGuiCol.Text, found ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted($"  {name,-14}  {(found ? $"0x{addr:X}" : "---")}");
        ImGui.PopStyleColor();
    }

    // ── Open Config Folder ────────────────────────────────────────────────

    private void RenderOpenFolderButton(float w)
    {
        ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColBg3);
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColAccentDim);
        ImGui.PushStyleColor(ImGuiCol.ButtonActive,  MenuRenderer.ColAccent with { W = 0.35f });
        ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColAccent);
        if (ImGui.Button("[ Open Config Folder ]##opencfg", new Vector2(200, 26)))
        {
            GlobalConfig.OpenConfigFolder();
            _log.Info($"[Settings] Opened: {GlobalConfig.ConfigDir}");
        }
        ImGui.PopStyleColor(4);
        ImGui.SameLine(0, 8);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(GlobalConfig.ConfigDir);
        ImGui.PopStyleColor();
    }

    // ── Display Settings ──────────────────────────────────────────────────

    private void RenderDisplaySettings(float w)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##disp_set", new Vector2(w, 100), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 8));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("DISPLAY");
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 28));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted("Font scale and ESP options are in the Visuals tab.");
        ImGui.TextUnformatted("Overlay opacity is in Capture -> Analysis.");
        ImGui.PopStyleColor();
        ImGui.EndChild();
    }
}
