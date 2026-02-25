using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Settings tab — hosts Keybinds section and future per-feature toggles.
///
/// Each hotkey button shows the current key label.  Clicking it enters
/// "press any key" capture mode; the next key (other than Escape) is bound
/// and persisted.  Escape cancels without changing anything.
/// </summary>
public class SettingsTab : ITab
{
    public string Title => "  Settings  ";

    private readonly TestLog _log;

    // Sub-tabs
    private int _subTab = 0;
    private static readonly string[] SubTabs = { "Keybinds", "Memory", "Display" };

    public SettingsTab(TestLog log) { _log = log; }

    // ══════════════════════════════════════════════════════════════════════
    // RENDER
    // ══════════════════════════════════════════════════════════════════════

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;

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
            case 0: RenderKeybinds(w); break;
            case 1: RenderMemorySettings(w); break;
            case 2: RenderDisplaySettings(w); break;
        }
    }

    // ── Keybinds ──────────────────────────────────────────────────────────

    private void RenderKeybinds(float w)
    {
        var cfg = GlobalHotkeyConfig.Instance;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##kbd_box", new Vector2(w, 220), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 8));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("KEYBINDS");
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 26));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted("Click a button to rebind.  Press Esc to cancel.");
        ImGui.PopStyleColor();
        ImGui.Spacing(); ImGui.Spacing();

        RenderKeyRow("Menu Toggle",   0, cfg.MenuToggleHotkey,
            "Show / hide the overlay window.", cfg);
        RenderKeyRow("Marker",        1, cfg.MarkerHotkey,
            "Place a position marker on the ESP overlay.", cfg);
        RenderKeyRow("Lock Target",   2, cfg.LockHotkey,
            "Lock the currently hovered item as the dupe target.", cfg);
        RenderKeyRow("Panic (Close)", 3, cfg.PanicHotkey,
            "Immediately close the application.", cfg);

        ImGui.Spacing();
        ImGui.SetCursorPosX(10);

        // Reset to defaults button
        ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColDanger with { W = 0.28f });
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColDanger with { W = 0.45f });
        ImGui.PushStyleColor(ImGuiCol.ButtonActive,  MenuRenderer.ColDanger with { W = 0.65f });
        if (ImGui.Button("Reset to Defaults##kbdreset", new Vector2(160, 26)))
        {
            cfg.ResetDefaults();
            _log.Info("[Settings] Hotkeys reset to defaults.");
        }
        ImGui.PopStyleColor(3);

        ImGui.EndChild();

        ImGui.Spacing();
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted("Keybinds are saved automatically to:");
        ImGui.TextUnformatted("  %AppData%\\HytaleSecurityTester\\hotkeys.json");
        ImGui.PopStyleColor();
    }

    private static void RenderKeyRow(string label, int slot, Silk.NET.Input.Key currentKey,
                                      string tooltip, GlobalHotkeyConfig cfg)
    {
        float rowW = ImGui.GetContentRegionAvail().X - 20;
        ImGui.SetCursorPosX(12);

        // Label
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColText);
        ImGui.TextUnformatted($"{label,-18}");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 8);

        bool isCapturing = cfg.IsCapturing && cfg.CaptureSlot == slot;

        if (isCapturing)
        {
            // Pulsing "press any key" button
            ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColWarn with { W = 0.35f });
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColWarn with { W = 0.55f });
            ImGui.PushStyleColor(ImGuiCol.ButtonActive,  MenuRenderer.ColWarn with { W = 0.75f });
            ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColWarn);
            if (ImGui.Button($"[ Press any key... ]##kbr{slot}", new Vector2(190, 24)))
                cfg.CancelCapture();   // click again = cancel
            ImGui.PopStyleColor(4);
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColAccentDim);
            ImGui.PushStyleColor(ImGuiCol.ButtonActive,  MenuRenderer.ColAccent with { W = 0.25f });
            ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColAccent);
            string keyLabel = $"[ {GlobalHotkeyConfig.KeyLabel(currentKey)} ]";
            if (ImGui.Button($"{keyLabel,-22}##kbr{slot}", new Vector2(190, 24)))
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

    // ── Memory Settings ───────────────────────────────────────────────────

    private void RenderMemorySettings(float w)
    {
        var au = AutoUpdateHandler.Instance;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##mem_set_box", new Vector2(w, 200), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 8));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("AUTO-UPDATE & AOB SCANNER");
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 26));

        // Version info
        if (!string.IsNullOrEmpty(au.CurrentGameHash))
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted($"Game build: {au.CurrentGameHash[..16]}…");
            if (au.WasUpdated)
            {
                ImGui.SameLine(0, 12);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted("  ⚠ Game was updated since last run");
                ImGui.PopStyleColor();
            }
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted("Game not attached — connect in Memory tab first.");
            ImGui.PopStyleColor();
        }

        ImGui.Spacing(); ImGui.Spacing();

        // Cached address status
        float col = 14;
        ImGui.SetCursorPosX(col);
        RenderAddrRow("EntityList",  au.EntityListAddr);
        ImGui.SetCursorPosX(col);
        RenderAddrRow("LocalPlayer", au.LocalPlayerAddr);
        ImGui.SetCursorPosX(col);
        RenderAddrRow("ItemList",    au.ItemListAddr);
        ImGui.SetCursorPosX(col);
        RenderAddrRow("HoverID",     au.HoverIdAddr);

        ImGui.Spacing();
        ImGui.SetCursorPosX(col);

        if (au.ScanRunning)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
            ImGui.TextUnformatted($"● Scanning… {au.ScanProgress}%  {au.ScanStatus}");
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColAccentDim);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColAccent with { W = 0.35f });
            ImGui.PushStyleColor(ImGuiCol.ButtonActive,  MenuRenderer.ColAccent with { W = 0.55f });
            ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColAccent);
            ImGui.TextUnformatted("[ Force Memory Rescan ] — attach in Memory tab first.");
            ImGui.PopStyleColor(4);
        }

        ImGui.EndChild();
    }

    private static void RenderAddrRow(string name, long addr)
    {
        bool found = addr != 0;
        ImGui.PushStyleColor(ImGuiCol.Text, found ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
        string addrStr = found ? $"0x{addr:X}" : "—";
        ImGui.TextUnformatted($"  {name,-14} {addrStr}");
        ImGui.PopStyleColor();
    }

    // ── Display Settings ──────────────────────────────────────────────────

    private void RenderDisplaySettings(float w)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##disp_set", new Vector2(w, 120), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 8));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("DISPLAY");
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 28));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted("Font scale, overlay opacity, and ESP options");
        ImGui.TextUnformatted("are controlled per-tab in Capture → ESP and Visuals.");
        ImGui.PopStyleColor();
        ImGui.EndChild();
    }
}
