using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

public class LogTab : ITab
{
    public string Title => "  Log  ";

    private readonly TestLog _log;
    private bool _autoScroll = true;

    public LogTab(TestLog log) => _log = log;

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;

        // Toolbar
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##ltb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));
        UiHelper.DangerButton("Clear##lc", 80, 22, () =>
        {
            _log.Clear(); _log.Info("Log cleared.");
        });
        ImGui.SameLine(0, 12);
        ImGui.Checkbox("Auto-scroll##as", ref _autoScroll);
        ImGui.SameLine(0, 16);
        UiHelper.MutedLabel("All test output appears here in real time.");
        ImGui.EndChild();

        ImGui.Spacing();

        // Log content — each line color-coded by severity
        float fh = ImGui.GetFrameHeightWithSpacing();
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##lb", new Vector2(0, -fh), ImGuiChildFlags.Border,
            ImGuiWindowFlags.HorizontalScrollbar);
        ImGui.PopStyleColor();

        string text = _log.GetText();
        foreach (var line in text.Split('\n'))
        {
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

        if (_autoScroll) ImGui.SetScrollHereY(1.0f);

        ImGui.EndChild();
    }
}
