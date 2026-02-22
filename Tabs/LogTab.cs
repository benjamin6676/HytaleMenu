using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Scrollable log viewer showing all test output.
/// </summary>
public class LogTab : ITab
{
    public string Title => "  Log  ";

    private readonly TestLog _log;
    private bool _autoScroll = true;

    public LogTab(TestLog log) => _log = log;

    public void Render()
    {
        ImGui.Spacing();

        // Toolbar
        if (ImGui.Button("Clear##logclear"))
        {
            _log.Clear();
            _log.Info("Log cleared.");
        }
        ImGui.SameLine();
        ImGui.Checkbox("Auto-scroll##as", ref _autoScroll);
        ImGui.SameLine();
        ImGui.TextDisabled("|  All test output appears here.");
        ImGui.Separator();

        // Log body
        float footerHeight = ImGui.GetStyle().ItemSpacing.Y + ImGui.GetFrameHeightWithSpacing();
        ImGui.BeginChild("##logscroll",
            new Vector2(0, -footerHeight),
            ImGuiChildFlags.None,
            ImGuiWindowFlags.HorizontalScrollbar);

        ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.7f, 1.0f, 0.7f, 1f));

        string text = _log.GetText();
        ImGui.TextUnformatted(text);

        ImGui.PopStyleColor();

        if (_autoScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 20)
            ImGui.SetScrollHereY(1.0f);

        ImGui.EndChild();
    }
}
