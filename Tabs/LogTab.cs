using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

public class LogTab : ITab
{
    public string Title => "  Log  ";

    private readonly TestLog   _log;
    private readonly PacketLog _pktLog;

    private bool _autoScrollGeneral = true;
    private bool _autoScrollPackets = true;
    private bool _showCS            = true;
    private bool _showSC            = true;
    private bool _showInjected      = true;

    public LogTab(TestLog log, PacketLog pktLog)
    {
        _log    = log;
        _pktLog = pktLog;
    }

    public void Render()
    {
        float w  = ImGui.GetContentRegionAvail().X;
        float h  = ImGui.GetContentRegionAvail().Y;
        float topH = h * 0.45f;
        float botH = h * 0.50f;

        RenderGeneralLog(w, topH);
        ImGui.Spacing();
        RenderPacketFeed(w, botH);
    }

    private void RenderGeneralLog(float w, float h)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##ltb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("GENERAL LOG");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 20);
        UiHelper.DangerButton("Clear##lgc", 70, 22, () =>
        {
            _log.Clear(); _log.Info("Log cleared.");
        });
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("Auto-scroll##lgas", ref _autoScrollGeneral);
        ImGui.SameLine(0, 16);
        UiHelper.MutedLabel("Test results, errors, dupe output — no packet spam.");
        ImGui.EndChild();

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##lgb", new Vector2(w, h - 34),
            ImGuiChildFlags.Border, ImGuiWindowFlags.HorizontalScrollbar);
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
        if (_autoScrollGeneral) ImGui.SetScrollHereY(1.0f);
        ImGui.EndChild();
    }

    private void RenderPacketFeed(float w, float h)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##lptb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 4));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("PACKET TRAFFIC");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 20);
        UiHelper.DangerButton("Clear##lpc", 70, 22, () => _pktLog.Clear());
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("Auto-scroll##lpas", ref _autoScrollPackets);
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("C\u2192S##lpcs", ref _showCS);
        ImGui.SameLine(0, 6);
        ImGui.Checkbox("S\u2192C##lpsc", ref _showSC);
        ImGui.SameLine(0, 6);
        ImGui.Checkbox("Injected##lpinj", ref _showInjected);
        var entries = _pktLog.GetEntries();
        ImGui.SameLine(0, 16);
        UiHelper.MutedLabel($"{entries.Count} packets");
        ImGui.EndChild();

        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.06f, 0.08f, 0.07f, 1f));
        ImGui.BeginChild("##lpb", new Vector2(w, h - 34),
            ImGuiChildFlags.Border, ImGuiWindowFlags.HorizontalScrollbar);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 4));
        UiHelper.MutedLabel("   Time            Dir    Bytes  INJ   Hex preview");
        var dl = ImGui.GetWindowDrawList();
        var lp = ImGui.GetWindowPos();
        float ly = ImGui.GetCursorScreenPos().Y - 2;
        dl.AddLine(new Vector2(lp.X, ly), new Vector2(lp.X + w, ly),
            ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        foreach (var e in entries)
        {
            bool cs = e.Direction == PacketDirection.ClientToServer;
            if (!_showCS && cs)  continue;
            if (!_showSC && !cs) continue;
            if (!_showInjected && e.Injected) continue;

            var col = e.Injected ? MenuRenderer.ColWarn
                    : cs         ? MenuRenderer.ColBlue
                    :              MenuRenderer.ColAccent;

            string injTag = e.Injected ? "INJ" : "   ";
            ImGui.PushStyleColor(ImGuiCol.Text, col);
            ImGui.TextUnformatted(
                $"   {e.TimeLabel}  {e.DirectionLabel,-5}  {e.ByteLength,5}b  {injTag}  {e.HexPreview}");
            ImGui.PopStyleColor();
        }

        if (_autoScrollPackets) ImGui.SetScrollHereY(1.0f);
        ImGui.EndChild();
    }
}
