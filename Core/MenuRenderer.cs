using ImGuiNET;
using HytaleSecurityTester.Tabs;
using System.Numerics;

namespace HytaleSecurityTester.Core;

public class MenuRenderer
{
    private readonly TestLog              _log;
    private readonly PacketLog            _pktLog;
    private readonly ServerConfig         _config;
    private readonly PacketStore          _store;
    private readonly ServerStats          _stats;
    private readonly ResponseTracker      _tracker;
    private readonly CaptureTab           _captureTab;
    private readonly DashboardTab         _dashboardTab;
    private readonly PacketTab            _packetTab;
    private readonly DupingTab            _dupingTab;
    private readonly PrivilegeTab         _privilegeTab;
    private readonly ItemInspectorTab     _itemInspectorTab;
    private readonly PacketBookTab        _packetBookTab;
    private readonly ResponseAnalyserTab  _responseAnalyserTab;
    private readonly DiffAnalysisTab      _diffAnalysisTab;
    private readonly LogTab               _logTab;
    private readonly MemoryTab            _memoryTab;
    private readonly VisualsTab           _visualsTab;
    private readonly SmartDetectionEngine _smartDetect;

    private int _selectedSection = 0;

    // 9 sidebar sections (merged from 13)
    // Dashboard absorbs: Log
    // Packets absorbs:   Response Analyser
    // Capture absorbs:   Diff Analysis
    // Connection tab removed (its features live in Dashboard > Connection sub-tab)
    private static readonly (string Icon, string Short, string Full)[] Sections = {
        ("⌂", "Dashboard",  "Dashboard"),
        ("⚡", "Packets",    "Packet Exploiting"),
        ("◈", "Duping",     "Dupe Methods"),
        ("◎", "Capture",    "Capture & Analysis"),
        ("▲", "Privilege",  "Privilege Escalation"),
        ("⊙", "Inspector",  "Item Inspector"),
        ("◫", "Book",       "Packet Book"),
        ("≡", "Memory",     "Memory Reader"),
        ("👁️", "Visuals", "Visuals / ESP"),
    };

    // Palette
    public static readonly Vector4 ColAccent       = new(0.18f, 0.95f, 0.45f, 1.00f);
    public static readonly Vector4 ColAccentDim    = new(0.18f, 0.95f, 0.45f, 0.18f);
    public static readonly Vector4 ColAccentMid    = new(0.18f, 0.95f, 0.45f, 0.55f);
    public static readonly Vector4 ColWarn         = new(0.95f, 0.75f, 0.10f, 1.00f);
    public static readonly Vector4 ColWarnDim      = new(0.95f, 0.75f, 0.10f, 0.15f);
    public static readonly Vector4 ColDanger       = new(0.95f, 0.28f, 0.22f, 1.00f);
    public static readonly Vector4 ColDangerDim    = new(0.95f, 0.28f, 0.22f, 0.15f);
    public static readonly Vector4 ColBlue         = new(0.28f, 0.72f, 1.00f, 1.00f);
    public static readonly Vector4 ColBlueDim      = new(0.28f, 0.72f, 1.00f, 0.15f);
    public static readonly Vector4 ColText         = new(0.88f, 0.95f, 0.88f, 1.00f);
    public static readonly Vector4 ColTextMuted    = new(0.45f, 0.55f, 0.48f, 1.00f);
    public static readonly Vector4 ColBg0          = new(0.07f, 0.08f, 0.08f, 1.00f);
    public static readonly Vector4 ColBg1          = new(0.09f, 0.11f, 0.10f, 1.00f);
    public static readonly Vector4 ColBg2          = new(0.12f, 0.14f, 0.13f, 1.00f);
    public static readonly Vector4 ColBg3          = new(0.15f, 0.18f, 0.16f, 1.00f);
    public static readonly Vector4 ColBorder       = new(0.18f, 0.95f, 0.45f, 0.22f);
    public static readonly Vector4 ColBorderBright = new(0.18f, 0.95f, 0.45f, 0.55f);

    /// <summary>Exposed so CaptureTab can send packets directly to diff slots.</summary>
    public DiffAnalysisTab DiffAnalysis => _diffAnalysisTab;

    public MenuRenderer()
    {
        _log     = new TestLog();
        _pktLog  = new PacketLog(2000);
        _config  = new ServerConfig();
        _store   = new PacketStore();
        _stats   = new ServerStats(_log);
        _tracker = new ResponseTracker();

        _captureTab = new CaptureTab(_log, _pktLog, _config);
        _captureTab.UdpProxy.OnPacket += _stats.OnPacket;
        _captureTab.UdpProxy.OnPacket += _tracker.Feed;
        _captureTab.Capture.OnPacket  += _tracker.Feed;
        _captureTab.Capture.OnPacket  += _stats.OnPacket;

        _dashboardTab        = new DashboardTab(_log, _config, _stats);
        _packetTab           = new PacketTab(_log, _captureTab.Capture, _captureTab.UdpProxy, _config);
        _dupingTab           = new DupingTab(_log, _captureTab.UdpProxy, _captureTab.Capture, _store, _config);
        _privilegeTab        = new PrivilegeTab(_log, _captureTab.Capture, _captureTab.UdpProxy, _config, _store);
        _smartDetect         = new SmartDetectionEngine(_captureTab.Capture, _store, _log, _config);
        _itemInspectorTab    = new ItemInspectorTab(_log, _captureTab.Capture, _captureTab.UdpProxy,
                                   _store, _config, _smartDetect);
        _packetBookTab       = new PacketBookTab(_log, _store, _captureTab.UdpProxy, _captureTab.Capture, _config);
        _responseAnalyserTab = new ResponseAnalyserTab(_log, _tracker, _captureTab.Capture,
                                   _captureTab.UdpProxy, _store, _config);
        _diffAnalysisTab     = new DiffAnalysisTab(_log, _store, _captureTab.Capture);
        _captureTab.SetDiffTab(_diffAnalysisTab);
        _logTab              = new LogTab(_log, _pktLog);
        _memoryTab           = new MemoryTab(_log, _store, _config);
        _visualsTab          = new VisualsTab(_log, _config, _smartDetect);
    }

    public void Render()
    {
        var io      = ImGui.GetIO();
        var display = io.DisplaySize;

        ImGui.SetNextWindowPos(Vector2.Zero);
        ImGui.SetNextWindowSize(display);
        ImGui.SetNextWindowBgAlpha(0f);

        var outerFlags =
            ImGuiWindowFlags.NoTitleBar   | ImGuiWindowFlags.NoResize  |
            ImGuiWindowFlags.NoMove       | ImGuiWindowFlags.NoCollapse |
            ImGuiWindowFlags.NoBringToFrontOnFocus | ImGuiWindowFlags.NoScrollbar;

        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, Vector2.Zero);
        ImGui.PushStyleColor(ImGuiCol.WindowBg, ColBg0);
        ImGui.Begin("##Root", outerFlags);
        ImGui.PopStyleColor();
        ImGui.PopStyleVar();

        const float SideW = 110f;
        float totalH   = display.Y;
        float contentW = display.X - SideW;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, ColBg1);
        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, Vector2.Zero);
        ImGui.BeginChild("##Sidebar", new Vector2(SideW, totalH),
            ImGuiChildFlags.None, ImGuiWindowFlags.NoScrollbar);
        ImGui.PopStyleVar();
        ImGui.PopStyleColor();
        RenderSidebar(SideW, totalH);
        ImGui.EndChild();

        ImGui.SameLine(0, 0);

        ImGui.PushStyleColor(ImGuiCol.ChildBg, ColBg0);
        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(20, 16));
        ImGui.BeginChild("##Content", new Vector2(contentW, totalH), ImGuiChildFlags.None);
        ImGui.PopStyleVar();
        ImGui.PopStyleColor();
        RenderTopBar();
        RenderContent();
        ImGui.EndChild();

        ImGui.End();
    }

    private void RenderSidebar(float sideW, float totalH)
    {
        var dl = ImGui.GetWindowDrawList();
        var wp = ImGui.GetWindowPos(); // screen-space, no offset issues

        // Top green bar
        dl.AddRectFilled(wp, wp + new Vector2(sideW, 3),
            ImGui.ColorConvertFloat4ToU32(ColAccent));

        // Logo
        ImGui.SetCursorPos(new Vector2(14, 14));
        ImGui.PushStyleColor(ImGuiCol.Text, ColAccent);
        ImGui.TextUnformatted("HST");
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(14, 32));
        ImGui.PushStyleColor(ImGuiCol.Text, ColTextMuted);
        ImGui.TextUnformatted("v8.0");
        ImGui.PopStyleColor();

        // Server status strip
        bool connected = _config.IsSet;
        ImGui.SetCursorPosY(54);
        var sp = ImGui.GetCursorScreenPos();
        dl.AddRectFilled(sp, sp + new Vector2(sideW, 26),
            ImGui.ColorConvertFloat4ToU32(connected ? ColAccentDim : ColDangerDim));
        ImGui.SetCursorPos(new Vector2(10, 59));
        ImGui.PushStyleColor(ImGuiCol.Text, connected ? ColAccent : ColDanger);
        ImGui.TextUnformatted(connected ? "● " + _config.ServerPort : "● OFFLINE");
        ImGui.PopStyleColor();

        // Separator
        ImGui.SetCursorPosY(83);
        var sep = ImGui.GetCursorScreenPos();
        dl.AddLine(sep, sep + new Vector2(sideW, 0),
            ImGui.ColorConvertFloat4ToU32(ColBorder));
        ImGui.SetCursorPosY(87);

        // Nav buttons in scrollable child — prevents vertical clipping on small monitors
        float navH = totalH - 87 - 30;
        ImGui.BeginChild("##NavScroll", new Vector2(sideW, navH),
            ImGuiChildFlags.None, ImGuiWindowFlags.NoScrollbar);

        const float BtnH = 52f;
        for (int i = 0; i < Sections.Length; i++)
        {
            bool sel = _selectedSection == i;

            // Capture screen pos BEFORE the button renders — used for background rects
            var btnSP = ImGui.GetCursorScreenPos();

            if (sel)
            {
                // Left accent bar — 3px wide strip
                dl.AddRectFilled(btnSP, btnSP + new Vector2(3, BtnH),
                    ImGui.ColorConvertFloat4ToU32(ColAccent));
                // Tinted background exactly over button area (no overflow into adjacent rects)
                dl.AddRectFilled(btnSP, btnSP + new Vector2(sideW, BtnH),
                    ImGui.ColorConvertFloat4ToU32(ColAccentDim));
            }

            ImGui.PushStyleColor(ImGuiCol.Button,        new Vector4(0, 0, 0, 0));
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.18f, 0.95f, 0.45f, 0.10f));
            ImGui.PushStyleColor(ImGuiCol.ButtonActive,  new Vector4(0.18f, 0.95f, 0.45f, 0.22f));
            ImGui.PushStyleColor(ImGuiCol.Text, sel ? ColAccent : ColTextMuted);
            ImGui.PushStyleVar(ImGuiStyleVar.ButtonTextAlign, new Vector2(0.5f, 0.5f));

            if (ImGui.Button(Sections[i].Icon + "\n" + Sections[i].Short + $"##nav{i}",
                new Vector2(sideW, BtnH)))
                _selectedSection = i;

            ImGui.PopStyleVar();
            ImGui.PopStyleColor(4);

            if (i < Sections.Length - 1)
            {
                var divSP = ImGui.GetCursorScreenPos();
                dl.AddLine(divSP + new Vector2(12, 0), divSP + new Vector2(sideW - 12, 0),
                    ImGui.ColorConvertFloat4ToU32(ColBorder));
            }
        }

        ImGui.EndChild();

        // Footer
        ImGui.SetCursorPosY(totalH - 26);
        ImGui.SetCursorPosX(10);
        ImGui.PushStyleColor(ImGuiCol.Text, ColTextMuted);
        ImGui.TextUnformatted("Hytale Sec");
        ImGui.PopStyleColor();
    }

    private void RenderTopBar()
    {
        var dl = ImGui.GetWindowDrawList();
        var p  = ImGui.GetWindowPos();
        float w = ImGui.GetContentRegionAvail().X;

        ImGui.PushStyleColor(ImGuiCol.Text, ColAccent);
        ImGui.SetWindowFontScale(1.20f);
        ImGui.TextUnformatted(Sections[_selectedSection].Full);
        ImGui.SetWindowFontScale(1.0f);
        ImGui.PopStyleColor();

        ImGui.SameLine(w - 180);
        if (_config.IsSet)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, ColTextMuted);
            ImGui.TextUnformatted($"{_config.ServerIp}:{_config.ServerPort}");
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Text, ColDanger);
            ImGui.TextUnformatted("No server configured");
            ImGui.PopStyleColor();
        }

        float lineY = p.Y + ImGui.GetCursorPosY() - 3;
        dl.AddLine(new Vector2(p.X, lineY), new Vector2(p.X + w + 20, lineY),
            ImGui.ColorConvertFloat4ToU32(ColBorder));
        ImGui.Spacing();
        ImGui.Spacing();
    }

    private void RenderContent()
    {
        switch (_selectedSection)
        {
            case 0: RenderDashboardMerged();    break;
            case 1: RenderPacketsMerged();      break;
            case 2: _dupingTab.Render();        break;
            case 3: RenderCaptureMerged();      break;
            case 4: _privilegeTab.Render();     break;
            case 5: _itemInspectorTab.Render(); break;
            case 6: _packetBookTab.Render();    break;
            case 7: _memoryTab.Render();        break;
            case 8: _visualsTab.Render();       break;
        }
    }

    // Dashboard absorbs Log
    private void RenderDashboardMerged()
    {
        if (ImGui.BeginTabBar("##dash_tabs"))
        {
            if (ImGui.BeginTabItem("  Dashboard  "))
            { ImGui.Spacing(); _dashboardTab.Render(); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Log  "))
            { ImGui.Spacing(); _logTab.Render(); ImGui.EndTabItem(); }
            ImGui.EndTabBar();
        }
    }

    // Packets absorbs Response Analyser
    private void RenderPacketsMerged()
    {
        if (ImGui.BeginTabBar("##pkt_tabs"))
        {
            if (ImGui.BeginTabItem("  Packet Exploiting  "))
            { ImGui.Spacing(); _packetTab.Render(); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Response Analyser  "))
            { ImGui.Spacing(); _responseAnalyserTab.Render(); ImGui.EndTabItem(); }
            ImGui.EndTabBar();
        }
    }

    // Capture absorbs Diff Analysis
    private void RenderCaptureMerged()
    {
        if (ImGui.BeginTabBar("##cap_tabs"))
        {
            if (ImGui.BeginTabItem("  Capture  "))
            { ImGui.Spacing(); _captureTab.Render(); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Diff Analysis  "))
            { ImGui.Spacing(); _diffAnalysisTab.Render(); ImGui.EndTabItem(); }
            ImGui.EndTabBar();
        }
    }

    public static void ApplyTheme()
    {
        var style = ImGui.GetStyle();
        style.WindowPadding    = new Vector2(14, 10);
        style.FramePadding     = new Vector2(7, 4);
        style.ItemSpacing      = new Vector2(8, 6);
        style.ItemInnerSpacing = new Vector2(6, 4);
        style.IndentSpacing    = 16f;
        style.ScrollbarSize    = 8f;
        style.GrabMinSize      = 8f;
        style.WindowRounding    = 0f;
        style.ChildRounding     = 4f;
        style.FrameRounding     = 3f;
        style.PopupRounding     = 4f;
        style.ScrollbarRounding = 4f;
        style.GrabRounding      = 3f;
        style.TabRounding       = 4f;
        style.WindowBorderSize  = 0f;
        style.ChildBorderSize   = 1f;
        style.FrameBorderSize   = 0f;
        style.PopupBorderSize   = 1f;

        var c = style.Colors;
        c[(int)ImGuiCol.WindowBg]             = ColBg0;
        c[(int)ImGuiCol.ChildBg]              = ColBg1;
        c[(int)ImGuiCol.PopupBg]              = ColBg2;
        c[(int)ImGuiCol.Border]               = ColBorder;
        c[(int)ImGuiCol.BorderShadow]         = new Vector4(0, 0, 0, 0);
        c[(int)ImGuiCol.Text]                 = ColText;
        c[(int)ImGuiCol.TextDisabled]         = ColTextMuted;
        c[(int)ImGuiCol.FrameBg]              = ColBg2;
        c[(int)ImGuiCol.FrameBgHovered]       = ColBg3;
        c[(int)ImGuiCol.FrameBgActive]        = new Vector4(0.18f, 0.95f, 0.45f, 0.20f);
        c[(int)ImGuiCol.TitleBg]              = ColBg0;
        c[(int)ImGuiCol.TitleBgActive]        = ColBg0;
        c[(int)ImGuiCol.TitleBgCollapsed]     = ColBg0;
        c[(int)ImGuiCol.MenuBarBg]            = ColBg1;
        c[(int)ImGuiCol.ScrollbarBg]          = ColBg1;
        c[(int)ImGuiCol.ScrollbarGrab]        = ColBg3;
        c[(int)ImGuiCol.ScrollbarGrabHovered] = new Vector4(0.18f, 0.95f, 0.45f, 0.35f);
        c[(int)ImGuiCol.ScrollbarGrabActive]  = ColAccent;
        c[(int)ImGuiCol.CheckMark]            = ColAccent;
        c[(int)ImGuiCol.SliderGrab]           = ColAccentMid;
        c[(int)ImGuiCol.SliderGrabActive]     = ColAccent;
        c[(int)ImGuiCol.Button]               = ColBg3;
        c[(int)ImGuiCol.ButtonHovered]        = new Vector4(0.18f, 0.95f, 0.45f, 0.22f);
        c[(int)ImGuiCol.ButtonActive]         = new Vector4(0.18f, 0.95f, 0.45f, 0.38f);
        c[(int)ImGuiCol.Header]               = new Vector4(0.18f, 0.95f, 0.45f, 0.16f);
        c[(int)ImGuiCol.HeaderHovered]        = new Vector4(0.18f, 0.95f, 0.45f, 0.26f);
        c[(int)ImGuiCol.HeaderActive]         = new Vector4(0.18f, 0.95f, 0.45f, 0.38f);
        c[(int)ImGuiCol.Separator]            = ColBorder;
        c[(int)ImGuiCol.SeparatorHovered]     = ColAccentMid;
        c[(int)ImGuiCol.SeparatorActive]      = ColAccent;
        c[(int)ImGuiCol.ResizeGrip]           = new Vector4(0, 0, 0, 0);
        c[(int)ImGuiCol.ResizeGripHovered]    = ColAccentMid;
        c[(int)ImGuiCol.ResizeGripActive]     = ColAccent;
        c[(int)ImGuiCol.Tab]                  = ColBg2;
        c[(int)ImGuiCol.TabHovered]           = new Vector4(0.18f, 0.95f, 0.45f, 0.18f);
        c[(int)ImGuiCol.TabActive]            = new Vector4(0.18f, 0.95f, 0.45f, 0.28f);
        c[(int)ImGuiCol.TabUnfocused]         = ColBg1;
        c[(int)ImGuiCol.TabUnfocusedActive]   = ColBg2;
        c[(int)ImGuiCol.PlotLines]            = ColAccent;
        c[(int)ImGuiCol.PlotLinesHovered]     = new Vector4(0.18f, 0.95f, 0.45f, 1f);
        c[(int)ImGuiCol.PlotHistogram]        = ColAccentMid;
        c[(int)ImGuiCol.PlotHistogramHovered] = ColAccent;
        c[(int)ImGuiCol.DragDropTarget]       = ColAccent;
        c[(int)ImGuiCol.NavHighlight]         = ColAccent;
        c[(int)ImGuiCol.NavWindowingHighlight]= ColAccent;
        c[(int)ImGuiCol.NavWindowingDimBg]    = new Vector4(0, 0, 0, 0.6f);
        c[(int)ImGuiCol.ModalWindowDimBg]     = new Vector4(0, 0, 0, 0.6f);
    }
}
