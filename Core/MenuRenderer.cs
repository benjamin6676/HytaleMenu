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
    private readonly ConnectionTab        _connectionTab;
    private readonly PrivilegeTab         _privilegeTab;
    private readonly ItemInspectorTab     _itemInspectorTab;
    private readonly PacketBookTab        _packetBookTab;
    private readonly DiffAnalysisTab      _diffAnalysisTab;
    private readonly ResponseAnalyserTab  _responseAnalyserTab;
    private readonly LogTab               _logTab;
    private readonly MemoryTab            _memoryTab;
    private readonly VisualsTab           _visualsTab;

    // Which sidebar section is active (0-based)
    private int _selectedSection = 0;

    private static readonly string[] SectionIcons = {
        "⌂", "⚡", "◈", "◎", "▲", "⊙", "⊗", "☰", "≋", "◫", "≡", "⬡"
    };

    private static readonly string[] SectionNames = {
        "Dashboard",
        "Packet\nExploiting",
        "Dupe\nMethods",
        "Capture",
        "Privilege\nEscalation",
        "Item\nInspector",
        "Response\nAnalyser",
        "Diff\nAnalysis",
        "Packet\nBook",
        "Connection",
        "Log",
        "Memory\nReader",
        "Visuals\n/ ESP"
    };

    private static readonly string[] SectionLabels = {
        "Dashboard",
        "Packet Exploiting",
        "Dupe Methods",
        "Capture",
        "Privilege Escalation",
        "Item Inspector",
        "Response Analyser",
        "Diff Analysis",
        "Packet Book",
        "Connection",
        "Log",
        "Memory Reader",
        "Visuals / ESP"
    };

    // ── Palette — one place to change every color in the app ──────────────

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

    public MenuRenderer()
    {
        _log     = new TestLog();
        _pktLog  = new PacketLog(2000);
        _config  = new ServerConfig();
        _store   = new PacketStore();
        _stats   = new ServerStats(_log);
        _tracker = new ResponseTracker();

        _captureTab = new CaptureTab(_log, _pktLog, _config);

        // Wire up packet feeds — stats + tracker both observe every proxied packet
        _captureTab.UdpProxy.OnPacket   += _stats.OnPacket;
        _captureTab.UdpProxy.OnPacket   += _tracker.Feed;
        _captureTab.Capture.OnPacket    += _tracker.Feed;
        _captureTab.Capture.OnPacket    += _stats.OnPacket;

        _dashboardTab        = new DashboardTab(_log, _config, _stats);
        _packetTab           = new PacketTab(_log, _captureTab.Capture, _captureTab.UdpProxy, _config);
        _dupingTab           = new DupingTab(_log, _captureTab.UdpProxy, _captureTab.Capture, _store, _config);
        _connectionTab       = new ConnectionTab(_log, _config);
        _privilegeTab        = new PrivilegeTab(_log, _captureTab.Capture, _captureTab.UdpProxy, _config, _store);
        _itemInspectorTab    = new ItemInspectorTab(_log, _captureTab.Capture, _captureTab.UdpProxy, _store, _config);
        _packetBookTab       = new PacketBookTab(_log, _store, _captureTab.UdpProxy, _captureTab.Capture, _config);
        _diffAnalysisTab     = new DiffAnalysisTab(_log, _store, _captureTab.Capture);
        _responseAnalyserTab = new ResponseAnalyserTab(_log, _tracker, _captureTab.Capture,
                                   _captureTab.UdpProxy, _store, _config);
        _logTab              = new LogTab(_log, _pktLog);
        _memoryTab           = new MemoryTab(_log, _store);
        _visualsTab          = new VisualsTab(_log, _config);
    }

    public void Render()
    {
        var io      = ImGui.GetIO();
        var display = io.DisplaySize;

        ImGui.SetNextWindowPos(Vector2.Zero);
        ImGui.SetNextWindowSize(display);
        ImGui.SetNextWindowBgAlpha(0f);

        var outerFlags =
            ImGuiWindowFlags.NoTitleBar    | ImGuiWindowFlags.NoResize  |
            ImGuiWindowFlags.NoMove        | ImGuiWindowFlags.NoCollapse |
            ImGuiWindowFlags.NoBringToFrontOnFocus | ImGuiWindowFlags.NoScrollbar;

        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, Vector2.Zero);
        ImGui.PushStyleColor(ImGuiCol.WindowBg, ColBg0);
        ImGui.Begin("##Root", outerFlags);
        ImGui.PopStyleColor();
        ImGui.PopStyleVar();

        float sideW    = 120f;
        float totalH   = display.Y;
        float contentW = display.X - sideW;

        // Left sidebar
        ImGui.PushStyleColor(ImGuiCol.ChildBg, ColBg1);
        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, Vector2.Zero);
        ImGui.BeginChild("##Sidebar", new Vector2(sideW, totalH), ImGuiChildFlags.None);
        ImGui.PopStyleVar();
        ImGui.PopStyleColor();

        RenderSidebar(sideW, totalH);

        ImGui.EndChild();
        ImGui.SameLine(0, 0);

        // Right content area
        ImGui.PushStyleColor(ImGuiCol.ChildBg, ColBg0);
        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(22, 18));
        ImGui.BeginChild("##Content", new Vector2(contentW, totalH), ImGuiChildFlags.None);
        ImGui.PopStyleVar();
        ImGui.PopStyleColor();

        RenderTopBar();
        RenderContent();

        ImGui.EndChild();
        ImGui.End();
    }

    // ── Sidebar ───────────────────────────────────────────────────────────

    private void RenderSidebar(float sideW, float totalH)
    {
        // Logo / header area
        ImGui.PushStyleColor(ImGuiCol.ChildBg, ColBg0);
        ImGui.BeginChild("##Logo", new Vector2(sideW, 72), ImGuiChildFlags.None);
        ImGui.PopStyleColor();

        var dl = ImGui.GetWindowDrawList();
        var p  = ImGui.GetWindowPos();

        // Green accent bar across top
        dl.AddRectFilled(p, p + new Vector2(sideW, 3),
            ImGui.ColorConvertFloat4ToU32(ColAccent));

        ImGui.SetCursorPos(new Vector2(12, 16));
        ImGui.PushStyleColor(ImGuiCol.Text, ColAccent);
        ImGui.Text("HST");
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(12, 36));
        ImGui.PushStyleColor(ImGuiCol.Text, ColTextMuted);
        ImGui.TextUnformatted("v1.0");
        ImGui.PopStyleColor();

        ImGui.EndChild();

        // Server status pill under logo
        ImGui.PushStyleColor(ImGuiCol.ChildBg,
            _config.IsSet ? ColAccentDim : ColDangerDim);
        ImGui.BeginChild("##SrvPill", new Vector2(sideW, 30), ImGuiChildFlags.None);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 7));
        ImGui.PushStyleColor(ImGuiCol.Text,
            _config.IsSet ? ColAccent : ColDanger);
        ImGui.TextUnformatted(_config.IsSet
            ? $"● {_config.ServerPort}"
            : "● NO SERVER");
        ImGui.PopStyleColor();
        ImGui.EndChild();

        ImGui.Spacing();

        // Nav buttons
        float btnH = 64f;
        for (int i = 0; i < SectionNames.Length; i++)
        {
            bool selected = _selectedSection == i;

            if (selected)
            {
                var wdl = ImGui.GetWindowDrawList();
                var wp  = ImGui.GetWindowPos();
                float cy = ImGui.GetCursorPosY();

                // Active indicator bar on left edge
                wdl.AddRectFilled(
                    wp + new Vector2(0, cy),
                    wp + new Vector2(3, cy + btnH),
                    ImGui.ColorConvertFloat4ToU32(ColAccent));

                // Active button background tint
                wdl.AddRectFilled(
                    wp + new Vector2(0, cy),
                    wp + new Vector2(sideW, cy + btnH),
                    ImGui.ColorConvertFloat4ToU32(ColAccentDim));
            }

            ImGui.PushStyleColor(ImGuiCol.Button,
                selected ? ColAccentDim : new Vector4(0, 0, 0, 0));
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered,
                new Vector4(0.18f, 0.95f, 0.45f, 0.10f));
            ImGui.PushStyleColor(ImGuiCol.ButtonActive,
                new Vector4(0.18f, 0.95f, 0.45f, 0.22f));
            ImGui.PushStyleColor(ImGuiCol.Text,
                selected ? ColAccent : ColTextMuted);
            ImGui.PushStyleVar(ImGuiStyleVar.ButtonTextAlign, new Vector2(0.5f, 0.5f));

            string[] nameParts = SectionNames[i].Split('\n');
            string   btnLabel  = SectionIcons[i] + "\n" +
                                 string.Join("\n", nameParts) +
                                 $"##nav{i}";

            if (ImGui.Button(btnLabel, new Vector2(sideW, btnH)))
                _selectedSection = i;

            ImGui.PopStyleVar();
            ImGui.PopStyleColor(4);

            // Divider between items
            if (!selected && i < SectionNames.Length - 1)
            {
                var wdl2 = ImGui.GetWindowDrawList();
                var wp2  = ImGui.GetWindowPos();
                float cy2 = ImGui.GetCursorPosY();
                wdl2.AddLine(
                    wp2 + new Vector2(16, cy2),
                    wp2 + new Vector2(sideW - 16, cy2),
                    ImGui.ColorConvertFloat4ToU32(ColBorder));
            }
        }

        // Footer label
        ImGui.SetCursorPosY(totalH - 36);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0, 0, 0, 0));
        ImGui.BeginChild("##SideBottom", new Vector2(sideW, 36), ImGuiChildFlags.None);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(10, 8));
        ImGui.PushStyleColor(ImGuiCol.Text, ColTextMuted);
        ImGui.TextUnformatted("Hytale Sec");
        ImGui.PopStyleColor();
        ImGui.EndChild();
    }

    // ── Top bar ───────────────────────────────────────────────────────────

    private void RenderTopBar()
    {
        var dl = ImGui.GetWindowDrawList();
        var p  = ImGui.GetWindowPos();
        float w = ImGui.GetContentRegionAvail().X;

        // Section title
        ImGui.PushStyleColor(ImGuiCol.Text, ColAccent);
        ImGui.SetWindowFontScale(1.25f);
        ImGui.Text(SectionLabels[_selectedSection]);
        ImGui.SetWindowFontScale(1.0f);
        ImGui.PopStyleColor();

        ImGui.SameLine(w - 200);

        // Server badge (top right)
        if (_config.IsSet)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, ColTextMuted);
            ImGui.Text($"{_config.ServerIp}:{_config.ServerPort}");
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Text, ColDanger);
            ImGui.Text("No server configured");
            ImGui.PopStyleColor();
        }

        // Accent underline
        float lineY = p.Y + ImGui.GetCursorPosY() - 4;
        dl.AddLine(
            new Vector2(p.X, lineY),
            new Vector2(p.X + w, lineY),
            ImGui.ColorConvertFloat4ToU32(ColBorder), 1f);

        ImGui.Spacing();
        ImGui.Spacing();
    }

    // ── Content routing ───────────────────────────────────────────────────

    private void RenderContent()
    {
        switch (_selectedSection)
        {
            case 0:  _dashboardTab.Render();        break;
            case 1:  _packetTab.Render();           break;
            case 2:  _dupingTab.Render();           break;
            case 3:  _captureTab.Render();          break;
            case 4:  _privilegeTab.Render();        break;
            case 5:  _itemInspectorTab.Render();    break;
            case 6:  _responseAnalyserTab.Render(); break;
            case 7:  _diffAnalysisTab.Render();     break;
            case 8:  _packetBookTab.Render();       break;
            case 9:  _connectionTab.Render();       break;
            case 10: _logTab.Render();              break;
            case 11: _memoryTab.Render();           break;
            case 12: _visualsTab.Render();          break;
        }
    }

    // ── Theme ─────────────────────────────────────────────────────────────

    public static void ApplyTheme()
    {
        var style = ImGui.GetStyle();

        style.WindowPadding    = new Vector2(16, 12);
        style.FramePadding     = new Vector2(8, 5);
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
        style.TabRounding       = 3f;

        style.WindowBorderSize = 0f;
        style.ChildBorderSize  = 1f;
        style.FrameBorderSize  = 0f;
        style.PopupBorderSize  = 1f;

        var c = style.Colors;

        c[(int)ImGuiCol.WindowBg]          = ColBg0;
        c[(int)ImGuiCol.ChildBg]           = ColBg1;
        c[(int)ImGuiCol.PopupBg]           = ColBg2;
        c[(int)ImGuiCol.Border]            = ColBorder;
        c[(int)ImGuiCol.BorderShadow]      = new Vector4(0, 0, 0, 0);
        c[(int)ImGuiCol.Text]              = ColText;
        c[(int)ImGuiCol.TextDisabled]      = ColTextMuted;
        c[(int)ImGuiCol.FrameBg]           = ColBg2;
        c[(int)ImGuiCol.FrameBgHovered]    = ColBg3;
        c[(int)ImGuiCol.FrameBgActive]     = new Vector4(0.18f, 0.95f, 0.45f, 0.20f);
        c[(int)ImGuiCol.TitleBg]           = ColBg0;
        c[(int)ImGuiCol.TitleBgActive]     = ColBg0;
        c[(int)ImGuiCol.TitleBgCollapsed]  = ColBg0;
        c[(int)ImGuiCol.MenuBarBg]         = ColBg1;
        c[(int)ImGuiCol.ScrollbarBg]       = ColBg1;
        c[(int)ImGuiCol.ScrollbarGrab]     = ColBg3;
        c[(int)ImGuiCol.ScrollbarGrabHovered] = new Vector4(0.18f, 0.95f, 0.45f, 0.35f);
        c[(int)ImGuiCol.ScrollbarGrabActive]  = ColAccent;
        c[(int)ImGuiCol.CheckMark]         = ColAccent;
        c[(int)ImGuiCol.SliderGrab]        = ColAccentMid;
        c[(int)ImGuiCol.SliderGrabActive]  = ColAccent;
        c[(int)ImGuiCol.Button]            = ColBg3;
        c[(int)ImGuiCol.ButtonHovered]     = new Vector4(0.18f, 0.95f, 0.45f, 0.22f);
        c[(int)ImGuiCol.ButtonActive]      = new Vector4(0.18f, 0.95f, 0.45f, 0.38f);
        c[(int)ImGuiCol.Header]            = new Vector4(0.18f, 0.95f, 0.45f, 0.16f);
        c[(int)ImGuiCol.HeaderHovered]     = new Vector4(0.18f, 0.95f, 0.45f, 0.26f);
        c[(int)ImGuiCol.HeaderActive]      = new Vector4(0.18f, 0.95f, 0.45f, 0.38f);
        c[(int)ImGuiCol.Separator]         = ColBorder;
        c[(int)ImGuiCol.SeparatorHovered]  = ColAccentMid;
        c[(int)ImGuiCol.SeparatorActive]   = ColAccent;
        c[(int)ImGuiCol.ResizeGrip]        = new Vector4(0, 0, 0, 0);
        c[(int)ImGuiCol.ResizeGripHovered] = ColAccentMid;
        c[(int)ImGuiCol.ResizeGripActive]  = ColAccent;
        c[(int)ImGuiCol.Tab]               = ColBg2;
        c[(int)ImGuiCol.TabHovered]        = new Vector4(0.18f, 0.95f, 0.45f, 0.22f);
        // Map tab-like colors to existing ImGuiCol entries available in this build
        c[(int)ImGuiCol.HeaderActive]      = new Vector4(0.18f, 0.95f, 0.45f, 0.28f);
        c[(int)ImGuiCol.ChildBg]           = ColBg1;
        c[(int)ImGuiCol.FrameBg]           = ColBg2;
        c[(int)ImGuiCol.PlotLines]         = ColAccent;
        c[(int)ImGuiCol.PlotLinesHovered]  = new Vector4(0.18f, 0.95f, 0.45f, 1f);
        c[(int)ImGuiCol.PlotHistogram]     = ColAccentMid;
        c[(int)ImGuiCol.PlotHistogramHovered] = ColAccent;
        c[(int)ImGuiCol.DragDropTarget]    = ColAccent;
        c[(int)ImGuiCol.NavHighlight]      = ColAccent;
        c[(int)ImGuiCol.NavWindowingHighlight] = ColAccent;
        c[(int)ImGuiCol.NavWindowingDimBg]    = new Vector4(0, 0, 0, 0.6f);
        c[(int)ImGuiCol.ModalWindowDimBg]     = new Vector4(0, 0, 0, 0.6f);
    }
}
