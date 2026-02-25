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
    private readonly AbuseEngineTab       _abuseEngineTab;
    private readonly PrivilegeTab         _privilegeTab;
    private readonly ModAuditorTab        _modAuditorTab;
    private readonly ItemInspectorTab     _itemInspectorTab;
    private readonly PacketBookTab        _packetBookTab;
    private readonly ResponseAnalyserTab  _responseAnalyserTab;
    private readonly DiffAnalysisTab      _diffAnalysisTab;
    private readonly LogTab               _logTab;
    private readonly MemoryTab            _memoryTab;
    private readonly VisualsTab           _visualsTab;
    private readonly SmartDetectionEngine _smartDetect;
    private readonly ProtocolMapTab       _protocolMapTab;
    private readonly MacroEngineTab       _macroEngineTab;
    private readonly SettingsTab          _settingsTab;

    private int   _selectedSection  = 0;
    private float _sidebarAnimTimer = 0f;   // drives selected-row slide animation

    // ── 10 sidebar sections (was 14: Duping+Abuse merged, PacketBook folded into
    //    Packets, ProtocolMap folded into Capture, ConnectionTab added to Privilege) ──
    //
    //  idx  Section                  Sub-tabs
    //  ---  -----------------------  -------------------------------------------
    //   0   Dashboard                Dashboard | Log
    //   1   Packets                  Exploiting | Response Analyser | Packet Book
    //   2   Exploit Tools            Duping | Abuse Engine
    //   3   Capture & Analysis       Capture | Diff Analysis | Protocol Map
    //   4   Privilege Escalation     (own internal sub-tabs + Conn Tests)
    //   5   Mod Auditor              (own internal sub-tabs)
    //   6   Item Inspector
    //   7   Memory Reader
    //   8   Visuals / ESP
    //   9   Macro Engine
    //  10   Settings

    private static readonly NavSection[] Sections =
    {
        // MONITOR
        new NavSection("__HDR__", "", "-- MONITOR --",        IsHeader: true),
        new NavSection("[H]",     "Dashboard", "Dashboard"),

        // ANALYSIS
        new NavSection("__HDR__", "", "-- ANALYSIS --",       IsHeader: true),
        new NavSection("[P]",     "Packets",   "Packet Exploiting"),
        new NavSection("[C]",     "Capture",   "Capture & Analysis"),

        // EXPLOIT
        new NavSection("__HDR__", "", "-- EXPLOIT --",        IsHeader: true),
        new NavSection("[D]",     "Exploit",   "Exploit Tools"),
        new NavSection("[X]",     "Privilege", "Privilege Escalation"),
        new NavSection("[M]",     "Mod Audit", "Mod Auditor"),

        // TOOLS
        new NavSection("__HDR__", "", "-- TOOLS --",          IsHeader: true),
        new NavSection("[I]",     "Inspector", "Item Inspector"),
        new NavSection("[R]",     "Memory",    "Memory Reader"),
        new NavSection("[V]",     "Visuals",   "Visuals / ESP"),
        new NavSection("[>]",     "Macros",    "Macro Engine"),
        new NavSection("[S]",     "Settings",  "Settings"),
    };

    // Map section index (0-based, skipping headers) to Sections[] index
    private static readonly int[] SectionIdx;   // SectionIdx[logicalIdx] = array idx
    private static readonly int   SectionCount; // logical count (non-headers)

    static MenuRenderer()
    {
        var idxList = new List<int>();
        for (int i = 0; i < Sections.Length; i++)
            if (!Sections[i].IsHeader)
                idxList.Add(i);
        SectionIdx   = idxList.ToArray();
        SectionCount = idxList.Count;
    }

    // ── Colour palette ────────────────────────────────────────────────────
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

        // ── Bootstrap global singletons ───────────────────────────────────
        GlobalConfig.Instance.SyncToHotkeyConfig();
        _log.Info($"[Init] GlobalConfig loaded from {GlobalConfig.ConfigPath}");

        AutoUpdateHandler.Instance.Init(_log);

        // Wire live memory polling -> SmartDetect + ServerConfig
        AutoUpdateHandler.Instance.OnHoverEntityChanged += hoverId =>
        {
            _smartDetect?.SetHoverEntity(hoverId);
            _smartDetect?.OnLiveMemoryHoverEntity(hoverId);
            _log.Info($"[MemPoll] HoverEntity -> {hoverId}");
        };
        AutoUpdateHandler.Instance.OnLocalPlayerIdChanged += playerId =>
        {
            _smartDetect?.OnLiveMemoryLocalPlayer(playerId);
            if (!_config.HasLocalPlayer || _config.LocalPlayerEntityId != playerId)
            {
                _config.SetLocalPlayerEntityId(playerId, AutoUpdateHandler.Instance.ScanSummary);
                _log.Success($"[MemPoll] LocalPlayerEntityId -> {playerId}");
            }
        };

        // Boot capture subsystem
        _captureTab = new CaptureTab(_log, _pktLog, _config);
        AbuseEngine.Instance.Init(_captureTab.UdpProxy, _log);
        EntityTracker.Instance.ToString();
        _captureTab.UdpProxy.OnPacket += _stats.OnPacket;
        _captureTab.UdpProxy.OnPacket += _tracker.Feed;
        _captureTab.Capture.OnPacket  += _tracker.Feed;
        _captureTab.Capture.OnPacket  += _stats.OnPacket;

        _dashboardTab        = new DashboardTab(_log, _config, _stats);
        _packetTab           = new PacketTab(_log, _captureTab.Capture, _captureTab.UdpProxy, _config);
        _dupingTab           = new DupingTab(_log, _captureTab.UdpProxy, _captureTab.Capture, _store, _config);
        _abuseEngineTab      = new AbuseEngineTab(_log, _captureTab.UdpProxy, _captureTab.Capture, _store, _config);
        _privilegeTab        = new PrivilegeTab(_log, _captureTab.Capture, _captureTab.UdpProxy, _config, _store);
        _smartDetect         = new SmartDetectionEngine(_captureTab.Capture, _store, _log, _config);

        _smartDetect.OnAdminOpCodeDetected += (op, _) =>
            AlertBus.Push(AlertBus.Sec_Inspector, AlertLevel.Critical,
                $"Admin opcode detected: 0x{op:X2}");
        _smartDetect.OnLootDropDetected += (id, _) =>
            AlertBus.Push(AlertBus.Sec_Inspector, AlertLevel.Info,
                $"Loot drop: entity {id}");

        _itemInspectorTab    = new ItemInspectorTab(_log, _captureTab.Capture, _captureTab.UdpProxy,
                                   _store, _config, _smartDetect);
        _modAuditorTab       = new ModAuditorTab(_log, _captureTab.Capture, _captureTab.UdpProxy, _config, _store);
        _packetBookTab       = new PacketBookTab(_log, _store, _captureTab.UdpProxy, _captureTab.Capture, _config);
        _responseAnalyserTab = new ResponseAnalyserTab(_log, _tracker, _captureTab.Capture,
                                   _captureTab.UdpProxy, _store, _config);
        _diffAnalysisTab     = new DiffAnalysisTab(_log, _store, _captureTab.Capture);
        _captureTab.SetDiffTab(_diffAnalysisTab);
        _logTab              = new LogTab(_log, _pktLog, _smartDetect.SmartLog);
        _memoryTab           = new MemoryTab(_log, _store, _config);
        _visualsTab          = new VisualsTab(_log, _config, _smartDetect);
        _protocolMapTab      = new ProtocolMapTab(_log, _captureTab.Capture);
        _macroEngineTab      = new MacroEngineTab(_log, _captureTab.Capture, _captureTab.UdpProxy, _config, _store);
        _settingsTab         = new SettingsTab(_log);

        // Auto-attach to HytaleClient
        Task.Run(() =>
        {
            string err = SharedMemoryReader.AutoAttach();
            if (string.IsNullOrEmpty(err))
            {
                _log.Success($"[Init] Auto-attached to {SharedMemoryReader.ProcessName} (PID {SharedMemoryReader.Pid})");
                AutoUpdateHandler.Instance.CheckVersion();
            }
            else
            {
                _log.Info($"[Init] Auto-attach: {err}");
            }
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // MAIN RENDER LOOP
    // ══════════════════════════════════════════════════════════════════════

    public void Render()
    {
        var io      = ImGui.GetIO();
        var display = io.DisplaySize;

        _sidebarAnimTimer += io.DeltaTime;

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

        const float SideW = 126f;    // was 110 - wider for cleaner labels
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

    // ══════════════════════════════════════════════════════════════════════
    // SIDEBAR
    // ══════════════════════════════════════════════════════════════════════

    private void RenderSidebar(float sideW, float totalH)
    {
        var dl = ImGui.GetWindowDrawList();
        var wp = ImGui.GetWindowPos();

        // Top accent bar (3 px)
        dl.AddRectFilled(wp, wp + new Vector2(sideW, 3),
            ImGui.ColorConvertFloat4ToU32(ColAccent));

        // Logo / name
        ImGui.SetCursorPos(new Vector2(12, 12));
        ImGui.PushStyleColor(ImGuiCol.Text, ColAccent);
        ImGui.SetWindowFontScale(1.05f);
        ImGui.TextUnformatted("HyTester");
        ImGui.SetWindowFontScale(1.0f);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(12, 30));
        ImGui.PushStyleColor(ImGuiCol.Text, ColTextMuted);
        ImGui.TextUnformatted("v16.0");
        ImGui.PopStyleColor();

        // Connection status strip
        bool connected = _config.IsSet;
        bool attached  = SharedMemoryReader.IsAttached;
        ImGui.SetCursorPosY(50);
        var sp = ImGui.GetCursorScreenPos();
        dl.AddRectFilled(sp, sp + new Vector2(sideW, 24),
            ImGui.ColorConvertFloat4ToU32(connected ? ColAccentDim : ColDangerDim));
        ImGui.SetCursorPos(new Vector2(9, 55));
        ImGui.PushStyleColor(ImGuiCol.Text, connected ? ColAccent : ColDanger);
        ImGui.TextUnformatted(connected ? "[>] :" + _config.ServerPort : "[>] OFFLINE");
        ImGui.PopStyleColor();

        // Memory attach dot (right side of status strip)
        var dotPos = sp + new Vector2(sideW - 14, 7);
        dl.AddCircleFilled(dotPos, 5f, ImGui.ColorConvertFloat4ToU32(
            attached ? ColAccent : new Vector4(0.4f, 0.4f, 0.4f, 0.8f)));

        // Divider
        ImGui.SetCursorPosY(77);
        var sep = ImGui.GetCursorScreenPos();
        dl.AddLine(sep, sep + new Vector2(sideW, 0),
            ImGui.ColorConvertFloat4ToU32(ColBorder));
        ImGui.SetCursorPosY(81);

        // Nav scroll area
        float navH = totalH - 81 - 52;   // 52 = footer height
        ImGui.BeginChild("##NavScroll", new Vector2(sideW, navH),
            ImGuiChildFlags.None, ImGuiWindowFlags.NoScrollbar);

        const float BtnH     = 46f;
        int         logIdx   = 0;

        for (int i = 0; i < Sections.Length; i++)
        {
            var sec = Sections[i];

            if (sec.IsHeader)
            {
                // Group label row
                ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.28f, 0.38f, 0.30f, 1f));
                ImGui.SetCursorPosX(8);
                ImGui.TextUnformatted(sec.Full);
                ImGui.PopStyleColor();
                // Headers don't count as logical nav sections - do NOT increment logIdx
                continue;
            }

            bool sel = _selectedSection == logIdx;
            var  btnSP = ImGui.GetCursorScreenPos();

            if (sel)
            {
                // Animated left accent bar (pulse brightness)
                float pulse  = 0.7f + 0.3f * MathF.Sin(_sidebarAnimTimer * 3.5f);
                var   barCol = new Vector4(ColAccent.X, ColAccent.Y, ColAccent.Z, pulse);
                dl.AddRectFilled(btnSP, btnSP + new Vector2(3, BtnH),
                    ImGui.ColorConvertFloat4ToU32(barCol));
                dl.AddRectFilled(btnSP, btnSP + new Vector2(sideW, BtnH),
                    ImGui.ColorConvertFloat4ToU32(ColAccentDim));
            }

            ImGui.PushStyleColor(ImGuiCol.Button,        new Vector4(0, 0, 0, 0));
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.18f, 0.95f, 0.45f, 0.10f));
            ImGui.PushStyleColor(ImGuiCol.ButtonActive,  new Vector4(0.18f, 0.95f, 0.45f, 0.22f));
            ImGui.PushStyleColor(ImGuiCol.Text, sel ? ColAccent : ColTextMuted);
            ImGui.PushStyleVar(ImGuiStyleVar.ButtonTextAlign, new Vector2(0.5f, 0.5f));

            int capturedIdx = logIdx;
            if (ImGui.Button(sec.Icon + "\n" + sec.Short + $"##nav{i}",
                new Vector2(sideW, BtnH)))
                _selectedSection = capturedIdx;

            ImGui.PopStyleVar();
            ImGui.PopStyleColor(4);

            // Badge
            int badge = AlertBus.GetBadge(logIdx);
            if (badge > 0 && _selectedSection != logIdx)
            {
                string badgeStr = badge > 9 ? "9+" : badge.ToString();
                float  badgeW   = ImGui.CalcTextSize(badgeStr).X + 6;
                float  bx       = btnSP.X + sideW - badgeW - 4;
                float  by       = btnSP.Y + 4;
                dl.AddRectFilled(new Vector2(bx - 2, by), new Vector2(bx + badgeW, by + 16),
                    ImGui.ColorConvertFloat4ToU32(ColDanger), 4f);
                dl.AddText(new Vector2(bx + 1, by + 1),
                    ImGui.ColorConvertFloat4ToU32(new Vector4(1, 1, 1, 1)), badgeStr);
            }

            logIdx++;
        }

        ImGui.EndChild();

        // ── Footer: memory polling status + player ID ─────────────────────
        float footerY = totalH - 50;
        ImGui.SetCursorPosY(footerY);
        var footSP = ImGui.GetCursorScreenPos();
        dl.AddLine(footSP, footSP + new Vector2(sideW, 0),
            ImGui.ColorConvertFloat4ToU32(ColBorder));

        ImGui.SetCursorPos(new Vector2(9, footerY + 5));
        ImGui.PushStyleColor(ImGuiCol.Text, ColTextMuted);

        bool polling = AutoUpdateHandler.Instance.IsPolling;
        if (polling)
        {
            // Spinning dot for polling indicator
            float spin = _sidebarAnimTimer * 2f;
            var   dotC = new Vector4(ColAccent.X, ColAccent.Y, ColAccent.Z,
                0.5f + 0.5f * MathF.Sin(spin));
            var spinSP = ImGui.GetCursorScreenPos() + new Vector2(0, 7);
            dl.AddCircleFilled(spinSP, 4f, ImGui.ColorConvertFloat4ToU32(dotC));
            ImGui.SetCursorPosX(18);
        }

        if (_config.HasLocalPlayer)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(ColAccent.X, ColAccent.Y, ColAccent.Z, 0.7f));
            ImGui.TextUnformatted($"PID {_config.LocalPlayerEntityId}");
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.TextUnformatted(polling ? "Polling..." : "HyTester");
        }

        ImGui.PopStyleColor();

        // Second footer row
        ImGui.SetCursorPos(new Vector2(9, footerY + 22));
        ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.22f, 0.30f, 0.24f, 1f));
        ImGui.TextUnformatted(AutoUpdateHandler.Instance.ScanSummary == ""
            ? "No scan"
            : AutoUpdateHandler.Instance.ScanSummary);
        ImGui.PopStyleColor();
    }

    // ══════════════════════════════════════════════════════════════════════
    // TOP BAR
    // ══════════════════════════════════════════════════════════════════════

    private void RenderTopBar()
    {
        var dl = ImGui.GetWindowDrawList();
        var p  = ImGui.GetWindowPos();
        float w = ImGui.GetContentRegionAvail().X;

        // Section title
        ImGui.PushStyleColor(ImGuiCol.Text, ColAccent);
        ImGui.SetWindowFontScale(1.18f);
        ImGui.TextUnformatted(Sections[SectionIdx[_selectedSection]].Full);
        ImGui.SetWindowFontScale(1.0f);
        ImGui.PopStyleColor();

        // Right side: server + memory status chips
        float rightStart = w - 320;
        ImGui.SameLine(rightStart);

        // Memory chip
        bool att = SharedMemoryReader.IsAttached;
        ImGui.PushStyleColor(ImGuiCol.Text, att ? ColAccent : ColTextMuted);
        ImGui.TextUnformatted(att
            ? $"[MEM] {SharedMemoryReader.ProcessName}"
            : "[MEM] ---");
        ImGui.PopStyleColor();

        ImGui.SameLine(0, 16);

        // Server chip
        if (_config.IsSet)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, ColTextMuted);
            ImGui.TextUnformatted($"{_config.ServerIp}:{_config.ServerPort}");
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Text, ColDanger);
            ImGui.TextUnformatted("No server");
            ImGui.PopStyleColor();
        }

        // Polling chip (only shown when active)
        if (AutoUpdateHandler.Instance.IsPolling)
        {
            ImGui.SameLine(0, 12);
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(ColAccent.X, ColAccent.Y, ColAccent.Z, 0.65f));
            ImGui.TextUnformatted("[POLL]");
            ImGui.PopStyleColor();
        }

        // Horizontal rule
        float lineY = p.Y + ImGui.GetCursorPosY() - 3;
        dl.AddLine(new Vector2(p.X, lineY), new Vector2(p.X + w + 20, lineY),
            ImGui.ColorConvertFloat4ToU32(ColBorder));
        ImGui.Spacing();
        ImGui.Spacing();
    }

    // ══════════════════════════════════════════════════════════════════════
    // CONTENT ROUTER
    // ══════════════════════════════════════════════════════════════════════

    private void RenderContent()
    {
        AlertBus.ClearBadge(_selectedSection);

        switch (_selectedSection)
        {
            case 0:  RenderDashboard();          break;   // Dashboard + Log
            case 1:  RenderPackets();            break;   // Exploiting + Response + Book
            case 2:  RenderCapture();            break;   // Capture + Diff + Proto Map
            case 3:  RenderExploit();            break;   // Duping + Abuse Engine
            case 4:  _privilegeTab.Render();     break;   // Privilege (incl. Conn Tests)
            case 5:  _modAuditorTab.Render();    break;
            case 6:  _itemInspectorTab.Render(); break;
            case 7:  _memoryTab.Render();        break;
            case 8:  _visualsTab.Render();       break;
            case 9:  _macroEngineTab.Render();   break;
            case 10: _settingsTab.Render();      break;
        }
    }

    // ── Dashboard (was 2 tabs: Dashboard + Log) ───────────────────────────
    private void RenderDashboard()
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

    // ── Packets (was 2 tabs: Exploiting + Response — now adds Packet Book) ─
    private void RenderPackets()
    {
        if (ImGui.BeginTabBar("##pkt_tabs"))
        {
            if (ImGui.BeginTabItem("  Packet Exploiting  "))
            { ImGui.Spacing(); _packetTab.Render(); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Response Analyser  "))
            { ImGui.Spacing(); _responseAnalyserTab.Render(); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Packet Book  "))
            { ImGui.Spacing(); _packetBookTab.Render(); ImGui.EndTabItem(); }
            ImGui.EndTabBar();
        }
    }

    // ── Capture (was 2 tabs: Capture + Diff — now adds Protocol Map) ──────
    private void RenderCapture()
    {
        if (ImGui.BeginTabBar("##cap_tabs"))
        {
            if (ImGui.BeginTabItem("  Capture  "))
            { ImGui.Spacing(); _captureTab.Render(); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Diff Analysis  "))
            { ImGui.Spacing(); _diffAnalysisTab.Render(); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Protocol Map  "))
            { ImGui.Spacing(); _protocolMapTab.Render(); ImGui.EndTabItem(); }
            ImGui.EndTabBar();
        }
    }

    // ── Exploit Tools (new merge: Duping + Abuse Engine) ─────────────────
    private void RenderExploit()
    {
        if (ImGui.BeginTabBar("##exp_tabs"))
        {
            if (ImGui.BeginTabItem("  Dupe Methods  "))
            { ImGui.Spacing(); _dupingTab.Render(); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("  Abuse Engine  "))
            { ImGui.Spacing(); _abuseEngineTab.Render(); ImGui.EndTabItem(); }
            ImGui.EndTabBar();
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // THEME
    // ══════════════════════════════════════════════════════════════════════

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

    // ══════════════════════════════════════════════════════════════════════
    // GLOBAL HOTKEY ACTIONS
    // ══════════════════════════════════════════════════════════════════════

    /// <summary>F8: Insert a purple timeline marker into the capture log.</summary>
    public void InsertTimelineMarker()
    {
        var marker = new CapturedPacket
        {
            Timestamp   = DateTime.Now,
            IsMarker    = true,
            MarkerLabel = $"[F8 MARKER] {DateTime.Now:HH:mm:ss.fff}",
            MarkerColor = 0xFF9000FF,
            Direction   = PacketDirection.ServerToClient,
            RawBytes     = Array.Empty<byte>(),
        };
        _captureTab.Capture.AddPacketExternal(marker);
        _log.Info($"[Marker] Timeline marker inserted at {DateTime.Now:HH:mm:ss.fff}");
    }

    /// <summary>F9: Lock/pin the last hovered entity in Item Inspector.</summary>
    public void LockHoveredTarget()
    {
        _itemInspectorTab.LockLastHoveredTarget();
        _log.Info("[Lock] Target locked via hotkey.");
    }

    // ── Internal nav helper struct ─────────────────────────────────────────

    private readonly record struct NavSection(
        string Icon, string Short, string Full, bool IsHeader = false);
}
