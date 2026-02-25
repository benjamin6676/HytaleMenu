using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace HytaleSecurityTester.Tabs;

public class CaptureTab : ITab
{
    public string Title => "  Capture  ";

    private readonly TestLog       _log;
    private readonly PacketCapture _capture;
    private readonly ServerConfig  _config;

    public PacketCapture Capture => _capture;

    private int _listenPort = 5521;

    private enum CaptureMode { Udp, Tcp, Tls }
    private CaptureMode _mode = CaptureMode.Udp;

    private bool                     _tlsIntercepting = false;
    private string                   _tlsCertStatus   = "Not generated";
    private X509Certificate2?        _tlsCert;
    private CancellationTokenSource? _tlsCts;

    private UdpProxy _udpProxy;
    private DiffAnalysisTab? _diffTab; // injected after construction

    private int    _selectedIndex    = -1;
    private string _filterText       = "";
    private bool   _showClientServer = true;
    private bool   _showServerClient = true;
    private bool   _autoScroll       = true;
    private bool   _hideSmallPkts    = false;   // hide packets < 15 bytes
    private bool   _decompressView   = false;   // show decompressed payload in hex view
    private int    _commentingIdx    = -1;       // index of packet being commented
    private string _commentBuf       = "";       // edit buffer for inline comment

    // ── PCAP export ───────────────────────────────────────────────────────
    private bool   _pcapExporting   = false;
    private string _pcapLastPath    = "";

    // ── Entropy sub-view ──────────────────────────────────────────────────
    private bool   _showEntropy     = false;
    private int    _entropyOpcode   = -1;      // -1 = all opcodes
    private int    _entropyDir      = 0;       // 0=both 1=CS 2=SC
    private List<float> _entropyCache = new();
    private int    _entropyCacheForPktCount = 0;

    // Right-click context state
    private int  _ctxIdx  = -1;

    public void SetDiffTab(DiffAnalysisTab diff) => _diffTab = diff;

    public CaptureTab(TestLog log, PacketLog pktLog, ServerConfig config)
    {
        _log      = log;
        _config   = config;
        _capture  = new PacketCapture(log, pktLog);
        _udpProxy = new UdpProxy(log, pktLog);

        // Forward UdpProxy packets into the shared capture list
        _udpProxy.OnPacket += pkt =>
        {
            _capture.AddPacketExternal(pkt);
            if (pkt.Injected)
                _log.Warn($"[UDP][INJ] {pkt.DirectionLabel} {pkt.RawBytes.Length}b");
        };

        _config.OnChanged += () =>
            _listenPort = _config.ServerPort + 1;
    }

    private bool IsRunning =>
        _capture.IsRunning || _tlsIntercepting || _udpProxy.IsRunning;

    public void Render()
    {
        ImGui.Spacing();
        RenderSetupPanel();
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();
        RenderPacketList();
    }

    // ── Setup panel ───────────────────────────────────────────────────────

    private void RenderSetupPanel()
    {
        bool   running = IsRunning;
        string localIp = GetLocalIp();
        float  w       = ImGui.GetContentRegionAvail().X;
        float  half    = (w - 12) * 0.5f;

        // Config + Mode side by side
        UiHelper.SectionBox("SERVER / PROXY CONFIG", half, 185, () =>
        {
            if (_config.IsSet)
            {
                UiHelper.Pill(
                    $"[>] {_config.ServerIp}:{_config.ServerPort}",
                    MenuRenderer.ColAccent, MenuRenderer.ColAccentDim);
                ImGui.Spacing();
            }
            else
            {
                UiHelper.DangerText("Set server IP in Dashboard tab first.");
                ImGui.Spacing();
            }

            ImGui.BeginDisabled(true);
            string dispIp   = _config.IsSet ? _config.ServerIp  : "- not set -";
            int    dispPort = _config.IsSet ? _config.ServerPort : 0;
            ImGui.SetNextItemWidth(190);
            ImGui.InputText("Server IP##csr",  ref dispIp,   64);
            ImGui.SameLine();
            ImGui.SetNextItemWidth(90);
            ImGui.InputInt("Port##csrp", ref dispPort);
            ImGui.EndDisabled();

            ImGui.Spacing();

            ImGui.BeginDisabled(running);
            ImGui.SetNextItemWidth(90);
            if (ImGui.InputInt("Proxy Port##plp", ref _listenPort))
                _listenPort = Math.Clamp(_listenPort, 1, 65535);
            ImGui.SameLine();
            UiHelper.MutedLabel("<- client connects here");
            ImGui.EndDisabled();
        });

        ImGui.SameLine(0, 12);

        UiHelper.SectionBox("CAPTURE MODE", half, 185, () =>
        {
            UiHelper.MutedLabel("Select capture protocol:");
            ImGui.Spacing();

            ImGui.BeginDisabled(running);

            void ModeBtn(string lbl, CaptureMode m)
            {
                bool sel = _mode == m;
                ImGui.PushStyleColor(ImGuiCol.Button,
                    sel ? new Vector4(0.18f, 0.95f, 0.45f, 0.22f)
                        : MenuRenderer.ColBg3);
                ImGui.PushStyleColor(ImGuiCol.Text,
                    sel ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
                if (ImGui.Button(lbl + $"##cm{(int)m}", new Vector2(-1, 26)))
                    _mode = m;
                ImGui.PopStyleColor(2);
            }

            ModeBtn("UDP  -  Hytale (recommended)", CaptureMode.Udp);
            ModeBtn("TCP  -  Plain unencrypted",     CaptureMode.Tcp);
            ModeBtn("TLS  -  HTTPS intercept",       CaptureMode.Tls);

            ImGui.EndDisabled();

            ImGui.Spacing();
            string desc = _mode switch
            {
                CaptureMode.Udp => "Best for Hytale. Proxies UDP game packets.",
                CaptureMode.Tcp => "Use if server communicates over plain TCP.",
                CaptureMode.Tls => "Decrypts TLS. Fails if game pins certificates.",
                _               => ""
            };
            UiHelper.MutedLabel(desc);
        });

        ImGui.Spacing(); ImGui.Spacing();

        // Start / Stop row
        if (!running)
        {
            ImGui.BeginDisabled(!_config.IsSet);
            UiHelper.PrimaryButton(
                $">  Start {_mode} Capture + Copy Address",
                360, 34, () => StartCapture(localIp));
            ImGui.EndDisabled();

            if (!_config.IsSet)
            {
                ImGui.SameLine(0, 10);
                UiHelper.DangerText("Set server in Dashboard first");
            }
        }
        else
        {
            UiHelper.DangerButton("■  Stop", 100, 34, StopCapture);
            ImGui.SameLine(0, 16);
            string addr = $"{localIp}:{_listenPort}";
            UiHelper.AccentText($"Connect game to:  {addr}");
            ImGui.SameLine(0, 10);
            UiHelper.SecondaryButton("Copy##cpa", 54, 34, () =>
            {
                ImGui.SetClipboardText(addr);
                _log.Info($"[Capture] Copied {addr}");
            });
        }

        ImGui.Spacing();

        // TLS status row
        if (_mode == CaptureMode.Tls)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.10f, 0.07f, 0.18f, 1f));
            ImGui.BeginChild("##tlsi", new Vector2(-1, 30), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();
            ImGui.SetCursorPos(new Vector2(12, 6));
            ImGui.PushStyleColor(ImGuiCol.Text,
                _tlsIntercepting ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted(
                _tlsIntercepting ? "[>] TLS Active - Decrypting" : "[>] TLS Inactive");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 20);
            UiHelper.MutedLabel(_tlsCertStatus);
            ImGui.EndChild();
            ImGui.Spacing();
        }

        // Status bar (3-step progress)
        var  pkts      = _capture.GetPackets();
        bool hasClient = _capture.TotalClients > 0 || _udpProxy.TotalClients > 0;
        bool hasPkts   = pkts.Count > 0;
        string modeStatus = _mode switch {
            CaptureMode.Udp => _udpProxy.IsRunning   ? $"[>] PROXY ON (UDP)" : "[>] PROXY OFF",
            CaptureMode.Tcp => _capture.IsRunning     ? $"[>] PROXY ON (TCP)" : "[>] PROXY OFF",
            CaptureMode.Tls => _tlsIntercepting       ? $"[>] PROXY ON (TLS)" : "[>] PROXY OFF",
            _               => "[>] PROXY OFF"
        };

        ImGui.PushStyleColor(ImGuiCol.ChildBg,
            running ? new Vector4(0.05f, 0.15f, 0.06f, 1f)
                    : new Vector4(0.13f, 0.05f, 0.05f, 1f));
        ImGui.BeginChild("##sbar", new Vector2(-1, 34), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 8));

        ImGui.PushStyleColor(ImGuiCol.Text,
            running ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(running ? $"[>] PROXY ON ({_mode})" : "[>] PROXY OFF");
        ImGui.PopStyleColor();

        ImGui.SameLine(200);
        ImGui.PushStyleColor(ImGuiCol.Text,
            hasClient ? MenuRenderer.ColAccent
                      : (running ? MenuRenderer.ColWarn : MenuRenderer.ColTextMuted));
        ImGui.TextUnformatted(hasClient ? "[>] CLIENT CONNECTED"
                                        : (running ? "[>] WAITING FOR CLIENT" : "[>] -"));
        ImGui.PopStyleColor();

        ImGui.SameLine(420);
        ImGui.PushStyleColor(ImGuiCol.Text,
            hasPkts ? MenuRenderer.ColAccent
                    : (hasClient ? MenuRenderer.ColWarn : MenuRenderer.ColTextMuted));
        ImGui.TextUnformatted(hasPkts ? $"[>] {pkts.Count} PACKETS"
                                      : (hasClient ? "[>] DO SOMETHING IN GAME" : "[>] -"));
        ImGui.PopStyleColor();

        ImGui.EndChild();
    }

    // ── Packet list ───────────────────────────────────────────────────────

    private void RenderPacketList()
    {
        var   packets = _capture.GetPackets();
        float w       = ImGui.GetContentRegionAvail().X;

        // ── Filter toolbar ─────────────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##fbar", new Vector2(w, 56), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 5));
        ImGui.SetNextItemWidth(200);
        ImGui.InputText("##flt", ref _filterText, 128);
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("C->S##cs", ref _showClientServer);
        ImGui.SameLine(0, 8);
        ImGui.Checkbox("S->C##sc", ref _showServerClient);
        ImGui.SameLine(0, 8);
        ImGui.Checkbox("Auto-scroll##as", ref _autoScroll);
        ImGui.SameLine(0, 10);
        ImGui.Checkbox("Hide <15b##hsm", ref _hideSmallPkts);

        // Row 2: counts + export controls
        ImGui.SetCursorPosX(8);
        UiHelper.MutedLabel($"{packets.Count} captured  |  dbl-click row to comment");
        ImGui.SameLine(0, 20);
        ImGui.BeginDisabled(packets.Count == 0 || _pcapExporting);
        UiHelper.SecondaryButton(
            _pcapExporting ? "Exporting..." : "⬇ Export PCAP##pcapexp",
            140, 20, ExportPcap);
        ImGui.EndDisabled();
        if (_pcapLastPath.Length > 0)
        {
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel(_pcapLastPath);
        }
        ImGui.SameLine(0, 16);
        if (ImGui.Checkbox("Entropy view##ent", ref _showEntropy) && _showEntropy)
            RebuildEntropyCache(packets);

        ImGui.EndChild();
        ImGui.Spacing();

        if (packets.Count == 0)
        {
            float tw = ImGui.CalcTextSize("Start proxy above and connect your game client.").X;
            ImGui.SetCursorPosX((w - tw) * 0.5f);
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 40);
            UiHelper.MutedLabel("Start proxy above and connect your game client.");
            return;
        }

        // ── Entropy view (shown above packet list if enabled) ──────────────
        if (_showEntropy) RenderEntropyPanel(packets, w);

        // ── Build filtered list (cheap, avoids LINQ allocation on hot path) ──
        var filtered = new List<(int globalIdx, CapturedPacket pkt)>(packets.Count);
        string filterUp = _filterText.ToUpperInvariant();
        foreach (var (idx, pkt) in packets.Select((p, i) => (i, p)))
        {
            if (!_showClientServer && pkt.Direction == PacketDirection.ClientToServer) continue;
            if (!_showServerClient && pkt.Direction == PacketDirection.ServerToClient) continue;
            if (_hideSmallPkts && pkt.RawBytes.Length < 15) continue;
            if (filterUp.Length > 0)
            {
                if (!pkt.HexString.Contains(filterUp) &&
                    !pkt.AsciiPreview.ToUpperInvariant().Contains(filterUp))
                    continue;
            }
            filtered.Add((idx, pkt));
        }

        // ── Layout ─────────────────────────────────────────────────────────
        float dw = 390f;
        float lw = ImGui.GetContentRegionAvail().X - dw - 8;
        float h  = ImGui.GetContentRegionAvail().Y;

        const float RowH = 20f;

        // ── Left pane: packet list with clipper ────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##pl", new Vector2(lw, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 5));
        UiHelper.MutedLabel("   #      Time           Dir            Bytes  Comment/Preview");

        var dlL   = ImGui.GetWindowDrawList();
        var lpPos = ImGui.GetWindowPos();
        float hly = ImGui.GetCursorScreenPos().Y - 2;
        dlL.AddLine(new Vector2(lpPos.X, hly), new Vector2(lpPos.X + lw, hly),
            ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        // Subtle row background colors by direction
        var csBg = new Vector4(0.08f, 0.10f, 0.18f, 1f); // dark blue tint = C->S
        var scBg = new Vector4(0.07f, 0.14f, 0.09f, 1f); // dark green tint = S->C

        // ImGuiListClipper - only renders visible rows
        ImGui.SetNextWindowScroll(ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 30 && _autoScroll
            ? new Vector2(-1, float.MaxValue) : new Vector2(-1, -1));

        var clipper = new ImGuiListClipper();
        clipper.Begin(filtered.Count, RowH);
        while (clipper.Step())
        {
            for (int vi = clipper.DisplayStart; vi < clipper.DisplayEnd; vi++)
            {
                var (globalIdx, p) = filtered[vi];
                bool cs  = p.Direction == PacketDirection.ClientToServer;
                var  rowBg = cs ? csBg : scBg;
                string dir = cs ? "C -> S" : "S -> C";

                // Draw direction-tinted background
                var sp = ImGui.GetCursorScreenPos();
                dlL.AddRectFilled(sp, sp + new Vector2(lw, RowH),
                    ImGui.ColorConvertFloat4ToU32(rowBg));

                // Selected row overlay
                if (_selectedIndex == globalIdx)
                    dlL.AddRectFilled(sp, sp + new Vector2(lw, RowH),
                        ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));

                // Comment or preview
                string annotation = p.Comment.Length > 0
                    ? $"[{p.Comment}]"
                    : (p.AsciiPreview.Length > 18 ? p.AsciiPreview[..18] + "..." : p.AsciiPreview);

                ImGui.PushStyleColor(ImGuiCol.Text,
                    p.Comment.Length > 0 ? MenuRenderer.ColWarn
                    : cs ? MenuRenderer.ColBlue : MenuRenderer.ColAccent);

                bool clicked = ImGui.Selectable(
                    $"   {globalIdx + 1,-5} {p.TimestampLabel}  {dir,-14} {p.RawBytes.Length,-7} {annotation}##pk{globalIdx}",
                    _selectedIndex == globalIdx, ImGuiSelectableFlags.None, new Vector2(0, RowH));
                ImGui.PopStyleColor();

                if (clicked) _selectedIndex = globalIdx;

                // Double-click -> enter comment mode
                if (ImGui.IsItemHovered() && ImGui.IsMouseDoubleClicked(ImGuiMouseButton.Left))
                {
                    _commentingIdx = globalIdx;
                    _commentBuf    = p.Comment;
                    ImGui.OpenPopup($"##cmt{globalIdx}");
                }

                // Comment popup
                if (_commentingIdx == globalIdx && ImGui.BeginPopup($"##cmt{globalIdx}"))
                {
                    ImGui.TextUnformatted("Add comment:");
                    ImGui.SetNextItemWidth(220);
                    if (ImGui.InputText("##cmtinput", ref _commentBuf, 128,
                            ImGuiInputTextFlags.EnterReturnsTrue))
                    {
                        p.Comment      = _commentBuf;
                        _commentingIdx = -1;
                        ImGui.CloseCurrentPopup();
                    }
                    ImGui.SameLine(0, 8);
                    if (ImGui.Button("OK##cmtok")) { p.Comment = _commentBuf; _commentingIdx = -1; ImGui.CloseCurrentPopup(); }
                    ImGui.SameLine(0, 4);
                    if (ImGui.Button("Clear##cmtcl")) { p.Comment = ""; _commentingIdx = -1; ImGui.CloseCurrentPopup(); }
                    ImGui.EndPopup();
                }

                // ── Right-click context menu ────────────────────────────
                if (ImGui.BeginPopupContextItem($"##ctx{globalIdx}"))
                {
                    _selectedIndex = globalIdx;
                    _ctxIdx        = globalIdx;
                    if (ImGui.MenuItem("Copy Hex"))
                    {
                        ImGui.SetClipboardText(p.HexString);
                        _log.Info($"[Capture] Pkt #{globalIdx + 1} hex copied.");
                    }
                    ImGui.Separator();
                    if (ImGui.MenuItem("Send to Diff A") && _diffTab != null)
                    {
                        _diffTab.SetSlotA(p.HexString);
                        _log.Info($"[Capture] Pkt #{globalIdx + 1} -> Diff A.");
                    }
                    if (ImGui.MenuItem("Send to Diff B") && _diffTab != null)
                    {
                        _diffTab.SetSlotB(p.HexString);
                        _log.Info($"[Capture] Pkt #{globalIdx + 1} -> Diff B.");
                    }
                    ImGui.Separator();
                    if (ImGui.MenuItem("Add Comment..."))
                    {
                        _commentingIdx = globalIdx;
                        _commentBuf    = p.Comment;
                        ImGui.CloseCurrentPopup();
                        ImGui.OpenPopup($"##cmt{globalIdx}");
                    }
                    ImGui.EndPopup();
                }
            }
        }
        // ImGuiListClipper in this ImGui.NET build does not expose End(); no explicit cleanup required here.

        if (_autoScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 30)
            ImGui.SetScrollHereY(1.0f);

        ImGui.EndChild();
        ImGui.SameLine(0, 8);

        // ── Right pane: detail ─────────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##pd", new Vector2(dw, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        // Find selected packet in full (unfiltered) list
        CapturedPacket? sel = (_selectedIndex >= 0 && _selectedIndex < packets.Count)
            ? packets[_selectedIndex] : null;

        if (sel != null)
        {
            bool cs = sel.Direction == PacketDirection.ClientToServer;

            ImGui.SetCursorPos(new Vector2(12, 10));
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
            ImGui.TextUnformatted("PACKET DETAIL");
            ImGui.PopStyleColor();

            var ddl = ImGui.GetWindowDrawList();
            var dp  = ImGui.GetWindowPos();
            float dly = ImGui.GetCursorScreenPos().Y - 2;
            ddl.AddLine(new Vector2(dp.X + 12, dly), new Vector2(dp.X + dw - 12, dly),
                ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
            ImGui.Spacing();

            UiHelper.StatusRow("Time",      sel.TimestampLabel, true, 80);
            UiHelper.StatusRow("Direction", cs ? "Client -> Server" : "Server -> Client", cs, 80);
            UiHelper.StatusRow("Size",      $"{sel.RawBytes.Length} bytes", true, 80);

            if (sel.Comment.Length > 0)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted($"  [*] {sel.Comment}");
                ImGui.PopStyleColor();
            }

            if (sel.RawBytes.Length > 0)
            {
                ImGui.Spacing();
                UiHelper.MutedLabel("Packet ID (first byte):");
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
                ImGui.TextUnformatted($"  0x{sel.RawBytes[0]:X2}   ({sel.RawBytes[0]})");
                ImGui.PopStyleColor();
            }

            ImGui.Spacing();
            ddl.AddLine(
                new Vector2(dp.X + 12, ImGui.GetCursorScreenPos().Y),
                new Vector2(dp.X + dw  - 12, ImGui.GetCursorScreenPos().Y),
                ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
            ImGui.Spacing();

            // Decompression toggle + hex dump
            UiHelper.MutedLabel("Hex dump:");
            ImGui.SameLine(0, 16);
            ImGui.Checkbox("Auto-decompress##dcv", ref _decompressView);

            byte[] displayBytes = sel.RawBytes;
            string decompLabel  = "";
            if (_decompressView && sel.RawBytes.Length > 4)
            {
                var decompressed = PacketAnalyser.TryDecompress(sel.RawBytes, out string method);
                if (decompressed != null)
                {
                    displayBytes = decompressed;
                    decompLabel  = $"  <- {method} {decompressed.Length}b";
                }
                else decompLabel = "  (not compressed)";
            }
            if (decompLabel.Length > 0)
            {
                ImGui.SameLine(0, 8);
                ImGui.PushStyleColor(ImGuiCol.Text, decompLabel.Contains("<-")
                    ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
                ImGui.TextUnformatted(decompLabel);
                ImGui.PopStyleColor();
            }

            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.7f, 1.0f, 0.7f, 1f));
            for (int row = 0; row < displayBytes.Length; row += 16)
            {
                int len = Math.Min(16, displayBytes.Length - row);
                string hex = string.Join(" ", displayBytes.Skip(row).Take(len).Select(b => $"{b:X2}"));
                string asc = new string(displayBytes.Skip(row).Take(len)
                    .Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
                ImGui.TextUnformatted($"{row:X4}  {hex,-47}  {asc}");
            }
            ImGui.PopStyleColor();

            ImGui.Spacing();
            UiHelper.MutedLabel("ASCII:");
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.9f, 0.9f, 0.6f, 1f));
            ImGui.TextWrapped(sel.AsciiPreview);
            ImGui.PopStyleColor();

            ImGui.Spacing();
            UiHelper.SecondaryButton("Copy Hex##cph", -1, 26, () =>
            {
                ImGui.SetClipboardText(sel.HexString);
                _log.Info($"[Capture] Pkt #{_selectedIndex + 1} copied.");
            });
            if (_diffTab != null)
            {
                UiHelper.SecondaryButton("-> Diff A##da", -1, 26, () =>
                {
                    _diffTab.SetSlotA(sel.HexString);
                    _log.Info($"[Capture] Pkt #{_selectedIndex + 1} -> Diff A.");
                });
                UiHelper.SecondaryButton("-> Diff B##db", -1, 26, () =>
                {
                    _diffTab.SetSlotB(sel.HexString);
                    _log.Info($"[Capture] Pkt #{_selectedIndex + 1} -> Diff B.");
                });
            }
            UiHelper.SecondaryButton("Send to Log##stl", -1, 26, () =>
                _log.Info($"[Capture] Pkt #{_selectedIndex + 1}:\n{sel.HexString}"));
        }
        else
        {
            ImGui.SetCursorPosY(h * 0.4f);
            float tw2 = ImGui.CalcTextSize("<- select a packet").X;
            ImGui.SetCursorPosX((dw - tw2) * 0.5f);
            UiHelper.MutedLabel("<- select a packet");
        }

        ImGui.EndChild();
    }

        // ── Start / Stop ──────────────────────────────────────────────────────

    private void StartCapture(string localIp)
    {
        switch (_mode)
        {
            case CaptureMode.Udp:
                _udpProxy.Start("0.0.0.0", _listenPort,
                    _config.ServerIp, _config.ServerPort);
                break;
            case CaptureMode.Tcp:
                _capture.Start("0.0.0.0", _listenPort,
                    _config.ServerIp, _config.ServerPort);
                break;
            case CaptureMode.Tls:
                StartTlsProxy();
                break;
        }

        string addr = $"{localIp}:{_listenPort}";
        ImGui.SetClipboardText(addr);
        _log.Success($"[Capture] Address copied: {addr}");
        _log.Info("[Capture] Disconnect in game and reconnect to address above.");
    }

    private void StopCapture()
    {
        _capture.Stop();
        _udpProxy.Stop();
        _tlsCts?.Cancel();
        _tlsIntercepting = false;
        _log.Warn("[Capture] All capture stopped.");
    }

    /// Exposed so PacketTab and PrivilegeTab can inject packets via the proxy.
    public UdpProxy UdpProxy => _udpProxy;

    // ── TLS proxy ─────────────────────────────────────────────────────────

    private void StartTlsProxy()
    {
        _tlsCertStatus = "Generating...";
        try
        {
            _tlsCert       = GenerateSelfSignedCert(_config.ServerIp);
            _tlsCertStatus = $"Ready (CN={_config.ServerIp})";
            _log.Success("[TLS] Certificate generated.");
        }
        catch (Exception ex)
        {
            _tlsCertStatus = $"Error: {ex.Message}";
            _log.Error($"[TLS] Cert: {ex.Message}");
            return;
        }

        _tlsCts          = new CancellationTokenSource();
        _tlsIntercepting = true;
        Task.Run(() => TlsListenLoop(_tlsCts.Token));
        _log.Success($"[TLS] Proxy on port {_listenPort}");
    }

    private async Task TlsListenLoop(CancellationToken ct)
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Any, _listenPort);
        listener.Start();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                _capture.IncrementClients();
                _log.Success($"[TLS] Client from {client.Client.RemoteEndPoint}");
                _ = Task.Run(() => HandleTlsClient(client, ct), ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (_tlsIntercepting) _log.Error($"[TLS] Listener: {ex.Message}");
        }
        finally
        {
            listener.Stop();
            _tlsIntercepting = false;
        }
    }

    private async Task HandleTlsClient(System.Net.Sockets.TcpClient client,
                                        CancellationToken ct)
    {
        System.Net.Sockets.TcpClient? server = null;
        SslStream? clientSsl = null;
        SslStream? serverSsl = null;
        try
        {
            clientSsl = new SslStream(client.GetStream(), false,
                (s, c, ch, e) => true);
            await clientSsl.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions
                {
                    ServerCertificate         = _tlsCert,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols       =
                        System.Security.Authentication.SslProtocols.Tls12 |
                        System.Security.Authentication.SslProtocols.Tls13,
                }, ct);
            _log.Success("[TLS] [OK] Client handshake - decrypting!");

            server    = new System.Net.Sockets.TcpClient();
            await server.ConnectAsync(_config.ServerIp, _config.ServerPort, ct);
            serverSsl = new SslStream(server.GetStream(), false,
                (s, c, ch, e) => true);
            await serverSsl.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = _config.ServerIp,
                    RemoteCertificateValidationCallback = (s, c, ch, e) => true,
                    EnabledSslProtocols =
                        System.Security.Authentication.SslProtocols.Tls12 |
                        System.Security.Authentication.SslProtocols.Tls13,
                }, ct);
            _log.Success("[TLS] [OK] Server handshake - full intercept active!");

            await Task.WhenAny(
                TlsPipeAsync(clientSsl, serverSsl, PacketDirection.ClientToServer, ct),
                TlsPipeAsync(serverSsl, clientSsl, PacketDirection.ServerToClient, ct));
        }
        catch (Exception ex)
        {
            if (ex.Message.Contains("authentication") || ex.Message.Contains("handshake"))
            {
                _log.Error("[TLS] Handshake failed - game likely pins certificates.");
                _log.Warn("[TLS] Switch to UDP mode instead.");
            }
            else _log.Error($"[TLS] {ex.Message}");
        }
        finally
        {
            clientSsl?.Dispose(); serverSsl?.Dispose();
            client.Dispose(); server?.Dispose();
        }
    }

    private async Task TlsPipeAsync(SslStream source, SslStream dest,
                                     PacketDirection dir, CancellationToken ct)
    {
        var buf = new byte[65536];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int n = await source.ReadAsync(buf, ct);
                if (n == 0) break;
                var chunk = new byte[n];
                Array.Copy(buf, chunk, n);
                await dest.WriteAsync(buf.AsMemory(0, n), ct);
                var pkt = new CapturedPacket
                {
                    Timestamp    = DateTime.Now,
                    Direction    = dir,
                    RawBytes     = chunk,
                    HexString    = PacketCapture.ToHex(chunk),
                    AsciiPreview = PacketCapture.ToAscii(chunk),
                };
                _capture.AddPacketExternal(pkt);
                string d = dir == PacketDirection.ClientToServer ? "C->S" : "S->C";
                _log.Info($"[TLS][{d}] {n}b decrypted | " +
                          $"{pkt.HexString[..Math.Min(48, pkt.HexString.Length)]}");
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!ct.IsCancellationRequested)
                _log.Error($"[TLS] Pipe ({dir}): {ex.Message}");
        }
    }

    private static X509Certificate2 GenerateSelfSignedCert(string host)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            $"CN={host}", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature |
            X509KeyUsageFlags.KeyEncipherment, false));

        var san = new SubjectAlternativeNameBuilder();
        if (IPAddress.TryParse(host, out var ip)) san.AddIpAddress(ip);
        else san.AddDnsName(host);
        req.CertificateExtensions.Add(san.Build());

        var cert = req.CreateSelfSigned(
            DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddYears(1));

        return new X509Certificate2(
            cert.Export(X509ContentType.Pfx), (string?)null,
            X509KeyStorageFlags.Exportable);
    }

    private static string GetLocalIp()
    {
        try
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            var ip   = host.AddressList.FirstOrDefault(
                a => a.AddressFamily == AddressFamily.InterNetwork);
            return ip?.ToString() ?? "127.0.0.1";
        }
        catch { return "127.0.0.1"; }
    }

    // ── PCAP Export ───────────────────────────────────────────────────────

    private void ExportPcap()
    {
        _pcapExporting = true;
        var packets    = _capture.GetPackets();
        string srv     = _config.IsSet ? _config.ServerIp : null!;

        Task.Run(() =>
        {
            try
            {
                string dir  = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    "HytaleCaptures");
                Directory.CreateDirectory(dir);
                string path = Path.Combine(dir,
                    $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcap");

                int written = PcapWriter.Write(path, packets, srv);
                _pcapLastPath = $"Saved {written} pkts -> {path}";
                _log.Success($"[Capture] PCAP export: {written} packets -> {path}");
                AlertBus.Push(AlertBus.Sec_Capture, AlertLevel.Info,
                    $"PCAP exported: {written} packets");
            }
            catch (Exception ex)
            {
                _pcapLastPath = $"Export failed: {ex.Message}";
                _log.Error($"[Capture] PCAP export: {ex.Message}");
            }
            finally { _pcapExporting = false; }
        });
    }

    // ── Entropy View ──────────────────────────────────────────────────────

    private void RenderEntropyPanel(List<CapturedPacket> packets, float w)
    {
        // Rebuild cache if packet count changed
        if (packets.Count != _entropyCacheForPktCount)
            RebuildEntropyCache(packets);

        UiHelper.SectionBox("ENTROPY ANALYSIS", w, 150, () =>
        {
            // Controls
            ImGui.SetNextItemWidth(90);
            ImGui.InputInt("Opcode filter##entop", ref _entropyOpcode);
            if (_entropyOpcode < -1) _entropyOpcode = -1;
            if (_entropyOpcode > 255) _entropyOpcode = 255;
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel(_entropyOpcode < 0 ? "(all)" : $"0x{_entropyOpcode:X2}");
            ImGui.SameLine(0, 16);
            ImGui.SetNextItemWidth(72);
            ImGui.Combo("Dir##entdir", ref _entropyDir, new[] { "Both", "C->S", "S->C" }, 3);
            ImGui.SameLine(0, 8);
            UiHelper.SecondaryButton("Refresh##entref", 80, 22, () => RebuildEntropyCache(packets));
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel($"{_entropyCache.Count} packets analysed");

            ImGui.Spacing();

            if (_entropyCache.Count == 0) { UiHelper.MutedLabel("No matching packets."); return; }

            // Shannon entropy bar chart - one bar per packet sample
            float gw  = ImGui.GetContentRegionAvail().X;
            float gh  = 70f;
            var   cp  = ImGui.GetCursorScreenPos();
            var   gdl = ImGui.GetWindowDrawList();

            gdl.AddRectFilled(cp, cp + new Vector2(gw, gh),
                ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBg2));

            // Grid lines at 2/4/6/8 bits
            foreach (float grid in new[] { 2f, 4f, 6f, 8f })
            {
                float gy = cp.Y + gh - (grid / 8f * gh);
                gdl.AddLine(new Vector2(cp.X, gy), new Vector2(cp.X + gw, gy),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
                gdl.AddText(new Vector2(cp.X + 2, gy - 12),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColTextMuted), $"{grid:F0}b");
            }

            int   n       = _entropyCache.Count;
            float barW    = Math.Max(1, gw / n);

            for (int i = 0; i < n; i++)
            {
                float ent   = _entropyCache[i];           // 0-8 bits
                float barH  = ent / 8f * gh;
                float bx    = cp.X + i * barW;
                float by    = cp.Y + gh - barH;

                var barCol  = ent > 6.5f ? MenuRenderer.ColDanger   // high entropy = likely encrypted
                            : ent > 4f   ? MenuRenderer.ColWarn
                            :              MenuRenderer.ColAccent;

                gdl.AddRectFilled(new Vector2(bx, by), new Vector2(bx + barW - 1, cp.Y + gh),
                    ImGui.ColorConvertFloat4ToU32(barCol));
            }

            ImGui.Dummy(new Vector2(gw, gh));

            // Averages
            float avg = _entropyCache.Average();
            float max = _entropyCache.Max();
            float min = _entropyCache.Min();
            ImGui.SameLine(0, 0);
            ImGui.SetCursorPosX(gw * 0.55f);
            UiHelper.MutedLabel($"avg:{avg:F2}b  min:{min:F2}b  max:{max:F2}b  " +
                $"{(avg > 6.5f ? "HIGH entropy - likely encrypted" : avg > 4f ? "Medium entropy" : "Low entropy - plaintext")}");
        });

        ImGui.Spacing();
    }

    private void RebuildEntropyCache(List<CapturedPacket> packets)
    {
        _entropyCache.Clear();
        var src = packets.AsEnumerable();
        if (_entropyDir == 1) src = src.Where(p => p.Direction == PacketDirection.ClientToServer);
        if (_entropyDir == 2) src = src.Where(p => p.Direction == PacketDirection.ServerToClient);
        if (_entropyOpcode >= 0) src = src.Where(p => p.RawBytes.Length > 0 && p.RawBytes[0] == _entropyOpcode);

        foreach (var pkt in src.TakeLast(400))
        {
            if (pkt.RawBytes.Length < 4) continue;
            _entropyCache.Add(ShannonEntropy(pkt.RawBytes));
        }
        _entropyCacheForPktCount = packets.Count;
    }

    private static float ShannonEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;
        int[] freq = new int[256];
        foreach (byte b in data) freq[b]++;
        double entropy = 0;
        double len     = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = freq[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return (float)entropy;
    }
}

