using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Text;
using System.Net.Sockets;
using System.Collections.Concurrent;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Mod Auditor — Universal mod / permission vulnerability scanner.
///
/// Sub-tabs:
///   Claims      — Claim/Zone border visualizer + ESP data + edge-gap detection
///   Interact    — Universal Interaction Spoofer (Force Interact, Ghost Mode)
///   Inventory   — Virtual Inventory Sniffer (Open Window, Remote Open)
///   Entities    — Active Modded Entities, Permission Status, Brute Force IDs
///   Race        — Race Condition / Burst Send tool
///   Dialogue    — NPC Dialogue Interceptor (hidden option IDs)
///   Teleport    — Teleport Hook (override X/Y/Z before packet leaves)
///   Payload     — Packet Payload Scaler (Area/Radius × slider)
///   Deps        — Dependency Scanner (mod library fingerprinting)
///   LagSwitch   — Defer Packets / Lag Switch buffer mode
/// </summary>
public class ModAuditorTab : ITab
{
    public string Title => "  Mod Auditor  ";

    private readonly TestLog       _log;
    private readonly PacketCapture _capture;
    private readonly UdpProxy      _udpProxy;
    private readonly ServerConfig  _config;
    private readonly PacketStore   _store;

    // ── Sub-tab ────────────────────────────────────────────────────────────
    private int _subTab = 0;
    private static readonly string[] SubTabs =
    {
        "Claims", "Interact", "Inventory", "Entities",
        "Race", "Dialogue", "Teleport", "Payload", "Deps", "LagSwitch"
    };

    // ── Shared ─────────────────────────────────────────────────────────────
    private int _lastPktCount = 0;

    public ModAuditorTab(TestLog log, PacketCapture capture, UdpProxy udpProxy,
                         ServerConfig config, PacketStore store)
    {
        _log = log; _capture = capture; _udpProxy = udpProxy;
        _config = config; _store = store;
    }

    // ══════════════════════════════════════════════════════════════════════
    // RENDER ENTRY POINT
    // ══════════════════════════════════════════════════════════════════════

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;

        // Background scan — runs every frame when new packets arrive
        int cur = _capture.GetPacketCount();
        if (cur != _lastPktCount)
        {
            _lastPktCount = cur;
            BackgroundScan(_capture.GetPackets());
        }

        // Lag-switch intercept — drains queued packets if timer expired
        DrainLagBuffer();

        // Status bar
        RenderStatusBar(w);
        ImGui.Spacing();

        // Sub-tab bar
        if (ImGui.BeginTabBar("##maud_subtabs", ImGuiTabBarFlags.FittingPolicyScroll))
        {
            for (int i = 0; i < SubTabs.Length; i++)
                if (ImGui.TabItemButton(SubTabs[i] + $"##mast{i}", ImGuiTabItemFlags.None))
                    _subTab = i;
            ImGui.EndTabBar();
        }
        ImGui.Spacing();

        switch (_subTab)
        {
            case 0: RenderClaims(w);     break;
            case 1: RenderInteract(w);   break;
            case 2: RenderInventory(w);  break;
            case 3: RenderEntities(w);   break;
            case 4: RenderRace(w);       break;
            case 5: RenderDialogue(w);   break;
            case 6: RenderTeleport(w);   break;
            case 7: RenderPayload(w);    break;
            case 8: RenderDeps(w);       break;
            case 9: RenderLagSwitch(w);  break;
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // STATUS BAR
    // ══════════════════════════════════════════════════════════════════════

    private void RenderStatusBar(float w)
    {
        bool srv = _config.IsSet;
        bool ses = _capture.IsRunning || _udpProxy.IsRunning;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##maudst", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));

        ImGui.PushStyleColor(ImGuiCol.Text, srv ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(srv ? $"● {_config.ServerIp}:{_config.ServerPort}" : "● No server");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 20);
        ImGui.PushStyleColor(ImGuiCol.Text, ses ? MenuRenderer.ColAccent : MenuRenderer.ColWarn);
        ImGui.TextUnformatted(ses ? "● Proxy active" : "● No proxy — start Capture first");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 20);
        ImGui.PushStyleColor(ImGuiCol.Text, _lagSwitchActive ? MenuRenderer.ColDanger : MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(_lagSwitchActive
            ? $"⚡ LAG BUFFER ON — {_lagQueue.Count} queued"
            : "⚡ Lag buffer off");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 20);
        ImGui.PushStyleColor(ImGuiCol.Text, _claimZones.Count > 0 ? MenuRenderer.ColWarn : MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted($"◈ {_claimZones.Count} claim(s)");
        ImGui.PopStyleColor();
        ImGui.EndChild();
    }

    // ══════════════════════════════════════════════════════════════════════
    // BACKGROUND SCANNER — runs each frame when packet count changes
    // ══════════════════════════════════════════════════════════════════════

    private void BackgroundScan(List<CapturedPacket> packets)
    {
        // Scan last 50 new packets only (avoid rescanning full history)
        int start = Math.Max(0, packets.Count - 50);
        for (int i = start; i < packets.Count; i++)
        {
            var p = packets[i];
            if (p.IsMarker || p.RawBytes.Length < 4) continue;

            // Claim scanner
            TryScanClaim(p);
            // Open-window sniffer
            TryScanOpenWindow(p);
            // Dialogue option scanner
            TryScanDialogue(p);
            // Dependency fingerprinting
            TryScanDependency(p);
            // Teleport hook (outgoing)
            if (_teleportArmed && p.Direction == PacketDirection.ClientToServer)
                TryInterceptTeleport(p);
            // Burst-arm
            if (_burstArmed && p.Direction == PacketDirection.ClientToServer)
                TryInterceptBurst(p);
            // Payload scaler arm
            if (_payloadArmed && p.Direction == PacketDirection.ClientToServer)
                TryInterceptPayload(p);
            // Lag switch intercept (all outgoing)
            if (_lagSwitchActive && p.Direction == PacketDirection.ClientToServer)
                TryQueueForLag(p, i);
            // Entity permission scan
            TryScanEntityPermission(p);
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // TAB 0 — CLAIM & BORDER VISUALIZER
    // ══════════════════════════════════════════════════════════════════════

    private readonly List<ClaimZone> _claimZones = new();
    private int _claimSelectedIdx = -1;
    private string _claimFilterText = "";
    private bool _claimAutoScan = true;
    private string _claimManualHex = "";
    private int _claimParseOffset = 1;

    private void TryScanClaim(CapturedPacket p)
    {
        if (!_claimAutoScan) return;
        if (p.Direction != PacketDirection.ServerToClient) return;

        byte[] b = p.RawBytes;
        if (b.Length < 28) return;

        // Heuristic: look for 6 consecutive floats that look like two XYZ corners
        // (values in reasonable world bounds -100000..100000)
        for (int off = 1; off + 24 <= b.Length; off += 1)
        {
            try
            {
                float x0 = BitConverter.ToSingle(b, off);
                float y0 = BitConverter.ToSingle(b, off + 4);
                float z0 = BitConverter.ToSingle(b, off + 8);
                float x1 = BitConverter.ToSingle(b, off + 12);
                float y1 = BitConverter.ToSingle(b, off + 16);
                float z1 = BitConverter.ToSingle(b, off + 20);

                if (!IsReasonableCoord(x0) || !IsReasonableCoord(y0) || !IsReasonableCoord(z0)) continue;
                if (!IsReasonableCoord(x1) || !IsReasonableCoord(y1) || !IsReasonableCoord(z1)) continue;

                // The two corners should be different (non-degenerate)
                float dx = Math.Abs(x1 - x0), dz = Math.Abs(z1 - z0);
                if (dx < 1f || dz < 1f || dx > 5000f || dz > 5000f) continue;

                // Looks like a claim — find or add
                var zone = new ClaimZone
                {
                    Min = new Vector3(Math.Min(x0, x1), Math.Min(y0, y1), Math.Min(z0, z1)),
                    Max = new Vector3(Math.Max(x0, x1), Math.Max(y0, y1), Math.Max(z0, z1)),
                    Opcode    = b[0],
                    FoundAt   = p.Timestamp,
                    PacketHex = BytesToHex(b, 32),
                    EdgeGaps  = DetectEdgeGaps(x0, y0, z0, x1, y1, z1),
                };
                // De-duplicate by approximate position
                if (!_claimZones.Any(c =>
                    Vector3.Distance(c.Min, zone.Min) < 2f &&
                    Vector3.Distance(c.Max, zone.Max) < 2f))
                {
                    _claimZones.Add(zone);
                    _log.Info($"[ModAudit/Claims] Zone #{_claimZones.Count} detected " +
                              $"({zone.Min.X:F0},{zone.Min.Z:F0})→({zone.Max.X:F0},{zone.Max.Z:F0})" +
                              (zone.EdgeGaps > 0 ? $"  ⚠ {zone.EdgeGaps} edge gaps!" : ""));
                }
                break; // one claim per packet
            }
            catch { }
        }
    }

    private static bool IsReasonableCoord(float f)
        => !float.IsNaN(f) && !float.IsInfinity(f) && f > -200_000f && f < 200_000f;

    private static int DetectEdgeGaps(float x0, float y0, float z0, float x1, float y1, float z1)
    {
        // Edge gaps = boundary values not aligned to integer block grid
        int gaps = 0;
        float[] vals = { x0, y0, z0, x1, y1, z1 };
        foreach (var v in vals)
            if (Math.Abs(v - MathF.Round(v)) > 0.05f) gaps++;
        return gaps;
    }

    private void RenderClaims(float w)
    {
        UiHelper.SectionBox("CLAIM / ZONE SCANNER", w, 0, () =>
        {
            UiHelper.MutedLabel("Detects protected zone boundaries from S→C packets.");
            UiHelper.MutedLabel("'Edge Gaps' = boundary not aligned to block grid → MOB collision leakage.");
            ImGui.Spacing();

            ImGui.Checkbox("Auto-scan incoming packets##clautoscan", ref _claimAutoScan);
            ImGui.SameLine(0, 20);
            UiHelper.SecondaryButton("⟳ Re-scan All##clrescan", 130, 24, () =>
            {
                _claimZones.Clear();
                foreach (var p in _capture.GetPackets()) TryScanClaim(p);
                _log.Info($"[ModAudit/Claims] Re-scan: {_claimZones.Count} zones found.");
            });
            ImGui.SameLine(0, 8);
            UiHelper.DangerButton("Clear##clclear", 70, 24, () => { _claimZones.Clear(); _claimSelectedIdx = -1; });

            ImGui.Spacing();
            ImGui.SetNextItemWidth(200);
            ImGui.InputText("Filter name/opcode##clf", ref _claimFilterText, 32);
        });

        ImGui.Spacing();

        if (_claimZones.Count == 0)
        {
            UiHelper.SectionBox("DETECTED ZONES", w, 0, () =>
            {
                UiHelper.MutedLabel("No claim zones detected yet.");
                UiHelper.MutedLabel("Join a server and walk near claimed areas — zone boundary packets should appear.");
            });
            return;
        }

        // Zone list
        float listH = Math.Min(240f, _claimZones.Count * 26f + 30f);
        UiHelper.SectionBox($"DETECTED ZONES  ({_claimZones.Count})", w, listH, () =>
        {
            ImGui.SetCursorPosX(8);
            UiHelper.MutedLabel($"  {"#",-4}  {"Min XZ",-22}  {"Max XZ",-22}  {"W×H×D",-18}  {"Gaps",-6}  {"Opcode"}");

            var dl = ImGui.GetWindowDrawList();
            float lineY = ImGui.GetCursorScreenPos().Y - 2;
            dl.AddLine(new Vector2(ImGui.GetWindowPos().X + 8, lineY),
                       new Vector2(ImGui.GetWindowPos().X + w - 8, lineY),
                       ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

            var clip = new ImGuiListClipper();
            clip.Begin(_claimZones.Count, 24f);
            while (clip.Step())
            {
                for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++)
                {
                    var z = _claimZones[i];
                    bool sel = _claimSelectedIdx == i;

                    if (sel)
                    {
                        var sp = ImGui.GetCursorScreenPos();
                        dl.AddRectFilled(sp, sp + new Vector2(w - 16, 24),
                            ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
                    }

                    Vector4 col = z.EdgeGaps > 0 ? MenuRenderer.ColWarn : MenuRenderer.ColAccent;
                    ImGui.PushStyleColor(ImGuiCol.Text, col);

                    Vector3 size = z.Max - z.Min;
                    string gapStr = z.EdgeGaps > 0 ? $"⚠ {z.EdgeGaps}" : "—";

                    if (ImGui.Selectable(
                        $"  #{i + 1,-3}  ({z.Min.X:F0},{z.Min.Z:F0}){"",-6}  " +
                        $"({z.Max.X:F0},{z.Max.Z:F0}){"",-6}  " +
                        $"{size.X:F0}×{size.Y:F0}×{size.Z:F0}{"",-4}  " +
                        $"{gapStr,-6}  0x{z.Opcode:X2}##clz{i}",
                        sel, ImGuiSelectableFlags.None, new Vector2(0, 24)))
                        _claimSelectedIdx = i;

                    ImGui.PopStyleColor();
                }
            }
            clip.End();
        });

        // Detail panel for selected zone
        if (_claimSelectedIdx >= 0 && _claimSelectedIdx < _claimZones.Count)
        {
            ImGui.Spacing();
            var z = _claimZones[_claimSelectedIdx];
            Vector3 size = z.Max - z.Min;

            UiHelper.SectionBox("ZONE DETAIL", w, 0, () =>
            {
                UiHelper.StatusRow("Min corner",  $"X={z.Min.X:F2}  Y={z.Min.Y:F2}  Z={z.Min.Z:F2}", true, 100);
                UiHelper.StatusRow("Max corner",  $"X={z.Max.X:F2}  Y={z.Max.Y:F2}  Z={z.Max.Z:F2}", true, 100);
                UiHelper.StatusRow("Dimensions",  $"{size.X:F2} × {size.Y:F2} × {size.Z:F2} blocks",  true, 100);
                UiHelper.StatusRow("Opcode",      $"0x{z.Opcode:X2}", true, 100);
                UiHelper.StatusRow("Detected",    z.FoundAt.ToString("HH:mm:ss"),  true, 100);

                if (z.EdgeGaps > 0)
                {
                    ImGui.Spacing();
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                    ImGui.TextUnformatted($"  ⚠  {z.EdgeGaps} edge gap(s) detected — " +
                        "boundary not on block grid. Test placing blocks along the exact edge.");
                    ImGui.PopStyleColor();
                }

                ImGui.Spacing();
                UiHelper.MutedLabel("ESP Hint: pass Min/Max to VisualsTab DrawBox when world view matrix is available.");
                UiHelper.MutedLabel($"Raw hex: {z.PacketHex}");

                ImGui.Spacing();
                UiHelper.SecondaryButton("Copy ESP Data##clesp", 160, 26, () =>
                {
                    ImGui.SetClipboardText(
                        $"DrawBox({z.Min.X:F2}f,{z.Min.Y:F2}f,{z.Min.Z:F2}f," +
                        $"{z.Max.X:F2}f,{z.Max.Y:F2}f,{z.Max.Z:F2}f)");
                    _log.Info("[ModAudit/Claims] ESP data copied.");
                });
                ImGui.SameLine(0, 8);
                UiHelper.SecondaryButton("Remove##clrem", 80, 26, () =>
                {
                    _claimZones.RemoveAt(_claimSelectedIdx);
                    _claimSelectedIdx = -1;
                });
            });
        }

        ImGui.Spacing();

        // Manual parse
        UiHelper.SectionBox("MANUAL PACKET PARSE", w, 0, () =>
        {
            UiHelper.MutedLabel("Paste a packet hex and specify a byte offset to force-parse 6 floats as a zone.");
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Hex##clmhex", ref _claimManualHex, 2048);
            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("Start offset##clmoff", ref _claimParseOffset);
            _claimParseOffset = Math.Max(0, _claimParseOffset);
            ImGui.SameLine(0, 8);
            UiHelper.PrimaryButton("Parse##clmparse", 80, 24, () =>
            {
                try
                {
                    byte[] b = HexToBytes(_claimManualHex);
                    if (_claimParseOffset + 24 > b.Length)
                    { _log.Error("[ModAudit/Claims] Offset out of range."); return; }

                    float x0 = BitConverter.ToSingle(b, _claimParseOffset);
                    float y0 = BitConverter.ToSingle(b, _claimParseOffset + 4);
                    float z0 = BitConverter.ToSingle(b, _claimParseOffset + 8);
                    float x1 = BitConverter.ToSingle(b, _claimParseOffset + 12);
                    float y1 = BitConverter.ToSingle(b, _claimParseOffset + 16);
                    float z1 = BitConverter.ToSingle(b, _claimParseOffset + 20);

                    var zone = new ClaimZone
                    {
                        Min = new Vector3(Math.Min(x0, x1), Math.Min(y0, y1), Math.Min(z0, z1)),
                        Max = new Vector3(Math.Max(x0, x1), Math.Max(y0, y1), Math.Max(z0, z1)),
                        Opcode    = b.Length > 0 ? b[0] : (byte)0,
                        FoundAt   = DateTime.Now,
                        PacketHex = BytesToHex(b, 32),
                        EdgeGaps  = DetectEdgeGaps(x0, y0, z0, x1, y1, z1),
                    };
                    _claimZones.Add(zone);
                    _claimSelectedIdx = _claimZones.Count - 1;
                    _log.Success($"[ModAudit/Claims] Manual parse ok — {zone.Min}→{zone.Max}, gaps={zone.EdgeGaps}");
                }
                catch (Exception ex) { _log.Error($"[ModAudit/Claims] {ex.Message}"); }
            });
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // TAB 1 — UNIVERSAL INTERACTION SPOOFER
    // ══════════════════════════════════════════════════════════════════════

    private string _forceInteractCapHex = "";
    private int    _forceInteractActionOffset = 1;   // byte offset where ActionType lives
    private int    _forceInteractDistOffset   = 5;   // byte offset where Distance float lives
    private int    _forceInteractNewAction    = 0;   // 0=use, 1=open, 2=attack, 3=sneak-use
    private float  _forceInteractNewDist      = 0f;  // 0 = snap to zero
    private bool   _ghostModeEnabled          = false;
    private float  _ghostOffsetX              = 1f;
    private float  _ghostOffsetZ              = 1f;
    private int    _ghostDelayMs              = 50;
    private string _forceInteractStatus       = "";

    private void RenderInteract(float w)
    {
        UiHelper.SectionBox("FORCE INTERACT — PERMISSION BYPASS SPOOFER", w, 0, () =>
        {
            UiHelper.MutedLabel("Capture the last C→S interaction packet, mutate Distance or ActionType, and replay.");
            UiHelper.MutedLabel("Tests if protected objects only check ActionType or skip distance validation.");
            ImGui.Spacing();

            UiHelper.PrimaryButton("⟳ Capture Last C→S Packet##ficap", 200, 28, () =>
            {
                var pkts = _capture.GetPackets();
                var last = pkts.LastOrDefault(p => p.Direction == PacketDirection.ClientToServer
                                                && !p.IsMarker && p.RawBytes.Length >= 8);
                if (last != null)
                {
                    _forceInteractCapHex = BytesToHex(last.RawBytes, last.RawBytes.Length);
                    _forceInteractStatus = $"Captured {last.RawBytes.Length}b opcode=0x{last.RawBytes[0]:X2}";
                    _log.Info($"[ModAudit/Interact] Captured packet: {_forceInteractCapHex}");
                }
                else _forceInteractStatus = "No C→S packets yet.";
            });

            ImGui.SameLine(0, 8);

            var saved = _store.GetAll();
            if (saved.Count > 0 && ImGui.BeginCombo("Load from Book##fibook", ""))
            {
                foreach (var s in saved.Where(s => s.Direction == PacketDirection.ClientToServer))
                    if (ImGui.Selectable(s.Label)) _forceInteractCapHex = s.HexString;
                ImGui.EndCombo();
            }

            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Interaction packet hex##fihex", ref _forceInteractCapHex, 4096);

            if (_forceInteractStatus.Length > 0)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                ImGui.TextUnformatted($"  ↳ {_forceInteractStatus}");
                ImGui.PopStyleColor();
            }

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            // ActionType mutation
            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("ActionType byte offset##fiao", ref _forceInteractActionOffset);
            _forceInteractActionOffset = Math.Max(0, _forceInteractActionOffset);
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(150);
            string[] actionNames = { "0 — Use/Interact", "1 — Open", "2 — Attack", "3 — Sneak+Use", "4 — Secondary" };
            ImGui.Combo("New ActionType##fiact", ref _forceInteractNewAction, actionNames, actionNames.Length);

            // Distance mutation
            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("Distance float offset##fido", ref _forceInteractDistOffset);
            _forceInteractDistOffset = Math.Max(0, _forceInteractDistOffset);
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(120);
            ImGui.InputFloat("Distance override##fidist", ref _forceInteractNewDist, 0.5f, 1f, "%.1f");
            ImGui.SameLine(0, 6);
            UiHelper.MutedLabel("(0 = snap player to block, 999 = ultra-range)");

            ImGui.Spacing();

            // Preview
            if (_forceInteractCapHex.Length > 0)
            {
                try
                {
                    byte[] preview = MutateInteractPacket(HexToBytes(_forceInteractCapHex));
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                    ImGui.TextUnformatted($"  Preview ({preview.Length}b): {BytesToHex(preview, 28)}");
                    ImGui.PopStyleColor();
                }
                catch { UiHelper.MutedLabel("  (invalid hex)"); }
            }

            ImGui.Spacing();

            UiHelper.WarnButton("▶ Force Interact (Mutated Send)##fisend", 240, 32, () =>
            {
                if (string.IsNullOrWhiteSpace(_forceInteractCapHex))
                { _log.Error("[ModAudit/Interact] Capture or paste a packet hex first."); return; }
                try
                {
                    byte[] mutated = MutateInteractPacket(HexToBytes(_forceInteractCapHex));
                    SendRaw(mutated);
                    _forceInteractStatus = $"Sent {mutated.Length}b — action={_forceInteractNewAction} dist={_forceInteractNewDist:F1}";
                    _log.Success($"[ModAudit/Interact] Force Interact sent — {_forceInteractStatus}");
                }
                catch (Exception ex) { _log.Error($"[ModAudit/Interact] {ex.Message}"); }
            });
        });

        ImGui.Spacing();

        // Ghost Interaction Mode
        UiHelper.SectionBox("GHOST INTERACTION MODE", w, 0, () =>
        {
            ImGui.PushStyleColor(ImGuiCol.Text, _ghostModeEnabled ? MenuRenderer.ColDanger : MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted(_ghostModeEnabled
                ? "  ★ GHOST MODE ACTIVE — next right-click will spoof position briefly"
                : "  Ghost mode disabled");
            ImGui.PopStyleColor();
            ImGui.Spacing();

            UiHelper.MutedLabel("Spoofs player coordinates to be 1 block inside a detected claim at the exact moment");
            UiHelper.MutedLabel("of interaction, then snaps back. Tests if the mod checks position only at click-time.");
            ImGui.Spacing();

            ImGui.Checkbox("Enable Ghost Interaction Mode##ghost", ref _ghostModeEnabled);
            ImGui.Spacing();

            ImGui.SetNextItemWidth(100); ImGui.InputFloat("Ghost ΔX##gox", ref _ghostOffsetX, 0.5f, 1f, "%.1f");
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(100); ImGui.InputFloat("Ghost ΔZ##goz", ref _ghostOffsetZ, 0.5f, 1f, "%.1f");
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(80);  ImGui.InputInt("Snap-back ms##ghd", ref _ghostDelayMs);
            _ghostDelayMs = Math.Clamp(_ghostDelayMs, 1, 500);
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel("ms after which original position is resent");

            if (_claimZones.Count > 0 && _claimSelectedIdx >= 0)
            {
                var z = _claimZones[_claimSelectedIdx];
                Vector3 ghostPos = z.Min + new Vector3(_ghostOffsetX, 0, _ghostOffsetZ);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted($"  Ghost position will be: X={ghostPos.X:F2}  Z={ghostPos.Z:F2}");
                ImGui.PopStyleColor();
            }
            else
                UiHelper.MutedLabel("Select a detected claim zone (Claims tab) to auto-aim the ghost position.");

            ImGui.Spacing();
            UiHelper.WarnButton("▶ Fire Ghost Interact Now##ghostfire", 220, 32, () =>
            {
                if (!_claimZones.Any())
                { _log.Error("[ModAudit/Ghost] No claim zones detected — scan first."); return; }
                if (string.IsNullOrWhiteSpace(_forceInteractCapHex))
                { _log.Error("[ModAudit/Ghost] Capture an interaction packet first."); return; }

                var z = _claimSelectedIdx >= 0 ? _claimZones[_claimSelectedIdx] : _claimZones[0];
                Vector3 spoofPos = z.Min + new Vector3(_ghostOffsetX, 1f, _ghostOffsetZ);
                byte[] posSpoof = BuildPositionPacket(spoofPos.X, spoofPos.Y, spoofPos.Z);
                byte[] interact = MutateInteractPacket(HexToBytes(_forceInteractCapHex));
                int delay = _ghostDelayMs;

                Task.Run(async () =>
                {
                    SendRaw(posSpoof);   // teleport ghost
                    await Task.Delay(2);
                    SendRaw(interact);   // interact inside claim
                    await Task.Delay(delay);
                    SendRaw(posSpoof);   // re-send position (snap back)
                    _log.Success($"[ModAudit/Ghost] Ghost interact sequence sent " +
                                 $"(pos: {spoofPos.X:F2},{spoofPos.Z:F2} → interact → snap-back).");
                });
            });
        });
    }

    private byte[] MutateInteractPacket(byte[] raw)
    {
        byte[] copy = (byte[])raw.Clone();

        // Mutate ActionType byte
        if (_forceInteractActionOffset < copy.Length)
            copy[_forceInteractActionOffset] = (byte)_forceInteractNewAction;

        // Mutate Distance float
        if (_forceInteractDistOffset + 4 <= copy.Length)
        {
            byte[] distBytes = BitConverter.GetBytes(_forceInteractNewDist);
            Array.Copy(distBytes, 0, copy, _forceInteractDistOffset, 4);
        }

        return copy;
    }

    private static byte[] BuildPositionPacket(float x, float y, float z)
    {
        // Generic position update packet: [0x11] [x:4] [y:4] [z:4] [yaw:4] [pitch:4] [flags:1]
        var pkt = new List<byte> { 0x11 };
        pkt.AddRange(BitConverter.GetBytes(x));
        pkt.AddRange(BitConverter.GetBytes(y));
        pkt.AddRange(BitConverter.GetBytes(z));
        pkt.AddRange(BitConverter.GetBytes(0f));  // yaw
        pkt.AddRange(BitConverter.GetBytes(0f));  // pitch
        pkt.Add(0x00);                            // flags (absolute)
        return pkt.ToArray();
    }

    // ══════════════════════════════════════════════════════════════════════
    // TAB 2 — VIRTUAL INVENTORY SNIFFER
    // ══════════════════════════════════════════════════════════════════════

    private readonly List<SniffedWindow> _openWindows = new();
    private int _selectedWindowIdx = -1;
    private int _remoteOpenWindowId = 0;
    private string _remoteOpenHexTemplate = "";
    private int _remoteOpenCount = 1;
    private int _remoteOpenDelayMs = 100;

    private void TryScanOpenWindow(CapturedPacket p)
    {
        if (p.Direction != PacketDirection.ServerToClient) return;
        byte[] b = p.RawBytes;
        if (b.Length < 5) return;

        // Heuristic: opcode in 0x2D–0x35 range (common open-window opcodes)
        // AND first few bytes encode a small integer (window ID: 1–255)
        byte op = b[0];
        if (op < 0x2C || op > 0x40) return;

        // Try byte 1 or bytes 1-2 as window ID
        int windowId = b.Length > 2 ? BitConverter.ToInt16(b, 1) : b[1];
        if (windowId < 0 || windowId > 512) return;

        // Look for non-physical signature: check if we already have a block position in
        // the packet — physical blocks normally have 3 ints after the window ID (X,Y,Z)
        bool hasBlockPos = b.Length >= 13;
        string typeName = op switch
        {
            0x2C or 0x2D => "Standard Inventory",
            0x2E => "Crafting Table",
            0x2F => "Furnace",
            0x30 => "Custom Forge",
            0x31 => "Modded Container",
            0x32 => "Workbench",
            0x33 => "NPC Shop",
            0x34 => "Bank/Vault",
            0x35 => "Custom Storage",
            _ => $"Unknown (0x{op:X2})"
        };

        // De-duplicate
        if (_openWindows.Any(w => w.WindowId == windowId && w.Opcode == op)) return;

        var win = new SniffedWindow
        {
            WindowId = windowId,
            Opcode   = op,
            TypeName = typeName,
            HasBlockPosition = hasBlockPos,
            PacketHex = BytesToHex(b, b.Length),
            SeenAt   = p.Timestamp,
        };
        _openWindows.Add(win);
        _log.Info($"[ModAudit/Inventory] Window #{windowId} ({typeName}) detected — " +
                  (hasBlockPos ? "has block pos" : "NO block pos — modded?"));
    }

    private void RenderInventory(float w)
    {
        UiHelper.SectionBox("VIRTUAL INVENTORY SNIFFER", w, 0, () =>
        {
            UiHelper.MutedLabel("Detects 'Open Window' S→C packets — especially those without a physical block position.");
            UiHelper.MutedLabel("Modded workbenches/forges often skip distance checks once the window is registered.");
            ImGui.Spacing();
            UiHelper.SecondaryButton("⟳ Re-scan##invrescan", 100, 24, () =>
            {
                _openWindows.Clear();
                foreach (var p in _capture.GetPackets()) TryScanOpenWindow(p);
            });
            ImGui.SameLine(0, 8);
            UiHelper.DangerButton("Clear##invclear", 70, 24, () => { _openWindows.Clear(); _selectedWindowIdx = -1; });
        });

        ImGui.Spacing();

        if (_openWindows.Count == 0)
        {
            UiHelper.SectionBox("SNIFFED WINDOWS", w, 0, () =>
                UiHelper.MutedLabel("No open-window packets seen yet. Open chests, workbenches, or NPC menus."));
            return;
        }

        float listH = Math.Min(200f, _openWindows.Count * 26f + 30f);
        UiHelper.SectionBox($"SNIFFED WINDOWS  ({_openWindows.Count})", w, listH, () =>
        {
            ImGui.SetCursorPosX(8);
            UiHelper.MutedLabel($"  {"ID",-6}  {"Opcode",-8}  {"Type",-22}  {"Block?",-8}  {"Time"}");

            var dl = ImGui.GetWindowDrawList();
            float lineY = ImGui.GetCursorScreenPos().Y - 2;
            dl.AddLine(new Vector2(ImGui.GetWindowPos().X + 8, lineY),
                       new Vector2(ImGui.GetWindowPos().X + w - 8, lineY),
                       ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

            var clip = new ImGuiListClipper();
            clip.Begin(_openWindows.Count, 24f);
            while (clip.Step())
            {
                for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++)
                {
                    var win = _openWindows[i];
                    bool sel = _selectedWindowIdx == i;

                    if (sel)
                    {
                        var sp = ImGui.GetCursorScreenPos();
                        dl.AddRectFilled(sp, sp + new Vector2(w - 16, 24),
                            ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
                    }

                    // Highlight windows without block position in amber — potential modded
                    Vector4 col = !win.HasBlockPosition ? MenuRenderer.ColWarn : MenuRenderer.ColAccent;
                    ImGui.PushStyleColor(ImGuiCol.Text, col);

                    string blockStr = win.HasBlockPosition ? "Yes" : "⚠ No";
                    if (ImGui.Selectable(
                        $"  {win.WindowId,-6}  0x{win.Opcode:X2}{"",-4}  {win.TypeName,-22}  {blockStr,-8}  " +
                        $"{win.SeenAt:HH:mm:ss}##inv{i}",
                        sel, ImGuiSelectableFlags.None, new Vector2(0, 24)))
                    {
                        _selectedWindowIdx = i;
                        _remoteOpenWindowId = win.WindowId;
                        _remoteOpenHexTemplate = win.PacketHex;
                    }
                    ImGui.PopStyleColor();
                }
            }
            clip.End();
        });

        ImGui.Spacing();

        // Remote Open panel
        UiHelper.SectionBox("REMOTE OPEN (DISTANCE-CHECK BYPASS)", w, 0, () =>
        {
            UiHelper.MutedLabel("Re-send an Open Window request with the saved WindowID from far away.");
            UiHelper.MutedLabel("If the server grants access, distance was not re-validated after initial open.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("Window ID##rowi", ref _remoteOpenWindowId);
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(80);
            ImGui.InputInt("Repeat##rowr", ref _remoteOpenCount);
            _remoteOpenCount = Math.Clamp(_remoteOpenCount, 1, 20);
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(80);
            ImGui.InputInt("Delay ms##rowd", ref _remoteOpenDelayMs);
            _remoteOpenDelayMs = Math.Max(0, _remoteOpenDelayMs);

            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Packet hex template##rowhex", ref _remoteOpenHexTemplate, 2048);

            ImGui.Spacing();
            UiHelper.WarnButton("▶ Remote Open Window##rosend", 200, 32, () =>
            {
                byte[] pkt;
                if (!string.IsNullOrWhiteSpace(_remoteOpenHexTemplate))
                {
                    // Use the stored packet (client sends the matching "open request" back to server)
                    pkt = HexToBytes(_remoteOpenHexTemplate);
                }
                else
                {
                    // Build a generic "request open window" C→S: [0x0E] [windowId:2]
                    pkt = new byte[] { 0x0E, (byte)(_remoteOpenWindowId & 0xFF),
                                              (byte)((_remoteOpenWindowId >> 8) & 0xFF) };
                }

                int count = _remoteOpenCount;
                int delay = _remoteOpenDelayMs;
                int wid   = _remoteOpenWindowId;
                _log.Info($"[ModAudit/Inventory] Remote Open WindowID={wid} × {count}");
                Task.Run(async () =>
                {
                    for (int n = 0; n < count; n++)
                    {
                        SendRaw(pkt);
                        if (delay > 0) await Task.Delay(delay);
                    }
                    _log.Success($"[ModAudit/Inventory] Remote Open × {count} sent.");
                });
            });
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // TAB 3 — ACTIVE MODDED ENTITIES + PERMISSION STATUS + BRUTE FORCE
    // ══════════════════════════════════════════════════════════════════════

    private readonly List<ModdedEntity> _moddedEntities = new();
    private ModdedEntity? _playerPermStatus = null;
    private int _bruteForceRadius     = 5;
    private int _bruteForceBaseId     = 0;
    private bool _bruteForceRunning   = false;
    private int  _bruteForceProgress  = 0;
    private string _bruteForceStatus  = "";

    private static readonly string[] _knownPermFlags = { "admin", "op", "mod", "owner",
        "canbuild", "canbreak", "bypass", "trust", "member", "guest" };

    private void TryScanEntityPermission(CapturedPacket p)
    {
        byte[] b = p.RawBytes;
        if (b.Length < 8) return;

        // Extract printable ASCII from the packet
        string text = ExtractText(b).ToLower();
        foreach (var flag in _knownPermFlags)
        {
            if (!text.Contains(flag)) continue;

            // Find if there's an entity ID-like integer alongside it
            for (int off = 0; off + 4 <= b.Length; off += 2)
            {
                int candidate = BitConverter.ToInt32(b, off);
                if (candidate < 1 || candidate > 1_000_000) continue;

                bool isPlayer = text.Contains("player") || text.Contains("name");
                var ent = new ModdedEntity
                {
                    EntityId    = (uint)candidate,
                    PermFlags   = ExtractPermFlags(text),
                    IsPlayer    = isPlayer,
                    PacketOpcode = b[0],
                    SeenAt      = p.Timestamp,
                };

                if (isPlayer && _playerPermStatus == null)
                    _playerPermStatus = ent;

                if (!_moddedEntities.Any(e => e.EntityId == ent.EntityId))
                    _moddedEntities.Add(ent);
                break;
            }
            break;
        }
    }

    private static string ExtractPermFlags(string text)
    {
        var found = new List<string>();
        foreach (var flag in _knownPermFlags)
            if (text.Contains(flag)) found.Add(flag);
        return found.Count > 0 ? string.Join(", ", found) : "—";
    }

    private void RenderEntities(float w)
    {
        // Permission Status
        UiHelper.SectionBox("PERMISSION STATUS", w, 0, () =>
        {
            if (_playerPermStatus != null)
            {
                UiHelper.StatusRow("EntityID",  _playerPermStatus.EntityId.ToString(),    true,  120);
                UiHelper.StatusRow("Flags seen", _playerPermStatus.PermFlags,              true,  120);
                UiHelper.StatusRow("IsAdmin",   _playerPermStatus.PermFlags.Contains("admin") ||
                                                _playerPermStatus.PermFlags.Contains("op") ? "True ★" : "False",
                                   _playerPermStatus.PermFlags.Contains("admin") ||
                                   _playerPermStatus.PermFlags.Contains("op"), 120);
                UiHelper.StatusRow("CanBuild",  _playerPermStatus.PermFlags.Contains("canbuild") ||
                                                _playerPermStatus.PermFlags.Contains("bypass") ? "True" : "False",
                                   _playerPermStatus.PermFlags.Contains("canbuild") ||
                                   _playerPermStatus.PermFlags.Contains("bypass"), 120);
                UiHelper.StatusRow("Opcode",    $"0x{_playerPermStatus.PacketOpcode:X2}",  true, 120);
            }
            else
            {
                UiHelper.MutedLabel("No permission data detected yet.");
                UiHelper.MutedLabel("Walk around or open GUI elements near claims — permission packets will appear.");
            }

            ImGui.Spacing();
            UiHelper.SecondaryButton("⟳ Re-scan##permrescan", 100, 24, () =>
            {
                _moddedEntities.Clear();
                _playerPermStatus = null;
                foreach (var p in _capture.GetPackets()) TryScanEntityPermission(p);
            });
        });

        ImGui.Spacing();

        // Modded entity list
        float listH = Math.Min(200f, Math.Max(80f, _moddedEntities.Count * 26f + 30f));
        UiHelper.SectionBox($"ACTIVE MODDED ENTITIES  ({_moddedEntities.Count})", w, listH, () =>
        {
            ImGui.SetCursorPosX(8);
            UiHelper.MutedLabel($"  {"EntityID",-12}  {"Opcode",-8}  {"Player?",-8}  {"Flags",-30}  {"Time"}");

            var dl = ImGui.GetWindowDrawList();
            float lineY = ImGui.GetCursorScreenPos().Y - 2;
            dl.AddLine(new Vector2(ImGui.GetWindowPos().X + 8, lineY),
                       new Vector2(ImGui.GetWindowPos().X + w - 8, lineY),
                       ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

            if (_moddedEntities.Count == 0)
            {
                ImGui.SetCursorPosX(12);
                UiHelper.MutedLabel("None yet — interact with mod entities or trigger permission checks.");
                return;
            }

            var clip = new ImGuiListClipper();
            clip.Begin(_moddedEntities.Count, 24f);
            while (clip.Step())
            {
                for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++)
                {
                    var ent = _moddedEntities[i];
                    bool hasAdmin = ent.PermFlags.Contains("admin") || ent.PermFlags.Contains("op");
                    Vector4 col   = hasAdmin ? MenuRenderer.ColDanger :
                                    ent.IsPlayer ? MenuRenderer.ColBlue : MenuRenderer.ColAccent;
                    ImGui.PushStyleColor(ImGuiCol.Text, col);
                    ImGui.Selectable(
                        $"  {ent.EntityId,-12}  0x{ent.PacketOpcode:X2}{"",-4}  " +
                        $"{(ent.IsPlayer ? "Player" : "Entity"),-8}  {ent.PermFlags,-30}  " +
                        $"{ent.SeenAt:HH:mm:ss}##ent{i}",
                        false, ImGuiSelectableFlags.None, new Vector2(0, 24));
                    ImGui.PopStyleColor();
                }
            }
            clip.End();
        });

        ImGui.Spacing();

        // Brute Force IDs
        UiHelper.SectionBox("BRUTE FORCE ENTITY IDs", w, 0, () =>
        {
            UiHelper.MutedLabel("Sends a generic 'entity data request' packet for every ID in a range.");
            UiHelper.MutedLabel("IDs that return data despite being 'protected' are leaking information.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(120);
            ImGui.InputInt("Base EntityID##bfbase", ref _bruteForceBaseId);
            _bruteForceBaseId = Math.Max(0, _bruteForceBaseId);
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("±Radius##bfrad", ref _bruteForceRadius);
            _bruteForceRadius = Math.Clamp(_bruteForceRadius, 1, 50);
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel($"→ will probe IDs {_bruteForceBaseId} to {_bruteForceBaseId + _bruteForceRadius}");

            if (_bruteForceBaseId == 0 && _moddedEntities.Count > 0)
            {
                ImGui.SameLine(0, 8);
                UiHelper.SecondaryButton("Auto-fill from entities##bfaf", 180, 22, () =>
                    _bruteForceBaseId = (int)_moddedEntities[0].EntityId);
            }

            ImGui.Spacing();

            if (_bruteForceRunning)
            {
                ImGui.ProgressBar(_bruteForceProgress / (float)(_bruteForceRadius + 1),
                    new Vector2(300, 24), $"Probing... {_bruteForceProgress}/{_bruteForceRadius + 1}");
            }
            else
            {
                UiHelper.WarnButton("▶ Brute Force IDs##bfrun", 180, 32, () =>
                {
                    if (_bruteForceRunning) return;
                    _bruteForceRunning = true;
                    _bruteForceProgress = 0;
                    int baseId = _bruteForceBaseId;
                    int radius = _bruteForceRadius;
                    int pktsBefore = _capture.GetPacketCount();

                    _log.Info($"[ModAudit/BruteForce] Probing IDs {baseId}..{baseId + radius}");

                    Task.Run(async () =>
                    {
                        for (int id = baseId; id <= baseId + radius; id++)
                        {
                            // Entity data request: [0x26] [entityId:4]
                            byte[] pkt = new byte[] { 0x26 }
                                .Concat(BitConverter.GetBytes(id)).ToArray();
                            SendRaw(pkt);
                            _bruteForceProgress++;
                            await Task.Delay(80);
                        }

                        await Task.Delay(300);
                        int newPkts = _capture.GetPacketCount() - pktsBefore;
                        _bruteForceStatus = $"Done — {radius + 1} probes sent, {newPkts} new S→C packets received.";
                        _log.Success($"[ModAudit/BruteForce] {_bruteForceStatus}");
                        _bruteForceRunning = false;
                    });
                });
            }

            if (_bruteForceStatus.Length > 0)
            {
                ImGui.Spacing();
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                ImGui.TextUnformatted($"  ↳ {_bruteForceStatus}");
                ImGui.PopStyleColor();
            }
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // TAB 4 — RACE CONDITION / BURST SEND
    // ══════════════════════════════════════════════════════════════════════

    private bool   _burstArmed       = false;
    private string _burstCapturedHex = "";
    private int    _burstCount       = 5;
    private int    _burstDelayMs     = 5;
    private bool   _burstRunning     = false;
    private string _burstStatus      = "";
    private int    _burstArmNextN    = 0; // tracks which packet index we armed on

    private void TryInterceptBurst(CapturedPacket p)
    {
        if (!_burstArmed || _burstRunning || p.RawBytes.Length < 2) return;
        _burstArmed = false;
        _burstCapturedHex = BytesToHex(p.RawBytes, p.RawBytes.Length);
        _log.Info($"[ModAudit/Race] Burst armed — captured {p.RawBytes.Length}b opcode=0x{p.RawBytes[0]:X2}");
    }

    private void RenderRace(float w)
    {
        UiHelper.SectionBox("RACE CONDITION — BURST SEND TOOL", w, 0, () =>
        {
            UiHelper.MutedLabel("Arm the interceptor, then perform any action in-game.");
            UiHelper.MutedLabel("The next outgoing packet is captured, then replayed rapidly to stress-test");
            UiHelper.MutedLabel("server-side double-action prevention (dupe, double-enter, etc.).");
            ImGui.Spacing();

            // Arm button
            if (_burstArmed)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted("  ⚡ ARMED — perform any in-game interaction now...");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 12);
                UiHelper.DangerButton("Disarm##racedisarm", 80, 24, () => _burstArmed = false);
            }
            else
            {
                UiHelper.PrimaryButton("⚡ Arm Interceptor##racearm", 180, 28, () =>
                {
                    _burstArmed = true;
                    _burstCapturedHex = "";
                    _burstStatus = "";
                    _log.Info("[ModAudit/Race] Burst interceptor armed — waiting for next C→S packet.");
                });
            }

            ImGui.Spacing();

            // Packet display and manual entry
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Packet hex (auto-filled or paste)##burstpkt", ref _burstCapturedHex, 4096);

            if (!string.IsNullOrWhiteSpace(_burstCapturedHex))
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
                ImGui.TextUnformatted($"  ✓ Packet ready: {_burstCapturedHex[..Math.Min(48, _burstCapturedHex.Length)]}...");
                ImGui.PopStyleColor();
            }

            ImGui.Spacing();

            ImGui.SetNextItemWidth(100); ImGui.InputInt("Burst count##burstcnt", ref _burstCount);
            _burstCount = Math.Clamp(_burstCount, 2, 200);
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(100); ImGui.InputInt("Delay ms##burstdly", ref _burstDelayMs);
            _burstDelayMs = Math.Clamp(_burstDelayMs, 0, 500);
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel("between each duplicate");

            ImGui.Spacing();

            if (_burstRunning)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted("  ● Burst in progress...");
                ImGui.PopStyleColor();
            }
            else
            {
                UiHelper.WarnButton($"▶ Burst Send × {_burstCount}##burstsend", 180, 32, () =>
                {
                    if (string.IsNullOrWhiteSpace(_burstCapturedHex))
                    { _log.Error("[ModAudit/Race] No packet — arm interceptor or paste hex first."); return; }
                    try
                    {
                        byte[] pkt   = HexToBytes(_burstCapturedHex);
                        int count    = _burstCount;
                        int delay    = _burstDelayMs;
                        _burstRunning = true;
                        _log.Info($"[ModAudit/Race] Burst × {count} with {delay}ms gap — {pkt.Length}b each");
                        Task.Run(async () =>
                        {
                            for (int n = 0; n < count; n++)
                            {
                                SendRaw(pkt);
                                if (delay > 0) await Task.Delay(delay);
                            }
                            _burstStatus = $"Burst complete — {count} × {pkt.Length}b at ≥{delay}ms intervals.";
                            _log.Success($"[ModAudit/Race] {_burstStatus}");
                            _burstRunning = false;
                        });
                    }
                    catch (Exception ex) { _log.Error($"[ModAudit/Race] {ex.Message}"); _burstRunning = false; }
                });
            }

            if (_burstStatus.Length > 0)
            {
                ImGui.Spacing();
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                ImGui.TextUnformatted($"  ↳ {_burstStatus}");
                ImGui.PopStyleColor();
            }

            ImGui.Spacing();
            RenderHowTo(
                "1. Click 'Arm Interceptor'",
                "2. Open a chest, click an entity, or use a workbench — the FIRST C→S packet is captured",
                "3. Set burst count (5–20) and delay (1–10ms)",
                "4. Click 'Burst Send' — if the server processes duplicates, a race condition exists",
                "Result: double inventory, duplicate loot, double-use — confirms lack of deduplication");
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // TAB 5 — DIALOGUE INTERCEPTOR
    // ══════════════════════════════════════════════════════════════════════

    private readonly List<DialogueOption> _dialogueOptions = new();
    private int    _dialogueSelectedOpt = -1;
    private int    _dialogueSendOptionId = 0;
    private string _dialoguePacketHex    = "";
    private int    _dialogueNpcId        = 0;

    private void TryScanDialogue(CapturedPacket p)
    {
        if (p.Direction != PacketDirection.ServerToClient) return;
        byte[] b = p.RawBytes;
        if (b.Length < 12) return;

        // Heuristic: NPC dialogue usually has opcode in 0x38–0x50
        // and a sequence of int16/int32 IDs that represent options
        if (b[0] < 0x38 || b[0] > 0x58) return;

        // Count int16 candidates in range 1–100 (typical option IDs)
        var optIds = new List<int>();
        for (int off = 2; off + 2 <= b.Length; off += 2)
        {
            short candidate = BitConverter.ToInt16(b, off);
            if (candidate >= 1 && candidate <= 200)
                optIds.Add(candidate);
        }

        if (optIds.Count < 2) return;

        // Try to find NPC entity ID (4 bytes after opcode)
        int npcId = b.Length >= 5 ? BitConverter.ToInt32(b, 1) : 0;

        foreach (int optId in optIds.Distinct())
        {
            if (!_dialogueOptions.Any(d => d.OptionId == optId && d.NpcEntityId == npcId))
            {
                _dialogueOptions.Add(new DialogueOption
                {
                    OptionId     = optId,
                    NpcEntityId  = npcId,
                    Opcode       = b[0],
                    Label        = $"Option {optId}",
                    IsLikelyHidden = optIds.IndexOf(optId) >= 3, // 4th+ option = likely hidden
                    SeenAt       = p.Timestamp,
                });
            }
        }

        if (optIds.Count > 0)
            _dialogueNpcId = npcId;
    }

    private void RenderDialogue(float w)
    {
        UiHelper.SectionBox("NPC DIALOGUE INTERCEPTOR", w, 0, () =>
        {
            UiHelper.MutedLabel("Captures all Option IDs from NPC dialogue packets — including hidden/locked ones.");
            UiHelper.MutedLabel("Allows sending any Option ID directly, bypassing game-side UI visibility.");
            ImGui.Spacing();
            UiHelper.SecondaryButton("⟳ Re-scan##diarescan", 100, 24, () =>
            {
                _dialogueOptions.Clear();
                foreach (var p in _capture.GetPackets()) TryScanDialogue(p);
            });
            ImGui.SameLine(0, 8);
            UiHelper.DangerButton("Clear##diaclear", 70, 24, () =>
            { _dialogueOptions.Clear(); _dialogueSelectedOpt = -1; });
        });

        ImGui.Spacing();

        float listH = Math.Min(200f, Math.Max(80f, _dialogueOptions.Count * 26f + 30f));
        UiHelper.SectionBox($"CAPTURED OPTION IDs  ({_dialogueOptions.Count})", w, listH, () =>
        {
            if (_dialogueOptions.Count == 0)
            {
                UiHelper.MutedLabel("Talk to any NPC — option IDs will appear here automatically.");
                return;
            }

            ImGui.SetCursorPosX(8);
            UiHelper.MutedLabel($"  {"ID",-8}  {"NPC ID",-10}  {"Opcode",-8}  {"Hidden?",-10}  {"Time"}");

            var dl = ImGui.GetWindowDrawList();
            float lineY = ImGui.GetCursorScreenPos().Y - 2;
            dl.AddLine(new Vector2(ImGui.GetWindowPos().X + 8, lineY),
                       new Vector2(ImGui.GetWindowPos().X + w - 8, lineY),
                       ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

            var clip = new ImGuiListClipper();
            clip.Begin(_dialogueOptions.Count, 24f);
            while (clip.Step())
            {
                for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++)
                {
                    var opt = _dialogueOptions[i];
                    bool sel = _dialogueSelectedOpt == i;

                    Vector4 col = opt.IsLikelyHidden ? MenuRenderer.ColWarn : MenuRenderer.ColAccent;
                    ImGui.PushStyleColor(ImGuiCol.Text, col);

                    if (sel)
                    {
                        var sp = ImGui.GetCursorScreenPos();
                        ImGui.GetWindowDrawList().AddRectFilled(sp, sp + new Vector2(w - 16, 24),
                            ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
                    }

                    string hiddenStr = opt.IsLikelyHidden ? "⚠ Likely" : "No";
                    if (ImGui.Selectable(
                        $"  {opt.OptionId,-8}  {opt.NpcEntityId,-10}  0x{opt.Opcode:X2}{"",-4}  " +
                        $"{hiddenStr,-10}  {opt.SeenAt:HH:mm:ss}##dia{i}",
                        sel, ImGuiSelectableFlags.None, new Vector2(0, 24)))
                    {
                        _dialogueSelectedOpt = i;
                        _dialogueSendOptionId = opt.OptionId;
                        _dialogueNpcId = opt.NpcEntityId;
                        // Build packet for this option
                        _dialoguePacketHex = BytesToHex(
                            BuildDialoguePacket(opt.OptionId, opt.NpcEntityId), 64);
                    }
                    ImGui.PopStyleColor();
                }
            }
            clip.End();
        });

        ImGui.Spacing();

        UiHelper.SectionBox("SEND OPTION (HIDDEN OPTION BYPASS)", w, 0, () =>
        {
            ImGui.SetNextItemWidth(100); ImGui.InputInt("Option ID##diasendid", ref _dialogueSendOptionId);
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(120); ImGui.InputInt("NPC Entity ID##diasendnpc", ref _dialogueNpcId);

            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Packet hex override##diapkt", ref _dialoguePacketHex, 512);

            ImGui.Spacing();
            UiHelper.WarnButton("▶ Send Dialogue Option##diasend", 220, 32, () =>
            {
                byte[] pkt;
                if (!string.IsNullOrWhiteSpace(_dialoguePacketHex))
                    pkt = HexToBytes(_dialoguePacketHex);
                else
                    pkt = BuildDialoguePacket(_dialogueSendOptionId, _dialogueNpcId);

                SendRaw(pkt);
                _log.Success($"[ModAudit/Dialogue] Option {_dialogueSendOptionId} sent for NPC {_dialogueNpcId}.");
            });
        });
    }

    private static byte[] BuildDialoguePacket(int optionId, int npcId)
    {
        // Generic: [0x3C] [npcId:4] [optionId:2]
        var pkt = new List<byte> { 0x3C };
        pkt.AddRange(BitConverter.GetBytes(npcId));
        pkt.AddRange(BitConverter.GetBytes((short)optionId));
        return pkt.ToArray();
    }

    // ══════════════════════════════════════════════════════════════════════
    // TAB 6 — TELEPORT HOOK
    // ══════════════════════════════════════════════════════════════════════

    private bool   _teleportArmed    = false;
    private string _teleportCapHex   = "";
    private float  _teleportOverrideX = 0f;
    private float  _teleportOverrideY = 64f;
    private float  _teleportOverrideZ = 0f;
    private int    _teleportFloatOff  = 1;
    private string _teleportStatus    = "";

    private void TryInterceptTeleport(CapturedPacket p)
    {
        if (!_teleportArmed) return;
        byte[] b = p.RawBytes;
        if (b.Length < 14) return;

        // Look for 3 consecutive plausible coordinate floats
        for (int off = 1; off + 12 <= b.Length; off += 1)
        {
            try
            {
                float x = BitConverter.ToSingle(b, off);
                float y = BitConverter.ToSingle(b, off + 4);
                float z = BitConverter.ToSingle(b, off + 8);
                if (IsReasonableCoord(x) && IsReasonableCoord(y) && IsReasonableCoord(z)
                    && y >= -10f && y <= 1000f)
                {
                    _teleportArmed = false;
                    _teleportCapHex = BytesToHex(b, b.Length);
                    _teleportFloatOff = off;
                    _teleportStatus = $"Captured {b.Length}b — coords @ offset {off}: X={x:F2} Y={y:F2} Z={z:F2}";
                    _log.Info($"[ModAudit/Teleport] Teleport intercepted: {_teleportStatus}");
                    break;
                }
            }
            catch { }
        }
    }

    private void RenderTeleport(float w)
    {
        UiHelper.SectionBox("TELEPORT HOOK — DESTINATION OVERRIDE", w, 0, () =>
        {
            UiHelper.MutedLabel("Arms an interceptor for the next outgoing teleport/waypoint packet.");
            UiHelper.MutedLabel("The XYZ floats are replaced with your override values before the packet is sent.");
            ImGui.Spacing();

            if (_teleportArmed)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted("  ⚡ ARMED — use any waypoint, teleport scroll, or /tp command in-game...");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 12);
                UiHelper.DangerButton("Disarm##tpdisarm", 80, 24, () => _teleportArmed = false);
            }
            else
            {
                UiHelper.PrimaryButton("⚡ Arm Teleport Hook##tparm", 180, 28, () =>
                {
                    _teleportArmed = true;
                    _teleportCapHex = "";
                    _teleportStatus = "";
                    _log.Info("[ModAudit/Teleport] Teleport hook armed.");
                });
            }

            ImGui.Spacing();

            if (_teleportStatus.Length > 0)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                ImGui.TextUnformatted($"  ↳ {_teleportStatus}");
                ImGui.PopStyleColor();
                ImGui.Spacing();
            }

            // Override coordinates
            ImGui.SetNextItemWidth(120); ImGui.InputFloat("X##tpx", ref _teleportOverrideX, 1f, 10f, "%.2f");
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(120); ImGui.InputFloat("Y##tpy", ref _teleportOverrideY, 1f, 10f, "%.2f");
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(120); ImGui.InputFloat("Z##tpz", ref _teleportOverrideZ, 1f, 10f, "%.2f");

            ImGui.Spacing();
            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("Float offset##tpfo", ref _teleportFloatOff);
            _teleportFloatOff = Math.Max(0, _teleportFloatOff);
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel("Auto-detected from packet — only change if coordinates are wrong.");

            ImGui.Spacing();
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Packet hex (auto-filled)##tphex", ref _teleportCapHex, 4096);

            ImGui.Spacing();

            UiHelper.WarnButton("▶ Send with Override Coords##tpsend", 240, 32, () =>
            {
                if (string.IsNullOrWhiteSpace(_teleportCapHex))
                { _log.Error("[ModAudit/Teleport] Capture a teleport packet first."); return; }
                try
                {
                    byte[] pkt = HexToBytes(_teleportCapHex);
                    if (_teleportFloatOff + 12 > pkt.Length)
                    { _log.Error("[ModAudit/Teleport] Float offset out of range."); return; }
                    Array.Copy(BitConverter.GetBytes(_teleportOverrideX), 0, pkt, _teleportFloatOff,     4);
                    Array.Copy(BitConverter.GetBytes(_teleportOverrideY), 0, pkt, _teleportFloatOff + 4, 4);
                    Array.Copy(BitConverter.GetBytes(_teleportOverrideZ), 0, pkt, _teleportFloatOff + 8, 4);
                    SendRaw(pkt);
                    _log.Success($"[ModAudit/Teleport] Sent with override X={_teleportOverrideX:F2} " +
                                 $"Y={_teleportOverrideY:F2} Z={_teleportOverrideZ:F2}");
                }
                catch (Exception ex) { _log.Error($"[ModAudit/Teleport] {ex.Message}"); }
            });
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // TAB 7 — PACKET PAYLOAD SCALER
    // ══════════════════════════════════════════════════════════════════════

    private bool   _payloadArmed     = false;
    private string _payloadCapHex    = "";
    private float  _payloadScale     = 1.0f;
    private int    _payloadFloatOff  = 0;
    private string _payloadFieldName = "Area/Radius";
    private float  _payloadOrigVal   = 0f;
    private string _payloadStatus    = "";

    private void TryInterceptPayload(CapturedPacket p)
    {
        if (!_payloadArmed || p.RawBytes.Length < 6) return;
        byte[] b = p.RawBytes;

        // Find a float that looks like an "area" or "radius" value (1–500)
        for (int off = 1; off + 4 <= b.Length; off += 1)
        {
            try
            {
                float v = BitConverter.ToSingle(b, off);
                if (v >= 1f && v <= 500f && !float.IsNaN(v) && !float.IsInfinity(v))
                {
                    _payloadArmed = false;
                    _payloadCapHex = BytesToHex(b, b.Length);
                    _payloadFloatOff = off;
                    _payloadOrigVal  = v;
                    _payloadStatus = $"Captured — value @ offset {off}: {v:F2}";
                    _log.Info($"[ModAudit/Payload] Area/Radius value {v:F2} found at offset {off}");
                    break;
                }
            }
            catch { }
        }
    }

    private void RenderPayload(float w)
    {
        UiHelper.SectionBox("PACKET PAYLOAD SCALER", w, 0, () =>
        {
            UiHelper.MutedLabel("Arms an interceptor that catches the next outgoing packet containing an Area/Radius float.");
            UiHelper.MutedLabel("Scale the value by up to 10× — tests if the server validates the radius server-side.");
            ImGui.Spacing();

            if (_payloadArmed)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted("  ⚡ ARMED — trigger any area-effect action in-game...");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 12);
                UiHelper.DangerButton("Disarm##psdisarm", 80, 24, () => _payloadArmed = false);
            }
            else
            {
                UiHelper.PrimaryButton("⚡ Arm Payload Interceptor##psarm", 220, 28, () =>
                {
                    _payloadArmed = true;
                    _payloadCapHex = "";
                    _payloadStatus = "";
                    _log.Info("[ModAudit/Payload] Payload interceptor armed.");
                });
            }

            ImGui.Spacing();

            if (_payloadStatus.Length > 0)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                ImGui.TextUnformatted($"  ↳ {_payloadStatus}");
                ImGui.PopStyleColor();
                ImGui.Spacing();
            }

            ImGui.SetNextItemWidth(200);
            ImGui.InputText("Field name label##psname", ref _payloadFieldName, 32);
            ImGui.SameLine(0, 12);
            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("Float offset##psoff", ref _payloadFloatOff);
            _payloadFloatOff = Math.Max(0, _payloadFloatOff);

            ImGui.Spacing();

            if (_payloadOrigVal > 0)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                ImGui.TextUnformatted($"  Original {_payloadFieldName} value: {_payloadOrigVal:F2}");
                ImGui.PopStyleColor();
            }

            // Scale slider
            ImGui.SetNextItemWidth(400);
            ImGui.SliderFloat($"Scale (× original)##psscale", ref _payloadScale, 1.0f, 10.0f, "%.1f×");
            if (_payloadOrigVal > 0)
            {
                float scaled = _payloadOrigVal * _payloadScale;
                ImGui.SameLine(0, 12);
                ImGui.PushStyleColor(ImGuiCol.Text,
                    _payloadScale > 3f ? MenuRenderer.ColDanger :
                    _payloadScale > 1.5f ? MenuRenderer.ColWarn : MenuRenderer.ColAccent);
                ImGui.TextUnformatted($"→ {scaled:F2}");
                ImGui.PopStyleColor();
            }

            ImGui.Spacing();
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Packet hex##pshex", ref _payloadCapHex, 4096);

            ImGui.Spacing();
            UiHelper.WarnButton("▶ Send Scaled Payload##pssend", 210, 32, () =>
            {
                if (string.IsNullOrWhiteSpace(_payloadCapHex))
                { _log.Error("[ModAudit/Payload] Capture a packet first."); return; }
                try
                {
                    byte[] pkt = HexToBytes(_payloadCapHex);
                    if (_payloadFloatOff + 4 > pkt.Length)
                    { _log.Error("[ModAudit/Payload] Float offset out of range."); return; }

                    float origVal = BitConverter.ToSingle(pkt, _payloadFloatOff);
                    float newVal  = origVal * _payloadScale;
                    Array.Copy(BitConverter.GetBytes(newVal), 0, pkt, _payloadFloatOff, 4);
                    SendRaw(pkt);
                    _log.Success($"[ModAudit/Payload] Sent — {_payloadFieldName}: {origVal:F2} → {newVal:F2} (×{_payloadScale:F1})");
                }
                catch (Exception ex) { _log.Error($"[ModAudit/Payload] {ex.Message}"); }
            });
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // TAB 8 — DEPENDENCY SCANNER
    // ══════════════════════════════════════════════════════════════════════

    private readonly List<DepEntry> _deps = new();
    private bool _depAutoScan = true;

    // Known mod library fingerprints — opcode + string marker combinations
    private static readonly (string LibName, byte[] Signature, string Description)[] KnownDeps =
    {
        ("HytaleAPI",        new byte[]{ 0x01, 0x48, 0x59 }, "Core Hytale API — most mods use this"),
        ("SimpleClaims",     new byte[]{ 0x44, 0x43, 0x4C }, "SimpleClaims land-claim mod (DCL header)"),
        ("CustomStorageLib", new byte[]{ 0x53, 0x54, 0x52 }, "Custom storage mod (STR header)"),
        ("TradeLib",         new byte[]{ 0x54, 0x52, 0x44 }, "Player trade / auction library (TRD)"),
        ("ChunkProtector",   new byte[]{ 0x43, 0x50, 0x52 }, "Chunk protection library (CPR)"),
        ("RankAPI",          new byte[]{ 0x52, 0x4B, 0x41 }, "Rank/permissions API (RKA)"),
        ("EconomyLib",       new byte[]{ 0x45, 0x43, 0x4F }, "Economy/currency library (ECO)"),
        ("WorldGuardPort",   new byte[]{ 0x57, 0x47, 0x50 }, "WorldGuard port (WGP header)"),
        ("QuestEngine",      new byte[]{ 0x51, 0x45, 0x4E }, "Quest/NPC dialogue engine (QEN)"),
        ("MagicLib",         new byte[]{ 0x4D, 0x47, 0x4C }, "Magic/spell casting library (MGL)"),
    };

    private void TryScanDependency(CapturedPacket p)
    {
        if (!_depAutoScan) return;
        byte[] b = p.RawBytes;
        if (b.Length < 3) return;

        foreach (var (lib, sig, desc) in KnownDeps)
        {
            // Check if the signature bytes appear anywhere in the packet
            bool found = false;
            for (int off = 0; off + sig.Length <= b.Length; off++)
            {
                bool match = true;
                for (int j = 0; j < sig.Length; j++)
                    if (b[off + j] != sig[j]) { match = false; break; }
                if (match) { found = true; break; }
            }

            if (found && !_deps.Any(d => d.LibName == lib))
            {
                _deps.Add(new DepEntry
                {
                    LibName     = lib,
                    Description = desc,
                    Opcode      = b[0],
                    FirstSeen   = p.Timestamp,
                    Occurrences = 1,
                });
                _log.Info($"[ModAudit/Deps] Library detected: {lib} — {desc}");
            }
            else
            {
                var existing = _deps.FirstOrDefault(d => d.LibName == lib);
                if (found && existing != null) existing.Occurrences++;
            }

            // Also scan printable ASCII strings for known library names
            string text = ExtractText(b);
            foreach (var (lname, _, ldesc) in KnownDeps)
            {
                if (text.Contains(lname, StringComparison.OrdinalIgnoreCase) &&
                    !_deps.Any(d => d.LibName == lname))
                {
                    _deps.Add(new DepEntry
                    {
                        LibName     = lname,
                        Description = ldesc + " (string match)",
                        Opcode      = b[0],
                        FirstSeen   = p.Timestamp,
                        Occurrences = 1,
                    });
                }
            }
        }
    }

    private void RenderDeps(float w)
    {
        UiHelper.SectionBox("MOD DEPENDENCY SCANNER", w, 0, () =>
        {
            UiHelper.MutedLabel("Identifies which mod libraries are active based on packet signatures.");
            UiHelper.MutedLabel("Mods sharing the same library (e.g. RankAPI) often share the same vulnerability.");
            ImGui.Spacing();
            ImGui.Checkbox("Auto-scan all packets##depautoscan", ref _depAutoScan);
            ImGui.SameLine(0, 20);
            UiHelper.SecondaryButton("⟳ Re-scan All##deprescan", 130, 24, () =>
            {
                _deps.Clear();
                foreach (var p in _capture.GetPackets()) TryScanDependency(p);
            });
            ImGui.SameLine(0, 8);
            UiHelper.DangerButton("Clear##depclear", 70, 24, () => _deps.Clear());
        });

        ImGui.Spacing();

        float listH = Math.Min(300f, Math.Max(80f, _deps.Count * 26f + 30f));
        UiHelper.SectionBox($"DETECTED LIBRARIES  ({_deps.Count})", w, listH, () =>
        {
            if (_deps.Count == 0)
            {
                UiHelper.MutedLabel("No known libraries detected yet.");
                UiHelper.MutedLabel("Trigger various mod interactions to increase packet coverage.");
                return;
            }

            ImGui.SetCursorPosX(8);
            UiHelper.MutedLabel($"  {"Library",-22}  {"First Opcode",-14}  {"Hits",-6}  {"Description"}");

            var dl = ImGui.GetWindowDrawList();
            float lineY = ImGui.GetCursorScreenPos().Y - 2;
            dl.AddLine(new Vector2(ImGui.GetWindowPos().X + 8, lineY),
                       new Vector2(ImGui.GetWindowPos().X + w - 8, lineY),
                       ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

            var clip = new ImGuiListClipper();
            clip.Begin(_deps.Count, 24f);
            while (clip.Step())
            {
                for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++)
                {
                    var d = _deps[i];
                    ImGui.PushStyleColor(ImGuiCol.Text,
                        d.Occurrences > 10 ? MenuRenderer.ColDanger :
                        d.Occurrences > 3  ? MenuRenderer.ColWarn   : MenuRenderer.ColAccent);
                    ImGui.Selectable(
                        $"  {d.LibName,-22}  0x{d.Opcode:X2} @{d.FirstSeen:HH:mm:ss}{"",-2}  " +
                        $"{d.Occurrences,-6}  {d.Description}##dep{i}",
                        false, ImGuiSelectableFlags.None, new Vector2(0, 24));
                    ImGui.PopStyleColor();
                }
            }
            clip.End();
        });

        ImGui.Spacing();

        UiHelper.SectionBox("VULNERABILITY IMPLICATIONS", w, 0, () =>
        {
            if (_deps.Count == 0)
            {
                UiHelper.MutedLabel("Library detections will appear here with their known vulnerabilities.");
                return;
            }

            foreach (var d in _deps)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted($"  ★ {d.LibName}");
                ImGui.PopStyleColor();
                string vuln = d.LibName switch
                {
                    "SimpleClaims"     => "Known: bypass via block-placement at claim corners. Check edge gaps.",
                    "RankAPI"          => "Known: rank integer can be spoofed in handshake header byte.",
                    "ChunkProtector"   => "Known: interaction packets bypass chunk ownership at opcode boundary.",
                    "CustomStorageLib" => "Known: WindowID re-use attack — test Remote Open in Inventory tab.",
                    "TradeLib"         => "Known: trade amount is client-side; try Payload Scaler ×10.",
                    "EconomyLib"       => "Known: economy deltas are signed ints — try sending negative amounts.",
                    "QuestEngine"      => "Known: hidden option IDs exist — use Dialogue Interceptor tab.",
                    _                  => "No known CVE — use Interact Spoofer and Brute Force tabs to probe.",
                };
                ImGui.SetCursorPosX(16);
                UiHelper.MutedLabel($"→ {vuln}");
                ImGui.Spacing();
            }
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // TAB 9 — LAG SWITCH / BUFFER MODE
    // ══════════════════════════════════════════════════════════════════════

    private bool   _lagSwitchActive = false;
    private int    _lagBufferMs     = 500;
    private readonly Queue<LaggedPacket> _lagQueue = new();
    private DateTime _lagReleaseAt  = DateTime.MinValue;
    private int    _lagTotalQueued  = 0;
    private int    _lagTotalReleased = 0;
    private bool   _lagReleasing    = false;

    private readonly HashSet<int> _seenLagPacketIdx = new();

    private void TryQueueForLag(CapturedPacket p, int pktIndex)
    {
        if (_seenLagPacketIdx.Contains(pktIndex)) return;
        _seenLagPacketIdx.Add(pktIndex);
        // Note: in production, UdpProxy/PacketCapture would need a "defer" hook.
        // Here we store and re-send — the original packet still goes through, but
        // we also burst-replay all queued packets after the delay, testing server deduplication.
        _lagQueue.Enqueue(new LaggedPacket { Data = p.RawBytes, QueuedAt = DateTime.Now });
        if (_lagReleaseAt == DateTime.MinValue)
            _lagReleaseAt = DateTime.Now.AddMilliseconds(_lagBufferMs);
        _lagTotalQueued++;
    }

    private void DrainLagBuffer()
    {
        if (!_lagSwitchActive || _lagQueue.Count == 0) return;
        if (DateTime.Now < _lagReleaseAt) return;
        if (_lagReleasing) return;

        _lagReleasing = true;
        var toRelease = _lagQueue.ToArray();
        _lagQueue.Clear();
        _lagReleaseAt = DateTime.MinValue;

        Task.Run(async () =>
        {
            _log.Info($"[ModAudit/LagSwitch] Releasing {toRelease.Length} queued packets...");
            foreach (var lp in toRelease)
            {
                SendRaw(lp.Data);
                _lagTotalReleased++;
                await Task.Delay(1);
            }
            _log.Success($"[ModAudit/LagSwitch] Burst released {toRelease.Length} packets.");
            _lagReleasing = false;
        });
    }

    private void RenderLagSwitch(float w)
    {
        UiHelper.SectionBox("LAG SWITCH — PACKET BUFFER MODE", w, 0, () =>
        {
            ImGui.PushStyleColor(ImGuiCol.Text, _lagSwitchActive ? MenuRenderer.ColDanger : MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted(_lagSwitchActive
                ? "  ⚡ BUFFER ACTIVE — outgoing packets are being queued and burst-replayed"
                : "  Buffer mode disabled");
            ImGui.PopStyleColor();
            ImGui.Spacing();

            UiHelper.MutedLabel("When enabled: captures a copy of every outgoing C→S packet and re-sends them");
            UiHelper.MutedLabel("all at once after the configured delay, simulating a lag spike.");
            UiHelper.MutedLabel("Tests if the server correctly deduplicates / rejects out-of-order action sequences.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(150);
            ImGui.InputInt("Buffer window ms##lagms", ref _lagBufferMs);
            _lagBufferMs = Math.Clamp(_lagBufferMs, 50, 10_000);
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel("Packets held for this long then burst-sent simultaneously");

            ImGui.Spacing();

            if (_lagSwitchActive)
            {
                UiHelper.DangerButton("■ Disable Lag Buffer##lagoff", 200, 30, () =>
                {
                    _lagSwitchActive = false;
                    _lagQueue.Clear();
                    _lagReleaseAt = DateTime.MinValue;
                    _seenLagPacketIdx.Clear();
                    _log.Info("[ModAudit/LagSwitch] Buffer disabled — queue cleared.");
                });
            }
            else
            {
                UiHelper.WarnButton("▶ Enable Lag Buffer##lagon", 200, 30, () =>
                {
                    _lagSwitchActive = true;
                    _lagTotalQueued = 0;
                    _lagTotalReleased = 0;
                    _seenLagPacketIdx.Clear();
                    _lagQueue.Clear();
                    _lagReleaseAt = DateTime.MinValue;
                    _log.Info($"[ModAudit/LagSwitch] Buffer enabled — {_lagBufferMs}ms window.");
                });
            }

            ImGui.Spacing();

            // Stats
            ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
            ImGui.BeginChild("##lagstats", new Vector2(w - 20, 60), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();
            ImGui.SetCursorPos(new Vector2(12, 8));
            UiHelper.StatusRow("Queued now",    _lagQueue.Count.ToString(),    _lagQueue.Count > 0, 120);
            ImGui.SetCursorPosX(12);
            UiHelper.StatusRow("Total queued",  _lagTotalQueued.ToString(),    _lagTotalQueued > 0, 120);
            ImGui.SetCursorPosX(12);
            UiHelper.StatusRow("Total released",_lagTotalReleased.ToString(),  _lagTotalReleased > 0, 120);
            if (_lagReleaseAt > DateTime.MinValue)
            {
                double msLeft = (_lagReleaseAt - DateTime.Now).TotalMilliseconds;
                ImGui.SetCursorPosX(12);
                UiHelper.StatusRow("Release in",
                    msLeft > 0 ? $"{msLeft:F0}ms" : "releasing...", true, 120);
            }
            ImGui.EndChild();

            ImGui.Spacing();
            UiHelper.SecondaryButton("Force Flush Now##lagflush", 160, 26, () =>
            {
                _lagReleaseAt = DateTime.Now.AddMilliseconds(-1);
                _log.Info("[ModAudit/LagSwitch] Force flush triggered.");
            });
            ImGui.SameLine(0, 8);
            UiHelper.DangerButton("Discard Queue##lagdisc", 140, 26, () =>
            {
                _lagQueue.Clear();
                _lagReleaseAt = DateTime.MinValue;
                _log.Info("[ModAudit/LagSwitch] Queue discarded.");
            });

            ImGui.Spacing();
            RenderHowTo(
                "1. Start the proxy (Capture tab) and connect to a server",
                "2. Enable the lag buffer here",
                "3. Perform rapid actions (pick up items, open chests, attack mobs)",
                "4. Wait for the buffer window — all packets burst at once",
                "Result: duplicate items, skipped cooldowns = server validation not timing-aware");
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // SHARED HELPERS
    // ══════════════════════════════════════════════════════════════════════

    private void SendRaw(byte[] data)
    {
        if (_udpProxy.IsRunning && _udpProxy.InjectToServer(data))
        { _log.Info($"[ModAudit] {data.Length}b → UDP proxy."); return; }

        bool ok = _capture.InjectToServer(data).GetAwaiter().GetResult();
        if (ok) { _log.Info($"[ModAudit] {data.Length}b → TCP."); return; }

        _log.Warn("[ModAudit] No live session — sending direct UDP...");
        try
        {
            using var udp = new UdpClient();
            udp.Connect(_config.ServerIp, _config.ServerPort);
            udp.Send(data, data.Length);
            _log.Info($"[ModAudit] {data.Length}b → direct UDP.");
        }
        catch (Exception ex) { _log.Error($"[ModAudit] Send failed: {ex.Message}"); }
    }

    private static string BytesToHex(byte[] b, int maxBytes)
    {
        int take = Math.Min(maxBytes, b.Length);
        return string.Join(" ", b.Take(take).Select(x => $"{x:X2}"))
               + (b.Length > maxBytes ? "…" : "");
    }

    private static byte[] HexToBytes(string hex)
    {
        string clean = hex.Replace(" ", "").Replace("\n", "").Replace("\r", "");
        if (clean.Length % 2 != 0) clean += "0";
        return Convert.FromHexString(clean);
    }

    private static string ExtractText(byte[] data)
    {
        var sb = new StringBuilder();
        foreach (byte b in data)
            if (b >= 32 && b < 127) sb.Append((char)b);
            else if (b == 0 && sb.Length > 0) sb.Append(' ');
        return sb.ToString().Trim();
    }

    private void RenderHowTo(params string[] steps)
    {
        ImGui.Spacing();
        float w = ImGui.GetContentRegionAvail().X;
        UiHelper.SectionBox("HOW TO USE", w, 0, () =>
        {
            foreach (var s in steps) UiHelper.MutedLabel(s);
        });
    }
}

// ── Supporting data types ──────────────────────────────────────────────────────

public class ClaimZone
{
    public Vector3  Min          { get; set; }
    public Vector3  Max          { get; set; }
    public byte     Opcode       { get; set; }
    public int      EdgeGaps     { get; set; }
    public string   PacketHex    { get; set; } = "";
    public DateTime FoundAt      { get; set; }
}

public class SniffedWindow
{
    public int      WindowId         { get; set; }
    public byte     Opcode           { get; set; }
    public string   TypeName         { get; set; } = "";
    public bool     HasBlockPosition { get; set; }
    public string   PacketHex        { get; set; } = "";
    public DateTime SeenAt           { get; set; }
}

public class ModdedEntity
{
    public uint     EntityId     { get; set; }
    public string   PermFlags    { get; set; } = "";
    public bool     IsPlayer     { get; set; }
    public byte     PacketOpcode { get; set; }
    public DateTime SeenAt       { get; set; }
}

public class DialogueOption
{
    public int      OptionId        { get; set; }
    public int      NpcEntityId     { get; set; }
    public byte     Opcode          { get; set; }
    public string   Label           { get; set; } = "";
    public bool     IsLikelyHidden  { get; set; }
    public DateTime SeenAt          { get; set; }
}

public class DepEntry
{
    public string   LibName     { get; set; } = "";
    public string   Description { get; set; } = "";
    public byte     Opcode      { get; set; }
    public DateTime FirstSeen   { get; set; }
    public int      Occurrences { get; set; }
}

public class LaggedPacket
{
    public byte[]   Data     { get; set; } = Array.Empty<byte>();
    public DateTime QueuedAt { get; set; }
}
