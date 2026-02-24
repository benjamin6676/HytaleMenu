using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Net.Sockets;
using System.Text;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Macro Engine — replaces PacketTab's basic Combo Chain with a full macro system.
///
/// Features:
///   - Named macros saved to disk — survive restarts
///   - Per-step hex templates with {{VAR}} variable substitution
///   - Per-step conditions: always / if_response / if_no_response
///   - Loop count per macro
///   - Abort-on-fail flag per step
///   - Import from Packet Book, export to clipboard
///   - Live step-by-step status indicators during playback
/// </summary>
public class MacroEngineTab : ITab
{
    public string Title => "  Macros  ";

    private readonly TestLog       _log;
    private readonly PacketCapture _capture;
    private readonly UdpProxy      _udpProxy;
    private readonly ServerConfig  _config;
    private readonly PacketStore   _store;

    private readonly MacroLibrary  _lib;

    // ── UI state ──────────────────────────────────────────────────────────
    private int    _selectedMacro  = -1;
    private int    _selectedStep   = -1;
    private bool   _running        = false;
    private CancellationTokenSource? _cts;

    // New macro form
    private string _newName = "New Macro";
    private string _newDesc = "";

    // New step form (for selected macro)
    private string _stepLabel     = "";
    private string _stepHex       = "";
    private int    _stepDelay     = 50;
    private int    _stepCondType  = 0;
    private string _stepCondVal   = "";

    // Variable edit
    private string _varName  = "VAR";
    private string _varValue = "";

    // Book import
    private string _bookImportLabel = "";

    private static readonly string[] CondTypes = { "Always send", "If server responded", "If no response" };

    // ─────────────────────────────────────────────────────────────────────

    public MacroEngineTab(TestLog log, PacketCapture capture, UdpProxy udpProxy,
                          ServerConfig config, PacketStore store)
    {
        _log = log; _capture = capture; _udpProxy = udpProxy;
        _config = config; _store = store;
        _lib = MacroLibrary.Instance;
    }

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;
        RenderStatusBar(w);
        ImGui.Spacing();

        float listW = 220;
        float mainW = w - listW - 10;
        float h     = ImGui.GetContentRegionAvail().Y;

        // Left: macro list
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##me_maclist", new Vector2(listW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        RenderMacroList(listW);
        ImGui.EndChild();

        ImGui.SameLine(0, 10);

        // Right: macro editor + runner
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##me_main", new Vector2(mainW, h), ImGuiChildFlags.None);
        ImGui.PopStyleColor();
        if (_selectedMacro >= 0 && _selectedMacro < _lib.Macros.Count)
            RenderMacroEditor(_lib.Macros[_selectedMacro], mainW);
        else
        {
            ImGui.SetCursorPosY(h * 0.4f);
            UiHelper.MutedLabel("   ← select a macro or create one");
        }
        ImGui.EndChild();
    }

    // ── Status bar ────────────────────────────────────────────────────────

    private void RenderStatusBar(float w)
    {
        bool srv  = _config.IsSet;
        bool prxy = _capture.IsRunning || _udpProxy.IsRunning;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##me_sb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, srv ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(srv ? $"● {_config.ServerIp}:{_config.ServerPort}" : "● No server");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 24);
        ImGui.PushStyleColor(ImGuiCol.Text, prxy ? MenuRenderer.ColAccent : MenuRenderer.ColWarn);
        ImGui.TextUnformatted(prxy ? "● Proxy active" : "● No proxy — start Capture first");
        ImGui.PopStyleColor();
        if (_running)
        {
            ImGui.SameLine(0, 24);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
            ImGui.TextUnformatted("● Macro running…");
            ImGui.PopStyleColor();
        }
        ImGui.EndChild();
    }

    // ── Macro list (left sidebar) ─────────────────────────────────────────

    private void RenderMacroList(float w)
    {
        ImGui.SetCursorPos(new Vector2(6, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("MACROS");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        // New macro
        UiHelper.SectionBox("NEW", w - 8, 80, () =>
        {
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##me_newname", ref _newName, 40);
            ImGui.SetNextItemWidth(-1); ImGui.InputText("Desc##me_newdesc", ref _newDesc, 80);
            ImGui.Spacing();
            UiHelper.PrimaryButton("Create Macro##me_create", -1, 24, () =>
            {
                if (!string.IsNullOrWhiteSpace(_newName))
                {
                    var m = new Macro { Name = _newName, Description = _newDesc };
                    _lib.Add(m);
                    _selectedMacro = _lib.Macros.IndexOf(m);
                    _log.Success($"[Macros] Created '{_newName}'.");
                    _newName = "New Macro"; _newDesc = "";
                }
            });
        });
        ImGui.Spacing();

        var dl = ImGui.GetWindowDrawList();

        for (int mi = 0; mi < _lib.Macros.Count; mi++)
        {
            var  m   = _lib.Macros[mi];
            bool sel = _selectedMacro == mi;

            if (sel)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(w, 44),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }

            ImGui.SetCursorPosX(8);
            ImGui.PushStyleColor(ImGuiCol.Text, sel ? MenuRenderer.ColAccent : MenuRenderer.ColText);
            ImGui.TextUnformatted(m.Name);
            ImGui.PopStyleColor();
            ImGui.SetCursorPosX(8);
            UiHelper.MutedLabel($"{m.Steps.Count} steps  ×{m.LoopCount}  {m.CreatedAt:dd/MM}");

            ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 40);
            if (ImGui.Selectable($"##mesel{mi}", sel, ImGuiSelectableFlags.None, new Vector2(w - 8, 40)))
                _selectedMacro = mi;

            // Delete button
            float btnX = w - 28;
            ImGui.SameLine(btnX);
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 20);
            ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
            if (ImGui.Button($"✕##medel{mi}", new Vector2(22, 18)) && !_running)
            {
                _lib.Delete(m.Name);
                if (_selectedMacro == mi) _selectedMacro = -1;
                mi--;
                _log.Warn($"[Macros] Deleted '{m.Name}'.");
            }
            ImGui.PopStyleColor(2);
            ImGui.Spacing();
        }
    }

    // ── Macro editor (right panel) ────────────────────────────────────────

    private void RenderMacroEditor(Macro m, float w)
    {
        // ── Macro header + run controls ────────────────────────────────────
        UiHelper.SectionBox("MACRO: " + m.Name.ToUpper(), w, 90, () =>
        {
            if (m.Description.Length > 0) UiHelper.MutedLabel(m.Description);
            ImGui.Spacing();
            ImGui.SetNextItemWidth(80);
            if (ImGui.InputInt("Loop count##me_loops", ref m.LoopCount))
            {
                m.LoopCount = Math.Clamp(m.LoopCount, 1, 1000);
                _lib.ScheduleSave();
            }
            ImGui.SameLine(0, 16);

            if (_running)
            {
                UiHelper.DangerButton("ABORT##me_abort", 100, 30, () =>
                {
                    _cts?.Cancel();
                    _running = false;
                    _log.Warn($"[Macros] '{m.Name}' aborted.");
                });
            }
            else
            {
                UiHelper.WarnButton($"▶ RUN ({m.Steps.Count(s => s.Enabled)} steps)##me_run",
                    200, 30, () => RunMacro(m));
                ImGui.SameLine(0, 8);
                UiHelper.SecondaryButton("Reset##me_rst", 70, 30, () =>
                {
                    foreach (var s in m.Steps) { s.LastResult = MacroStepResult.Pending; s.LastResponse = ""; }
                });
            }
        });

        ImGui.Spacing();

        // ── Variables panel ────────────────────────────────────────────────
        float halfW = (w - 10) * 0.4f;
        UiHelper.SectionBox("VARIABLES", halfW, 100, () =>
        {
            UiHelper.MutedLabel("Use {{VAR}} in hex templates. Substituted at run-time.");
            ImGui.Spacing();
            foreach (var v in m.Variables)
            {
                ImGui.SetNextItemWidth(80); ImGui.InputText($"##vn_{v.Name}", ref v.Name, 24);
                ImGui.SameLine(0, 4);
                ImGui.SetNextItemWidth(120); ImGui.InputText($"##vv_{v.Name}", ref v.Value, 128);
                ImGui.SameLine(0, 4);
                if (ImGui.Button($"✕##vdel_{v.Name}", new Vector2(22, 20)))
                { m.Variables.Remove(v); _lib.ScheduleSave(); break; }
            }
            ImGui.Spacing();
            ImGui.SetNextItemWidth(80); ImGui.InputText("##me_vname", ref _varName, 24);
            ImGui.SameLine(0, 4);
            ImGui.SetNextItemWidth(120); ImGui.InputText("##me_vval", ref _varValue, 128);
            ImGui.SameLine(0, 4);
            UiHelper.PrimaryButton("+Var##me_vadd", 54, 22, () =>
            {
                m.Variables.Add(new MacroVar { Name = _varName, Value = _varValue });
                _lib.ScheduleSave();
                _varName = "VAR"; _varValue = "";
            });
        });

        ImGui.SameLine(0, 10);

        // ── Import from Book ───────────────────────────────────────────────
        float impW = w - halfW - 10;
        UiHelper.SectionBox("IMPORT FROM PACKET BOOK", impW, 100, () =>
        {
            var saved = _store.GetAll();
            if (saved.Count == 0) { UiHelper.MutedLabel("No saved packets in Book."); return; }
            UiHelper.MutedLabel("Append a saved packet as a new step:");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(-70);
            if (ImGui.BeginCombo("##me_booksel", _bookImportLabel))
            {
                foreach (var sp in saved)
                    if (ImGui.Selectable(sp.Label)) { _bookImportLabel = sp.Label; }
                ImGui.EndCombo();
            }
            ImGui.SameLine(0, 6);
            UiHelper.PrimaryButton("Add##me_bookadd", 60, 22, () =>
            {
                var sp = saved.FirstOrDefault(s => s.Label == _bookImportLabel);
                if (sp != null)
                {
                    m.Steps.Add(new MacroStep
                    { Label = sp.Label, HexTemplate = sp.HexString, DelayMs = 50 });
                    _lib.ScheduleSave();
                    _log.Info($"[Macros] Imported '{sp.Label}' into '{m.Name}'.");
                }
            });
        });

        ImGui.Spacing();

        // ── Add step form ──────────────────────────────────────────────────
        UiHelper.SectionBox("ADD STEP", w, 80, () =>
        {
            ImGui.SetNextItemWidth(120); ImGui.InputText("Label##me_sl", ref _stepLabel, 48);
            ImGui.SameLine(0, 6);
            ImGui.SetNextItemWidth(w - 430); ImGui.InputText("Hex##me_shex", ref _stepHex, 2048);
            ImGui.SameLine(0, 6);
            ImGui.SetNextItemWidth(70); ImGui.InputInt("ms##me_sdly", ref _stepDelay);
            _stepDelay = Math.Max(0, _stepDelay);
            ImGui.SameLine(0, 6);
            ImGui.SetNextItemWidth(140); ImGui.Combo("Condition##me_scond", ref _stepCondType, CondTypes, CondTypes.Length);
            if (_stepCondType > 0)
            {
                ImGui.SameLine(0, 6);
                ImGui.SetNextItemWidth(100); ImGui.InputText("Match##me_scval", ref _stepCondVal, 48);
            }
            ImGui.SameLine(0, 6);
            UiHelper.PrimaryButton("Add Step##me_sadd", 80, 26, () =>
            {
                if (!string.IsNullOrWhiteSpace(_stepHex))
                {
                    string lbl = string.IsNullOrWhiteSpace(_stepLabel)
                        ? $"Step {m.Steps.Count + 1}" : _stepLabel;
                    m.Steps.Add(new MacroStep
                    {
                        Label          = lbl,
                        HexTemplate    = _stepHex.Trim(),
                        DelayMs        = _stepDelay,
                        ConditionType  = _stepCondType == 0 ? "always"
                                       : _stepCondType == 1 ? "if_response" : "if_no_response",
                        ConditionValue = _stepCondVal,
                    });
                    _lib.ScheduleSave();
                    _stepLabel = ""; _stepHex = ""; _stepDelay = 50; _stepCondType = 0; _stepCondVal = "";
                }
            });
        });

        ImGui.Spacing();

        // ── Step list ──────────────────────────────────────────────────────
        float stepsH = ImGui.GetContentRegionAvail().Y;
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##me_steps", new Vector2(w, stepsH), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        UiHelper.MutedLabel($"  {"#",-3} {"Condition",-18} {"Label",-20} {"Delay",-7} Hex template");
        var dlh = ImGui.GetWindowDrawList();
        float hy = ImGui.GetCursorScreenPos().Y - 1;
        dlh.AddLine(new Vector2(ImGui.GetWindowPos().X, hy),
                    new Vector2(ImGui.GetWindowPos().X + w, hy),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));

        int removeStep = -1;
        for (int si = 0; si < m.Steps.Count; si++)
        {
            var step = m.Steps[si];

            // Row background based on last result
            if (step.LastResult != MacroStepResult.Pending)
            {
                var sp = ImGui.GetCursorScreenPos();
                var rowCol = step.LastResult switch
                {
                    MacroStepResult.Sent            => MenuRenderer.ColAccentDim,
                    MacroStepResult.ConditionPass   => MenuRenderer.ColAccentDim,
                    MacroStepResult.ConditionFail   => MenuRenderer.ColWarnDim,
                    MacroStepResult.Error           => MenuRenderer.ColDangerDim,
                    MacroStepResult.Running         => MenuRenderer.ColBlueDim,
                    MacroStepResult.Skipped         => new Vector4(0.1f, 0.1f, 0.1f, 0.4f),
                    _ => new Vector4(0, 0, 0, 0),
                };
                ImGui.GetWindowDrawList().AddRectFilled(sp, sp + new Vector2(w, 24),
                    ImGui.ColorConvertFloat4ToU32(rowCol));
            }

            // Enable checkbox
            ImGui.SetCursorPosX(4);
            if (ImGui.Checkbox($"##meen{si}", ref step.Enabled))
                _lib.ScheduleSave();
            ImGui.SameLine(0, 4);

            // Result indicator
            string resultGlyph = step.LastResult switch
            {
                MacroStepResult.Sent          => "✓",
                MacroStepResult.Running       => "●",
                MacroStepResult.ConditionFail => "✗",
                MacroStepResult.Error         => "!",
                MacroStepResult.Skipped       => "–",
                _ => " ",
            };
            var glyphCol = step.LastResult switch
            {
                MacroStepResult.Sent or MacroStepResult.ConditionPass => MenuRenderer.ColAccent,
                MacroStepResult.Running  => MenuRenderer.ColBlue,
                MacroStepResult.Error    => MenuRenderer.ColDanger,
                MacroStepResult.Skipped  => MenuRenderer.ColTextMuted,
                _ => MenuRenderer.ColTextMuted,
            };
            ImGui.PushStyleColor(ImGuiCol.Text, glyphCol);
            ImGui.TextUnformatted(resultGlyph);
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 4);

            // Step content
            ImGui.PushStyleColor(ImGuiCol.Text,
                step.Enabled ? MenuRenderer.ColText : MenuRenderer.ColTextMuted);

            string condLabel = step.ConditionType switch
            {
                "if_response"    => $"↳ resp '{step.ConditionValue}'",
                "if_no_response" => "↳ no response",
                _                => "always",
            };
            string hexPreview = step.HexTemplate.Length > 40
                ? step.HexTemplate[..37] + "…" : step.HexTemplate;

            ImGui.TextUnformatted(
                $"[{si+1,-2}] {condLabel,-18} {step.Label,-20} {step.DelayMs}ms  {hexPreview}");
            ImGui.PopStyleColor();

            // Up/Down/Delete buttons
            ImGui.SameLine(w - 82);
            ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            if (ImGui.Button($"↑##meup{si}", new Vector2(22, 20)) && si > 0)
            {
                (m.Steps[si], m.Steps[si - 1]) = (m.Steps[si - 1], m.Steps[si]);
                _lib.ScheduleSave();
            }
            ImGui.SameLine(0, 2);
            if (ImGui.Button($"↓##medn{si}", new Vector2(22, 20)) && si < m.Steps.Count - 1)
            {
                (m.Steps[si], m.Steps[si + 1]) = (m.Steps[si + 1], m.Steps[si]);
                _lib.ScheduleSave();
            }
            ImGui.PopStyleColor(2);
            ImGui.SameLine(0, 2);
            ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
            if (ImGui.Button($"✕##medels{si}", new Vector2(24, 20))) removeStep = si;
            ImGui.PopStyleColor(2);

            // Tooltip with last response
            if (step.LastResponse.Length > 0 && ImGui.IsItemHovered())
                ImGui.SetTooltip($"Response: {step.LastResponse}");
        }

        if (removeStep >= 0) { m.Steps.RemoveAt(removeStep); _lib.ScheduleSave(); }

        if (m.Steps.Count == 0)
            UiHelper.MutedLabel("  No steps — add steps above or import from Packet Book.");

        ImGui.EndChild();
    }

    // ── Runner ────────────────────────────────────────────────────────────

    private void RunMacro(Macro m)
    {
        if (_running || m.Steps.Count == 0) return;
        _running = true;
        _cts = new CancellationTokenSource();
        var cts  = _cts;
        var snap = new Macro
        {
            Name      = m.Name,
            LoopCount = m.LoopCount,
            Variables = m.Variables.Select(v => new MacroVar { Name = v.Name, Value = v.Value }).ToList(),
            Steps     = m.Steps.ToList(),
        };

        foreach (var s in m.Steps) { s.LastResult = MacroStepResult.Pending; s.LastResponse = ""; }

        _log.Info($"[Macros] Running '{m.Name}' — {snap.Steps.Count} steps × {snap.LoopCount}");

        Task.Run(async () =>
        {
            try
            {
                for (int loop = 0; loop < snap.LoopCount && !cts.IsCancellationRequested; loop++)
                {
                    for (int si = 0; si < snap.Steps.Count && !cts.IsCancellationRequested; si++)
                    {
                        var step = snap.Steps[si];
                        if (!step.Enabled) { step.LastResult = MacroStepResult.Skipped; continue; }

                        step.LastResult = MacroStepResult.Running;

                        // Apply variable substitution
                        string hex = step.HexTemplate;
                        foreach (var v in snap.Variables)
                            hex = hex.Replace($"{{{{{v.Name}}}}}", v.Value);
                        hex = hex.Replace(" ", "").Replace("\n", "").Replace("\r", "");
                        if (hex.Length % 2 != 0) hex += "0";

                        byte[]? data;
                        try { data = Convert.FromHexString(hex); }
                        catch (Exception ex)
                        {
                            step.LastResult   = MacroStepResult.Error;
                            step.LastResponse = ex.Message;
                            _log.Error($"[Macros] Step {si+1} hex parse: {ex.Message}");
                            if (step.AbortOnFail) break;
                            continue;
                        }

                        // Check condition
                        if (step.ConditionType != "always" && step.ConditionValue.Length > 0)
                        {
                            // Look at last N server packets for the condition value
                            int pktsBefore = _capture.GetPackets().Count;
                            bool matchFound = _capture.GetPackets()
                                .TakeLast(20)
                                .Where(p => p.Direction == PacketDirection.ServerToClient)
                                .Any(p => p.HexString.Contains(step.ConditionValue.ToUpper().Replace(" ", "")));

                            bool shouldSend = step.ConditionType == "if_response"    &&  matchFound
                                           || step.ConditionType == "if_no_response" && !matchFound;

                            if (!shouldSend)
                            {
                                step.LastResult = MacroStepResult.ConditionFail;
                                _log.Info($"[Macros] Step {si+1} skipped (condition not met).");
                                continue;
                            }
                        }

                        // Send
                        bool ok = false;
                        if (_udpProxy.IsRunning) ok = _udpProxy.InjectToServer(data);
                        if (!ok)
                        {
                            try
                            {
                                ok = await _capture.InjectToServer(data);
                                if (!ok)
                                {
                                    using var udp = new UdpClient();
                                    udp.Connect(_config.ServerIp, _config.ServerPort);
                                    udp.Send(data, data.Length);
                                    ok = true;
                                }
                            }
                            catch (Exception ex) { step.LastResponse = ex.Message; }
                        }

                        step.LastResult = ok ? MacroStepResult.Sent : MacroStepResult.Error;
                        if (!ok && step.AbortOnFail) break;

                        _log.Info($"[Macros] Step {si+1} '{step.Label}' → {(ok ? "sent" : "FAIL")} {data.Length}b");

                        if (step.DelayMs > 0) await Task.Delay(step.DelayMs, cts.Token);
                    }
                }

                _log.Success($"[Macros] '{m.Name}' complete — {snap.LoopCount} loop(s).");
            }
            catch (OperationCanceledException) { _log.Warn($"[Macros] '{m.Name}' cancelled."); }
            catch (Exception ex) { _log.Error($"[Macros] {ex.Message}"); }
            finally { _running = false; }
        });
    }
}
