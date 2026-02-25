using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// AbuseEngineTab - Packet manipulation UI for security testing.
///
/// Exposes 5 primitives via the AbuseEngine singleton:
///   [1] Delay / Reorder  - hold opcode for N ms (race condition setup)
///   [2] Replay / Dupe    - send same packet N times (double-process test)
///   [3] Suppression      - drop opcode class silently (ghost window)
///   [4] Coord Spoof      - inject false position before trigger opcode
///   [5] Burst Dupe       - two sends within ~1ms (server dup detection)
///
/// All actions are logged to the menu log and captured in the packet log.
/// Active rules are shown in the status bar.
///
/// Confidence scoring on results:
///   If the server processes a replayed or suppressed packet and produces
///   a visible state change, confidence = HIGH [PKT 80%+].
///   Otherwise, impact is marked INFERRED [INF 55%].
/// </summary>
public class AbuseEngineTab : ITab
{
    public string Title => "  Abuse Engine  ";

    private readonly TestLog       _log;
    private readonly UdpProxy      _proxy;
    private readonly PacketCapture _capture;
    private readonly PacketStore   _store;
    private readonly ServerConfig  _config;

    private int  _subTab = 0;
    private static readonly string[] SubTabs =
        { "Delay/Reorder", "Replay/Dupe", "Suppress", "Coord Spoof", "Timing Sweep" };

    // ── Delay tab state ───────────────────────────────────────────────────
    private int    _delayOpcode  = 0x0F;   // ContainerClose
    private int    _delayMs      = 100;
    private string _delayLabel   = "ContainerClose delay";

    // ── Replay tab state ──────────────────────────────────────────────────
    private string _replayHex    = "";
    private int    _replayCount  = 2;
    private int    _replayDelay  = 0;
    private string _replayLabel  = "";
    private bool   _replayRunning = false;

    // ── Suppress tab state ────────────────────────────────────────────────
    private int    _suppressOpcode  = 0x0F;  // ContainerClose
    private int    _suppressDuration = 5000;  // ms, 0=indefinite

    // ── Coord spoof state ─────────────────────────────────────────────────
    private float  _spoofX = 0f, _spoofY = 64f, _spoofZ = 0f;
    private int    _spoofTrigger = 0x09;  // InventoryClick
    private string _spoofLabel  = "Claim bypass test";

    // ── Timing sweep state ────────────────────────────────────────────────
    private string _sweepPkt1   = "";
    private string _sweepPkt2   = "";
    private int    _sweepStart  = 0;
    private int    _sweepEnd    = 100;
    private int    _sweepStep   = 5;
    private bool   _sweepRunning = false;
    private CancellationTokenSource? _sweepCts;
    private readonly List<(int delay, string result)> _sweepResults = new();

    public AbuseEngineTab(TestLog log, UdpProxy proxy, PacketCapture capture,
                           PacketStore store, ServerConfig config)
    {
        _log = log; _proxy = proxy; _capture = capture;
        _store = store; _config = config;
    }

    // ════════════════════════════════════════════════════════════════════
    // RENDER
    // ════════════════════════════════════════════════════════════════════

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;
        RenderStatusBar(w);
        ImGui.Spacing();

        if (ImGui.BeginTabBar("##abuse_tabs"))
        {
            for (int i = 0; i < SubTabs.Length; i++)
                if (ImGui.TabItemButton(SubTabs[i] + $"##abt{i}"))
                    _subTab = i;
            ImGui.EndTabBar();
        }
        ImGui.Spacing();

        switch (_subTab)
        {
            case 0: RenderDelayTab(w);   break;
            case 1: RenderReplayTab(w);  break;
            case 2: RenderSuppressTab(w); break;
            case 3: RenderSpoofTab(w);   break;
            case 4: RenderSweepTab(w);   break;
        }
    }

    // ── Status bar ────────────────────────────────────────────────────────

    private static void RenderStatusBar(float w)
    {
        var ab  = AbuseEngine.Instance;
        bool any = ab.HasActiveRules;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##ab_bar", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 6));

        if (any)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
            ImGui.TextUnformatted(
                $"[!] ACTIVE: {ab.ActiveDelayRules} delay rule(s)  " +
                $"{ab.SuppressedOpcodes} suppression(s)  " +
                $"{(ab.SpoofActive ? "coord spoof ARMED" : "")}");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 20);
            ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColDanger with { W = 0.35f });
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColDanger with { W = 0.55f });
            ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColDanger);
            if (ImGui.Button("STOP ALL##abortall", new Vector2(80, 20)))
                AbuseEngine.Instance.StopAll();
            ImGui.PopStyleColor(3);
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            ImGui.TextUnformatted("[>] No active rules.  All packet manipulation is paused.");
            ImGui.PopStyleColor();
        }

        ImGui.EndChild();
    }

    // ── [1] Delay / Reorder ───────────────────────────────────────────────

    private void RenderDelayTab(float w)
    {
        Header("DELAY / REORDER", "Hold matching packets for N ms then release. " +
               "Simulates network delay or sets up a race condition window.");

        RenderOpcodeCombo("Target opcode##delay_op", ref _delayOpcode);
        RenderField("Delay (ms)##delay_ms", ref _delayMs, 1, 5000);
        RenderTextField("Label##delay_lbl", ref _delayLabel, 80);

        ImGui.Spacing();
        AccentButton("Add Delay Rule##add_delay", () =>
        {
            AbuseEngine.Instance.AddDelayRule((byte)_delayOpcode, _delayMs, _delayLabel);
        });
        ImGui.SameLine(0, 8);
        DangerButton("Remove Rule##rem_delay", () =>
        {
            AbuseEngine.Instance.RemoveDelayRule((byte)_delayOpcode);
        });

        ImGui.Spacing();
        HowTo(
            "1. Select the opcode you want to delay (e.g. 0x0F ContainerClose).",
            "2. Set delay in ms. 50-200ms typically opens a race window.",
            "3. Click 'Add Delay Rule'. All matching C->S packets are queued.",
            "4. Interact with the container in-game. The Close packet will be delayed.",
            "5. Remove rule to stop. Check Item Inspector for duped items."
        );
    }

    // ── [2] Replay / Duplicate ────────────────────────────────────────────

    private void RenderReplayTab(float w)
    {
        Header("REPLAY / DUPLICATE", "Send a captured packet N times. 0ms gap = burst (~1ms). " +
               "Tests server-side duplicate detection and idempotency.");

        RenderTextField("Packet hex##rep_hex", ref _replayHex, 200);
        ImGui.SameLine(0, 6);
        WarnButton("From Book##repfrombook", () =>
        {
            // Placeholder: user pastes from packet book
            _log.Info("[Abuse] Paste hex into the field above from Packet Book.");
        });

        RenderField("Repeat count##rep_cnt", ref _replayCount, 1, 100);
        RenderField("Delay ms##rep_delay", ref _replayDelay, 0, 1000);
        RenderTextField("Label##rep_lbl", ref _replayLabel, 80);

        ImGui.Spacing();
        bool canRun = !_replayRunning && !string.IsNullOrWhiteSpace(_replayHex);
        if (!canRun) ImGui.BeginDisabled();
        AccentButton(_replayRunning ? "Running..." : $"Replay x{_replayCount}##run_replay", () =>
        {
            byte[]? data = ParseHex(_replayHex);
            if (data == null) { _log.Error("[Abuse] Invalid hex."); return; }
            _replayRunning = true;
            _ = AbuseEngine.Instance.ReplayAsync(data, _replayCount, _replayDelay, _replayLabel)
                           .ContinueWith(_ => _replayRunning = false);
        });
        if (!canRun) ImGui.EndDisabled();
        ImGui.SameLine(0, 8);
        WarnButton("Burst Dupe (x2 ~1ms)##burst", () =>
        {
            byte[]? data = ParseHex(_replayHex);
            if (data == null) { _log.Error("[Abuse] Invalid hex."); return; }
            _ = AbuseEngine.Instance.BurstDupeAsync(data);
        });

        HowTo(
            "1. Capture a packet in the packet log. Right-click -> Copy Hex.",
            "2. Paste the hex bytes into the field above.",
            "3. Set repeat count: 2 = basic dupe, 10-30 = stress test.",
            "4. Set delay ms: 0 = burst all at once, 1ms = near-simultaneous.",
            "5. Click Replay. Watch the Item Inspector for duplicate items."
        );
    }

    // ── [3] Suppression ───────────────────────────────────────────────────

    private void RenderSuppressTab(float w)
    {
        Header("SUPPRESSION / GHOST WINDOW", "Drop all packets of a given opcode for N ms. " +
               "ContainerClose suppression creates a ghost window for item extraction.");

        RenderOpcodeCombo("Opcode to suppress##sup_op", ref _suppressOpcode);
        RenderField("Duration ms (0=indefinite)##sup_dur", ref _suppressDuration, 0, 60000);

        ImGui.Spacing();
        DangerButton($"Suppress 0x{_suppressOpcode:X2} for {_suppressDuration}ms##run_sup", () =>
        {
            _ = AbuseEngine.Instance.SuppressAsync((byte)_suppressOpcode, _suppressDuration,
                    OpcodeRegistry.Label((byte)_suppressOpcode, PacketDirection.ClientToServer));
        });
        ImGui.SameLine(0, 8);
        AccentButton("Stop Suppression##stop_sup", () =>
        {
            AbuseEngine.Instance.StopSuppression((byte)_suppressOpcode);
        });

        HowTo(
            "1. Select ContainerClose (0x0F) to create a ghost window.",
            "2. Set duration: 5000ms lets you move items while close is suppressed.",
            "3. Click Suppress. Open a chest in-game and move items.",
            "4. The server thinks the container is still open - authority confusion.",
            "5. Stop suppression to release the queue. Check server response."
        );
    }

    // ── [4] Coord Spoof ───────────────────────────────────────────────────

    private void RenderSpoofTab(float w)
    {
        Header("COORDINATE SPOOF", "Inject a false position packet immediately before a trigger " +
               "opcode. Tests claim/permission boundary checks.");

        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted("Spoof coordinates (X / Y / Z):");
        ImGui.PopStyleColor();
        ImGui.SetNextItemWidth(90); ImGui.InputFloat("X##spx", ref _spoofX, 1f, 10f, "%.1f");
        ImGui.SameLine(0, 6);
        ImGui.SetNextItemWidth(90); ImGui.InputFloat("Y##spy", ref _spoofY, 1f, 10f, "%.1f");
        ImGui.SameLine(0, 6);
        ImGui.SetNextItemWidth(90); ImGui.InputFloat("Z##spz", ref _spoofZ, 1f, 10f, "%.1f");

        ImGui.Spacing();
        RenderOpcodeCombo("Trigger opcode##spoof_trig", ref _spoofTrigger);
        RenderTextField("Label##spoof_lbl", ref _spoofLabel, 80);

        ImGui.Spacing();
        bool armed = AbuseEngine.Instance.SpoofActive;
        if (armed)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
            ImGui.TextUnformatted("[!] Coord spoof ARMED - next trigger opcode will inject spoof.");
            ImGui.PopStyleColor();
            DangerButton("Disarm Spoof##disarm", () => AbuseEngine.Instance.DisarmCoordSpoof());
        }
        else
        {
            AccentButton("Arm Coord Spoof##arm_spoof", () =>
            {
                AbuseEngine.Instance.ArmCoordSpoof(_spoofX, _spoofY, _spoofZ,
                    (byte)_spoofTrigger, _spoofLabel);
            });
        }

        HowTo(
            "1. Enter coordinates INSIDE a protected claim or restricted area.",
            "2. Set trigger to InventoryClick (0x09) or ContainerOpen (0x0D).",
            "3. Click Arm. When you interact in-game, a spoofed PlayerMove fires first.",
            "4. The server may grant access thinking you're at the spoofed location.",
            "5. Spoof fires once per trigger. Re-arm to test again."
        );
    }

    // ── [5] Timing Sweep ─────────────────────────────────────────────────

    private void RenderSweepTab(float w)
    {
        Header("TIMING SWEEP", "Automatically sweep delay from start to end ms. " +
               "Finds the exact race window where the server is vulnerable.");

        RenderTextField("Packet 1 hex (trigger)##sw1", ref _sweepPkt1, 200);
        RenderTextField("Packet 2 hex (exploit)##sw2", ref _sweepPkt2, 200);

        ImGui.Spacing();
        RenderField("Start ms##sw_start", ref _sweepStart, 0, 500);
        RenderField("End ms##sw_end",   ref _sweepEnd,   1, 2000);
        RenderField("Step ms##sw_step", ref _sweepStep,  1, 100);

        ImGui.Spacing();
        bool canSweep = !_sweepRunning
            && !string.IsNullOrWhiteSpace(_sweepPkt1)
            && !string.IsNullOrWhiteSpace(_sweepPkt2);

        if (!canSweep) ImGui.BeginDisabled();
        AccentButton(_sweepRunning ? "Sweeping..." : "Start Sweep##run_sweep", () =>
        {
            byte[]? p1 = ParseHex(_sweepPkt1);
            byte[]? p2 = ParseHex(_sweepPkt2);
            if (p1 == null || p2 == null) { _log.Error("[Abuse] Invalid hex in sweep packets."); return; }
            _sweepRunning = true;
            _sweepResults.Clear();
            _sweepCts = new CancellationTokenSource();
            _ = AbuseEngine.Instance.TimingSweepAsync(p1, p2, _sweepStart, _sweepEnd, _sweepStep,
                    (d, r) => { lock (_sweepResults) _sweepResults.Add((d, r)); },
                    _sweepCts.Token)
                .ContinueWith(_ => _sweepRunning = false);
        });
        if (!canSweep) ImGui.EndDisabled();
        ImGui.SameLine(0, 8);
        if (_sweepRunning)
            DangerButton("Stop##stop_sweep", () => { _sweepCts?.Cancel(); _sweepRunning = false; });

        // Results table
        if (_sweepResults.Count > 0)
        {
            ImGui.Spacing();
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
            ImGui.TextUnformatted($"RESULTS ({_sweepResults.Count} data points):");
            ImGui.PopStyleColor();
            float tableH = Math.Clamp(_sweepResults.Count * 18f + 8f, 40f, 200f);
            ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg0);
            ImGui.BeginChild("##sweep_res", new Vector2(w, tableH), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();
            lock (_sweepResults)
            {
                foreach (var (d, r) in _sweepResults)
                {
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                    ImGui.TextUnformatted($"  {d,5}ms  ->  {r}");
                    ImGui.PopStyleColor();
                }
            }
            ImGui.EndChild();
        }

        HowTo(
            "1. Put the triggering packet (e.g. ContainerOpen) in Packet 1.",
            "2. Put the exploit packet (e.g. ContainerMove) in Packet 2.",
            "3. Set range 0-200ms, step 5ms. Click Start Sweep.",
            "4. The engine sends P1, waits N ms, sends P2 for each N in range.",
            "5. Watch item inspector for the delay at which dupe succeeds."
        );
    }

    // ── Shared UI helpers ─────────────────────────────────────────────────

    private static void Header(string title, string subtitle)
    {
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted(title);
        ImGui.PopStyleColor();
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(subtitle);
        ImGui.PopStyleColor();
        ImGui.Spacing();
    }

    private static void RenderOpcodeCombo(string label, ref int opcode)
    {
        string display = $"0x{opcode:X2}  {OpcodeRegistry.Label((byte)opcode, PacketDirection.ClientToServer)}";
        ImGui.SetNextItemWidth(260);
        if (ImGui.BeginCombo(label, display))
        {
            foreach (var (op, info, isCs) in OpcodeRegistry.AllKnown().Where(x => x.isCs).OrderBy(x => x.id))
            {
                bool sel = opcode == op;
                if (ImGui.Selectable($"0x{op:X2}  {info.Name}  [{info.Category}]##op{op}", sel))
                    opcode = op;
                if (sel) ImGui.SetItemDefaultFocus();
            }
            ImGui.EndCombo();
        }
    }

    private static void RenderField(string label, ref int value, int min, int max)
    {
        ImGui.SetNextItemWidth(140);
        ImGui.SliderInt(label, ref value, min, max);
    }

    private static void RenderTextField(string label, ref string value, int maxLen)
    {
        ImGui.SetNextItemWidth(-1);
        ImGui.InputText(label, ref value, (uint)maxLen);
    }

    private void AccentButton(string label, Action onClick)
    {
        ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColAccentDim);
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColAccent with { W = 0.35f });
        ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColAccent);
        if (ImGui.Button(label, new Vector2(0, 26))) onClick();
        ImGui.PopStyleColor(3);
    }

    private void DangerButton(string label, Action onClick)
    {
        ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColDanger with { W = 0.28f });
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColDanger with { W = 0.45f });
        ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColDanger);
        if (ImGui.Button(label, new Vector2(0, 26))) onClick();
        ImGui.PopStyleColor(3);
    }

    private void WarnButton(string label, Action onClick)
    {
        ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColWarnDim);
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColWarn with { W = 0.30f });
        ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColWarn);
        if (ImGui.Button(label, new Vector2(0, 26))) onClick();
        ImGui.PopStyleColor(3);
    }

    private static void HowTo(params string[] steps)
    {
        ImGui.Spacing();
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted("HOW TO USE:");
        foreach (var s in steps)
            ImGui.TextUnformatted($"  {s}");
        ImGui.PopStyleColor();
    }

    private static byte[]? ParseHex(string hex)
    {
        try
        {
            hex = hex.Trim().Replace(" ", "").Replace("0x", "");
            if (hex.Length % 2 != 0) return null;
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }
        catch { return null; }
    }
}
