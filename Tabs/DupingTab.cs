using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Net.Sockets;

namespace HytaleSecurityTester.Tabs;

public class DupingTab : ITab
{
    public string Title => "  Dupe Methods  ";

    private readonly TestLog       _log;
    private readonly UdpProxy      _udpProxy;
    private readonly PacketCapture _capture;
    private readonly PacketStore   _store;
    private readonly ServerConfig  _config;

    private int  _itemId    = 1001;
    private int  _itemCount = 1;
    private bool _itemIdFromInspector = false; // true when set via TargetItemId

    // Drop race
    private string _dropHex    = "";
    private string _pickupHex  = "";
    private int    _raceThreads = 8;
    private int    _raceIter    = 20;
    private bool   _raceRunning = false;
    private CancellationTokenSource? _raceCts;

    // Trade race
    private string _tradeAcceptHex = "";
    private string _tradeCancelHex = "";
    private int    _tradeThreads   = 4;
    private bool   _tradeRunning   = false;

    // Container race
    private string _containerMoveHex = "";
    private int    _containerThreads = 6;
    private bool   _containerRunning = false;

    // Replay dupe
    private string _replayHex     = "";
    private int    _replayCount   = 30;
    private int    _replayDelayMs = 0;

    // Rollback
    private string _rollbackStartHex = "";
    private int    _rollbackDelayMs  = 50;
    private bool   _rollbackDrop     = true;
    private bool   _rollbackTrade    = false;

    // Timing sweep
    private string _sweepPkt1    = "";
    private string _sweepPkt2    = "";
    private int    _sweepStart   = 0;
    private int    _sweepEnd     = 100;
    private int    _sweepStep    = 5;
    private bool   _sweepRunning = false;
    private List<(int delay, string result)> _sweepResults = new();

    private int _subTab = 0;
    private static readonly string[] SubTabs =
        { "Drop Race", "Trade Race", "Container Race", "Replay", "Rollback", "Timing Sweep", "Burst Test" };

    public DupingTab(TestLog log, UdpProxy udpProxy, PacketCapture capture,
                     PacketStore store, ServerConfig config)
    {
        _log = log; _udpProxy = udpProxy; _capture = capture;
        _store = store; _config = config;

        // Auto-fill item ID whenever Item Inspector sets a new target
        _config.OnTargetItemChanged += () =>
        {
            if (_config.HasTargetItem)
            {
                _itemId              = _config.TargetItemId;
                _itemIdFromInspector = true;
                _log.Success($"[Dupe] Target item auto-filled: {_itemId} " +
                             $"(from {_config.TargetItemSource})");
            }
        };
    }

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;
        RenderStatusBar(w);
        ImGui.Spacing();
        RenderItemConfig(w);
        ImGui.Spacing();
        RenderSubTabBar();
        ImGui.Spacing();
        switch (_subTab)
        {
            case 0: RenderDropRace(w);      break;
            case 1: RenderTradeRace(w);     break;
            case 2: RenderContainerRace(w); break;
            case 3: RenderReplayDupe(w);    break;
            case 4: RenderRollback(w);      break;
            case 5: RenderTimingSweep(w);   break;
            case 6: RenderBurstTest(w);     break;
        }
    }

    private void RenderStatusBar(float w)
    {
        bool proxy = _udpProxy.IsRunning || _capture.IsRunning;
        bool srv   = _config.IsSet;
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##dupesb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));
        ImGui.PushStyleColor(ImGuiCol.Text, srv   ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(srv ? $"● {_config.ServerIp}:{_config.ServerPort}" : "● No server");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 24);
        ImGui.PushStyleColor(ImGuiCol.Text, proxy ? MenuRenderer.ColAccent : MenuRenderer.ColWarn);
        ImGui.TextUnformatted(proxy ? "● Proxy active" : "● No proxy — start Capture tab");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 24);
        bool anyRunning = _raceRunning || _tradeRunning || _containerRunning || _sweepRunning;
        ImGui.PushStyleColor(ImGuiCol.Text, anyRunning ? MenuRenderer.ColWarn : MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(anyRunning ? "● TEST RUNNING" : "● Idle");
        ImGui.PopStyleColor();
        ImGui.EndChild();
    }

    private void RenderItemConfig(float w)
    {
        UiHelper.SectionBox("TARGET ITEM", w, 68, () =>
        {
            ImGui.SetNextItemWidth(130);
            if (ImGui.InputInt("Item ID##dit", ref _itemId))
                _itemIdFromInspector = false; // manual edit clears the badge
            _itemId = Math.Max(1, _itemId);

            ImGui.SameLine(0, 8);

            // Badge showing where the ID came from
            if (_itemIdFromInspector && _config.HasTargetItem && _config.TargetItemId == _itemId)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted($"★ from {_config.TargetItemSource}");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 10);
                UiHelper.SecondaryButton("✕##clrtgt", 26, 22, () =>
                {
                    _itemIdFromInspector = false;
                    _log.Info("[Dupe] Item ID cleared from inspector target.");
                });
            }
            else
            {
                UiHelper.MutedLabel("← set via Item Inspector or enter manually");
            }

            ImGui.SameLine(0, 16);
            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("Stack##dic", ref _itemCount);
            _itemCount = Math.Max(1, _itemCount);
        });
    }

    private void RenderSubTabBar()
    {
        if (!ImGui.BeginTabBar("##dupe_subtabs", ImGuiTabBarFlags.FittingPolicyScroll))
            return;
        for (int i = 0; i < SubTabs.Length; i++)
        {
            if (ImGui.TabItemButton(SubTabs[i] + $"##dst{i}",
                    ImGuiTabItemFlags.None))
                _subTab = i;
        }
        ImGui.EndTabBar();
    }

    private void RenderDropRace(float w)
    {
        float half = (w - 12) * 0.5f;
        UiHelper.SectionBox("DROP PACKET", half, 90, () =>
        {
            UiHelper.MutedLabel("Capture a Drop Item packet (C\u2192S).");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##drph", ref _dropHex, 512);
            RenderBookPicker("Load from Book##drbook", v => _dropHex = v);
        });
        ImGui.SameLine(0, 12);
        UiHelper.SectionBox("PICKUP PACKET", half, 90, () =>
        {
            UiHelper.MutedLabel("Capture a PickUp / item acquire packet (C\u2192S).");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##puph", ref _pickupHex, 512);
            RenderBookPicker("Load from Book##pubook", v => _pickupHex = v);
        });
        ImGui.Spacing();
        UiHelper.SectionBox("RACE CONFIG + RUN", w, 150, () =>
        {
            UiHelper.MutedLabel("Sends Drop + Pickup simultaneously from parallel threads.");
            UiHelper.MutedLabel("If server doesn\u2019t lock item state, both succeed \u2192 dupe.");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(110); ImGui.InputInt("Threads##drrt", ref _raceThreads);
            _raceThreads = Math.Clamp(_raceThreads, 1, 64);
            ImGui.SameLine(0, 16);
            ImGui.SetNextItemWidth(110); ImGui.InputInt("Iterations##drri", ref _raceIter);
            _raceIter = Math.Clamp(_raceIter, 1, 500);
            ImGui.Spacing();
            if (_raceRunning)
            {
                UiHelper.DangerButton("STOP##drstop", 100, 30, () =>
                { _raceCts?.Cancel(); _raceRunning = false; _log.Warn("[DropRace] Stopped."); });
                ImGui.SameLine(0, 12); UiHelper.WarnText("● Running...");
            }
            else UiHelper.WarnButton("RUN DROP RACE##drrun", 180, 30, RunDropRace);
        });
        ImGui.Spacing();
        RenderHowTo("1. Capture Drop Item packet \u2192 paste above",
                    "2. Capture PickUp packet \u2192 paste above",
                    "3. Set threads to 8+ for best coverage",
                    "4. Click RUN \u2014 watch if item count increases in-game",
                    "5. Server log showing duplicate item = vulnerable");
    }

    private void RunDropRace()
    {
        if (string.IsNullOrWhiteSpace(_dropHex) || string.IsNullOrWhiteSpace(_pickupHex))
        { _log.Error("[DropRace] Paste both packets first."); return; }
        if (!TryParseHex(_dropHex, out byte[]? drop))   { _log.Error("[DropRace] Invalid Drop hex.");   return; }
        if (!TryParseHex(_pickupHex, out byte[]? pickup)){ _log.Error("[DropRace] Invalid Pickup hex."); return; }

        _raceRunning = true; _raceCts = new CancellationTokenSource();
        var cts = _raceCts;
        _log.Info($"[DropRace] {_raceThreads} threads \u00d7 {_raceIter} iters...");
        Task.Run(async () =>
        {
            int wins = 0;
            var tasks = Enumerable.Range(0, _raceThreads).Select(_ => Task.Run(async () =>
            {
                for (int i = 0; i < _raceIter; i++)
                {
                    if (cts.IsCancellationRequested) break;
                    await Task.WhenAll(Task.Run(() => SendRaw(drop!)), Task.Run(() => SendRaw(pickup!)));
                    Interlocked.Increment(ref wins);
                    await Task.Delay(Random.Shared.Next(0, 3));
                }
            })).ToList();
            await Task.WhenAll(tasks);
            _raceRunning = false;
            _log.Success($"[DropRace] Done \u2014 {wins} race pairs fired. Check inventory + server logs.");
        });
    }

    private void RenderTradeRace(float w)
    {
        float half = (w - 12) * 0.5f;
        UiHelper.SectionBox("TRADE ACCEPT PACKET", half, 85, () =>
        {
            UiHelper.MutedLabel("C\u2192S packet when you confirm a trade.");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##taph", ref _tradeAcceptHex, 512);
            RenderBookPicker("Load##tabook", v => _tradeAcceptHex = v);
        });
        ImGui.SameLine(0, 12);
        UiHelper.SectionBox("TRADE CANCEL PACKET", half, 85, () =>
        {
            UiHelper.MutedLabel("C\u2192S packet when you cancel/close a trade.");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##tcph", ref _tradeCancelHex, 512);
            RenderBookPicker("Load##tcbook", v => _tradeCancelHex = v);
        });
        ImGui.Spacing();
        UiHelper.SectionBox("RUN", w, 125, () =>
        {
            UiHelper.MutedLabel("Sends Accept + Cancel simultaneously.");
            UiHelper.MutedLabel("If server has no mutex on trade state, both may succeed.");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(110); ImGui.InputInt("Threads##trrt", ref _tradeThreads);
            _tradeThreads = Math.Clamp(_tradeThreads, 1, 32);
            ImGui.Spacing();
            if (_tradeRunning)
                UiHelper.DangerButton("STOP##trstop", 100, 28, () =>
                { _tradeRunning = false; _log.Warn("[TradeRace] Stopped."); });
            else
                UiHelper.WarnButton("RUN TRADE RACE##trrun", 170, 28, RunTradeRace);
        });
        ImGui.Spacing();
        RenderHowTo("1. Open a trade with another player or NPC",
                    "2. Capture Accept and Cancel packets",
                    "3. Paste both above and click RUN",
                    "4. If items appear in both inventories = vulnerable");
    }

    private void RunTradeRace()
    {
        if (string.IsNullOrWhiteSpace(_tradeAcceptHex) || string.IsNullOrWhiteSpace(_tradeCancelHex))
        { _log.Error("[TradeRace] Paste both packets first."); return; }
        if (!TryParseHex(_tradeAcceptHex, out byte[]? accept)) { _log.Error("[TradeRace] Invalid Accept hex."); return; }
        if (!TryParseHex(_tradeCancelHex, out byte[]? cancel)) { _log.Error("[TradeRace] Invalid Cancel hex."); return; }
        _tradeRunning = true;
        _log.Info($"[TradeRace] {_tradeThreads} threads...");
        Task.Run(async () =>
        {
            var tasks = Enumerable.Range(0, _tradeThreads).Select(_ => Task.Run(async () =>
                await Task.WhenAll(Task.Run(() => SendRaw(accept!)), Task.Run(() => SendRaw(cancel!)))
            )).ToList();
            await Task.WhenAll(tasks);
            _tradeRunning = false;
            _log.Success("[TradeRace] Done. Check if both parties received items.");
        });
    }

    private void RenderContainerRace(float w)
    {
        UiHelper.SectionBox("CONTAINER MOVE PACKET", w, 85, () =>
        {
            UiHelper.MutedLabel("C\u2192S packet for moving an item inside a container/chest.");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##cmph", ref _containerMoveHex, 512);
            RenderBookPicker("Load##cmbook", v => _containerMoveHex = v);
        });
        ImGui.Spacing();
        UiHelper.SectionBox("RUN", w, 120, () =>
        {
            UiHelper.MutedLabel("Sends the same MoveItem packet simultaneously \u2014 tests if server allows only one move per item.");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(110); ImGui.InputInt("Threads##crth", ref _containerThreads);
            _containerThreads = Math.Clamp(_containerThreads, 1, 32);
            ImGui.Spacing();
            if (_containerRunning)
                UiHelper.DangerButton("STOP##crstop", 100, 28, () =>
                { _containerRunning = false; _log.Warn("[ContainerRace] Stopped."); });
            else
                UiHelper.WarnButton("RUN CONTAINER RACE##crrun", 200, 28, RunContainerRace);
        });
        ImGui.Spacing();
        RenderHowTo("1. Open a chest/container in-game",
                    "2. Capture the move-item packet",
                    "3. Paste above and click RUN",
                    "4. Item in two locations = vulnerable");
    }

    private void RunContainerRace()
    {
        if (string.IsNullOrWhiteSpace(_containerMoveHex))
        { _log.Error("[ContainerRace] Paste a MoveItem packet first."); return; }
        if (!TryParseHex(_containerMoveHex, out byte[]? move)) { _log.Error("[ContainerRace] Invalid hex."); return; }
        _containerRunning = true;
        _log.Info($"[ContainerRace] Firing {_containerThreads} simultaneous packets...");
        Task.Run(async () =>
        {
            await Task.WhenAll(Enumerable.Range(0, _containerThreads).Select(_ => Task.Run(() => SendRaw(move!))));
            _containerRunning = false;
            _log.Success("[ContainerRace] Done. Check if item was duplicated.");
        });
    }

    private void RenderReplayDupe(float w)
    {
        UiHelper.SectionBox("REPLAY PACKET", w, 85, () =>
        {
            UiHelper.MutedLabel("Any item-related C\u2192S packet. A PickUp packet is ideal.");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##rdph", ref _replayHex, 512);
            RenderBookPicker("Load##rdbook", v => _replayHex = v);
        });
        ImGui.Spacing();
        UiHelper.SectionBox("RUN", w, 120, () =>
        {
            ImGui.SetNextItemWidth(110); ImGui.InputInt("Count##rdcnt", ref _replayCount);
            _replayCount = Math.Clamp(_replayCount, 1, 10000);
            ImGui.SameLine(0, 16);
            ImGui.SetNextItemWidth(110); ImGui.InputInt("Delay ms##rddly", ref _replayDelayMs);
            _replayDelayMs = Math.Clamp(_replayDelayMs, 0, 5000);
            ImGui.SameLine(0, 16); UiHelper.MutedLabel("0 = as fast as possible");
            ImGui.Spacing();
            UiHelper.WarnButton($"REPLAY \u00d7{_replayCount}##rdrun", 160, 28, RunReplayDupe);
        });
        ImGui.Spacing();
        RenderHowTo("1. Pick up or receive an item in-game",
                    "2. Capture the resulting packet",
                    "3. Paste above, set count to 10, click REPLAY",
                    "4. Item duplicates = no replay protection");
    }

    private void RunReplayDupe()
    {
        if (string.IsNullOrWhiteSpace(_replayHex)) { _log.Error("[Replay] Paste a packet first."); return; }
        if (!TryParseHex(_replayHex, out byte[]? data)) { _log.Error("[Replay] Invalid hex."); return; }
        int count = _replayCount, delay = _replayDelayMs;
        _log.Info($"[Replay] Sending \u00d7{count} delay={delay}ms...");
        Task.Run(async () =>
        {
            int sent = 0;
            for (int i = 0; i < count; i++)
            {
                SendRaw(data!); sent++;
                if (delay > 0) await Task.Delay(delay);
            }
            _log.Success($"[Replay] {sent}/{count} sent. Watch for duplicate items.");
        });
    }

    private void RenderRollback(float w)
    {
        float half = (w - 12) * 0.5f;
        UiHelper.SectionBox("TRANSACTION START PACKET", half, 85, () =>
        {
            UiHelper.MutedLabel("Packet that starts the transaction (drop, trade start, etc.).");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##rbph", ref _rollbackStartHex, 512);
            RenderBookPicker("Load##rbbook", v => _rollbackStartHex = v);
        });
        ImGui.SameLine(0, 12);
        UiHelper.SectionBox("ROLLBACK CONFIG", half, 85, () =>
        {
            UiHelper.MutedLabel("Delay between packet send and forced disconnect:");
            ImGui.SetNextItemWidth(110); ImGui.InputInt("Delay ms##rbdly", ref _rollbackDelayMs);
            _rollbackDelayMs = Math.Clamp(_rollbackDelayMs, 1, 5000);
            ImGui.Spacing();
            ImGui.Checkbox("Mid-drop##rbdrop", ref _rollbackDrop);
            ImGui.SameLine(0, 12);
            ImGui.Checkbox("Mid-trade##rbtrade", ref _rollbackTrade);
        });
        ImGui.Spacing();
        UiHelper.SectionBox("RUN", w, 100, () =>
        {
            UiHelper.MutedLabel("Sends transaction start, waits delay ms, then kills UDP proxy.");
            UiHelper.MutedLabel("If item committed before disconnect = rollback failure = dupe.");
            ImGui.Spacing();
            UiHelper.WarnButton("RUN ROLLBACK TEST##rbrun", 200, 28, RunRollback);
        });
        ImGui.Spacing();
        RenderHowTo("1. Start UDP proxy in Capture tab",
                    "2. Capture the first packet of a drop or trade",
                    "3. Set delay 50\u2013200ms (experiment to find commit time)",
                    "4. RUN \u2014 tool sends start packet then kills connection",
                    "5. Reconnect \u2014 item in both places = rollback failure");
    }

    private void RunRollback()
    {
        if (string.IsNullOrWhiteSpace(_rollbackStartHex))
        { _log.Error("[Rollback] Paste a transaction start packet first."); return; }
        if (!TryParseHex(_rollbackStartHex, out byte[]? txStart))
        { _log.Error("[Rollback] Invalid hex."); return; }
        int delay = _rollbackDelayMs;
        _log.Info($"[Rollback] Sending start, disconnecting in {delay}ms...");
        Task.Run(async () =>
        {
            SendRaw(txStart!);
            _log.Info("[Rollback] Packet sent \u2014 waiting...");
            await Task.Delay(delay);
            _udpProxy.Stop();
            _log.Warn("[Rollback] Proxy stopped (connection killed). Reconnect in-game and check inventory.");
        });
    }

    private void RenderTimingSweep(float w)
    {
        float half = (w - 12) * 0.5f;
        UiHelper.SectionBox("PACKET 1", half, 85, () =>
        {
            UiHelper.MutedLabel("First send (e.g. transaction start).");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##swp1", ref _sweepPkt1, 512);
            RenderBookPicker("Load##sw1book", v => _sweepPkt1 = v);
        });
        ImGui.SameLine(0, 12);
        UiHelper.SectionBox("PACKET 2", half, 85, () =>
        {
            UiHelper.MutedLabel("Second send (e.g. competing action).");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##swp2", ref _sweepPkt2, 512);
            RenderBookPicker("Load##sw2book", v => _sweepPkt2 = v);
        });
        ImGui.Spacing();
        UiHelper.SectionBox("SWEEP CONFIG + RUN", w, 130, () =>
        {
            UiHelper.MutedLabel("Sends Pkt1, waits [delay], sends Pkt2. Sweeps from Start to End ms.");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(90); ImGui.InputInt("Start ms##sws", ref _sweepStart);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(90); ImGui.InputInt("End ms##swe",   ref _sweepEnd);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(90); ImGui.InputInt("Step ms##swst", ref _sweepStep);
            _sweepStart = Math.Max(0, _sweepStart);
            _sweepEnd   = Math.Clamp(_sweepEnd, _sweepStart + 1, 5000);
            _sweepStep  = Math.Clamp(_sweepStep, 1, 1000);
            ImGui.Spacing();
            if (_sweepRunning)
            {
                UiHelper.DangerButton("STOP##swstop", 80, 28, () => { _sweepRunning = false; });
                ImGui.SameLine(0, 12); UiHelper.WarnText("● Sweeping...");
            }
            else UiHelper.WarnButton("RUN TIMING SWEEP##swrun", 180, 28, RunTimingSweep);
        });
        if (_sweepResults.Count > 0)
        {
            ImGui.Spacing();
            UiHelper.SectionBox("SWEEP RESULTS", w, 110, () =>
            {
                UiHelper.MutedLabel("Delay (ms)   Result");
                ImGui.Separator();
                foreach (var (delay, result) in _sweepResults.TakeLast(10))
                {
                    UiHelper.MutedLabel($"  {delay,-12}");
                    ImGui.SameLine();
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
                    ImGui.TextUnformatted(result);
                    ImGui.PopStyleColor();
                }
            });
        }
    }

    private void RunTimingSweep()
    {
        if (string.IsNullOrWhiteSpace(_sweepPkt1) || string.IsNullOrWhiteSpace(_sweepPkt2))
        { _log.Error("[Sweep] Paste both packets first."); return; }
        if (!TryParseHex(_sweepPkt1, out byte[]? p1)) { _log.Error("[Sweep] Invalid Pkt1 hex."); return; }
        if (!TryParseHex(_sweepPkt2, out byte[]? p2)) { _log.Error("[Sweep] Invalid Pkt2 hex."); return; }
        _sweepRunning = true; _sweepResults.Clear();
        int start = _sweepStart, end = _sweepEnd, step = _sweepStep;
        _log.Info($"[Sweep] Sweeping {start}\u2013{end}ms step={step}ms...");
        Task.Run(async () =>
        {
            for (int delay = start; delay <= end && _sweepRunning; delay += step)
            {
                SendRaw(p1!);
                await Task.Delay(delay);
                SendRaw(p2!);
                _sweepResults.Add((delay, "SENT"));
                _log.Info($"[Sweep] delay={delay}ms \u2014 both sent.");
                await Task.Delay(300);
            }
            _sweepRunning = false;
            _log.Success("[Sweep] Complete. Watch for dupes at specific delays.");
        });
    }

    // ── Burst Test ────────────────────────────────────────────────────────
    // Up to 3 packet templates can be burst simultaneously to test how the
    // server handles rapid concurrent state changes.

    private string _burstPkt1      = "";
    private string _burstPkt2      = "";
    private string _burstPkt3      = "";
    private bool   _burstUsePkt2   = false;
    private bool   _burstUsePkt3   = false;
    private int    _burstCount     = 500;     // total packets per template
    private int    _burstThreads   = 16;      // degree of parallelism
    private int    _burstDelayUs   = 0;       // microsecond gap between sends (0 = flat out)
    private int    _burstBatchSize  = 10;     // packets per thread batch before yielding
    private bool   _burstRunning   = false;
    private CancellationTokenSource? _burstCts;

    // Live telemetry updated from the burst task
    private volatile int   _burstSent       = 0;
    private volatile int   _burstErrors     = 0;
    private          long  _burstStartTicks = 0;
    private          long  _burstEndTicks   = 0;

    // Histogram: latency buckets in µs (0-1, 1-5, 5-20, 20-100, 100-500, 500+)
    private readonly int[] _burstBuckets  = new int[6];
    private static readonly string[] BucketLabels =
        { "<1µs", "1–5µs", "5–20µs", "20–100µs", "100–500µs", "500µs+" };

    // ── Latency Emulator ──────────────────────────────────────────────────
    private bool   _latencyEnabled  = false;
    private string _latStage1Hex    = "";   // trigger packet (opens container / initiates auth check)
    private string _latStage2Hex    = "";   // exploit packet (state change during auth gap)
    private int    _latPropDelayMs  = 80;   // plugin propagation delay to emulate (ms)
    private int    _latJitterMs     = 20;   // ±jitter added to propagation delay
    private int    _latRepeat       = 10;   // how many stage1→delay→stage2 cycles to run
    private int    _latStage2Burst  = 5;    // how many stage2 packets per cycle
    private int    _latCooldownMs   = 200;  // ms between cycles
    private bool   _latRunning      = false;
    private int    _latIteration    = 0;
    private int    _latStage        = 0;    // 1 or 2 — which stage is currently executing
    private CancellationTokenSource? _latCts;

    private void RenderBurstTest(float w)
    {
        float half = (w - 12) * 0.5f;

        // ── Packet templates ──────────────────────────────────────────────
        UiHelper.SectionBox("BURST PACKETS", w, 180, () =>
        {
            UiHelper.MutedLabel("Define up to 3 packet templates. All enabled templates are sent");
            UiHelper.MutedLabel("concurrently on every burst cycle to maximise race condition exposure.");
            ImGui.Spacing();

            UiHelper.MutedLabel("Packet 1 (required):");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##bp1", ref _burstPkt1, 1024);
            RenderBookPicker("Load##bp1book", v => _burstPkt1 = v);

            ImGui.Spacing();
            ImGui.Checkbox("Packet 2##bpu2", ref _burstUsePkt2);
            ImGui.BeginDisabled(!_burstUsePkt2);
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##bp2", ref _burstPkt2, 1024);
            RenderBookPicker("Load##bp2book", v => _burstPkt2 = v);
            ImGui.EndDisabled();

            ImGui.Spacing();
            ImGui.Checkbox("Packet 3##bpu3", ref _burstUsePkt3);
            ImGui.BeginDisabled(!_burstUsePkt3);
            ImGui.SetNextItemWidth(-1); ImGui.InputText("##bp3", ref _burstPkt3, 1024);
            RenderBookPicker("Load##bp3book", v => _burstPkt3 = v);
            ImGui.EndDisabled();
        });

        ImGui.Spacing();

        // ── Burst config ──────────────────────────────────────────────────
        UiHelper.SectionBox("BURST CONFIG", half, 150, () =>
        {
            UiHelper.MutedLabel("Total sends per template:");
            ImGui.SetNextItemWidth(120); ImGui.InputInt("Count##brcnt", ref _burstCount);
            _burstCount = Math.Clamp(_burstCount, 1, 100_000);

            UiHelper.MutedLabel("Parallel threads:");
            ImGui.SetNextItemWidth(120); ImGui.InputInt("Threads##brth", ref _burstThreads);
            _burstThreads = Math.Clamp(_burstThreads, 1, 128);

            UiHelper.MutedLabel("Intra-burst delay (µs, 0 = full speed):");
            ImGui.SetNextItemWidth(120); ImGui.InputInt("Delay µs##brdly", ref _burstDelayUs);
            _burstDelayUs = Math.Max(0, _burstDelayUs);

            UiHelper.MutedLabel("Batch size per thread yield:");
            ImGui.SetNextItemWidth(120); ImGui.InputInt("Batch##brbatch", ref _burstBatchSize);
            _burstBatchSize = Math.Clamp(_burstBatchSize, 1, 1000);
        });

        ImGui.SameLine(0, 12);

        // ── Live telemetry ────────────────────────────────────────────────
        UiHelper.SectionBox("LIVE TELEMETRY", half, 150, () =>
        {
            if (_burstRunning || _burstSent > 0)
            {
                long elapsed = _burstRunning
                    ? (long)((DateTime.UtcNow.Ticks - _burstStartTicks) / (double)TimeSpan.TicksPerMillisecond)
                    : (long)((_burstEndTicks - _burstStartTicks) / (double)TimeSpan.TicksPerMillisecond);

                float pps = elapsed > 0 ? _burstSent / (elapsed / 1000f) : 0;

                UiHelper.StatusRow("Sent",   $"{_burstSent:N0}", true, 70);
                UiHelper.StatusRow("Errors", $"{_burstErrors:N0}", _burstErrors == 0, 70);
                UiHelper.StatusRow("Elapsed",$"{elapsed}ms", true, 70);
                UiHelper.StatusRow("Rate",   $"{pps:N0} pkt/s", true, 70);

                // Progress bar
                if (_burstRunning && _burstCount > 0)
                {
                    float progress = Math.Clamp((float)_burstSent / _burstCount, 0f, 1f);
                    ImGui.ProgressBar(progress, new Vector2(-1, 16), $"{progress*100:F0}%");
                }

                // Histogram
                ImGui.Spacing();
                UiHelper.MutedLabel("Send latency histogram:");
                int maxBucket = _burstBuckets.Max();
                for (int b = 0; b < _burstBuckets.Length; b++)
                {
                    float barW = maxBucket > 0 ? (_burstBuckets[b] / (float)maxBucket) * 140f : 0;
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                    ImGui.TextUnformatted($"  {BucketLabels[b],-12}");
                    ImGui.PopStyleColor();
                    ImGui.SameLine(0, 4);
                    ImGui.PushStyleColor(ImGuiCol.PlotHistogram, MenuRenderer.ColAccent);
                    ImGui.ProgressBar(_burstBuckets[b] / Math.Max(1f, maxBucket),
                        new Vector2(120, 12), "");
                    ImGui.PopStyleColor();
                    ImGui.SameLine(0, 6);
                    UiHelper.MutedLabel($"{_burstBuckets[b]}");
                }
            }
            else
            {
                UiHelper.MutedLabel("Telemetry appears here");
                UiHelper.MutedLabel("once a burst is running.");
            }
        });

        ImGui.Spacing();

        // ── Run / Stop ────────────────────────────────────────────────────
        if (_burstRunning)
        {
            UiHelper.DangerButton("STOP BURST##brstop", 140, 34, () =>
            {
                _burstCts?.Cancel();
                _burstRunning = false;
                _burstEndTicks = DateTime.UtcNow.Ticks;
                _log.Warn($"[Burst] Stopped — {_burstSent:N0} sent, {_burstErrors} errors.");
            });
            ImGui.SameLine(0, 12);
            UiHelper.WarnText("● BURST RUNNING — monitor server for state corruption...");
        }
        else
        {
            UiHelper.WarnButton("RUN BURST TEST##brrun", 180, 34, RunBurstTest);
            ImGui.SameLine(0, 12);
            if (_burstSent > 0)
            {
                UiHelper.SecondaryButton("Reset Stats##brreset", 110, 34, () =>
                {
                    _burstSent = _burstErrors = 0;
                    Array.Clear(_burstBuckets);
                    _burstStartTicks = _burstEndTicks = 0;
                });
            }
        }

        ImGui.Spacing();

        // ── Network Latency Emulator ──────────────────────────────────────
        UiHelper.SectionBox("NETWORK LATENCY EMULATOR  (Async Auth / SimpleClaims)", w, 210, () =>
        {
            UiHelper.MutedLabel("Tests whether server-side async permission plugins (e.g. SimpleClaims,");
            UiHelper.MutedLabel("LuckPerms async) can be bypassed during their propagation delay.");
            UiHelper.MutedLabel("Workflow: send an innocuous 'open' packet, sleep for PropDelay ms");
            UiHelper.MutedLabel("(simulating network RTT to the auth plugin), then race the state-change.");
            ImGui.Spacing();

            ImGui.Checkbox("Enable Latency Emulator##laten", ref _latencyEnabled);
            if (!_latencyEnabled)
            {
                UiHelper.MutedLabel("Enable to configure and add latency stages below.");
                return;
            }

            ImGui.Spacing();

            float hw = (w - 18) / 3f;

            // Stage 1 — trigger packet (container open / permission check initiator)
            UiHelper.SectionBox("STAGE 1 — TRIGGER", hw, 100, () =>
            {
                UiHelper.MutedLabel("Initiates async auth check.");
                ImGui.SetNextItemWidth(-1); ImGui.InputText("##lts1", ref _latStage1Hex, 512);
                RenderBookPicker("Load##ls1bk", v => _latStage1Hex = v);
            });
            ImGui.SameLine(0, 6);

            // Propagation delay
            UiHelper.SectionBox("PROPAGATION DELAY", hw, 100, () =>
            {
                UiHelper.MutedLabel("Simulated plugin RTT (ms):");
                ImGui.SetNextItemWidth(-1); ImGui.InputInt("##ltpd", ref _latPropDelayMs);
                _latPropDelayMs = Math.Clamp(_latPropDelayMs, 0, 30_000);
                ImGui.Spacing();
                ImGui.SetNextItemWidth(-1); ImGui.InputInt("Jitter ±ms##ltjit", ref _latJitterMs);
                _latJitterMs = Math.Max(0, _latJitterMs);
            });
            ImGui.SameLine(0, 6);

            // Stage 2 — state-change packet (the privileged action)
            UiHelper.SectionBox("STAGE 2 — EXPLOIT", hw, 100, () =>
            {
                UiHelper.MutedLabel("Action during auth gap.");
                ImGui.SetNextItemWidth(-1); ImGui.InputText("##lts2", ref _latStage2Hex, 512);
                RenderBookPicker("Load##ls2bk", v => _latStage2Hex = v);
            });

            ImGui.Spacing();

            ImGui.SetNextItemWidth(90); ImGui.InputInt("Repeat count##ltrc", ref _latRepeat);
            _latRepeat = Math.Clamp(_latRepeat, 1, 200);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(90); ImGui.InputInt("Stage2 burst##ltburst", ref _latStage2Burst);
            _latStage2Burst = Math.Clamp(_latStage2Burst, 1, 100);
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("Send Stage 2 this many times within the prop-delay window");
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(90); ImGui.InputInt("Cooldown ms##ltcool", ref _latCooldownMs);
            _latCooldownMs = Math.Max(0, _latCooldownMs);

            ImGui.Spacing();
            if (_latRunning)
            {
                UiHelper.DangerButton("STOP##latstop", 100, 28, () =>
                {
                    _latCts?.Cancel(); _latRunning = false;
                    _log.Warn("[Latency] Emulator stopped.");
                });
                ImGui.SameLine(0, 8);
                UiHelper.WarnText($"● Iteration {_latIteration}/{_latRepeat}  —  stage {_latStage}");
            }
            else
            {
                UiHelper.WarnButton("RUN LATENCY EMULATOR##latrun", 200, 28, RunLatencyEmulator);
                ImGui.SameLine(0, 8);
                UiHelper.MutedLabel("Send Stage1 → wait PropDelay → burst Stage2 × N");
            }
        });

        ImGui.Spacing();
        RenderHowTo(
            "Burst Test: capture a state-changing packet, paste into Packet 1, set Count+Threads, click Run",
            "  → Watch for: duplicate items, negative balances, state desync under load",
            "Latency Emulator: enable it, paste the 'container open' packet into Stage 1",
            "  → Set PropDelay to the measured RTT of the auth plugin (e.g. 80ms for SimpleClaims)",
            "  → Paste the privileged action (e.g. container move) into Stage 2, burst=10",
            "  → Run: tool sends Stage1, waits PropDelay±jitter, then floods Stage2",
            "  → If Stage2 succeeds during the async gap → Async Auth bypass documented",
            "  → Increase burst count or reduce jitter to maximise window coverage"
        );
    }

    private void RunBurstTest()
    {
        if (string.IsNullOrWhiteSpace(_burstPkt1))
        { _log.Error("[Burst] Packet 1 is required."); return; }

        if (!TryParseHex(_burstPkt1, out byte[]? p1) || p1 == null)
        { _log.Error("[Burst] Invalid hex in Packet 1."); return; }

        byte[]? p2 = null, p3 = null;
        if (_burstUsePkt2 && !string.IsNullOrWhiteSpace(_burstPkt2))
            if (!TryParseHex(_burstPkt2, out p2)) { _log.Error("[Burst] Invalid hex in Packet 2."); return; }
        if (_burstUsePkt3 && !string.IsNullOrWhiteSpace(_burstPkt3))
            if (!TryParseHex(_burstPkt3, out p3)) { _log.Error("[Burst] Invalid hex in Packet 3."); return; }

        // Build the send list (interleaved templates for maximum overlap)
        var templates = new List<byte[]> { p1! };
        if (p2 != null) templates.Add(p2);
        if (p3 != null) templates.Add(p3);

        _burstRunning    = true;
        _burstSent       = 0;
        _burstErrors     = 0;
        _burstStartTicks = DateTime.UtcNow.Ticks;
        _burstEndTicks   = 0;
        Array.Clear(_burstBuckets);

        _burstCts = new CancellationTokenSource();
        var cts         = _burstCts;
        int count       = _burstCount;
        int threads     = _burstThreads;
        int delayUs     = _burstDelayUs;
        int batchSize   = _burstBatchSize;

        _log.Info($"[Burst] Starting — {count} × {templates.Count} template(s), " +
                  $"{threads} threads, {delayUs}µs inter-send delay.");

        Task.Run(() =>
        {
            int perThread = (count + threads - 1) / threads;

            Parallel.For(0, threads, new ParallelOptions
            {
                MaxDegreeOfParallelism = threads,
                CancellationToken      = cts.Token,
            },
            threadIdx =>
            {
                int myCount = Math.Min(perThread, count - threadIdx * perThread);
                if (myCount <= 0) return;

                int batch = 0;
                for (int i = 0; i < myCount && !cts.Token.IsCancellationRequested; i++)
                {
                    // Interleave all templates on each iteration
                    foreach (var tmpl in templates)
                    {
                        var t0 = System.Diagnostics.Stopwatch.GetTimestamp();
                        try
                        {
                            SendRaw(tmpl);
                            Interlocked.Increment(ref _burstSent);
                        }
                        catch
                        {
                            Interlocked.Increment(ref _burstErrors);
                        }
                        long elapsedUs = (System.Diagnostics.Stopwatch.GetTimestamp() - t0)
                                       * 1_000_000L / System.Diagnostics.Stopwatch.Frequency;

                        // Bucket the send latency
                        int bucket = elapsedUs < 1   ? 0
                                   : elapsedUs < 5   ? 1
                                   : elapsedUs < 20  ? 2
                                   : elapsedUs < 100 ? 3
                                   : elapsedUs < 500 ? 4
                                   :                   5;
                        Interlocked.Increment(ref _burstBuckets[bucket]);
                    }

                    if (delayUs > 0)
                        Thread.SpinWait(delayUs * 30); // ~1µs per 30 spins on modern hardware

                    if (++batch >= batchSize)
                    {
                        batch = 0;
                        Thread.Yield();
                    }
                }
            });

            _burstRunning  = false;
            _burstEndTicks = DateTime.UtcNow.Ticks;
            long ms = (_burstEndTicks - _burstStartTicks) / TimeSpan.TicksPerMillisecond;
            _log.Success($"[Burst] Complete — {_burstSent:N0} sent, {_burstErrors} errors, " +
                         $"{ms}ms elapsed ({(_burstSent / Math.Max(1.0, ms / 1000.0)):N0} pkt/s).");
        });
    }

    private void RunLatencyEmulator()
    {
        if (string.IsNullOrWhiteSpace(_latStage1Hex))
        { _log.Error("[Latency] Stage 1 packet is required."); return; }
        if (string.IsNullOrWhiteSpace(_latStage2Hex))
        { _log.Error("[Latency] Stage 2 packet is required."); return; }

        if (!TryParseHex(_latStage1Hex, out byte[]? s1) || s1 == null)
        { _log.Error("[Latency] Invalid hex in Stage 1."); return; }
        if (!TryParseHex(_latStage2Hex, out byte[]? s2) || s2 == null)
        { _log.Error("[Latency] Invalid hex in Stage 2."); return; }

        _latRunning   = true;
        _latIteration = 0;
        _latStage     = 0;
        _latCts       = new CancellationTokenSource();
        var cts       = _latCts;

        int repeat     = _latRepeat;
        int propDelay  = _latPropDelayMs;
        int jitter     = _latJitterMs;
        int burst      = _latStage2Burst;
        int cooldown   = _latCooldownMs;

        _log.Info($"[Latency] Starting async-auth emulator — " +
                  $"{repeat} cycles, PropDelay={propDelay}±{jitter}ms, Stage2×{burst}");

        Task.Run(async () =>
        {
            int success = 0, error = 0;

            for (int i = 0; i < repeat && !cts.Token.IsCancellationRequested; i++)
            {
                _latIteration = i + 1;

                // ── Stage 1: send trigger (initiates async auth check) ────
                _latStage = 1;
                try { SendRaw(s1!); }
                catch { error++; }

                _log.Info($"[Latency] Cycle {i+1}/{repeat} — Stage 1 sent, waiting {propDelay}±{jitter}ms");

                // ── Propagation delay with jitter ─────────────────────────
                int delay = jitter > 0
                    ? propDelay + Random.Shared.Next(-jitter, jitter)
                    : propDelay;
                delay = Math.Max(0, delay);
                await Task.Delay(delay, cts.Token).ContinueWith(_ => { });

                if (cts.Token.IsCancellationRequested) break;

                // ── Stage 2: burst the exploit packet during the auth gap ─
                _latStage = 2;
                int sentThisCycle = 0;
                for (int b = 0; b < burst && !cts.Token.IsCancellationRequested; b++)
                {
                    try { SendRaw(s2!); sentThisCycle++; success++; }
                    catch { error++; }
                }
                _log.Info($"[Latency] Cycle {i+1} — Stage 2 ×{sentThisCycle} sent during gap.");

                // ── Cooldown between cycles ────────────────────────────────
                if (cooldown > 0 && i < repeat - 1)
                    await Task.Delay(cooldown, cts.Token).ContinueWith(_ => { });
            }

            _latRunning = false;
            _latStage   = 0;
            _log.Success($"[Latency] Complete — {repeat} cycles, Stage2 sent {success}× " +
                         $"({error} errors). Check server for auth bypass evidence.");
        });
    }

    private void RenderBookPicker(string label, Action<string> onSelect)
    {
        var saved = _store.GetAll();
        if (saved.Count == 0) return;
        if (ImGui.BeginCombo(label, ""))
        {
            foreach (var s in saved)
            {
                if (ImGui.Selectable(s.Label)) onSelect(s.HexString);
                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip(s.Notes.Length > 0 ? s.Notes : s.HexString[..Math.Min(40, s.HexString.Length)]);
            }
            ImGui.EndCombo();
        }
    }

    private void RenderHowTo(params string[] steps)
    {
        float w = ImGui.GetContentRegionAvail().X;
        UiHelper.SectionBox("HOW TO USE", w, 40 + steps.Length * 22, () =>
        { foreach (var s in steps) UiHelper.MutedLabel(s); });
    }

    private bool TryParseHex(string hex, out byte[]? data)
    {
        data = null;
        try
        {
            string clean = hex.Replace(" ", "").Replace("\n", "");
            if (clean.Length % 2 != 0) clean += "0";
            data = Convert.FromHexString(clean);
            return true;
        }
        catch { return false; }
    }

    private void SendRaw(byte[] data)
    {
        if (_udpProxy.IsRunning && _udpProxy.InjectToServer(data)) return;
        if (_capture.InjectToServer(data).GetAwaiter().GetResult()) return;
        try
        {
            using var udp = new UdpClient();
            udp.Connect(_config.ServerIp, _config.ServerPort);
            udp.Send(data, data.Length);
        }
        catch (Exception ex) { _log.Error($"[Dupe] Send: {ex.Message}"); }
    }
}
