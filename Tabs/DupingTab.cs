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
        { "Drop Race", "Trade Race", "Container Race", "Replay", "Rollback", "Timing Sweep" };

    public DupingTab(TestLog log, UdpProxy udpProxy, PacketCapture capture,
                     PacketStore store, ServerConfig config)
    {
        _log = log; _udpProxy = udpProxy; _capture = capture;
        _store = store; _config = config;
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
        UiHelper.SectionBox("TARGET ITEM", w, 65, () =>
        {
            ImGui.SetNextItemWidth(130); ImGui.InputInt("Item ID##dit", ref _itemId);
            _itemId = Math.Max(1, _itemId);
            ImGui.SameLine(0, 16);
            ImGui.SetNextItemWidth(100); ImGui.InputInt("Stack##dic", ref _itemCount);
            _itemCount = Math.Max(1, _itemCount);
            ImGui.SameLine(0, 16);
            UiHelper.MutedLabel("← from Item Inspector or enter manually");
        });
    }

    private void RenderSubTabBar()
    {
        for (int i = 0; i < SubTabs.Length; i++)
        {
            bool sel = _subTab == i;
            ImGui.PushStyleColor(ImGuiCol.Button,
                sel ? new Vector4(0.18f, 0.95f, 0.45f, 0.22f) : MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text,
                sel ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
            if (ImGui.Button(SubTabs[i] + $"##dst{i}", new Vector2(130, 28))) _subTab = i;
            ImGui.PopStyleColor(2);
            if (i < SubTabs.Length - 1) ImGui.SameLine(0, 4);
        }
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
        UiHelper.SectionBox("RACE CONFIG + RUN", w, 120, () =>
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
        UiHelper.SectionBox("RUN", w, 100, () =>
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
        UiHelper.SectionBox("RUN", w, 95, () =>
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
        UiHelper.SectionBox("RUN", w, 95, () =>
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
        UiHelper.SectionBox("RUN", w, 75, () =>
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
        UiHelper.SectionBox("SWEEP CONFIG + RUN", w, 100, () =>
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
        UiHelper.SectionBox("HOW TO USE", w, 30 + steps.Length * 18, () =>
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
