using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Tests targeting item/currency duplication vulnerabilities.
/// </summary>
public class DupingTab : ITab
{
    public string Title => "  Duping Tests  ";

    private readonly TestLog _log;

    // Item dupe
    private int    _itemId         = 1001;
    private int    _itemCount      = 1;
    private bool   _dropDupe       = true;
    private bool   _tradeDupe      = false;
    private bool   _containerDupe  = false;

    // Transaction race
    private int    _raceThreads    = 4;
    private int    _raceIterations = 10;

    // Rollback test
    private bool   _simulateDrop   = true;
    private bool   _simulateTrade  = false;

    public DupingTab(TestLog log) => _log = log;

    public void Render()
    {
        ImGui.Spacing();

        // ── Item dupe methods ─────────────────────────────────────────────
        ImGui.BeginChild("##dupe_left", new Vector2(ImGui.GetContentRegionAvail().X * 0.5f - 6, 0), ImGuiChildFlags.None);

        ImGui.TextColored(new Vector4(0.3f, 0.9f, 0.5f, 1f), "Item Duplication Vectors");
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.SetNextItemWidth(130);
        ImGui.InputInt("Item ID##iid", ref _itemId);

        ImGui.SetNextItemWidth(100);
        ImGui.InputInt("Stack Size##icount", ref _itemCount);
        _itemCount = Math.Max(1, _itemCount);

        ImGui.Spacing();
        ImGui.TextDisabled("Test vectors:");
        ImGui.Checkbox("Drop-pickup race condition", ref _dropDupe);
        ImGui.Checkbox("Trade window exploit", ref _tradeDupe);
        ImGui.Checkbox("Container transfer exploit", ref _containerDupe);

        ImGui.Spacing();

        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.15f, 0.0f, 1f));
        if (ImGui.Button("Run Selected Dupe Tests", new Vector2(220, 32)))
            RunDupeTests();
        ImGui.PopStyleColor();

        ImGui.Spacing();
        ImGui.TextDisabled("Expected: server rejects all duplicate item states.");

        ImGui.EndChild();

        ImGui.SameLine();

        // ── Race condition / rollback ─────────────────────────────────────
        ImGui.BeginChild("##dupe_right", new Vector2(0, 0), ImGuiChildFlags.None);

        ImGui.TextColored(new Vector4(0.3f, 0.9f, 0.5f, 1f), "Transaction Race Condition");
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.TextWrapped("Simultaneously send conflicting transactions to test atomicity.");
        ImGui.Spacing();

        ImGui.SetNextItemWidth(120);
        ImGui.InputInt("Threads##rthrd", ref _raceThreads);
        _raceThreads = Math.Clamp(_raceThreads, 1, 32);

        ImGui.SetNextItemWidth(120);
        ImGui.InputInt("Iterations##riter", ref _raceIterations);
        _raceIterations = Math.Clamp(_raceIterations, 1, 1000);

        ImGui.Spacing();

        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.15f, 0.0f, 1f));
        if (ImGui.Button("Run Race Condition Test", new Vector2(220, 32)))
        {
            _log.Info($"[Race] {_raceThreads} threads x {_raceIterations} iterations on item {_itemId}");
            _log.Warn("[Race] Stub — implement parallel HttpClient/socket sends here");
        }
        ImGui.PopStyleColor();

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.TextColored(new Vector4(0.3f, 0.9f, 0.5f, 1f), "Server Rollback Test");
        ImGui.Separator();
        ImGui.Spacing();
        ImGui.TextWrapped("Force a disconnect mid-transaction to verify item state is rolled back.");
        ImGui.Checkbox("Simulate mid-drop disconnect##sdd", ref _simulateDrop);
        ImGui.Checkbox("Simulate mid-trade disconnect##std", ref _simulateTrade);

        ImGui.Spacing();

        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.15f, 0.0f, 1f));
        if (ImGui.Button("Run Rollback Test", new Vector2(200, 32)))
        {
            _log.Info($"[Rollback] Drop={_simulateDrop} Trade={_simulateTrade}");
            _log.Warn("[Rollback] Stub — implement forced disconnect mid-packet here");
            _log.Success("[Rollback] Test queued.");
        }
        ImGui.PopStyleColor();

        ImGui.EndChild();
    }

    private void RunDupeTests()
    {
        if (!_dropDupe && !_tradeDupe && !_containerDupe)
        {
            _log.Warn("[Dupe] No test vectors selected!");
            return;
        }

        _log.Info($"[Dupe] Starting tests on item {_itemId} x{_itemCount}");

        if (_dropDupe)
        {
            _log.Info("[Dupe] Running drop-pickup race...");
            _log.Warn("[Dupe] Drop dupe: stub — send Pick Up + Drop simultaneously");
        }
        if (_tradeDupe)
        {
            _log.Info("[Dupe] Running trade window exploit...");
            _log.Warn("[Dupe] Trade dupe: stub — send Accept + Cancel simultaneously");
        }
        if (_containerDupe)
        {
            _log.Info("[Dupe] Running container transfer exploit...");
            _log.Warn("[Dupe] Container dupe: stub — double-send MoveItem packet");
        }

        _log.Success("[Dupe] All selected tests dispatched. Check server item state.");
    }
}
