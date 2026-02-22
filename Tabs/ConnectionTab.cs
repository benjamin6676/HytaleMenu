using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

public class ConnectionTab : ITab
{
    public string Title => "  Connection  ";

    private readonly TestLog      _log;
    private readonly ServerConfig _config;

    private bool   _handshakeTamper = true;
    private bool   _authBypass      = true;
    private bool   _sessionHijack   = false;
    private bool   _timeoutTest     = true;
    private int    _fakeSessionId   = 99999;
    private string _fakeToken       = "aaaabbbbccccdddd";
    private int    _timeoutMs       = 30000;

    public ConnectionTab(TestLog log, ServerConfig config)
    {
        _log = log; _config = config;
    }

    public void Render()
    {
        float w    = ImGui.GetContentRegionAvail().X;
        float half = (w - 12) * 0.5f;

        UiHelper.SectionBox("TEST SELECTION", half, 200, RenderTestSelection);
        ImGui.SameLine(0, 12);
        UiHelper.SectionBox("PARAMETERS",     half, 200, RenderParameters);

        ImGui.Spacing(); ImGui.Spacing();

        UiHelper.SectionBox("RUN", w, 80, RenderRun);
    }

    private void RenderTestSelection()
    {
        UiHelper.MutedLabel("Select connection tests to run:");
        ImGui.Spacing();
        ImGui.Checkbox("Handshake Tampering##ht", ref _handshakeTamper);
        ImGui.Checkbox("Auth Bypass Test##ab",     ref _authBypass);
        ImGui.Checkbox("Session Hijack##sh",       ref _sessionHijack);
        ImGui.Checkbox("Timeout Behavior##tb",     ref _timeoutTest);
    }

    private void RenderParameters()
    {
        UiHelper.MutedLabel("Test parameters:");
        ImGui.Spacing();
        ImGui.SetNextItemWidth(150);
        ImGui.InputInt("Fake Session ID##fs", ref _fakeSessionId);
        ImGui.SetNextItemWidth(-1);
        ImGui.InputText("Fake Token##ft", ref _fakeToken, 128);
        ImGui.SetNextItemWidth(110);
        ImGui.InputInt("Timeout ms##to", ref _timeoutMs);
        _timeoutMs = Math.Clamp(_timeoutMs, 100, 120000);
    }

    private void RenderRun()
    {
        UiHelper.WarnButton("Run Connection Tests", 200, 34, () =>
        {
            if (!_config.IsSet)
            { _log.Error("[Conn] No server set — go to Dashboard first."); return; }

            _log.Info($"[Conn] Testing {_config.ServerIp}:{_config.ServerPort}");
            if (_handshakeTamper) _log.Warn("[Conn] Handshake tamper — stub");
            if (_authBypass)      _log.Warn("[Conn] Auth bypass — stub");
            if (_sessionHijack)   _log.Warn($"[Conn] Hijack session {_fakeSessionId} — stub");
            if (_timeoutTest)     _log.Warn($"[Conn] Timeout {_timeoutMs}ms — stub");
            _log.Success("[Conn] Tests dispatched.");
        });

        ImGui.SameLine(0, 12);
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(
            _config.IsSet
                ? $"→ {_config.ServerIp}:{_config.ServerPort}"
                : "Set server in Dashboard first");
        ImGui.PopStyleColor();
    }
}
