using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Tests connection-level security: auth bypass, handshake tampering, timeout handling.
/// </summary>
public class ConnectionTab : ITab
{
    public string Title => "  Connection  ";

    private readonly TestLog _log;

    private bool   _testHandshakeTamper = true;
    private bool   _testAuthBypass      = true;
    private bool   _testSessionHijack   = false;
    private bool   _testTimeoutBehavior = true;
    private int    _fakeSessionId       = 99999;
    private string _fakeToken           = "aaaabbbbccccdddd";
    private int    _timeoutMs           = 30000;

    public ConnectionTab(TestLog log) => _log = log;

    public void Render()
    {
        ImGui.Spacing();

        ImGui.TextColored(new Vector4(0.3f, 0.9f, 0.5f, 1f), "Connection Security Tests");
        ImGui.TextDisabled("Test handshake, auth, and session handling for security flaws.");
        ImGui.Separator();
        ImGui.Spacing();

        // Left pane — options
        ImGui.BeginChild("##conn_left", new Vector2(300, 220), ImGuiChildFlags.Borders);
        ImGui.TextDisabled("Test Selection");
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.Checkbox("Handshake Tampering##ht", ref _testHandshakeTamper);
        ImGui.TextDisabled("  Send modified handshake fields.");
        ImGui.Spacing();

        ImGui.Checkbox("Auth Bypass Attempt##ab", ref _testAuthBypass);
        ImGui.TextDisabled("  Send fake/empty credentials.");
        ImGui.Spacing();

        ImGui.Checkbox("Session Hijack##sh", ref _testSessionHijack);
        ImGui.TextDisabled("  Reuse an expired session token.");
        ImGui.Spacing();

        ImGui.Checkbox("Timeout Behavior##tb", ref _testTimeoutBehavior);
        ImGui.TextDisabled("  Send no data and observe timeout.");

        ImGui.EndChild();

        ImGui.SameLine();

        // Right pane — params
        ImGui.BeginChild("##conn_right", new Vector2(0, 220), ImGuiChildFlags.Borders);
        ImGui.TextDisabled("Parameters");
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.SetNextItemWidth(150);
        ImGui.InputInt("Fake Session ID##fsid", ref _fakeSessionId);

        ImGui.SetNextItemWidth(250);
        ImGui.InputText("Fake Auth Token##fat", ref _fakeToken, 128);

        ImGui.SetNextItemWidth(120);
        ImGui.InputInt("Timeout (ms)##to", ref _timeoutMs);
        _timeoutMs = Math.Clamp(_timeoutMs, 100, 120000);

        ImGui.EndChild();

        ImGui.Spacing();

        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.15f, 0.0f, 1f));
        if (ImGui.Button("Run Connection Tests", new Vector2(220, 34)))
            RunConnectionTests();
        ImGui.PopStyleColor();
    }

    private void RunConnectionTests()
    {
        _log.Info("[Conn] Starting connection security tests...");

        if (_testHandshakeTamper)
        {
            _log.Info("[Conn] Handshake Tamper: sending modified protocol version...");
            _log.Warn("[Conn] Stub — modify handshake packet bytes before send");
        }

        if (_testAuthBypass)
        {
            _log.Info("[Conn] Auth Bypass: sending blank credentials...");
            _log.Warn("[Conn] Stub — send empty/null auth packet");
        }

        if (_testSessionHijack)
        {
            _log.Info($"[Conn] Session Hijack: using fake session {_fakeSessionId} / token {_fakeToken[..Math.Min(8, _fakeToken.Length)]}...");
            _log.Warn("[Conn] Stub — replay old session tokens here");
        }

        if (_testTimeoutBehavior)
        {
            _log.Info($"[Conn] Timeout Test: connect and wait {_timeoutMs}ms without sending data");
            _log.Warn("[Conn] Stub — open TCP socket, send nothing, measure disconnect time");
        }

        _log.Success("[Conn] Tests dispatched. Review server logs for auth errors / crashes.");
    }
}
