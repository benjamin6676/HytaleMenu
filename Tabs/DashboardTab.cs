using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Overview dashboard — connection status, quick-launch buttons.
/// </summary>
public class DashboardTab : ITab
{
    public string Title => "  Dashboard  ";

    private readonly TestLog _log;
    private string _serverIp   = "127.0.0.1";
    private int    _serverPort = 25565;
    private bool   _connected  = false;

    public DashboardTab(TestLog log) => _log = log;

    public void Render()
    {
        // ── Connection panel ──────────────────────────────────────────────
        ImGui.BeginChild("##dashboard_conn", new Vector2(340, 130), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.3f, 0.9f, 0.5f, 1f), "Server Connection");
        ImGui.Separator();

        ImGui.SetNextItemWidth(200);
        ImGui.InputText("IP##ip", ref _serverIp, 128);

        ImGui.SetNextItemWidth(100);
        ImGui.InputInt("Port##port", ref _serverPort);

        ImGui.Spacing();

        if (_connected)
        {
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.1f, 0.1f, 1f));
            if (ImGui.Button("Disconnect", new Vector2(120, 28)))
            {
                _connected = false;
                _log.Warn($"Disconnected from {_serverIp}:{_serverPort}");
            }
            ImGui.PopStyleColor();
        }
        else
        {
            if (ImGui.Button("Connect", new Vector2(120, 28)))
            {
                _connected = true;
                _log.Success($"Connected to {_serverIp}:{_serverPort}");
            }
        }

        ImGui.SameLine();
        ImGui.TextColored(
            _connected
                ? new Vector4(0.2f, 0.9f, 0.3f, 1f)
                : new Vector4(0.8f, 0.3f, 0.2f, 1f),
            _connected ? "● Connected" : "● Disconnected"
        );

        ImGui.EndChild();

        ImGui.SameLine();

        // ── Info panel ────────────────────────────────────────────────────
        ImGui.BeginChild("##dashboard_info", new Vector2(0, 130), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.3f, 0.9f, 0.5f, 1f), "About");
        ImGui.Separator();
        ImGui.TextWrapped(
            "This tool is designed for authorized security research against " +
            "Hytale server infrastructure. Use only on servers you own or " +
            "have explicit written permission to test."
        );
        ImGui.EndChild();

        ImGui.Spacing();

        // ── Quick actions ─────────────────────────────────────────────────
        ImGui.TextDisabled("Quick Actions");
        ImGui.Separator();

        if (ImGui.Button("Run All Tests", new Vector2(160, 34)))
        {
            _log.Info("--- Running all test suites ---");
            _log.Warn("Not implemented yet — run tests individually per tab.");
        }

        ImGui.SameLine();

        if (ImGui.Button("Clear Logs", new Vector2(120, 34)))
        {
            _log.Clear();
            _log.Info("Log cleared.");
        }
    }
}
