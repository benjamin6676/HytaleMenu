using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Text;
using System;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Packet-level security tests — malformed packets, replay attacks, flood tests, etc.
/// </summary>
public class PacketTab : ITab
{
    public string Title => "  Packets  ";

    private readonly TestLog _log;

    // Malformed packet
    private int    _packetId       = 0x00;
    private string _payloadHex     = "DEADBEEF00FF";
    private bool   _randomizeSize  = false;
    private int    _payloadLen     = 64;

    // Replay attack
    private string _capturedPacket = "";
    private int    _replayCount    = 50;
    private int    _replayDelayMs  = 10;

    // Flood test
    private int    _floodCount     = 500;
    private int    _floodPacketId  = 0x10;
    private bool   _floodRunning   = false;

    // Sequence manipulation
    private bool   _outOfOrder     = false;
    private bool   _duplicateSeq   = false;
    private int    _seqOffset      = -1;

    public PacketTab(TestLog log) => _log = log;

    public void Render()
    {
        if (ImGui.BeginTabBar("##PacketSubTabs"))
        {
            if (ImGui.BeginTabItem("Malformed Packets"))
            {
                RenderMalformed();
                ImGui.EndTabItem();
            }
            if (ImGui.BeginTabItem("Replay Attack"))
            {
                RenderReplay();
                ImGui.EndTabItem();
            }
            if (ImGui.BeginTabItem("Flood / Rate Limit"))
            {
                RenderFlood();
                ImGui.EndTabItem();
            }
            if (ImGui.BeginTabItem("Sequence Manipulation"))
            {
                RenderSequence();
                ImGui.EndTabItem();
            }
            ImGui.EndTabBar();
        }
    }

    // ── Malformed packets ─────────────────────────────────────────────────
    private void RenderMalformed()
    {
        ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.3f, 0.9f, 0.5f, 1f), "Malformed Packet Sender");
        ImGui.TextDisabled("Send crafted packets with invalid fields to probe server validation.");
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.SetNextItemWidth(120);
        ImGui.InputInt("Packet ID (hex)##pid", ref _packetId);
        _packetId = Math.Clamp(_packetId, 0, 0xFFFF);

        ImGui.SetNextItemWidth(300);
        ImGui.InputText("Payload (hex)##pay", ref _payloadHex, 512);
        ImGui.SameLine();
        if (ImGui.Button("Random##randpay"))
            _payloadHex = GenerateRandomHex(16);

        ImGui.Checkbox("Randomize payload size", ref _randomizeSize);
        if (!_randomizeSize)
        {
            ImGui.SameLine();
            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("Bytes##plen", ref _payloadLen);
            _payloadLen = Math.Clamp(_payloadLen, 1, 65535);
        }

        ImGui.Spacing();

        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.2f, 0.0f, 1f));
        if (ImGui.Button("Send Malformed Packet", new Vector2(220, 32)))
            SimulateMalformedSend();
        ImGui.PopStyleColor();

        ImGui.SameLine();

        if (ImGui.Button("Send Oversized Packet", new Vector2(200, 32)))
            SimulateOversizedSend();

        ImGui.Spacing();
        ImGui.TextDisabled("Tests: invalid length header, wrong field types, oversized payloads.");
    }

    private void SimulateMalformedSend()
    {
        string hex = string.IsNullOrWhiteSpace(_payloadHex) ? "00" : _payloadHex;
        _log.Info($"[Malformed] Sending packet ID=0x{_packetId:X4} payload={hex}");
        // TODO: replace with real socket send when connected
        _log.Warn("[Malformed] Stub — replace with actual TCP/UDP send logic");
        _log.Success("[Malformed] Test dispatched. Monitor server logs for errors.");
    }

    private void SimulateOversizedSend()
    {
        int size = 1024 * 1024; // 1 MB
        _log.Info($"[Oversized] Sending {size / 1024} KB packet to test buffer handling");
        _log.Warn("[Oversized] Stub — replace with actual socket send logic");
    }

    // ── Replay attack ─────────────────────────────────────────────────────
    private void RenderReplay()
    {
        ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.3f, 0.9f, 0.5f, 1f), "Packet Replay Attack");
        ImGui.TextDisabled("Re-send a captured packet multiple times to test replay protection.");
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.SetNextItemWidth(400);
        ImGui.InputText("Captured Packet (hex)##cap", ref _capturedPacket, 2048);
        ImGui.SameLine();
        if (ImGui.Button("Paste Example##ex"))
            _capturedPacket = "01 00 00 00 FF A0 3C 10 00 00 00 00 00 00 00 01";

        ImGui.SetNextItemWidth(120);
        ImGui.InputInt("Replay Count##rc", ref _replayCount);
        _replayCount = Math.Clamp(_replayCount, 1, 10000);

        ImGui.SetNextItemWidth(120);
        ImGui.InputInt("Delay (ms)##rdel", ref _replayDelayMs);
        _replayDelayMs = Math.Clamp(_replayDelayMs, 0, 5000);

        ImGui.Spacing();

        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.2f, 0.0f, 1f));
        if (ImGui.Button("Start Replay", new Vector2(160, 32)))
        {
            if (string.IsNullOrWhiteSpace(_capturedPacket))
                _log.Error("[Replay] No packet data provided.");
            else
                SimulateReplay();
        }
        ImGui.PopStyleColor();

        ImGui.Spacing();
        ImGui.TextDisabled("Check server for: item duplication, currency changes, position resets.");
    }

    private void SimulateReplay()
    {
        _log.Info($"[Replay] Replaying packet {_replayCount}x with {_replayDelayMs}ms interval");
        _log.Info($"[Replay] Data: {_capturedPacket[..Math.Min(40, _capturedPacket.Length)]}...");
        _log.Warn("[Replay] Stub — connect real packet replay logic here");
    }

    // ── Flood test ────────────────────────────────────────────────────────
    private void RenderFlood()
    {
        ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.3f, 0.9f, 0.5f, 1f), "Packet Flood / Rate Limit Test");
        ImGui.TextDisabled("Rapidly send packets to test server rate limiting and DoS protection.");
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.SetNextItemWidth(120);
        ImGui.InputInt("Packet ID##fid", ref _floodPacketId);

        ImGui.SetNextItemWidth(120);
        ImGui.InputInt("Packet Count##fc", ref _floodCount);
        _floodCount = Math.Clamp(_floodCount, 1, 100_000);

        ImGui.Spacing();

        if (_floodRunning)
        {
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.1f, 0.1f, 1f));
            if (ImGui.Button("Stop Flood", new Vector2(140, 32)))
            {
                _floodRunning = false;
                _log.Warn("[Flood] Test stopped by user.");
            }
            ImGui.PopStyleColor();
            ImGui.SameLine();
            ImGui.TextColored(new Vector4(0.9f, 0.5f, 0.1f, 1f), "Running...");
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.2f, 0.0f, 1f));
            if (ImGui.Button("Start Flood", new Vector2(140, 32)))
            {
                _floodRunning = true;
                _log.Info($"[Flood] Sending {_floodCount} packets (ID=0x{_floodPacketId:X4})");
                _log.Warn("[Flood] Stub — wire up actual async send logic here");
                // Immediately stop stub after logging
                _floodRunning = false;
            }
            ImGui.PopStyleColor();
        }

        ImGui.Spacing();
        ImGui.TextDisabled("Expected behavior: server should throttle/kick after threshold.");
    }

    // ── Sequence manipulation ─────────────────────────────────────────────
    private void RenderSequence()
    {
        ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.3f, 0.9f, 0.5f, 1f), "Sequence Number Manipulation");
        ImGui.TextDisabled("Test how the server handles out-of-order or duplicated sequence IDs.");
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.Checkbox("Send out-of-order packets", ref _outOfOrder);
        ImGui.Checkbox("Send duplicate sequence numbers", ref _duplicateSeq);

        ImGui.SetNextItemWidth(100);
        ImGui.InputInt("Sequence offset##seqoff", ref _seqOffset);

        ImGui.Spacing();

        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.2f, 0.0f, 1f));
        if (ImGui.Button("Run Sequence Test", new Vector2(200, 32)))
        {
            _log.Info($"[SeqTest] OutOfOrder={_outOfOrder} Duplicate={_duplicateSeq} Offset={_seqOffset}");
            _log.Warn("[SeqTest] Stub — connect actual sequence manipulation logic here");
            _log.Success("[SeqTest] Test dispatched.");
        }
        ImGui.PopStyleColor();

        ImGui.Spacing();
        ImGui.TextDisabled("Watch for: items appearing twice, inventory desyncs, rollback failures.");
    }

    // ── Helpers ───────────────────────────────────────────────────────────
    private static string GenerateRandomHex(int bytes)
    {
        var rng = new Random();
        var sb  = new StringBuilder();
        for (int i = 0; i < bytes; i++)
            sb.AppendFormat("{0:X2}", rng.Next(256));
        return sb.ToString();
    }
}
