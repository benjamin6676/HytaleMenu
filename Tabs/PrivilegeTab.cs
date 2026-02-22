using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;
using System.Text;
using System.Net.Sockets;

namespace HytaleSecurityTester.Tabs;

public class PrivilegeTab : ITab
{
    public string Title => "  Privilege Escalation  ";

    private readonly TestLog       _log;
    private readonly PacketCapture _capture;
    private readonly UdpProxy      _udpProxy;
    private readonly ServerConfig  _config;

    private int    _itemId        = 1001;
    private int    _itemCount     = 1;
    private int    _playerId      = 1;
    private string _rawCommand    = "/give @s diamond 64";
    private string _customHex     = "";
    private bool   _spoofOwner    = false;
    private int    _fakePermLevel = 4;

    // Auto-fill state
    private ContextSnapshot? _lastFill;
    private string           _fillStatus = "Click ⟳ to auto-fill from captured packets";

    // Sub-tab selection (inline button tabs, not ImGui tabs)
    private int _subTab = 0;
    private static readonly string[] SubTabs = { "Give Item", "Command Inject", "Perm Spoof" };

    public PrivilegeTab(TestLog log, PacketCapture capture, UdpProxy udpProxy, ServerConfig config)
    {
        _log = log; _capture = capture; _udpProxy = udpProxy; _config = config;
    }

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;

        RenderStatusBar(w);
        ImGui.Spacing();
        RenderAutoFillBar(w);
        ImGui.Spacing();

        // Inline sub-tab selector
        for (int i = 0; i < SubTabs.Length; i++)
        {
            bool sel = _subTab == i;
            ImGui.PushStyleColor(ImGuiCol.Button,
                sel ? new Vector4(0.18f, 0.95f, 0.45f, 0.22f)
                    : MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text,
                sel ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);

            if (ImGui.Button(SubTabs[i] + $"##st{i}", new Vector2(160, 30)))
                _subTab = i;

            ImGui.PopStyleColor(2);
            if (i < SubTabs.Length - 1) ImGui.SameLine(0, 4);
        }

        ImGui.Spacing(); ImGui.Spacing();

        switch (_subTab)
        {
            case 0: UiHelper.SectionBox("GIVE ITEM (AS NON-OP)",     w, 220, RenderGiveItem);      break;
            case 1: UiHelper.SectionBox("COMMAND INJECTION",          w, 220, RenderCommandInject); break;
            case 2: UiHelper.SectionBox("PERMISSION LEVEL SPOOF",     w, 220, RenderPermSpoof);    break;
        }
    }

    private void RenderStatusBar(float w)
    {
        bool srv = _config.IsSet;
        bool ses = _capture.IsRunning;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##privst", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));
        ImGui.PushStyleColor(ImGuiCol.Text,
            srv ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(srv
            ? $"● {_config.ServerIp}:{_config.ServerPort}"
            : "● No server — set in Dashboard");
        ImGui.PopStyleColor();
        ImGui.SameLine(0, 24);
        ImGui.PushStyleColor(ImGuiCol.Text,
            ses ? MenuRenderer.ColAccent : MenuRenderer.ColWarn);
        ImGui.TextUnformatted(ses
            ? "● Capture proxy active — injecting into session"
            : "● No proxy — start Capture tab first for best results");
        ImGui.PopStyleColor();
        ImGui.EndChild();
    }

    private void RenderAutoFillBar(float w)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
        ImGui.BeginChild("##privaf", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(8, 5));

        UiHelper.SecondaryButton("⟳ Auto-fill IDs from packets##privafbtn", 200, 22, () =>
        {
            _lastFill = ContextFiller.Fill(_capture, _udpProxy);
            if (_lastFill.HasItem)   { _itemId   = _lastFill.ItemId!.Value; }
            if (_lastFill.HasPlayer) { _playerId  = _lastFill.PlayerId ?? _playerId; }
            if (_lastFill.HasItem || _lastFill.HasPlayer)
            {
                _fillStatus = $"Filled: ItemID={_itemId}  PlayerID={_playerId}" +
                              (_lastFill.PlayerName != null ? $"  Name={_lastFill.PlayerName}" : "");
                _log.Success($"[PrivEsc] Auto-filled from packets — {_fillStatus}");
            }
            else
            {
                _fillStatus = "Nothing found — capture traffic first, then retry.";
                _log.Warn("[PrivEsc] Auto-fill: no item/player IDs found in recent packets.");
            }
        });

        ImGui.SameLine(0, 14);
        ImGui.PushStyleColor(ImGuiCol.Text, _lastFill?.HasItem == true
            ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
        ImGui.TextUnformatted(_fillStatus);
        ImGui.PopStyleColor();
        ImGui.EndChild();
    }

    private void RenderGiveItem()
    {
        UiHelper.MutedLabel("Sends a give-item packet as a normal player.");
        UiHelper.MutedLabel("If server only validates client-side, item appears in inventory.");
        ImGui.Spacing();

        ImGui.SetNextItemWidth(130);
        ImGui.InputInt("Item ID##giid", ref _itemId);
        ImGui.SameLine(0, 6);
        UiHelper.SecondaryButton("⟳##giaf", 26, 22, () => {
            var f = ContextFiller.Fill(_capture, _udpProxy);
            if (f.HasItem) { _itemId = f.ItemId!.Value; _log.Info($"[PrivEsc] Item ID filled: {_itemId}"); }
            else _log.Warn("[PrivEsc] No item ID found — capture traffic while holding/dropping an item.");
        });
        ImGui.SameLine(0, 8);
        UiHelper.MutedLabel("← use ⟳ or auto-fill bar to get real ID");

        ImGui.SetNextItemWidth(100);
        ImGui.InputInt("Amount##gicnt", ref _itemCount);
        _itemCount = Math.Max(1, _itemCount);

        ImGui.SetNextItemWidth(100);
        ImGui.InputInt("Player ID##gpid", ref _playerId);
        ImGui.Spacing();

        UiHelper.WarnButton("Send Give Item Packet", 210, 32, () =>
        {
            var pkt = new List<byte> { 0x2A };
            pkt.AddRange(BitConverter.GetBytes(_itemId));
            pkt.AddRange(BitConverter.GetBytes(_itemCount));
            pkt.AddRange(BitConverter.GetBytes(_playerId));
            SendRaw(pkt.ToArray());
            _log.Info($"[PrivEsc] Give item — ItemID={_itemId} ×{_itemCount} PlayerID={_playerId}");
        });

        ImGui.Spacing();
        UiHelper.MutedLabel("Result: item appears = server trusts client  |  kick = validated.");
    }

    private void RenderCommandInject()
    {
        UiHelper.MutedLabel("Sends a command as a normal player without OP.");
        UiHelper.MutedLabel("Tests if server checks permission level before executing.");
        ImGui.Spacing();

        ImGui.SetNextItemWidth(-1);
        ImGui.InputText("Command##cmd", ref _rawCommand, 256);

        ImGui.Spacing();
        UiHelper.MutedLabel("Try: /give @s <id> 64  |  /op <name>  |  /gamemode creative");
        ImGui.Spacing();

        UiHelper.WarnButton("Send Command", 180, 32, () =>
        {
            _log.Info($"[PrivEsc] Sending command: {_rawCommand}");
            byte[] bytes = Encoding.UTF8.GetBytes(_rawCommand);
            var pkt = new List<byte> { 0x01 };
            pkt.AddRange(BitConverter.GetBytes((ushort)bytes.Length));
            pkt.AddRange(bytes);
            SendRaw(pkt.ToArray());
        });

        ImGui.Spacing();
        UiHelper.MutedLabel("Executes = server not checking perms  |  No effect = secure.");
    }

    private void RenderPermSpoof()
    {
        UiHelper.MutedLabel("Prepend a spoofed permission level byte to a captured packet.");
        ImGui.Spacing();

        ImGui.Checkbox("Prepend perm byte##spl", ref _spoofOwner);
        ImGui.BeginDisabled(!_spoofOwner);
        ImGui.SetNextItemWidth(100);
        ImGui.InputInt("Level##pl", ref _fakePermLevel);
        _fakePermLevel = Math.Clamp(_fakePermLevel, 0, 255);
        ImGui.SameLine();
        UiHelper.MutedLabel("0=guest 1=member 2=mod 3=admin 4=owner");
        ImGui.EndDisabled();

        ImGui.Spacing();
        ImGui.SetNextItemWidth(-1);
        ImGui.InputText("Packet Hex##cph", ref _customHex, 1024);
        UiHelper.MutedLabel("Paste a captured packet hex above.");
        ImGui.Spacing();

        UiHelper.WarnButton("Send Spoofed Packet", 200, 32, () =>
        {
            if (string.IsNullOrWhiteSpace(_customHex))
            { _log.Error("[PrivEsc] No hex provided."); return; }
            try
            {
                string clean = _customHex.Replace(" ", "");
                if (clean.Length % 2 != 0) clean += "0";
                byte[] raw = Convert.FromHexString(clean);
                var pkt = new List<byte>();
                if (_spoofOwner)
                {
                    pkt.Add((byte)_fakePermLevel);
                    _log.Info($"[PrivEsc] Prepending perm level 0x{_fakePermLevel:X2}");
                }
                pkt.AddRange(raw);
                SendRaw(pkt.ToArray());
                _log.Success("[PrivEsc] Spoofed packet sent.");
            }
            catch (Exception ex) { _log.Error($"[PrivEsc] {ex.Message}"); }
        });
    }

    private void SendRaw(byte[] data)
    {
        // Prefer UDP proxy (injects into real game session)
        if (_udpProxy.IsRunning && _udpProxy.InjectToServer(data))
        {
            _log.Info($"[PrivEsc] {data.Length}b injected via UDP proxy.");
            return;
        }
        // Fall back to TCP session injection
        bool ok = _capture.InjectToServer(data).GetAwaiter().GetResult();
        if (ok) { _log.Info($"[PrivEsc] {data.Length}b injected via TCP."); return; }

        // Last resort: direct UDP
        _log.Warn("[PrivEsc] No session — sending direct UDP...");
        try
        {
            using var udp = new UdpClient();
            udp.Connect(_config.ServerIp, _config.ServerPort);
            udp.Send(data, data.Length);
            _log.Info($"[PrivEsc] {data.Length}b sent via direct UDP.");
        }
        catch (Exception ex) { _log.Error($"[PrivEsc] {ex.Message}"); }
    }
}
