using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Packet Book - your personal library of identified and labelled packets.
///
/// Once you know what a packet does (from Capture + Item Inspector), save it
/// here. Then replay, edit, or send it directly from this tab without
/// copy-pasting hex every time.
/// </summary>
public class PacketBookTab : ITab
{
    public string Title => "  Packet Book  ";

    private readonly TestLog      _log;
    private readonly PacketStore  _store;
    private readonly UdpProxy     _udpProxy;
    private readonly PacketCapture _capture;
    private readonly ServerConfig  _config;

    private int    _selectedIdx  = -1;
    private string _editHex      = "";
    private string _editLabel    = "";
    private string _editNotes    = "";
    private bool   _editing      = false;
    private int    _replayCount  = 5;
    private int    _replayDelay  = 50;

    // ── Search + tag filter ───────────────────────────────────────────────
    private string _searchText   = "";
    private string _tagFilter    = "";
    private string _newTagInput  = "";
    private int    _sortMode     = 0;   // 0=saved-at  1=opcode  2=size  3=label

    // ── Virtualized list cache (avoids re-sorting 35000+ entries every frame) ─
    private List<SavedPacket>? _sortedCache    = null;
    private int               _cacheStoreCount = -1;   // invalidate when store grows
    private string            _cacheSearch     = "";
    private string            _cacheTag        = "";
    private int               _cacheSort       = -1;
    private const int         PageSize         = 200;   // rows shown at once
    private int               _pageOffset      = 0;     // first visible row index

    public PacketBookTab(TestLog log, PacketStore store, UdpProxy udpProxy,
                          PacketCapture capture, ServerConfig config)
    {
        _log = log; _store = store; _udpProxy = udpProxy;
        _capture = capture; _config = config;
    }

    public void Render()
    {
        float w    = ImGui.GetContentRegionAvail().X;
        float listW = w * 0.40f;
        float detW  = w - listW - 8;
        float h     = ImGui.GetContentRegionAvail().Y;

        // Left: packet list
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##pblist", new Vector2(listW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 8));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("SAVED PACKETS");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        // ── Search + sort toolbar ──────────────────────────────────────────
        ImGui.SetNextItemWidth(listW - 16);
        ImGui.InputText("##pbsearch", ref _searchText, 64);
        if (_searchText.Length == 0)
        {
            var dl2 = ImGui.GetWindowDrawList();
            var p2  = ImGui.GetItemRectMin();
            dl2.AddText(p2 + new Vector2(6, 3),
                ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColTextMuted), "Search...");
        }
        ImGui.Spacing();
        ImGui.SetNextItemWidth(listW - 16);
        ImGui.InputText("Tag##pbtag", ref _tagFilter, 32);
        ImGui.Spacing();
        ImGui.SetNextItemWidth(listW - 16);
        ImGui.Combo("Sort##pbsort", ref _sortMode, new[] { "Newest", "Opcode", "Size", "Label" }, 4);
        ImGui.Spacing();

        // ── Clear buttons ─────────────────────────────────────────────────
        var packets = _store.GetAll();
        int schemaCount = packets.Count(p => p.Label.StartsWith("Schema:", StringComparison.OrdinalIgnoreCase));

        // Clear auto-named (Schema:) entries only
        if (schemaCount > 0)
        {
            ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColWarnDim);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColWarn with { W = 0.35f });
            ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColWarn);
            if (ImGui.Button($"Clear auto-names ({schemaCount})##pbclrsch",
                new Vector2(listW - 16, 22)))
            {
                int n = _store.ClearByPrefix("Schema:");
                _sortedCache = null;  // invalidate cache
                _log.Info($"[Book] Cleared {n} auto-named (Schema:*) entries.");
            }
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("Remove all Schema:xxx=yyy auto-named entries.\n" +
                    "Manual entries are kept. Re-run capture to rebuild from scratch.");
            ImGui.PopStyleColor(3);
            ImGui.Spacing();
        }

        // Clear everything
        ImGui.PushStyleColor(ImGuiCol.Button,        MenuRenderer.ColDanger with { W = 0.22f });
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, MenuRenderer.ColDanger with { W = 0.40f });
        ImGui.PushStyleColor(ImGuiCol.Text,          MenuRenderer.ColDanger);
        if (ImGui.Button($"Clear ALL ({packets.Count})##pbclrall",
            new Vector2(listW - 16, 22)))
        {
            int n = _store.ClearAll();
            _sortedCache = null;  // invalidate cache
            _log.Warn($"[Book] Cleared ALL {n} entries from Packet Book.");
        }
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Remove EVERY entry including manual ones.\nThis cannot be undone.");
        ImGui.PopStyleColor(3);
        ImGui.Spacing();

        // ── Build sorted/filtered list (cached - only re-sort when inputs change) ─
        // With 35000+ entries, rebuilding every frame causes severe lag.
        bool filterChanged = _searchText != _cacheSearch || _tagFilter != _cacheTag
                          || _sortMode   != _cacheSort   || packets.Count != _cacheStoreCount;
        if (filterChanged || _sortedCache == null)
        {
            _cacheSearch     = _searchText;
            _cacheTag        = _tagFilter;
            _cacheSort       = _sortMode;
            _cacheStoreCount = packets.Count;
            _pageOffset      = 0;   // reset page when filter changes

            packets = _store.GetAll();
            var filtered = packets.AsEnumerable();
            if (_searchText.Length > 0)
            {
                string su = _searchText.ToLower();
                filtered = filtered.Where(p =>
                    p.Label.ToLower().Contains(su) ||
                    p.Notes.ToLower().Contains(su) ||
                    p.Tags.Any(t => t.ToLower().Contains(su)));
            }
            if (_tagFilter.Length > 0)
                filtered = filtered.Where(p => p.Tags.Any(t =>
                    t.ToLower().Contains(_tagFilter.ToLower())));

            _sortedCache = _sortMode switch
            {
                1 => filtered.OrderBy(p => p.ToBytes().Length > 0 ? p.ToBytes()[0] : 0).ToList(),
                2 => filtered.OrderByDescending(p => p.ToBytes().Length).ToList(),
                3 => filtered.OrderBy(p => p.Label).ToList(),
                _ => filtered.OrderByDescending(p => p.SavedAt).ToList(),
            };
        }
        var sortedList = _sortedCache;

        if (packets.Count == 0)
        {
            ImGui.SetCursorPosX(12);
            UiHelper.MutedLabel("No saved packets yet.");
            ImGui.SetCursorPosX(12);
            UiHelper.MutedLabel("Capture packets -> Item Inspector");
            ImGui.SetCursorPosX(12);
            UiHelper.MutedLabel("<- Save to Packet Book.");
        }

        var dl = ImGui.GetWindowDrawList();

        // ── Pagination controls ───────────────────────────────────────────
        int totalVisible = sortedList.Count;
        int pageStart    = Math.Min(_pageOffset, Math.Max(0, totalVisible - 1));
        int pageEnd      = Math.Min(pageStart + PageSize, totalVisible);
        if (totalVisible > PageSize)
        {
            ImGui.SetCursorPosX(8);
            int pages = (int)Math.Ceiling((double)totalVisible / PageSize);
            int curPg = pageStart / PageSize + 1;
            UiHelper.MutedLabel($"{pageStart+1}-{pageEnd}/{totalVisible}  pg {curPg}/{pages}");
            ImGui.SameLine(0, 8);
            ImGui.BeginDisabled(_pageOffset == 0);
            if (ImGui.SmallButton("<##pbprev")) _pageOffset = Math.Max(0, _pageOffset - PageSize);
            ImGui.EndDisabled();
            ImGui.SameLine(0, 2);
            ImGui.BeginDisabled(pageEnd >= totalVisible);
            if (ImGui.SmallButton(">##pbnext")) _pageOffset = Math.Min((pages-1)*PageSize, _pageOffset + PageSize);
            ImGui.EndDisabled();
            ImGui.Spacing();
        }
        else if (totalVisible < packets.Count)
        {
            ImGui.SetCursorPosX(8);
            UiHelper.MutedLabel($"{totalVisible}/{packets.Count} shown");
            ImGui.Spacing();
        }

        // ── Render only the current page ─────────────────────────────────
        for (int i = pageStart; i < pageEnd; i++)
        {
            var  pkt = sortedList[i];
            int  globalIdx = packets.IndexOf(pkt);
            bool cs  = pkt.Direction == PacketDirection.ClientToServer;
            var  col = cs ? MenuRenderer.ColBlue : MenuRenderer.ColAccent;

            if (_selectedIdx == globalIdx)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(listW, 54),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }

            ImGui.SetCursorPosX(12);
            ImGui.PushStyleColor(ImGuiCol.Text, col);
            ImGui.TextUnformatted(pkt.Label);
            ImGui.PopStyleColor();
            ImGui.SetCursorPosX(12);
            UiHelper.MutedLabel(
                $"{pkt.Direction.ToString()[..1]}->  {pkt.ToBytes().Length}b  " +
                $"saved {pkt.SavedAt:HH:mm dd/MM}");
            if (pkt.Tags.Count > 0)
            {
                ImGui.SetCursorPosX(12);
                foreach (var tag in pkt.Tags.Take(4))
                {
                    ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBlueDim);
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                    ImGui.Button($"#{tag}##tag_{i}_{tag}", new Vector2(0, 14));
                    ImGui.PopStyleColor(2);
                    ImGui.SameLine(0, 2);
                }
                ImGui.NewLine();
            }
            if (!string.IsNullOrEmpty(pkt.Notes))
            {
                ImGui.SetCursorPosX(12);
                UiHelper.MutedLabel(pkt.Notes.Length > 36 ? pkt.Notes[..33] + "..." : pkt.Notes);
            }

            float rowH = pkt.Tags.Count > 0 ? 60 : (pkt.Notes.Length > 0 ? 60 : 48);
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() - rowH);
            if (ImGui.Selectable($"##pbs{i}", _selectedIdx == globalIdx,
                ImGuiSelectableFlags.None, new Vector2(listW - 12, rowH)))
            {
                _selectedIdx = globalIdx;
                _editing     = false;
            }
            ImGui.Separator();
        }

        ImGui.EndChild();
        ImGui.SameLine(0, 8);

        // Right: detail + actions
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##pbdet", new Vector2(detW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        if (_selectedIdx >= 0 && _selectedIdx < packets.Count)
        {
            RenderDetail(packets[_selectedIdx], detW);
        }
        else
        {
            ImGui.SetCursorPosY(h * 0.4f);
            float tw = ImGui.CalcTextSize("<- select a saved packet").X;
            ImGui.SetCursorPosX((detW - tw) * 0.5f);
            UiHelper.MutedLabel("<- select a saved packet");
        }

        ImGui.EndChild();
    }

    private void RenderDetail(SavedPacket pkt, float w)
    {
        byte[] data = pkt.ToBytes();

        ImGui.SetCursorPos(new Vector2(12, 10));
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted(pkt.Label.ToUpper());
        ImGui.PopStyleColor();
        ImGui.Spacing();

        bool cs = pkt.Direction == PacketDirection.ClientToServer;
        UiHelper.StatusRow("Direction", cs ? "Client -> Server" : "Server -> Client", cs,  90);
        UiHelper.StatusRow("Size",      $"{data.Length} bytes", true, 90);
        if (data.Length > 0)
            UiHelper.StatusRow("Packet ID", $"0x{data[0]:X2}", true, 90);
        UiHelper.StatusRow("Saved",     pkt.SavedAt.ToString("HH:mm dd/MM/yy"), true, 90);

        // ── Tag editor ────────────────────────────────────────────────────
        ImGui.Spacing();
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("TAGS");
        ImGui.PopStyleColor();
        ImGui.Spacing();
        foreach (var tag in pkt.Tags.ToList())
        {
            ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBlueDim);
            ImGui.PushStyleColor(ImGuiCol.Text,   MenuRenderer.ColBlue);
            if (ImGui.Button($"#{tag}##dettag_{tag}", new Vector2(0, 20)))
            {
                pkt.Tags.Remove(tag);
                _store.Save(pkt.Label, pkt.Notes, pkt.ToBytes(), pkt.Direction,
                    pkt.Tags.ToArray());
            }
            ImGui.PopStyleColor(2);
            if (ImGui.IsItemHovered()) ImGui.SetTooltip("Click to remove");
            ImGui.SameLine(0, 4);
        }
        ImGui.NewLine();
        ImGui.SetNextItemWidth(100); ImGui.InputText("##pbtaginput", ref _newTagInput, 24);
        ImGui.SameLine(0, 4);
        UiHelper.SecondaryButton("Add Tag##pbtagadd", 80, 20, () =>
        {
            string t = _newTagInput.Trim().ToLower().Replace(" ", "_");
            if (t.Length > 0 && !pkt.Tags.Contains(t))
            {
                pkt.Tags.Add(t);
                _store.Save(pkt.Label, pkt.Notes, pkt.ToBytes(), pkt.Direction,
                    pkt.Tags.ToArray());
            }
            _newTagInput = "";
        });
        if (!string.IsNullOrEmpty(pkt.Notes))
        {
            ImGui.Spacing();
            UiHelper.MutedLabel(pkt.Notes);
        }

        ImGui.Spacing();
        var dl = ImGui.GetWindowDrawList();
        var wp = ImGui.GetWindowPos();
        dl.AddLine(new Vector2(wp.X + 12, ImGui.GetCursorScreenPos().Y),
                   new Vector2(wp.X + w  - 12, ImGui.GetCursorScreenPos().Y),
                   ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
        ImGui.Spacing();

        // ── Hex editor ────────────────────────────────────────────────────
        if (_editing)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
            ImGui.TextUnformatted("EDIT PACKET");
            ImGui.PopStyleColor();
            ImGui.Spacing();

            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Label##pbelab", ref _editLabel, 64);
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Notes##pbenotes", ref _editNotes, 128);
            ImGui.Spacing();
            UiHelper.MutedLabel("Hex (space-separated or continuous):");
            ImGui.SetNextItemWidth(-1);
            ImGui.InputTextMultiline("##pbehex", ref _editHex, 4096, new Vector2(-1, 80));
            ImGui.Spacing();

            UiHelper.PrimaryButton("Save Changes##pbsave", 140, 28, () =>
            {
                try
                {
                    string clean = _editHex.Replace(" ", "").Replace("\n", "");
                    if (clean.Length % 2 != 0) clean += "0";
                    byte[] newData = Convert.FromHexString(clean);
                    _store.Delete(pkt.Label);
                    _store.Save(_editLabel, _editNotes, newData, pkt.Direction);
                    _log.Success($"[Book] '{_editLabel}' updated ({newData.Length}b).");
                    _editing = false;
                }
                catch (Exception ex) { _log.Error($"[Book] Edit: {ex.Message}"); }
            });
            ImGui.SameLine(0, 8);
            UiHelper.SecondaryButton("Cancel##pbcanc", 80, 28, () => _editing = false);
        }
        else
        {
            // Hex display
            UiHelper.MutedLabel("Hex dump:");
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.7f, 1.0f, 0.7f, 1f));
            for (int row = 0; row < data.Length; row += 16)
            {
                int    len = Math.Min(16, data.Length - row);
                string hex = string.Join(" ", data.Skip(row).Take(len).Select(b => $"{b:X2}"));
                string asc = new string(data.Skip(row).Take(len)
                    .Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
                ImGui.Text($"  {row:X4}  {hex,-47}  {asc}");
            }
            ImGui.PopStyleColor();

            ImGui.Spacing();
            UiHelper.SecondaryButton("Edit##pbedit", 70, 26, () =>
            {
                _editHex   = pkt.HexString;
                _editLabel = pkt.Label;
                _editNotes = pkt.Notes;
                _editing   = true;
            });
            ImGui.SameLine(0, 6);
            UiHelper.SecondaryButton("Copy Hex##pbcopy", 90, 26, () =>
            {
                ImGui.SetClipboardText(pkt.HexString);
                _log.Info($"[Book] '{pkt.Label}' hex copied.");
            });
            ImGui.SameLine(0, 6);
            UiHelper.DangerButton("Delete##pbdel", 70, 26, () =>
            {
                _store.Delete(pkt.Label);
                _selectedIdx = -1;
                _log.Warn($"[Book] '{pkt.Label}' deleted.");
            });
        }

        ImGui.Spacing();
        dl.AddLine(new Vector2(wp.X + 12, ImGui.GetCursorScreenPos().Y),
                   new Vector2(wp.X + w  - 12, ImGui.GetCursorScreenPos().Y),
                   ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColBorder));
        ImGui.Spacing();

        // ── Send / Replay controls ─────────────────────────────────────────
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
        ImGui.TextUnformatted("SEND / REPLAY");
        ImGui.PopStyleColor();
        ImGui.Spacing();

        ImGui.SetNextItemWidth(100);
        ImGui.InputInt("Count##pbrc", ref _replayCount);
        _replayCount = Math.Clamp(_replayCount, 1, 10000);
        ImGui.SameLine(0, 12);
        ImGui.SetNextItemWidth(100);
        ImGui.InputInt("Delay ms##pbrd", ref _replayDelay);
        _replayDelay = Math.Clamp(_replayDelay, 0, 5000);
        ImGui.Spacing();

        UiHelper.WarnButton("Send Once##pbsend1", 110, 28, () => DoSend(data, pkt.Label, 1, 0));
        ImGui.SameLine(0, 8);
        UiHelper.WarnButton($"Replayx{_replayCount}##pbsendN", 120, 28,
            () => DoSend(data, pkt.Label, _replayCount, _replayDelay));
        ImGui.Spacing();
        UiHelper.MutedLabel("Uses UDP proxy if active, otherwise direct UDP.");
    }

    private void DoSend(byte[] data, string label, int count, int delayMs)
    {
        if (data.Length == 0) { _log.Error($"[Book] '{label}' is empty."); return; }
        _log.Info($"[Book] Sending '{label}'x{count}...");
        Task.Run(async () =>
        {
            int sent = 0;
            for (int i = 0; i < count; i++)
            {
                bool ok = false;
                if (_udpProxy.IsRunning) ok = _udpProxy.InjectToServer(data);
                if (!ok) ok = await _capture.InjectToServer(data);
                if (!ok)
                {
                    try
                    {
                        using var udp = new System.Net.Sockets.UdpClient();
                        udp.Connect(_config.ServerIp, _config.ServerPort);
                        udp.Send(data, data.Length);
                        ok = true;
                    }
                    catch (Exception ex) { _log.Error($"[Book] Send: {ex.Message}"); break; }
                }
                if (ok) sent++;
                if (delayMs > 0) await Task.Delay(delayMs);
            }
            _log.Success($"[Book] '{label}' sent {sent}/{count}.");
        });
    }
}
