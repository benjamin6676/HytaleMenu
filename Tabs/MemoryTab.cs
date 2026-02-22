using ImGuiNET;
using HytaleSecurityTester.Core;
using System.Numerics;

namespace HytaleSecurityTester.Tabs;

/// <summary>
/// Memory Reader tab.
///
/// Attaches to any running process (primarily Hytale) and lets you:
///   - Browse and attach to running processes
///   - Read raw bytes / int32 / float from any address
///   - Scan all readable memory for byte patterns
///   - Scan for int32 values in a range (item IDs, entity IDs, counts)
///   - Rescan to narrow down — do action in-game, rescan, repeat
///   - Heuristic inventory scan — finds item ID clusters automatically
///
/// No injection, no DLL. Read-only. Works on any Windows process.
/// </summary>
public class MemoryTab : ITab
{
    public string Title => "  Memory  ";

    private readonly TestLog     _log;
    private readonly MemoryReader _reader = new();

    // ── Sub-tabs ──────────────────────────────────────────────────────────
    private int _subTab = 0;
    private static readonly string[] SubTabs =
        { "Attach", "Read", "Pattern Scan", "Value Scan", "Inventory Scan",
          "AOB Scan", "Memory Map", "Pointer Path" };

    // ── AOB scan ──────────────────────────────────────────────────────────
    private string          _aobModule     = "";
    private string          _aobPattern    = "";
    private string          _aobResult     = "";
    private List<ModuleInfo> _aobModules   = new();
    private bool            _aobAllModules = false;
    private List<AobMatch>  _aobMatches    = new();
    private bool            _aobScanning   = false;

    // ── Memory Map ────────────────────────────────────────────────────────
    private List<MemoryMapEntry> _memMap      = new();
    private bool                 _memMapLoaded = false;
    private bool                 _memMapOnlyR  = true;
    private string               _memMapFilter = "";
    private int                  _memMapSel    = -1;

    // ── Pointer Path ──────────────────────────────────────────────────────
    private string _ppBase        = "0x0000000000000000";
    private string _ppOffsets     = "0x8 0x10 0x30";
    private string _ppResult      = "";
    private string _ppTrace       = "";
    private int    _ppReadBytes   = 32;
    private byte[] _ppReadResult  = Array.Empty<byte>();

    // ── Process list ──────────────────────────────────────────────────────
    private List<ProcessEntry> _processes     = new();
    private string             _procFilter    = "";
    private bool               _refreshing    = false;

    // ── Read ──────────────────────────────────────────────────────────────
    private string _readAddrHex  = "0x0000000000000000";
    private int    _readBytes    = 64;
    private byte[] _readResult   = Array.Empty<byte>();
    private string _readError    = "";

    // ── Pattern scan ──────────────────────────────────────────────────────
    private string             _patternInput   = ""; // e.g.  "48 8B ?? 48 89"
    private List<ScanMatch>    _patternResults = new();
    private bool               _patternScanning = false;
    private int                _patternProgress = 0;
    private int                _patternMax      = 200;
    private int                _patternSelected = -1;

    // ── Value scan ────────────────────────────────────────────────────────
    private int             _vsMin         = 100;
    private int             _vsMax         = 9999;
    private List<ScanMatch> _vsResults     = new();
    private List<ScanMatch> _vsPrevResults = new();
    private bool            _vsScanning    = false;
    private int             _vsProgress    = 0;
    private int             _vsSelected    = -1;
    private bool            _vsHasFirst    = false;
    // Rescan range
    private int             _vsRescanMin   = 100;
    private int             _vsRescanMax   = 9999;

    // ── Inventory scan ────────────────────────────────────────────────────
    private List<InventoryCandidate> _invResults  = new();
    private bool                     _invScanning = false;
    private int                      _invProgress = 0;
    private int                      _invSelected = -1;

    private int _manualPid = 0;

    public MemoryTab(TestLog log) => _log = log;

    public void Render()
    {
        float w = ImGui.GetContentRegionAvail().X;

        RenderStatusBar(w);
        ImGui.Spacing();
        RenderSubTabBar();
        ImGui.Spacing();

        switch (_subTab)
        {
            case 0: RenderAttach(w);        break;
            case 1: RenderRead(w);          break;
            case 2: RenderPatternScan(w);   break;
            case 3: RenderValueScan(w);     break;
            case 4: RenderInventoryScan(w); break;
            case 5: RenderAobScan(w);       break;
            case 6: RenderMemoryMap(w);     break;
            case 7: RenderPointerPath(w);   break;
        }
    }

    // ── Status bar ────────────────────────────────────────────────────────

    private void RenderStatusBar(float w)
    {
        bool att = _reader.IsAttached;
        ImGui.PushStyleColor(ImGuiCol.ChildBg,
            att ? new Vector4(0.05f, 0.15f, 0.07f, 1f)
                : new Vector4(0.13f, 0.05f, 0.05f, 1f));
        ImGui.BeginChild("##memsb", new Vector2(w, 30), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();
        ImGui.SetCursorPos(new Vector2(12, 6));

        var dl = ImGui.GetWindowDrawList();
        var p  = ImGui.GetWindowPos();
        dl.AddRectFilled(p, p + new Vector2(3, 30),
            ImGui.ColorConvertFloat4ToU32(att ? MenuRenderer.ColAccent : MenuRenderer.ColDanger));

        ImGui.PushStyleColor(ImGuiCol.Text, att ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
        ImGui.TextUnformatted(att
            ? $"● Attached — {_reader.ProcessName} (PID {_reader.Pid})"
            : "● Not attached — go to Attach tab");
        ImGui.PopStyleColor();

        if (att)
        {
            ImGui.SameLine(0, 24);
            UiHelper.DangerButton("Detach##memdet", 70, 20, () =>
            {
                _reader.Detach();
                _log.Warn("[Memory] Detached.");
            });
        }
        ImGui.EndChild();
    }

    // ── Sub-tab bar ───────────────────────────────────────────────────────

    private void RenderSubTabBar()
    {
        for (int i = 0; i < SubTabs.Length; i++)
        {
            bool sel = _subTab == i;
            ImGui.PushStyleColor(ImGuiCol.Button,
                sel ? new Vector4(0.18f, 0.95f, 0.45f, 0.22f) : MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text,
                sel ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
            if (ImGui.Button(SubTabs[i] + $"##mst{i}", new Vector2(130, 28))) _subTab = i;
            ImGui.PopStyleColor(2);
            if (i < SubTabs.Length - 1) ImGui.SameLine(0, 4);
        }
    }

    // ── Attach ────────────────────────────────────────────────────────────

    private void RenderAttach(float w)
    {
        float half = (w - 12) * 0.5f;

        UiHelper.SectionBox("PROCESS LIST", w * 0.6f, 380, () =>
        {
            UiHelper.MutedLabel("Find and attach to a running process.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(200);
            ImGui.InputText("Filter##mpf", ref _procFilter, 64);
            ImGui.SameLine(0, 8);
            ImGui.BeginDisabled(_refreshing);
            UiHelper.SecondaryButton(_refreshing ? "Refreshing..." : "Refresh##mpr",
                110, 26, RefreshProcessList);
            ImGui.EndDisabled();

            ImGui.Spacing();

            if (_processes.Count == 0)
            {
                UiHelper.MutedLabel("Click Refresh to load process list.");
            }
            else
            {
                float lh = 300f;
                ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg2);
                ImGui.BeginChild("##mpl", new Vector2(-1, lh), ImGuiChildFlags.Border);
                ImGui.PopStyleColor();

                ImGui.SetCursorPos(new Vector2(8, 4));
                UiHelper.MutedLabel("  PID      Name                              Title");
                ImGui.Separator();

                var filtered = string.IsNullOrWhiteSpace(_procFilter)
                    ? _processes
                    : _processes.Where(p =>
                        p.Name.Contains(_procFilter, StringComparison.OrdinalIgnoreCase) ||
                        p.Title.Contains(_procFilter, StringComparison.OrdinalIgnoreCase) ||
                        p.Pid.ToString().Contains(_procFilter)).ToList();

                foreach (var proc in filtered)
                {
                    bool isHytale = proc.Name.Contains("Hytale",
                        StringComparison.OrdinalIgnoreCase);
                    bool attached = _reader.IsAttached && _reader.Pid == proc.Pid;

                    var col = attached  ? MenuRenderer.ColAccent
                            : isHytale ? MenuRenderer.ColWarn
                            :            MenuRenderer.ColText;

                    ImGui.PushStyleColor(ImGuiCol.Text, col);
                    string label = $"  {proc.Pid,-8} {proc.Name,-34} {proc.Title[..Math.Min(proc.Title.Length, 30)]}";
                    if (ImGui.Selectable(label + $"##mpsel{proc.Pid}", attached,
                        ImGuiSelectableFlags.None, new Vector2(0, 18)))
                    {
                        if (!attached)
                        {
                            string err = _reader.Attach(proc.Pid);
                            if (string.IsNullOrEmpty(err))
                                _log.Success($"[Memory] Attached to {proc.Name} (PID {proc.Pid})");
                            else
                                _log.Error($"[Memory] Attach failed: {err}");
                        }
                    }
                    ImGui.PopStyleColor();
                }

                ImGui.EndChild();
            }
        });

        ImGui.SameLine(0, 12);

        UiHelper.SectionBox("QUICK ATTACH", w * 0.38f, 380, () =>
        {
            UiHelper.MutedLabel("Hytale process names to try:");
            ImGui.Spacing();

            foreach (var name in new[] { "Hytale", "hytale", "HytaleClient", "java", "javaw" })
            {
                UiHelper.SecondaryButton($"Attach to '{name}'##qa{name}", -1, 26, () =>
                {
                    var procs = Process.GetProcessesByName(name);
                    if (procs.Length == 0)
                    {
                        _log.Warn($"[Memory] No process named '{name}' found.");
                        return;
                    }
                    string err = _reader.Attach(procs[0].Id);
                    if (string.IsNullOrEmpty(err))
                        _log.Success($"[Memory] Attached to {name} (PID {procs[0].Id})");
                    else
                        _log.Error($"[Memory] Attach failed: {err}");
                });
                ImGui.Spacing();
            }

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();
            UiHelper.MutedLabel("Or enter PID manually:");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(-1);
            ImGui.InputInt("##mpid", ref _manualPid);
            UiHelper.PrimaryButton("Attach by PID##apid", -1, 28, () =>
            {
                if (_manualPid <= 0) { _log.Error("[Memory] Enter a valid PID."); return; }
                string err = _reader.Attach(_manualPid);
                if (string.IsNullOrEmpty(err))
                    _log.Success($"[Memory] Attached to PID {_manualPid}");
                else
                    _log.Error($"[Memory] Attach failed: {err}");
            });
        });
    }

    // ── Read ──────────────────────────────────────────────────────────────

    private void RenderRead(float w)
    {
        UiHelper.SectionBox("READ MEMORY", w, 100, () =>
        {
            UiHelper.MutedLabel("Read raw bytes from any address in the attached process.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(240);
            ImGui.InputText("Address (hex)##mra", ref _readAddrHex, 32);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("Bytes##mrb", ref _readBytes);
            _readBytes = Math.Clamp(_readBytes, 1, 4096);
            ImGui.SameLine(0, 8);

            ImGui.BeginDisabled(!_reader.IsAttached);
            UiHelper.PrimaryButton("Read##mrread", 80, 26, DoRead);
            ImGui.EndDisabled();

            if (!string.IsNullOrEmpty(_readError))
            {
                ImGui.SameLine(0, 12);
                UiHelper.DangerText(_readError);
            }
        });

        ImGui.Spacing();

        if (_readResult.Length > 0)
        {
            UiHelper.SectionBox("RESULT", w, ImGui.GetContentRegionAvail().Y, () =>
            {
                // Hex dump
                UiHelper.MutedLabel("Hex dump:");
                ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.7f, 1f, 0.7f, 1f));
                for (int row = 0; row < _readResult.Length; row += 16)
                {
                    int    len  = Math.Min(16, _readResult.Length - row);
                    string hex  = string.Join(" ", _readResult.Skip(row).Take(len).Select(b => $"{b:X2}"));
                    string asc  = new string(_readResult.Skip(row).Take(len)
                        .Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
                    ImGui.Text($"  {row:X4}  {hex,-47}  {asc}");
                }
                ImGui.PopStyleColor();

                ImGui.Spacing();
                ImGui.Separator();
                ImGui.Spacing();

                // Interpret as various types
                UiHelper.MutedLabel("Interpreted values (at offset 0):");
                ImGui.Spacing();
                if (_readResult.Length >= 1)
                    RenderInterpRow("Byte",   _readResult[0].ToString(), "");
                if (_readResult.Length >= 2)
                    RenderInterpRow("Int16",  BitConverter.ToInt16(_readResult, 0).ToString(), "");
                if (_readResult.Length >= 4)
                {
                    RenderInterpRow("Int32",  BitConverter.ToInt32(_readResult, 0).ToString(), "");
                    RenderInterpRow("Float",  BitConverter.ToSingle(_readResult, 0).ToString("F4"), "");
                    RenderInterpRow("UInt32", BitConverter.ToUInt32(_readResult, 0).ToString(), "");
                }
                if (_readResult.Length >= 8)
                {
                    RenderInterpRow("Int64",  BitConverter.ToInt64(_readResult, 0).ToString(), "");
                    RenderInterpRow("Double", BitConverter.ToDouble(_readResult, 0).ToString("F6"), "");
                    RenderInterpRow("Ptr",    $"0x{BitConverter.ToInt64(_readResult, 0):X16}", "");
                }
                // ASCII string
                int end = Array.IndexOf(_readResult, (byte)0);
                bool allPrintable = _readResult.Take(end < 0 ? _readResult.Length : end)
                    .All(b => b >= 32 && b < 127);
                if (allPrintable && _readResult.Length > 0)
                {
                    string s = System.Text.Encoding.ASCII.GetString(
                        _readResult, 0, end < 0 ? _readResult.Length : end);
                    RenderInterpRow("String", $"\"{s}\"", "");
                }
            });
        }
    }

    private static void RenderInterpRow(string label, string value, string hint)
    {
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
        ImGui.Text($"  {label,-10}");
        ImGui.PopStyleColor();
        ImGui.SameLine();
        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
        ImGui.Text(value);
        ImGui.PopStyleColor();
        if (!string.IsNullOrEmpty(hint))
        {
            ImGui.SameLine(0, 12);
            UiHelper.MutedLabel(hint);
        }
    }

    private void DoRead()
    {
        _readError  = "";
        _readResult = Array.Empty<byte>();
        try
        {
            string clean = _readAddrHex.Replace("0x", "").Replace("0X", "").Trim();
            long   addr  = Convert.ToInt64(clean, 16);
            var    buf   = new byte[_readBytes];
            if (_reader.ReadBytes(new IntPtr(addr), buf))
                _readResult = buf;
            else
                _readError = "ReadProcessMemory failed — invalid address or no access.";
        }
        catch (Exception ex) { _readError = ex.Message; }
    }

    // ── Pattern Scan ──────────────────────────────────────────────────────

    private void RenderPatternScan(float w)
    {
        float half = (w - 12) * 0.5f;

        UiHelper.SectionBox("PATTERN INPUT", w, 110, () =>
        {
            UiHelper.MutedLabel("Hex bytes separated by spaces. Use ?? for wildcard.");
            UiHelper.MutedLabel("Example:  48 8B ?? 48 89 C3  or  01 00 ?? ?? 03");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(w - 200);
            ImGui.InputText("##mpat", ref _patternInput, 256);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(90);
            ImGui.InputInt("Max##mpatmax", ref _patternMax);
            _patternMax = Math.Clamp(_patternMax, 1, 2000);
            ImGui.SameLine(0, 8);

            ImGui.BeginDisabled(!_reader.IsAttached || _patternScanning);
            UiHelper.WarnButton(_patternScanning ? "Scanning..." : "Scan##mpatscan",
                100, 28, StartPatternScan);
            ImGui.EndDisabled();

            if (_patternScanning)
            {
                ImGui.SameLine(0, 12);
                ImGui.ProgressBar(_patternProgress / 100f, new Vector2(200, 20),
                    $"{_patternProgress}%");
            }
        });

        ImGui.Spacing();

        if (_patternResults.Count > 0)
            RenderScanResults(_patternResults, ref _patternSelected, w, "Pattern");
    }

    private void StartPatternScan()
    {
        if (string.IsNullOrWhiteSpace(_patternInput)) return;

        byte?[] pattern;
        try
        {
            pattern = _patternInput.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(t => t == "??" ? (byte?)null : (byte?)Convert.ToByte(t, 16))
                .ToArray();
        }
        catch { _log.Error("[Memory] Invalid pattern — use hex bytes like  48 8B ?? 48"); return; }

        _patternScanning = true;
        _patternResults.Clear();
        _patternProgress = 0;
        int max = _patternMax;

        _log.Info($"[Memory] Pattern scan started — {pattern.Length} bytes...");
        Task.Run(() =>
        {
            var prog = new Progress<int>(v => _patternProgress = v);
            _patternResults = _reader.ScanPattern(pattern, max, prog);
            _patternScanning = false;
            _log.Success($"[Memory] Pattern scan done — {_patternResults.Count} match(es).");
        });
    }

    // ── Value Scan ────────────────────────────────────────────────────────

    private void RenderValueScan(float w)
    {
        UiHelper.SectionBox("SCAN CONFIG", w, 160, () =>
        {
            UiHelper.MutedLabel("Scan all readable memory for int32 values in a range.");
            UiHelper.MutedLabel("Workflow:");
            UiHelper.MutedLabel("  1. Initial Scan — finds all addresses with value in [Min,Max]");
            UiHelper.MutedLabel("  2. Change the value in-game (pick up/drop item, change count)");
            UiHelper.MutedLabel("  3. Enter the new value in New min/max and click Rescan");
            UiHelper.MutedLabel("  4. Repeat until only 1-2 addresses remain — those are your targets");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(110); ImGui.InputInt("Min##vsmin", ref _vsMin);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(110); ImGui.InputInt("Max##vsmax", ref _vsMax);
            ImGui.SameLine(0, 16);

            ImGui.BeginDisabled(!_reader.IsAttached || _vsScanning);
            UiHelper.PrimaryButton(_vsScanning ? "Scanning..." : "Initial Scan##vsscan",
                140, 28, StartValueScan);
            ImGui.EndDisabled();

            if (_vsHasFirst)
            {
                ImGui.SameLine(0, 16);
                ImGui.SetNextItemWidth(110); ImGui.InputInt("New min##vrmin", ref _vsRescanMin);
                ImGui.SameLine(0, 8);
                ImGui.SetNextItemWidth(110); ImGui.InputInt("New max##vrmax", ref _vsRescanMax);
                ImGui.SameLine(0, 8);
                ImGui.BeginDisabled(!_reader.IsAttached || _vsScanning);
                UiHelper.WarnButton("Rescan##vsrescan", 90, 28, DoRescan);
                ImGui.EndDisabled();
                ImGui.SameLine(0, 8);
                UiHelper.DangerButton("Reset##vsreset", 70, 28, () =>
                {
                    _vsResults.Clear(); _vsPrevResults.Clear();
                    _vsHasFirst = false; _vsSelected = -1;
                    _log.Info("[Memory] Value scan reset.");
                });
            }

            if (_vsScanning)
            {
                ImGui.Spacing();
                ImGui.ProgressBar(_vsProgress / 100f, new Vector2(300, 20), $"{_vsProgress}%");
            }
        });

        ImGui.Spacing();

        if (_vsResults.Count > 0)
            RenderScanResults(_vsResults, ref _vsSelected, w, "Value");
    }

    private void StartValueScan()
    {
        _vsScanning = true;
        _vsResults.Clear();
        _vsProgress = 0;
        int min = _vsMin, max = _vsMax;
        _log.Info($"[Memory] Value scan [{min}–{max}] started...");
        Task.Run(() =>
        {
            var prog = new Progress<int>(v => _vsProgress = v);
            _vsResults     = _reader.ScanInt32Range(min, max, 500, prog);
            _vsPrevResults = new List<ScanMatch>(_vsResults);
            _vsHasFirst    = true;
            _vsScanning    = false;
            _log.Success($"[Memory] Initial scan done — {_vsResults.Count} result(s).");
        });
    }

    private void DoRescan()
    {
        _vsScanning = true;
        _vsProgress = 0;
        int min = _vsRescanMin, max = _vsRescanMax;
        var prev = new List<ScanMatch>(_vsResults);
        _log.Info($"[Memory] Rescan [{min}–{max}] across {prev.Count} addresses...");
        Task.Run(() =>
        {
            _vsResults  = _reader.RescanInt32(prev, min, max);
            _vsScanning = false;
            _log.Success($"[Memory] Rescan done — {_vsResults.Count} result(s) remain.");
        });
    }

    // ── Inventory Scan ────────────────────────────────────────────────────

    private void RenderInventoryScan(float w)
    {
        UiHelper.SectionBox("INVENTORY SCAN", w, 90, () =>
        {
            UiHelper.MutedLabel("Heuristic scan: finds clusters of int32 values that look like");
            UiHelper.MutedLabel("item ID (100–9999) + stack count + slot index in adjacent memory.");
            ImGui.Spacing();

            ImGui.BeginDisabled(!_reader.IsAttached || _invScanning);
            UiHelper.WarnButton(_invScanning ? "Scanning..." : "Run Inventory Scan##invscan",
                200, 30, StartInventoryScan);
            ImGui.EndDisabled();

            if (_invScanning)
            {
                ImGui.SameLine(0, 12);
                ImGui.ProgressBar(_invProgress / 100f, new Vector2(250, 22), $"{_invProgress}%");
            }
            else if (_invResults.Count > 0)
            {
                ImGui.SameLine(0, 16);
                UiHelper.AccentText($"{_invResults.Count} candidate(s) found.");
            }
        });

        ImGui.Spacing();

        if (_invResults.Count == 0) return;

        float listW = w * 0.5f;
        float detW  = w - listW - 8;
        float h     = ImGui.GetContentRegionAvail().Y;

        // List
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##invlist", new Vector2(listW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 6));
        UiHelper.MutedLabel("  ItemID   Stack  Slot   Address");
        ImGui.Separator();

        var dl = ImGui.GetWindowDrawList();
        var lp = ImGui.GetWindowPos();

        for (int i = 0; i < _invResults.Count; i++)
        {
            var c   = _invResults[i];
            bool sel = _invSelected == i;

            if (sel)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(listW, 20),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }

            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
            if (ImGui.Selectable(
                $"  {c.ItemId,-8} {c.StackCount,-6} {(c.SlotIndex >= 0 ? c.SlotIndex.ToString() : "?"),-6} {c.AddressHex}##inv{i}",
                sel, ImGuiSelectableFlags.None, new Vector2(0, 20)))
                _invSelected = i;
            ImGui.PopStyleColor();
        }

        ImGui.EndChild();
        ImGui.SameLine(0, 8);

        // Detail
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##invdet", new Vector2(detW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        if (_invSelected >= 0 && _invSelected < _invResults.Count)
        {
            var c = _invResults[_invSelected];
            ImGui.SetCursorPos(new Vector2(12, 10));
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
            ImGui.TextUnformatted("CANDIDATE DETAIL");
            ImGui.PopStyleColor();
            ImGui.Spacing();

            UiHelper.StatusRow("Address",  c.AddressHex, true, 90);
            UiHelper.StatusRow("Item ID",  c.ItemId.ToString(), true, 90);
            UiHelper.StatusRow("Stack",    c.StackCount.ToString(), true, 90);
            UiHelper.StatusRow("Slot",     c.SlotIndex >= 0 ? c.SlotIndex.ToString() : "unknown", true, 90);

            ImGui.Spacing();
            UiHelper.MutedLabel("Context bytes:");
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.7f, 1f, 0.7f, 1f));
            ImGui.TextUnformatted($"  {c.ContextHex}");
            ImGui.PopStyleColor();

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            UiHelper.SecondaryButton("Copy Address##invca", -1, 26, () =>
            {
                ImGui.SetClipboardText(c.AddressHex);
                _log.Info($"[Memory] Copied {c.AddressHex}");
            });
            ImGui.Spacing();
            UiHelper.SecondaryButton("Read 64b from here##invr", -1, 26, () =>
            {
                _readAddrHex = c.AddressHex;
                _readBytes   = 64;
                DoRead();
                _subTab = 1; // jump to Read tab
            });
            ImGui.Spacing();
            UiHelper.MutedLabel("Tip: cross-reference Item ID with");
            UiHelper.MutedLabel("what Item Inspector sees in packets.");
        }
        else
        {
            ImGui.SetCursorPosY(h * 0.4f);
            float tw = ImGui.CalcTextSize("← select a candidate").X;
            ImGui.SetCursorPosX((detW - tw) * 0.5f);
            UiHelper.MutedLabel("← select a candidate");
        }

        ImGui.EndChild();
    }

    private void StartInventoryScan()
    {
        _invScanning = true;
        _invResults.Clear();
        _invProgress = 0;
        _invSelected = -1;
        _log.Info("[Memory] Inventory scan started...");
        Task.Run(() =>
        {
            var prog = new Progress<int>(v => _invProgress = v);
            _invResults  = _reader.ScanInventory(prog);
            _invScanning = false;
            _log.Success($"[Memory] Inventory scan done — {_invResults.Count} candidate(s).");
        });
    }

    // ── Shared scan results renderer ──────────────────────────────────────

    private void RenderScanResults(List<ScanMatch> results, ref int selected,
                                    float w, string id)
    {
        float listW = w * 0.55f;
        float detW  = w - listW - 8;
        float h     = ImGui.GetContentRegionAvail().Y;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild($"##srlist{id}", new Vector2(listW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        ImGui.SetCursorPos(new Vector2(8, 6));
        UiHelper.MutedLabel($"  #     Address                Value    Context");
        ImGui.Separator();

        var dl = ImGui.GetWindowDrawList();
        var lp = ImGui.GetWindowPos();

        for (int i = 0; i < results.Count; i++)
        {
            var  r   = results[i];
            bool sel = selected == i;

            if (sel)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl.AddRectFilled(sp, sp + new Vector2(listW, 20),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }

            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
            if (ImGui.Selectable(
                $"  {i+1,-5} {r.AddressHex}  {r.Value,-8} {r.ContextHex}##{id}{i}",
                sel, ImGuiSelectableFlags.None, new Vector2(0, 20)))
                selected = i;
            ImGui.PopStyleColor();
        }

        ImGui.EndChild();
        ImGui.SameLine(0, 8);

        // Detail
        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild($"##srdet{id}", new Vector2(detW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        if (selected >= 0 && selected < results.Count)
        {
            var r = results[selected];
            ImGui.SetCursorPos(new Vector2(12, 10));
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
            ImGui.TextUnformatted("MATCH DETAIL");
            ImGui.PopStyleColor();
            ImGui.Spacing();

            UiHelper.StatusRow("Address", r.AddressHex, true, 80);
            UiHelper.StatusRow("Value",   r.Value.ToString(), true, 80);
            ImGui.Spacing();
            UiHelper.MutedLabel("Context bytes:");
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.7f, 1f, 0.7f, 1f));
            ImGui.TextUnformatted($"  {r.ContextHex}");
            ImGui.PopStyleColor();

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            UiHelper.SecondaryButton($"Copy Address##{id}ca", -1, 26, () =>
            {
                ImGui.SetClipboardText(r.AddressHex);
                _log.Info($"[Memory] Copied {r.AddressHex}");
            });
            ImGui.Spacing();
            UiHelper.SecondaryButton($"Read 64b here##{id}r64", -1, 26, () =>
            {
                _readAddrHex = r.AddressHex;
                _readBytes   = 64;
                DoRead();
                _subTab = 1;
            });

            // Live re-read
            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();
            UiHelper.MutedLabel("Live value:");
            if (_reader.IsAttached && _reader.ReadInt32(r.Address, out int live))
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                ImGui.TextUnformatted($"  int32 = {live}");
                ImGui.PopStyleColor();
            }
            else
                UiHelper.MutedLabel("  (not readable)");
        }
        else
        {
            ImGui.SetCursorPosY(h * 0.4f);
            float tw = ImGui.CalcTextSize("← select a result").X;
            ImGui.SetCursorPosX((detW - tw) * 0.5f);
            UiHelper.MutedLabel("← select a result");
        }

        ImGui.EndChild();
    }

    // ── AOB Scan ──────────────────────────────────────────────────────────

    private void RenderAobScan(float w)
    {
        UiHelper.SectionBox("AOB SIGNATURE SCAN", w, 160, () =>
        {
            UiHelper.MutedLabel("High-performance module scan using ReadOnlySpan. Fast zero-allocation search.");
            UiHelper.MutedLabel("Pattern: hex bytes with '??' wildcards — e.g.  48 8B ?? 48 89 C3 ?? 00");
            ImGui.Spacing();

            // Load modules
            if (_aobModules.Count == 0 && _reader.IsAttached)
                _aobModules = _reader.GetModules();

            ImGui.SetNextItemWidth(220);
            ImGui.InputText("Pattern##aobp", ref _aobPattern, 256);
            ImGui.SameLine(0, 10);

            ImGui.Checkbox("Scan all modules##aobam", ref _aobAllModules);
            ImGui.SameLine(0, 10);

            if (!_aobAllModules)
            {
                ImGui.SetNextItemWidth(200);
                if (ImGui.BeginCombo("Module##aobmod",
                    string.IsNullOrEmpty(_aobModule) ? "Select..." : _aobModule))
                {
                    foreach (var mod in _aobModules)
                        if (ImGui.Selectable($"{mod.Name}  ({mod.SizeStr})##aobsel{mod.Name}"))
                            _aobModule = mod.Name;
                    ImGui.EndCombo();
                }
                ImGui.SameLine(0, 8);
            }

            ImGui.BeginDisabled(!_reader.IsAttached || _aobScanning || string.IsNullOrWhiteSpace(_aobPattern));
            UiHelper.WarnButton(_aobScanning ? "Scanning..." : "Scan##aobscan", 90, 26, StartAobScan);
            ImGui.EndDisabled();

            if (!string.IsNullOrEmpty(_aobResult))
            {
                ImGui.Spacing();
                bool found = _aobResult.Contains("0x") && !_aobResult.StartsWith("Pattern not");
                ImGui.PushStyleColor(ImGuiCol.Text, found ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
                ImGui.TextUnformatted($"  {_aobResult}");
                ImGui.PopStyleColor();
            }
        });

        ImGui.Spacing();

        if (_aobMatches.Count > 0)
        {
            UiHelper.SectionBox($"RESULTS — {_aobMatches.Count} match(es)", w,
                ImGui.GetContentRegionAvail().Y, () =>
            {
                foreach (var m in _aobMatches)
                {
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
                    ImGui.TextUnformatted($"  {m.AddressHex}  [{m.Module}]");
                    ImGui.PopStyleColor();
                    ImGui.SameLine(0, 12);
                    UiHelper.SecondaryButton($"Read##aobr{m.AddressHex}", 50, 20, () =>
                    {
                        _readAddrHex = m.AddressHex;
                        _readBytes   = 64;
                        DoRead();
                        _subTab = 1;
                    });
                    ImGui.SameLine(0, 6);
                    UiHelper.SecondaryButton($"Copy##aobc{m.AddressHex}", 50, 20, () =>
                        ImGui.SetClipboardText(m.AddressHex));
                }
            });
        }

        // Module list
        ImGui.Spacing();
        if (_aobModules.Count > 0)
        {
            UiHelper.SectionBox($"LOADED MODULES — {_aobModules.Count}", w, 180, () =>
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
                ImGui.BeginChild("##aobmods", new Vector2(-1, -1), ImGuiChildFlags.Border);
                ImGui.PopStyleColor();
                UiHelper.MutedLabel("  Name                                Base                Size");
                ImGui.Separator();
                foreach (var mod in _aobModules)
                {
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                    ImGui.TextUnformatted($"  {mod.Name,-36} {mod.BaseHex}  {mod.SizeStr}");
                    ImGui.PopStyleColor();
                }
                ImGui.EndChild();
            });
        }
    }

    private void StartAobScan()
    {
        _aobScanning = true;
        _aobMatches.Clear();
        _aobResult  = "";
        _log.Info($"[AOB] Scanning for: {_aobPattern}");
        Task.Run(() =>
        {
            if (_aobAllModules)
            {
                _aobMatches  = _reader.AobScanAllModules(_aobPattern);
                _aobResult   = $"{_aobMatches.Count} match(es) across all modules.";
            }
            else
            {
                var addr = _reader.AobScanModule(_aobModule, _aobPattern, out string diag);
                _aobResult = diag;
                if (addr != IntPtr.Zero)
                    _aobMatches.Add(new AobMatch { Address = addr, Module = _aobModule, Diagnostic = diag });
            }
            _aobScanning = false;
            _log.Success($"[AOB] Done: {_aobResult}");
        });
    }

    // ── Memory Map ────────────────────────────────────────────────────────

    private void RenderMemoryMap(float w)
    {
        UiHelper.SectionBox("MEMORY MAP", w, 40, () =>
        {
            ImGui.BeginDisabled(!_reader.IsAttached);
            UiHelper.SecondaryButton("Refresh Map##mmref", 130, 26, () =>
            {
                _memMap      = _reader.GetMemoryMap();
                _memMapLoaded = true;
                _memMapSel   = -1;
                _log.Info($"[MemMap] {_memMap.Count} regions loaded.");
            });
            ImGui.EndDisabled();
            ImGui.SameLine(0, 12);
            ImGui.Checkbox("Readable only##mmro", ref _memMapOnlyR);
            ImGui.SameLine(0, 10);
            ImGui.SetNextItemWidth(150);
            ImGui.InputText("Filter type##mmflt", ref _memMapFilter, 32);
            if (_memMapLoaded)
            {
                ImGui.SameLine(0, 16);
                UiHelper.MutedLabel($"{_memMap.Count} regions total");
            }
        });

        ImGui.Spacing();

        if (!_memMapLoaded) { UiHelper.MutedLabel("  Click Refresh Map to load."); return; }

        var show = _memMap.Where(r =>
            (!_memMapOnlyR || r.Readable) &&
            (string.IsNullOrEmpty(_memMapFilter) ||
             r.Type.Contains(_memMapFilter, StringComparison.OrdinalIgnoreCase) ||
             r.Protect.Contains(_memMapFilter, StringComparison.OrdinalIgnoreCase))
        ).ToList();

        float listW = w * 0.65f;
        float detW  = w - listW - 8;
        float h     = ImGui.GetContentRegionAvail().Y;

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##mmlist", new Vector2(listW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        UiHelper.MutedLabel("  Base                     Size     State    Prot   Type");
        ImGui.Separator();

        var dl2 = ImGui.GetWindowDrawList();
        for (int i = 0; i < show.Count; i++)
        {
            var r   = show[i];
            bool sel = _memMapSel == i;
            if (sel)
            {
                var sp = ImGui.GetCursorScreenPos();
                dl2.AddRectFilled(sp, sp + new Vector2(listW, 18),
                    ImGui.ColorConvertFloat4ToU32(MenuRenderer.ColAccentDim));
            }
            var col = r.Protect == "RWX" ? MenuRenderer.ColDanger
                    : r.Protect == "RW-" ? MenuRenderer.ColWarn
                    : r.Readable         ? MenuRenderer.ColAccent
                    :                      MenuRenderer.ColTextMuted;
            ImGui.PushStyleColor(ImGuiCol.Text, col);
            if (ImGui.Selectable(
                $"  {r.BaseHex}  {r.SizeStr,-8} {r.State,-8} {r.Protect,-6} {r.Type}##mm{i}",
                sel, ImGuiSelectableFlags.None, new Vector2(0, 18)))
                _memMapSel = i;
            ImGui.PopStyleColor();
        }
        ImGui.EndChild();
        ImGui.SameLine(0, 8);

        ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
        ImGui.BeginChild("##mmdet", new Vector2(detW, h), ImGuiChildFlags.Border);
        ImGui.PopStyleColor();

        if (_memMapSel >= 0 && _memMapSel < show.Count)
        {
            var r = show[_memMapSel];
            ImGui.SetCursorPos(new Vector2(10, 8));
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccentMid);
            ImGui.TextUnformatted("REGION DETAIL");
            ImGui.PopStyleColor();
            ImGui.Spacing();
            UiHelper.StatusRow("Base",    r.BaseHex,  true, 70);
            UiHelper.StatusRow("Size",    r.SizeStr,  true, 70);
            UiHelper.StatusRow("State",   r.State,    true, 70);
            UiHelper.StatusRow("Protect", r.Protect,  r.Readable, 70);
            UiHelper.StatusRow("Type",    r.Type,     true, 70);
            ImGui.Spacing();
            if (r.Readable)
            {
                UiHelper.SecondaryButton("Read 64b##mmrd", -1, 26, () =>
                {
                    _readAddrHex = r.BaseHex;
                    _readBytes   = 64;
                    DoRead();
                    _subTab = 1;
                });
            }
        }
        else
        {
            ImGui.SetCursorPosY(h * 0.45f);
            float tw = ImGui.CalcTextSize("← select region").X;
            ImGui.SetCursorPosX((detW - tw) * 0.5f);
            UiHelper.MutedLabel("← select region");
        }
        ImGui.EndChild();
    }

    // ── Pointer Path ──────────────────────────────────────────────────────

    private void RenderPointerPath(float w)
    {
        UiHelper.SectionBox("POINTER CHAIN RESOLVER", w, 190, () =>
        {
            UiHelper.MutedLabel("Resolve a multi-level pointer chain: base → deref → +offset → deref → ...");
            UiHelper.MutedLabel("Use this when the target data structure is dynamic (address changes each session).");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(260);
            ImGui.InputText("Base address (hex)##ppbase", ref _ppBase, 32);
            ImGui.SameLine(0, 10);
            UiHelper.MutedLabel("e.g. module base + 0x1A2B3C");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Offsets (space-separated hex)##ppoff", ref _ppOffsets, 256);
            UiHelper.MutedLabel("e.g.  0x8 0x10 0x30   (applied after each dereference)");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(100);
            ImGui.InputInt("Read bytes##pprbyt", ref _ppReadBytes);
            _ppReadBytes = Math.Clamp(_ppReadBytes, 1, 1024);
            ImGui.SameLine(0, 8);

            ImGui.BeginDisabled(!_reader.IsAttached);
            UiHelper.PrimaryButton("Resolve + Read##ppres", 140, 28, DoResolvePointerChain);
            ImGui.EndDisabled();

            if (!string.IsNullOrEmpty(_ppResult))
            {
                ImGui.Spacing();
                bool ok = _ppResult.StartsWith("Resolved");
                ImGui.PushStyleColor(ImGuiCol.Text, ok ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
                ImGui.TextUnformatted($"  {_ppResult}");
                ImGui.PopStyleColor();
            }
        });

        ImGui.Spacing();

        if (!string.IsNullOrEmpty(_ppTrace))
        {
            UiHelper.SectionBox("RESOLUTION TRACE", w, 200, () =>
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                foreach (var line in _ppTrace.Split('\n'))
                {
                    if (!string.IsNullOrEmpty(line))
                        ImGui.TextUnformatted(line);
                }
                ImGui.PopStyleColor();
            });
        }

        ImGui.Spacing();

        if (_ppReadResult.Length > 0)
        {
            UiHelper.SectionBox("DATA AT RESOLVED ADDRESS", w, ImGui.GetContentRegionAvail().Y, () =>
            {
                for (int row = 0; row < _ppReadResult.Length; row += 16)
                {
                    int    len = Math.Min(16, _ppReadResult.Length - row);
                    string hex = string.Join(" ", _ppReadResult.Skip(row).Take(len).Select(b => $"{b:X2}"));
                    string asc = new string(_ppReadResult.Skip(row).Take(len)
                        .Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
                    ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.7f, 1f, 0.7f, 1f));
                    ImGui.Text($"  {row:X4}  {hex,-47}  {asc}");
                    ImGui.PopStyleColor();
                }
            });
        }
    }

    private void DoResolvePointerChain()
    {
        _ppResult     = "";
        _ppTrace      = "";
        _ppReadResult = Array.Empty<byte>();
        try
        {
            string baseClean = _ppBase.Replace("0x", "").Replace("0X", "").Trim();
            long   baseAddr  = Convert.ToInt64(baseClean, 16);

            int[] offsets = _ppOffsets.Trim()
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(t =>
                {
                    t = t.Replace("0x", "").Replace("0X", "");
                    return Convert.ToInt32(t, 16);
                })
                .ToArray();

            var final = _reader.ResolvePointerChain(new IntPtr(baseAddr), offsets, out string trace);
            _ppTrace = trace;

            if (final == IntPtr.Zero)
            {
                _ppResult = "Failed — see trace for details.";
                return;
            }

            _ppResult = $"Resolved → 0x{final.ToInt64():X16}";
            _log.Success($"[PtrPath] {_ppResult}");

            var buf = new byte[_ppReadBytes];
            if (_reader.ReadBytes(final, buf))
                _ppReadResult = buf;
            else
                _ppResult += "  (read failed)";
        }
        catch (Exception ex)
        {
            _ppResult = $"Error: {ex.Message}";
        }
    }
    {
        _refreshing = true;
        Task.Run(() =>
        {
            _processes  = MemoryReader.GetProcessList();
            _refreshing = false;
            _log.Info($"[Memory] Process list refreshed — {_processes.Count} processes.");
        });
    }
}
