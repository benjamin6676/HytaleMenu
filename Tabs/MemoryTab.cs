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
          "AOB Scan", "Memory Map", "Pointer Path",
          "String Scan", "VTable", "Breakpoints", "Ptr Tree", "CT Import", "Correlator" };

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

    private readonly PacketStore  _store;
    private LiveMemoryCorrelator? _correlator;

    public MemoryTab(TestLog log, PacketStore store)
    {
        _log   = log;
        _store = store;
        _correlator = new LiveMemoryCorrelator(log, store, _reader);
    }

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
            case 8: RenderStringScan(w);    break;
            case 9: RenderVTable(w);        break;
            case 10: RenderBreakpoints(w);  break;
            case 11: RenderPointerTree(w);  break;
            case 12: RenderCtImport(w);     break;
            case 13: RenderCorrelator(w);   break;
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
    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB 8: STRING-TO-POINTER SCANNER
    // ══════════════════════════════════════════════════════════════════════

    private string            _ssFilter    = "";
    private int               _ssMinLen    = 4;
    private int               _ssMaxLen    = 64;
    private bool              _ssUtf8      = true;
    private bool              _ssUtf16     = true;
    private bool              _ssScanning  = false;
    private List<StringMatch> _ssResults   = new();
    private string            _ssStatus    = "";

    private void RenderStringScan(float w)
    {
        UiHelper.SectionBox("STRING-TO-POINTER SCANNER", w, 130, () =>
        {
            UiHelper.MutedLabel("Scans all readable heap memory for UTF-8 and UTF-16 strings.");
            UiHelper.MutedLabel("Use the filter to find custom item names, entity names, or protocol strings.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(90); ImGui.InputInt("Min len##ssmin", ref _ssMinLen);
            _ssMinLen = Math.Clamp(_ssMinLen, 1, 256);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(90); ImGui.InputInt("Max len##ssmax", ref _ssMaxLen);
            _ssMaxLen = Math.Clamp(_ssMaxLen, _ssMinLen, 512);
            ImGui.SameLine(0, 12);
            ImGui.Checkbox("UTF-8##ssu8",   ref _ssUtf8);
            ImGui.SameLine(0, 8);
            ImGui.Checkbox("UTF-16##ssu16", ref _ssUtf16);
            ImGui.Spacing();

            ImGui.SetNextItemWidth(300); ImGui.InputText("Filter##ssf", ref _ssFilter, 128);
            ImGui.SameLine(0, 8);
            ImGui.BeginDisabled(!_reader.IsAttached || _ssScanning);
            UiHelper.WarnButton(_ssScanning ? "Scanning...##ssscan" : "Scan##ssscan",
                90, 26, StartStringScan);
            ImGui.EndDisabled();

            if (_ssStatus.Length > 0)
            {
                ImGui.Spacing();
                ImGui.PushStyleColor(ImGuiCol.Text,
                    _ssStatus.StartsWith("Done") ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);
                ImGui.TextUnformatted($"  {_ssStatus}");
                ImGui.PopStyleColor();
            }
        });

        if (_ssResults.Count > 0)
        {
            ImGui.Spacing();
            float resultsH = ImGui.GetContentRegionAvail().Y;
            ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
            ImGui.BeginChild("##ssres", new Vector2(w, resultsH), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();

            UiHelper.MutedLabel($"  {"Address",-20} {"Enc",-8} {"Len",-6} {"Value"}");
            ImGui.Separator();

            var filtered = string.IsNullOrEmpty(_ssFilter)
                ? _ssResults
                : _ssResults.Where(r => r.Value.Contains(_ssFilter,
                    StringComparison.OrdinalIgnoreCase)).ToList();

            foreach (var m in filtered.Take(500))
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
                ImGui.TextUnformatted($"  {m.AddressHex,-20} {m.Encoding,-8} {m.Length,-6}");
                ImGui.PopStyleColor();
                ImGui.SameLine(0, 6);
                UiHelper.MutedLabel(m.Value.Length > 80 ? m.Value[..80] + "…" : m.Value);
                ImGui.SameLine(0, 8);
                ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                if (ImGui.Button($"Read##ssr{m.AddressHex}", new Vector2(44, 18)))
                {
                    _readAddrHex = m.AddressHex;
                    _readBytes   = m.Length + 8;
                    DoRead();
                    _subTab = 1;
                }
                ImGui.PopStyleColor(2);
            }

            ImGui.EndChild();
        }
    }

    private void StartStringScan()
    {
        _ssScanning = true;
        _ssResults.Clear();
        _ssStatus = "Scanning...";
        _log.Info("[StringScan] Starting scan...");
        var progress = new Progress<int>(p => _ssStatus = $"Scanning... {p}%");

        Task.Run(() =>
        {
            _ssResults = _reader.ScanStrings(_ssMinLen, _ssMaxLen, 3000, progress);
            _ssScanning = false;
            _ssStatus = $"Done — {_ssResults.Count} strings found.";
            _log.Success($"[StringScan] {_ssResults.Count} strings found.");
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB 9: VTABLE RESOLVER
    // ══════════════════════════════════════════════════════════════════════

    private string    _vtObjAddr  = "";
    private int       _vtMaxMethods = 32;
    private VTableInfo? _vtResult  = null;

    private void RenderVTable(float w)
    {
        UiHelper.SectionBox("VTABLE RESOLVER", w, 120, () =>
        {
            UiHelper.MutedLabel("Reads the vtable pointer at the given object address, then walks up to N");
            UiHelper.MutedLabel("function pointer slots and resolves each to [module + offset].");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(260); ImGui.InputText("Object address##vto", ref _vtObjAddr, 32);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(90);  ImGui.InputInt("Max methods##vtmm", ref _vtMaxMethods);
            _vtMaxMethods = Math.Clamp(_vtMaxMethods, 1, 256);
            ImGui.SameLine(0, 8);
            ImGui.BeginDisabled(!_reader.IsAttached || string.IsNullOrWhiteSpace(_vtObjAddr));
            UiHelper.WarnButton("Resolve##vtres", 90, 26, DoResolveVTable);
            ImGui.EndDisabled();
        });

        if (_vtResult != null)
        {
            ImGui.Spacing();
            if (_vtResult.Error.Length > 0)
            {
                UiHelper.SectionBox("ERROR", w, 50, () =>
                {
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
                    ImGui.TextUnformatted($"  {_vtResult.Error}");
                    ImGui.PopStyleColor();
                });
            }
            else
            {
                UiHelper.SectionBox($"VTABLE @ 0x{_vtResult.VTableAddress.ToInt64():X16}" +
                                    $"  —  {_vtResult.Methods.Count} method(s)", w,
                    ImGui.GetContentRegionAvail().Y, () =>
                {
                    UiHelper.MutedLabel($"  {"Slot",-6} {"Address",-22} {"Module",-28} {"Offset"}");
                    ImGui.Separator();
                    foreach (var m in _vtResult.Methods)
                    {
                        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColAccent);
                        ImGui.TextUnformatted(
                            $"  [{m.Index,-3}] {m.AddressHex,-22} {m.Module,-28} {m.OffsetHex}");
                        ImGui.PopStyleColor();
                        ImGui.SameLine(0, 8);
                        ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
                        ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                        if (ImGui.Button($"Copy##vtc{m.Index}", new Vector2(44, 18)))
                            ImGui.SetClipboardText($"{m.Module} {m.OffsetHex}");
                        ImGui.PopStyleColor(2);
                    }
                });
            }
        }
    }

    private void DoResolveVTable()
    {
        try
        {
            string clean = _vtObjAddr.Replace("0x", "").Replace("0X", "").Trim();
            long addr = Convert.ToInt64(clean, 16);
            _vtResult = _reader.ResolveVTable(new IntPtr(addr), _vtMaxMethods);
            if (_vtResult.Error.Length > 0)
                _log.Error($"[VTable] {_vtResult.Error}");
            else
                _log.Success($"[VTable] Resolved {_vtResult.Methods.Count} methods from " +
                             $"0x{_vtResult.VTableAddress.ToInt64():X16}");
        }
        catch (Exception ex) { _log.Error($"[VTable] {ex.Message}"); }
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB 10: HARDWARE BREAKPOINT MONITOR
    // ══════════════════════════════════════════════════════════════════════

    private string              _bpWatchAddr   = "";
    private int                 _bpSlot        = 0;
    private string              _bpStatus      = "";
    private List<BreakpointHit> _bpHits        = new();
    private bool                _bpPolling     = false;
    private CancellationTokenSource? _bpCts;

    private void RenderBreakpoints(float w)
    {
        UiHelper.SectionBox("HARDWARE BREAKPOINT MONITOR", w, 140, () =>
        {
            UiHelper.MutedLabel("Sets a CPU-level hardware write breakpoint on the target address (DR0–DR3).");
            UiHelper.MutedLabel("Polls all threads for DR6 hit status to log which functions write to that address.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(260); ImGui.InputText("Watch address##bpwa", ref _bpWatchAddr, 32);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(60);  ImGui.InputInt("Slot##bpsl", ref _bpSlot);
            _bpSlot = Math.Clamp(_bpSlot, 0, 3);
            ImGui.Spacing();

            ImGui.BeginDisabled(!_reader.IsAttached || string.IsNullOrWhiteSpace(_bpWatchAddr));
            UiHelper.WarnButton("Set Breakpoint##bpset", 150, 26, SetBreakpoint);
            ImGui.EndDisabled();
            ImGui.SameLine(0, 8);
            UiHelper.SecondaryButton("Clear All##bpclr", 100, 26, ClearBreakpoints);
            ImGui.SameLine(0, 8);

            if (_bpPolling)
            {
                UiHelper.DangerButton("Stop Poll##bpstopoll", 100, 26, () =>
                {
                    _bpCts?.Cancel(); _bpPolling = false;
                });
            }
            else
            {
                ImGui.BeginDisabled(!_reader.IsAttached);
                UiHelper.SecondaryButton("Start Poll##bpoll", 100, 26, StartBpPoll);
                ImGui.EndDisabled();
            }

            if (_bpStatus.Length > 0)
            {
                ImGui.Spacing();
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColBlue);
                ImGui.TextUnformatted($"  {_bpStatus}");
                ImGui.PopStyleColor();
            }
        });

        if (_bpHits.Count > 0)
        {
            ImGui.Spacing();
            UiHelper.SectionBox($"HITS — {_bpHits.Count}", w, ImGui.GetContentRegionAvail().Y, () =>
            {
                UiHelper.MutedLabel($"  {"Time",-12} {"Thread",-10} {"Slot"}");
                ImGui.Separator();
                foreach (var h in _bpHits.TakeLast(50).Reverse())
                {
                    ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColWarn);
                    ImGui.TextUnformatted(
                        $"  {h.Timestamp:HH:mm:ss.fff}  TID={h.ThreadId,-8} DR{h.Slot}");
                    ImGui.PopStyleColor();
                }
            });
        }
    }

    private void SetBreakpoint()
    {
        try
        {
            string clean = _bpWatchAddr.Replace("0x","").Replace("0X","").Trim();
            long addr = Convert.ToInt64(clean, 16);
            _bpStatus = _reader.SetHardwareBreakpoint(new IntPtr(addr), _bpSlot);
            _log.Info($"[BP] {_bpStatus}");
        }
        catch (Exception ex) { _bpStatus = $"Error: {ex.Message}"; }
    }

    private void ClearBreakpoints()
    {
        _bpStatus = _reader.ClearHardwareBreakpoints();
        _log.Info($"[BP] {_bpStatus}");
    }

    private void StartBpPoll()
    {
        _bpPolling = true;
        _bpCts     = new CancellationTokenSource();
        var cts    = _bpCts;
        Task.Run(async () =>
        {
            _log.Info("[BP] Polling started (250ms interval)...");
            while (!cts.Token.IsCancellationRequested)
            {
                var hits = _reader.PollBreakpointHits();
                if (hits.Count > 0)
                {
                    lock (_bpHits) _bpHits.AddRange(hits);
                    _log.Warn($"[BP] {hits.Count} hit(s) detected!");
                }
                await Task.Delay(250, cts.Token).ContinueWith(_ => { });
            }
            _bpPolling = false;
            _log.Info("[BP] Polling stopped.");
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB 11: POINTER TREE VIEW
    // ══════════════════════════════════════════════════════════════════════

    private string              _ptBaseAddr    = "";
    private int                 _ptDepth       = 3;
    private int                 _ptMaxChildren = 8;
    private List<PointerNode>   _ptRoots       = new();
    private bool                _ptBuilding    = false;

    private void RenderPointerTree(float w)
    {
        UiHelper.SectionBox("POINTER TREE VIEW", w, 130, () =>
        {
            UiHelper.MutedLabel("Starting from a base address, dereferences pointer chains to build a tree.");
            UiHelper.MutedLabel("Visualizes nested memory structures — entities → components → fields.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(260); ImGui.InputText("Root address##ptba", ref _ptBaseAddr, 32);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(70); ImGui.InputInt("Depth##ptd", ref _ptDepth);
            _ptDepth = Math.Clamp(_ptDepth, 1, 6);
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(70); ImGui.InputInt("Width##ptw", ref _ptMaxChildren);
            _ptMaxChildren = Math.Clamp(_ptMaxChildren, 1, 32);
            ImGui.SameLine(0, 8);
            ImGui.BeginDisabled(!_reader.IsAttached || string.IsNullOrWhiteSpace(_ptBaseAddr) || _ptBuilding);
            UiHelper.WarnButton(_ptBuilding ? "Building...##ptbld" : "Build Tree##ptbld",
                110, 26, BuildPointerTree);
            ImGui.EndDisabled();
        });

        if (_ptRoots.Count > 0)
        {
            ImGui.Spacing();
            float treeH = ImGui.GetContentRegionAvail().Y;
            ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
            ImGui.BeginChild("##pttree", new Vector2(w, treeH), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();

            foreach (var root in _ptRoots)
                RenderPointerNode(root, 0);

            ImGui.EndChild();
        }
    }

    private void RenderPointerNode(PointerNode node, int depth)
    {
        string indent  = new string(' ', depth * 4);
        string addrStr = $"0x{node.Address.ToInt64():X16}";
        string valStr  = node.IsValid
            ? $"→ 0x{node.DereferencedValue:X16}  [{node.BytePreview}]"
            : "(unreadable)";

        bool hasChildren = node.Children.Count > 0;

        ImGui.PushStyleColor(ImGuiCol.Text,
            node.IsValid ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);

        if (hasChildren)
        {
            bool open = ImGui.TreeNodeEx(
                $"{indent}{addrStr}  {valStr}##ptn{addrStr}{depth}",
                ImGuiTreeNodeFlags.OpenOnArrow);
            ImGui.PopStyleColor();
            if (open)
            {
                foreach (var child in node.Children)
                    RenderPointerNode(child, depth + 1);
                ImGui.TreePop();
            }
        }
        else
        {
            ImGui.TextUnformatted($"  {indent}{addrStr}  {valStr}");
            ImGui.PopStyleColor();
        }

        // Inline Read button
        if (node.IsValid)
        {
            ImGui.SameLine(0, 8);
            ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
            if (ImGui.Button($"R##ptnr{addrStr}{depth}", new Vector2(22, 16)))
            {
                _readAddrHex = addrStr;
                _readBytes   = 64;
                DoRead();
                _subTab = 1;
            }
            ImGui.PopStyleColor(2);
        }
    }

    private void BuildPointerTree()
    {
        _ptBuilding = true;
        _ptRoots.Clear();
        Task.Run(() =>
        {
            try
            {
                string clean = _ptBaseAddr.Replace("0x","").Replace("0X","").Trim();
                long   root  = Convert.ToInt64(clean, 16);
                _ptRoots = BuildNodeChildren(new IntPtr(root), 0, _ptDepth, _ptMaxChildren);
                _log.Success($"[PtrTree] Built from 0x{root:X16} depth={_ptDepth}");
            }
            catch (Exception ex) { _log.Error($"[PtrTree] {ex.Message}"); }
            finally { _ptBuilding = false; }
        });
    }

    private List<PointerNode> BuildNodeChildren(IntPtr addr, int depth, int maxDepth, int maxW)
    {
        var nodes = new List<PointerNode>();
        if (depth >= maxDepth) return nodes;

        // Read up to maxW pointer slots (8 bytes each) starting at addr
        for (int i = 0; i < maxW; i++)
        {
            var slotAddr = IntPtr.Add(addr, i * 8);
            var node     = new PointerNode { Address = slotAddr };

            if (_reader.ReadInt64(slotAddr, out long ptrVal) && ptrVal != 0
                && ptrVal > 0x10000 && ptrVal < 0x7FFFFFFFFFFF)
            {
                node.IsValid            = true;
                node.DereferencedValue  = ptrVal;

                // Read 8 bytes at the pointer for preview
                var preview = new byte[8];
                if (_reader.ReadBytes(new IntPtr(ptrVal), preview))
                    node.BytePreview = string.Join(" ", preview.Select(b => $"{b:X2}"));

                // Recurse
                node.Children = BuildNodeChildren(new IntPtr(ptrVal), depth + 1, maxDepth, maxW);
            }

            nodes.Add(node);
        }
        return nodes;
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB 12: CHEAT ENGINE .CT / XML SCHEMA IMPORT
    // ══════════════════════════════════════════════════════════════════════

    private string         _ctFilePath  = "";
    private List<CtEntry>  _ctEntries   = new();
    private string         _ctStatus    = "";
    private bool           _ctLiveRead  = false;
    private string         _ctFilter    = "";

    private void RenderCtImport(float w)
    {
        UiHelper.SectionBox("CHEAT ENGINE .CT / XML SCHEMA IMPORT", w, 90, () =>
        {
            UiHelper.MutedLabel("Import a .CT or .XML memory map. Resolves addresses and reads live values.");
            UiHelper.MutedLabel("Supports module-relative addresses (e.g. game.exe+1A2B3C) and pointer chains.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("File path##ctfp", ref _ctFilePath, 512);
            UiHelper.MutedLabel("Drag & drop a .ct or .xml file path above, or type the full path.");
            ImGui.Spacing();

            UiHelper.PrimaryButton("Load File##ctload", 120, 28, LoadCtFile);
            ImGui.SameLine(0, 8);
            ImGui.Checkbox("Live read##ctlive", ref _ctLiveRead);
            ImGui.SameLine(0, 8);
            if (_ctLiveRead && _reader.IsAttached)
                UiHelper.SecondaryButton("Refresh Values##ctref", 140, 28, RefreshCtValues);

            if (_ctStatus.Length > 0)
            {
                ImGui.SameLine(0, 12);
                ImGui.PushStyleColor(ImGuiCol.Text, _ctStatus.StartsWith("Loaded")
                    ? MenuRenderer.ColAccent : MenuRenderer.ColDanger);
                ImGui.TextUnformatted(_ctStatus);
                ImGui.PopStyleColor();
            }
        });

        if (_ctEntries.Count > 0)
        {
            ImGui.Spacing();

            ImGui.SetNextItemWidth(300);
            ImGui.InputText("Filter##ctfilt", ref _ctFilter, 64);
            ImGui.SameLine(0, 8);
            UiHelper.MutedLabel($"{_ctEntries.Count} entries loaded");

            ImGui.Spacing();
            float tblH = ImGui.GetContentRegionAvail().Y;
            ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
            ImGui.BeginChild("##cttbl", new Vector2(w, tblH), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();

            UiHelper.MutedLabel($"  {"Description",-32} {"Type",-12} {"Address",-20} {"Offsets",-24} {"Value"}");
            ImGui.Separator();

            var filtered = string.IsNullOrEmpty(_ctFilter)
                ? _ctEntries
                : _ctEntries.Where(e => e.Description.Contains(_ctFilter,
                    StringComparison.OrdinalIgnoreCase)).ToList();

            foreach (var e in filtered)
            {
                bool en = e.Enabled;
                if (ImGui.Checkbox($"##cten{e.Description.GetHashCode()}", ref en)) e.Enabled = en;
                ImGui.SameLine(0, 4);

                ImGui.PushStyleColor(ImGuiCol.Text,
                    e.Enabled ? MenuRenderer.ColAccent : MenuRenderer.ColTextMuted);

                string addrStr = e.IsModuleRelative
                    ? $"{e.ModuleName}+{e.BaseOffset:X}"
                    : $"0x{e.AbsoluteAddress.ToInt64():X}";
                string offStr  = e.Offsets.Count > 0
                    ? string.Join(",", e.Offsets.Select(o => $"{o:X}"))
                    : "";
                string valStr  = e.LiveValue.Length > 0 ? e.LiveValue : "—";

                ImGui.TextUnformatted(
                    $"  {e.Description[..Math.Min(30, e.Description.Length)],-32}" +
                    $" {e.VariableType,-12} {addrStr,-20} {offStr,-24} {valStr}");
                ImGui.PopStyleColor();
            }

            ImGui.EndChild();
        }
    }

    private void LoadCtFile()
    {
        if (string.IsNullOrWhiteSpace(_ctFilePath))
        { _ctStatus = "Enter a file path first."; return; }

        try
        {
            _ctEntries = MemoryReader.LoadCheatTable(_ctFilePath);
            _ctStatus  = $"Loaded {_ctEntries.Count} entries from {Path.GetFileName(_ctFilePath)}";
            _log.Success($"[CT] {_ctStatus}");
        }
        catch (Exception ex) { _ctStatus = $"Error: {ex.Message}"; _log.Error($"[CT] {ex.Message}"); }
    }

    private void RefreshCtValues()
    {
        if (!_reader.IsAttached) return;
        var mods = _reader.GetModules();

        foreach (var e in _ctEntries.Where(e => e.Enabled))
        {
            try
            {
                IntPtr baseAddr;
                if (e.IsModuleRelative)
                {
                    var mod = mods.FirstOrDefault(m =>
                        m.Name.Equals(e.ModuleName, StringComparison.OrdinalIgnoreCase));
                    if (mod == null) { e.LiveValue = "(mod not found)"; continue; }
                    baseAddr = IntPtr.Add(mod.Base, (int)e.BaseOffset);
                }
                else baseAddr = e.AbsoluteAddress;

                // Follow pointer chain
                IntPtr addr = e.Offsets.Count > 0
                    ? _reader.ResolvePointerChain(baseAddr, e.Offsets.ToArray(), out _)
                    : baseAddr;

                if (addr == IntPtr.Zero) { e.LiveValue = "(resolve failed)"; continue; }

                e.LiveValue = e.VariableType.ToLower() switch
                {
                    "float"   => _reader.ReadFloat(addr, out float f) ? $"{f:F4}" : "?",
                    "4 bytes" => _reader.ReadInt32(addr, out int v32) ? $"{v32}" : "?",
                    "8 bytes" => _reader.ReadInt64(addr, out long v64) ? $"{v64}" : "?",
                    _         => _reader.ReadInt32(addr, out int vi)  ? $"{vi}" : "?",
                };
            }
            catch { e.LiveValue = "(error)"; }
        }

        _log.Info($"[CT] Values refreshed for {_ctEntries.Count(e => e.Enabled)} entries.");
    }

    // ══════════════════════════════════════════════════════════════════════
    // SUB-TAB 13: LIVE MEMORY CORRELATOR
    // ══════════════════════════════════════════════════════════════════════

    private string   _corrWatchAddr  = "";
    private string   _corrWatchLabel = "";
    private WatchSize _corrWatchSize = WatchSize.Int32;
    private int      _corrPollMs    = 150;
    private int      _corrWindowMs  = 800;

    private void RenderCorrelator(float w)
    {
        float half = (w - 12) * 0.5f;

        UiHelper.SectionBox("LIVE MEMORY CORRELATOR", w, 80, () =>
        {
            UiHelper.MutedLabel("Monitors PacketStore for new entries and cross-references memory value");
            UiHelper.MutedLabel("changes in the target process to find dynamic offsets for player attributes.");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(90); ImGui.InputInt("Poll ms##corrpl", ref _corrPollMs);
            _corrPollMs = Math.Clamp(_corrPollMs, 50, 5000);
            if (_correlator != null) _correlator.PollIntervalMs = _corrPollMs;
            ImGui.SameLine(0, 8);
            ImGui.SetNextItemWidth(90); ImGui.InputInt("Window ms##corrwm", ref _corrWindowMs);
            _corrWindowMs = Math.Clamp(_corrWindowMs, 50, 5000);
            if (_correlator != null) _correlator.WindowMs = _corrWindowMs;
        });

        // Watch address adder
        UiHelper.SectionBox("WATCH LIST", half, 120, () =>
        {
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Address##corrwa", ref _corrWatchAddr, 32);
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("Label##corrwl", ref _corrWatchLabel, 64);

            var sizeNames = Enum.GetNames<WatchSize>();
            int sizeIdx   = (int)_corrWatchSize;
            ImGui.SetNextItemWidth(100);
            if (ImGui.BeginCombo("Size##corrws", sizeNames[sizeIdx]))
            {
                for (int i = 0; i < sizeNames.Length; i++)
                    if (ImGui.Selectable(sizeNames[i], i == sizeIdx))
                        _corrWatchSize = (WatchSize)i;
                ImGui.EndCombo();
            }
            ImGui.SameLine(0, 8);
            UiHelper.PrimaryButton("Add Watch##corradd", 100, 24, () =>
            {
                try
                {
                    string clean = _corrWatchAddr.Replace("0x","").Replace("0X","").Trim();
                    long addr    = Convert.ToInt64(clean, 16);
                    _correlator?.AddWatch(new IntPtr(addr),
                        _corrWatchLabel.Length > 0 ? _corrWatchLabel : $"0x{addr:X}",
                        _corrWatchSize);
                    _log.Info($"[Corr] Watch added: {_corrWatchLabel} @ 0x{addr:X}");
                    _corrWatchAddr = _corrWatchLabel = "";
                }
                catch (Exception ex) { _log.Error($"[Corr] {ex.Message}"); }
            });

            ImGui.Spacing();
            var watches = _correlator?.GetWatches() ?? new();
            foreach (var ww in watches)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColTextMuted);
                ImGui.TextUnformatted($"  {ww.Label}  ({ww.Size})  {ww.AddressHex}");
                ImGui.PopStyleColor();
                ImGui.SameLine(w * 0.42f);
                ImGui.PushStyleColor(ImGuiCol.Button, MenuRenderer.ColBg3);
                ImGui.PushStyleColor(ImGuiCol.Text, MenuRenderer.ColDanger);
                if (ImGui.Button($"✕##cwrem{ww.AddressHex}", new Vector2(22, 18)))
                    _correlator?.RemoveWatch(ww.Address);
                ImGui.PopStyleColor(2);
            }
        });

        ImGui.SameLine(0, 12);

        // Controls
        UiHelper.SectionBox("CONTROLS", half, 120, () =>
        {
            bool running = _correlator?.IsRunning == true;
            if (running)
            {
                UiHelper.DangerButton("Stop Correlator##corrstop", -1, 28, () =>
                {
                    _correlator?.Stop();
                });
                ImGui.Spacing();
                UiHelper.WarnText("● Correlating — perform actions in-game...");
            }
            else
            {
                ImGui.BeginDisabled(!_reader.IsAttached);
                UiHelper.WarnButton("Start Correlator##corrstart", -1, 28, () =>
                {
                    _correlator?.Start();
                });
                ImGui.EndDisabled();
                if (!_reader.IsAttached)
                    UiHelper.MutedLabel("Attach to process first (Attach tab).");
            }

            ImGui.Spacing();
            UiHelper.SecondaryButton("Clear Results##corrclear", -1, 24, () =>
                _correlator?.ClearResults());
        });

        // Results table
        ImGui.Spacing();
        var results = _correlator?.GetResults() ?? new();
        if (results.Count > 0)
        {
            float tblH = ImGui.GetContentRegionAvail().Y;
            ImGui.PushStyleColor(ImGuiCol.ChildBg, MenuRenderer.ColBg1);
            ImGui.BeginChild("##corrres", new Vector2(w, tblH), ImGuiChildFlags.Border);
            ImGui.PopStyleColor();

            UiHelper.MutedLabel($"  {"Time",-12} {"Label",-24} {"Before",-14} {"After",-14} {"Δ",-10} Triggered by");
            ImGui.Separator();

            foreach (var r in results.TakeLast(200).Reverse())
            {
                ImGui.PushStyleColor(ImGuiCol.Text,
                    r.Delta > 0 ? MenuRenderer.ColAccent : MenuRenderer.ColWarn);
                ImGui.TextUnformatted(
                    $"  {r.Timestamp:HH:mm:ss}  {r.Label,-24} {r.ValueBefore,-14} {r.ValueAfter,-14}" +
                    $" {r.DeltaStr,-10} {r.PacketLabel}");
                ImGui.PopStyleColor();
            }

            ImGui.EndChild();
        }
        else
        {
            ImGui.Spacing();
            UiHelper.MutedLabel("No correlations yet — add watches, start the correlator,");
            UiHelper.MutedLabel("then save packets to the PacketStore to trigger observations.");
        }
    }

}

// ── Pointer tree node ─────────────────────────────────────────────────────────

public class PointerNode
{
    public IntPtr          Address            { get; set; }
    public bool            IsValid            { get; set; }
    public long            DereferencedValue  { get; set; }
    public string          BytePreview        { get; set; } = "";
    public List<PointerNode> Children         { get; set; } = new();
}
