using System.Text.Json;
using System.Text.Json.Serialization;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Consolidated application configuration - single config.json file.
///
/// Replaces:
///   - hotkeys.json          - key bindings
///   - global_id_store.json  - IdNameMap, Watchlist, Blacklist
///
/// Location: %AppData%\HytaleSecurityTester\config.json
///
/// Thread-safety: All mutations go through the public API which schedules
/// a 500ms debounced save.  SaveNow() flushes immediately (called on close).
/// </summary>
public sealed class GlobalConfig
{
    // ── Singleton ─────────────────────────────────────────────────────────
    public static readonly GlobalConfig Instance = new();

    // ── Paths ─────────────────────────────────────────────────────────────
    public static readonly string ConfigDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                     "HytaleSecurityTester");
    public static readonly string ConfigPath = Path.Combine(ConfigDir, "config.json");

    // ── In-memory state ───────────────────────────────────────────────────

    // Hotkeys - integers matching Silk.NET.Input.Key enum values
    public int HotkeyMenuToggle { get; set; } = (int)Silk.NET.Input.Key.Insert;
    public int HotkeyMarker     { get; set; } = (int)Silk.NET.Input.Key.F8;
    public int HotkeyLock       { get; set; } = (int)Silk.NET.Input.Key.F9;
    public int HotkeyPanic      { get; set; } = (int)Silk.NET.Input.Key.End;

    // IdNameMap - uint ID -> resolved name string
    private readonly Dictionary<string, string> _idNameMap = new();

    // Watchlist / Blacklist
    private readonly List<uint> _watchlist = new();
    private readonly List<uint> _blacklist = new();

    // ── Debounce ──────────────────────────────────────────────────────────
    private System.Timers.Timer? _debounce;
    private readonly object      _saveLock = new();

    // ── Constructor (private - singleton) ────────────────────────────────
    private GlobalConfig()
    {
        Load();
    }

    // ── Public API ────────────────────────────────────────────────────────

    public void SetName(uint id, string name)
    {
        lock (_idNameMap) { _idNameMap[id.ToString()] = name; }
        ScheduleSave();
    }

    public string GetName(uint id)
    {
        lock (_idNameMap)
            return _idNameMap.TryGetValue(id.ToString(), out var n) ? n : "";
    }

    public IReadOnlyDictionary<string, string> GetIdNameMapSnapshot()
    {
        lock (_idNameMap)
            return new Dictionary<string, string>(_idNameMap);
    }

    public void AddToWatchlist(uint id) { lock (_watchlist) { if (!_watchlist.Contains(id)) _watchlist.Add(id); } ScheduleSave(); }
    public void AddToBlacklist(uint id) { lock (_blacklist) { if (!_blacklist.Contains(id)) _blacklist.Add(id); } ScheduleSave(); }
    public IReadOnlyList<uint> Watchlist { get { lock (_watchlist) return _watchlist.ToList(); } }
    public IReadOnlyList<uint> Blacklist { get { lock (_blacklist) return _blacklist.ToList(); } }

    // ── Hotkey sync ───────────────────────────────────────────────────────

    /// <summary>Push saved integers into GlobalHotkeyConfig live Key fields.</summary>
    public void SyncToHotkeyConfig()
    {
        var h = GlobalHotkeyConfig.Instance;
        h.MenuToggleHotkey = (Silk.NET.Input.Key)HotkeyMenuToggle;
        h.MarkerHotkey     = (Silk.NET.Input.Key)HotkeyMarker;
        h.LockHotkey       = (Silk.NET.Input.Key)HotkeyLock;
        h.PanicHotkey      = (Silk.NET.Input.Key)HotkeyPanic;
    }

    /// <summary>Pull live Key fields from GlobalHotkeyConfig into save-ready integers.</summary>
    public void PullFromHotkeyConfig()
    {
        var h = GlobalHotkeyConfig.Instance;
        HotkeyMenuToggle = (int)h.MenuToggleHotkey;
        HotkeyMarker     = (int)h.MarkerHotkey;
        HotkeyLock       = (int)h.LockHotkey;
        HotkeyPanic      = (int)h.PanicHotkey;
    }

    // ── Save / Load ───────────────────────────────────────────────────────

    public void ScheduleSave()
    {
        lock (_saveLock)
        {
            if (_debounce == null)
            {
                _debounce = new System.Timers.Timer(500) { AutoReset = false };
                _debounce.Elapsed += (_, _) => SaveNow();
            }
            _debounce.Stop();
            _debounce.Start();
        }
    }

    public void SaveNow()
    {
        try
        {
            PullFromHotkeyConfig();
            Directory.CreateDirectory(ConfigDir);
            var dto = BuildDto();
            File.WriteAllText(ConfigPath,
                JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    public void Load()
    {
        try
        {
            if (!File.Exists(ConfigPath)) return;

            var dto = JsonSerializer.Deserialize<ConfigDto>(File.ReadAllText(ConfigPath));
            if (dto == null) return;

            HotkeyMenuToggle = dto.HotkeyMenuToggle;
            HotkeyMarker     = dto.HotkeyMarker;
            HotkeyLock       = dto.HotkeyLock;
            HotkeyPanic      = dto.HotkeyPanic;

            lock (_idNameMap)
            {
                _idNameMap.Clear();
                if (dto.IdNameMap != null)
                    foreach (var kv in dto.IdNameMap)
                        _idNameMap[kv.Key] = kv.Value;
            }

            lock (_watchlist)
            {
                _watchlist.Clear();
                if (dto.Watchlist != null) _watchlist.AddRange(dto.Watchlist);
            }

            lock (_blacklist)
            {
                _blacklist.Clear();
                if (dto.Blacklist != null) _blacklist.AddRange(dto.Blacklist);
            }

            // Apply hotkeys immediately
            SyncToHotkeyConfig();
        }
        catch { /* corrupt config - use defaults */ }
    }

    public static void OpenConfigFolder()
    {
        try
        {
            Directory.CreateDirectory(ConfigDir);
            System.Diagnostics.Process.Start("explorer.exe", ConfigDir);
        }
        catch { }
    }

    // ── DTO (public for JSON - avoids private ctor deserialization issue) ─

    private ConfigDto BuildDto()
    {
        lock (_idNameMap)
        lock (_watchlist)
        lock (_blacklist)
        {
            return new ConfigDto
            {
                HotkeyMenuToggle = HotkeyMenuToggle,
                HotkeyMarker     = HotkeyMarker,
                HotkeyLock       = HotkeyLock,
                HotkeyPanic      = HotkeyPanic,
                IdNameMap        = new Dictionary<string, string>(_idNameMap),
                Watchlist        = _watchlist.ToList(),
                Blacklist        = _blacklist.ToList(),
            };
        }
    }

    private class ConfigDto
    {
        public int                       HotkeyMenuToggle { get; set; } = (int)Silk.NET.Input.Key.Insert;
        public int                       HotkeyMarker     { get; set; } = (int)Silk.NET.Input.Key.F8;
        public int                       HotkeyLock       { get; set; } = (int)Silk.NET.Input.Key.F9;
        public int                       HotkeyPanic      { get; set; } = (int)Silk.NET.Input.Key.End;
        public Dictionary<string, string>? IdNameMap      { get; set; }
        public List<uint>?               Watchlist        { get; set; }
        public List<uint>?               Blacklist        { get; set; }
    }
}
