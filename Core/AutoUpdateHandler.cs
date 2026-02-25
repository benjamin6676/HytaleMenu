using System.Diagnostics;
using System.Text.Json;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Universal Update Handler — detects Hytale game build changes on startup
/// and automatically triggers a full AOB memory re-scan when the version changes.
///
/// Cached pointer results (EntityList, LocalPlayer, ItemList, HoverID)
/// are stored keyed to the game executable hash.  On mismatch the cache
/// is cleared and every AOB signature is re-run against the new binary.
///
/// Resilient AOB signatures use ?? wildcards for patch-variant bytes,
/// targeting stable "code bones" that survive minor game updates.
/// </summary>
public sealed class AutoUpdateHandler
{
    // ── Singleton ─────────────────────────────────────────────────────────

    public static readonly AutoUpdateHandler Instance = new();

    // ── Persist paths ─────────────────────────────────────────────────────

    private static readonly string CacheDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                     "HytaleSecurityTester");

    private static readonly string CachePath = Path.Combine(CacheDir, "aob_cache.json");

    // ── State ─────────────────────────────────────────────────────────────

    public  string LastGameHash   { get; private set; } = "";
    public  string CurrentGameHash { get; private set; } = "";
    public  bool   WasUpdated      { get; private set; }
    public  bool   ScanRunning     { get; private set; }
    public  int    ScanProgress    { get; private set; }
    public  string ScanStatus      { get; private set; } = "";

    public  event Action<string, string>? OnUpdateDetected; // (oldHash, newHash)
    public  event Action<string, long>?  OnSymbolFound;     // (symbolName, address)

    // Resolved addresses — cleared and re-populated on each full scan
    public  long EntityListAddr  { get; private set; }
    public  long LocalPlayerAddr { get; private set; }
    public  long ItemListAddr    { get; private set; }
    public  long HoverIdAddr     { get; private set; }

    private readonly TestLog? _log;
    private AobCache?         _cache;

    // ── AOB Signatures ─────────────────────────────────────────────────────
    // Wildcards (??) over bytes that change between minor patches
    // (relocated addresses, jmp distances, register allocations).

    private static readonly Dictionary<string, string> Signatures = new()
    {
        // EntityList pointer: find via "entity_list" or loop-init pattern
        { "EntityList",  "48 8B ?? ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B ?? 00 00 00 00" },

        // LocalPlayer: commonly referenced as "self" or player-controller offset
        { "LocalPlayer", "48 89 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 75 ?? 48 8B" },

        // ItemList: inventory array init — uint32 item IDs loaded in a loop
        { "ItemList",    "8B 0D ?? ?? ?? ?? 8B 01 ?? ?? ?? 0F ?? ?? 4C 8D ?? ?? ?? ?? ??" },

        // HoverID: the uint32 written when the cursor hovers an object
        { "HoverEntityId", "89 ?? ?? ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 8B ?? 48 85" },
    };

    // ── Constructor ───────────────────────────────────────────────────────

    private AutoUpdateHandler() { }

    

    // ── Version Detection ─────────────────────────────────────────────────

    /// <summary>
    /// Detect whether the game exe has changed since the last run.
    /// Call this once on startup with the MemoryReader already attached.
    /// Returns true if a re-scan is needed.
    /// </summary>
    public bool CheckVersion(MemoryReader reader)
    {
        CurrentGameHash = ComputeGameHash(reader);
        LastGameHash    = _cache?.GameHash ?? "";

        if (string.IsNullOrEmpty(CurrentGameHash))
        {
            _log?.Info("[AutoUpdate] Game not attached — skipping version check.");
            return false;
        }

        WasUpdated = CurrentGameHash != LastGameHash;

        if (WasUpdated)
        {
            _log?.Warn($"[AutoUpdate] Game version changed: {LastGameHash[..8]}… → {CurrentGameHash[..8]}…");
            _log?.Warn("[AutoUpdate] Clearing cached pointers — mandatory re-scan required.");
            OnUpdateDetected?.Invoke(LastGameHash, CurrentGameHash);
            ClearCachedPointers();
        }
        else
        {
            _log?.Info($"[AutoUpdate] Game version unchanged ({CurrentGameHash[..8]}…).");
            // Restore cached addresses
            if (_cache != null)
            {
                EntityListAddr  = _cache.EntityListAddr;
                LocalPlayerAddr = _cache.LocalPlayerAddr;
                ItemListAddr    = _cache.ItemListAddr;
                HoverIdAddr     = _cache.HoverIdAddr;
            }
        }

        return WasUpdated;
    }

    // ── Force Re-Scan ─────────────────────────────────────────────────────

    /// <summary>
    /// Clear all cached pointers and run every AOB signature immediately.
    /// Progress is reported via ScanProgress (0-100) and ScanStatus.
    /// </summary>
    public Task ForceRescanAsync(MemoryReader reader)
    {
        if (ScanRunning) return Task.CompletedTask;
        return Task.Run(() => RunScan(reader));
    }

    // ── Internal scan ─────────────────────────────────────────────────────

    private void RunScan(MemoryReader reader)
    {
        ScanRunning = true;
        ScanProgress = 0;
        ClearCachedPointers();

        _log?.Info("[AutoUpdate] Starting full AOB re-scan…");

        var symbols = Signatures.ToList();
        for (int i = 0; i < symbols.Count; i++)
        {
            var (name, pattern) = symbols[i];
            ScanStatus = $"Scanning {name}…";

            var addr = reader.AobScanAllModules(pattern, maxResults: 1)
                             .FirstOrDefault()?.Address ?? IntPtr.Zero;

            if (addr != IntPtr.Zero)
            {
                long absAddr = addr.ToInt64();
                _log?.Success($"[AutoUpdate] Found {name} at 0x{absAddr:X}");
                OnSymbolFound?.Invoke(name, absAddr);

                switch (name)
                {
                    case "EntityList":   EntityListAddr  = absAddr; break;
                    case "LocalPlayer":  LocalPlayerAddr = absAddr; break;
                    case "ItemList":     ItemListAddr    = absAddr; break;
                    case "HoverEntityId": HoverIdAddr    = absAddr; break;
                }
            }
            else
            {
                _log?.Warn($"[AutoUpdate] {name}: pattern not found in current build.");
            }

            ScanProgress = (i + 1) * 100 / symbols.Count;
        }

        ScanStatus = "Done.";
        _log?.Success("[AutoUpdate] Re-scan complete.");

        // Persist
        PersistCache();
        ScanRunning = false;
    }

    private void ClearCachedPointers()
    {
        EntityListAddr = LocalPlayerAddr = ItemListAddr = HoverIdAddr = 0;
    }

    // ── Cache ─────────────────────────────────────────────────────────────

    private void PersistCache()
    {
        try
        {
            Directory.CreateDirectory(CacheDir);
            var c = new AobCache
            {
                GameHash      = CurrentGameHash,
                EntityListAddr  = EntityListAddr,
                LocalPlayerAddr = LocalPlayerAddr,
                ItemListAddr    = ItemListAddr,
                HoverIdAddr     = HoverIdAddr,
            };
            File.WriteAllText(CachePath,
                JsonSerializer.Serialize(c, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    private static AobCache? LoadCache()
    {
        try
        {
            if (!File.Exists(CachePath)) return null;
            return JsonSerializer.Deserialize<AobCache>(File.ReadAllText(CachePath));
        }
        catch { return null; }
    }

    private static string ComputeGameHash(MemoryReader reader)
    {
        try
        {
            var mods = reader.GetModules();
            // Find the main game executable (largest .exe)
            var exe = mods.Where(m => m.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                          .OrderByDescending(m => m.Size)
                          .FirstOrDefault();
            if (exe == null) return "";

            // Use module path + size as a fast lightweight version fingerprint
            // A real hash of the full module bytes would be slow (100MB+)
            string info = $"{exe.FullPath}|{exe.Size}";
            using var sha = System.Security.Cryptography.SHA256.Create();
            byte[] hash = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(info));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch { return ""; }
    }

    // ── DTO ───────────────────────────────────────────────────────────────

    private class AobCache
    {
        public string GameHash      { get; set; } = "";
        public long EntityListAddr  { get; set; }
        public long LocalPlayerAddr { get; set; }
        public long ItemListAddr    { get; set; }
        public long HoverIdAddr     { get; set; }
    }
}
