using System.Text.Json;
using System.Collections.Concurrent;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Universal Update Handler for Hytale Security Tester.
///
/// v3 fixes:
///  - WasUpdated now resets to false once a scan completes successfully.
///  - Signatures dictionary is now mutable (user can add/edit patterns in Settings).
///  - Added UserSignatures: overlay that replaces built-in patterns when set.
///  - Shorter, more tolerant built-in fallback patterns (fewer fixed bytes).
///  - ASCII-only log messages.
///  - ScanSummary property for Settings tab status display.
/// </summary>
public sealed class AutoUpdateHandler
{
    // ── Singleton ─────────────────────────────────────────────────────────
    public static readonly AutoUpdateHandler Instance = new();

    // ── Persist paths ─────────────────────────────────────────────────────
    private static readonly string CacheDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                     "HytaleSecurityTester");
    private static readonly string CachePath  = Path.Combine(CacheDir, "aob_cache.json");
    private static readonly string SigsPath   = Path.Combine(CacheDir, "aob_patterns.json");

    // ── State ─────────────────────────────────────────────────────────────
    public string LastGameHash    { get; private set; } = "";
    public string CurrentGameHash { get; private set; } = "";

    // WasUpdated is true only until a scan completes or user dismisses it
    public bool   WasUpdated      { get; private set; }
    public bool   ScanRunning     { get; private set; }
    public int    ScanProgress    { get; private set; }
    public string ScanStatus      { get; private set; } = "Not scanned yet.";
    public string ScanSummary     { get; private set; } = "";  // e.g. "3/4 found"

    public event Action<string, string>? OnUpdateDetected;
    public event Action<string, long>?  OnSymbolFound;

    public long EntityListAddr  { get; private set; }
    public long LocalPlayerAddr { get; private set; }
    public long ItemListAddr    { get; private set; }
    public long HoverIdAddr     { get; private set; }

    private TestLog?  _log;
    private AobCache? _cache;

    // ── Built-in signatures (shorter = more resilient across minor patches) ─
    //
    // Strategy for 0/4 failures:
    //   The 20-byte patterns were too precise.  These are shortened to the
    //   minimum stable "anchor" bytes.  Each pattern is 10-12 bytes with
    //   wildcards on ALL relocatable offsets.
    //
    //   HOW TO UPDATE MANUALLY (if these still fail):
    //     1. Open Cheat Engine, attach to HytaleClient.exe
    //     2. Memory -> "Memory View" -> Ctrl+B (AOB scan)
    //     3. Find the instruction that writes your pointer and grab 6-10 bytes
    //        around a stable opcode, put ?? on any 4-byte address operand.
    //     4. Paste into Settings -> Memory -> Pattern Editor -> save.
    //
    //   FORMAT: space-separated hex bytes, "??" = wildcard single byte.

    private static readonly Dictionary<string, string> BuiltInSignatures = new()
    {
        // LEA RCX,[rip+offset]  ; load entity-list pointer
        // 48 8D 0D xx xx xx xx  followed by any call
        { "EntityList",
          "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ??" },

        // MOV [rip+offset], RAX  ; store local-player ptr
        // 48 89 05 xx xx xx xx
        { "LocalPlayer",
          "48 89 05 ?? ?? ?? ?? 48 8B" },

        // MOV R8,[rip+offset]  ; load item-list ptr
        // 4C 8B 05 xx xx xx xx
        { "ItemList",
          "4C 8B 05 ?? ?? ?? ?? 48 8B" },

        // MOV [rip+offset], EBX  ; 32-bit store of hover entity id
        // 89 1D xx xx xx xx
        { "HoverEntityId",
          "89 1D ?? ?? ?? ?? 48 8B 0D" },
    };

    // User-supplied overrides (persisted to aob_patterns.json)
    // Key must match one of the BuiltIn keys, or can be a new custom key.
    public ConcurrentDictionary<string, string> UserSignatures { get; } = new();

    private static readonly string[] GameModuleNames =
        { "HytaleClient.exe", "HytaleClient", "Hytale.exe", "Hytale" };

    // ── Constructor ───────────────────────────────────────────────────────
    private AutoUpdateHandler()
    {
        _cache = LoadCache();
        LoadUserSignatures();
    }

    public void Init(TestLog log)
    {
        _log = log;
        _log.Info("[AutoUpdate] Ready - waiting for game attachment.");
    }

    // ── Effective signatures (user overrides built-in) ────────────────────
    private IReadOnlyDictionary<string, string> EffectiveSignatures
    {
        get
        {
            var result = new Dictionary<string, string>(BuiltInSignatures);
            foreach (var kv in UserSignatures)
                result[kv.Key] = kv.Value;   // override or add
            return result;
        }
    }

    // ── Version check ─────────────────────────────────────────────────────
    public bool CheckVersion()
    {
        var reader = SharedMemoryReader.Instance;
        if (!reader.IsAttached)
        {
            _log?.Warn("[AutoUpdate] CheckVersion: not attached - skipping.");
            return false;
        }

        CurrentGameHash = ComputeGameHash(reader);
        LastGameHash    = _cache?.GameHash ?? "";

        if (string.IsNullOrEmpty(CurrentGameHash))
        {
            _log?.Warn("[AutoUpdate] Could not compute game hash (modules unavailable?).");
            return false;
        }

        WasUpdated = string.IsNullOrEmpty(LastGameHash) ||
                     CurrentGameHash != LastGameHash;

        if (WasUpdated)
        {
            string oldS = LastGameHash.Length >= 8 ? LastGameHash[..8] : "(none)";
            _log?.Warn($"[AutoUpdate] Build changed: {oldS}... -> {CurrentGameHash[..8]}...");
            _log?.Warn("[AutoUpdate] Cached offsets cleared - force rescan recommended.");
            OnUpdateDetected?.Invoke(LastGameHash, CurrentGameHash);
            ClearCachedPointers();
        }
        else
        {
            _log?.Success($"[AutoUpdate] Build unchanged ({CurrentGameHash[..8]}...) - restoring cached offsets.");
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

    /// <summary>Dismiss the "Build changed" banner without running a scan.</summary>
    public void DismissUpdateWarning() { WasUpdated = false; }

    // ── Force re-scan ─────────────────────────────────────────────────────
    public Task ForceRescanAsync()
    {
        if (ScanRunning)
        {
            _log?.Warn("[AutoUpdate] Scan already running - ignored.");
            return Task.CompletedTask;
        }

        var reader = SharedMemoryReader.Instance;
        if (!reader.IsAttached)
        {
            _log?.Error("[AutoUpdate] Cannot scan - attach to HytaleClient in the Memory tab first.");
            ScanStatus = "ERROR: not attached.";
            return Task.CompletedTask;
        }

        return Task.Run(() => RunScan(reader));
    }

    // ── Internal scan ─────────────────────────────────────────────────────
    private void RunScan(MemoryReader reader)
    {
        ScanRunning  = true;
        ScanProgress = 0;
        ScanStatus   = "Starting...";
        ScanSummary  = "";
        ClearCachedPointers();

        // Find HytaleClient module
        string targetModule = "";
        foreach (var cand in GameModuleNames)
        {
            if (reader.GetModuleBaseAddress(cand) != 0)
            {
                targetModule = cand;
                break;
            }
        }

        if (string.IsNullOrEmpty(targetModule))
        {
            string loadedMods = string.Join(", ",
                reader.GetModules().Select(m => m.Name).Take(15));
            _log?.Error("[AutoUpdate] HytaleClient module not found in process.");
            _log?.Info($"[AutoUpdate] Loaded modules: {loadedMods}");
            _log?.Info("[AutoUpdate] TIP: If the exe has a different name, add it via Manual PID attach.");
            ScanStatus  = "ERROR: module not found.";
            ScanRunning = false;
            return;
        }

        var sigs = EffectiveSignatures.ToList();
        _log?.Info($"[AutoUpdate] AOB scan starting on [{targetModule}] - {sigs.Count} patterns");

        for (int i = 0; i < sigs.Count; i++)
        {
            var (name, pattern) = sigs[i];
            ScanStatus   = $"[{i+1}/{sigs.Count}] {name}...";
            ScanProgress = i * 100 / sigs.Count;

            _log?.Info($"[AutoUpdate] [{i+1}/{sigs.Count}] Scanning {name}  ({pattern})");

            var addr = reader.AobScanModule(targetModule, pattern, out string diag);

            if (addr != IntPtr.Zero)
            {
                long instrAddr = addr.ToInt64();

                // ── RIP-relative dereference ──────────────────────────────
                //
                // AOB patterns like:
                //   LEA RCX, [RIP+offset]   (48 8D 0D xx xx xx xx)
                //   MOV [RIP+offset], RAX   (48 89 05 xx xx xx xx)
                //   MOV R8, [RIP+offset]    (4C 8B 05 xx xx xx xx)
                //   MOV [RIP+offset], EBX   (89 1D xx xx xx xx)
                //
                // The 4-byte signed offset is at bytes +3 (or +2 for 89 1D).
                // Effective address = instrAddr + offsetLen + signedOffset
                // For a pointer-store pattern, the value AT that EA is the pointer.
                //
                // offsetByte = position of the 4-byte RIP offset within the instruction
                // instrLen   = total instruction length (used as RIP value = instrAddr + instrLen)

                long resolvedAddr = TryResolveRipRelative(reader, instrAddr, name, out string resolveInfo);

                if (resolvedAddr != 0)
                {
                    _log?.Success($"[AutoUpdate] [OK] {name} = 0x{resolvedAddr:X}  (instr@0x{instrAddr:X}, {resolveInfo})");
                    OnSymbolFound?.Invoke(name, resolvedAddr);
                    switch (name)
                    {
                        case "EntityList":    EntityListAddr  = resolvedAddr; break;
                        case "LocalPlayer":   LocalPlayerAddr = resolvedAddr; break;
                        case "ItemList":      ItemListAddr    = resolvedAddr; break;
                        case "HoverEntityId": HoverIdAddr     = resolvedAddr; break;
                    }
                }
                else
                {
                    // Fallback: store raw instruction address (at least marks it as found)
                    long abs = instrAddr;
                    _log?.Warn($"[AutoUpdate] [!] {name}: RIP resolve failed ({resolveInfo}), storing raw 0x{abs:X}");
                    OnSymbolFound?.Invoke(name, abs);
                    switch (name)
                    {
                        case "EntityList":    EntityListAddr  = abs; break;
                        case "LocalPlayer":   LocalPlayerAddr = abs; break;
                        case "ItemList":      ItemListAddr    = abs; break;
                        case "HoverEntityId": HoverIdAddr     = abs; break;
                    }
                }
            }
            else
            {
                _log?.Warn($"[AutoUpdate] [!!] {name} not found - {diag}");
                _log?.Info($"[AutoUpdate]      Pattern was: {pattern}");
                _log?.Info("[AutoUpdate]      TIP: Open Cheat Engine -> Memory View -> Ctrl+B");
                _log?.Info("             Find the instruction, copy bytes, replace 4-byte offsets with ??");
                _log?.Info("             Paste into Settings -> Memory -> Pattern Editor");
            }

            ScanProgress = (i + 1) * 100 / sigs.Count;
        }

        int found = new long[] { EntityListAddr, LocalPlayerAddr, ItemListAddr, HoverIdAddr }
                        .Count(a => a != 0);

        ScanSummary = $"{found}/{sigs.Count} patterns found";
        ScanStatus  = $"Done - {found}/{sigs.Count} found.";

        // ── Clear the "build changed" banner once scan runs ──────────────
        // Whether we found 0 or 4, the user has run the scan for this build.
        WasUpdated = false;

        if (found > 0)
            _log?.Success($"[AutoUpdate] Scan done: {found}/{sigs.Count} symbols resolved.");
        else
        {
            _log?.Error($"[AutoUpdate] Scan done: 0/{sigs.Count} - all patterns failed.");
            _log?.Warn("[AutoUpdate] This usually means the patterns need updating for this build.");
            _log?.Warn("[AutoUpdate] Use Settings -> Memory -> Pattern Editor to enter custom patterns.");
        }

        PersistCache();
        ScanRunning = false;
    }

    // ── RIP-relative resolution ───────────────────────────────────────────
    //
    // Reads the 4-byte signed offset from the matched instruction bytes and
    // computes the effective address of the static data pointer.
    // Then dereferences it once with ReadInt64 to get the actual pointer value.
    //
    // Returns the dereferenced pointer, or 0 if anything fails.

    private static long TryResolveRipRelative(MemoryReader reader, long instrAddr,
                                               string sigName, out string info)
    {
        info = "";
        try
        {
            // Read the first 12 bytes of the matched instruction
            var buf = new byte[12];
            if (!reader.ReadBytes(new IntPtr(instrAddr), buf))
            {
                info = "ReadBytes failed";
                return 0;
            }
            int read = buf.Length;

            // Determine opcode layout to find offset byte position and instruction length
            // Layout: [prefix(s)] opcode [mod/rm] [4-byte RIP offset]
            int offsetPos;   // byte position of the 4-byte signed offset
            int instrLen;    // full instruction length (RIP = instrAddr + instrLen)

            byte b0 = buf[0], b1 = buf[1], b2 = buf[2];

            if (b0 == 0x48 && b1 == 0x8D && b2 == 0x0D)         // LEA RCX,[RIP+off]
                { offsetPos = 3; instrLen = 7; }
            else if (b0 == 0x48 && b1 == 0x89 && b2 == 0x05)    // MOV [RIP+off],RAX
                { offsetPos = 3; instrLen = 7; }
            else if (b0 == 0x48 && b1 == 0x8B && b2 == 0x05)    // MOV RAX,[RIP+off]
                { offsetPos = 3; instrLen = 7; }
            else if (b0 == 0x4C && b1 == 0x8B && b2 == 0x05)    // MOV R8,[RIP+off]
                { offsetPos = 3; instrLen = 7; }
            else if (b0 == 0x89 && b1 == 0x1D)                   // MOV [RIP+off],EBX
                { offsetPos = 2; instrLen = 6; }
            else if (b0 == 0x48 && b1 == 0x8B && b2 == 0x0D)    // MOV RCX,[RIP+off]
                { offsetPos = 3; instrLen = 7; }
            else
            {
                // Unknown layout - try generic: offset at byte 3, len 7
                offsetPos = 3; instrLen = 7;
                info = $"Unknown opcode {b0:X2} {b1:X2} {b2:X2}, guessing offset@3";
            }

            if (offsetPos + 4 > read) { info = "Buffer too small"; return 0; }

            int  ripOffset  = BitConverter.ToInt32(buf, offsetPos);
            long ripValue   = instrAddr + instrLen;   // RIP = address of NEXT instruction
            long ptrAddress = ripValue + ripOffset;   // effective address of the static var

            // For pointer-load instructions (MOV R8,[RIP+off]), the static var IS the pointer
            // For pointer-store instructions (MOV [RIP+off],RAX), the static var holds the ptr
            // Either way we read 8 bytes at ptrAddress to get the actual heap/segment address
            if (!reader.ReadInt64(new IntPtr(ptrAddress), out long pointedValue))
            {
                // Return the static var address itself as a fallback
                info = $"off={ripOffset:X8}, ea=0x{ptrAddress:X}, ReadInt64 failed";
                return ptrAddress;
            }

            info = $"off={ripOffset:X8}, ea=0x{ptrAddress:X}, deref=0x{pointedValue:X}";

            // Sanity check: deref'd value should be a plausible heap pointer
            // (typically 0x7FF... on 64-bit Windows, or 0x00007F... on Linux)
            if (pointedValue > 0x0000_0100_0000_0000L && pointedValue < 0x7FFF_FFFF_FFFF_FFFFL)
                return pointedValue;

            // Value looks wrong - return static EA instead
            info += " [deref OOB, returning EA]";
            return ptrAddress;
        }
        catch (Exception ex)
        {
            info = $"Exception: {ex.Message}";
            return 0;
        }
    }

    private void ClearCachedPointers()
    {
        EntityListAddr = LocalPlayerAddr = ItemListAddr = HoverIdAddr = 0;
    }

    // ── User signature persistence ────────────────────────────────────────
    public void SetUserPattern(string name, string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            UserSignatures.TryRemove(name, out _);
        else
            UserSignatures[name] = pattern.Trim();
        SaveUserSignatures();
        _log?.Info($"[AutoUpdate] Pattern '{name}' updated - run Force Rescan to apply.");
    }

    public string GetEffectivePattern(string name)
    {
        if (UserSignatures.TryGetValue(name, out var up)) return up;
        if (BuiltInSignatures.TryGetValue(name, out var bp)) return bp;
        return "";
    }

    public string GetBuiltInPattern(string name) =>
        BuiltInSignatures.TryGetValue(name, out var p) ? p : "";

    public IReadOnlyList<string> SignatureNames =>
        BuiltInSignatures.Keys.Concat(
            UserSignatures.Keys.Where(k => !BuiltInSignatures.ContainsKey(k)))
        .Distinct().ToList();

    private void SaveUserSignatures()
    {
        try
        {
            Directory.CreateDirectory(CacheDir);
            File.WriteAllText(SigsPath,
                JsonSerializer.Serialize(new Dictionary<string, string>(UserSignatures),
                    new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    private void LoadUserSignatures()
    {
        try
        {
            if (!File.Exists(SigsPath)) return;
            var d = JsonSerializer.Deserialize<Dictionary<string, string>>(
                        File.ReadAllText(SigsPath));
            if (d == null) return;
            foreach (var kv in d)
                UserSignatures[kv.Key] = kv.Value;
        }
        catch { }
    }

    // ── Cache helpers ─────────────────────────────────────────────────────
    private void PersistCache()
    {
        try
        {
            Directory.CreateDirectory(CacheDir);
            File.WriteAllText(CachePath, JsonSerializer.Serialize(new AobCache
            {
                GameHash        = CurrentGameHash,
                EntityListAddr  = EntityListAddr,
                LocalPlayerAddr = LocalPlayerAddr,
                ItemListAddr    = ItemListAddr,
                HoverIdAddr     = HoverIdAddr,
            }, new JsonSerializerOptions { WriteIndented = true }));
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
            var exe  = mods.FirstOrDefault(m =>
                           GameModuleNames.Any(n =>
                               m.Name.Equals(n, StringComparison.OrdinalIgnoreCase)))
                    ?? mods.Where(m => m.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                           .OrderByDescending(m => m.Size).FirstOrDefault();
            if (exe == null) return "";
            using var sha = System.Security.Cryptography.SHA256.Create();
            return Convert.ToHexString(
                sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(
                    $"{exe.FullPath}|{exe.Size}"))).ToLowerInvariant();
        }
        catch { return ""; }
    }

    private class AobCache
    {
        public string GameHash        { get; set; } = "";
        public long   EntityListAddr  { get; set; }
        public long   LocalPlayerAddr { get; set; }
        public long   ItemListAddr    { get; set; }
        public long   HoverIdAddr     { get; set; }
    }
}
