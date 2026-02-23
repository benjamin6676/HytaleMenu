using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Windows process memory reader.
///
/// Uses ReadProcessMemory via P/Invoke — no injection, no DLL, read-only.
/// Works against any running process. Attach to Hytale, then scan for
/// item structs, entity IDs, inventory data, and arbitrary byte patterns.
///
/// Workflow:
///   1. Launch Hytale and log in
///   2. Attach to the Hytale process here
///   3. Use pattern scan to find item ID regions
///   4. Use struct scan to read inventory state directly from memory
///   5. Cross-reference with what Item Inspector sees in packets
/// </summary>
public class MemoryReader : IDisposable
{
    // ── Win32 P/Invoke ────────────────────────────────────────────────────

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwAccess, bool bInherit, int dwPid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(
        IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModules(
        IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, out int lpcbNeeded);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
    private static extern int GetModuleFileNameEx(
        IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, int nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetModuleInformation(
        IntPtr hProcess, IntPtr hModule,
        out MODULEINFO lpmodinfo, uint cb);

    [StructLayout(LayoutKind.Sequential)]
    private struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint   SizeOfImage;
        public IntPtr EntryPoint;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr  BaseAddress;
        public IntPtr  AllocationBase;
        public uint    AllocationProtect;
        public IntPtr  RegionSize;
        public uint    State;
        public uint    Protect;
        public uint    Type;
    }

    private const uint PROCESS_VM_READ      = 0x0010;
    private const uint PROCESS_QUERY_INFO   = 0x0400;
    private const uint MEM_COMMIT           = 0x1000;
    private const uint PAGE_READABLE        =
        0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80; // R, RW, RCW, ER, ERW, ERCW

    // ── State ─────────────────────────────────────────────────────────────

    private IntPtr  _handle    = IntPtr.Zero;
    private int     _pid       = 0;
    private string  _procName  = "";

    public bool   IsAttached  => _handle != IntPtr.Zero;
    public int    Pid         => _pid;
    public string ProcessName => _procName;

    // ── Attach / Detach ───────────────────────────────────────────────────

    public string Attach(int pid)
    {
        Detach();
        try
        {
            var proc = Process.GetProcessById(pid);
            _handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFO, false, pid);
            if (_handle == IntPtr.Zero)
                return $"OpenProcess failed: {Marshal.GetLastWin32Error()}";

            _pid      = pid;
            _procName = proc.ProcessName;
            return "";
        }
        catch (Exception ex)
        {
            Detach();
            return ex.Message;
        }
    }

    public void Detach()
    {
        if (_handle != IntPtr.Zero)
        {
            CloseHandle(_handle);
            _handle = IntPtr.Zero;
        }
        _pid      = 0;
        _procName = "";
    }

    public void Dispose() => Detach();

    // ── Read primitives ───────────────────────────────────────────────────

    public bool ReadBytes(IntPtr address, byte[] buffer)
    {
        if (!IsAttached) return false;
        return ReadProcessMemory(_handle, address, buffer, buffer.Length, out _);
    }

    public bool ReadInt32(IntPtr address, out int value)
    {
        value = 0;
        var buf = new byte[4];
        if (!ReadBytes(address, buf)) return false;
        value = BitConverter.ToInt32(buf, 0);
        return true;
    }

    public bool ReadInt64(IntPtr address, out long value)
    {
        value = 0;
        var buf = new byte[8];
        if (!ReadBytes(address, buf)) return false;
        value = BitConverter.ToInt64(buf, 0);
        return true;
    }

    public bool ReadFloat(IntPtr address, out float value)
    {
        value = 0;
        var buf = new byte[4];
        if (!ReadBytes(address, buf)) return false;
        value = BitConverter.ToSingle(buf, 0);
        return true;
    }

    public bool ReadString(IntPtr address, int maxLen, out string value)
    {
        value = "";
        var buf = new byte[maxLen];
        if (!ReadBytes(address, buf)) return false;
        int end = Array.IndexOf(buf, (byte)0);
        value = Encoding.UTF8.GetString(buf, 0, end < 0 ? maxLen : end);
        return true;
    }

    // ── Enumerate readable memory regions ─────────────────────────────────

    public List<MemoryRegion> GetReadableRegions(long maxSizeMb = 64)
    {
        var regions = new List<MemoryRegion>();
        if (!IsAttached) return regions;

        IntPtr addr = IntPtr.Zero;
        long   maxBytes = maxSizeMb * 1024 * 1024;

        while (true)
        {
            int result = VirtualQueryEx(_handle, addr,
                out MEMORY_BASIC_INFORMATION mbi,
                (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());

            if (result == 0) break;

            long regionSize = mbi.RegionSize.ToInt64();
            if (regionSize <= 0) break;

            bool committed  = (mbi.State   & MEM_COMMIT)  != 0;
            bool readable   = (mbi.Protect & PAGE_READABLE) != 0;
            bool notGuarded = (mbi.Protect & 0x100) == 0; // PAGE_GUARD

            if (committed && readable && notGuarded && regionSize <= maxBytes)
            {
                regions.Add(new MemoryRegion
                {
                    BaseAddress = mbi.BaseAddress,
                    Size        = (long)mbi.RegionSize,
                    Protect     = mbi.Protect,
                });
            }

            try
            {
                addr = IntPtr.Add(mbi.BaseAddress, (int)Math.Min(regionSize, int.MaxValue));
            }
            catch { break; }

            if (addr.ToInt64() < 0 || addr.ToInt64() > 0x7FFFFFFFFFFF) break;
        }

        return regions;
    }

    // ── Pattern scanner ───────────────────────────────────────────────────

    /// <summary>
    /// Scan all readable memory for a byte pattern.
    /// Use ?? (0x100 encoded as -1 in the int array) for wildcards.
    ///
    /// Example: ScanPattern(new int[]{ 0x48, 0x8B, -1, 0x48 })
    /// </summary>
    public List<ScanMatch> ScanPattern(byte?[] pattern,
                                        int maxResults = 200,
                                        IProgress<int>? progress = null)
    {
        var matches  = new List<ScanMatch>();
        if (!IsAttached || pattern.Length == 0) return matches;

        var regions  = GetReadableRegions();
        int done     = 0;

        foreach (var region in regions)
        {
            if (matches.Count >= maxResults) break;

            int  size = (int)Math.Min(region.Size, 64 * 1024 * 1024);
            var  buf  = new byte[size];
            if (!ReadBytes(region.BaseAddress, buf)) { done++; continue; }

            for (int i = 0; i <= buf.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (pattern[j].HasValue && buf[i + j] != pattern[j]!.Value)
                    { match = false; break; }
                }
                if (match)
                {
                    long addr = region.BaseAddress.ToInt64() + i;
                    matches.Add(new ScanMatch
                    {
                        Address = new IntPtr(addr),
                        Context = buf.Skip(i).Take(Math.Min(16, buf.Length - i)).ToArray(),
                    });
                    if (matches.Count >= maxResults) break;
                }
            }

            done++;
            progress?.Report(done * 100 / Math.Max(1, regions.Count));
        }

        return matches;
    }

    /// <summary>
    /// Scan for int32 values within a given range across all readable memory.
    /// Useful for finding item IDs, entity IDs, health values etc.
    /// </summary>
    public List<ScanMatch> ScanInt32Range(int min, int max,
                                           int maxResults = 500,
                                           IProgress<int>? progress = null)
    {
        var matches = new List<ScanMatch>();
        if (!IsAttached) return matches;

        var regions = GetReadableRegions();
        int done    = 0;

        foreach (var region in regions)
        {
            if (matches.Count >= maxResults) break;

            int size = (int)Math.Min(region.Size, 64 * 1024 * 1024);
            if (size < 4) { done++; continue; }

            var buf = new byte[size];
            if (!ReadBytes(region.BaseAddress, buf)) { done++; continue; }

            for (int i = 0; i <= buf.Length - 4; i += 4)
            {
                int v = BitConverter.ToInt32(buf, i);
                if (v >= min && v <= max)
                {
                    long addr = region.BaseAddress.ToInt64() + i;
                    matches.Add(new ScanMatch
                    {
                        Address = new IntPtr(addr),
                        Value   = v,
                        Context = buf.Skip(i).Take(Math.Min(16, buf.Length - i)).ToArray(),
                    });
                    if (matches.Count >= maxResults) break;
                }
            }

            done++;
            progress?.Report(done * 100 / Math.Max(1, regions.Count));
        }

        return matches;
    }

    /// <summary>
    /// Re-read a list of previously found addresses and return which ones
    /// still have a value in range. Used to narrow down results after
    /// performing an in-game action.
    /// </summary>
    public List<ScanMatch> RescanInt32(List<ScanMatch> previous, int newMin, int newMax)
    {
        var results = new List<ScanMatch>();
        foreach (var m in previous)
        {
            if (!ReadInt32(m.Address, out int v)) continue;
            if (v < newMin || v > newMax) continue;
            results.Add(new ScanMatch
            {
                Address = m.Address,
                Value   = v,
                Context = m.Context,
            });
        }
        return results;
    }

    // ── Inventory struct scan ─────────────────────────────────────────────

    /// <summary>
    /// Heuristic inventory scan: looks for clusters of int32 values
    /// that fall in the item ID range (100–9999), preceded or followed
    /// by small integers (slot index 0–64, stack count 1–999).
    ///
    /// This is pattern-matched, not a definitive parse — confirm results
    /// by comparing with what Item Inspector sees in packets.
    /// </summary>
    public List<InventoryCandidate> ScanInventory(IProgress<int>? progress = null)
    {
        var candidates = new List<InventoryCandidate>();
        if (!IsAttached) return candidates;

        var regions = GetReadableRegions(maxSizeMb: 32);
        int done    = 0;

        foreach (var region in regions)
        {
            int size = (int)Math.Min(region.Size, 8 * 1024 * 1024);
            if (size < 32) { done++; continue; }

            var buf = new byte[size];
            if (!ReadBytes(region.BaseAddress, buf)) { done++; continue; }

            for (int i = 0; i <= buf.Length - 12; i += 4)
            {
                int itemId = BitConverter.ToInt32(buf, i);
                if (itemId < 100 || itemId > 9999) continue;

                // Look for count in next int32
                int count = i + 4 < buf.Length
                    ? BitConverter.ToInt32(buf, i + 4) : 0;

                // Look for slot before
                int slot = i >= 4
                    ? BitConverter.ToInt32(buf, i - 4) : -1;

                // Filter: count must be plausible, slot must be plausible
                bool countOk = count >= 1 && count <= 999;
                bool slotOk  = slot >= 0  && slot <= 64;

                if (!countOk && !slotOk) continue;

                long addr = region.BaseAddress.ToInt64() + i;
                candidates.Add(new InventoryCandidate
                {
                    Address    = new IntPtr(addr),
                    ItemId     = itemId,
                    StackCount = countOk ? count : 1,
                    SlotIndex  = slotOk  ? slot  : -1,
                    Context    = buf.Skip(Math.Max(0, i - 4))
                                    .Take(Math.Min(20, buf.Length - i))
                                    .ToArray(),
                });

                if (candidates.Count >= 1000) break;
            }

            done++;
            progress?.Report(done * 100 / Math.Max(1, regions.Count));
            if (candidates.Count >= 1000) break;
        }

        return candidates;
    }

    // ── Pointer Path Builder ──────────────────────────────────────────────

    /// <summary>
    /// Resolves a multi-level pointer chain.
    /// baseAddress + offsets[0] → dereference → + offsets[1] → dereference → ...
    ///
    /// Returns the final resolved address, or IntPtr.Zero on failure.
    /// Useful for tracking dynamic game objects whose base pointers are stable
    /// but internal structure changes each session.
    ///
    /// Example: ResolvePointerChain(moduleBase + 0x1A2B3C, [0x8, 0x10, 0x30])
    /// </summary>
    public IntPtr ResolvePointerChain(IntPtr baseAddress, int[] offsets,
                                       out string trace)
    {
        var sb   = new StringBuilder();
        var addr = baseAddress;
        sb.AppendLine($"Base: 0x{addr.ToInt64():X16}");

        for (int i = 0; i < offsets.Length; i++)
        {
            // Dereference — read 8-byte pointer (64-bit process)
            if (!ReadInt64(addr, out long ptr))
            {
                sb.AppendLine($"  [offset {i}] FAILED — cannot read at 0x{addr.ToInt64():X16}");
                trace = sb.ToString();
                return IntPtr.Zero;
            }
            addr = new IntPtr(ptr);
            sb.AppendLine($"  → deref = 0x{ptr:X16}");

            // Apply next offset
            addr = IntPtr.Add(addr, offsets[i]);
            sb.AppendLine($"  + 0x{offsets[i]:X} = 0x{addr.ToInt64():X16}");
        }

        trace = sb.ToString();
        return addr;
    }

    // ── Memory Map ────────────────────────────────────────────────────────

    /// <summary>
    /// Returns a full memory map of the process — all regions with their
    /// protection, state, and size. Used for the Memory Map UI view.
    /// </summary>
    public List<MemoryMapEntry> GetMemoryMap()
    {
        var map  = new List<MemoryMapEntry>();
        if (!IsAttached) return map;

        IntPtr addr = IntPtr.Zero;

        while (true)
        {
            int result = VirtualQueryEx(_handle, addr,
                out MEMORY_BASIC_INFORMATION mbi,
                (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
            if (result == 0) break;

            long size = mbi.RegionSize.ToInt64();
            if (size <= 0) break;

            string stateStr = mbi.State switch
            {
                0x1000  => "COMMIT",
                0x2000  => "RESERVE",
                0x10000 => "FREE",
                _       => $"0x{mbi.State:X}"
            };

            string protStr = ProtectToString(mbi.Protect);
            string typeStr = mbi.Type switch
            {
                0x1000000 => "IMAGE",
                0x40000   => "MAPPED",
                0x20000   => "PRIVATE",
                _         => $"0x{mbi.Type:X}"
            };

            map.Add(new MemoryMapEntry
            {
                Base    = mbi.BaseAddress,
                Size    = size,
                State   = stateStr,
                Protect = protStr,
                Type    = typeStr,
                RawProtect = mbi.Protect,
            });

            try { addr = IntPtr.Add(mbi.BaseAddress, (int)Math.Min(size, int.MaxValue)); }
            catch { break; }
            if (addr.ToInt64() < 0 || addr.ToInt64() > 0x7FFFFFFFFFFF) break;
        }

        return map;
    }

    private static string ProtectToString(uint p)
    {
        if ((p & 0x100) != 0) return "GUARD";
        return (p & 0x7F) switch
        {
            0x01 => "---",
            0x02 => "R--",
            0x04 => "RW-",
            0x08 => "RCW",
            0x10 => "--X",
            0x20 => "R-X",
            0x40 => "RWX",
            0x80 => "RCX",
            _    => $"0x{p:X2}"
        };
    }
    public List<ProcessEntry> GetProcesses()
    {
        var list = new List<ProcessEntry>();
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    list.Add(new ProcessEntry
                    {
                        Pid  = p.Id,
                        Name = p.ProcessName,
                        Title = p.MainWindowTitle,
                    });
                }
                catch { }
            }
        }
        catch { }
        return list.OrderBy(p => p.Name).ToList();
    }

    // ── Module enumeration ────────────────────────────────────────────────

    /// <summary>
    /// Returns all loaded modules (DLLs) in the attached process.
    /// </summary>
    public List<ModuleInfo> GetModules()
    {
        var modules = new List<ModuleInfo>();
        if (!IsAttached) return modules;

        var buf = new IntPtr[1024];
        if (!EnumProcessModules(_handle, buf, buf.Length * IntPtr.Size, out int needed))
            return modules;

        int count = needed / IntPtr.Size;
        for (int i = 0; i < count; i++)
        {
            var nameBuilder = new StringBuilder(260);
            GetModuleFileNameEx(_handle, buf[i], nameBuilder, 260);
            string fullPath = nameBuilder.ToString();
            string name     = Path.GetFileName(fullPath);

            long size = 0;
            if (GetModuleInformation(_handle, buf[i], out MODULEINFO info,
                (uint)Marshal.SizeOf<MODULEINFO>()))
                size = info.SizeOfImage;

            modules.Add(new ModuleInfo
            {
                Name     = name,
                FullPath = fullPath,
                Base     = buf[i],
                Size     = size,
            });
        }
        return modules;
    }

    // ── High-performance AOB (Array-Of-Bytes) scanner using ReadOnlySpan ─

    /// <summary>
    /// Scans a specific module's memory for a pattern.
    /// Uses ReadOnlySpan&lt;byte&gt; for zero-allocation in-buffer search — far
    /// faster than scanning all regions when you know the target module.
    ///
    /// Pattern format: hex bytes separated by spaces, '??' = wildcard.
    /// Example: "48 8B ?? 48 89 C3 ?? 00"
    ///
    /// Returns the absolute address of the first match, or IntPtr.Zero.
    /// </summary>
    public IntPtr AobScanModule(string moduleName, string hexPattern,
                                 out string diagnostics)
    {
        diagnostics = "";
        if (!IsAttached) { diagnostics = "Not attached."; return IntPtr.Zero; }

        // Parse pattern
        byte?[] pattern;
        try
        {
            pattern = hexPattern.Trim()
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(t => t == "??" ? (byte?)null : (byte?)Convert.ToByte(t, 16))
                .ToArray();
        }
        catch (Exception ex)
        {
            diagnostics = $"Pattern parse error: {ex.Message}";
            return IntPtr.Zero;
        }

        if (pattern.Length == 0) { diagnostics = "Empty pattern."; return IntPtr.Zero; }

        // Find the module
        var mods = GetModules();
        var mod = mods.FirstOrDefault(m =>
            m.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase) ||
            m.FullPath.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

        if (mod == null)
        {
            var names = string.Join(", ", mods.Select(m => m.Name));
            diagnostics = $"Module '{moduleName}' not found. Loaded: {names}";
            return IntPtr.Zero;
        }

        // Read module memory in one shot
        int  size = (int)Math.Min(mod.Size, 128 * 1024 * 1024L);
        var  buf  = new byte[size];
        if (!ReadBytes(mod.Base, buf))
        {
            diagnostics = $"Could not read {size:N0}b from {mod.Name}.";
            return IntPtr.Zero;
        }

        // Span-based search — no allocations inside the loop
        ReadOnlySpan<byte> span = buf.AsSpan();

        for (int i = 0; i <= span.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (pattern[j].HasValue && span[i + j] != pattern[j]!.Value)
                { match = false; break; }
            }
            if (match)
            {
                long abs = mod.Base.ToInt64() + i;
                diagnostics = $"Match at 0x{abs:X16} (+0x{i:X} in {mod.Name})";
                return new IntPtr(abs);
            }
        }

        diagnostics = $"Pattern not found in {mod.Name} ({size:N0}b scanned).";
        return IntPtr.Zero;
    }

    /// <summary>
    /// Scan all loaded modules for a pattern. Returns all matches across
    /// every loaded module (exe + all DLLs).
    /// </summary>
    public List<AobMatch> AobScanAllModules(string hexPattern,
                                              int maxResults = 100)
    {
        var results = new List<AobMatch>();
        foreach (var mod in GetModules())
        {
            if (results.Count >= maxResults) break;
            var addr = AobScanModule(mod.Name, hexPattern, out string diag);
            if (addr != IntPtr.Zero)
                results.Add(new AobMatch { Address = addr, Module = mod.Name, Diagnostic = diag });
        }
        return results;
    }

    // ── String-to-Pointer Scanner ─────────────────────────────────────────

    /// <summary>
    /// Scans all readable memory regions for UTF-8 and UTF-16LE strings.
    /// Returns every occurrence with its address, encoding, and the string value.
    /// Useful for finding custom-named items / entity names stored in the heap.
    /// </summary>
    public List<StringMatch> ScanStrings(int minLen = 4, int maxLen = 128,
                                          int maxResults = 2000,
                                          IProgress<int>? progress = null)
    {
        var results = new List<StringMatch>();
        if (!IsAttached) return results;

        var regions = GetReadableRegions(maxSizeMb: 64);
        int done    = 0;

        foreach (var region in regions)
        {
            if (results.Count >= maxResults) break;
            int size = (int)Math.Min(region.Size, 32 * 1024 * 1024);
            if (size < minLen) { done++; continue; }

            var buf = new byte[size];
            if (!ReadBytes(region.BaseAddress, buf)) { done++; continue; }

            // ── UTF-8 scan ────────────────────────────────────────────────
            int i = 0;
            while (i < buf.Length && results.Count < maxResults)
            {
                if (buf[i] >= 0x20 && buf[i] < 0x7F)
                {
                    int start = i;
                    while (i < buf.Length && buf[i] >= 0x20 && buf[i] < 0x7F) i++;
                    int len = i - start;
                    if (len >= minLen && len <= maxLen)
                    {
                        results.Add(new StringMatch
                        {
                            Address  = IntPtr.Add(region.BaseAddress, start),
                            Value    = Encoding.ASCII.GetString(buf, start, len),
                            Encoding = "UTF-8",
                            Length   = len,
                        });
                    }
                }
                else i++;
            }

            // ── UTF-16LE scan ─────────────────────────────────────────────
            for (int j = 0; j + 2 <= buf.Length && results.Count < maxResults; j += 2)
            {
                char c = (char)BitConverter.ToUInt16(buf, j);
                if (c >= 0x20 && c < 0x7F)
                {
                    int start = j;
                    var sb    = new StringBuilder();
                    while (j + 2 <= buf.Length)
                    {
                        char ch = (char)BitConverter.ToUInt16(buf, j);
                        if (ch < 0x20 || ch >= 0x7F) break;
                        sb.Append(ch); j += 2;
                    }
                    int len = sb.Length;
                    if (len >= minLen && len <= maxLen)
                    {
                        results.Add(new StringMatch
                        {
                            Address  = IntPtr.Add(region.BaseAddress, start),
                            Value    = sb.ToString(),
                            Encoding = "UTF-16",
                            Length   = len * 2,
                        });
                    }
                }
            }

            done++;
            progress?.Report(done * 100 / Math.Max(1, regions.Count));
        }

        return results;
    }

    // ── VTable Resolver ───────────────────────────────────────────────────

    /// <summary>
    /// Reads the vtable pointer at <paramref name="objectAddress"/>,
    /// then reads up to <paramref name="maxMethods"/> 8-byte function pointers
    /// from that vtable and resolves each to [module + offset].
    /// </summary>
    public VTableInfo ResolveVTable(IntPtr objectAddress, int maxMethods = 32)
    {
        var info = new VTableInfo { ObjectAddress = objectAddress };
        if (!IsAttached) { info.Error = "Not attached."; return info; }

        // Read vtable pointer (first 8 bytes of object = ptr to vtable)
        if (!ReadInt64(objectAddress, out long vtPtr))
        { info.Error = $"Cannot read vtable ptr at {objectAddress.ToInt64():X16}"; return info; }

        info.VTableAddress = new IntPtr(vtPtr);

        var mods = GetModules();
        for (int i = 0; i < maxMethods; i++)
        {
            IntPtr slotAddr = IntPtr.Add(info.VTableAddress, i * 8);
            if (!ReadInt64(slotAddr, out long fnPtr) || fnPtr == 0) break;

            // Resolve function pointer to module
            var mod = mods.FirstOrDefault(m =>
            {
                long b = m.Base.ToInt64(), e = b + m.Size;
                return fnPtr >= b && fnPtr < e;
            });

            info.Methods.Add(new VTableMethod
            {
                Index      = i,
                Address    = new IntPtr(fnPtr),
                Module     = mod?.Name ?? "?",
                Offset     = mod != null ? fnPtr - mod.Base.ToInt64() : fnPtr,
            });
        }

        return info;
    }

    // ── Hardware Breakpoint Monitor ───────────────────────────────────────

    // Thread-context P/Invokes
    [DllImport("kernel32.dll")] private static extern IntPtr OpenThread(uint access, bool inherit, uint threadId);
    [DllImport("kernel32.dll")] private static extern bool   GetThreadContext(IntPtr hThread, ref CONTEXT64 ctx);
    [DllImport("kernel32.dll")] private static extern bool   SetThreadContext(IntPtr hThread, ref CONTEXT64 ctx);

    private const uint THREAD_GET_CONTEXT = 0x0008;
    private const uint THREAD_SET_CONTEXT = 0x0010;
    private const uint THREAD_SUSPEND_RESUME = 0x0002;
    private const uint CONTEXT_DEBUG_REGISTERS = 0x00010010;

    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    private struct CONTEXT64
    {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint  ContextFlags;
        public uint  MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint  EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        // Remaining fields — we only need debug registers, but struct size must be exact
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] _padding;
    }

    /// <summary>
    /// Sets hardware breakpoint slot 0 on all threads of the attached process
    /// to watch <paramref name="watchAddress"/> for write accesses (DR7 condition 01).
    /// Call ClearHardwareBreakpoints() to remove.
    /// </summary>
    public string SetHardwareBreakpoint(IntPtr watchAddress, int slot = 0)
    {
        if (!IsAttached) return "Not attached.";
        if (slot < 0 || slot > 3) return "Slot must be 0–3.";

        int set = 0, fail = 0;
        foreach (ProcessThread thread in Process.GetProcessById(_pid).Threads)
        {
            IntPtr hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                false, (uint)thread.Id);
            if (hThread == IntPtr.Zero) { fail++; continue; }

            try
            {
                var ctx = new CONTEXT64 { ContextFlags = CONTEXT_DEBUG_REGISTERS };
                ctx._padding = new byte[128];
                if (!GetThreadContext(hThread, ref ctx)) { fail++; continue; }

                // Set the DR slot to our watch address
                ulong addr = (ulong)watchAddress.ToInt64();
                switch (slot)
                {
                    case 0: ctx.Dr0 = addr; break;
                    case 1: ctx.Dr1 = addr; break;
                    case 2: ctx.Dr2 = addr; break;
                    case 3: ctx.Dr3 = addr; break;
                }

                // DR7: enable local breakpoint for slot (bits 0,2,4,6) + write condition (bits 16+)
                // Condition 01 = write, size 00 = 1-byte, enabled in bits 2*slot (local enable)
                uint enable = (uint)(1 << (slot * 2));         // L0–L3
                uint cond   = (uint)(0b01 << (16 + slot * 4)); // write access
                uint size   = 0;                                // 1-byte width
                ctx.Dr7 = (ctx.Dr7 & ~(ulong)((0xF << (16 + slot * 4)) | (0x3 << (slot * 2))))
                         | enable | cond | size;
                ctx.Dr6 = 0;

                if (SetThreadContext(hThread, ref ctx)) set++;
                else fail++;
            }
            finally { CloseHandle(hThread); }
        }

        return $"Breakpoint set on {set} thread(s) — {fail} failed. Watch: 0x{watchAddress.ToInt64():X16}";
    }

    /// <summary>Clears all hardware breakpoint slots on all threads.</summary>
    public string ClearHardwareBreakpoints()
    {
        if (!IsAttached) return "Not attached.";
        int cleared = 0;
        foreach (ProcessThread thread in Process.GetProcessById(_pid).Threads)
        {
            IntPtr hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                false, (uint)thread.Id);
            if (hThread == IntPtr.Zero) continue;
            try
            {
                var ctx = new CONTEXT64 { ContextFlags = CONTEXT_DEBUG_REGISTERS };
                ctx._padding = new byte[128];
                if (!GetThreadContext(hThread, ref ctx)) continue;
                ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = ctx.Dr6 = ctx.Dr7 = 0;
                if (SetThreadContext(hThread, ref ctx)) cleared++;
            }
            finally { CloseHandle(hThread); }
        }
        return $"Cleared breakpoints on {cleared} thread(s).";
    }

    /// <summary>
    /// Polls all threads for DR6 hit status. Returns a list of (threadId, slot) hits.
    /// Call this on a timer to detect breakpoint fires.
    /// </summary>
    public List<BreakpointHit> PollBreakpointHits()
    {
        var hits = new List<BreakpointHit>();
        if (!IsAttached) return hits;
        try
        {
            foreach (ProcessThread thread in Process.GetProcessById(_pid).Threads)
            {
                IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                    false, (uint)thread.Id);
                if (hThread == IntPtr.Zero) continue;
                try
                {
                    var ctx = new CONTEXT64 { ContextFlags = CONTEXT_DEBUG_REGISTERS };
                    ctx._padding = new byte[128];
                    if (!GetThreadContext(hThread, ref ctx)) continue;

                    ulong dr6 = ctx.Dr6;
                    for (int s = 0; s < 4; s++)
                    {
                        if ((dr6 & (ulong)(1 << s)) != 0)
                        {
                            hits.Add(new BreakpointHit
                            {
                                ThreadId  = thread.Id,
                                Slot      = s,
                                Timestamp = DateTime.Now,
                            });
                        }
                    }
                    // Clear DR6
                    if (hits.Count > 0)
                    {
                        ctx.Dr6 = 0;
                        SetThreadContext(hThread, ref ctx);
                    }
                }
                finally { CloseHandle(hThread); }
            }
        }
        catch { /* process may have exited */ }
        return hits;
    }

    // ── Cheat Engine .CT schema loader ────────────────────────────────────

    /// <summary>
    /// Parses a Cheat Engine .CT file (XML) and extracts all CheatEntry records.
    /// Supports Address + Offsets pointer chains and VariableType mapping.
    /// </summary>
    public static List<CtEntry> LoadCheatTable(string xmlPath)
    {
        var entries = new List<CtEntry>();
        try
        {
            var doc  = XDocument.Load(xmlPath);
            var root = doc.Root;
            if (root == null) return entries;

            // Handle both flat and nested CheatEntries
            foreach (var el in root.Descendants("CheatEntry"))
            {
                var entry = new CtEntry
                {
                    Description = el.Element("Description")?.Value ?? "",
                    VariableType = el.Element("VariableType")?.Value ?? "4 Bytes",
                    AddressText  = el.Element("Address")?.Value ?? "",
                };

                // Parse offsets
                var offsetsEl = el.Element("Offsets");
                if (offsetsEl != null)
                {
                    foreach (var offEl in offsetsEl.Elements("Offset"))
                    {
                        string txt = offEl.Value.Trim().Replace("0x","").Replace("0X","");
                        if (int.TryParse(txt, System.Globalization.NumberStyles.HexNumber,
                            null, out int off))
                            entry.Offsets.Add(off);
                    }
                }

                // Try parse base address
                string addrTxt = entry.AddressText.Trim()
                    .Replace("0x","").Replace("0X","");
                if (addrTxt.Contains("+"))
                {
                    entry.IsModuleRelative = true;
                    var parts = addrTxt.Split('+');
                    entry.ModuleName = parts[0].Trim().Trim('"');
                    if (parts.Length > 1 &&
                        long.TryParse(parts[1].Trim(),
                            System.Globalization.NumberStyles.HexNumber, null, out long off))
                        entry.BaseOffset = off;
                }
                else if (long.TryParse(addrTxt,
                    System.Globalization.NumberStyles.HexNumber, null, out long abs))
                {
                    entry.AbsoluteAddress = new IntPtr(abs);
                }

                entries.Add(entry);
            }
        }
        catch (Exception ex)
        {
            entries.Add(new CtEntry { Description = $"[Parse error: {ex.Message}]" });
        }
        return entries;
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

public class MemoryRegion
{
    public IntPtr BaseAddress { get; set; }
    public long   Size        { get; set; }
    public uint   Protect     { get; set; }
}

public class ScanMatch
{
    public IntPtr Address { get; set; }
    public int    Value   { get; set; }
    public byte[] Context { get; set; } = Array.Empty<byte>();

    public string AddressHex => $"0x{Address.ToInt64():X16}";
    public string ContextHex => string.Join(" ", Context.Select(b => $"{b:X2}"));
}

public class InventoryCandidate
{
    public IntPtr Address    { get; set; }
    public int    ItemId     { get; set; }
    public int    StackCount { get; set; }
    public int    SlotIndex  { get; set; }
    public byte[] Context    { get; set; } = Array.Empty<byte>();

    public string AddressHex => $"0x{Address.ToInt64():X16}";
    public string ContextHex => string.Join(" ", Context.Select(b => $"{b:X2}"));
}

public class ProcessEntry
{
    public int    Pid   { get; set; }
    public string Name  { get; set; } = "";
    public string Title { get; set; } = "";
}

public class ModuleInfo
{
    public string Name     { get; set; } = "";
    public string FullPath { get; set; } = "";
    public IntPtr Base     { get; set; }
    public long   Size     { get; set; }

    public string BaseHex => $"0x{Base.ToInt64():X16}";
    public string SizeStr => $"{Size / 1024}KB";
}

public class AobMatch
{
    public IntPtr Address    { get; set; }
    public string Module     { get; set; } = "";
    public string Diagnostic { get; set; } = "";
    public string AddressHex => $"0x{Address.ToInt64():X16}";
}

public class MemoryMapEntry
{
    public IntPtr Base       { get; set; }
    public long   Size       { get; set; }
    public string State      { get; set; } = "";
    public string Protect    { get; set; } = "";
    public string Type       { get; set; } = "";
    public uint   RawProtect { get; set; }

    public string BaseHex  => $"0x{Base.ToInt64():X16}";
    public string SizeStr  => Size >= 1024 * 1024 ? $"{Size / (1024 * 1024)}MB"
                            : Size >= 1024        ? $"{Size / 1024}KB"
                            :                       $"{Size}B";
    public bool   Readable => (RawProtect & 0xFE) != 0 && (RawProtect & 0x100) == 0;
}

public class StringMatch
{
    public IntPtr Address  { get; set; }
    public string Value    { get; set; } = "";
    public string Encoding { get; set; } = "UTF-8";
    public int    Length   { get; set; }
    public string AddressHex => $"0x{Address.ToInt64():X16}";
}

public class VTableInfo
{
    public IntPtr            ObjectAddress { get; set; }
    public IntPtr            VTableAddress { get; set; }
    public List<VTableMethod> Methods      { get; set; } = new();
    public string            Error         { get; set; } = "";
}

public class VTableMethod
{
    public int    Index   { get; set; }
    public IntPtr Address { get; set; }
    public string Module  { get; set; } = "";
    public long   Offset  { get; set; }
    public string AddressHex => $"0x{Address.ToInt64():X16}";
    public string OffsetHex  => $"+0x{Offset:X}";
}

public class BreakpointHit
{
    public int      ThreadId  { get; set; }
    public int      Slot      { get; set; }
    public DateTime Timestamp { get; set; }
}

public class CtEntry
{
    public string      Description     { get; set; } = "";
    public string      VariableType    { get; set; } = "4 Bytes";
    public string      AddressText     { get; set; } = "";
    public bool        IsModuleRelative { get; set; }
    public string      ModuleName      { get; set; } = "";
    public long        BaseOffset      { get; set; }
    public IntPtr      AbsoluteAddress { get; set; }
    public List<int>   Offsets         { get; set; } = new();
    public bool        Enabled         { get; set; } = true;
    public string      LiveValue       { get; set; } = "";
}
