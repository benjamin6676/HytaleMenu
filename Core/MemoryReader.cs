using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

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

    // ── Process list helper ───────────────────────────────────────────────

    public static List<ProcessEntry> GetProcessList()
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
                        // MainWindowTitle may throw for some system processes
                        Title = p.MainWindowTitle,
                    });
                }
                catch { /* skip inaccessible processes */ }
            }
        }
        catch { }
        return list.OrderBy(p => p.Name).ToList();
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
