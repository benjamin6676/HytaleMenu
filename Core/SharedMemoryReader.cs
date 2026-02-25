namespace HytaleSecurityTester.Core;

/// <summary>
/// Global singleton wrapper around MemoryReader.
///
/// Problem solved: MemoryTab created its own private MemoryReader instance.
/// SettingsTab/AutoUpdateHandler had no access to it, so they always saw
/// "not attached" even when Memory tab was connected.
///
/// Fix: Every tab that needs memory access should use
///   SharedMemoryReader.Instance.Reader
/// MemoryTab also switches to using this singleton instead of creating its
/// own private reader.
/// </summary>
public static class SharedMemoryReader
{
    // ── Single shared instance ────────────────────────────────────────────

    public static readonly MemoryReader Instance = new();

    // ── Convenience passthrough properties ────────────────────────────────

    public static bool   IsAttached   => Instance.IsAttached;
    public static int    Pid          => Instance.Pid;
    public static string ProcessName  => Instance.ProcessName;

    // ── Quick-attach helper targeting HytaleClient first ─────────────────

    /// <summary>
    /// Try to attach to the game process.  Searches for HytaleClient first,
    /// then falls back to the other known process names.
    ///
    /// Returns empty string on success or an error message on failure.
    /// </summary>
    public static string AutoAttach()
    {
        // Priority order: HytaleClient is the actual process name in the screenshot
        var candidates = new[]
        {
            "HytaleClient", "HytaleClient.exe",
            "Hytale",       "hytale",
            "java",         "javaw",
        };

        foreach (var name in candidates)
        {
            var procs = System.Diagnostics.Process.GetProcessesByName(
                name.Replace(".exe", "", StringComparison.OrdinalIgnoreCase));
            if (procs.Length == 0) continue;

            string err = Instance.Attach(procs[0].Id);
            if (string.IsNullOrEmpty(err))
                return "";        // success
        }

        return "No Hytale process found.  Start the game first.";
    }
}
