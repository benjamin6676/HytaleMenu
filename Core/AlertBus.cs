using System.Collections.Concurrent;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Cross-tab notification bus.  Any tab can push an alert; MenuRenderer reads
/// badge counts and clears them when the user visits the tab.
///
/// Thread-safe - SmartDetectionEngine fires events from a background thread.
/// </summary>
public static class AlertBus
{
    // Per-tab unread counts  (tab section index -> count)
    private static readonly ConcurrentDictionary<int, int> _badges = new();

    // Recent alerts for the global feed (capped at 100)
    private static readonly object _feedLock = new();
    private static readonly List<AlertEntry> _feed = new();
    private const int MaxFeed = 100;

    // ── Public read ────────────────────────────────────────────────────────

    public static int GetBadge(int sectionIndex) =>
        _badges.TryGetValue(sectionIndex, out int v) ? v : 0;

    public static IReadOnlyList<AlertEntry> GetFeed()
    {
        lock (_feedLock) return _feed.ToList();
    }

    // ── Push ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Push an alert for a given section index.
    /// <paramref name="sectionIndex"/> matches the Sections[] array in MenuRenderer.
    /// </summary>
    public static void Push(int sectionIndex, AlertLevel level, string message)
    {
        _badges.AddOrUpdate(sectionIndex, 1, (_, v) => v + 1);

        var entry = new AlertEntry
        {
            SectionIndex = sectionIndex,
            Level        = level,
            Message      = message,
            At           = DateTime.Now,
        };

        lock (_feedLock)
        {
            _feed.Insert(0, entry);
            while (_feed.Count > MaxFeed)
                _feed.RemoveAt(_feed.Count - 1);
        }
    }

    // ── Clear ──────────────────────────────────────────────────────────────

    /// <summary>Clear badge when user navigates to that section.</summary>
    public static void ClearBadge(int sectionIndex) =>
        _badges.TryRemove(sectionIndex, out _);

    public static void ClearAll()
    {
        _badges.Clear();
        lock (_feedLock) _feed.Clear();
    }

    // ── Known section indices (mirrors MenuRenderer.Sections order) ────────
    public const int Sec_Dashboard    = 0;
    public const int Sec_Packets      = 1;
    public const int Sec_Duping       = 2;
    public const int Sec_Capture      = 3;
    public const int Sec_Privilege    = 4;
    public const int Sec_ModAudit     = 5;
    public const int Sec_Inspector    = 6;
    public const int Sec_Book         = 7;
    public const int Sec_Memory       = 8;
    public const int Sec_Visuals      = 9;
    public const int Sec_ProtoMap     = 10;
    public const int Sec_Macros       = 11;
}

public enum AlertLevel { Info, Warn, Critical }

public sealed class AlertEntry
{
    public int        SectionIndex { get; init; }
    public AlertLevel Level        { get; init; }
    public string     Message      { get; init; } = "";
    public DateTime   At           { get; init; }
}
