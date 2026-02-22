namespace HytaleSecurityTester.Core;

/// <summary>
/// Separate ring-buffer log exclusively for raw packet traffic.
/// Keeps the general TestLog clean for test results, errors, and dupe output.
///
/// Holds the last N packet log lines in memory — old lines are dropped
/// automatically so it never grows unbounded even under heavy traffic.
/// </summary>
public class PacketLog
{
    private readonly Queue<PacketLogEntry> _entries = new();
    private readonly object                _lock    = new();
    private readonly int                   _maxEntries;

    public PacketLog(int maxEntries = 2000) => _maxEntries = maxEntries;

    public void Add(PacketDirection direction, int byteLen,
                    string hexPreview, bool injected = false)
    {
        var entry = new PacketLogEntry
        {
            Timestamp  = DateTime.Now,
            Direction  = direction,
            ByteLength = byteLen,
            HexPreview = hexPreview,
            Injected   = injected,
        };

        lock (_lock)
        {
            _entries.Enqueue(entry);
            while (_entries.Count > _maxEntries)
                _entries.Dequeue();
        }
    }

    public List<PacketLogEntry> GetEntries()
    {
        lock (_lock) return new List<PacketLogEntry>(_entries);
    }

    public int Count
    {
        get { lock (_lock) return _entries.Count; }
    }

    public void Clear()
    {
        lock (_lock) _entries.Clear();
    }
}

public class PacketLogEntry
{
    public DateTime        Timestamp  { get; set; }
    public PacketDirection Direction  { get; set; }
    public int             ByteLength { get; set; }
    public string          HexPreview { get; set; } = "";
    public bool            Injected   { get; set; }

    public string DirectionLabel =>
        Direction == PacketDirection.ClientToServer ? "C→S" : "S→C";
    public string TimeLabel =>
        Timestamp.ToString("HH:mm:ss.fff");
}
