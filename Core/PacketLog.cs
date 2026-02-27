using System.Collections.Concurrent;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Separate ring-buffer log for raw packet traffic.
/// Each entry now carries full analysis metadata so the Deep Log tab can show
/// compressed/decompressed sizes, encryption type, packet ID and name.
/// </summary>
public class PacketLog
{
    private readonly Queue<PacketLogEntry> _entries = new();
    private readonly object                _lock    = new();
    private readonly int                   _maxEntries;

    // ── Per-opcode ring buffers: last 5 packets of each type ─────────────
    // Used by Deep Log tab for side-by-side comparison without noise.
    private readonly ConcurrentDictionary<ushort, Queue<PacketLogEntry>> _byOpcode = new();
    private const int MaxPerOpcode = 5;

    public PacketLog(int maxEntries = 2000) => _maxEntries = maxEntries;

    /// <summary>Original lightweight add (used by PacketCapture - no analysis).</summary>
    public void Add(PacketDirection direction, int byteLen,
                    string hexPreview, bool injected = false)
    {
        var entry = new PacketLogEntry
        {
            Timestamp         = DateTime.Now,
            Direction         = direction,
            ByteLength        = byteLen,
            HexPreview        = hexPreview,
            Injected          = injected,
            CompressionMethod = "none",
            PacketId          = OpcodeRegistry.DecodePacketIdFromHex(hexPreview),
        };
        AddEntry(entry);
    }

    /// <summary>Enriched add used by SmartDetectionEngine with full analysis.</summary>
    public void AddAnalyzed(PacketDirection direction,
                             byte[]   rawBytes,
                             byte[]   decompressed,
                             string   compressionMethod,
                             ushort   packetId,
                             string   packetName,
                             bool     injected = false)
    {
        string hexPrev = rawBytes.Length == 0 ? ""
            : PacketCapture.ToHex(rawBytes[..Math.Min(48, rawBytes.Length)]);

        string? encType = DetectEncryption(rawBytes);

        var entry = new PacketLogEntry
        {
            Timestamp            = DateTime.Now,
            Direction            = direction,
            ByteLength           = rawBytes.Length,
            HexPreview           = hexPrev,
            Injected             = injected,
            CompressionMethod    = compressionMethod,
            CompressedSize       = rawBytes.Length,
            DecompressedSize     = decompressed.Length,
            PacketId             = packetId,
            PacketName           = packetName,
            EncryptionType       = encType ?? "none",
            DecompressedHexPreview = decompressed.Length == 0 ? "" :
                PacketCapture.ToHex(decompressed[..Math.Min(64, decompressed.Length)]),
            IsCompressed         = compressionMethod != "none",
        };
        AddEntry(entry);

        // Keep per-opcode ring
        var q = _byOpcode.GetOrAdd(packetId, _ => new Queue<PacketLogEntry>());
        lock (q) {
            q.Enqueue(entry);
            while (q.Count > MaxPerOpcode) q.Dequeue();
        }
    }

    private void AddEntry(PacketLogEntry entry)
    {
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

    /// <summary>Returns last N entries (newest-last). Useful for Deep Log snapshot.</summary>
    public List<PacketLogEntry> GetLastN(int n)
    {
        lock (_lock)
        {
            var all = _entries.ToList();
            return all.Skip(Math.Max(0, all.Count - n)).ToList();
        }
    }

    /// <summary>Returns the last MaxPerOpcode entries for a given opcode ID.</summary>
    public List<PacketLogEntry> GetByOpcode(ushort id)
    {
        if (!_byOpcode.TryGetValue(id, out var q)) return new();
        lock (q) return new List<PacketLogEntry>(q);
    }

    /// <summary>Returns one representative entry per unique opcode seen (newest).</summary>
    public List<PacketLogEntry> GetOnePerOpcode()
    {
        var result = new List<PacketLogEntry>();
        foreach (var kv in _byOpcode)
        {
            lock (kv.Value)
            {
                if (kv.Value.Count > 0) result.Add(kv.Value.Last());
            }
        }
        return result.OrderBy(e => e.PacketId).ToList();
    }

    public int Count { get { lock (_lock) return _entries.Count; } }
    public int OpcodeTypeCount => _byOpcode.Count;

    public void Clear()
    {
        lock (_lock) _entries.Clear();
        _byOpcode.Clear();
    }

    // ── Heuristic encryption detector ────────────────────────────────────
    private static string? DetectEncryption(byte[] data)
    {
        if (data.Length < 4) return null;
        // High entropy + not matching any compression magic = possible XOR/RC4/AES
        double entropy = ComputeEntropy(data);
        if (entropy > 7.5) return "high-entropy (possible enc)";
        if (data[0] == 0x1F && data[1] == 0x8B) return null; // gzip - not encrypted
        if (data[0] == 0x78) return null; // zlib
        if (data[0] == 0x04 && data[1] == 0x22) return null; // lz4
        if (entropy > 6.5 && data.Length > 64) return "medium-entropy";
        return null;
    }

    private static double ComputeEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;
        int[] freq = new int[256];
        foreach (byte b in data) freq[b]++;
        double ent = 0;
        double len = data.Length;
        foreach (int f in freq)
        {
            if (f == 0) continue;
            double p = f / len;
            ent -= p * Math.Log2(p);
        }
        return ent;
    }
}

public class PacketLogEntry
{
    public DateTime        Timestamp            { get; set; }
    public PacketDirection Direction            { get; set; }
    public int             ByteLength           { get; set; }
    public string          HexPreview           { get; set; } = "";
    public bool            Injected             { get; set; }

    // ── Analysis fields (populated by AddAnalyzed) ─────────────────────
    public ushort  PacketId              { get; set; }
    public string  PacketName            { get; set; } = "";
    public string  CompressionMethod     { get; set; } = "none";
    public int     CompressedSize        { get; set; }
    public int     DecompressedSize      { get; set; }
    public bool    IsCompressed          { get; set; }
    public string  EncryptionType        { get; set; } = "none";
    public string  DecompressedHexPreview{ get; set; } = "";

    public string DirectionLabel =>
        Direction == PacketDirection.ClientToServer ? "C→S" : "S→C";
    public string TimeLabel =>
        Timestamp.ToString("HH:mm:ss.fff");

    public string CompressionSummary => IsCompressed
        ? $"{CompressionMethod}  {CompressedSize}B → {DecompressedSize}B  ({DecompressedSize * 100 / Math.Max(1, CompressedSize)}%)"
        : $"none  {ByteLength}B";
}
