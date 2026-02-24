using System.Text.Json;

namespace HytaleSecurityTester.Core;

/// <summary>
/// A named packet library.  Once you identify what a packet does via the
/// Capture/Analyse tabs, save it here with a label.  Other tabs (Dupe, Packet,
/// Privilege) can then recall it by name instead of re-pasting hex each time.
///
/// Saved to disk as JSON so it persists between sessions.
/// </summary>
public class PacketStore
{
    private const string SaveFile = "HyTester_PacketStore.json";

    private readonly List<SavedPacket>  _packets = new();
    private readonly object             _lock    = new();

    public PacketStore() => Load();

    // ── CRUD ──────────────────────────────────────────────────────────────

    public void Save(string label, string notes, byte[] data, PacketDirection direction)
        => Save(label, notes, data, direction, Array.Empty<string>());

    public void Save(string label, string notes, byte[] data, PacketDirection direction,
                     string[] tags)
    {
        lock (_lock)
        {
            // Replace if same label exists
            _packets.RemoveAll(p => p.Label.Equals(label, StringComparison.OrdinalIgnoreCase));
            _packets.Add(new SavedPacket
            {
                Label     = label,
                Notes     = notes,
                HexString = PacketCapture.ToHex(data),
                Direction = direction,
                SavedAt   = DateTime.Now,
                Tags      = tags.ToList(),
            });
            Persist();
        }
    }

    public void Delete(string label)
    {
        lock (_lock)
        {
            _packets.RemoveAll(p => p.Label.Equals(label, StringComparison.OrdinalIgnoreCase));
            Persist();
        }
    }

    public List<SavedPacket> GetAll()
    {
        lock (_lock) return new List<SavedPacket>(_packets);
    }

    public SavedPacket? Get(string label)
    {
        lock (_lock)
            return _packets.FirstOrDefault(
                p => p.Label.Equals(label, StringComparison.OrdinalIgnoreCase));
    }

    public bool TryGetBytes(string label, out byte[] data)
    {
        var pkt = Get(label);
        if (pkt == null) { data = Array.Empty<byte>(); return false; }
        try
        {
            string clean = pkt.HexString.Replace(" ", "");
            if (clean.Length % 2 != 0) clean += "0";
            data = Convert.FromHexString(clean);
            return true;
        }
        catch { data = Array.Empty<byte>(); return false; }
    }

    // ── Persistence ───────────────────────────────────────────────────────

    private void Persist()
    {
        try
        {
            string json = JsonSerializer.Serialize(_packets,
                new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SaveFile, json);
        }
        catch { /* non-fatal */ }
    }

    private void Load()
    {
        if (!File.Exists(SaveFile)) return;
        try
        {
            string json = File.ReadAllText(SaveFile);
            var    list = JsonSerializer.Deserialize<List<SavedPacket>>(json);
            if (list != null)
            {
                lock (_lock) { _packets.Clear(); _packets.AddRange(list); }
            }
        }
        catch { /* corrupt file — start fresh */ }
    }
}

public class SavedPacket
{
    public string          Label     { get; set; } = "";
    public string          Notes     { get; set; } = "";
    public string          HexString { get; set; } = "";
    public PacketDirection Direction { get; set; }
    public DateTime        SavedAt   { get; set; }
    public List<string>    Tags      { get; set; } = new();

    public byte[] ToBytes()
    {
        string clean = HexString.Replace(" ", "");
        if (clean.Length % 2 != 0) clean += "0";
        try   { return Convert.FromHexString(clean); }
        catch { return Array.Empty<byte>(); }
    }
}
