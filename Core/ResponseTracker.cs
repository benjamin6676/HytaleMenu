using System.Collections.Concurrent;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Response Tracker - correlates injected/test packets with the server's
/// subsequent responses.
///
/// How it works:
///   1. When you send a test packet, call RecordSend(tag, data)
///   2. Feed every server->client packet into Feed(packet)
///   3. The tracker captures all server packets within the response window
///      and associates them with your send
///   4. Call GetResults() to see what the server said after each test
///
/// This turns the tool from "fires blind" into "fires and listens" -
/// you can see immediately whether the server accepted, denied, or
/// ignored each test packet.
/// </summary>
public class ResponseTracker
{
    // ── Configuration ─────────────────────────────────────────────────────
    /// How long to wait for a server response after a send (ms)
    public int ResponseWindowMs { get; set; } = 500;
    /// Maximum responses to keep in history
    public int MaxHistory { get; set; } = 200;

    // ── State ─────────────────────────────────────────────────────────────
    private readonly ConcurrentQueue<ResponseRecord> _history = new();
    private readonly List<PendingSend>               _pending = new();
    private readonly object                          _lock    = new();

    public event Action<ResponseRecord>? OnResponse;

    // ── API ───────────────────────────────────────────────────────────────

    /// Call this when you send a test packet. Tag is a human-readable label.
    public Guid RecordSend(string tag, byte[] data, string testType = "")
    {
        var id = Guid.NewGuid();
        lock (_lock)
        {
            _pending.Add(new PendingSend
            {
                Id         = id,
                Tag        = tag,
                TestType   = testType,
                SentAt     = DateTime.Now,
                SentBytes  = (byte[])data.Clone(),
                ExpiresAt  = DateTime.Now.AddMilliseconds(ResponseWindowMs),
            });
        }
        return id;
    }

    /// Feed every server->client packet here
    public void Feed(CapturedPacket pkt)
    {
        if (pkt.Direction != PacketDirection.ServerToClient) return;

        var now = DateTime.Now;
        lock (_lock)
        {
            // Expire old pending sends
            _pending.RemoveAll(p => p.ExpiresAt < now);

            // Attach this packet to all currently pending sends
            foreach (var pending in _pending)
                pending.Responses.Add(pkt);
        }
    }

    /// Flush pending sends that have passed their window and return them as results
    public List<ResponseRecord> Flush()
    {
        var completed = new List<ResponseRecord>();
        var now       = DateTime.Now;

        lock (_lock)
        {
            var expired = _pending.Where(p => p.ExpiresAt < now).ToList();
            foreach (var p in expired)
            {
                var record = BuildRecord(p);
                completed.Add(record);
                _history.Enqueue(record);
                while (_history.Count > MaxHistory) _history.TryDequeue(out _);
                OnResponse?.Invoke(record);
                _pending.Remove(p);
            }
        }
        return completed;
    }

    public List<ResponseRecord> GetHistory() => _history.ToList();

    public void Clear()
    {
        lock (_lock) { _pending.Clear(); }
        while (_history.TryDequeue(out _)) { }
    }

    // ── Build record ──────────────────────────────────────────────────────

    private ResponseRecord BuildRecord(PendingSend p)
    {
        var record = new ResponseRecord
        {
            Id           = p.Id,
            Tag          = p.Tag,
            TestType     = p.TestType,
            SentAt       = p.SentAt,
            SentBytes    = p.SentBytes,
            Responses    = p.Responses.ToList(),
            ResponseCount = p.Responses.Count,
        };

        if (p.Responses.Count == 0)
        {
            record.Outcome = ResponseOutcome.NoResponse;
            record.Summary = "No server response - server may have ignored or silently accepted.";
        }
        else
        {
            // Analyse responses
            record.Outcome = ClassifyOutcome(p.Responses, p.SentBytes);
            record.Summary = BuildResponseSummary(record);
        }

        return record;
    }

    private ResponseOutcome ClassifyOutcome(List<CapturedPacket> responses, byte[] sent)
    {
        if (responses.Count == 0) return ResponseOutcome.NoResponse;

        foreach (var r in responses)
        {
            if (r.RawBytes.Length == 0) continue;
            var analysis = PacketAnalyser.Analyse(r);

            // Look for error/deny indicators
            if (IsErrorPacket(r))    return ResponseOutcome.Denied;
            if (IsSuccessPacket(r))  return ResponseOutcome.Accepted;
            if (IsKickPacket(r))     return ResponseOutcome.Kicked;
        }

        // Got responses but couldn't classify - likely accepted
        return ResponseOutcome.AcceptedUnknown;
    }

    private bool IsErrorPacket(CapturedPacket pkt)
    {
        // Common error/deny indicators in server responses
        if (pkt.RawBytes.Length == 0) return false;
        byte id = pkt.RawBytes[0];

        // Check for known error packet IDs
        if (id is 0xFF or 0xFE or 0xFD) return true;

        // Check ASCII for error strings
        string ascii = pkt.AsciiPreview.ToLower();
        return ascii.Contains("error") || ascii.Contains("denied") ||
               ascii.Contains("invalid") || ascii.Contains("kick") ||
               ascii.Contains("fail");
    }

    private bool IsSuccessPacket(CapturedPacket pkt)
    {
        if (pkt.RawBytes.Length == 0) return false;
        string ascii = pkt.AsciiPreview.ToLower();
        return ascii.Contains("ok") || ascii.Contains("success") ||
               ascii.Contains("accept");
    }

    private bool IsKickPacket(CapturedPacket pkt)
    {
        if (pkt.RawBytes.Length == 0) return false;
        string ascii = pkt.AsciiPreview.ToLower();
        return ascii.Contains("kick") || ascii.Contains("disconnect") ||
               ascii.Contains("banned");
    }

    private string BuildResponseSummary(ResponseRecord r)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append($"{r.ResponseCount} response packet(s). ");
        sb.Append(r.Outcome switch
        {
            ResponseOutcome.Accepted        => "[OK] Server appears to have ACCEPTED the packet.",
            ResponseOutcome.AcceptedUnknown => "? Server responded - outcome unclear.",
            ResponseOutcome.Denied          => "[!!] Server DENIED / returned error.",
            ResponseOutcome.Kicked          => "[!] Server sent a KICK / disconnect packet!",
            ResponseOutcome.NoResponse      => "- No response received.",
            _ => ""
        });
        if (r.Responses.Count > 0)
        {
            var ids = r.Responses.Where(p => p.RawBytes.Length > 0)
                                  .Select(p => $"0x{p.RawBytes[0]:X2}")
                                  .Distinct();
            sb.Append($" Response IDs: {string.Join(", ", ids)}");
        }
        return sb.ToString();
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

public class PendingSend
{
    public Guid               Id        { get; set; }
    public string             Tag       { get; set; } = "";
    public string             TestType  { get; set; } = "";
    public DateTime           SentAt    { get; set; }
    public DateTime           ExpiresAt { get; set; }
    public byte[]             SentBytes { get; set; } = Array.Empty<byte>();
    public List<CapturedPacket> Responses { get; set; } = new();
}

public class ResponseRecord
{
    public Guid               Id            { get; set; }
    public string             Tag           { get; set; } = "";
    public string             TestType      { get; set; } = "";
    public DateTime           SentAt        { get; set; }
    public byte[]             SentBytes     { get; set; } = Array.Empty<byte>();
    public List<CapturedPacket> Responses   { get; set; } = new();
    public int                ResponseCount { get; set; }
    public ResponseOutcome    Outcome       { get; set; }
    public string             Summary       { get; set; } = "";

    public string TimeLabel => SentAt.ToString("HH:mm:ss.fff");
}

public enum ResponseOutcome
{
    NoResponse,
    Accepted,
    AcceptedUnknown,
    Denied,
    Kicked,
}
