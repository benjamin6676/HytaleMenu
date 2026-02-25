namespace HytaleSecurityTester.Core;

/// <summary>
/// Thread-safe ring-buffer log. Stores lines as a List so LogTab can
/// use ImGuiListClipper (O(visible) per frame instead of O(total)).
/// Version counter increments on every write so UI cache knows when to refresh.
/// </summary>
public class TestLog
{
    private const int MaxLines = 2000;

    private readonly List<string> _lines   = new(MaxLines + 64);
    private readonly object       _lock    = new();
    private          int          _version = 0;

    /// <summary>Increments every time a line is added or the log is cleared.</summary>
    public int Version { get { lock (_lock) return _version; } }

    public void Clear()
    {
        lock (_lock) { _lines.Clear(); _version++; }
    }

    public void Info(string msg)    => Append($"[{DateTime.Now:HH:mm:ss}] [INFO]  {msg}");
    public void Success(string msg) => Append($"[{DateTime.Now:HH:mm:ss}] [OK]    {msg}");
    public void Warn(string msg)    => Append($"[{DateTime.Now:HH:mm:ss}] [WARN]  {msg}");
    public void Error(string msg)   => Append($"[{DateTime.Now:HH:mm:ss}] [ERROR] {msg}");

    private void Append(string line)
    {
        lock (_lock)
        {
            _lines.Add(line);
            if (_lines.Count > MaxLines)
                _lines.RemoveRange(0, _lines.Count - MaxLines);
            _version++;
        }
    }

    /// <summary>Snapshot for UI rendering — safe to iterate without holding the lock.</summary>
    public List<string> GetLines()
    {
        lock (_lock) return new List<string>(_lines);
    }

    /// <summary>Legacy compat shim for callers that still use GetText().</summary>
    public string GetText()
    {
        lock (_lock) return string.Join("\n", _lines);
    }
}
