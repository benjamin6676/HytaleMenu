using System.Text;

namespace HytaleSecurityTester.Core;

public class TestLog
{
    private readonly StringBuilder _buffer = new();
    private readonly object        _lock   = new();

    public void Clear()             { lock (_lock) _buffer.Clear(); }
    public void Info(string msg)    => Append($"[INFO]  {msg}");
    public void Success(string msg) => Append($"[OK]    {msg}");
    public void Warn(string msg)    => Append($"[WARN]  {msg}");
    public void Error(string msg)   => Append($"[ERROR] {msg}");

    private void Append(string line)
    {
        lock (_lock)
            _buffer.AppendLine($"[{DateTime.Now:HH:mm:ss}] {line}");
    }

    public string GetText()
    {
        lock (_lock) return _buffer.ToString();
    }
}
