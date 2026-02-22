namespace HytaleSecurityTester.Core;

/// <summary>
/// Shared server configuration — set once on the Dashboard,
/// used everywhere else automatically.
/// </summary>
public class ServerConfig
{
    public string ServerIp   { get; set; } = "149.56.241.73";
    public int    ServerPort { get; set; } = 5520;
    public bool   IsSet      => !string.IsNullOrWhiteSpace(ServerIp) && ServerPort > 0;

    // Fired whenever IP or port changes so all tabs can react
    public event Action? OnChanged;

    public void Set(string ip, int port)
    {
        ServerIp   = ip;
        ServerPort = port;
        OnChanged?.Invoke();
    }
}
