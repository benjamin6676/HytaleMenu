namespace HytaleSecurityTester.Core;

/// <summary>
/// Shared server configuration - set once on the Dashboard,
/// used everywhere else automatically.
/// </summary>
public class ServerConfig
{
    public string ServerIp   { get; set; } = "149.56.241.73";
    public int    ServerPort { get; set; } = 5520;
    public bool   IsSet      => !string.IsNullOrWhiteSpace(ServerIp) && ServerPort > 0;

    // ── Target item - set from Item Inspector, consumed by Dupe Methods ───
    /// The item ID currently targeted for dupe testing.
    public uint   TargetItemId     { get; private set; } = 0;
    /// Where the current TargetItemId came from (e.g. "Item Inspector", "Manual")
    public string TargetItemSource { get; private set; } = "";
    /// True when TargetItemId has been set at least once
    public bool   HasTargetItem    => TargetItemId > 0;

    // ── Local Player EntityID - set from MemoryTab LocalPlayer scanner ────
    /// The EntityID of the local player found via memory scanning.
    /// SmartDetectionEngine uses this to label the matching entity "LocalPlayer".
    public uint   LocalPlayerEntityId     { get; private set; } = 0;
    public string LocalPlayerName         { get; private set; } = "";
    public bool   HasLocalPlayer          => LocalPlayerEntityId > 0;

    public event Action? OnChanged;
    public event Action? OnTargetItemChanged;
    public event Action? OnLocalPlayerChanged;

    public void SetLocalPlayerEntityId(uint entityId, string playerName = "")
    {
        LocalPlayerEntityId = entityId;
        LocalPlayerName     = playerName;
        OnLocalPlayerChanged?.Invoke();
    }

    public void Set(string ip, int port)
    {
        ServerIp   = ip;
        ServerPort = port;
        OnChanged?.Invoke();
    }

    /// <summary>
    /// Set the global target item ID. Called from Item Inspector when user
    /// clicks "Set as Target". DupingTab subscribes to OnTargetItemChanged
    /// to auto-populate its item ID field.
    /// </summary>
    public void SetTargetItemId(uint itemId, string source = "Item Inspector")
    {
        TargetItemId     = itemId;
        TargetItemSource = source;
        OnTargetItemChanged?.Invoke();
    }
}
