using Silk.NET.Input;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Configurable hotkey system.
///
/// Bindings are now stored in GlobalConfig.config.json (not a separate hotkeys.json).
/// GlobalConfig.SyncToHotkeyConfig() populates this on load.
/// GlobalConfig.PullFromHotkeyConfig() reads it back before save.
///
/// This class keeps the live Silk.NET.Input.Key fields and the capture-mode
/// state machine used by SettingsTab.
/// </summary>
public sealed class GlobalHotkeyConfig
{
    // ── Singleton ─────────────────────────────────────────────────────────
    public static readonly GlobalHotkeyConfig Instance = new();

    // ── Hotkeys (actual Key values) ───────────────────────────────────────
    public Key MenuToggleHotkey { get; set; } = Key.Insert;
    public Key MarkerHotkey     { get; set; } = Key.F8;
    public Key LockHotkey       { get; set; } = Key.F9;
    public Key PanicHotkey      { get; set; } = Key.End;

    // ── Capture state ─────────────────────────────────────────────────────
    // Slot: 0=MenuToggle 1=Marker 2=Lock 3=Panic  -1=none
    public  int  CaptureSlot { get; private set; } = -1;
    public  bool IsCapturing => CaptureSlot >= 0;
    private Action? _onCaptured;

    private GlobalHotkeyConfig() { }

    // ── API ───────────────────────────────────────────────────────────────

    public void BeginCapture(int slot, Action? onCaptured = null)
    {
        CaptureSlot = slot;
        _onCaptured = onCaptured;
    }

    public void CancelCapture() { CaptureSlot = -1; _onCaptured = null; }

    /// <summary>
    /// Called from Application.OnKeyDown on every key event.
    /// Binds the key to the waiting slot and triggers a config save.
    /// Returns true if the key was consumed.
    /// </summary>
    public bool TryCapture(Key key)
    {
        if (CaptureSlot < 0) return false;

        if (key == Key.Escape)
        {
            CancelCapture();
            return true;
        }

        switch (CaptureSlot)
        {
            case 0: MenuToggleHotkey = key; break;
            case 1: MarkerHotkey     = key; break;
            case 2: LockHotkey       = key; break;
            case 3: PanicHotkey      = key; break;
        }

        CaptureSlot = -1;
        _onCaptured?.Invoke();
        _onCaptured = null;

        // Persist through GlobalConfig (consolidated config.json)
        GlobalConfig.Instance.ScheduleSave();
        return true;
    }

    public void ResetDefaults()
    {
        MenuToggleHotkey = Key.Insert;
        MarkerHotkey     = Key.F8;
        LockHotkey       = Key.F9;
        PanicHotkey      = Key.End;
        GlobalConfig.Instance.ScheduleSave();
    }

    public static string KeyLabel(Key k) => k.ToString();
}
