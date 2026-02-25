using Silk.NET.Input;
using System.Text.Json;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Configurable hotkey system.
///
/// Provides four user-rebindable keys with defaults:
///   MenuToggleHotkey  — Insert  (show/hide overlay)
///   MarkerHotkey      — F8      (place position marker)
///   LockHotkey        — F9      (lock item target)
///   PanicHotkey       — End     (immediately close the app)
///
/// Usage — Settings tab calls BeginCapture(slot) to enter listen mode.
/// Application.OnKeyDown calls TryCapture(key) on every keypress.
/// </summary>
public sealed class GlobalHotkeyConfig
{
    // ── Singleton ─────────────────────────────────────────────────────────

    public static readonly GlobalHotkeyConfig Instance = new();

    // ── Persist path ─────────────────────────────────────────────────────

    private static readonly string SavePath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                     "HytaleSecurityTester", "hotkeys.json");

    // ── Hotkeys ───────────────────────────────────────────────────────────

    public Key MenuToggleHotkey { get; set; } = Key.Insert;
    public Key MarkerHotkey     { get; set; } = Key.F8;
    public Key LockHotkey       { get; set; } = Key.F9;
    public Key PanicHotkey      { get; set; } = Key.End;

    // ── Capture state ─────────────────────────────────────────────────────

    // Which slot is waiting for a key press? -1 = none
    // 0=MenuToggle 1=Marker 2=Lock 3=Panic
    public  int  CaptureSlot    { get; private set; } = -1;
    public  bool IsCapturing    => CaptureSlot >= 0;
    private Action? _onCaptured;

    // ── Constructor ───────────────────────────────────────────────────────

    private GlobalHotkeyConfig()
    {
        try
        {
            if (File.Exists(SavePath))
            {
                var json = File.ReadAllText(SavePath);
                var dto  = JsonSerializer.Deserialize<HotkeyDto>(json);
                if (dto != null)
                {
                    MenuToggleHotkey = (Key)dto.MenuToggle;
                    MarkerHotkey     = (Key)dto.Marker;
                    LockHotkey       = (Key)dto.Lock;
                    PanicHotkey      = (Key)dto.Panic;
                }
            }
        }
        catch { /* silently use defaults */ }
    }

    // ── API ───────────────────────────────────────────────────────────────

    /// <summary>Start capturing the next keypress for the given slot.</summary>
    public void BeginCapture(int slot, Action? onCaptured = null)
    {
        CaptureSlot = slot;
        _onCaptured = onCaptured;
    }

    /// <summary>Cancel any active capture.</summary>
    public void CancelCapture() { CaptureSlot = -1; _onCaptured = null; }

    /// <summary>
    /// Called from Application.OnKeyDown — if capturing, bind the key.
    /// Returns true if the key was consumed by the capture system.
    /// Escape cancels without binding.
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

        int captured = CaptureSlot;
        CaptureSlot  = -1;
        _onCaptured?.Invoke();
        _onCaptured  = null;
        Save();
        return true;
    }

    /// <summary>Reset all hotkeys to factory defaults.</summary>
    public void ResetDefaults()
    {
        MenuToggleHotkey = Key.Insert;
        MarkerHotkey     = Key.F8;
        LockHotkey       = Key.F9;
        PanicHotkey      = Key.End;
        Save();
    }

    /// <summary>Human-readable name for the key used in UI labels.</summary>
    public static string KeyLabel(Key k) => k.ToString();

    /// <summary>Persist current bindings to disk.</summary>
    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SavePath)!);
            var dto  = new HotkeyDto
            {
                MenuToggle = (int)MenuToggleHotkey,
                Marker     = (int)MarkerHotkey,
                Lock       = (int)LockHotkey,
                Panic      = (int)PanicHotkey,
            };
            File.WriteAllText(SavePath, JsonSerializer.Serialize(dto,
                new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    // ── DTO for JSON serialization ─────────────────────────────────────────

    private class HotkeyDto
    {
        public int MenuToggle { get; set; }
        public int Marker     { get; set; }
        public int Lock       { get; set; }
        public int Panic      { get; set; }
    }
}
