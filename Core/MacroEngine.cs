using System.Text.Json;
using System.Text.Json.Serialization;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Persistent macro engine data layer.
/// Macros are named sequences of steps; each step is a hex packet + delay + optional condition.
/// Variables ({{VAR}}) are substituted at fire-time.
/// Persisted to %AppData%/HytaleSecurityTester/macros.json.
/// </summary>
public sealed class MacroLibrary
{
    // ── Singleton ──────────────────────────────────────────────────────────
    private static MacroLibrary? _instance;
    public  static MacroLibrary  Instance => _instance ??= new MacroLibrary();

    private static string SavePath
    {
        get
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "HytaleSecurityTester");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "macros.json");
        }
    }

    public List<Macro> Macros { get; private set; } = new();

    private MacroLibrary() => Load();

    // ── Mutations ──────────────────────────────────────────────────────────

    public void Add(Macro m)
    {
        Macros.RemoveAll(x => x.Name == m.Name);
        Macros.Add(m);
        ScheduleSave();
    }

    public void Delete(string name)
    {
        Macros.RemoveAll(x => x.Name == name);
        ScheduleSave();
    }

    // ── Persistence ────────────────────────────────────────────────────────

    private bool _savePending;
    private readonly object _lk = new();

    public void ScheduleSave()
    {
        lock (_lk) { if (_savePending) return; _savePending = true; }
        Task.Run(async () =>
        {
            await Task.Delay(500);
            lock (_lk) _savePending = false;
            try
            {
                string json = JsonSerializer.Serialize(Macros,
                    new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(SavePath, json);
            }
            catch { }
        });
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(SavePath)) return;
            var list = JsonSerializer.Deserialize<List<Macro>>(File.ReadAllText(SavePath));
            if (list != null) Macros = list;
        }
        catch { }
    }
}

// ── Data types ─────────────────────────────────────────────────────────────

public sealed class Macro
{
    public string         Name        { get; set; } = "Unnamed";
    public string         Description { get; set; } = "";
    public List<MacroStep> Steps      { get; set; } = new();
    public List<MacroVar>  Variables  { get; set; } = new();
    public int             LoopCount  { get; set; } = 1;
    public DateTime        CreatedAt  { get; set; } = DateTime.Now;
}

public sealed class MacroStep
{
    public string  Label          { get; set; } = "";
    public string  HexTemplate    { get; set; } = "";  // may contain {{VAR}}
    public int     DelayMs        { get; set; } = 0;
    public string  ConditionType  { get; set; } = "always";  // always | if_response | if_no_response
    public string  ConditionValue { get; set; } = "";         // hex substring or text to match
    public bool    Enabled        { get; set; } = true;
    public bool    AbortOnFail    { get; set; } = false;

    [JsonIgnore]
    public MacroStepResult LastResult { get; set; } = MacroStepResult.Pending;
    [JsonIgnore]
    public string          LastResponse { get; set; } = "";
}

public sealed class MacroVar
{
    public string Name  { get; set; } = "VAR";
    public string Value { get; set; } = "";
}

public enum MacroStepResult { Pending, Running, Sent, ConditionPass, ConditionFail, Skipped, Error }
