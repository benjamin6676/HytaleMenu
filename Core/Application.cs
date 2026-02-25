using Silk.NET.Input;
using Silk.NET.Maths;
using Silk.NET.OpenGL;
using Silk.NET.OpenGL.Extensions.ImGui;
using Silk.NET.Windowing;
using ImGuiNET;
using System.Runtime.InteropServices;

namespace HytaleSecurityTester.Core;

public sealed class Application : IDisposable
{
    private IWindow?         _window;
    private GL?              _gl;
    private IInputContext?   _input;
    private ImGuiController? _imgui;
    private MenuRenderer?    _menu;

    public Application()
    {
        var opts = WindowOptions.Default with
        {
            Title = "Hytale Security Tester",
            Size  = new Vector2D<int>(1100, 720),
            VSync = true,
        };

        _window          = Window.Create(opts);
        _window.Load    += OnLoad;
        _window.Update  += OnUpdate;
        _window.Render  += OnRender;
        _window.Resize  += OnResize;
        // NOTE: Do NOT hook Closing - Silk.NET fires it from inside the render loop
        // and disposing there crashes with "Cannot call Reset inside the render loop".
    }

    public void Run() => _window!.Run();

    private void OnLoad()
    {
        _gl = _window!.CreateOpenGL();
        _input = _window.CreateInput();
        _imgui = new ImGuiController(_gl, _window, _input); // Bruk _input her

        var io = ImGui.GetIO();
        io.ConfigFlags |= ImGuiConfigFlags.NavEnableKeyboard;
        io.FontGlobalScale = 1.15f;

        foreach (var keyboard in _input.Keyboards)
            keyboard.KeyDown += OnKeyDown;

        MenuRenderer.ApplyTheme();
        _menu = new MenuRenderer();
    }


    private void OnKeyDown(IKeyboard keyboard, Key key, int scancode)
    {
        // Fix: Parsec / remote-desktop sends Key.Unknown for unmapped keys.
        // Passing Unknown to ImGui triggers NotImplementedException in
        // TranslateInputKeyToImGuiKey - drop it here before it reaches ImGui.
        if (key == Key.Unknown) return;

        bool ctrl = keyboard.IsKeyPressed(Key.ControlLeft)
                 || keyboard.IsKeyPressed(Key.ControlRight);

        // ── Paste intercept ──────────────────────────────────────────────
        if (key == Key.V && ctrl)
        {
            string text = GetClipboardText();
            if (!string.IsNullOrEmpty(text))
                foreach (char c in text)
                    ImGui.GetIO().AddInputCharacter(c);
        }

        // ── Global hotkey dispatch ───────────────────────────────────────
        // Panic hotkey: instantly close the application
        if (key == GlobalHotkeyConfig.Instance.PanicHotkey)
        {
            _window?.Close();
            return;
        }

        // Capture key binding if Settings tab is waiting for input
        GlobalHotkeyConfig.Instance.TryCapture(key);
    }

    private static string GetClipboardText()
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return WindowsClipboard.Get();

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                var p = System.Diagnostics.Process.Start(
                    new System.Diagnostics.ProcessStartInfo
                    {
                        FileName               = "pbpaste",
                        RedirectStandardOutput = true,
                        UseShellExecute        = false,
                    });
                return p?.StandardOutput.ReadToEnd() ?? "";
            }

            var xclip = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo
                {
                    FileName               = "xclip",
                    Arguments              = "-selection clipboard -o",
                    RedirectStandardOutput = true,
                    UseShellExecute        = false,
                });
            return xclip?.StandardOutput.ReadToEnd() ?? "";
        }
        catch { return ""; }
    }

    private void OnUpdate(double dt)
    {
        try
        {
            _imgui!.Update((float)dt);
        }
        catch (System.NotImplementedException ex) when (ex.Message.Contains("TranslateInputKeyToImGuiKey"))
        {
            // Vi fanger Silk.NET sin krasj for ukjente taster her.
            // Programmet fortsetter å kjøre som om ingenting skjedde.
        }
    }

    private void OnRender(double dt)
    {
        _gl!.ClearColor(0.07f, 0.08f, 0.08f, 1f);
        _gl.Clear(ClearBufferMask.ColorBufferBit);
        _menu!.Render();

        // Draw entity bounding boxes on background draw list BEFORE ImGui render
        DrawEntityOverlays();

        _imgui!.Render();
    }

    // ── Entity Visualizer ─────────────────────────────────────────────────
    //
    // Feed world-space Vector3 coordinates (from memory reader or packet data)
    // to this list at any time. The overlay will project them to screen and
    // draw bounding boxes using the ImGui background draw list.
    //
    // Usage from MemoryTab / ItemInspectorTab:
    //   Application.EntityPositions.Add(new Vector3(x, y, z));

    public static readonly List<EntityOverlayEntry> EntityPositions = new();

    // Set this from MenuRenderer / MemoryTab when you have a real view matrix
    public static Matrix4x4 ViewProjectionMatrix = Matrix4x4.Identity;

    /// <summary>
    /// When true, entity positions are treated as screen pixels (X,Y) instead
    /// of world-space. Useful for testing the rendering engine without a VP matrix.
    /// </summary>
    public static bool ScreenSpaceMode = false;

    /// <summary>
    /// Projects a world-space position to 2D screen coordinates using the
    /// 4x4 view-projection matrix. Returns false if the point is behind
    /// the camera (clip-space W ≤ 0).
    /// </summary>
    public static bool WorldToScreen(Vector3 worldPos, Vector2 screenSize,
                                     out Vector2 screenPos)
    {
        screenPos = Vector2.Zero;
        var m   = ViewProjectionMatrix;

        float clipX = worldPos.X * m.M11 + worldPos.Y * m.M21 + worldPos.Z * m.M31 + m.M41;
        float clipY = worldPos.X * m.M12 + worldPos.Y * m.M22 + worldPos.Z * m.M32 + m.M42;
        float clipW = worldPos.X * m.M14 + worldPos.Y * m.M24 + worldPos.Z * m.M34 + m.M44;

        if (clipW <= 0f) return false; // behind camera

        float ndcX = clipX / clipW;
        float ndcY = clipY / clipW;

        screenPos = new Vector2(
            (ndcX + 1f) * 0.5f * screenSize.X,
            (1f - ndcY) * 0.5f * screenSize.Y   // Y flipped for screen coords
        );
        return true;
    }

    private void DrawEntityOverlays()
    {
        if (EntityPositions.Count == 0) return;

        var io         = ImGui.GetIO();
        var screenSize = io.DisplaySize;
        var drawList   = ImGui.GetBackgroundDrawList();

        lock (EntityPositions)
        {
            foreach (var entry in EntityPositions)
            {
                Vector2 center;

                if (ScreenSpaceMode)
                {
                    // Screen-space: X,Y are direct pixel coordinates
                    center = new Vector2(entry.Position.X, entry.Position.Y);
                }
                else
                {
                    if (!WorldToScreen(entry.Position, screenSize, out center))
                        continue;
                }

                // Draw bounding box
                float hw = entry.Width  * 0.5f;
                float hh = entry.Height * 0.5f;

                var tl = new Vector2(center.X - hw, center.Y - hh);
                var br = new Vector2(center.X + hw, center.Y + hh);

                uint boxColor  = ImGui.ColorConvertFloat4ToU32(entry.Color);
                uint textColor = ImGui.ColorConvertFloat4ToU32(new Vector4(1, 1, 1, 0.9f));

                drawList.AddRect(tl, br, boxColor, 0f, ImDrawFlags.None, 1.5f);

                // Corner ticks
                float cs = Math.Min(hw, hh) * 0.3f;
                uint tc = boxColor;
                drawList.AddLine(tl,                  tl + new Vector2(cs, 0),    tc, 2f);
                drawList.AddLine(tl,                  tl + new Vector2(0,  cs),   tc, 2f);
                drawList.AddLine(br,                  br - new Vector2(cs, 0),    tc, 2f);
                drawList.AddLine(br,                  br - new Vector2(0,  cs),   tc, 2f);
                drawList.AddLine(new Vector2(br.X, tl.Y), new Vector2(br.X - cs, tl.Y), tc, 2f);
                drawList.AddLine(new Vector2(br.X, tl.Y), new Vector2(br.X, tl.Y + cs), tc, 2f);
                drawList.AddLine(new Vector2(tl.X, br.Y), new Vector2(tl.X + cs, br.Y), tc, 2f);
                drawList.AddLine(new Vector2(tl.X, br.Y), new Vector2(tl.X, br.Y - cs), tc, 2f);

                // Label
                if (!string.IsNullOrEmpty(entry.Label))
                    drawList.AddText(new Vector2(center.X - 20, tl.Y - 14), textColor, entry.Label);
            }
        }
    }

    private void OnResize(Vector2D<int> size) => _gl?.Viewport(size);

    public void Dispose()
    {
        // Save config.json before the process exits (flush any pending debounce)
        try { GlobalConfig.Instance.SaveNow(); } catch { }

        // Intentionally not disposing Silk.NET resources here.
        // See comment below for explanation.
        _imgui = null;
        _input = null;
        _gl    = null;
        _menu  = null;
    }
}

// ── Entity Overlay Entry ──────────────────────────────────────────────────────

public class EntityOverlayEntry
{
    public Vector3 Position { get; set; }
    public string  Label    { get; set; } = "";
    public float   Width    { get; set; } = 40f;
    public float   Height   { get; set; } = 80f;
    public Vector4 Color    { get; set; } = new(0.18f, 0.95f, 0.45f, 0.9f); // green default
}

// ── Windows clipboard P/Invoke (no extra NuGet needed) ────────────────────

internal static class WindowsClipboard
{
    [DllImport("user32.dll")] static extern bool   OpenClipboard(IntPtr h);
    [DllImport("user32.dll")] static extern bool   CloseClipboard();
    [DllImport("user32.dll")] static extern bool   EmptyClipboard();
    [DllImport("user32.dll")] static extern IntPtr GetClipboardData(uint f);
    [DllImport("user32.dll")] static extern IntPtr SetClipboardData(uint f, IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr GlobalLock(IntPtr h);
    [DllImport("kernel32.dll")] static extern bool   GlobalUnlock(IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr GlobalAlloc(uint f, UIntPtr s);

    const uint CF_UNICODE = 13;
    const uint GMEM_MOVE  = 0x0002;

    public static string Get()
    {
        if (!OpenClipboard(IntPtr.Zero)) return "";
        try
        {
            IntPtr h = GetClipboardData(CF_UNICODE);
            if (h == IntPtr.Zero) return "";
            IntPtr p = GlobalLock(h);
            if (p == IntPtr.Zero) return "";
            try   { return Marshal.PtrToStringUni(p) ?? ""; }
            finally { GlobalUnlock(h); }
        }
        finally { CloseClipboard(); }
    }

    public static void Set(string text)
    {
        if (!OpenClipboard(IntPtr.Zero)) return;
        try
        {
            EmptyClipboard();
            int    bytes = (text.Length + 1) * 2;
            IntPtr hg    = GlobalAlloc(GMEM_MOVE, (UIntPtr)bytes);
            if (hg == IntPtr.Zero) return;
            IntPtr p = GlobalLock(hg);
            try   { Marshal.Copy(text.ToCharArray(), 0, p, text.Length); }
            finally { GlobalUnlock(hg); }
            SetClipboardData(CF_UNICODE, hg);
        }
        finally { CloseClipboard(); }
    }
}
