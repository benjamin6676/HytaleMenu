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
        _window.Closing += OnClosing;
    }

    public void Run() => _window!.Run();

    private void OnLoad()
    {
        _gl    = _window!.CreateOpenGL();
        _input = _window.CreateInput();
        _imgui = new ImGuiController(_gl, _window, _input);

        var io = ImGui.GetIO();
        io.ConfigFlags    |= ImGuiConfigFlags.NavEnableKeyboard;
        io.FontGlobalScale = 1.15f;   // bump all text up ~15%

        foreach (var keyboard in _input.Keyboards)
            keyboard.KeyDown += OnKeyDown;

        MenuRenderer.ApplyTheme();
        _menu = new MenuRenderer();
    }

    private void OnKeyDown(IKeyboard keyboard, Key key, int scancode)
    {
        bool ctrl = keyboard.IsKeyPressed(Key.ControlLeft)
                 || keyboard.IsKeyPressed(Key.ControlRight);

        if (key == Key.V && ctrl)
        {
            string text = GetClipboardText();
            if (!string.IsNullOrEmpty(text))
                foreach (char c in text)
                    ImGui.GetIO().AddInputCharacter(c);
        }
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

    private void OnUpdate(double dt) => _imgui!.Update((float)dt);

    private void OnRender(double dt)
    {
        _gl!.ClearColor(0.07f, 0.08f, 0.08f, 1f);
        _gl.Clear(ClearBufferMask.ColorBufferBit);
        _menu!.Render();
        _imgui!.Render();
    }

    private void OnResize(Vector2D<int> size) => _gl?.Viewport(size);

    private void OnClosing()
    {
        _imgui?.Dispose();
        _input?.Dispose();
        _gl?.Dispose();
    }

    public void Dispose() => _window?.Dispose();
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
