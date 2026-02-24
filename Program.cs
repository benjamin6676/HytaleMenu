using HytaleSecurityTester.Core;

namespace HytaleSecurityTester;

internal class Program
{
    static void Main(string[] args)
    {
        // Install global handlers to capture startup/runtime exceptions and log them
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            try { ReportFatal(e.ExceptionObject as Exception ?? new Exception("Unhandled exception")); }
            catch { }
        };
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            try { ReportFatal(e.Exception); }
            catch { }
        };

        try
        {
            // Do NOT use `using` — Silk.NET's Run() owns the full window/GL/ImGui lifecycle.
            // Calling Dispose() after Run() returns triggers "Cannot call Reset inside the
            // render loop" because ImGuiController.Dispose() calls back into the window
            // which Silk.NET has already started tearing down internally.
            var app = new Application();
            app.Run();
            // app.Dispose() intentionally NOT called — OS cleans up on exit.
        }
        catch (Exception ex)
        {
            ReportFatal(ex);
        }
    }

    private static void ReportFatal(Exception ex)
    {
        try
        {
            string msg = $"Fatal exception: {ex.GetType()}: {ex.Message}\n\n{ex.StackTrace}";
            // write to crash log
            try { System.IO.File.WriteAllText("crash.log", msg); } catch { }

            // attempt to show a native message box so the user sees the error even without WinForms
            try
            {
                NativeMethods.MessageBoxW(IntPtr.Zero, msg, "HytaleSecurityTester - Crash", 0);
            }
            catch { }
        }
        catch { }
    }

    private static class NativeMethods
    {
        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        public static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);
    }
}
