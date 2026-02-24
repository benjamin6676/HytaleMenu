using HytaleSecurityTester.Core;

namespace HytaleSecurityTester;

internal class Program
{
    static void Main(string[] args)
    {
        // Behold de globale handlerne dine øverst
        AppDomain.CurrentDomain.UnhandledException += (_, e) => {
            try { ReportFatal(e.ExceptionObject as Exception ?? new Exception("Unhandled exception")); } catch { }
        };

        TaskScheduler.UnobservedTaskException += (_, e) => {
            try { ReportFatal(e.Exception); } catch { }
        };

        try
        {
            var app = new Application();
            app.Run();
        }
        catch (Exception ex)
        {
            // HER ER FIKSEN: Sjekk om krasjen skyldes Silk.NET sin tastatur-feil
            if (ex is NotImplementedException && ex.StackTrace != null && ex.StackTrace.Contains("TranslateInputKeyToImGuiKey"))
            {
                // Vi ignorerer denne spesifikke feilen og starter på nytt
                Main(args);
                return;
            }

            // For alle andre ekte feil, vis den vanlige krasj-meldingen
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
