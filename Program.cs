using HytaleSecurityTester.Core;

namespace HytaleSecurityTester;

internal class Program
{
    static void Main(string[] args)
    {
        using var app = new Application();
        app.Run();
    }
}
