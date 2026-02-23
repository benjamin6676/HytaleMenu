using System;
using System.Collections.Concurrent;
using System.Threading;

// Compatibility shim in global namespace in case ImGuiNET namespace isn't imported.
public static class ImGuiListClipperCompatibility
{
    private static long _nextId2 = 0;
    private static readonly ConcurrentDictionary<long, byte> _state2 = new();

    public static void Begin(ref ImGuiNET.ImGuiListClipper clipper, int itemsCount, float itemsHeight)
    {
        clipper.ItemsCount = itemsCount;
        clipper.ItemsHeight = itemsHeight;
        clipper.DisplayStart = 0;
        clipper.DisplayEnd = itemsCount;
        var id = Interlocked.Increment(ref _nextId2);
        clipper.Ctx = (nint)id;
        _state2[(long)id] = 0;
    }

    public static bool Step(ref ImGuiNET.ImGuiListClipper clipper)
    {
        if (clipper.ItemsCount <= 0) return false;
        long id = (long)clipper.Ctx;
        if (!_state2.TryGetValue(id, out var v)) return false;
        if (v == 0)
        {
            _state2[id] = 1;
            return true;
        }
        return false;
    }

    public static void End(ref ImGuiNET.ImGuiListClipper clipper)
    {
        long id = (long)clipper.Ctx;
        _state2.TryRemove(id, out _);
        clipper.Ctx = (nint)0;
    }
}
