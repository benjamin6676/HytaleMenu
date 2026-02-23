using System;
using System.Collections.Concurrent;
using System.Threading;

namespace ImGuiNET
{
    // Lightweight compatibility shim for ImGuiListClipper Begin/Step/End
    // Some ImGui.NET builds expose instance methods; others only provide the struct.
    // Provide minimal behavior: iterate once over full range (no clipping) to keep UI correct.
    public static class ImGuiListClipperExtensions
    {
        private static long _nextId = 0;
        private static readonly ConcurrentDictionary<long, byte> _state = new();

        public static void Begin(this ref ImGuiListClipper clipper, int itemsCount, float itemsHeight)
        {
            clipper.ItemsCount = itemsCount;
            clipper.ItemsHeight = itemsHeight;
            clipper.DisplayStart = 0;
            clipper.DisplayEnd = itemsCount;
            var id = Interlocked.Increment(ref _nextId);
            clipper.Ctx = (nint)id;
            _state[(long)id] = 0;
        }

        public static bool Step(this ref ImGuiListClipper clipper)
        {
            if (clipper.ItemsCount <= 0) return false;
            long id = (long)clipper.Ctx;
            if (!_state.TryGetValue(id, out var v)) return false;
            if (v == 0)
            {
                _state[id] = 1;
                return true;
            }
            return false;
        }

        public static void End(this ref ImGuiListClipper clipper)
        {
            long id = (long)clipper.Ctx;
            _state.TryRemove(id, out _);
            clipper.Ctx = (nint)0;
        }
    }
}
