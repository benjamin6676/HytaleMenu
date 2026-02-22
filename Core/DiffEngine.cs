using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HytaleSecurityTester.Core;

/// <summary>
/// Packet differential analysis engine.
///
/// Capture the same in-game action multiple times varying one value each time
/// (e.g. drop item 100, drop item 200, drop item 300).
/// Feed the captures here — the engine diffs byte by byte and shows you
/// exactly which bytes changed and by how much.
/// A 4-byte region that increased by 100 each time = the item ID field.
/// </summary>
public static class DiffEngine
{
    // ── Single diff ───────────────────────────────────────────────────────

    public static DiffResult Diff(byte[] a, byte[] b,
                                   string labelA = "A", string labelB = "B")
    {
        var result = new DiffResult
        {
            LabelA    = labelA,
            LabelB    = labelB,
            LengthA   = a.Length,
            LengthB   = b.Length,
            Identical = a.SequenceEqual(b),
        };

        int maxLen = Math.Max(a.Length, b.Length);

        for (int i = 0; i < maxLen; i++)
        {
            bool inA = i < a.Length;
            bool inB = i < b.Length;

            if (!inA) { result.Bytes.Add(new ByteDiff(i, null, b[i], DiffKind.Added));   continue; }
            if (!inB) { result.Bytes.Add(new ByteDiff(i, a[i], null, DiffKind.Removed)); continue; }

            result.Bytes.Add(a[i] != b[i]
                ? new ByteDiff(i, a[i], b[i], DiffKind.Changed)
                : new ByteDiff(i, a[i], b[i], DiffKind.Same));
        }

        result.ChangedRegions = FindChangedRegions(result.Bytes, a, b);
        result.Summary        = BuildSummary(result);
        return result;
    }

    // ── Multi-capture diff ────────────────────────────────────────────────

    public static MultiDiffResult MultiDiff(List<LabelledPacket> packets)
    {
        var result = new MultiDiffResult();

        if (packets.Count < 2)
        {
            result.Error = "Need at least 2 packets to diff.";
            return result;
        }

        int minLen = packets.Min(p => p.Data.Length);
        int maxLen = packets.Max(p => p.Data.Length);
        result.MinLength = minLen;
        result.MaxLength = maxLen;

        var byteValues = new Dictionary<int, List<byte>>();
        for (int i = 0; i < maxLen; i++)
        {
            byteValues[i] = new List<byte>();
            foreach (var pkt in packets)
                if (i < pkt.Data.Length) byteValues[i].Add(pkt.Data[i]);
        }

        for (int i = 0; i < minLen; i++)
        {
            var vals  = byteValues[i];
            bool same = vals.Distinct().Count() == 1;

            var field = new FieldMapEntry
            {
                Offset      = i,
                IsFixed     = same,
                FixedVal    = same ? vals[0] : (byte?)null,
                Values      = new List<byte>(vals),
                UniqueCount = vals.Distinct().Count(),
            };

            if (!same && i + 3 < minLen)
            {
                bool adjacentVary = byteValues[i + 1].Distinct().Count() > 1
                                 || byteValues[i + 2].Distinct().Count() > 1
                                 || byteValues[i + 3].Distinct().Count() > 1;
                if (adjacentVary)
                {
                    var int32vals = new List<int>();
                    foreach (var p in packets)
                        if (i + 4 <= p.Data.Length)
                            int32vals.Add(BitConverter.ToInt32(p.Data, i));
                    int32vals = int32vals.Distinct().ToList();
                    if (int32vals.Count == packets.Count)
                        field.Int32Interpretation = int32vals;
                }
            }

            field.Hint = GuessFieldHint(i, field);
            result.Fields.Add(field);
        }

        for (int i = 0; i < packets.Count - 1; i++)
            result.PairDiffs.Add(Diff(
                packets[i].Data,  packets[i + 1].Data,
                packets[i].Label, packets[i + 1].Label));

        result.Summary = BuildMultiSummary(result, packets.Count);
        return result;
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static List<ChangedRegion> FindChangedRegions(
        List<ByteDiff> bytes, byte[] a, byte[] b)
    {
        var regions = new List<ChangedRegion>();
        int i = 0;

        while (i < bytes.Count)
        {
            if (bytes[i].Kind == DiffKind.Same) { i++; continue; }

            int start = i;
            while (i < bytes.Count && bytes[i].Kind != DiffKind.Same) i++;
            int len = i - start;

            var region = new ChangedRegion { StartOffset = start, Length = len };

            if (len == 4 && start + 4 <= Math.Min(a.Length, b.Length))
            {
                int va = BitConverter.ToInt32(a, start);
                int vb = BitConverter.ToInt32(b, start);
                region.InterpretationA = "int32: " + va;
                region.InterpretationB = "int32: " + vb;
                region.Delta           = vb - va;
                region.Hint            = GuessRegionHint(start, len, va, vb);
            }
            else if (len == 2 && start + 2 <= Math.Min(a.Length, b.Length))
            {
                ushort va = BitConverter.ToUInt16(a, start);
                ushort vb = BitConverter.ToUInt16(b, start);
                region.InterpretationA = "uint16: " + va;
                region.InterpretationB = "uint16: " + vb;
                region.Delta           = vb - va;
                region.Hint            = GuessRegionHint(start, len, va, vb);
            }
            else if (len == 1)
            {
                byte va = start < a.Length ? a[start] : (byte)0;
                byte vb = start < b.Length ? b[start] : (byte)0;
                region.InterpretationA = "byte: " + va;
                region.InterpretationB = "byte: " + vb;
                region.Delta           = vb - va;
            }
            else
            {
                string sa = TryExtractString(a, start, len);
                string sb = TryExtractString(b, start, len);
                if (sa.Length > 0 || sb.Length > 0)
                {
                    region.InterpretationA = "string: \"" + sa + "\"";
                    region.InterpretationB = "string: \"" + sb + "\"";
                    region.Hint            = "String/text field";
                }
            }

            regions.Add(region);
        }

        return regions;
    }

    private static string GuessRegionHint(int offset, int len, long va, long vb)
    {
        long delta = Math.Abs(vb - va);
        if (offset <= 1 && len == 1)                              return "Packet ID / type byte";
        if (va >= 100 && va <= 9999 && vb >= 100 && vb <= 9999)  return "Likely item ID";
        if (va >= 1   && va <= 999  && vb >= 1   && vb <= 999)   return "Likely stack count or slot";
        if (va >= 1000 && vb >= 1000)                             return "Likely entity/player ID";
        if (offset >= 1 && offset <= 4 && len == 4)               return "Likely sequence number";
        if (len == 4 && delta > 100000)                           return "Likely timestamp or hash";
        return "";
    }

    private static string GuessFieldHint(int offset, FieldMapEntry field)
    {
        if (field.IsFixed)
        {
            if (offset == 0)         return "Fixed packet ID";
            if (field.FixedVal == 0) return "Padding / reserved";
            return "Fixed header byte";
        }

        var int32s = field.Int32Interpretation;
        if (int32s != null && int32s.Count > 0)
        {
            long min = int32s.Min();
            long max = int32s.Max();
            if (min >= 100  && max <= 9999) return "Item ID field";
            if (min >= 1    && max <= 999)  return "Stack count / slot";
            if (min >= 1000 && max >= 1000) return "Entity / player ID";
        }

        return "Variable field";
    }

    private static string TryExtractString(byte[] data, int offset, int len)
    {
        if (offset + len > data.Length) return "";
        var slice = new byte[len];
        Array.Copy(data, offset, slice, 0, len);
        foreach (byte b in slice)
            if (b < 32 || b >= 127) return "";
        return Encoding.ASCII.GetString(slice);
    }

    private static string BuildSummary(DiffResult r)
    {
        if (r.Identical) return "Packets are identical.";
        int changed = 0, added = 0, removed = 0;
        foreach (var b in r.Bytes)
        {
            if (b.Kind == DiffKind.Changed) changed++;
            else if (b.Kind == DiffKind.Added)   added++;
            else if (b.Kind == DiffKind.Removed) removed++;
        }
        return changed + " bytes changed, " + added + " added, " + removed +
               " removed. " + r.ChangedRegions.Count + " distinct changed region(s).";
    }

    private static string BuildMultiSummary(MultiDiffResult r, int count)
    {
        int fixedCount = 0, varCount = 0, itemIdFields = 0;
        foreach (var f in r.Fields)
        {
            if (f.IsFixed) fixedCount++;
            else           varCount++;
            if (f.Hint.Contains("Item ID")) itemIdFields++;
        }
        return count + " packets compared. " + fixedCount + " fixed bytes (header), " +
               varCount + " variable bytes (" + itemIdFields + " likely item ID field(s)).";
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

public class DiffResult
{
    public string              LabelA         { get; set; } = "";
    public string              LabelB         { get; set; } = "";
    public int                 LengthA        { get; set; }
    public int                 LengthB        { get; set; }
    public bool                Identical      { get; set; }
    public string              Summary        { get; set; } = "";
    public List<ByteDiff>      Bytes          { get; set; } = new List<ByteDiff>();
    public List<ChangedRegion> ChangedRegions { get; set; } = new List<ChangedRegion>();
}

public class ByteDiff
{
    public int      Offset { get; }
    public byte?    A      { get; }
    public byte?    B      { get; }
    public DiffKind Kind   { get; }

    public ByteDiff(int offset, byte? a, byte? b, DiffKind kind)
    {
        Offset = offset;
        A      = a;
        B      = b;
        Kind   = kind;
    }
}

public class ChangedRegion
{
    public int    StartOffset     { get; set; }
    public int    Length          { get; set; }
    public string InterpretationA { get; set; } = "";
    public string InterpretationB { get; set; } = "";
    public long   Delta           { get; set; }
    public string Hint            { get; set; } = "";
}

public class MultiDiffResult
{
    public string              Error     { get; set; } = "";
    public int                 MinLength { get; set; }
    public int                 MaxLength { get; set; }
    public string              Summary   { get; set; } = "";
    public List<FieldMapEntry> Fields    { get; set; } = new List<FieldMapEntry>();
    public List<DiffResult>    PairDiffs { get; set; } = new List<DiffResult>();
}

public class FieldMapEntry
{
    public int        Offset              { get; set; }
    public bool       IsFixed             { get; set; }
    public byte?      FixedVal            { get; set; }
    public List<byte> Values              { get; set; } = new List<byte>();
    public int        UniqueCount         { get; set; }
    public List<int>? Int32Interpretation { get; set; }
    public string     Hint                { get; set; } = "";
}

public class LabelledPacket
{
    public string Label { get; set; } = "";
    public byte[] Data  { get; set; } = Array.Empty<byte>();
}

public enum DiffKind { Same, Changed, Added, Removed }
