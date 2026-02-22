namespace HytaleSecurityTester.Core;

/// <summary>
/// Packet differential analysis engine.
///
/// You capture the same in-game action multiple times, varying one thing
/// each time (item ID, count, slot, etc.).  Feed those packet captures here
/// and the engine diffs them byte by byte to tell you exactly which bytes
/// changed and by how much — giving you a real packet map without needing
/// documentation.
///
/// Example workflow:
///   - Drop item ID 100 → capture packet A
///   - Drop item ID 200 → capture packet B
///   - DiffEngine.Diff(A, B) → shows bytes 1-4 changed by +100 → that's the item ID field
/// </summary>
public static class DiffEngine
{
    // ── Single diff ───────────────────────────────────────────────────────

    public static DiffResult Diff(byte[] a, byte[] b, string labelA = "A", string labelB = "B")
    {
        var result = new DiffResult
        {
            LabelA   = labelA,
            LabelB   = labelB,
            LengthA  = a.Length,
            LengthB  = b.Length,
            Identical = a.SequenceEqual(b),
        };

        int maxLen = Math.Max(a.Length, b.Length);
        int minLen = Math.Min(a.Length, b.Length);

        // Byte-by-byte diff
        for (int i = 0; i < maxLen; i++)
        {
            bool inA = i < a.Length;
            bool inB = i < b.Length;

            if (!inA)  { result.Bytes.Add(new ByteDiff(i, null, b[i], DiffKind.Added));   continue; }
            if (!inB)  { result.Bytes.Add(new ByteDiff(i, a[i], null, DiffKind.Removed)); continue; }
            if (a[i] != b[i])
                result.Bytes.Add(new ByteDiff(i, a[i], b[i], DiffKind.Changed));
            else
                result.Bytes.Add(new ByteDiff(i, a[i], b[i], DiffKind.Same));
        }

        // Find changed regions and try to interpret them
        result.ChangedRegions = FindChangedRegions(result.Bytes, a, b);
        result.Summary        = BuildSummary(result);
        return result;
    }

    // ── Multi-capture diff (3+ captures of same action) ──────────────────

    /// <summary>
    /// Takes N captures of the same action and diffs all of them together.
    /// Returns a "field map" showing which byte ranges vary across all captures
    /// and what the variance looks like — stable bytes are likely fixed headers,
    /// varying bytes are likely data fields.
    /// </summary>
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

        // For each byte position, collect all values seen
        var byteValues = new Dictionary<int, List<byte>>();
        for (int i = 0; i < maxLen; i++)
        {
            byteValues[i] = new List<byte>();
            foreach (var pkt in packets)
                if (i < pkt.Data.Length) byteValues[i].Add(pkt.Data[i]);
        }

        // Build field map
        for (int i = 0; i < minLen; i++)
        {
            var vals  = byteValues[i];
            bool same = vals.Distinct().Count() == 1;

            var field = new FieldMapEntry
            {
                Offset   = i,
                IsFixed  = same,
                FixedVal = same ? vals[0] : (byte?)null,
                Values   = vals.ToList(),
                UniqueCount = vals.Distinct().Count(),
            };

            // Try to group into int32/int16 ranges
            if (!same && i + 3 < minLen)
            {
                bool nextThreeSame = byteValues[i+1].Distinct().Count() > 1 ||
                                     byteValues[i+2].Distinct().Count() > 1 ||
                                     byteValues[i+3].Distinct().Count() > 1;
                if (nextThreeSame)
                {
                    // Check if reading int32 LE makes sense across all packets
                    var int32vals = packets
                        .Where(p => i + 4 <= p.Data.Length)
                        .Select(p => BitConverter.ToInt32(p.Data, i))
                        .Distinct().ToList();

                    if (int32vals.Count == packets.Count)
                        field.Int32Interpretation = int32vals;
                }
            }

            field.Hint = GuessFieldHint(i, field, packets);
            result.Fields.Add(field);
        }

        // Pair-wise diffs for the detail view
        for (int i = 0; i < packets.Count - 1; i++)
            result.PairDiffs.Add(Diff(packets[i].Data, packets[i+1].Data,
                packets[i].Label, packets[i+1].Label));

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

            // Try to interpret the changed bytes as common types
            if (len == 4 && start + 4 <= Math.Min(a.Length, b.Length))
            {
                int va = BitConverter.ToInt32(a, start);
                int vb = BitConverter.ToInt32(b, start);
                region.InterpretationA = $"int32: {va}";
                region.InterpretationB = $"int32: {vb}";
                region.Delta           = vb - va;
                region.Hint            = GuessRegionHint(start, len, va, vb);
            }
            else if (len == 2 && start + 2 <= Math.Min(a.Length, b.Length))
            {
                ushort va = BitConverter.ToUInt16(a, start);
                ushort vb = BitConverter.ToUInt16(b, start);
                region.InterpretationA = $"uint16: {va}";
                region.InterpretationB = $"uint16: {vb}";
                region.Delta           = vb - va;
                region.Hint            = GuessRegionHint(start, len, va, vb);
            }
            else if (len == 1)
            {
                region.InterpretationA = $"byte: {(start < a.Length ? a[start] : 0)}";
                region.InterpretationB = $"byte: {(start < b.Length ? b[start] : 0)}";
                region.Delta           = (start < b.Length ? b[start] : 0) -
                                         (start < a.Length ? a[start] : 0);
            }
            else
            {
                // Try to extract a string
                string sa = TryString(a, start, len);
                string sb = TryString(b, start, len);
                if (!string.IsNullOrEmpty(sa) || !string.IsNullOrEmpty(sb))
                {
                    region.InterpretationA = $"string: \"{sa}\"";
                    region.InterpretationB = $"string: \"{sb}\"";
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
        if (offset <= 1 && len == 1) return "Packet ID / type byte";
        if (va >= 100 && va <= 9999 && vb >= 100 && vb <= 9999) return "Likely item ID";
        if (va >= 1   && va <= 999  && vb >= 1   && vb <= 999)  return "Likely stack count or slot";
        if (va >= 1000 && vb >= 1000)                            return "Likely entity/player ID";
        if (offset >= 1 && offset <= 4 && len == 4)              return "Likely sequence number";
        if (len == 4 && delta > 100000)                          return "Likely timestamp or hash";
        return "";
    }

    private static string GuessFieldHint(int offset, FieldMapEntry field,
                                          List<LabelledPacket> packets)
    {
        if (field.IsFixed)
        {
            if (offset == 0)          return "Fixed packet ID";
            if (field.FixedVal == 0)  return "Padding / reserved";
            return "Fixed header byte";
        }
        var int32s = field.Int32Interpretation;
        if (int32s != null && int32s.Count > 0)
        {
            long min = int32s.Min();
            long max = int32s.Max();
            if (min >= 100 && max <= 9999)  return "Item ID field";
            if (min >= 1   && max <= 999)   return "Stack count / slot";
            if (min >= 1000 && max >= 1000) return "Entity / player ID";
        }
        return "Variable field";
    }

    private static string TryString(byte[] data, int offset, int len)
    {
        if (offset + len > data.Length) return "";
        var bytes = data.Skip(offset).Take(len).ToArray();
        if (bytes.All(b => b >= 32 && b < 127))
            return System.Text.Encoding.ASCII.GetString(bytes);
        return "";
    }

    private static string BuildSummary(DiffResult r)
    {
        if (r.Identical) return "Packets are identical.";
        int changed = r.Bytes.Count(b => b.Kind == DiffKind.Changed);
        int added   = r.Bytes.Count(b => b.Kind == DiffKind.Added);
        int removed = r.Bytes.Count(b => b.Kind == DiffKind.Removed);
        return $"{changed} bytes changed, {added} added, {removed} removed. " +
               $"{r.ChangedRegions.Count} distinct regions.";
    }

    private static string BuildMultiSummary(MultiDiffResult r, int count)
    {
        int fixedCount   = r.Fields.Count(f => f.IsFixed);
        int varCount     = r.Fields.Count(f => !f.IsFixed);
        int itemIdFields = r.Fields.Count(f => f.Hint.Contains("Item ID"));
        return $"{count} packets compared. {fixedCount} fixed bytes (header), " +
               $"{varCount} variable bytes ({itemIdFields} likely item ID fields).";
    }
}

// ── Result types ──────────────────────────────────────────────────────────────

public class DiffResult
{
    public string           LabelA         { get; set; } = "";
    public string           LabelB         { get; set; } = "";
    public int              LengthA        { get; set; }
    public int              LengthB        { get; set; }
    public bool             Identical      { get; set; }
    public string           Summary        { get; set; } = "";
    public List<ByteDiff>   Bytes          { get; set; } = new();
    public List<ChangedRegion> ChangedRegions { get; set; } = new();
}

public class ByteDiff
{
    public int      Offset { get; }
    public byte?    A      { get; }
    public byte?    B      { get; }
    public DiffKind Kind   { get; }

    public ByteDiff(int offset, byte? a, byte? b, DiffKind kind)
    { Offset = offset; A = a; B = b; Kind = kind; }
}

public class ChangedRegion
{
    public int    StartOffset      { get; set; }
    public int    Length           { get; set; }
    public string InterpretationA  { get; set; } = "";
    public string InterpretationB  { get; set; } = "";
    public long   Delta            { get; set; }
    public string Hint             { get; set; } = "";
}

public class MultiDiffResult
{
    public string                Error      { get; set; } = "";
    public int                   MinLength  { get; set; }
    public int                   MaxLength  { get; set; }
    public string                Summary    { get; set; } = "";
    public List<FieldMapEntry>   Fields     { get; set; } = new();
    public List<DiffResult>      PairDiffs  { get; set; } = new();
}

public class FieldMapEntry
{
    public int         Offset              { get; set; }
    public bool        IsFixed             { get; set; }
    public byte?       FixedVal            { get; set; }
    public List<byte>  Values              { get; set; } = new();
    public int         UniqueCount         { get; set; }
    public List<int>?  Int32Interpretation { get; set; }
    public string      Hint                { get; set; } = "";
}

public class LabelledPacket
{
    public string Label { get; set; } = "";
    public byte[] Data  { get; set; } = Array.Empty<byte>();
}

public enum DiffKind { Same, Changed, Added, Removed }
