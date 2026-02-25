namespace HytaleSecurityTester.Core;

/// <summary>
/// Scans the most recent captured packets and extracts best-guess values for
/// ItemID, PlayerID, and EntityID. Used to auto-populate input fields in
/// Privilege Escalation, Item Inspector, etc. so they always have real values.
/// </summary>
public static class ContextFiller
{
    /// <summary>
    /// Scan recent packets and return the best candidate for each ID type.
    /// Returns null for a type if nothing was found.
    /// </summary>
    public static ContextSnapshot Fill(PacketCapture capture, UdpProxy udpProxy)
    {
        // Combine both sources: TCP captured packets + UDP proxy captured packets
        var packets = capture.GetPackets();
        // Take the 100 most recent
        var recent = packets.Count > 100
            ? packets.GetRange(packets.Count - 100, 100)
            : packets;

        uint? bestItemId   = null;
        uint? bestPlayerId = null;
        uint? bestEntityId = null;
        string? playerName = null;

        foreach (var pkt in Enumerable.Reverse(recent))
        {
            if (pkt.RawBytes.Length < 4) continue;
            var analysis = PacketAnalyser.Analyse(pkt);

            foreach (var guess in analysis.Guesses)
            {
                string n = guess.Name;

                if (bestItemId == null && n.StartsWith("Item ID?"))
                    bestItemId = guess.IntValue >= 0 ? (uint)guess.IntValue : (uint?)null;

                if (bestPlayerId == null && n.StartsWith("Entity/Player ID?"))
                    bestPlayerId = guess.IntValue >= 0 ? (uint)guess.IntValue : (uint?)null;

                if (bestEntityId == null && n.StartsWith("Entity/Player ID?")
                    && (uint)guess.IntValue != bestPlayerId)
                    bestEntityId = guess.IntValue >= 0 ? (uint)guess.IntValue : (uint?)null;

                if (playerName == null && n.StartsWith("Player Name"))
                    playerName = guess.StrValue;
            }

            // Stop early if we found everything
            if (bestItemId.HasValue && bestPlayerId.HasValue && playerName != null)
                break;
        }

        return new ContextSnapshot
        {
            ItemId     = bestItemId,
            PlayerId   = bestPlayerId,
            EntityId   = bestEntityId,
            PlayerName = playerName,
            Source     = $"Last {recent.Count} packets"
        };
    }
}

public class ContextSnapshot
{
    public uint?  ItemId     { get; set; }
    public uint?  PlayerId   { get; set; }
    public uint?  EntityId   { get; set; }
    public string? PlayerName { get; set; }
    public string  Source    { get; set; } = "";

    public bool HasItem   => ItemId.HasValue;
    public bool HasPlayer => PlayerId.HasValue || PlayerName != null;
}
