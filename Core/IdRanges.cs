namespace HytaleSecurityTester.Core;

/// <summary>
/// Centralised ID range constants and validators.
///
/// Previously every subsystem had its own magic numbers (9_999, 4_000_000,
/// 16_000_000 ...) which caused silent mismatches between the packet scanner,
/// the memory scanner, and the UI.  All ranges now live here so a single
/// change propagates everywhere.
///
/// Hytale alpha entity ID observations:
///   Items   : small uint32,  typically 100 – 9 999
///   Mobs/NPCs: mid uint32,   typically 10 000 – 999 999
///   Players : uint32,        typically 1 000 – 4 000 000 (spawn-counter)
///   World   : large uint32,  up to ~16 000 000
///   UUID    : 128-bit value  (two uint64 halves - upper half often 0 in alpha)
/// </summary>
public static class IdRanges
{
    // ── Raw bounds ────────────────────────────────────────────────────────
    public const uint ItemMin      = 100;
    public const uint ItemMax      = 9_999;
    public const uint MobMin       = 10_000;
    public const uint MobMax       = 999_999;
    public const uint PlayerMin    = 1_000;
    public const uint PlayerMax    = 4_000_000;
    public const uint EntityMin    = 1;
    public const uint EntityMax    = 16_000_000;

    // VarInt IDs are typically small items
    public const uint VarIntMin    = 1;
    public const uint VarIntMax    = 9_999;

    // Loot-drop IDs come from C->S interaction packets
    public const uint LootDropMin  = 100;
    public const uint LootDropMax  = 999_999;

    // ── Classification helpers ────────────────────────────────────────────

    /// Returns true for any plausible entity ID (includes items/mobs/players).
    public static bool IsEntityId(uint v)
        => v >= EntityMin && v <= EntityMax;

    /// Returns true for item IDs specifically.
    public static bool IsItemId(uint v)
        => v >= ItemMin && v <= ItemMax;

    /// Returns true for mob/NPC IDs.
    public static bool IsMobId(uint v)
        => v >= MobMin && v <= MobMax;

    /// Returns true for player-range IDs.
    public static bool IsPlayerId(uint v)
        => v >= PlayerMin && v <= PlayerMax;

    /// Broad scan: accepts anything in entity range (does NOT filter by type).
    public static bool IsBroadEntityId(uint v)
        => v >= ItemMin && v <= EntityMax;

    /// Returns the best EntityClass guess for a given ID value alone.
    public static EntityClass GuessClassFromId(uint v)
    {
        if (v >= ItemMin  && v <= ItemMax)   return EntityClass.Item;
        if (v >= MobMin   && v <= MobMax)    return EntityClass.Mob;
        if (v >= PlayerMin && v <= PlayerMax) return EntityClass.Player;
        return EntityClass.Unknown;
    }

    // ── UUID helpers ──────────────────────────────────────────────────────

    /// Try to read a 16-byte UUID from a packet buffer.
    /// Returns the lower 64 bits as a uint64 (commonly used as entity ID).
    public static bool TryReadUuid(byte[] data, int offset, out ulong lo, out ulong hi)
    {
        lo = hi = 0;
        if (offset + 16 > data.Length) return false;
        hi = BitConverter.ToUInt64(data, offset);
        lo = BitConverter.ToUInt64(data, offset + 8);
        // Reject zero / all-ones
        if (lo == 0 && hi == 0)           return false;
        if (lo == ulong.MaxValue)          return false;
        return true;
    }

    /// Cast the lower 32 bits of a UUID lower half as a uint32 entity ID.
    public static uint UuidLo32(ulong lo) => (uint)(lo & 0xFFFF_FFFF);
}
