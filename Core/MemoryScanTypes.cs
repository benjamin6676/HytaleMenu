using System;

namespace HytaleSecurityTester.Core
{
    /// <summary>
    /// How the entity ID was read from memory.
    /// Knowing the read method helps the UI show why a candidate was found.
    /// </summary>
    public enum EntityIdType { Int32, UInt32, Int64, UInt64, UuidLo32 }

    public class LocalPlayerCandidate
    {
        public string       FoundName        { get; set; } = "";
        public string       NameAddrHex      { get; set; } = "0x0";
        public string       EntityIdAddrHex  { get; set; } = "0x0";
        public int          Offset           { get; set; } = 0;     // bytes from name to entity id field

        /// <summary>
        /// FIX: was `int` - caused silent corruption of IDs > 2^31.
        /// Now `uint` to match the rest of the codebase (SmartDetect, EntityTracker, etc.)
        /// Cast to (uint) when calling SetLocalPlayerEntityId.
        /// </summary>
        public uint         EntityId         { get; set; } = 0;

        /// <summary>Optional 64-bit form when the field in memory was 8 bytes.</summary>
        public ulong        EntityId64       { get; set; } = 0;

        public EntityIdType IdType           { get; set; } = EntityIdType.UInt32;

        /// <summary>How many bytes the ID field occupies at EntityIdAddress (4 or 8).</summary>
        public int          IdSize           { get; set; } = 4;

        /// <summary>Human-readable description of the read method (LE-uint32, BE-uint32, int64-low32).</summary>
        public string       ReadMethod       { get; set; } = "LE-uint32";

        public int          Score            { get; set; } = 0;
        public IntPtr       NameAddress      { get; set; }
        public IntPtr       EntityIdAddress  { get; set; }

        public override string ToString()
            => $"{FoundName} @ {NameAddrHex} id={EntityId} ({ReadMethod}) addr={EntityIdAddrHex} score={Score}";
    }
}
