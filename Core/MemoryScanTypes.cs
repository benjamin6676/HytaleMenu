using System;
using System.Collections.Generic;

namespace HytaleSecurityTester.Core
{
    public class LocalPlayerCandidate
    {
        public string FoundName { get; set; } = "";
        public string NameAddrHex { get; set; } = "0x0";
        public string EntityIdAddrHex { get; set; } = "0x0";
        public int Offset { get; set; } = 0; // bytes from name to entity id
        public int EntityId { get; set; } = -1;
        public int Score { get; set; } = 0;
        public IntPtr NameAddress { get; set; }
        public IntPtr EntityIdAddress { get; set; }
        public override string ToString() => $"{FoundName} @ {NameAddrHex} id={EntityId} addr={EntityIdAddrHex} score={Score}";
    }
}
