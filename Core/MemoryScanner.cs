using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;

namespace HytaleSecurityTester.Core
{
    public class MemoryScanner
    {
        private IntPtr _processHandle = IntPtr.Zero;
        public long ClientBase { get; private set; }

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwAccess, bool bInherit, int dwPid);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProc, long lpBase, byte[] lpBuf, int dwSize, out int lpRead);

        public bool Connect()
        {
            var proc = Process.GetProcessesByName("Hytale").FirstOrDefault();
            if (proc == null) return false;
            _processHandle = OpenProcess(0x0010 | 0x0400, false, proc.Id);
            ClientBase = proc.MainModule.BaseAddress.ToInt64();
            return _processHandle != IntPtr.Zero;
        }

        public T Read<T>(long addr) where T : unmanaged
        {
            unsafe
            {
                int size = sizeof(T);
                byte[] buf = new byte[size];
                ReadProcessMemory(_processHandle, addr, buf, size, out _);
                fixed (byte* p = buf) return *(T*)p;
            }
        }
    }
}
