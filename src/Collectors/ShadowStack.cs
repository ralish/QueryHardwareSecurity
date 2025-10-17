using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal sealed class ShadowStack : Collector {
        private ShadowStackInfo _shadowStackInfo;

        public ShadowStack() : base("Shadow Stack") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            var shadowStackInfoLength = Marshal.SizeOf(typeof(ShadowStackInfo));
            WriteConsoleDebug($"Size of {nameof(ShadowStackInfo)} structure: {shadowStackInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemShadowStackInformation,
                                                    out _shadowStackInfo,
                                                    (uint)shadowStackInfoLength,
                                                    IntPtr.Zero);

            switch (ntStatus) {
                case 0: return;
                case -1073741821: // STATUS_INVALID_INFO_CLASS
                case -1073741822: // STATUS_NOT_IMPLEMENTED
                    throw new NotImplementedException($"System support for querying {Name} information not present.");
            }

            WriteConsoleVerbose($"Error requesting {Name} information: {ntStatus}");
            var symbolicNtStatus = GetSymbolicNtStatus(ntStatus);
            throw new Win32Exception(symbolicNtStatus);
        }

        public override string ConvertToJson() {
            return JsonConvert.SerializeObject(_shadowStackInfo);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(true);
            foreach (var property in _shadowStackInfo.GetType().GetProperties()) {
                if (property.PropertyType == typeof(bool)) {
                    WriteConsoleEntry(property.Name, (bool)property.GetValue(_shadowStackInfo));
                } else if (property.PropertyType == typeof(byte)) {
                    WriteConsoleEntry(property.Name, ((byte)property.GetValue(_shadowStackInfo)).ToString());
                }
            }
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out ShadowStackInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

        private struct ShadowStackInfo {
            private uint _RawBits;

            [JsonProperty(Order = 1)]
            public bool CetCapable => (_RawBits & 0x1) == 1; // Bit 0

            [JsonProperty(Order = 2)]
            public bool UserCetAllowed => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

            private byte ReservedForUserCet => (byte)((_RawBits >> 2) & 0x3F); // Bit 2-7

            [JsonProperty(Order = 3)]
            public bool KernelCetEnabled => ((_RawBits >> 7) & 0x1) == 1; // Bit 8

            [JsonProperty(Order = 4)]
            public bool KernelCetAuditModeEnabled => ((_RawBits >> 8) & 0x1) == 1; // Bit 9

            private byte ReservedForKernelCet => (byte)((_RawBits >> 9) & 0x3F); // Bit 10-15
        }

        #endregion
    }
}
