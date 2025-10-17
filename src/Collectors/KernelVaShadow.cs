using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal sealed class KernelVaShadow : Collector {
        private KernelVaShadowInfo _kernelVaShadowInfo;

        public KernelVaShadow() : base("Kernel VA Shadowing") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            RetrieveInfo();
        }

        /// <summary>Retrieve Kernel Virtual Address (KVA) Shadow information</summary>
        /// <remarks>
        ///     This information is only exposed via the NtQuerySystemInformation function in the native API. Microsoft has
        ///     documented this information class, although currently there are 18 unused bits in the 32-bit bit field.
        /// </remarks>
        private void RetrieveInfo() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            var kernelVaShadowInfoLength = Marshal.SizeOf(typeof(KernelVaShadowInfo));
            WriteConsoleDebug($"Size of {nameof(KernelVaShadowInfo)} structure: {kernelVaShadowInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemKernelVaShadowInformation,
                                                    out _kernelVaShadowInfo,
                                                    (uint)kernelVaShadowInfoLength,
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
            return JsonConvert.SerializeObject(_kernelVaShadowInfo);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(true);
            foreach (var property in _kernelVaShadowInfo.GetType().GetProperties()) {
                if (property.PropertyType == typeof(bool)) {
                    WriteConsoleEntry(property.Name, (bool)property.GetValue(_kernelVaShadowInfo));
                } else if (property.PropertyType == typeof(byte)) {
                    WriteConsoleEntry(property.Name, ((byte)property.GetValue(_kernelVaShadowInfo)).ToString());
                }
            }
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out KernelVaShadowInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

        private struct KernelVaShadowInfo {
            private uint _RawBits;

            [JsonProperty(Order = 1)]
            public bool KvaShadowEnabled => (_RawBits & 0x1) == 1; // Bit 0

            [JsonProperty(Order = 2)]
            public bool KvaShadowUserGlobal => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

            [JsonProperty(Order = 3)]
            public bool KvaShadowPcid => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

            [JsonProperty(Order = 4)]
            public bool KvaShadowInvpcid => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

            [JsonProperty(Order = 5)]
            public bool KvaShadowRequired => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

            [JsonProperty(Order = 6)]
            public bool KvaShadowRequiredAvailable => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

            [JsonProperty(Order = 7)]
            public byte InvalidPteBit => (byte)((_RawBits >> 6) & 0x3F); // Bit 6-11

            [JsonProperty(Order = 8)]
            public bool L1DataCacheFlushSupported => ((_RawBits >> 12) & 0x1) == 1; // Bit 12

            [JsonProperty(Order = 9)]
            public bool L1TerminalFaultMitigationPresent => ((_RawBits >> 13) & 0x1) == 1; // Bit 13
        }

        #endregion
    }
}
