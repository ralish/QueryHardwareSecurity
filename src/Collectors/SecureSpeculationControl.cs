using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal sealed class SecureSpeculationControl : Collector {
        private SecureSpeculationControlInfo _secureSpecCtrlInfo;

        public SecureSpeculationControl() : base("Secure Speculation Control") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            var secureSpecCtrlInfoLength = Marshal.SizeOf(typeof(SecureSpeculationControlInfo));
            WriteConsoleDebug($"Size of {nameof(SecureSpeculationControlInfo)} structure: {secureSpecCtrlInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemSecureSpeculationControlInformation,
                                                    out _secureSpecCtrlInfo,
                                                    (uint)secureSpecCtrlInfoLength,
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
            return JsonConvert.SerializeObject(_secureSpecCtrlInfo);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(true);
            foreach (var property in _secureSpecCtrlInfo.GetType().GetProperties()) {
                WriteConsoleEntry(property.Name, (bool)property.GetValue(_secureSpecCtrlInfo));
            }
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out SecureSpeculationControlInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

        private struct SecureSpeculationControlInfo {
            private uint _RawBits;

            [JsonProperty(Order = 1)]
            public bool KvaShadowSupported => (_RawBits & 0x1) == 1; // Bit 0

            [JsonProperty(Order = 2)]
            public bool KvaShadowEnabled => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

            [JsonProperty(Order = 3)]
            public bool KvaShadowUserGlobal => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

            [JsonProperty(Order = 4)]
            public bool KvaShadowPcid => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

            [JsonProperty(Order = 5)]
            public bool MbClearEnabled => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

            [JsonProperty(Order = 6)]
            public bool L1TFMitigated => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

            [JsonProperty(Order = 7)]
            public bool BpbEnabled => ((_RawBits >> 6) & 0x1) == 1; // Bit 6

            [JsonProperty(Order = 8)]
            public bool IbrsPresent => ((_RawBits >> 7) & 0x1) == 1; // Bit 7

            [JsonProperty(Order = 9)]
            public bool EnhancedIbrs => ((_RawBits >> 8) & 0x1) == 1; // Bit 8

            [JsonProperty(Order = 10)]
            public bool StibpPresent => ((_RawBits >> 9) & 0x1) == 1; // Bit 9

            [JsonProperty(Order = 11)]
            public bool SsbdSupported => ((_RawBits >> 10) & 0x1) == 1; // Bit 10

            [JsonProperty(Order = 12)]
            public bool SsbdRequired => ((_RawBits >> 11) & 0x1) == 1; // Bit 11

            [JsonProperty(Order = 13)]
            public bool BpbKernelToUser => ((_RawBits >> 12) & 0x1) == 1; // Bit 12

            [JsonProperty(Order = 14)]
            public bool BpbUserToKernel => ((_RawBits >> 13) & 0x1) == 1; // Bit 13

            [JsonProperty(Order = 15)]
            public bool ReturnSpeculate => ((_RawBits >> 14) & 0x1) == 1; // Bit 14

            [JsonProperty(Order = 16)]
            public bool BranchConfusionSafe => ((_RawBits >> 15) & 0x1) == 1; // Bit 15

            [JsonProperty(Order = 17)]
            public bool SsbsEnabledAlways => ((_RawBits >> 16) & 0x1) == 1; // Bit 16

            [JsonProperty(Order = 18)]
            public bool SsbsEnabledKernel => ((_RawBits >> 17) & 0x1) == 1; // Bit 17
        }

        #endregion
    }
}
