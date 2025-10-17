using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal sealed class VsmProtection : Collector {
        private VsmProtectionInfo _vsmProtectionInfo;

        public VsmProtection() : base("VSM Protection") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            var vsmProtectionInfoLength = Marshal.SizeOf(typeof(VsmProtectionInfo));
            WriteConsoleDebug($"Size of {nameof(VsmProtectionInfo)} structure: {vsmProtectionInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemVsmProtectionInformation,
                                                    out _vsmProtectionInfo,
                                                    (uint)vsmProtectionInfoLength,
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
            return JsonConvert.SerializeObject(_vsmProtectionInfo);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(true);
            foreach (var field in _vsmProtectionInfo.GetType().GetFields()) {
                WriteConsoleEntry(field.Name, (bool)field.GetValue(_vsmProtectionInfo));
            }
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out VsmProtectionInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

#pragma warning disable CS0649 // Field is never assigned to

        private struct VsmProtectionInfo {
            [JsonProperty(Order = 1)]
            [MarshalAs(UnmanagedType.U1)]
            public bool DmaProtectionsAvailable;

            [JsonProperty(Order = 2)]
            [MarshalAs(UnmanagedType.U1)]
            public bool DmaProtectionsInUse;

            [JsonProperty(Order = 3)]
            [MarshalAs(UnmanagedType.U1)]
            public bool HardwareMbecAvailable;

            [JsonProperty(Order = 4)]
            [MarshalAs(UnmanagedType.U1)]
            public bool ApicVirtualizationAvailable;
        }

#pragma warning restore CS0649 // Field is never assigned to

        #endregion
    }
}
