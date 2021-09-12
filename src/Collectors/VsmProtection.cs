using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    [JsonObject(MemberSerialization.OptIn)]
    internal class VsmProtection : Collector {
        [JsonProperty] public bool DmaProtectionsAvailable => SystemInfo.DmaProtectionsAvailable;
        [JsonProperty] public bool DmaProtectionsInUse => SystemInfo.DmaProtectionsInUse;
        [JsonProperty] public bool HardwareMbecAvailable => SystemInfo.HardwareMbecAvailable;
        [JsonProperty] public bool ApicVirtualizationAvailable => SystemInfo.ApicVirtualizationAvailable;

        public VsmProtectionInfo SystemInfo { get; private set; }

        public VsmProtection() : base("VSM Protection") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 72;

            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            var sysInfoLength = Marshal.SizeOf(typeof(VsmProtectionInfo));
            WriteConsoleDebug($"Size of {nameof(VsmProtectionInfo)} structure: {sysInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemVsmProtectionInformation,
                                                    out var sysInfo,
                                                    (uint)sysInfoLength,
                                                    IntPtr.Zero);

            switch (ntStatus) {
                case 0:
                    SystemInfo = sysInfo;
                    return;
                // STATUS_INVALID_INFO_CLASS || STATUS_NOT_IMPLEMENTED
                case -1073741821:
                case -1073741822:
                    throw new NotImplementedException($"System support for querying {Name} information not present.");
            }

            WriteConsoleVerbose($"Error requesting {Name} information: {ntStatus}");
            var symbolicNtStatus = GetSymbolicNtStatus(ntStatus);
            throw new Win32Exception(symbolicNtStatus);
        }

        public override string ConvertToJson() {
            return JsonConvert.SerializeObject(this);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(false);
            foreach (var field in SystemInfo.GetType().GetFields()) {
                WriteConsoleEntry(field.Name, (bool)field.GetValue(SystemInfo));
            }
        }

        #region P/Invoke

#pragma warning disable CS0649 // Field is never assigned to
        // @formatter:off

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out VsmProtectionInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

        public struct VsmProtectionInfo {
            [MarshalAs(UnmanagedType.U1)]
            public bool DmaProtectionsAvailable;

            [MarshalAs(UnmanagedType.U1)]
            public bool DmaProtectionsInUse;

            [MarshalAs(UnmanagedType.U1)]
            public bool HardwareMbecAvailable;

            [MarshalAs(UnmanagedType.U1)]
            public bool ApicVirtualizationAvailable;
        }

        // @formatter:on
#pragma warning restore CS0649 // Field is never assigned to

        #endregion
    }
}
