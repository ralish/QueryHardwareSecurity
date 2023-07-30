using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    [JsonObject(MemberSerialization.OptIn)]
    internal class DmaGuardPolicy : Collector {
        [JsonProperty]
        public bool DmaGuardPolicyEnabled => SystemInfo.DmaGuardPolicyEnabled;

        public DmaGuardPolicyInfo SystemInfo { get; private set; }

        public DmaGuardPolicy() : base("DMA Guard Policy") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 72;

            RetrieveInfo();
        }

        /// <summary>
        ///     Retrieve DMA Guard Policy information
        /// </summary>
        /// <remarks>
        ///     There's no documented API to retrieve the enablement state of Kernel DMA Protection. The only documented method to
        ///     check its status is the System Information (msinfo32.exe) utility. Reverse-engineering how it obtains the current
        ///     state of Kernel DMA Protection shows it calls the native NtQuerySystemInformation API with an information class
        ///     dedicated to exposing the Kernel DMA Protection enablement state. The returned data is a 1-byte structure with a
        ///     single boolean field showing if the feature is disabled or enabled.
        /// </remarks>
        private void RetrieveInfo() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            var sysInfoLength = Marshal.SizeOf(typeof(DmaGuardPolicyInfo));
            WriteConsoleDebug($"Size of {nameof(DmaGuardPolicy)} structure: {sysInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemDmaGuardPolicyInformation,
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
            foreach (var field in SystemInfo.GetType().GetFields()) WriteConsoleEntry(field.Name, (bool)field.GetValue(SystemInfo));
        }

        #region P/Invoke

#pragma warning disable CS0649 // Field is never assigned to
        // @formatter:int_align_fields true

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out DmaGuardPolicyInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

        public struct DmaGuardPolicyInfo {
            [MarshalAs(UnmanagedType.U1)]
            public bool DmaGuardPolicyEnabled;
        }

        // @formatter:int_align_fields false
#pragma warning restore CS0649 // Field is never assigned to

        #endregion
    }
}
