using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal sealed class DmaGuardPolicy : Collector {
        private DmaGuardPolicyInfo _DmaGuardPolicyInfo;

        public DmaGuardPolicy() : base("DMA Guard Policy") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            RetrieveInfo();
        }

        /// <summary>Retrieve DMA Guard Policy information</summary>
        /// <remarks>
        ///     There's no documented API to retrieve the enablement state of Kernel DMA Protection. The only documented
        ///     method to check its status is the System Information (msinfo32.exe) utility. Reverse-engineering how it obtains the
        ///     current state of Kernel DMA Protection shows it calls the native NtQuerySystemInformation API with an information
        ///     class dedicated to exposing the Kernel DMA Protection enablement state. The returned data is a 1-byte structure
        ///     with a single boolean field showing if the feature is disabled or enabled.
        /// </remarks>
        private void RetrieveInfo() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            var dmaGuardPolicyInfoLength = Marshal.SizeOf(typeof(DmaGuardPolicyInfo));
            WriteConsoleDebug($"Size of {nameof(DmaGuardPolicy)} structure: {dmaGuardPolicyInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemDmaGuardPolicyInformation,
                                                    out _DmaGuardPolicyInfo,
                                                    (uint)dmaGuardPolicyInfoLength,
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
            return JsonConvert.SerializeObject(_DmaGuardPolicyInfo);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(true);
            foreach (var field in _DmaGuardPolicyInfo.GetType().GetFields()) {
                WriteConsoleEntry(field.Name, (bool)field.GetValue(_DmaGuardPolicyInfo));
            }
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out DmaGuardPolicyInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

        private struct DmaGuardPolicyInfo {
            [JsonProperty(Order = 1)]
            [MarshalAs(UnmanagedType.U1)]
            public bool DmaGuardPolicyEnabled;
        }

        #endregion
    }
}
