using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    [JsonObject(MemberSerialization.OptIn)]
    internal class Miscellaneous : Collector {
        // ReSharper disable once MemberCanBePrivate.Global
        [JsonProperty] public string KernelDmaProtection { get; private set; } = "Unsupported";

        public Miscellaneous() : base("Miscellaneous") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 72;

            RetrieveKernelDmaProtection();
        }

        #region Kernel DMA Protection

        [Flags]
        // ReSharper disable once MemberCanBePrivate.Global
        public enum DmaGuardPolicyFlags : byte {
            DmaGuardPolicyEnabled = 0x1
        }


        /*
         * There's no documented API to retrieve the enablement state of Kernel DMA Protection and
         * the only documented method to check its status is the System Information (msinfo32.exe)
         * utility. Reverse-engineering how it obtains this information shows it calls the native
         * NtQuerySystemInformation API with an information class dedicated to exposing the Kernel
         * DMA Protection enablement state. The returned data is literally a single bit reflecting
         * the status of the security feature.
         */
        private void RetrieveKernelDmaProtection() {
            WriteConsoleVerbose("Retrieving DmaGuardPolicy info ...");

            const int sysInfoLength = sizeof(DmaGuardPolicyFlags);
            var sysInfo = Marshal.AllocHGlobal(sysInfoLength);
            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemDmaGuardPolicyInformation,
                                                    sysInfo,
                                                    sysInfoLength,
                                                    IntPtr.Zero);

            if (ntStatus == 0) {
                var flags = (DmaGuardPolicyFlags)Marshal.ReadByte(sysInfo);
                KernelDmaProtection = flags.HasFlag(DmaGuardPolicyFlags.DmaGuardPolicyEnabled) ? "Enabled" : "Disabled";
            }

            Marshal.FreeHGlobal(sysInfo);

            if (ntStatus != 0) {
                // STATUS_INVALID_INFO_CLASS || STATUS_NOT_IMPLEMENTED
                if (ntStatus == -1073741821 || ntStatus == -1073741822) {
                    return;
                }

                WriteConsoleVerbose($"Error requesting DmaGuardPolicy information: {ntStatus}");
                var symbolicNtStatus = GetSymbolicNtStatus(ntStatus);
                throw new Win32Exception(symbolicNtStatus);
            }
        }

        #endregion

        public override string ConvertToJson() {
            return JsonConvert.SerializeObject(this);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(false);
            WriteConsoleEntry("Kernel DMA Protection", KernelDmaProtection);
        }
    }
}
