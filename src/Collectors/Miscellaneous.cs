using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    [JsonObject(MemberSerialization.OptIn)]
    internal class Miscellaneous : Collector {
        [JsonProperty] internal string KernelDmaProtection { get; private set; } = "Unsupported";

        public Miscellaneous() : base("Miscellaneous") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 72;

            RetrieveKernelDmaProtection();
        }

        #region Kernel DMA Protection

        [Flags]
        internal enum DmaGuardPolicyFlags : byte {
            DmaGuardPolicyEnabled = 0x1
        }


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

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(this);
        }

        internal override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(false);
            WriteConsoleEntry("Kernel DMA Protection", KernelDmaProtection);
        }
    }
}
