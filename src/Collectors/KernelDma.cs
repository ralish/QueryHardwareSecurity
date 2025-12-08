using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace QueryHardwareSecurity.Collectors {
    /*
     * Kernel DMA Protection
     *
     * Introduced:  Windows 10 1903 (unverified), Windows Server 2019
     * Platforms:   x86-64
     * Notes:       Information class is present on ARM64
     */
    internal sealed class KernelDma : Collector {
        private const int DmaGuardPolicyInfoClass = 0xCA;

        private DmaGuardPolicyInfo _dmaGuardPolicyInfo;

        public KernelDma() : base("Kernel DMA Protection", TableStyle.Full) {
            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteVerbose($"Retrieving {Name} info ...");

            var dmaGuardPolicyInfoLength = Marshal.SizeOf<DmaGuardPolicyInfo>();
            WriteDebug($"Size of {nameof(DmaGuardPolicyInfo)} structure: {dmaGuardPolicyInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(DmaGuardPolicyInfoClass, out _dmaGuardPolicyInfo, (uint)dmaGuardPolicyInfoLength, IntPtr.Zero);
            if (ntStatus != 0) NtQsiFailure(ntStatus);
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(_dmaGuardPolicyInfo);
        }

        internal override void WriteOutput(OutputFormat format, bool color) {
            SetOutputSettings(format, color);
            WriteOutputHeader();

            var dmaGuardPolicyEnabled = _dmaGuardPolicyInfo.DmaGuardPolicyEnabled;
            WriteOutputEntry("DmaGuardPolicyEnabled", dmaGuardPolicyEnabled, dmaGuardPolicyEnabled);
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(int systemInformationClass,
                                                           out DmaGuardPolicyInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

#pragma warning disable CS0649 // Field is never assigned to

        private struct DmaGuardPolicyInfo {
            [MarshalAs(UnmanagedType.U1)]
            public bool DmaGuardPolicyEnabled;
        }

#pragma warning restore CS0649 // Field is never assigned to

        #endregion
    }
}
