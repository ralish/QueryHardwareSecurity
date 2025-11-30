using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace QueryHardwareSecurity.Collectors {
    internal sealed class Vsm : Collector {
        private const int VsmProtectionInfoClass = 0xA9;

        private VsmProtectionInfo _vsmProtectionInfo;

        public Vsm() : base("Virtual Secure Mode", TableStyle.Full) {
            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteVerbose($"Retrieving {Name} info ...");

            var vsmProtectionInfoLength = Marshal.SizeOf<VsmProtectionInfo>();
            WriteDebug($"Size of {nameof(VsmProtectionInfo)} structure: {vsmProtectionInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(VsmProtectionInfoClass, out _vsmProtectionInfo, (uint)vsmProtectionInfoLength, IntPtr.Zero);
            if (ntStatus != 0) NtQsiFailure(ntStatus);
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(_vsmProtectionInfo);
        }

        internal override void WriteOutput(OutputFormat format, bool color) {
            SetOutputSettings(format, color);
            WriteOutputHeader();

            var dmaProtectionsAvailable = _vsmProtectionInfo.DmaProtectionsAvailable;
            var dmaProtectionsInUse = _vsmProtectionInfo.DmaProtectionsInUse;
            var hardwareMbecAvailable = _vsmProtectionInfo.HardwareMbecAvailable;
            var apicVirtualizationAvailable = _vsmProtectionInfo.ApicVirtualizationAvailable;

            var dmaProtectionsInUseSecure = dmaProtectionsAvailable && dmaProtectionsInUse;

            WriteOutputEntry("DmaProtectionsAvailable", dmaProtectionsAvailable, dmaProtectionsAvailable);
            WriteOutputEntry("DmaProtectionsInUse", dmaProtectionsInUse, dmaProtectionsInUseSecure);
            WriteOutputEntry("HardwareMbecAvailable", hardwareMbecAvailable, hardwareMbecAvailable);
            WriteOutputEntry("ApicVirtualizationAvailable", apicVirtualizationAvailable, apicVirtualizationAvailable);
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(int systemInformationClass,
                                                           out VsmProtectionInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

#pragma warning disable CS0649 // Field is never assigned to

        private struct VsmProtectionInfo {
            [MarshalAs(UnmanagedType.U1)]
            public bool DmaProtectionsAvailable;

            [MarshalAs(UnmanagedType.U1)]
            public bool DmaProtectionsInUse;

            [MarshalAs(UnmanagedType.U1)]
            public bool HardwareMbecAvailable;

            [MarshalAs(UnmanagedType.U1)]
            public bool ApicVirtualizationAvailable;
        }

#pragma warning restore CS0649 // Field is never assigned to

        #endregion
    }
}
