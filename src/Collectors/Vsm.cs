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
            WriteOutputEntry("DmaProtectionsAvailable", dmaProtectionsAvailable, dmaProtectionsAvailable);

            var dmaProtectionsInUse = _vsmProtectionInfo.DmaProtectionsInUse;
            var dmaProtectionsInUseSecure = dmaProtectionsAvailable && dmaProtectionsInUse;
            WriteOutputEntry("DmaProtectionsInUse", dmaProtectionsInUse, dmaProtectionsInUseSecure);

            // TODO: Verify if added in Windows 10 version 1803
            var hardwareMbecAvailable = _vsmProtectionInfo.HardwareMbecAvailable;
            var hardwareMbecDescription = "Processor supports ";
            if (SystemInfo.IsProcessorIntel) {
                hardwareMbecDescription += "MBEC (Intel)";
            } else if (SystemInfo.IsProcessorAmd) {
                hardwareMbecDescription += "GMET (AMD)";
            } else if (SystemInfo.IsProcessorArm) {
                hardwareMbecDescription += "TTS2UXN (ARM)";
            } else {
                hardwareMbecDescription += "Mode Based Execution Control";
            }
            WriteOutputEntry("HardwareMbecAvailable", hardwareMbecAvailable, hardwareMbecAvailable, hardwareMbecDescription);

            // TODO: Verify if added in Windows 10 version 20H1
            var apicVirtualizationAvailable = _vsmProtectionInfo.ApicVirtualizationAvailable;
            var apicVirtualizationDescription = "Processor supports ";
            if (SystemInfo.IsProcessorIntel) {
                apicVirtualizationDescription += "APICv (Intel)";
            } else if (SystemInfo.IsProcessorAmd) {
                apicVirtualizationDescription += "AVEC (AMD)";
            } else if (SystemInfo.IsProcessorArm) {
                apicVirtualizationDescription += "GIC Virtualization Extensions (ARM)";
            } else {
                apicVirtualizationDescription += "virtualisation of interrupts";
            }
            WriteOutputEntry("ApicVirtualizationAvailable", apicVirtualizationAvailable, apicVirtualizationAvailable, apicVirtualizationDescription);
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
