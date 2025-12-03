using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace QueryHardwareSecurity.Collectors {
    internal sealed class ShadowStacks : Collector {
        private const int ShadowStackInfoClass = 0xDD;

        private ShadowStackInfo _shadowStackInfo;

        public ShadowStacks() : base("Shadow Stacks", TableStyle.Full) {
            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteVerbose($"Retrieving {Name} info ...");

            var shadowStackInfoLength = Marshal.SizeOf<ShadowStackInfo>();
            WriteDebug($"Size of {nameof(ShadowStackInfo)} structure: {shadowStackInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(ShadowStackInfoClass, out _shadowStackInfo, (uint)shadowStackInfoLength, IntPtr.Zero);
            if (ntStatus != 0) NtQsiFailure(ntStatus);
            WriteDebug($"Result: 0x{_shadowStackInfo._RawBits:X8}");
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(_shadowStackInfo);
        }

        internal override void WriteOutput(OutputFormat format, bool color) {
            SetOutputSettings(format, color);
            WriteOutputHeader();

            var cetCapable = _shadowStackInfo.CetCapable;
            var userCetAllowed = _shadowStackInfo.UserCetAllowed;
            var kernelCetEnabled = _shadowStackInfo.KernelCetEnabled;
            var kernelCetAuditModeEnabled = _shadowStackInfo.KernelCetAuditModeEnabled;

            var userCetAllowedSecure = cetCapable && userCetAllowed;
            var kernelCetEnabledSecure = cetCapable && kernelCetEnabled;

            WriteOutputEntry("CetCapable", cetCapable, cetCapable);
            WriteOutputEntry("UserCetAllowed", userCetAllowed, userCetAllowedSecure);
            WriteOutputEntry("KernelCetEnabled", kernelCetEnabled, kernelCetEnabledSecure);
            WriteOutputEntry("KernelCetAuditModeEnabled", kernelCetAuditModeEnabled);
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(int systemInformationClass,
                                                           out ShadowStackInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Field can be made readonly
#pragma warning disable IDE0251 // Member can be made readonly

        // ReSharper disable InconsistentNaming

        private struct ShadowStackInfo {
            internal uint _RawBits;

            public bool CetCapable => (_RawBits & 0x1) == 1;                       // Bit 0
            public bool UserCetAllowed => ((_RawBits >> 1) & 0x1) == 1;            // Bit 1
            private byte ReservedForUserCet => (byte)((_RawBits >> 2) & 0x3F);     // Bits 2-7
            public bool KernelCetEnabled => ((_RawBits >> 7) & 0x1) == 1;          // Bit 8
            public bool KernelCetAuditModeEnabled => ((_RawBits >> 8) & 0x1) == 1; // Bit 9
            private byte ReservedForKernelCet => (byte)((_RawBits >> 9) & 0x3F);   // Bits 10-15
        }

        // ReSharper restore InconsistentNaming

#pragma warning restore IDE0251 // Member can be made readonly
#pragma warning restore IDE0044 // Field can be made readonly
#pragma warning restore CS0649  // Field is never assigned to

        #endregion
    }
}
