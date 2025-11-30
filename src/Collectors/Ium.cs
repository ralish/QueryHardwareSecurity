using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace QueryHardwareSecurity.Collectors {
    internal sealed class Ium : Collector {
        private const int IsolatedUserModeInfoClass = 0xA5;

        private IsolatedUserModeInfo _iumInfo;

        public Ium() : base("Isolated User Mode", TableStyle.Full) {
            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteVerbose($"Retrieving {Name} info ...");

            var iumInfoLength = Marshal.SizeOf<IsolatedUserModeInfo>();
            WriteDebug($"Size of {nameof(IsolatedUserModeInfo)} structure: {iumInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(IsolatedUserModeInfoClass, out _iumInfo, (uint)iumInfoLength, IntPtr.Zero);
            if (ntStatus != 0) NtQsiFailure(ntStatus);
            WriteDebug($"Result: 0x{_iumInfo._RawBits:X4}");
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(_iumInfo);
        }

        internal override void WriteOutput(OutputFormat format, bool color) {
            SetOutputSettings(format, color);
            WriteOutputHeader();

            var secureKernelRunning = _iumInfo.SecureKernelRunning;
            var hvciEnabled = _iumInfo.HvciEnabled;
            var hvciStrictMode = _iumInfo.HvciStrictMode;
            var debugEnabled = _iumInfo.DebugEnabled;
            var firmwarePageProtection = _iumInfo.FirmwarePageProtection;
            var encryptionKeyAvailable = _iumInfo.EncryptionKeyAvailable;
            var trustletRunning = _iumInfo.TrustletRunning;
            var hvciDisableAllowed = _iumInfo.HvciDisableAllowed;
            var hardwareEnforcedVbs = _iumInfo.HardwareEnforcedVbs;
            var noSecrets = _iumInfo.NoSecrets;
            var encryptionKeyPersistent = _iumInfo.EncryptionKeyPersistent;
            var hardwareEnforcedHvpt = _iumInfo.HardwareEnforcedHvpt;
            var hardwareHvptAvailable = _iumInfo.HardwareHvptAvailable;

            WriteOutputEntry("SecureKernelRunning", secureKernelRunning, secureKernelRunning);
            WriteOutputEntry("HvciEnabled", hvciEnabled, hvciEnabled);
            WriteOutputEntry("HvciStrictMode", hvciStrictMode, hvciStrictMode);
            WriteOutputEntry("DebugEnabled", debugEnabled, !debugEnabled);
            WriteOutputEntry("FirmwarePageProtection", firmwarePageProtection, firmwarePageProtection);
            WriteOutputEntry("EncryptionKeyAvailable", encryptionKeyAvailable, encryptionKeyAvailable);
            WriteOutputEntry("TrustletRunning", trustletRunning);
            WriteOutputEntry("HvciDisableAllowed", hvciDisableAllowed, !hvciDisableAllowed);
            WriteOutputEntry("HardwareEnforcedVbs", hardwareEnforcedVbs, hardwareEnforcedVbs);
            WriteOutputEntry("NoSecrets", noSecrets);
            WriteOutputEntry("EncryptionKeyPersistent", encryptionKeyPersistent, encryptionKeyPersistent);
            WriteOutputEntry("HardwareEnforcedHvpt", hardwareEnforcedHvpt, hardwareEnforcedHvpt);
            WriteOutputEntry("HardwareHvptAvailable", hardwareHvptAvailable, hardwareHvptAvailable);
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(int systemInformationClass,
                                                           out IsolatedUserModeInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

#pragma warning disable CA1823  // Avoid unused private fields
#pragma warning disable CS0169  // Field is never used
#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Field can be made readonly
#pragma warning disable IDE0251 // Member can be made readonly

        // ReSharper disable InconsistentNaming

        private struct IsolatedUserModeInfo {
            internal ushort _RawBits;

            public bool SecureKernelRunning => (_RawBits & 0x1) == 1;             // Bit 0
            public bool HvciEnabled => ((_RawBits >> 1) & 0x1) == 1;              // Bit 1
            public bool HvciStrictMode => ((_RawBits >> 2) & 0x1) == 1;           // Bit 2
            public bool DebugEnabled => ((_RawBits >> 3) & 0x1) == 1;             // Bit 3
            public bool FirmwarePageProtection => ((_RawBits >> 4) & 0x1) == 1;   // Bit 4
            public bool EncryptionKeyAvailable => ((_RawBits >> 5) & 0x1) == 1;   // Bit 5
            private bool SpareFlags => ((_RawBits >> 6) & 0x3) == 1;              // Bits 6-7
            public bool TrustletRunning => ((_RawBits >> 8) & 0x1) == 1;          // Bit 8
            public bool HvciDisableAllowed => ((_RawBits >> 9) & 0x1) == 1;       // Bit 9
            public bool HardwareEnforcedVbs => ((_RawBits >> 10) & 0x1) == 1;     // Bit 10
            public bool NoSecrets => ((_RawBits >> 11) & 0x1) == 1;               // Bit 11
            public bool EncryptionKeyPersistent => ((_RawBits >> 12) & 0x1) == 1; // Bit 12
            public bool HardwareEnforcedHvpt => ((_RawBits >> 13) & 0x1) == 1;    // Bit 13
            public bool HardwareHvptAvailable => ((_RawBits >> 14) & 0x1) == 1;   // Bit 14
            private bool SpareFlags2 => ((_RawBits >> 15) & 0x1) == 1;            // Bit 15

            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U1, SizeConst = 6)]
            private bool[] Spare0; // Bits 16-63

            private ulong Spare1; // Bits 64-127
        }

        // ReSharper restore InconsistentNaming

#pragma warning restore IDE0251 // Member can be made readonly
#pragma warning restore IDE0044 // Field can be made readonly
#pragma warning restore CS0649  // Field is never assigned to
#pragma warning restore CS0169  // Field is never used
#pragma warning restore CA1823  // Avoid unused private fields

        #endregion
    }
}
