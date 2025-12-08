using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace QueryHardwareSecurity.Collectors {
    /*
     * Isolated User Mode
     *
     * Introduced:  Windows 10 1507, Windows Server 2016
     * Platforms:   ARM64, x86-64
     */
    internal sealed class Ium : Collector {
        private const int IsolatedUserModeInfoClass = 0xA5;

        private IsolatedUserModeInfo _iumInfo;

        public Ium() : base("Isolated User Mode", TableStyle.Full) {
            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteVerbose($"Retrieving {Name} info ...");

            // For the TrustletRunning flag to be populated we need to use
            // NtQuerySystemInformationEx and provide an 8 byte input buffer
            // with the first bit set. In practice this is most likely a bit
            // field but it's completely undocumented. As of Windows 11 25H2
            // there are no other bits which affect the returned results.
            ulong iumInput = 1;

            var iumInfoLength = Marshal.SizeOf<IsolatedUserModeInfo>();
            WriteDebug($"Size of {nameof(IsolatedUserModeInfo)} structure: {iumInfoLength} bytes");

            var ntStatus = NtQuerySystemInformationEx(IsolatedUserModeInfoClass, ref iumInput, sizeof(ulong), out _iumInfo, (uint)iumInfoLength, IntPtr.Zero);
            if (ntStatus != 0) NtQsiFailure(ntStatus);
            WriteDebug($"Result: 0x{_iumInfo._RawBits:X8}");
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(_iumInfo);
        }

        internal override void WriteOutput(OutputFormat format, bool color) {
            SetOutputSettings(format, color);
            WriteOutputHeader();

            var firmwarePageProtection = _iumInfo.FirmwarePageProtection;
            WriteOutputEntry("FirmwarePageProtection", firmwarePageProtection, firmwarePageProtection);

            var secureKernelRunning = _iumInfo.SecureKernelRunning;
            WriteOutputEntry("SecureKernelRunning", secureKernelRunning, secureKernelRunning);

            // TODO: Determine where this is set
            var hardwareEnforcedVbs = _iumInfo.HardwareEnforcedVbs;
            WriteOutputEntry("HardwareEnforcedVbs", hardwareEnforcedVbs, hardwareEnforcedVbs);

            var encryptionKeyAvailable = _iumInfo.EncryptionKeyAvailable;
            WriteOutputEntry("EncryptionKeyAvailable", encryptionKeyAvailable, encryptionKeyAvailable);

            var encryptionKeyPersistent = _iumInfo.EncryptionKeyPersistent;
            WriteOutputEntry("EncryptionKeyPersistent", encryptionKeyPersistent, encryptionKeyPersistent);

            var noSecrets = _iumInfo.NoSecrets;
            WriteOutputEntry("NoSecrets", noSecrets, !noSecrets);

            // Undocumented (inc. in Process Hacker NT headers)
            // TODO: Determine Windows version requirement
            var secretsTpmBound = _iumInfo.SecretsTpmBound;
            WriteOutputEntry("SecretsTpmBound", secretsTpmBound, secretsTpmBound);

            var hvciEnabled = _iumInfo.HvciEnabled;
            WriteOutputEntry("HvciEnabled", hvciEnabled, hvciEnabled);

            var hvciDisableAllowed = _iumInfo.HvciDisableAllowed;
            WriteOutputEntry("HvciDisableAllowed", hvciDisableAllowed, !hvciDisableAllowed);

            // TODO: N/A if HvciEnabled is false?
            var hvciStrictMode = _iumInfo.HvciStrictMode;
            WriteOutputEntry("HvciStrictMode", hvciStrictMode, hvciStrictMode);

            // TODO: N/A if HvciEnabled is false?
            var debugEnabled = _iumInfo.DebugEnabled;
            WriteOutputEntry("DebugEnabled", debugEnabled, !debugEnabled);

            // HVPT is only supported on recent Intel processors
            var hardwareHvptAvailable = _iumInfo.HardwareHvptAvailable;
            var hardwareHvptAvailableSecure = hardwareHvptAvailable || !SystemInfo.IsProcessorIntel;
            WriteOutputEntry("HardwareHvptAvailable", hardwareHvptAvailable, hardwareHvptAvailableSecure);

            // HVPT is only supported on recent Intel processors
            var hardwareEnforcedHvpt = _iumInfo.HardwareEnforcedHvpt;
            var hardwareEnforcedHvptSecure = (hardwareHvptAvailable && hardwareEnforcedHvpt) || !SystemInfo.IsProcessorIntel;
            WriteOutputEntry("HardwareEnforcedHvpt", hardwareEnforcedHvpt, hardwareEnforcedHvptSecure);

            // TODO: Display Credential Guard and Key Guard status
            var trustletRunning = _iumInfo.TrustletRunning;
            WriteOutputEntry("TrustletRunning", trustletRunning, trustletRunning);
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformationEx(int systemInformationClass,
                                                             ref ulong inputBuffer,
                                                             uint inputBufferLength,
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
            internal uint _RawBits;

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
            public bool SecretsTpmBound => ((_RawBits >> 16) & 0x1) == 1;         // Bit 16

            private uint Spare0;  // Bits 32-63
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
