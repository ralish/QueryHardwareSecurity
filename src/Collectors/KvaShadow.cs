using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace QueryHardwareSecurity.Collectors {
    internal sealed class KvaShadow : Collector {
        private const int KernelVaShadowInfoClass = 0xC4;

        private KernelVaShadowInfo _kernelVaShadowInfo;

        public KvaShadow() : base("Kernel VA Shadow", TableStyle.Full) {
            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteVerbose($"Retrieving {Name} info ...");

            var kernelVaShadowInfoLength = Marshal.SizeOf<KernelVaShadowInfo>();
            WriteDebug($"Size of {nameof(KernelVaShadowInfo)} structure: {kernelVaShadowInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(KernelVaShadowInfoClass, out _kernelVaShadowInfo, (uint)kernelVaShadowInfoLength, IntPtr.Zero);
            if (ntStatus != 0) NtQsiFailure(ntStatus);
            WriteDebug($"Result: 0x{_kernelVaShadowInfo._RawBits:X8}");
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(_kernelVaShadowInfo);
        }

        internal override void WriteOutput(OutputFormat format, bool color) {
            SetOutputSettings(format, color);
            WriteOutputHeader();

            /*
             * Rogue Data Cache Load (RDCL)
             * Aka. Spectre: Variant 3, Meltdown
             *
             * Affects:     ARM, Intel
             * CVE IDs:     CVE-2017-5754
             */

            var kvaShadowEnabled = _kernelVaShadowInfo.KvaShadowEnabled;
            var kvaShadowUserGlobal = _kernelVaShadowInfo.KvaShadowUserGlobal;
            var kvaShadowPcid = _kernelVaShadowInfo.KvaShadowPcid;
            var kvaShadowInvpcid = _kernelVaShadowInfo.KvaShadowInvpcid;
            var kvaShadowRequiredAvailable = _kernelVaShadowInfo.KvaShadowRequiredAvailable;
            var kvaShadowRequired = kvaShadowRequiredAvailable ? (bool?)_kernelVaShadowInfo.KvaShadowRequired : null;

            /*
             * The SpeculationControl PowerShell module sets KvaShadowRequired
             * based on its own logic if KvaShadowRequiredAvailable is false.
             * That additional logic isn't implemented as it's unclear if it's
             * really necessary, but for reference the logic used is:
             *
             * - For AMD CPUs, sets KvaShadowRequired to false.
             * - For Intel CPUs, checks the CPU model against a set of values
             *   and sets it to false if any match (the default is true).
             * - For other CPUs, throws an exception stating that the processor
             *   manufacturer is unsupported.
             */
            var kvaShadowRequiredSecure = kvaShadowRequired != null && !kvaShadowRequired.Value;
            var kvaShadowEnabledSecure = kvaShadowEnabled || (kvaShadowRequired != null && !kvaShadowRequired.Value);

            WriteOutputEntry("KvaShadowEnabled", kvaShadowEnabled, kvaShadowEnabledSecure);
            WriteOutputEntry("KvaShadowUserGlobal", kvaShadowUserGlobal);
            WriteOutputEntry("KvaShadowPcid", kvaShadowPcid);
            WriteOutputEntry("KvaShadowInvpcid", kvaShadowInvpcid);
            WriteOutputEntry("KvaShadowRequired", kvaShadowRequired, kvaShadowRequiredSecure);
            WriteOutputEntry("KvaShadowRequiredAvailable", kvaShadowRequiredAvailable, kvaShadowRequiredAvailable);

            /*
             * L1 Terminal Fault
             * Aka. Foreshadow-NG: OS
             *
             * Affects:     Intel
             * CVE IDs:     CVE-2018-3620
             */

            var l1tfMitigationPresent = _kernelVaShadowInfo.L1TerminalFaultMitigationPresent;
            var invalidPteBit = l1tfMitigationPresent ? (byte?)_kernelVaShadowInfo.InvalidPteBit : null;
            var l1DataCacheFlushSupported = l1tfMitigationPresent ? (bool?)_kernelVaShadowInfo.L1DataCacheFlushSupported : null;


            /*
             * The SpeculationControl PowerShell module determines if the L1TF
             * mitigation is enabled by checking for any of these conditions:
             *
             * - L1TerminalFaultMitigationPresent is true.
             * - L1DataCacheFlushSupported is true.
             * - KvaShadowEnabled is true and InvalidPteBit is non-zero.
             *
             * This doesn't seem to make much sense as surely the latter two
             * conditions can't ever be true if the first one isn't met?
             */
            var l1tfMitigationEnabled = l1tfMitigationPresent && ((kvaShadowEnabled && invalidPteBit != 0) || l1DataCacheFlushSupported.Value);

            /*
             * The SpeculationControl PowerShell module implements custom logic
             * to determine if the L1TF mitigation is required. The logic seems
             * somewhat redundant and it's not clear if it's necessary so isn't
             * implemented, but for reference the logic used is:
             *
             * - For all non-Intel CPUs, mitigation is not required.
             * - For Intel CPUs:
             *   - Mitigation is not required if RdclHardwareProtectedReported
             *     and RdclHardwareProtected are both true.
             *   - Mitigation is not required if HvL1tfStatusAvailable and
             *     HvL1tfProcessorNotAffected are both true.
             *   - Otherwise, checks the CPU model and stepping against a list
             *     of values, and sets the mitigation as required if any match.
             */
            // TODO: Secure states with above logic & override ARM as secure
            WriteOutputEntry("InvalidPteBit", invalidPteBit);
            WriteOutputEntry("L1DataCacheFlushSupported", l1DataCacheFlushSupported);
            WriteOutputEntry("L1TerminalFaultMitigationPresent", l1tfMitigationPresent, l1tfMitigationPresent);
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(int systemInformationClass,
                                                           out KernelVaShadowInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0251 // Member can be made readonly

        // ReSharper disable InconsistentNaming

        private struct KernelVaShadowInfo {
            internal uint _RawBits;

            public bool KvaShadowEnabled => (_RawBits & 0x1) == 1;                         // Bit 0
            public bool KvaShadowUserGlobal => ((_RawBits >> 1) & 0x1) == 1;               // Bit 1
            public bool KvaShadowPcid => ((_RawBits >> 2) & 0x1) == 1;                     // Bit 2
            public bool KvaShadowInvpcid => ((_RawBits >> 3) & 0x1) == 1;                  // Bit 3
            public bool KvaShadowRequired => ((_RawBits >> 4) & 0x1) == 1;                 // Bit 4
            public bool KvaShadowRequiredAvailable => ((_RawBits >> 5) & 0x1) == 1;        // Bit 5
            public byte InvalidPteBit => (byte)((_RawBits >> 6) & 0x3F);                   // Bits 6-11
            public bool L1DataCacheFlushSupported => ((_RawBits >> 12) & 0x1) == 1;        // Bit 12
            public bool L1TerminalFaultMitigationPresent => ((_RawBits >> 13) & 0x1) == 1; // Bit 13
        }

        // ReSharper restore InconsistentNaming

#pragma warning restore IDE0251 // Member can be made readonly
#pragma warning restore CS0649  // Field is never assigned to

        #endregion
    }
}
