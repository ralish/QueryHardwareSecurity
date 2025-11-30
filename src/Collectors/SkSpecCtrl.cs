using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace QueryHardwareSecurity.Collectors {
    internal sealed class SkSpecCtrl : Collector {
        private const int SecureSpeculationControlInfoClass = 0xD5;

        private SecureSpeculationControlInfo _secSpecCtrlInfo;

        public SkSpecCtrl() : base("Secure Kernel Speculation Control", TableStyle.Full) {
            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteVerbose($"Retrieving {Name} info ...");

            var secureSpecCtrlInfoLength = Marshal.SizeOf<SecureSpeculationControlInfo>();
            WriteDebug($"Size of {nameof(SecureSpeculationControlInfo)} structure: {secureSpecCtrlInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SecureSpeculationControlInfoClass, out _secSpecCtrlInfo, (uint)secureSpecCtrlInfoLength, IntPtr.Zero);
            if (ntStatus != 0) NtQsiFailure(ntStatus);
            WriteDebug($"Result: 0x{_secSpecCtrlInfo._RawBits:X8}");
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(_secSpecCtrlInfo);
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

            var kvaShadowSupported = _secSpecCtrlInfo.KvaShadowSupported;
            var kvaShadowEnabled = _secSpecCtrlInfo.KvaShadowEnabled; // TODO: Fix secure state
            var kvaShadowUserGlobal = _secSpecCtrlInfo.KvaShadowUserGlobal;
            var kvaShadowPcid = _secSpecCtrlInfo.KvaShadowPcid;

            WriteOutputEntry("KvaShadowSupported", kvaShadowSupported, kvaShadowSupported);
            WriteOutputEntry("KvaShadowEnabled", kvaShadowEnabled, kvaShadowEnabled);
            WriteOutputEntry("KvaShadowUserGlobal", kvaShadowUserGlobal);
            WriteOutputEntry("KvaShadowPcid", kvaShadowPcid);

            /*
             * Microarchitectural Data Sampling (MDS)
             * Aka. CacheOut, Fallout, RIDL, ZombieLoad
             *
             * Affects:     Intel
             * CVE IDs:     CVE-2018-12126, CVE-2018-12127, CVE-2018-12130, CVE-2019-11091, CVE-2019-11135, CVE-2020-0548, CVE-2020-0549
             */

            var mbClearEnabled = _secSpecCtrlInfo.MbClearEnabled;

            WriteOutputEntry("MbClearEnabled", mbClearEnabled, mbClearEnabled);

            /*
             * L1 Terminal Fault
             * Aka. Foreshadow-NG: OS
             *
             * Affects:     Intel
             * CVE IDs:     CVE-2018-3620
             */

            var l1tfMitigated = _secSpecCtrlInfo.L1TFMitigated;

            WriteOutputEntry("L1TFMitigated", l1tfMitigated, l1tfMitigated);

            /*
             * Branch Target Injection (BTI)
             * Aka. Spectre: Variant 2
             *
             * Affects:     AMD, ARM, Intel
             * CVE IDs:     CVE-2017-5715
             */

            var bpbEnabled = _secSpecCtrlInfo.BpbEnabled;

            WriteOutputEntry("BpbEnabled", bpbEnabled, bpbEnabled);

            /*
             * Processor features
             */

            var ibrsPresent = _secSpecCtrlInfo.IbrsPresent;
            var enhancedIbrs = _secSpecCtrlInfo.EnhancedIbrs;
            var stibpPresent = _secSpecCtrlInfo.StibpPresent;

            WriteOutputEntry("IbrsPresent", ibrsPresent);
            WriteOutputEntry("EnhancedIbrs", enhancedIbrs);
            WriteOutputEntry("StibpPresent", stibpPresent);

            /*
             * Speculative Store Bypass (SSB)
             * Aka. Spectre-NG: Variant 4
             *
             * Affects:     AMD, ARM, Intel
             * CVE IDs:     CVE-2018-3639
             */

            var ssbdSupported = _secSpecCtrlInfo.SsbdSupported;
            var ssbdRequired = _secSpecCtrlInfo.SsbdRequired;

            WriteOutputEntry("SsbdSupported", ssbdSupported, ssbdSupported);
            WriteOutputEntry("SsbdRequired", ssbdRequired, !ssbdRequired);

            /*
             * Additional BTI settings
             */

            var bpbKernelToUser = _secSpecCtrlInfo.BpbKernelToUser;
            var bpbUserToKernel = _secSpecCtrlInfo.BpbUserToKernel;

            WriteOutputEntry("BpbKernelToUser", bpbKernelToUser);
            WriteOutputEntry("BpbUserToKernel", bpbUserToKernel);

            // TODO
            WriteOutputEntry("ReturnSpeculate", _secSpecCtrlInfo.ReturnSpeculate, _secSpecCtrlInfo.ReturnSpeculate);

            /*
             * Branch Type Confusion (BTC)
             * Aka. Phantom, Retbleed
             *
             * Affects:     AMD, ARM, Intel
             * CVE IDs:     CVE-2022-23825, CVE-2022-29900, CVE-2022-29901
             */

            var branchConfusionSafe = _secSpecCtrlInfo.BranchConfusionSafe;

            WriteOutputEntry("BranchConfusionSafe", branchConfusionSafe, branchConfusionSafe);

            // TODO
            WriteOutputEntry("SsbsEnabledAlways", _secSpecCtrlInfo.SsbsEnabledAlways, _secSpecCtrlInfo.SsbsEnabledAlways);
            WriteOutputEntry("SsbsEnabledKernel", _secSpecCtrlInfo.SsbsEnabledKernel, _secSpecCtrlInfo.SsbsEnabledKernel);
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(int systemInformationClass,
                                                           out SecureSpeculationControlInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0251 // Member can be made readonly

        // ReSharper disable InconsistentNaming

        private struct SecureSpeculationControlInfo {
            internal uint _RawBits;

            public bool KvaShadowSupported => (_RawBits & 0x1) == 1;          // Bit 0
            public bool KvaShadowEnabled => ((_RawBits >> 1) & 0x1) == 1;     // Bit 1
            public bool KvaShadowUserGlobal => ((_RawBits >> 2) & 0x1) == 1;  // Bit 2
            public bool KvaShadowPcid => ((_RawBits >> 3) & 0x1) == 1;        // Bit 3
            public bool MbClearEnabled => ((_RawBits >> 4) & 0x1) == 1;       // Bit 4
            public bool L1TFMitigated => ((_RawBits >> 5) & 0x1) == 1;        // Bit 5
            public bool BpbEnabled => ((_RawBits >> 6) & 0x1) == 1;           // Bit 6
            public bool IbrsPresent => ((_RawBits >> 7) & 0x1) == 1;          // Bit 7
            public bool EnhancedIbrs => ((_RawBits >> 8) & 0x1) == 1;         // Bit 8
            public bool StibpPresent => ((_RawBits >> 9) & 0x1) == 1;         // Bit 9
            public bool SsbdSupported => ((_RawBits >> 10) & 0x1) == 1;       // Bit 10
            public bool SsbdRequired => ((_RawBits >> 11) & 0x1) == 1;        // Bit 11
            public bool BpbKernelToUser => ((_RawBits >> 12) & 0x1) == 1;     // Bit 12
            public bool BpbUserToKernel => ((_RawBits >> 13) & 0x1) == 1;     // Bit 13
            public bool ReturnSpeculate => ((_RawBits >> 14) & 0x1) == 1;     // Bit 14
            public bool BranchConfusionSafe => ((_RawBits >> 15) & 0x1) == 1; // Bit 15
            public bool SsbsEnabledAlways => ((_RawBits >> 16) & 0x1) == 1;   // Bit 16
            public bool SsbsEnabledKernel => ((_RawBits >> 17) & 0x1) == 1;   // Bit 17
        }

        // ReSharper restore InconsistentNaming

#pragma warning restore IDE0251 // Member can be made readonly
#pragma warning restore CS0649  // Field is never assigned to

        #endregion
    }
}
