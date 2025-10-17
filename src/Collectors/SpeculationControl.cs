using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal sealed class SpeculationControl : Collector {
        private SpeculationControlInfo _specCtrlInfo;

        public SpeculationControl() : base("Speculation Control") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            RetrieveInfo();
        }

        /// <summary>Retrieve Speculation Control information</summary>
        /// <remarks>
        ///     This information is only exposed via the NtQuerySystemInformation function in the native API. Microsoft has
        ///     partially documented this information class, however many of the newer flags in the 32-bit bit field remain
        ///     informally or completely undocumented. The meaning of undocumented flags was determined by reverse-engineering of
        ///     the NT kernel. Currently 31-bits in the 32-bit bit field are used, which may necessitate the addition of another
        ///     information class if additional speculative execution vulnerability mitigations are introduced.
        /// </remarks>
        private void RetrieveInfo() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            var specCtrlInfoLength = Marshal.SizeOf(typeof(SpeculationControlInfo));

            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemSpeculationControlInformation,
                                                    out var specCtrlInfo,
                                                    (uint)specCtrlInfoLength,
                                                    out var returnLength);

            WriteConsoleDebug($"Size of {nameof(SpeculationControlInfo)} structure: {returnLength} bytes");

            switch (ntStatus) {
                case 0: break;
                case -1073741821: // STATUS_INVALID_INFO_CLASS
                case -1073741822: // STATUS_NOT_IMPLEMENTED
                    throw new NotImplementedException($"System support for querying {Name} information not present.");
                default:
                    WriteConsoleVerbose($"Error requesting {Name} information: {ntStatus}");
                    var symbolicNtStatus = GetSymbolicNtStatus(ntStatus);
                    throw new Win32Exception(symbolicNtStatus);
            }

            var specCtrlFlags = new SpeculationControlFlags { _RawBits = (uint)specCtrlInfo };
            var specCtrlFlags2 = returnLength == 8 ? new SpeculationControlFlags2 { _RawBits = (uint)(specCtrlInfo >> 31) } : new SpeculationControlFlags2();
            _specCtrlInfo = new SpeculationControlInfo { Flags = specCtrlFlags, Flags2 = specCtrlFlags2 };
        }

        public override string ConvertToJson() {
            return JsonConvert.SerializeObject(_specCtrlInfo);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(true);
            foreach (var property in _specCtrlInfo.Flags.GetType().GetProperties()) {
                if (property.PropertyType == typeof(bool)) {
                    WriteConsoleEntry(property.Name, (bool)property.GetValue(_specCtrlInfo.Flags));
                } else if (property.PropertyType == typeof(byte)) {
                    WriteConsoleEntry(property.Name, ((byte)property.GetValue(_specCtrlInfo.Flags)).ToString());
                }
            }

            foreach (var property in _specCtrlInfo.Flags2.GetType().GetProperties()) {
                if (property.PropertyType == typeof(bool)) {
                    WriteConsoleEntry(property.Name, (bool)property.GetValue(_specCtrlInfo.Flags2));
                } else if (property.PropertyType == typeof(byte)) {
                    WriteConsoleEntry(property.Name, ((byte)property.GetValue(_specCtrlInfo.Flags2)).ToString());
                }
            }
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out ulong systemInformation,
                                                           uint systemInformationLength,
                                                           out uint returnLength);

        private struct SpeculationControlInfo {
            [JsonProperty(Order = 1)]
            internal SpeculationControlFlags Flags;

            [JsonProperty(Order = 2)]
            internal SpeculationControlFlags2 Flags2;
        }

        private struct SpeculationControlFlags {
            internal uint _RawBits;

            public bool BpbEnabled => (_RawBits & 0x1) == 1;                                    // Bit 0
            public bool BpbDisabledSystemPolicy => (_RawBits & 0x2) == 1;                       // Bit 1
            public bool BpbDisabledNoHardwareSupport => (_RawBits & 0x4) == 1;                  // Bit 2
            public bool SpecCtrlEnumerated => (_RawBits & 0x8) == 1;                            // Bit 3
            public bool SpecCmdEnumerated => (_RawBits & 0x10) == 1;                            // Bit 4
            public bool IbrsPresent => (_RawBits & 0x20) == 1;                                  // Bit 5
            public bool StibpPresent => (_RawBits & 0x40) == 1;                                 // Bit 6
            public bool SmepPresent => (_RawBits & 0x80) == 1;                                  // Bit 7
            public bool SpeculativeStoreBypassDisableAvailable => (_RawBits & 0x100) == 1;      // Bit 8
            public bool SpeculativeStoreBypassDisableSupported => (_RawBits & 0x200) == 1;      // Bit 9
            public bool SpeculativeStoreBypassDisabledSystemWide => (_RawBits & 0x400) == 1;    // Bit 10
            public bool SpeculativeStoreBypassDisabledKernel => (_RawBits & 0x800) == 1;        // Bit 11
            public bool SpeculativeStoreBypassDisableRequired => (_RawBits & 0x1000) == 1;      // Bit 12
            public bool BpbDisabledKernelToUser => (_RawBits & 0x2000) == 1;                    // Bit 13
            public bool SpecCtrlRetpolineEnabled => (_RawBits & 0x4000) == 1;                   // Bit 14
            public bool SpecCtrlImportOptimizationEnabled => (_RawBits & 0x8000) == 1;          // Bit 15
            public bool EnhancedIbrs => (_RawBits & 0x10000) == 1;                              // Bit 16
            public bool HvL1tfStatusAvailable => (_RawBits & 0x20000) == 1;                     // Bit 17
            public bool HvL1tfProcessorNotAffected => (_RawBits & 0x40000) == 1;                // Bit 18
            public bool HvL1tfMigitationEnabled => (_RawBits & 0x80000) == 1;                   // Bit 19
            public bool HvL1tfMigitationNotEnabled_Hardware => (_RawBits & 0x100000) == 1;      // Bit 20
            public bool HvL1tfMigitationNotEnabled_LoadOption => (_RawBits & 0x200000) == 1;    // Bit 21
            public bool HvL1tfMigitationNotEnabled_CoreScheduler => (_RawBits & 0x400000) == 1; // Bit 22
            public bool EnhancedIbrsReported => (_RawBits & 0x800000) == 1;                     // Bit 23
            public bool MdsHardwareProtected => (_RawBits & 0x1000000) == 1;                    // Bit 24
            public bool MbClearEnabled => (_RawBits & 0x2000000) == 1;                          // Bit 25
            public bool MbClearReported => (_RawBits & 0x4000000) == 1;                         // Bit 26
            public byte TsxCtrlStatus => (byte)((_RawBits >> 27) & 0x3);                        // Bits 27-28 TODO
            public bool TsxCtrlReported => (_RawBits & 0x20000000) == 1;                        // Bit 29
            public bool TaaHardwareImmune => (_RawBits & 0x40000000) == 1;                      // Bit 30
            private bool Reserved => (_RawBits & 0x80000000) == 1;                               // Bit 31
        }

        [Flags]
        private enum SpeculationControlTsxCtrlStatus : byte {
            RtmDisabled = 0x1,
            RtmAndHleEnumDisabled = 0x2
        }

        private struct SpeculationControlFlags2 {
            internal uint _RawBits;

            public bool SbdrSsdpHardwareProtected => (_RawBits & 0x1) == 1;       // Bit 0
            public bool FbsdpHardwareProtected => (_RawBits & 0x2) == 1;          // Bit 1
            public bool PsdpHardwareProtected => (_RawBits & 0x4) == 1;           // Bit 2
            public bool FbClearEnabled => (_RawBits & 0x8) == 1;                  // Bit 3
            public bool FbClearReported => (_RawBits & 0x10) == 1;                // Bit 4
            public bool BhbEnabled => (_RawBits & 0x20) == 1;                     // Bit 5
            public bool BhbDisabledSystemPolicy => (_RawBits & 0x40) == 1;        // Bit 6
            public bool BhbDisabledNoHardwareSupport => (_RawBits & 0x80) == 1;   // Bit 7
            public byte BranchConfusionStatus => (byte)((_RawBits >> 8) & 0x3);   // Bits 8-9 TODO
            public bool BranchConfusionReported => (_RawBits & 0x400) == 1;       // Bit 10
            public bool RdclHardwareProtectedReported => (_RawBits & 0x800) == 1; // Bit 11
            public bool RdclHardwareProtected => (_RawBits & 0x1000) == 1;        // Bit 12
            public bool GdsReported => (_RawBits & 0x2000) == 1;                  // Bit 13
            public byte GdsStatus => (byte)((_RawBits >> 14) & 0x7);              // Bits 14-16 TODO
            public bool SrsoReported => (_RawBits & 0x20000) == 1;                // Bit 17
            public byte SrsoStatus => (byte)((_RawBits >> 18) & 0x3);             // Bits 18-19 TODO
            public bool DivideByZeroReported => (_RawBits & 0x100000) == 1;       // Bit 20
            public bool DivideByZeroStatus => (_RawBits & 0x200000) == 1;         // Bit 21
            public bool RfdsReported => (_RawBits & 0x400000) == 1;               // Bit 22
            public byte RfdsStatus => (byte)((_RawBits >> 23) & 0x3);             // Bits 23-24 TODO
            private byte Reserved => (byte)((_RawBits >> 28) & 0x7F);              // Bits 25-31 TODO
        }

        private enum SpeculationControlBranchConfusionStatus : byte {
            MitigationUnsupported = 0x0,
            MitigationDisabled = 0x1,
            HardwareImmune = 0x2,
            Mitigated = 0x3
        }

        private enum SpeculationControlGdsStatus : byte {
            MitigationUnsupported = 0x0,
            MitigationDisabled = 0x1,
            HardwareImmune = 0x2,
            Mitigated = 0x3,
            MitigatedAndLocked = 0x4
        }

        private enum SpeculationControlSrsoStatus : byte {
            MitigationUnsupported = 0x0,
            MitigationDisabled = 0x1,
            HardwareImmune = 0x2,
            Mitigated = 0x3
        }

        private enum SpeculationControlDivideByZeroStatus : byte {
            HardwareImmune = 0x0,
            Mitigated = 0x1
        }

        private enum SpeculationControlRfdsStatus : byte {
            MitigationUnsupported = 0x0,
            MitigationDisabled = 0x1,
            HardwareImmune = 0x2,
            Mitigated = 0x3
        }

        #endregion
    }
}
