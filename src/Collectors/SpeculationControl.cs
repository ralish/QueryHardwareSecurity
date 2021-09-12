using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal class SpeculationControl : Collector {
        // ReSharper disable once MemberCanBePrivate.Global
        public SpeculationControlFlags Flags { get; private set; }

        private readonly dynamic _metadata;

        public SpeculationControl() : base("Speculation Control") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            RetrieveFlags();

            _metadata = LoadMetadata();
            ParseFlags(Flags, _metadata);
        }

        /// <summary>
        ///     Retrieve Speculation Control information
        /// </summary>
        /// <remarks>
        ///     This information is only exposed via the NtQuerySystemInformation function in the native API. Microsoft has
        ///     partially documented this information class, however many of the newer flags in the 32-bit bit field remain
        ///     informally or completely undocumented. The meaning of undocumented flags was determined by reverse-engineering of
        ///     the NT kernel. Currently 31-bits in the 32-bit bit field are used, which may necessitate the addition of another
        ///     information class if additional speculative execution vulnerability mitigations are introduced.
        /// </remarks>
        private void RetrieveFlags() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            const int sysInfoLength = sizeof(SpeculationControlFlags);
            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemSpeculationControlInformation,
                                                    out var sysInfo,
                                                    sysInfoLength,
                                                    IntPtr.Zero);


            switch (ntStatus) {
                case 0:
                    Flags = sysInfo;
                    return;
                // STATUS_INVALID_INFO_CLASS || STATUS_NOT_IMPLEMENTED
                case -1073741821:
                case -1073741822:
                    throw new NotImplementedException($"System support for querying {Name} information not present.");
            }

            WriteConsoleVerbose($"Error requesting {Name} information: {ntStatus}");
            var symbolicNtStatus = GetSymbolicNtStatus(ntStatus);
            throw new Win32Exception(symbolicNtStatus);
        }

        public override string ConvertToJson() {
            return JsonConvert.SerializeObject(_metadata);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(true);
            WriteConsoleFlags(Flags, _metadata);
        }

        #region P/Invoke

        // @formatter:off
        // ReSharper disable InconsistentNaming

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out SpeculationControlFlags systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

        [Flags]
        public enum SpeculationControlFlags {
            BpbEnabled                                  = 0x1,              // Checked by SpeculationControl module
            BpbDisabledSystemPolicy                     = 0x2,              // Checked by SpeculationControl module
            BpbDisabledNoHardwareSupport                = 0x4,              // Checked by SpeculationControl module
            SpecCtrlEnumerated                          = 0x8,              // Checked by SpeculationControl module
            SpecCmdEnumerated                           = 0x10,             // Checked by SpeculationControl module
            IbrsPresent                                 = 0x20,
            StibpPresent                                = 0x40,
            SmepPresent                                 = 0x80,
            SpeculativeStoreBypassDisableAvailable      = 0x100,            // Checked by SpeculationControl module
            SpeculativeStoreBypassDisableSupported      = 0x200,            // Checked by SpeculationControl module
            SpeculativeStoreBypassDisabledSystemWide    = 0x400,            // Checked by SpeculationControl module
            SpeculativeStoreBypassDisabledKernel        = 0x800,
            SpeculativeStoreBypassDisableRequired       = 0x1000,           // Checked by SpeculationControl module
            BpbDisabledKernelToUser                     = 0x2000,
            SpecCtrlRetpolineEnabled                    = 0x4000,           // Checked by SpeculationControl module (silent)
            SpecCtrlImportOptimizationEnabled           = 0x8000,           // Checked by SpeculationControl module (silent)
            EnhancedIbrs                                = 0x10000,
            HvL1tfStatusAvailable                       = 0x20000,
            HvL1tfProcessorNotAffected                  = 0x40000,
            HvL1tfMigitationEnabled                     = 0x80000,
            HvL1tfMigitationNotEnabled_Hardware         = 0x100000,
            HvL1tfMigitationNotEnabled_LoadOption       = 0x200000,
            HvL1tfMigitationNotEnabled_CoreScheduler    = 0x400000,
            EnhancedIbrsReported                        = 0x800000,
            MdsHardwareProtected                        = 0x1000000,        // Checked by SpeculationControl module
            MbClearEnabled                              = 0x2000000,        // Checked by SpeculationControl module
            MbClearReported                             = 0x4000000,        // Checked by SpeculationControl module
            TsxControlStatus1                           = 0x8000000,
            TsxControlStatus2                           = 0x10000000,
            TsxCtrlReported                             = 0x20000000,
            TaaHardwareImmune                           = 0x40000000
        }

        // ReSharper enable InconsistentNaming
        // @formatter:on

        #endregion
    }
}
