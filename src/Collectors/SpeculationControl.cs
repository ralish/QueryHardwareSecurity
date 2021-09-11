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

        /*
         * This information is only exposed via the NtQuerySystemInformation function in the native
         * API. Microsoft has partially documented this specific information class, but many of the
         * newer flags in the returned bitmask remain informally or completely undocumented.
         *
         * The meaning of undocumented flags was determined by reverse-engineering of the NT kernel.
         * It's worth nothing all 32-bits of the returned bitmask have now been utilised, which may
         * require the introduction of an additional information class if more flags are required.
         *
         * SYSTEM_SPECULATION_CONTROL_INFORMATION
         * https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_speculation_control_information
         */
        private void RetrieveFlags() {
            WriteConsoleVerbose("Retrieving SpeculationControl info ...");

            const int sysInfoLength = sizeof(SpeculationControlFlags);
            var sysInfo = Marshal.AllocHGlobal(sysInfoLength);
            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemSpeculationControlInformation,
                                                    sysInfo,
                                                    sysInfoLength,
                                                    IntPtr.Zero);

            if (ntStatus == 0) {
                Flags = (SpeculationControlFlags)Marshal.ReadInt32(sysInfo);
            }

            Marshal.FreeHGlobal(sysInfo);

            if (ntStatus != 0) {
                // STATUS_INVALID_INFO_CLASS || STATUS_NOT_IMPLEMENTED
                if (ntStatus == -1073741821 || ntStatus == -1073741822) {
                    throw new NotImplementedException($"System support for querying {Name} information not present.");
                }

                WriteConsoleVerbose($"Error requesting {Name} information: {ntStatus}");
                var symbolicNtStatus = GetSymbolicNtStatus(ntStatus);
                throw new Win32Exception(symbolicNtStatus);
            }
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
        // ReSharper disable MemberCanBePrivate.Global

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

        // ReSharper enable MemberCanBePrivate.Global
        // ReSharper enable InconsistentNaming
        // @formatter:on

        #endregion
    }
}
