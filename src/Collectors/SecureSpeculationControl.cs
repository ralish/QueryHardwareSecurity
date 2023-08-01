using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal sealed class SecureSpeculationControl : Collector {
        // ReSharper disable once MemberCanBePrivate.Global
        public SecureSpeculationControlFlags SystemInfo { get; private set; }

        private readonly dynamic _metadata;

        public SecureSpeculationControl() : base("Secure Speculation Control") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            RetrieveFlags();

            _metadata = LoadMetadata();
            ParseFlags(SystemInfo, _metadata);
        }

        private void RetrieveFlags() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            const int sysInfoLength = sizeof(SecureSpeculationControlFlags);
            WriteConsoleDebug($"Size of {nameof(SecureSpeculationControlFlags)} bit field: {sysInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemSecureSpeculationControlInformation,
                                                    out var sysInfo,
                                                    sysInfoLength,
                                                    IntPtr.Zero);


            switch (ntStatus) {
                case 0:
                    SystemInfo = sysInfo;
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
            WriteConsoleFlags(SystemInfo, _metadata);
        }

        #region P/Invoke

        // ReSharper disable InconsistentNaming

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out SecureSpeculationControlFlags systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

        // @formatter:int_align_fields true

        [Flags]
        public enum SecureSpeculationControlFlags {
            KvaShadowSupported  = 0x1,
            KvaShadowEnabled    = 0x2,
            KvaShadowUserGlobal = 0x4,
            KvaShadowPcid       = 0x8,
            MbClearEnabled      = 0x10,
            L1TFMitigated       = 0x20,
            BpbEnabled          = 0x40,
            IbrsPresent         = 0x80,
            EnhancedIbrs        = 0x100,
            StibpPresent        = 0x200,
            SsbdSupported       = 0x400,
            SsbdRequired        = 0x800,
            BpbKernelToUser     = 0x1000,
            BpbUserToKernel     = 0x2000
        }

        // @formatter:int_align_fields false

        // ReSharper enable InconsistentNaming

        #endregion
    }
}
