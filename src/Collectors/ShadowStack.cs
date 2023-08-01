using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal sealed class ShadowStack : Collector {
        private static readonly List<string> FlagsIgnored = new List<string> {
            "ReservedForKernelCet1",
            "ReservedForKernelCet2",
            "ReservedForKernelCet3",
            "ReservedForKernelCet4",
            "ReservedForKernelCet5",
            "ReservedForKernelCet6",
            "ReservedForUserCet1",
            "ReservedForUserCet2",
            "ReservedForUserCet3",
            "ReservedForUserCet4",
            "ReservedForUserCet5",
            "ReservedForUserCet6"
        };

        // ReSharper disable once MemberCanBePrivate.Global
        public ShadowStackFlags SystemInfo { get; private set; }

        private readonly dynamic _metadata;

        public ShadowStack() : base("Shadow Stack") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            RetrieveFlags();

            _metadata = LoadMetadata();
            ParseFlags(SystemInfo, _metadata, FlagsIgnored);
        }

        private void RetrieveFlags() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            const int sysInfoLength = sizeof(ShadowStackFlags);
            WriteConsoleDebug($"Size of {nameof(ShadowStackFlags)} bit field: {sysInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemShadowStackInformation,
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
            WriteConsoleFlags(SystemInfo, _metadata, FlagsIgnored);
        }

        #region P/Invoke

        // ReSharper disable MemberCanBePrivate.Global

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out ShadowStackFlags systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

        // @formatter:int_align_fields true

        [Flags]
        public enum ShadowStackFlags {
            CetCapable                = 0x1,
            UserCetAllowed            = 0x2,
            KernelCetEnabled          = 0x100,
            KernelCetAuditModeEnabled = 0x200,

            ReservedForUserCet1 = 0x4,
            ReservedForUserCet2 = 0x8,
            ReservedForUserCet3 = 0x10,
            ReservedForUserCet4 = 0x20,
            ReservedForUserCet5 = 0x40,
            ReservedForUserCet6 = 0x80,

            ReservedForKernelCet1 = 0x400,
            ReservedForKernelCet2 = 0x800,
            ReservedForKernelCet3 = 0x1000,
            ReservedForKernelCet4 = 0x2000,
            ReservedForKernelCet5 = 0x4000,
            ReservedForKernelCet6 = 0x8000
        }

        // @formatter:int_align_fields false

        // ReSharper enable MemberCanBePrivate.Global

        #endregion
    }
}
