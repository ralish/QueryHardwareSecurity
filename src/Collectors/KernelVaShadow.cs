using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal class KernelVaShadow : Collector {
        private static readonly List<string> FlagsIgnored =
            Enumerable.Range(1, 6).Select(n => $"InvalidPte{n}").ToList();

        // ReSharper disable once MemberCanBePrivate.Global
        public KernelVaShadowFlags SystemInfo { get; private set; }

        private readonly dynamic _metadata;

        public KernelVaShadow() : base("Kernel VA Shadowing") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            RetrieveFlags();

            _metadata = LoadMetadata();
            ParseFlags(SystemInfo, _metadata, FlagsIgnored);
            ParseFlagsInternal();
        }

        /// <summary>
        ///     Retrieve Kernel VA Shadow information
        /// </summary>
        /// <remarks>
        ///     This information is only exposed via the NtQuerySystemInformation function in the native API. Microsoft has
        ///     documented this information class, although currently there are 18 unused bits in the 32-bit bit field.
        /// </remarks>
        private void RetrieveFlags() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            const int sysInfoLength = sizeof(KernelVaShadowFlags);
            WriteConsoleDebug($"Size of {nameof(KernelVaShadowFlags)} bit field: {sysInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemKernelVaShadowInformation,
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

        private void ParseFlagsInternal() {
            const string flagName = "InvalidPteBit";
            var flagValue = (((int)SystemInfo & InvalidPteBitMask) >> InvalidPteBitShift).ToString();
            var flagData = GetOrCreateDynamicObjectKey(_metadata, flagName);
            flagData.value = flagValue;
        }

        public override string ConvertToJson() {
            return JsonConvert.SerializeObject(_metadata);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(true);
            WriteConsoleFlags(SystemInfo, _metadata, FlagsIgnored);
            WriteConsoleEntry("InvalidPteBit", _metadata);
        }

        #region P/Invoke

        // @formatter:off
        // ReSharper disable MemberCanBePrivate.Global

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out KernelVaShadowFlags systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

        [Flags]
        public enum KernelVaShadowFlags {
            KvaShadowEnabled                    = 0x1,                      // Checked by SpeculationControl module
            KvaShadowUserGlobal                 = 0x2,
            KvaShadowPcid                       = 0x4,                      // Checked by SpeculationControl module
            KvaShadowInvpcid                    = 0x8,                      // Checked by SpeculationControl module
            KvaShadowRequired                   = 0x10,                     // Checked by SpeculationControl module
            KvaShadowRequiredAvailable          = 0x20,                     // Checked by SpeculationControl module
            L1DataCacheFlushSupported           = 0x40,                     // Checked by SpeculationControl module
            L1TerminalFaultMitigationPresent    = 0x80,                     // Checked by SpeculationControl module

            // Handled separately in ParseFlagsInternal()
            InvalidPte1 = 0x100,
            InvalidPte2 = 0x200,
            InvalidPte3 = 0x400,
            InvalidPte4 = 0x800,
            InvalidPte5 = 0x1000,
            InvalidPte6 = 0x2000
        }

        public const int InvalidPteBitMask = 0xFC0;
        public const int InvalidPteBitShift = 6;

        // ReSharper enable MemberCanBePrivate.Global
        // @formatter:on

        #endregion
    }
}
