using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal class KernelVaShadow : Collector {
        private static readonly List<string> FlagsIgnored =
            Enumerable.Range(1, 6).Select(n => $"InvalidPte{n}").ToList();

        internal KernelVaShadowFlags Flags { get; private set; }
        internal bool FlagsRetrieved { get; private set; }

        private readonly dynamic _metadata;

        public KernelVaShadow() : base("Kernel VA Shadowing") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            _metadata = LoadMetadata();
            RetrieveFlags();
            ParseFlags(Flags, _metadata, FlagsIgnored);
            ParseFlagsInternal();
        }

        private void RetrieveFlags() {
            WriteConsoleVerbose("Retrieving KernelVaShadow information class ...");

            var sysInfoLength = sizeof(KernelVaShadowFlags);
            var sysInfo = Marshal.AllocHGlobal(sysInfoLength);
            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemKernelVaShadowInformation,
                                                    sysInfo,
                                                    (uint)sysInfoLength,
                                                    IntPtr.Zero);

            if (ntStatus == 0) {
                FlagsRetrieved = true;
                Flags = (KernelVaShadowFlags)Marshal.ReadInt32(sysInfo);
            } else {
                // STATUS_INVALID_INFO_CLASS, STATUS_NOT_IMPLEMENTED
                if (ntStatus == -1073741821 || ntStatus == -1073741822) {
                    WriteConsoleError($"System support for querying {Name} information not present.");
                } else {
                    WriteConsoleError($"Error on requesting {Name} information: {ntStatus}");
                    var symbolicNtStatus = GetSymbolicNtStatus(ntStatus);
                    WriteConsoleError(symbolicNtStatus, false);
                }
            }

            Marshal.FreeHGlobal(sysInfo);
        }

        private void ParseFlagsInternal() {
            var flagName = "InvalidPteBit";
            var flagValue = (((int)Flags & InvalidPteBitMask) >> InvalidPteBitShift).ToString();
            var flagData = GetOrCreateDynamicObjectKey(_metadata, flagName);
            flagData.value = flagValue;
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(_metadata);
        }

        internal override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(true);
            WriteConsoleFlags(Flags, _metadata, FlagsIgnored);
            WriteConsoleEntry("InvalidPteBit", _metadata);
        }

        #region P/Invoke

        // @formatter:off
        // ReSharper disable InconsistentNaming

        [Flags]
        internal enum KernelVaShadowFlags {
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

        private const int InvalidPteBitMask = 0xFC0;
        private const int InvalidPteBitShift = 6;

        // ReSharper enable InconsistentNaming
        // @formatter:on

        #endregion
    }
}
