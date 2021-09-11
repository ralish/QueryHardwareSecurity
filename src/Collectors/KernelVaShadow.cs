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
        public KernelVaShadowFlags Flags { get; private set; }

        private readonly dynamic _metadata;

        public KernelVaShadow() : base("Kernel VA Shadowing") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            RetrieveFlags();

            _metadata = LoadMetadata();
            ParseFlags(Flags, _metadata, FlagsIgnored);
            ParseFlagsInternal();
        }

        /*
         * This information is only exposed via the NtQuerySystemInformation function in the native
         * API. Microsoft has documented this specific information class, although at the time of
         * writing there are 18 unused bits in the returned 32-bit bitmask.
         *
         * SYSTEM_KERNEL_VA_SHADOW_INFORMATION
         * https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_kernel_va_shadow_information
         */
        private void RetrieveFlags() {
            WriteConsoleVerbose("Retrieving KernelVaShadow info ...");

            const int sysInfoLength = sizeof(KernelVaShadowFlags);
            var sysInfo = Marshal.AllocHGlobal(sysInfoLength);
            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemKernelVaShadowInformation,
                                                    sysInfo,
                                                    sysInfoLength,
                                                    IntPtr.Zero);

            if (ntStatus == 0) {
                Flags = (KernelVaShadowFlags)Marshal.ReadInt32(sysInfo);
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

        private void ParseFlagsInternal() {
            const string flagName = "InvalidPteBit";
            var flagValue = (((int)Flags & InvalidPteBitMask) >> InvalidPteBitShift).ToString();
            var flagData = GetOrCreateDynamicObjectKey(_metadata, flagName);
            flagData.value = flagValue;
        }

        public override string ConvertToJson() {
            return JsonConvert.SerializeObject(_metadata);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(true);
            WriteConsoleFlags(Flags, _metadata, FlagsIgnored);
            WriteConsoleEntry("InvalidPteBit", _metadata);
        }

        #region P/Invoke

        // @formatter:off
        // ReSharper disable InconsistentNaming
        // ReSharper disable MemberCanBePrivate.Global

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
        // ReSharper enable InconsistentNaming
        // @formatter:on

        #endregion
    }
}
