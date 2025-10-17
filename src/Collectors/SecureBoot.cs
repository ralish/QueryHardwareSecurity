using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal sealed class SecureBoot : Collector {
        private SecureBootInfo _secureBootInfo;

        public SecureBoot() : base("Secure Boot") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 5;
            ConsoleWidthDescription = 64;

            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteConsoleVerbose($"Retrieving {Name} info ...");

            var secureBootInfoLength = Marshal.SizeOf(typeof(SecureBootInfo));
            WriteConsoleDebug($"Size of {nameof(SecureBootInfo)} structure: {secureBootInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemSecureBootInformation,
                                                    out _secureBootInfo,
                                                    (uint)secureBootInfoLength,
                                                    IntPtr.Zero);

            switch (ntStatus) {
                case 0: return;
                case -1073741821: // STATUS_INVALID_INFO_CLASS
                case -1073741822: // STATUS_NOT_IMPLEMENTED
                    throw new NotImplementedException($"System support for querying {Name} information not present.");
            }

            WriteConsoleVerbose($"Error requesting {Name} information: {ntStatus}");
            var symbolicNtStatus = GetSymbolicNtStatus(ntStatus);
            throw new Win32Exception(symbolicNtStatus);
        }

        public override string ConvertToJson() {
            return JsonConvert.SerializeObject(_secureBootInfo);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(true);
            foreach (var field in _secureBootInfo.GetType().GetFields()) {
                WriteConsoleEntry(field.Name, (bool)field.GetValue(_secureBootInfo));
            }
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                           out SecureBootInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

        private struct SecureBootInfo {
            [JsonProperty(Order = 1)]
            [MarshalAs(UnmanagedType.U1)]
            public bool SecureBootEnabled;

            [JsonProperty(Order = 2)]
            [MarshalAs(UnmanagedType.U1)]
            public bool SecureBootCapable;
        }

        #endregion
    }
}
