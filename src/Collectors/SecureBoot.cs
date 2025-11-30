using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace QueryHardwareSecurity.Collectors {
    internal sealed class SecureBoot : Collector {
        private const int SecureBootInfoClass = 0x91;

        private SecureBootInfo _secureBootInfo;

        public SecureBoot() : base("Secure Boot", TableStyle.Full) {
            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteVerbose($"Retrieving {Name} info ...");

            var secureBootInfoLength = Marshal.SizeOf<SecureBootInfo>();
            WriteDebug($"Size of {nameof(SecureBootInfo)} structure: {secureBootInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(SecureBootInfoClass, out _secureBootInfo, (uint)secureBootInfoLength, IntPtr.Zero);
            if (ntStatus != 0) NtQsiFailure(ntStatus);
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(_secureBootInfo);
        }

        internal override void WriteOutput(OutputFormat format, bool color) {
            SetOutputSettings(format, color);
            WriteOutputHeader();

            var secureBootEnabled = _secureBootInfo.SecureBootEnabled;
            var secureBootCapable = _secureBootInfo.SecureBootCapable;

            var secureBootEnabledSecure = secureBootCapable && secureBootEnabled;

            WriteOutputEntry("SecureBootEnabled", secureBootEnabled, secureBootEnabledSecure);
            WriteOutputEntry("SecureBootCapable", secureBootCapable, secureBootCapable);
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(int systemInformationClass,
                                                           out SecureBootInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

#pragma warning disable CS0649 // Field is never assigned to

        private struct SecureBootInfo {
            [MarshalAs(UnmanagedType.U1)]
            public bool SecureBootEnabled;

            [MarshalAs(UnmanagedType.U1)]
            public bool SecureBootCapable;
        }

#pragma warning restore CS0649 // Field is never assigned to

        #endregion
    }
}
