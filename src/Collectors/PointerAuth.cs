using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace QueryHardwareSecurity.Collectors {
    internal sealed class PointerAuth : Collector {
        private const int PointerAuthInfoClass = 0xEC;

        private PointerAuthInfo _pointerAuthInfo;

        public PointerAuth() : base("Pointer Authentication", TableStyle.Full) {
            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteVerbose($"Retrieving {Name} info ...");

            var pointerAuthInfoLength = Marshal.SizeOf<PointerAuthInfo>();
            WriteDebug($"Size of {nameof(PointerAuthInfo)} structure: {pointerAuthInfoLength} bytes");

            var ntStatus = NtQuerySystemInformation(PointerAuthInfoClass, out _pointerAuthInfo, (uint)pointerAuthInfoLength, IntPtr.Zero);
            if (ntStatus != 0) NtQsiFailure(ntStatus);
            WriteDebug($"Result: 0x{_pointerAuthInfo._RawBits:X8}");
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(_pointerAuthInfo);
        }

        internal override void WriteOutput(OutputFormat format, bool color) {
            SetOutputSettings(format, color);
            WriteOutputHeader();

            var addressAuthSupported = _pointerAuthInfo.AddressAuthSupported;
            var addressAuthQarma = _pointerAuthInfo.AddressAuthQarma;
            var genericAuthSupported = _pointerAuthInfo.GenericAuthSupported;
            var genericAuthQarma = _pointerAuthInfo.GenericAuthQarma;
            var addressAuthFaulting = _pointerAuthInfo.AddressAuthFaulting;

            WriteOutputEntry("AddressAuthSupported", addressAuthSupported, addressAuthSupported);
            WriteOutputEntry("AddressAuthQarma", addressAuthQarma, addressAuthQarma);
            WriteOutputEntry("GenericAuthSupported", genericAuthSupported, genericAuthSupported);
            WriteOutputEntry("GenericAuthQarma", genericAuthQarma, genericAuthQarma);
            WriteOutputEntry("AddressAuthFaulting", addressAuthFaulting, addressAuthFaulting);

            var userPerProcessIpAuthEnabled = _pointerAuthInfo.UserPerProcessIpAuthEnabled;
            var userGlobalIpAuthEnabled = _pointerAuthInfo.UserGlobalIpAuthEnabled;
            var kernelIpAuthEnabled = _pointerAuthInfo.KernelIpAuthEnabled;

            var userPerProcessIpAuthEnabledSecure = userPerProcessIpAuthEnabled || userGlobalIpAuthEnabled;

            WriteOutputEntry("UserPerProcessIpAuthEnabled", userPerProcessIpAuthEnabled, userPerProcessIpAuthEnabledSecure);
            WriteOutputEntry("UserGlobalIpAuthEnabled", userGlobalIpAuthEnabled, userGlobalIpAuthEnabled);
            WriteOutputEntry("KernelIpAuthEnabled", kernelIpAuthEnabled, kernelIpAuthEnabled);
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(int systemInformationClass,
                                                           out PointerAuthInfo systemInformation,
                                                           uint systemInformationLength,
                                                           IntPtr returnLength);

#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Field can be made readonly
#pragma warning disable IDE0251 // Member can be made readonly

        // ReSharper disable InconsistentNaming

        private struct PointerAuthInfo {
            internal uint _RawBits;

            /*
             * SupportedFlags
             */
            public bool AddressAuthSupported => (_RawBits & 0x1) == 1;        // Bit 0
            public bool AddressAuthQarma => ((_RawBits >> 1) & 0x1) == 1;     // Bit 1
            public bool GenericAuthSupported => ((_RawBits >> 2) & 0x1) == 1; // Bit 2
            public bool GenericAuthQarma => ((_RawBits >> 3) & 0x1) == 1;     // Bit 3
            public bool AddressAuthFaulting => ((_RawBits >> 4) & 0x1) == 1;  // Bit 4

            /*
             * EnabledFlags
             */
            public bool UserPerProcessIpAuthEnabled => ((_RawBits >> 16) & 0x1) == 1; // Bit 16
            public bool UserGlobalIpAuthEnabled => ((_RawBits >> 17) & 0x1) == 1;     // Bit 17
            private byte UserEnabledReserved => (byte)((_RawBits >> 18) & 0x3F);      // Bits 18-23
            public bool KernelIpAuthEnabled => ((_RawBits >> 24) & 0x1) == 1;         // Bit 24
            private byte KernelEnabledReserved => (byte)(_RawBits >> 9);              // Bits 25-31
        }

        // ReSharper restore InconsistentNaming

#pragma warning restore IDE0251 // Member can be made readonly
#pragma warning restore IDE0044 // Field can be made readonly
#pragma warning restore CS0649  // Field is never assigned to

        #endregion
    }
}
