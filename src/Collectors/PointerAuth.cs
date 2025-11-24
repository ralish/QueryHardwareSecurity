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
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(_pointerAuthInfo);
        }

        internal override void WriteOutput(OutputFormat format, bool color) {
            SetOutputSettings(format, color);
            WriteOutputHeader();

            // Displaying the symbolic names of the SupportedFlags flags will
            // make the value column too wide in table format, so we'll display
            // the flags as individual booleans.
            var supportedFlags = _pointerAuthInfo.SupportedFlags;
            var addressAuthSupported = supportedFlags.HasFlag(SupportedFlags.AddressAuthSupported);
            var addressAuthQarma = supportedFlags.HasFlag(SupportedFlags.AddressAuthQarma);
            var genericAuthSupported = supportedFlags.HasFlag(SupportedFlags.GenericAuthSupported);
            var genericAuthQarma = supportedFlags.HasFlag(SupportedFlags.GenericAuthQarma);
            var addressAuthFaulting = supportedFlags.HasFlag(SupportedFlags.AddressAuthFaulting);

            WriteOutputEntry("AddressAuthSupported", addressAuthSupported, addressAuthSupported);
            WriteOutputEntry("AddressAuthQarma", addressAuthQarma, addressAuthQarma);
            WriteOutputEntry("GenericAuthSupported", genericAuthSupported, genericAuthSupported);
            WriteOutputEntry("GenericAuthQarma", genericAuthQarma, genericAuthQarma);
            WriteOutputEntry("AddressAuthFaulting", addressAuthFaulting, addressAuthFaulting);

            var enabledFlags = _pointerAuthInfo.EnabledFlags;
            var userPerProcessIpAuthEnabled = enabledFlags.UserPerProcessIpAuthEnabled;
            var userGlobalIpAuthEnabled = enabledFlags.UserGlobalIpAuthEnabled;
            var kernelIpAuthEnabled = enabledFlags.KernelIpAuthEnabled;

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

#pragma warning disable CS0649 // Field is never assigned to

        private struct PointerAuthInfo {
            internal SupportedFlags SupportedFlags;
            internal EnabledFlags EnabledFlags;
        }

        // @formatter:int_align_fields true

        [Flags]
        private enum SupportedFlags : ushort {
            AddressAuthSupported = 0x1,
            AddressAuthQarma     = 0x2,
            GenericAuthSupported = 0x4,
            GenericAuthQarma     = 0x8,
            AddressAuthFaulting  = 0x10
        }

        // @formatter:int_align_fields false

#pragma warning disable IDE0044 // Field can be made readonly
#pragma warning disable IDE0251 // Member can be made readonly

        // ReSharper disable InconsistentNaming

        private struct EnabledFlags {
            private ushort _RawBits;

            public bool UserPerProcessIpAuthEnabled => (_RawBits & 0x1) == 1;    // Bit 0
            public bool UserGlobalIpAuthEnabled => ((_RawBits >> 1) & 0x1) == 1; // Bit 1
            private byte UserEnabledReserved => (byte)((_RawBits >> 2) & 0x3F);  // Bits 2-7
            public bool KernelIpAuthEnabled => ((_RawBits >> 8) & 0x1) == 1;     // Bit 8
            private byte KernelEnabledReserved => (byte)(_RawBits >> 9);         // Bits 9-15
        }

        // ReSharper restore InconsistentNaming

#pragma warning restore IDE0251 // Member can be made readonly
#pragma warning restore IDE0044 // Field can be made readonly
#pragma warning restore CS0649  // Field is never assigned to

        #endregion
    }
}
